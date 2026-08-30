#include "tls_coprocessor.h"

#include "rpc_calls.h"

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"

#ifdef ESP_PLATFORM
#include "esp_crt_bundle.h"
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#define TLS_CA_MAX 4096
#define TLS_RING_SIZE 4096
#define TLS_RESPONSE_MAX (CMD_BUF_SIZE - offsetof(rpc_tls_resp, data))

static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context rng;
static mbedtls_x509_crt ca_roots;
static mbedtls_ssl_config config;
static mbedtls_ssl_context ssl;
static uint8_t ca_bundle[TLS_CA_MAX + 1];
static uint8_t input_ring[TLS_RING_SIZE];
static uint8_t output_ring[TLS_RING_SIZE];
static uint8_t plain[TLS_RESPONSE_MAX];
static size_t ca_length;
static size_t input_length;
static size_t output_length;
static int ca_initialized;
static int ca_ready;
static int crypto_ready;
static int session_ready;

static int tls_recv(void *ctx, unsigned char *buffer, size_t length)
{
    (void)ctx;
    if (!input_length) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    if (length > input_length) {
        length = input_length;
    }
    memcpy(buffer, input_ring, length);
    input_length -= length;
    memmove(input_ring, input_ring + length, input_length);
    return (int)length;
}

static int tls_send(void *ctx, const unsigned char *buffer, size_t length)
{
    (void)ctx;
    if (length > sizeof(output_ring) - output_length) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    memcpy(output_ring + output_length, buffer, length);
    output_length += length;
    return (int)length;
}

static void free_session(void)
{
    if (session_ready) {
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&config);
    }
    session_ready = 0;
    input_length = 0;
    output_length = 0;
}

int tls_coprocessor_init(void)
{
    if (crypto_ready) {
        return 0;
    }

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&rng);
    static const unsigned char personal[] = "Ultimate TLS";
    int result = mbedtls_ctr_drbg_seed(&rng, mbedtls_entropy_func, &entropy,
                                      personal, sizeof(personal) - 1);
#ifdef ESP_PLATFORM
    if (result == 0) {
        result = esp_crt_bundle_attach(NULL);
    }
#endif
    if (result != 0) {
        mbedtls_ctr_drbg_free(&rng);
        mbedtls_entropy_free(&entropy);
        return result;
    }
    crypto_ready = 1;
    return 0;
}

static int append_input(const uint8_t *data, size_t length)
{
    if (length > sizeof(input_ring) - input_length) {
        return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    }
    memcpy(input_ring + input_length, data, length);
    input_length += length;
    return 0;
}

static size_t take_output(uint8_t *data, size_t capacity)
{
    size_t length = output_length < capacity ? output_length : capacity;
    memcpy(data, output_ring, length);
    output_length -= length;
    memmove(output_ring, output_ring + length, output_length);
    return length;
}

static int set_ca(const rpc_tls_req *req)
{
    if (req->flags & TLS_CA_RESET) {
        if (ca_initialized) {
            mbedtls_x509_crt_free(&ca_roots);
        }
        mbedtls_x509_crt_init(&ca_roots);
        ca_initialized = 1;
        ca_length = 0;
        ca_ready = 0;
    }
    if (req->length > TLS_CA_MAX - ca_length) {
        return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    }
    memcpy(ca_bundle + ca_length, &req->data, req->length);
    ca_length += req->length;
    if (!(req->flags & TLS_CA_FINAL)) {
        return 0;
    }
    if (ca_length == 0) {
        return 0;
    }
    ca_bundle[ca_length] = 0;
    int result = mbedtls_x509_crt_parse(&ca_roots, ca_bundle, ca_length + 1);
    ca_ready = result == 0;
    return result;
}

static int start_session(const rpc_tls_start_data *start)
{
    if (!start->hostname[0]
#ifndef ESP_PLATFORM
        || !ca_ready
#endif
    ) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    free_session();
    struct timeval now = { .tv_sec = (time_t)start->unix_time, .tv_usec = 0 };
    settimeofday(&now, NULL);

    mbedtls_ssl_config_init(&config);
    mbedtls_ssl_init(&ssl);
    session_ready = 1;

    int result = tls_coprocessor_init();
    if (result == 0) {
        result = mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_CLIENT,
                                             MBEDTLS_SSL_TRANSPORT_STREAM,
                                             MBEDTLS_SSL_PRESET_DEFAULT);
    }
    if (result == 0) {
        mbedtls_ssl_conf_authmode(&config, MBEDTLS_SSL_VERIFY_REQUIRED);
#ifdef ESP_PLATFORM
        result = esp_crt_bundle_attach(&config);
#endif
    }
    if (result == 0) {
        if (ca_ready) {
            /* Custom roots augment the ESP-IDF Mozilla bundle. */
            mbedtls_ssl_conf_ca_chain(&config, &ca_roots, NULL);
        }
        mbedtls_ssl_conf_rng(&config, mbedtls_ctr_drbg_random, &rng);
        result = mbedtls_ssl_setup(&ssl, &config);
    }
    if (result == 0) {
        result = mbedtls_ssl_set_hostname(&ssl, start->hostname);
    }
    if (result == 0) {
        mbedtls_ssl_set_bio(&ssl, NULL, tls_send, tls_recv, NULL);
    } else {
        free_session();
    }
    return result;
}

static void respond(command_buf_t *buf, rpc_header_t header, uint8_t operation,
                    int result, const uint8_t *data, size_t length)
{
    rpc_tls_resp *resp = (rpc_tls_resp *)buf->data;
    resp->hdr = header;
    resp->operation = operation;
    resp->reserved = 0;
    resp->result = result;
    resp->length = (uint16_t)length;
    if (length) {
        memcpy(&resp->data, data, length);
    }
    buf->size = offsetof(rpc_tls_resp, data) + length;
}

void tls_coprocessor_handle(command_buf_t *buf)
{
    rpc_tls_req *req = (rpc_tls_req *)buf->data;
    rpc_header_t header = req->hdr;
    uint8_t operation = req->operation;
    size_t request_header = offsetof(rpc_tls_req, data);
    if (buf->size < (int)request_header ||
        req->length > (size_t)buf->size - request_header) {
        respond(buf, header, operation, MBEDTLS_ERR_SSL_BAD_INPUT_DATA, NULL, 0);
        return;
    }

    int result;
    size_t length = 0;
    switch (operation) {
    case TLS_OP_CA:
        result = set_ca(req);
        break;
    case TLS_OP_START: {
        if (req->length != sizeof(rpc_tls_start_data)) {
            result = MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
            break;
        }
        rpc_tls_start_data start;
        memcpy(&start, &req->data, sizeof(start));
        start.hostname[sizeof(start.hostname) - 1] = 0;
        result = start_session(&start);
        break;
    }
    case TLS_OP_HANDSHAKE:
        result = session_ready ? append_input(&req->data, req->length)
                               : MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        if (result == 0) {
            result = mbedtls_ssl_handshake(&ssl);
        }
        length = take_output(plain, sizeof(plain));
        break;
    case TLS_OP_PULL:
        result = session_ready ? 0 : MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        length = take_output(plain, sizeof(plain));
        break;
    case TLS_OP_WRITE:
        result = session_ready ? mbedtls_ssl_write(&ssl, &req->data, req->length)
                               : MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        length = take_output(plain, sizeof(plain));
        break;
    case TLS_OP_READ: {
        if (!session_ready || req->length < sizeof(uint16_t)) {
            result = MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
            break;
        }
        uint16_t read_length;
        memcpy(&read_length, &req->data, sizeof(read_length));
        if (read_length > sizeof(plain)) {
            read_length = sizeof(plain);
        }
        result = append_input(&req->data + sizeof(read_length),
                              req->length - sizeof(read_length));
        if (result == 0) {
            result = mbedtls_ssl_read(&ssl, plain, read_length);
            if (result > 0) {
                length = (size_t)result;
            }
        }
        break;
    }
    case TLS_OP_CLOSE:
        result = session_ready ? mbedtls_ssl_close_notify(&ssl)
                               : MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        length = take_output(plain, sizeof(plain));
        free_session();
        break;
    default:
        result = MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        break;
    }
    respond(buf, header, operation, result, plain, length);
}
