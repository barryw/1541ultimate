#include "tls_coprocessor.h"

#include "esp_crt_bundle.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#define TLS_CA_MAX 4096
#define TLS_INPUT_SIZE 2048
#define TLS_OUTPUT_SIZE 4096
#define TLS_MIN_VALID_TIME 1577836800
#define TLS_RESPONSE_MAX (CMD_BUF_SIZE - offsetof(rpc_tls_resp, data))

typedef struct {
    mbedtls_ssl_context ssl;
    uint8_t input[TLS_INPUT_SIZE];
    uint8_t output[TLS_OUTPUT_SIZE];
    size_t input_length;
    size_t output_length;
    int active;
} tls_session_t;

static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context rng;
static mbedtls_x509_crt ca_roots;
static mbedtls_ssl_config config;
static tls_session_t sessions[TLS_MAX_SESSIONS];
static uint8_t ca_bundle[TLS_CA_MAX + 1];
static uint8_t plain[TLS_RESPONSE_MAX];
static size_t ca_length;
static int ca_uploading;
static int crypto_ready;

static int tls_recv(void *ctx, unsigned char *buffer, size_t length)
{
    tls_session_t *session = (tls_session_t *)ctx;
    if (!session->input_length) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    if (length > session->input_length) {
        length = session->input_length;
    }
    memcpy(buffer, session->input, length);
    session->input_length -= length;
    memmove(session->input, session->input + length, session->input_length);
    return (int)length;
}

static int tls_send(void *ctx, const unsigned char *buffer, size_t length)
{
    tls_session_t *session = (tls_session_t *)ctx;
    if (length > sizeof(session->output) - session->output_length) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    memcpy(session->output + session->output_length, buffer, length);
    session->output_length += length;
    return (int)length;
}

static void free_session(tls_session_t *session)
{
    if (session->active) {
        mbedtls_ssl_free(&session->ssl);
    }
    memset(session, 0, sizeof(*session));
}

static int active_sessions(void)
{
    int count = 0;
    for (int i = 0; i < TLS_MAX_SESSIONS; i++) {
        count += sessions[i].active;
    }
    return count;
}

int tls_coprocessor_init(void)
{
    if (crypto_ready) {
        return 0;
    }

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&rng);
    mbedtls_x509_crt_init(&ca_roots);
    mbedtls_ssl_config_init(&config);

    static const unsigned char personal[] = "Ultimate TLS";
    int bundle_attached = 0;
    int result = mbedtls_ctr_drbg_seed(&rng, mbedtls_entropy_func, &entropy,
                                      personal, sizeof(personal) - 1);
    if (result == 0) {
        result = mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_CLIENT,
                                             MBEDTLS_SSL_TRANSPORT_STREAM,
                                             MBEDTLS_SSL_PRESET_DEFAULT);
    }
    if (result == 0) {
        mbedtls_ssl_conf_authmode(&config, MBEDTLS_SSL_VERIFY_REQUIRED);
        result = esp_crt_bundle_attach(&config);
        bundle_attached = result == 0;
    }
    if (result == 0) {
        mbedtls_ssl_conf_rng(&config, mbedtls_ctr_drbg_random, &rng);
        crypto_ready = 1;
        return 0;
    }

    if (bundle_attached) {
        esp_crt_bundle_detach(&config);
    }
    mbedtls_ssl_config_free(&config);
    mbedtls_x509_crt_free(&ca_roots);
    mbedtls_ctr_drbg_free(&rng);
    mbedtls_entropy_free(&entropy);
    return result;
}

static int append_input(tls_session_t *session, const uint8_t *data, size_t length)
{
    if (length > sizeof(session->input) - session->input_length) {
        return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    }
    memcpy(session->input + session->input_length, data, length);
    session->input_length += length;
    return 0;
}

static size_t take_output(tls_session_t *session, uint8_t *data, size_t capacity)
{
    size_t length = session->output_length < capacity ? session->output_length : capacity;
    memcpy(data, session->output, length);
    session->output_length -= length;
    memmove(session->output, session->output + length, session->output_length);
    return length;
}

static int set_ca(const rpc_tls_req *req)
{
    if (active_sessions()) {
        return TLS_ERR_CA_IN_USE;
    }
    if (req->flags & TLS_CA_RESET) {
        ca_length = 0;
        ca_uploading = 1;
    } else if (!ca_uploading) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (req->length > TLS_CA_MAX - ca_length) {
        return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    }
    memcpy(ca_bundle + ca_length, &req->data, req->length);
    ca_length += req->length;
    if (!(req->flags & TLS_CA_FINAL)) {
        return 0;
    }
    ca_uploading = 0;

    if (!ca_length) {
        mbedtls_x509_crt_free(&ca_roots);
        mbedtls_x509_crt_init(&ca_roots);
        return esp_crt_bundle_attach(&config);
    }

    ca_bundle[ca_length] = 0;
    mbedtls_x509_crt parsed;
    mbedtls_x509_crt_init(&parsed);
    int result = mbedtls_x509_crt_parse(&parsed, ca_bundle, ca_length + 1);
    if (result == 0) {
        mbedtls_x509_crt_free(&ca_roots);
        ca_roots = parsed;
        memset(&parsed, 0, sizeof(parsed));
        /* The bundle verify callback remains installed and handles chains
           that are not anchored by these additional roots. */
        mbedtls_ssl_conf_ca_chain(&config, &ca_roots, NULL);
    }
    mbedtls_x509_crt_free(&parsed);
    return result;
}

static int ensure_time(uint32_t host_time)
{
    if (time(NULL) >= TLS_MIN_VALID_TIME) {
        return 0;
    }
    if (host_time < TLS_MIN_VALID_TIME) {
        return TLS_ERR_INVALID_TIME;
    }
    struct timeval now = { .tv_sec = (time_t)host_time, .tv_usec = 0 };
    return settimeofday(&now, NULL) == 0 ? 0 : TLS_ERR_INVALID_TIME;
}

static int start_session(const rpc_tls_start_data *start, uint8_t *session_id)
{
    if (!start->hostname[0]) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    int result = tls_coprocessor_init();
    if (result != 0) {
        return result;
    }
    result = ensure_time(start->unix_time);
    if (result != 0) {
        return result;
    }

    int index;
    for (index = 0; index < TLS_MAX_SESSIONS; index++) {
        if (!sessions[index].active) {
            break;
        }
    }
    if (index == TLS_MAX_SESSIONS) {
        return TLS_ERR_NO_SESSION;
    }

    tls_session_t *session = &sessions[index];
    memset(session, 0, sizeof(*session));
    mbedtls_ssl_init(&session->ssl);
    session->active = 1;
    result = mbedtls_ssl_setup(&session->ssl, &config);
    if (result == 0) {
        result = mbedtls_ssl_set_hostname(&session->ssl, start->hostname);
    }
    if (result == 0) {
        mbedtls_ssl_set_bio(&session->ssl, session, tls_send, tls_recv, NULL);
        *session_id = (uint8_t)index;
    } else {
        free_session(session);
    }
    return result;
}

static int wire_result(int result)
{
    switch (result) {
    case MBEDTLS_ERR_SSL_WANT_READ:
        return TLS_RESULT_WANT_READ;
    case MBEDTLS_ERR_SSL_WANT_WRITE:
        return TLS_RESULT_WANT_WRITE;
    case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
    case MBEDTLS_ERR_SSL_CONN_EOF:
        return TLS_RESULT_CLOSED;
    case MBEDTLS_ERR_SSL_TIMEOUT:
        return TLS_RESULT_TIMEOUT;
    default:
        return result;
    }
}

static void respond(command_buf_t *buf, rpc_header_t header, uint8_t operation,
                    uint8_t session, int result, const uint8_t *data, size_t length)
{
    rpc_tls_resp *resp = (rpc_tls_resp *)buf->data;
    resp->hdr = header;
    resp->operation = operation;
    resp->session = session;
    resp->length = (uint16_t)length;
    resp->result = wire_result(result);
    if (length) {
        memcpy(&resp->data, data, length);
    }
    buf->size = offsetof(rpc_tls_resp, data) + length;
}

void tls_coprocessor_handle(command_buf_t *buf)
{
    rpc_header_t header = { 0 };
    uint8_t operation = 0;
    uint8_t session_id = TLS_NEW_SESSION;
    if (buf->size >= (int)sizeof(header)) {
        memcpy(&header, buf->data, sizeof(header));
    }

    size_t request_header = offsetof(rpc_tls_req, data);
    if (buf->size < (int)request_header) {
        respond(buf, header, operation, session_id,
                MBEDTLS_ERR_SSL_BAD_INPUT_DATA, NULL, 0);
        return;
    }

    rpc_tls_req *req = (rpc_tls_req *)buf->data;
    operation = req->operation;
    session_id = req->session;
    if (req->length > (size_t)buf->size - request_header) {
        respond(buf, header, operation, session_id,
                MBEDTLS_ERR_SSL_BAD_INPUT_DATA, NULL, 0);
        return;
    }
    if (req->reserved || (operation != TLS_OP_CA && req->flags)) {
        respond(buf, header, operation, session_id,
                MBEDTLS_ERR_SSL_BAD_INPUT_DATA, NULL, 0);
        return;
    }

    int result;
    size_t length = 0;
    tls_session_t *session = NULL;
    if (session_id < TLS_MAX_SESSIONS && sessions[session_id].active) {
        session = &sessions[session_id];
    }

    switch (operation) {
    case TLS_OP_CA:
        result = (session_id == TLS_NEW_SESSION &&
                  !(req->flags & ~(TLS_CA_RESET | TLS_CA_FINAL)))
                     ? tls_coprocessor_init()
                     : MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        if (result == 0) {
            result = set_ca(req);
        }
        break;
    case TLS_OP_START: {
        if (session_id != TLS_NEW_SESSION || req->length != sizeof(rpc_tls_start_data)) {
            result = MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
            break;
        }
        rpc_tls_start_data start;
        memcpy(&start, &req->data, sizeof(start));
        start.hostname[sizeof(start.hostname) - 1] = 0;
        result = start_session(&start, &session_id);
        break;
    }
    case TLS_OP_HANDSHAKE:
        result = session ? append_input(session, &req->data, req->length)
                         : MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        if (result == 0) {
            result = mbedtls_ssl_handshake(&session->ssl);
        }
        if (session) {
            length = take_output(session, plain, sizeof(plain));
        }
        break;
    case TLS_OP_PULL:
        result = (session && !req->length) ? 0 : MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        if (result == 0) {
            length = take_output(session, plain, sizeof(plain));
        }
        break;
    case TLS_OP_WRITE:
        result = session ? mbedtls_ssl_write(&session->ssl, &req->data, req->length)
                         : MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        if (session) {
            length = take_output(session, plain, sizeof(plain));
        }
        break;
    case TLS_OP_READ: {
        if (!session || req->length < sizeof(uint16_t)) {
            result = MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
            break;
        }
        uint16_t read_length;
        memcpy(&read_length, &req->data, sizeof(read_length));
        if (read_length > sizeof(plain)) {
            read_length = sizeof(plain);
        }
        result = append_input(session, &req->data + sizeof(read_length),
                              req->length - sizeof(read_length));
        if (result == 0) {
            result = mbedtls_ssl_read(&session->ssl, plain, read_length);
            if (result > 0) {
                length = (size_t)result;
            }
        }
        break;
    }
    case TLS_OP_CLOSE:
        result = (session && !req->length)
                     ? mbedtls_ssl_close_notify(&session->ssl)
                     : MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        if (session && !req->length) {
            length = take_output(session, plain, sizeof(plain));
            free_session(session);
        }
        break;
    case TLS_OP_FEED:
        result = session ? append_input(session, &req->data, req->length)
                         : MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        break;
    default:
        result = MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        break;
    }
    respond(buf, header, operation, session_id, result, plain, length);
}
