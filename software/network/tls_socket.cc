#include "tls_socket.h"

#include "filemanager.h"
#include "lwip/sockets.h"
#include "wifi_cmd.h"

#include "FreeRTOS.h"
#include "task.h"

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <time.h>

#define CA_DIRECTORY "/flash/data"
#define CA_FILENAME "custom-ca.pem"
#define CA_BUNDLE_MAX 4096
#define TLS_RPC_CHUNK 1400
#define TLS_WRITE_CHUNK 1024
#define TLS_TIMEOUT_MS 10000

static bool tls_active;
static bool ca_sent;
static int socket_fd = -1;
static uint8_t rpc_input[TLS_RPC_CHUNK + sizeof(uint16_t)];
static uint8_t rpc_output[CMD_BUF_SIZE];

static void zeroize(void *data, size_t length)
{
    volatile uint8_t *byte = (volatile uint8_t *)data;
    while (length--) {
        *byte++ = 0;
    }
}

static bool timed_out(TickType_t started)
{
    return (TickType_t)(xTaskGetTickCount() - started) >= pdMS_TO_TICKS(TLS_TIMEOUT_MS);
}

static int socket_send_all(const uint8_t *data, size_t length)
{
    while (length) {
        int sent = lwip_send(socket_fd, data, length, 0);
        if (sent <= 0) {
            return MBEDTLS_ERR_NET_SEND_FAILED;
        }
        data += sent;
        length -= sent;
    }
    return 0;
}

static int send_rpc_output(size_t length)
{
    int result = socket_send_all(rpc_output, length);
    while (result == 0 && length) {
        result = wifi_tls_exchange(TLS_OP_PULL, NULL, 0, rpc_output,
                                   sizeof(rpc_output), &length);
        if (result == 0 && length) {
            result = socket_send_all(rpc_output, length);
        }
    }
    return result;
}

static int send_ca_bundle(void)
{
    uint8_t *bundle = new uint8_t[CA_BUNDLE_MAX + 1];
    uint32_t length = 0;
    FRESULT file_result = FileManager::getFileManager()->load_file(
        CA_DIRECTORY, CA_FILENAME, bundle, CA_BUNDLE_MAX, &length);
    if (file_result != FR_OK && file_result != FR_NO_FILE) {
        delete[] bundle;
        return -1;
    }
    if (length == CA_BUNDLE_MAX) {
        zeroize(bundle, length);
        delete[] bundle;
        return -1;
    }

    int result = 0;
    if (file_result == FR_NO_FILE || length == 0) {
        result = wifi_tls_ca(NULL, 0, TLS_CA_RESET | TLS_CA_FINAL);
    }

    size_t offset = 0;
    while (offset < length && result == 0) {
        size_t chunk = length - offset;
        if (chunk > TLS_RPC_CHUNK) {
            chunk = TLS_RPC_CHUNK;
        }
        uint8_t flags = offset == 0 ? TLS_CA_RESET : 0;
        if (offset + chunk == length) {
            flags |= TLS_CA_FINAL;
        }
        result = wifi_tls_ca(bundle + offset, chunk, flags);
        offset += chunk;
    }
    zeroize(bundle, length);
    delete[] bundle;
    return result;
}

void tls_socket_invalidate(void)
{
    ca_sent = false;
}

int tls_socket_prepare(void)
{
    if (ca_sent) {
        return 0;
    }
    int result = send_ca_bundle();
    ca_sent = result == 0;
    return result;
}

bool tls_socket_is_handle(uint8_t handle)
{
    return handle == TLS_SOCKET_HANDLE;
}

int tls_socket_open(int socket, const char *hostname)
{
    if (tls_active || !hostname || !hostname[0]) {
        return -1;
    }

    socket_fd = socket;
    struct timeval timeout = {
        .tv_sec = TLS_TIMEOUT_MS / 1000,
        .tv_usec = (TLS_TIMEOUT_MS % 1000) * 1000
    };
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    int result = tls_socket_prepare();
    if (result == 0) {
        result = wifi_tls_start(hostname, (int64_t)time(NULL));
    }

    size_t input_length = 0;
    TickType_t started = xTaskGetTickCount();
    while (result == 0 || result == MBEDTLS_ERR_SSL_WANT_READ ||
           result == MBEDTLS_ERR_SSL_WANT_WRITE) {
        size_t output_length = 0;
        result = wifi_tls_exchange(TLS_OP_HANDSHAKE, rpc_input, input_length,
                                   rpc_output, sizeof(rpc_output), &output_length);
        input_length = 0;
        int send_result = send_rpc_output(output_length);
        if (send_result != 0) {
            result = send_result;
            break;
        }
        if (result == 0) {
            tls_active = true;
            return TLS_SOCKET_HANDLE;
        }
        if (timed_out(started)) {
            result = MBEDTLS_ERR_SSL_TIMEOUT;
            break;
        }
        if (result == MBEDTLS_ERR_SSL_WANT_READ) {
            int received = lwip_recv(socket_fd, rpc_input, TLS_RPC_CHUNK, 0);
            if (received <= 0) {
                result = MBEDTLS_ERR_NET_RECV_FAILED;
                break;
            }
            input_length = received;
        } else if (result != MBEDTLS_ERR_SSL_WANT_WRITE) {
            break;
        }
    }

    size_t ignored;
    wifi_tls_exchange(TLS_OP_CLOSE, NULL, 0, rpc_output,
                      sizeof(rpc_output), &ignored);
    socket_fd = -1;
    return result;
}

int tls_socket_read(void *buffer, size_t length)
{
    if (!tls_active) {
        errno = EBADF;
        return -1;
    }
    if (length > TLS_RPC_CHUNK) {
        length = TLS_RPC_CHUNK;
    }

    uint16_t requested = (uint16_t)length;
    memcpy(rpc_input, &requested, sizeof(requested));
    size_t output_length = 0;
    int result = wifi_tls_exchange(TLS_OP_READ, rpc_input, sizeof(requested),
                                   buffer, length, &output_length);
    if (result == MBEDTLS_ERR_SSL_WANT_READ) {
        int received = lwip_recv(socket_fd, rpc_input + sizeof(requested),
                                 TLS_RPC_CHUNK, 0);
        if (received <= 0) {
            errno = EIO;
            return -1;
        }
        memcpy(rpc_input, &requested, sizeof(requested));
        result = wifi_tls_exchange(TLS_OP_READ, rpc_input,
                                   received + sizeof(requested), buffer,
                                   length, &output_length);
    }
    if (result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        return 0;
    }
    if (result < 0) {
        errno = result == MBEDTLS_ERR_SSL_WANT_READ ? EWOULDBLOCK : EIO;
        return -1;
    }
    return (int)output_length;
}

int tls_socket_write(const void *buffer, size_t length)
{
    if (!tls_active) {
        errno = EBADF;
        return -1;
    }

    size_t written = 0;
    TickType_t started = xTaskGetTickCount();
    while (written < length) {
        size_t chunk = length - written;
        if (chunk > TLS_WRITE_CHUNK) {
            chunk = TLS_WRITE_CHUNK;
        }
        size_t output_length = 0;
        int result = wifi_tls_exchange(TLS_OP_WRITE,
                                       (const uint8_t *)buffer + written, chunk,
                                       rpc_output, sizeof(rpc_output), &output_length);
        int send_result = send_rpc_output(output_length);
        if (send_result != 0) {
            errno = EIO;
            return -1;
        }
        if (result > 0) {
            written += result;
        } else if ((result != MBEDTLS_ERR_SSL_WANT_READ &&
                    result != MBEDTLS_ERR_SSL_WANT_WRITE) || timed_out(started)) {
            errno = EIO;
            return -1;
        }
    }
    return (int)written;
}

int tls_socket_close(void)
{
    if (!tls_active) {
        errno = EBADF;
        return -1;
    }
    size_t output_length = 0;
    int tls_result = wifi_tls_exchange(TLS_OP_CLOSE, NULL, 0, rpc_output,
                                       sizeof(rpc_output), &output_length);
    if (output_length) {
        socket_send_all(rpc_output, output_length);
    }
    int result = lwip_close(socket_fd);
    socket_fd = -1;
    tls_active = false;
    return tls_result < 0 ? -1 : result;
}
