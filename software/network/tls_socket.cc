#include "tls_socket.h"

#include "wifi_cmd.h"
#include "../wifi/tls_rpc.h"
#include "socket.h"
#include "FreeRTOS.h"
#include "task.h"

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <time.h>

#define TLS_IO_TIMEOUT_MS 10000
#define TLS_REQUEST_MAX (CMD_BUF_SIZE - offsetof(rpc_tls_req, data))
#define TLS_RESPONSE_MAX (CMD_BUF_SIZE - offsetof(rpc_tls_resp, data))

static bool tls_timed_out(unsigned long started)
{
    TickType_t elapsed = xTaskGetTickCount() - (TickType_t)started;
    return elapsed >= pdMS_TO_TICKS(TLS_IO_TIMEOUT_MS);
}

TlsSocket::TlsSocket(int fd)
    : socket_fd(fd), last_error(0), session_id(TLS_NEW_SESSION), active(false)
{
}

TlsSocket::~TlsSocket()
{
    close();
}

int TlsSocket::fail(int result)
{
    last_error = result;
    if (result == TLS_RESULT_TIMEOUT) {
        errno = ETIMEDOUT;
    } else if (result == TLS_RESULT_CLOSED) {
        errno = ECONNRESET;
    } else {
        errno = EIO;
    }
    return -1;
}

int TlsSocket::receive_encrypted(size_t capacity, unsigned long started, bool wait)
{
    do {
        int result = lwip_recv(socket_fd, input, capacity, MSG_DONTWAIT);
        if (result > 0) {
            return result;
        }
        if (result == 0) {
            errno = ECONNRESET;
            return -1;
        }
        if (errno != EWOULDBLOCK && errno != EAGAIN && errno != EINTR) {
            return -1;
        }
        if (!wait) {
            return -1;
        }
        vTaskDelay(1);
    } while (!tls_timed_out(started));
    errno = ETIMEDOUT;
    return -1;
}

int TlsSocket::send_encrypted(const uint8_t *data, size_t length,
                              unsigned long started)
{
    while (length && !tls_timed_out(started)) {
        int result = lwip_send(socket_fd, data, length, MSG_DONTWAIT);
        if (result > 0) {
            data += result;
            length -= result;
            continue;
        }
        if (result == 0) {
            errno = ECONNRESET;
            return -1;
        }
        if (errno != EWOULDBLOCK && errno != EAGAIN && errno != EINTR) {
            return -1;
        }
        vTaskDelay(1);
    }
    if (length) {
        errno = ETIMEDOUT;
        return -1;
    }
    return 0;
}

int TlsSocket::feed(size_t length)
{
    return wifi_tls_rpc(TLS_OP_FEED, session_id, 0, input, length,
                        NULL, 0, NULL, NULL);
}

int TlsSocket::drain_output(unsigned long started)
{
    size_t length;
    do {
        int result = wifi_tls_rpc(TLS_OP_PULL, session_id, 0, NULL, 0,
                                  output, TLS_RESPONSE_MAX, &length, NULL);
        if (result != 0) {
            return fail(result);
        }
        if (send_encrypted(output, length, started) < 0) {
            return -1;
        }
    } while (length == TLS_RESPONSE_MAX);
    return 0;
}

int TlsSocket::send_output(size_t length, unsigned long started)
{
    if (send_encrypted(output, length, started) < 0) {
        return -1;
    }
    return length == TLS_RESPONSE_MAX ? drain_output(started) : 0;
}

int TlsSocket::handshake(const char *hostname)
{
    rpc_tls_start_data start = { 0 };
    if (!hostname || !hostname[0] || strlen(hostname) >= sizeof(start.hostname) ||
        socket_fd < 0 || active) {
        errno = EINVAL;
        last_error = -EINVAL;
        return -1;
    }

    time_t now = time(NULL);
    if (now > 0 && (uint64_t)now <= UINT32_MAX) {
        start.unix_time = (uint32_t)now;
    }
    strcpy(start.hostname, hostname);

    uint8_t allocated = TLS_NEW_SESSION;
    int result = wifi_tls_rpc(TLS_OP_START, TLS_NEW_SESSION, 0,
                              &start, sizeof(start), NULL, 0, NULL, &allocated);
    if (result != 0 || allocated >= TLS_MAX_SESSIONS) {
        return fail(result);
    }
    session_id = allocated;
    active = true;

    unsigned long started = xTaskGetTickCount();
    size_t input_length = 0;
    while (!tls_timed_out(started)) {
        size_t output_length = 0;
        result = wifi_tls_rpc(TLS_OP_HANDSHAKE, session_id, 0,
                              input, input_length,
                              output, TLS_RESPONSE_MAX, &output_length, NULL);
        input_length = 0;
        if (send_output(output_length, started) < 0) {
            break;
        }
        if (result == 0) {
            return 0;
        }
        if (result == TLS_RESULT_WANT_WRITE) {
            continue;
        }
        if (result != TLS_RESULT_WANT_READ) {
            fail(result);
            break;
        }
        int received = receive_encrypted(TLS_REQUEST_MAX, started, true);
        if (received < 0) {
            break;
        }
        input_length = (size_t)received;
    }
    if (tls_timed_out(started)) {
        errno = ETIMEDOUT;
    }
    int saved_errno = errno ? errno : EIO;
    int saved_error = last_error ? last_error : -saved_errno;
    close();
    errno = saved_errno;
    last_error = saved_error;
    return -1;
}

int TlsSocket::write(const void *data, size_t length)
{
    if (!active || (!data && length) || length > INT_MAX) {
        errno = EINVAL;
        return -1;
    }

    const uint8_t *source = (const uint8_t *)data;
    size_t total = 0;
    unsigned long started = xTaskGetTickCount();
    while (total < length && !tls_timed_out(started)) {
        size_t chunk = length - total;
        if (chunk > TLS_REQUEST_MAX) {
            chunk = TLS_REQUEST_MAX;
        }
        size_t output_length = 0;
        int result = wifi_tls_rpc(TLS_OP_WRITE, session_id, 0,
                                  source + total, chunk,
                                  output, TLS_RESPONSE_MAX, &output_length, NULL);
        if (send_output(output_length, started) < 0) {
            return -1;
        }
        if (result > 0) {
            if ((size_t)result > chunk) {
                return fail(result);
            }
            total += (size_t)result;
            continue;
        }
        if (result == TLS_RESULT_WANT_WRITE) {
            continue;
        }
        if (result == TLS_RESULT_WANT_READ) {
            int received = receive_encrypted(TLS_REQUEST_MAX, started, true);
            if (received < 0) {
                return -1;
            }
            result = feed((size_t)received);
            if (result == 0) {
                continue;
            }
        }
        return fail(result);
    }
    if (total != length) {
        errno = ETIMEDOUT;
        return -1;
    }
    return (int)total;
}

int TlsSocket::read(void *data, size_t length, bool *truncated)
{
    if (!active || (!data && length)) {
        errno = EINVAL;
        return -1;
    }
    if (!length) {
        return 0;
    }
    if (truncated) {
        *truncated = false;
    }

    uint16_t requested = length > TLS_RESPONSE_MAX
                             ? (uint16_t)TLS_RESPONSE_MAX
                             : (uint16_t)length;
    unsigned long started = xTaskGetTickCount();
    while (!tls_timed_out(started)) {
        size_t plain_length = 0;
        int result = wifi_tls_rpc(TLS_OP_READ, session_id, 0,
                                  &requested, sizeof(requested),
                                  data, requested, &plain_length, NULL);
        if (drain_output(started) < 0) {
            return -1;
        }
        if (result > 0) {
            if ((size_t)result != plain_length) {
                return fail(result);
            }
            return result;
        }
        if (result == 0) {
            return 0;
        }
        if (result == TLS_RESULT_CLOSED) {
            return 0;
        }
        if (result == TLS_RESULT_WANT_WRITE) {
            continue;
        }
        if (result != TLS_RESULT_WANT_READ) {
            return fail(result);
        }
        int received = receive_encrypted(TLS_REQUEST_MAX, started, false);
        if (received < 0) {
            return -1;
        }
        result = feed((size_t)received);
        if (result != 0) {
            return fail(result);
        }
    }
    errno = ETIMEDOUT;
    return -1;
}

int TlsSocket::close(void)
{
    int status = 0;
    if (active) {
        size_t length = 0;
        unsigned long started = xTaskGetTickCount();
        int result = wifi_tls_rpc(TLS_OP_CLOSE, session_id, 0, NULL, 0,
                                  output, TLS_RESPONSE_MAX, &length, NULL);
        if (send_output(length, started) < 0 ||
            (result != 0 && result != TLS_RESULT_CLOSED)) {
            status = -1;
        }
        active = false;
        session_id = TLS_NEW_SESSION;
    }
    if (socket_fd >= 0) {
        lwip_shutdown(socket_fd, 2);
        if (lwip_close(socket_fd) < 0) {
            status = -1;
        }
        socket_fd = -1;
    }
    return status;
}

static NetworkSocket *create_tls_socket(int fd, const char *hostname, int *tls_error)
{
    TlsSocket *socket = new TlsSocket(fd);
    if (socket->handshake(hostname) == 0) {
        return socket;
    }
    if (tls_error) {
        *tls_error = socket->error();
    }
    int saved_errno = errno;
    delete socket;
    errno = saved_errno;
    return NULL;
}

class TlsSocketRegistration {
public:
    TlsSocketRegistration() { tls_socket_factory = create_tls_socket; }
};

static TlsSocketRegistration tls_socket_registration;
