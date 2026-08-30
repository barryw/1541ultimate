#include "tls_coprocessor.h"
#include "rpc_calls.h"

#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define RPC_DATA_MAX (CMD_BUF_SIZE - offsetof(rpc_tls_req, data))

static command_buf_t command;

static int rpc(uint8_t operation, uint8_t flags, const void *input,
               size_t input_length, void *output, size_t output_capacity,
               size_t *output_length)
{
    assert(input_length <= RPC_DATA_MAX);
    memset(&command, 0, sizeof(command));
    rpc_tls_req *request = (rpc_tls_req *)command.data;
    request->hdr.command = CMD_TLS;
    request->hdr.thread = 3;
    request->hdr.sequence = 0x1234;
    request->operation = operation;
    request->flags = flags;
    request->length = (uint16_t)input_length;
    if (input_length) {
        memcpy(&request->data, input, input_length);
    }
    command.size = (int)(offsetof(rpc_tls_req, data) + input_length);

    tls_coprocessor_handle(&command);

    rpc_tls_resp *response = (rpc_tls_resp *)command.data;
    assert(response->hdr.command == CMD_TLS);
    assert(response->hdr.thread == 3);
    assert(response->hdr.sequence == 0x1234);
    assert(response->operation == operation);
    assert(response->length <= output_capacity);
    if (response->length) {
        memcpy(output, &response->data, response->length);
    }
    if (output_length) {
        *output_length = response->length;
    }
    return response->result;
}

static uint8_t *read_file(const char *path, size_t *length)
{
    FILE *file = fopen(path, "rb");
    assert(file);
    assert(fseek(file, 0, SEEK_END) == 0);
    long size = ftell(file);
    assert(size > 0);
    assert(fseek(file, 0, SEEK_SET) == 0);
    uint8_t *data = malloc((size_t)size);
    assert(data);
    assert(fread(data, 1, (size_t)size, file) == (size_t)size);
    fclose(file);
    *length = (size_t)size;
    return data;
}

static void load_ca(const char *path)
{
    size_t length;
    uint8_t *data = read_file(path, &length);
    assert(length <= 4096);
    size_t offset = 0;
    while (offset < length) {
        size_t chunk = length - offset;
        if (chunk > 1400) {
            chunk = 1400;
        }
        uint8_t flags = offset == 0 ? TLS_CA_RESET : 0;
        if (offset + chunk == length) {
            flags |= TLS_CA_FINAL;
        }
        assert(rpc(TLS_OP_CA, flags, data + offset, chunk, NULL, 0, NULL) == 0);
        offset += chunk;
    }
    free(data);
}

static int connect_tcp(const char *host, const char *port)
{
    struct addrinfo hints = { 0 };
    struct addrinfo *addresses = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    assert(getaddrinfo(host, port, &hints, &addresses) == 0);

    int socket_fd = -1;
    for (struct addrinfo *address = addresses; address; address = address->ai_next) {
        socket_fd = socket(address->ai_family, address->ai_socktype,
                           address->ai_protocol);
        if (socket_fd >= 0 &&
            connect(socket_fd, address->ai_addr, address->ai_addrlen) == 0) {
            break;
        }
        if (socket_fd >= 0) {
            close(socket_fd);
        }
        socket_fd = -1;
    }
    freeaddrinfo(addresses);
    assert(socket_fd >= 0);
    return socket_fd;
}

static void send_all(int socket_fd, const uint8_t *data, size_t length)
{
    while (length) {
        ssize_t sent = send(socket_fd, data, length, 0);
        assert(sent > 0);
        data += sent;
        length -= (size_t)sent;
    }
}

static void send_rpc_output(int socket_fd, uint8_t *output, size_t length)
{
    send_all(socket_fd, output, length);
    while (length) {
        int result = rpc(TLS_OP_PULL, 0, NULL, 0, output, RPC_DATA_MAX, &length);
        assert(result == 0);
        send_all(socket_fd, output, length);
    }
}

static int handshake(int socket_fd, const char *hostname)
{
    rpc_tls_start_data start = { 0 };
    start.unix_time = (int64_t)time(NULL);
    strncpy(start.hostname, hostname, sizeof(start.hostname) - 1);
    int result = rpc(TLS_OP_START, 0, &start, sizeof(start), NULL, 0, NULL);
    assert(result == 0);

    uint8_t input[1400];
    uint8_t output[RPC_DATA_MAX];
    size_t input_length = 0;
    for (int attempt = 0; attempt < 100; attempt++) {
        size_t output_length = 0;
        result = rpc(TLS_OP_HANDSHAKE, 0, input, input_length, output,
                     sizeof(output), &output_length);
        input_length = 0;
        send_rpc_output(socket_fd, output, output_length);
        if (result == 0) {
            return 0;
        }
        if (result != MBEDTLS_ERR_SSL_WANT_READ &&
            result != MBEDTLS_ERR_SSL_WANT_WRITE) {
            return result;
        }
        if (result == MBEDTLS_ERR_SSL_WANT_READ) {
            ssize_t received = recv(socket_fd, input, sizeof(input), 0);
            if (received <= 0) {
                return MBEDTLS_ERR_SSL_CONN_EOF;
            }
            input_length = (size_t)received;
        }
    }
    return MBEDTLS_ERR_SSL_TIMEOUT;
}

static void tls_write_all(int socket_fd, const uint8_t *plain, size_t length)
{
    uint8_t output[RPC_DATA_MAX];
    size_t written = 0;
    while (written < length) {
        size_t output_length = 0;
        int result = rpc(TLS_OP_WRITE, 0, plain + written, length - written,
                         output, sizeof(output), &output_length);
        send_rpc_output(socket_fd, output, output_length);
        assert(result > 0);
        written += (size_t)result;
    }
}

static size_t tls_read_once(int socket_fd, uint8_t *plain, size_t capacity)
{
    uint8_t request[RPC_DATA_MAX];
    uint8_t encrypted[1400];
    assert(capacity <= UINT16_MAX);
    uint16_t requested = (uint16_t)capacity;
    memcpy(request, &requested, sizeof(requested));

    for (int attempt = 0; attempt < 100; attempt++) {
        size_t plain_length = 0;
        int result = rpc(TLS_OP_READ, 0, request, sizeof(requested), plain,
                         capacity, &plain_length);
        if (result > 0) {
            return plain_length;
        }
        assert(result == MBEDTLS_ERR_SSL_WANT_READ);
        ssize_t received = recv(socket_fd, encrypted, sizeof(encrypted), 0);
        assert(received > 0);
        memcpy(request, &requested, sizeof(requested));
        memcpy(request + sizeof(requested), encrypted, (size_t)received);
        result = rpc(TLS_OP_READ, 0, request,
                     sizeof(requested) + (size_t)received, plain, capacity,
                     &plain_length);
        if (result > 0) {
            return plain_length;
        }
        assert(result == MBEDTLS_ERR_SSL_WANT_READ);
    }
    assert(!"TLS read timed out");
    return 0;
}

static void close_tls(int socket_fd)
{
    uint8_t output[RPC_DATA_MAX];
    size_t output_length = 0;
    int result = rpc(TLS_OP_CLOSE, 0, NULL, 0, output, sizeof(output),
                     &output_length);
    assert(result == 0 || result == MBEDTLS_ERR_SSL_WANT_WRITE);
    send_all(socket_fd, output, output_length);
    close(socket_fd);
}

static void test_invalid_rpc(void)
{
    memset(&command, 0, sizeof(command));
    command.size = 0;
    tls_coprocessor_handle(&command);
    rpc_tls_resp *response = (rpc_tls_resp *)command.data;
    assert(response->result == MBEDTLS_ERR_SSL_BAD_INPUT_DATA);

    rpc_tls_start_data start = { 0 };
    strcpy(start.hostname, "localhost");
    assert(rpc(TLS_OP_START, 0, &start, sizeof(start), NULL, 0, NULL) ==
           MBEDTLS_ERR_SSL_BAD_INPUT_DATA);

    uint8_t chunk[1400] = { 0 };
    assert(rpc(TLS_OP_CA, TLS_CA_RESET, chunk, sizeof(chunk), NULL, 0, NULL) == 0);
    assert(rpc(TLS_OP_CA, 0, chunk, sizeof(chunk), NULL, 0, NULL) == 0);
    assert(rpc(TLS_OP_CA, 0, chunk, sizeof(chunk), NULL, 0, NULL) ==
           MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL);
}

static void test_connection(const char *host, const char *port,
                            const char *hostname, int http)
{
    int socket_fd = connect_tcp(host, port);
    assert(handshake(socket_fd, hostname) == 0);

    static const uint8_t binary[] = {
        0x00, 0x01, 0x7f, 0x80, 0xff, 'U', 'L', 'T', 'I', 'M', 'A', 'T', 'E'
    };
    static const uint8_t request[] =
        "GET /test HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    const uint8_t *payload = http ? request : binary;
    size_t payload_length = http ? sizeof(request) - 1 : sizeof(binary);
    tls_write_all(socket_fd, payload, payload_length);

    uint8_t response[1024];
    size_t response_length = tls_read_once(socket_fd, response, sizeof(response));
    if (http) {
        assert(response_length >= 12);
        assert(memcmp(response, "HTTP/1.1 200", 12) == 0);
    } else {
        assert(response_length == sizeof(binary));
        assert(memcmp(response, binary, sizeof(binary)) == 0);
    }
    close_tls(socket_fd);
}

int main(int argc, char **argv)
{
    assert(argc == 6);
    const char *host = argv[1];
    const char *port = argv[2];
    const char *ca_path = argv[3];
    const char *hostname = argv[4];
    const char *mode = argv[5];

    assert(tls_coprocessor_init() == 0);
    assert(tls_coprocessor_init() == 0);
    test_invalid_rpc();
    load_ca(ca_path);

    if (strcmp(mode, "reject") == 0) {
        int socket_fd = connect_tcp(host, port);
        int result = handshake(socket_fd, hostname);
        assert(result == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED);
        close(socket_fd);
        puts("certificate rejection passed");
        return 0;
    }

    int http = strcmp(mode, "http") == 0;
    int repetitions = http ? 1 : 3;
    for (int i = 0; i < repetitions; i++) {
        test_connection(host, port, hostname, http);
    }
    puts(http ? "HTTPS passed" : "TLS binary and reconnect passed");
    return 0;
}
