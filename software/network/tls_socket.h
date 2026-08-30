#ifndef SOFTWARE_NETWORK_TLS_SOCKET_H_
#define SOFTWARE_NETWORK_TLS_SOCKET_H_

#include <stddef.h>
#include <stdint.h>
#include "cmd_buffer.h"
#include "network_socket.h"

class TlsSocket : public NetworkSocket {
    int socket_fd;
    int last_error;
    uint8_t session_id;
    bool active;
    uint8_t input[CMD_BUF_SIZE];
    uint8_t output[CMD_BUF_SIZE];

    TlsSocket(const TlsSocket &);
    TlsSocket &operator=(const TlsSocket &);

    int receive_encrypted(size_t capacity, unsigned long started, bool wait);
    int send_encrypted(const uint8_t *data, size_t length, unsigned long started);
    int feed(size_t length);
    int drain_output(unsigned long started);
    int send_output(size_t length, unsigned long started);
    int fail(int result);

public:
    explicit TlsSocket(int fd);
    ~TlsSocket();

    int handshake(const char *hostname);
    int error(void) const { return last_error; }
    int read(void *data, size_t length, bool *truncated);
    int write(const void *data, size_t length);
    int close(void);
};

#endif
