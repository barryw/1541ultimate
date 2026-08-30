#ifndef SOFTWARE_NETWORK_NETWORK_SOCKET_H_
#define SOFTWARE_NETWORK_NETWORK_SOCKET_H_

#include <stddef.h>

class NetworkSocket {
public:
    virtual ~NetworkSocket() {}
    virtual int read(void *data, size_t length, bool *truncated) = 0;
    virtual int write(const void *data, size_t length) = 0;
    virtual int close(void) = 0;
};

// The TLS translation unit registers this factory only on products whose
// communication coprocessor implements the TLS RPC. The factory owns fd.
typedef NetworkSocket *(*TlsSocketFactory)(int fd, const char *hostname, int *tls_error);
extern TlsSocketFactory tls_socket_factory;

#endif
