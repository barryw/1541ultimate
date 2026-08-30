#ifndef TLS_SOCKET_H
#define TLS_SOCKET_H

#include <stddef.h>
#include <stdint.h>

#define TLS_SOCKET_HANDLE 0x80

bool tls_socket_is_handle(uint8_t handle);
void tls_socket_invalidate(void);
int tls_socket_prepare(void);
int tls_socket_open(int socket, const char *hostname);
int tls_socket_read(void *buffer, size_t length);
int tls_socket_write(const void *buffer, size_t length);
int tls_socket_close(void);

#endif
