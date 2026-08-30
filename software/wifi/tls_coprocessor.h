#ifndef TLS_COPROCESSOR_H
#define TLS_COPROCESSOR_H

#include "cmd_buffer.h"

int tls_coprocessor_init(void);
void tls_coprocessor_handle(command_buf_t *buf);

#endif
