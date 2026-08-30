#ifndef SOFTWARE_WIFI_TLS_COPROCESSOR_H_
#define SOFTWARE_WIFI_TLS_COPROCESSOR_H_

#include "cmd_buffer.h"
#include "tls_rpc.h"

int tls_coprocessor_init(void);
void tls_coprocessor_handle(command_buf_t *buf);

#endif
