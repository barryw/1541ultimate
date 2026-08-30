#ifndef TLS_RPC_H
#define TLS_RPC_H

typedef struct {
    rpc_header_t hdr;
    uint8_t operation;
    uint8_t flags;
    uint16_t length;
    uint8_t data;
} rpc_tls_req;

typedef struct {
    rpc_header_t hdr;
    uint8_t operation;
    uint8_t reserved;
    uint16_t length;
    int32_t result;
    uint8_t data;
} rpc_tls_resp;

typedef struct {
    int64_t unix_time;
    char hostname[128];
} rpc_tls_start_data;

#define CMD_TLS               0x17

#define TLS_OP_CA             0
#define TLS_OP_START          1
#define TLS_OP_HANDSHAKE      2
#define TLS_OP_PULL           3
#define TLS_OP_WRITE          4
#define TLS_OP_READ           5
#define TLS_OP_CLOSE          6

#define TLS_CA_RESET          0x01
#define TLS_CA_FINAL          0x02

#endif
