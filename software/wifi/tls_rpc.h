#ifndef SOFTWARE_WIFI_TLS_RPC_H_
#define SOFTWARE_WIFI_TLS_RPC_H_

#include <stddef.h>
#include <stdint.h>
#include "rpc_calls.h"

typedef struct {
    rpc_header_t hdr;
    uint8_t operation;
    uint8_t session;
    uint8_t flags;
    uint8_t reserved;
    uint16_t length;
    uint8_t data;
} rpc_tls_req;

typedef struct {
    rpc_header_t hdr;
    uint8_t operation;
    uint8_t session;
    uint16_t length;
    int32_t result;
    uint8_t data;
} rpc_tls_resp;

typedef struct {
    uint32_t unix_time;
    char hostname[128];
} rpc_tls_start_data;

#define CMD_TLS               0x1A

#define TLS_OP_CA             0
#define TLS_OP_START          1
#define TLS_OP_HANDSHAKE      2
#define TLS_OP_PULL           3
#define TLS_OP_WRITE          4
#define TLS_OP_READ           5
#define TLS_OP_CLOSE          6
#define TLS_OP_FEED           7

#define TLS_NEW_SESSION       0xFF
#define TLS_MAX_SESSIONS      4

#define TLS_CA_RESET          0x01
#define TLS_CA_FINAL          0x02

#define TLS_ERR_NO_SESSION    (-1)
#define TLS_ERR_INVALID_TIME  (-2)
#define TLS_ERR_CA_IN_USE     (-3)

#define TLS_RESULT_WANT_READ  (-0x10001)
#define TLS_RESULT_WANT_WRITE (-0x10002)
#define TLS_RESULT_CLOSED     (-0x10003)
#define TLS_RESULT_TIMEOUT    (-0x10004)

#ifdef __cplusplus
#if __cplusplus >= 201103L
static_assert(offsetof(rpc_tls_req, data) == 10, "TLS request wire layout changed");
static_assert(offsetof(rpc_tls_resp, data) == 12, "TLS response wire layout changed");
static_assert(sizeof(rpc_tls_start_data) == 132, "TLS start wire layout changed");
#else
typedef char tls_request_wire_layout[(offsetof(rpc_tls_req, data) == 10) ? 1 : -1];
typedef char tls_response_wire_layout[(offsetof(rpc_tls_resp, data) == 12) ? 1 : -1];
typedef char tls_start_wire_layout[(sizeof(rpc_tls_start_data) == 132) ? 1 : -1];
#endif
#else
_Static_assert(offsetof(rpc_tls_req, data) == 10, "TLS request wire layout changed");
_Static_assert(offsetof(rpc_tls_resp, data) == 12, "TLS response wire layout changed");
_Static_assert(sizeof(rpc_tls_start_data) == 132, "TLS start wire layout changed");
#endif

#endif
