#pragma once
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t TcpWndSizeT;


enum TcpState {
  CLOSED      = 0,
  LISTEN      = 1,
  SYN_SENT    = 2,
  SYN_RCVD    = 3,
  ESTABLISHED = 4,
  FIN_WAIT_1  = 5,
  FIN_WAIT_2  = 6,
  CLOSE_WAIT  = 7,
  CLOSING     = 8,
  LAST_ACK    = 9,
  TIME_WAIT   = 10
};

/* ATTENTION: this depends on state number ordering! */
inline bool TcpStateIsClosing(const TcpState state) {
    return  state >= FIN_WAIT_1;
}

/* Flags for "apiflags" parameter in tcp_write */
#define TCP_WRITE_FLAG_COPY 0x01
#define TCP_WRITE_FLAG_MORE 0x02

#define TCP_PRIO_MIN    1
#define TCP_PRIO_NORMAL 64
#define TCP_PRIO_MAX    127

const char* tcp_debug_state_str(enum TcpState s);

#ifdef __cplusplus
}
#endif

