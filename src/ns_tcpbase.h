///
/// file: tcpbase.h
/// 

#pragma once
#include <cstdint>

using TcpWndSize = uint32_t;

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

/// ATTENTION: this depends on state number ordering!
inline bool TcpStateIsClosing(const TcpState state) {
    return  state >= FIN_WAIT_1;
}

/// Flags for "apiflags" parameter in tcp_write
constexpr auto TCP_WRITE_FLAG_COPY = 0x01;
constexpr auto TCP_WRITE_FLAG_MORE = 0x02;

enum TcpPriority
{
    TCP_PRIO_MIN = 1,
    TCP_PRIO_NORMAL = 64,
    TCP_PRIO_MAX = 127,
};


const char* tcp_debug_state_str(enum TcpState s);

//
// END OF FILE
//
