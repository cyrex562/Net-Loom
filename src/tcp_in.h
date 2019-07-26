#pragma once
void
tcp_listen_input(struct TcpPcbListen* pcb);
/// Initial CWND calculation as defined RFC 2581
inline TcpWndSize
lwip_tcp_calc_initial_cwnd(const uint16_t mss)
{
    return TcpWndSize(std::min((4U * (mss)), std::max((2U * (mss)), 4380U)));
}

LwipStatus
tcp_process(struct TcpPcb* pcb);
void
tcp_receive(struct TcpPcb* pcb);
void
tcp_parseopt(struct TcpPcb* pcb);
void
tcp_timewait_input(struct TcpPcb* pcb);
int
tcp_input_delayed_close(struct TcpPcb* pcb);
void
tcp_add_sack(struct TcpPcb* pcb, uint32_t left, uint32_t right);
void
tcp_remove_sacks_lt(struct TcpPcb* pcb, uint32_t seq);
void
tcp_remove_sacks_gt(TcpPcb* pcb, uint32_t seq); //
// END OF FILE
//
