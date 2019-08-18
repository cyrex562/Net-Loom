///
/// ethip6.h
/// 


#pragma once
#include <ip6.h>

#include <ip6_addr.h>

#include <packet_buffer.h>

LwipStatus ethip6_output(NetworkInterface& net_ifc, PacketBuffer& pkt_buf, const Ip6Addr& ip6_addr);

//
// END OF FILE
//
