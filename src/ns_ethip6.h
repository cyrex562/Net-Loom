///
/// ethip6.h
///
#pragma once
#include "ns_ip6.h"
#include "ns_ip6_addr.h"
#include "ns_packet.h"

NsStatus
ethip6_output(NetworkInterface& net_ifc,
              PacketContainer& pkt_buf,
              const Ip6Addr& ip6_addr);

//
// END OF FILE
//
