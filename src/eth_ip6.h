///
/// ethip6.h
///
#pragma once
#include "ip6.h"
#include "ip6_addr.h"
#include "packet.h"

NsStatus
ethip6_output(NetworkInterface& net_ifc,
              PacketContainer& pkt_buf,
              const Ip6Addr& ip6_addr);

//
// END OF FILE
//
