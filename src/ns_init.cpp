#include "ns_config.h"
#include "ns_dns.h"
#include "ns_etharp.h"
#include "igmp.h"
#include "init.h"
#include "ns_ip.h"
#include "ns_ip6.h"
#include "lwip_sockets.h"
#include "mld6.h"
#include "nd6.h"
#include "ns_network_interface.h"
#include "ns_packet.h"
#include "raw.h"
#include "ns_sys.h"
#include "tcp_priv.h"
#include "ns_timeouts.h"
#include "ns_udp.h"
#include "ns_debug.h"

#include "ns_ppp_config.h"

/**
 * @ingroup lwip_nosys
 * Initialize all modules.
 * Use this in NO_SYS mode. Use tcpip_init() otherwise.
 */
void lwip_init(void)
{
    auto a = 0;
    sys_init();
    pbuf_init();
    // netif_init();
    init_ip4_module();
    etharp_init();
    raw_init();
    udp_init();
    tcp_init();
    init_igmp_module();
    dns_init();
    init_ppp_subsys();
    sys_timeouts_init();
}

//
// END OF FILE
//