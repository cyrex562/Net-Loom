#include "netloom_config.h"
#include "dns.h"
#include "eth_arp.h"
#include "igmp.h"
#include "init.h"
#include "ip.h"
#include "ip6.h"
#include "lwip_sockets.h"
#include "mld6.h"
#include "nd6.h"
#include "network_interface.h"
#include "packet.h"
#include "raw.h"
#include "netloom_sys.h"
#include "tcp_priv.h"
#include "timeouts.h"
#include "udp.h"
#include "netloom_debug.h"

#include "ppp_config.h"

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