#include <opt.h>
#include <dns.h>
#include <etharp.h>
#include <igmp.h>
#include <init.h>
#include <ip.h>
#include <ip6.h>
#include <lwip_sockets.h>
#include <mld6.h>
#include <nd6.h>
#include <netif.h>
#include <packet_buffer.h>
#include <raw.h>
#include <sys.h>
#include <tcp_priv.h>
#include <timeouts.h>
#include <udp.h>
#include <lwip_debug.h>
#include <ppp_impl.h>
#include <ppp_opts.h>

/**
 * @ingroup lwip_nosys
 * Initialize all modules.
 * Use this in NO_SYS mode. Use tcpip_init() otherwise.
 */
void lwip_init(void)
{
    auto a = 0;; /* Modules initialization */
    sys_init();
    pbuf_init();
    // netif_init();
    ip_init();
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