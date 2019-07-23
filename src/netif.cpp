//
// file: netif.cpp
//

#include <netif.h>
#include <opt.h>
#include <def.h>
#include <ip_addr.h>
#include <ip6_addr.h>
#include <tcp_priv.h>
#include <udp.h>
#include <raw_priv.h>
#include <igmp.h>
#include <etharp.h>
#include <sys.h>
#include <ip.h>
#include <ethernet.h>
#include <lwip_debug.h>
#include <lwip_status.h>
#include <tcpip.h>
#include <autoip.h>
#include <dhcp6.h>
#include <mld6.h>
#include <nd6.h>
#include <cstring> /* memset */
#include <cstdlib> /* atoi */

inline void NETIF_STATUS_CALLBACK(NetIfc* n)
{
    if (n->status_callback)
    {
        (n->status_callback)(n);
    }
}

inline void NETIF_LINK_CALLBACK(NetIfc* n)
{
    if (n->link_callback)
    {
        (n->link_callback)(n);
    }
}

static netif_ext_callback_t *ext_callback;

NetIfc*netif_list;

NetIfc*netif_default;
//
// #define netif_index_to_num(index)   ((index) - 1)
static uint8_t netif_num;

static uint8_t netif_client_id;


constexpr auto NETIF_REPORT_TYPE_IPV4 = 0x01;
constexpr auto NETIF_REPORT_TYPE_IPV6 = 0x02;
static void netif_issue_reports(NetIfc*netif, uint8_t report_type);

static LwipStatus netif_null_output_ip6(NetIfc*netif, struct PacketBuffer *p, const Ip6Addr*ipaddr);

static LwipStatus netif_null_output_ip4(NetIfc*netif, struct PacketBuffer *p, const Ip4Addr *ipaddr);

static LwipStatus netif_loop_output_ipv4(NetIfc*netif, struct PacketBuffer *p, const Ip4Addr *addr);

static LwipStatus netif_loop_output_ipv6(NetIfc*netif, struct PacketBuffer *p, const Ip6Addr*addr);



// static NetIfc* loop_netif;

/**
 * Initialize a lwip network interface structure for a loopback interface
 *
 * @param netif the lwip network interface structure for this loopif
 * @return ERR_OK if the loopif is initialized
 *         ERR_MEM if private data couldn't be allocated
 */
static LwipStatus
netif_loopif_init(NetIfc*netif)
{
  lwip_assert("netif_loopif_init: invalid netif", netif != nullptr);

  /* initialize the snmp variables and counters inside the NetIfc*
   * ifSpeed: no assumption can be made!
   */
  // MIB2_INIT_NETIF(netif, snmp_ifType_softwareLoopback, 0);

  netif->name[0] = 'l';
  netif->name[1] = 'o';
  netif->output = netif_loop_output_ipv4;
  netif->output_ip6 = netif_loop_output_ipv6;
  netif_set_flags(netif, NETIF_FLAG_IGMP);
  // NETIF_SET_CHECKSUM_CTRL(netif, NETIF_CHECKSUM_DISABLE_ALL);
  return ERR_OK;
}

void netif_init(NetIfc* loop_netif)
{
    Ip4Addr loop_ipaddr{};
    Ip4Addr loop_netmask{};
    Ip4Addr loop_gw{};
    Ipv4AddrFromBytes(&loop_gw, 127, 0, 0, 1);
    Ipv4AddrFromBytes(&loop_ipaddr, 127, 0, 0, 1);
    Ipv4AddrFromBytes(&loop_netmask, 255, 0, 0, 0);
    netif_add(loop_netif,
              &loop_ipaddr,
              &loop_netmask,
              &loop_gw,
              nullptr,
              netif_loopif_init,
              tcpip_input);
    ip_addr_ip6_host(loop_netif.ip6_addr, 0, 0, 0, 0x00000001UL);
    loop_netif.ip6_addr_state[0] = IP6_ADDR_VALID;
    netif_set_link_up(&loop_netif);
    netif_set_up(&loop_netif);
}

/**
 * @ingroup lwip_nosys
 * Forwards a received packet for input processing with
 * ethernet_input() or ip_input() depending on netif flags.
 * Don't call directly, pass to netif_add() and call
 * netif->input().
 * Only works if the netif driver correctly sets
 * NETIF_FLAG_ETHARP and/or NETIF_FLAG_ETHERNET flag!
 */
LwipStatus
netif_input(struct PacketBuffer *p, NetIfc*inp)
{
 

  lwip_assert("netif_input: invalid pbuf", p != nullptr);
  lwip_assert("netif_input: invalid netif", inp != nullptr);

  if (inp->flags & (NETIF_FLAG_ETH_ARP | NETIF_FLAG_ETH)) {
    return ethernet_input(p, inp);
  } else

    return ip_input(p, inp);
}

/**
 * @ingroup netif
 * Add a network interface to the list of lwIP netifs.
 *
 * Same as @ref netif_add but without IPv4 addresses
 */
NetIfc*
netif_add_noaddr(NetIfc*netif, uint8_t *state, NetifInitFn init, NetifInputFn input)
{
  return netif_add(netif,

                   nullptr, nullptr, nullptr,

                   state, init, input);
}

///
/// @ingroup netif
/// Add a network interface to the list of lwIP netifs.
///
/// @param netif a pre-allocated netif structure
/// @param ipaddr IP address for the new netif
/// @param netmask network mask for the new netif
///@param gw default gateway IP address for the new netif
///@param state opaque data passed to the new netif
///@param init callback function that initializes the interface
///@param input callback function that is called to pass
//ingress packets up in the protocol layer stack.\n
// It is recommended to use a function that passes the input directly
// to the stack (netif_input(), NO_SYS=1 mode) or via sending a
// message to TCPIP thread (tcpip_input(), NO_SYS=0 mode).\n
// These functions use netif flags NETIF_FLAG_ETHARP and NETIF_FLAG_ETHERNET
// to decide whether to forward to ethernet_input() or ip_input().
// In other words, the functions only work when the netif
// driver is implemented correctly!\n
// Most members of NetIfc* should be be initialized by the
// netif init function = netif driver (init parameter of this function).\n
// IPv6: Don't forget to call netif_create_ip6_linklocal_address() after
// setting the MAC address in NetIfc*.hwaddr
// (IPv6 requires a link-local address).
//
// @return netif, or NULL if failed.
//
NetIfc* netif_add(NetIfc* netif,
                  const Ip4Addr* ipaddr,
                  const Ip4Addr* netmask,
                  const Ip4Addr* gw,
                  uint8_t* state,
                  NetifInitFn init,
                  NetifInputFn input)
{
   
    if (netif_default != nullptr)
    {
        lwip_assert("single netif already set", 0);
        return nullptr;
    } // 
    if (netif == nullptr)
    {
        return nullptr;
    } // 
    if (ipaddr == nullptr)
    {

        ipaddr = convert_ip_addr_to_ip4_addr(create_ip4_addr_any);
    }
    if (netmask == nullptr)
    {
        netmask = convert_ip_addr_to_ip4_addr(create_ip4_addr_any);
    }
    if (gw == nullptr)
    {
        gw = convert_ip_addr_to_ip4_addr(create_ip4_addr_any);
    } /* reset new interface configuration state */
    zerp_ip_addr_ip4(&netif->ip_addr);
    zerp_ip_addr_ip4(&netif->netmask);
    zerp_ip_addr_ip4(&netif->gw);
    netif->output = netif_null_output_ip4;
    for (int8_t i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++)
    {
        zero_ip_addr_ip6(&netif->ip6_addr[i]);
        netif->ip6_addr_state[i] = IP6_ADDR_INVALID;
        netif->ip6_addr_valid_life[i] = (0);
        netif->ip6_addr_pref_life[i] = (0);
    }
    netif->output_ip6 = netif_null_output_ip6;
    NETIF_SET_CHECKSUM_CTRL(netif, NETIF_CHECKSUM_ENABLE_ALL);
    netif->mtu = 0;
    netif->flags = 0;
    memset(netif->client_data, 0, sizeof(netif->client_data));
    /* IPv6 address autoconfiguration not enabled by default */
    netif->ip6_autoconfig_enabled = 0;
    nd6_restart_netif(netif);
    netif->status_callback = nullptr;
    netif->link_callback = nullptr;
    netif->igmp_mac_filter = nullptr;
    netif->mld_mac_filter = nullptr;
    netif->loop_first = nullptr;
    netif->loop_last = nullptr; /* remember netif specific state information data */
    netif->state = state;
    netif->num = netif_num;
    netif->input = input;
    NETIF_RESET_HINTS(netif);
    netif->loop_cnt_current = 0;
    netif_set_addr(netif, ipaddr, netmask, gw);
    /* call user specified initialization function for netif */
    if (init(netif) != ERR_OK)
    {
        return nullptr;
    } /* Initialize the MTU for IPv6 to the one set by the netif driver.
     This can be updated later by RA. */
    netif->mtu6 = netif->mtu;
    /* Assign a unique netif number in the range [0..254], so that (num+1) can
        serve as an interface index that fits in a uint8_t.
        We assume that the new netif has not yet been added to the list here.
        This algorithm is O(n^2), but that should be OK for lwIP.
        */
    {
        NetIfc* netif2;
        int num_netifs;
        do
        {
            if (netif->num == 255)
            {
                netif->num = 0;
            }
            num_netifs = 0;
            for (netif2 = netif_list; netif2 != nullptr; netif2 = netif2->next)
            {
                lwip_assert("netif already added", netif2 != netif);
                num_netifs++;
                lwip_assert("too many netifs, max. supported number is 255",
                            num_netifs <= 255);
                if (netif2->num == netif->num)
                {
                    netif->num++;
                    break;
                }
            }
        }
        while (netif2 != nullptr);
    }
    if (netif->num == 254)
    {
        netif_num = 0;
    }
    else
    {
        netif_num = (uint8_t)(netif->num + 1);
    } /* add this netif to the list */
    netif->next = netif_list;
    netif_list = netif;
    mib2_netif_added(netif); /* start IGMP processing */
    if (netif->flags & NETIF_FLAG_IGMP)
    {
        igmp_start(netif);
    }
    Logf(NETIF_DEBUG, ("netif: added interface %c%c IP", netif->name[0], netif->name[1]));
    Logf(NETIF_DEBUG, (" addr "));
    ip4_addr_debug_print(NETIF_DEBUG, ipaddr)
    ;
    Logf(NETIF_DEBUG, (" netmask "));
    ip4_addr_debug_print(NETIF_DEBUG, netmask)
    ;
    Logf(NETIF_DEBUG, (" gw "));
    ip4_addr_debug_print(NETIF_DEBUG, gw)
    ;
    Logf(NETIF_DEBUG, ("\n"));
    netif_invoke_ext_callback(netif, LWIP_NSC_NETIF_ADDED, nullptr);
    return netif;
}

static void
netif_do_ip_addr_changed(const IpAddr *old_addr, const IpAddr *new_addr)
{

  tcp_netif_ip_addr_changed(old_addr, new_addr);

  udp_netif_ip_addr_changed(old_addr, new_addr);

  raw_netif_ip_addr_changed(old_addr, new_addr);

}

static int
netif_do_set_ipaddr(NetIfc*netif, const Ip4Addr *ipaddr, IpAddr *old_addr)
{
  lwip_assert("invalid pointer", ipaddr != nullptr);
  lwip_assert("invalid pointer", old_addr != nullptr);

  /* address is actually being changed? */
  if (ip4_addr_cmp(ipaddr, get_net_ifc_ip4_addr(netif)) == 0) {
    IpAddr new_addr;
    *convert_ip_addr_to_ip4_addr(&new_addr) = *ipaddr;
    IP_SET_TYPE_VAL(new_addr, IPADDR_TYPE_V4);

    copy_ip_addr(*old_addr, *netif_ip_addr4(netif));

    Logf(NETIF_DEBUG | LWIP_DBG_STATE, ("netif_set_ipaddr: netif address being changed\n"));
    netif_do_ip_addr_changed(old_addr, &new_addr);

    mib2_remove_ip4(netif);
    mib2_remove_route_ip4(0, netif);
    /* set new IP address to netif */
    ip4_addr_set(convert_ip_addr_to_ip4_addr(&netif->ip_addr), ipaddr);
    IP_SET_TYPE_VAL(netif->ip_addr, IPADDR_TYPE_V4);
    mib2_add_ip4(netif);
    mib2_add_route_ip4(0, netif);

    netif_issue_reports(netif, NETIF_REPORT_TYPE_IPV4);

    NETIF_STATUS_CALLBACK(netif);
    return 1; /* address changed */
  }
  return 0; /* address unchanged */
}

/**
 * @ingroup netif_ip4
 * Change the IP address of a network interface
 *
 * @param netif the network interface to change
 * @param ipaddr the new IP address
 *
 * @note call netif_set_addr() if you also want to change netmask and
 * default gateway
 */
void
netif_set_ipaddr(NetIfc*netif, const Ip4Addr *ipaddr)
{
  IpAddr old_addr;

  

  /* Don't propagate NULL pointer (IPv4 ANY) to subsequent functions */
  if (ipaddr == nullptr) {
    ipaddr = IP4_ADDR_ANY4;
  }

 

  if (netif_do_set_ipaddr(netif, ipaddr, &old_addr)) {

    netif_ext_callback_args_t args;
    args.ipv4_changed.old_address = &old_addr;
    netif_invoke_ext_callback(netif, LWIP_NSC_IPV4_ADDRESS_CHANGED, &args);

  }
}

static int
netif_do_set_netmask(NetIfc*netif, const Ip4Addr *netmask, IpAddr *old_nm)
{
  /* address is actually being changed? */
  if (ip4_addr_cmp(netmask, netif_ip4_netmask(netif)) == 0) {
    lwip_assert("invalid pointer", old_nm != nullptr);
    ip_addr_copy(*old_nm, *netif_ip_netmask4(netif));

    mib2_remove_route_ip4(0, netif);
    /* set new netmask to netif */
    ip4_addr_set(convert_ip_addr_to_ip4_addr(&netif->netmask), netmask);
    IP_SET_TYPE_VAL(netif->netmask, IPADDR_TYPE_V4);
    mib2_add_route_ip4(0, netif);
//    Logf(NETIF_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("netif: netmask of interface %c%c set to %d.%d.%d.%d\n",
//                netif->name[0], netif->name[1],
//                ip4_addr1_16(netif_ip4_netmask(netif)),
//                ip4_addr2_16(netif_ip4_netmask(netif)),
//                ip4_addr3_16(netif_ip4_netmask(netif)),
//                ip4_addr4_16(netif_ip4_netmask(netif))));
    return 1; /* netmask changed */
  }
  return 0; /* netmask unchanged */
}

/**
 * @ingroup netif_ip4
 * Change the netmask of a network interface
 *
 * @param netif the network interface to change
 * @param netmask the new netmask
 *
 * @note call netif_set_addr() if you also want to change ip address and
 * default gateway
 */
void
netif_set_netmask(NetIfc*netif, const Ip4Addr *netmask)
{

  IpAddr old_nm_val;
  IpAddr *old_nm = &old_nm_val;

 

  

  /* Don't propagate NULL pointer (IPv4 ANY) to subsequent functions */
  if (netmask == nullptr) {
    netmask = IP4_ADDR_ANY4;
  }

  if (netif_do_set_netmask(netif, netmask, old_nm)) {

    netif_ext_callback_args_t args;
    args.ipv4_changed.old_netmask = old_nm;
    netif_invoke_ext_callback(netif, LWIP_NSC_IPV4_NETMASK_CHANGED, &args);

  }
}

static int
netif_do_set_gw(NetIfc*netif, const Ip4Addr *gw, IpAddr *old_gw)
{
  /* address is actually being changed? */
  if (ip4_addr_cmp(gw, netif_ip4_gw(netif)) == 0) {

    lwip_assert("invalid pointer", old_gw != nullptr);
    ip_addr_copy(*old_gw, *netif_ip_gw4(netif));


    ip4_addr_set(convert_ip_addr_to_ip4_addr(&netif->gw), gw);
    IP_SET_TYPE_VAL(netif->gw, IPADDR_TYPE_V4);
//    Logf(NETIF_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("netif: GW address of interface %c%c set to %d.%d.%d.%d\n",
//                netif->name[0], netif->name[1],
//                ip4_addr1_16(netif_ip4_gw(netif)),
//                ip4_addr2_16(netif_ip4_gw(netif)),
//                ip4_addr3_16(netif_ip4_gw(netif)),
//                ip4_addr4_16(netif_ip4_gw(netif))));
    return 1; /* gateway changed */
  }
  return 0; /* gateway unchanged */
}

/**
 * @ingroup netif_ip4
 * Change the default gateway for a network interface
 *
 * @param netif the network interface to change
 * @param gw the new default gateway
 *
 * @note call netif_set_addr() if you also want to change ip address and netmask
 */
void
netif_set_gw(NetIfc*netif, const Ip4Addr *gw)
{

  IpAddr old_gw_val;
  IpAddr *old_gw = &old_gw_val;

 

  

  /* Don't propagate NULL pointer (IPv4 ANY) to subsequent functions */
  if (gw == nullptr) {
    gw = IP4_ADDR_ANY4;
  }

  if (netif_do_set_gw(netif, gw, old_gw)) {

    netif_ext_callback_args_t args;
    args.ipv4_changed.old_gw = old_gw;
    netif_invoke_ext_callback(netif, LWIP_NSC_IPV4_GATEWAY_CHANGED, &args);

  }
}

/**
 * @ingroup netif_ip4
 * Change IP address configuration for a network interface (including netmask
 * and default gateway).
 *
 * @param netif the network interface to change
 * @param ipaddr the new IP address
 * @param netmask the new netmask
 * @param gw the new default gateway
 */
bool netif_set_addr(NetIfc* netif,
                    const Ip4Addr* ipaddr,
                    const Ip4Addr* netmask,
                    const Ip4Addr* gw)
{
    IpAddr* old_nm = nullptr;
    IpAddr* old_gw = nullptr;
    IpAddr old_addr;
   
    /* Don't propagate NULL pointer (IPv4 ANY) to subsequent functions */
    if (ipaddr == nullptr)
    {
        ipaddr = IP4_ADDR_ANY4;
    }
    if (netmask == nullptr)
    {
        netmask = IP4_ADDR_ANY4;
    }
    if (gw == nullptr)
    {
        gw = IP4_ADDR_ANY4;
    }
    int remove = ip4_addr_isany(ipaddr);
    if (remove)
    {
        /* when removing an address, we have to remove it *before* changing netmask/gw
           to ensure that tcp RST segment can be sent correctly */
        if (netif_do_set_ipaddr(netif, ipaddr, &old_addr))
        {
        }
    }
    if (netif_do_set_netmask(netif, netmask, old_nm))
    {
    }
    if (netif_do_set_gw(netif, gw, old_gw))
    {
    }
    if (!remove)
    {
        /* set ipaddr last to ensure netmask/gw have been set when status callback is called */
        if (netif_do_set_ipaddr(netif, ipaddr, &old_addr))
        {
        }
    }
}


/**
 * @ingroup netif
 * Remove a network interface from the list of lwIP netifs.
 *
 * @param netif the network interface to remove
 */
void
netif_remove(NetIfc*netif)
{

  int i;


 

  if (netif == nullptr) {
    return;
  }

  netif_invoke_ext_callback(netif, LWIP_NSC_NETIF_REMOVED, nullptr);

  if (!ip4_addr_isany_val(*get_net_ifc_ip4_addr(netif))) {
    netif_do_ip_addr_changed(netif_ip_addr4(netif), nullptr);
  }

  /* stop IGMP processing */
  if (netif->flags & NETIF_FLAG_IGMP) {
    igmp_stop(netif);
  }

  for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
    if (ip6_addr_isvalid(netif_ip6_addr_state(netif, i))) {
      netif_do_ip_addr_changed(netif_ip_addr6(netif, i), nullptr);
    }
  }

  /* stop MLD processing */
  mld6_stop(netif);

  if (netif_is_up(netif)) {
    /* set netif down before removing (call callback function) */
    netif_set_down(netif);
  }

  mib2_remove_ip4(netif);

  /* this netif is default? */
  if (netif_default == netif) {
    /* reset default netif */
    netif_set_default(nullptr);
  }

  /*  is it the first netif? */
  if (netif_list == netif) {
    netif_list = netif->next;
  } else {
    /*  look for netif further down the list */
    NetIfc*tmp_netif;
    for ((tmp_netif) = netif_list; (tmp_netif) != NULL; (tmp_netif) = (tmp_netif)->next) {
      if (tmp_netif->next == netif) {
        tmp_netif->next = netif->next;
        break;
      }
    }
    if (tmp_netif == nullptr) {
      return; /* netif is not on the list */
    }
  }

  mib2_netif_removed(netif);
  if (netif->remove_callback) {
    netif->remove_callback(netif);
  }

  Logf(NETIF_DEBUG, ("netif_remove: removed netif\n") );
}

/**
 * @ingroup netif
 * Set a network interface as the default network interface
 * (used to output all packets for which no specific route is found)
 *
 * @param netif the default network interface
 */
void
netif_set_default(NetIfc*netif)
{
 

  if (netif == nullptr) {
    /* remove default route */
    mib2_remove_route_ip4(1, netif);
  } else {
    /* install default route */
    mib2_add_route_ip4(1, netif);
  }
  netif_default = netif;
  Logf(NETIF_DEBUG, ("netif: setting default interface %c%c\n",
           netif ? netif->name[0] : '\'', netif ? netif->name[1] : '\''));
}

/**
 * @ingroup netif
 * Bring an interface up, available for processing
 * traffic.
 */
void
netif_set_up(NetIfc*netif)
{
 

  

  if (!(netif->flags & NETIF_FLAG_UP)) {
    netif_set_flags(netif, NETIF_FLAG_UP);

    MIB2_COPY_SYSUPTIME_TO(&netif->ts);

    NETIF_STATUS_CALLBACK(netif);


    {
      netif_ext_callback_args_t args;
      args.status_changed.state = 1;
      netif_invoke_ext_callback(netif, LWIP_NSC_STATUS_CHANGED, &args);
    }


    netif_issue_reports(netif, NETIF_REPORT_TYPE_IPV4 | NETIF_REPORT_TYPE_IPV6);

    nd6_restart_netif(netif);

  }
}

/** Send ARP/IGMP/MLD/RS events, e.g. on link-up/netif-up or addr-change
 */
static void
netif_issue_reports(NetIfc*netif, uint8_t report_type)
{
  lwip_assert("netif_issue_reports: invalid netif", netif != nullptr);

  /* Only send reports when both link and admin states are up */
  if (!(netif->flags & NETIF_FLAG_LINK_UP) ||
      !(netif->flags & NETIF_FLAG_UP)) {
    return;
  }


  if ((report_type & NETIF_REPORT_TYPE_IPV4) &&
      !ip4_addr_isany_val(*get_net_ifc_ip4_addr(netif))) {

    /* For Ethernet network interfaces, we would like to send a "gratuitous ARP" */
    if (netif->flags & (NETIF_FLAG_ETH_ARP)) {
      etharp_gratuitous(netif);
    }

    /* resend IGMP memberships */
    if (netif->flags & NETIF_FLAG_IGMP) {
      igmp_report_groups(netif);
    }

  }

  if (report_type & NETIF_REPORT_TYPE_IPV6) {

    /* send mld memberships */
    mld6_report_groups(netif);

  }

}

/**
 * @ingroup netif
 * Bring an interface down, disabling any traffic processing.
 */
void
netif_set_down(NetIfc*netif)
{
 

  

  if (netif->flags & NETIF_FLAG_UP) {

    {
      netif_ext_callback_args_t args;
      args.status_changed.state = 0;
      netif_invoke_ext_callback(netif, LWIP_NSC_STATUS_CHANGED, &args);
    }


    netif_clear_flags(netif, NETIF_FLAG_UP);
    MIB2_COPY_SYSUPTIME_TO(&netif->ts);


    if (netif->flags & NETIF_FLAG_ETH_ARP) {
      etharp_cleanup_netif(netif);
    }



    nd6_cleanup_netif(netif);


    NETIF_STATUS_CALLBACK(netif);
  }
}

/**
 * @ingroup netif
 * Set callback to be called when interface is brought up/down or address is changed while up
 */
void
netif_set_status_callback(NetIfc*netif, netif_status_callback_fn status_callback)
{
 

  if (netif) {
    netif->status_callback = status_callback;
  }
}

/**
 * @ingroup netif
 * Set callback to be called when the interface has been removed
 */
void
netif_set_remove_callback(NetIfc*netif, netif_status_callback_fn remove_callback)
{
 

  if (netif) {
    netif->remove_callback = remove_callback;
  }
}


/**
 * @ingroup netif
 * Called by a driver when its link goes up
 */
void
netif_set_link_up(NetIfc*netif)
{
 

  

  if (!(netif->flags & NETIF_FLAG_LINK_UP)) {
    netif_set_flags(netif, NETIF_FLAG_LINK_UP);

    dhcp_network_changed(netif);

    autoip_network_changed(netif);


    netif_issue_reports(netif, NETIF_REPORT_TYPE_IPV4 | NETIF_REPORT_TYPE_IPV6);
    nd6_restart_netif(netif);

    NETIF_LINK_CALLBACK(netif);
    {
      netif_ext_callback_args_t args;
      args.link_changed.state = 1;
      netif_invoke_ext_callback(netif, LWIP_NSC_LINK_CHANGED, &args);
    }
  }
}

/**
 * @ingroup netif
 * Called by a driver when its link goes down
 */
void
netif_set_link_down(NetIfc*netif)
{
 

  

  if (netif->flags & NETIF_FLAG_LINK_UP) {
    netif_clear_flags(netif, NETIF_FLAG_LINK_UP);
    NETIF_LINK_CALLBACK(netif);
    {
      netif_ext_callback_args_t args;
      args.link_changed.state = 0;
      netif_invoke_ext_callback(netif, LWIP_NSC_LINK_CHANGED, &args);
    }

  }
}

/**
 * @ingroup netif
 * Set callback to be called when link is brought up/down
 */
void
netif_set_link_callback(NetIfc*netif, netif_status_callback_fn link_callback)
{
 

  if (netif) {
    netif->link_callback = link_callback;
  }
}

/**
 * @ingroup netif
 * Send an IP packet to be received on the same netif (loopif-like).
 * The PacketBuffer is simply copied and handed back to netif->input.
 * In multithreaded mode, this is done directly since netif->input must put
 * the packet on a queue.
 * In callback mode, the packet is put on an internal queue and is fed to
 * netif->input by netif_poll().
 *
 * @param netif the lwip network interface structure
 * @param p the (IP) packet to 'send'
 * @return ERR_OK if the packet has been sent
 *         ERR_MEM if the PacketBuffer used to copy the packet couldn't be allocated
 */
LwipStatus
netif_loop_output(NetIfc*netif, struct PacketBuffer *p, NetIfc* loop_netif)
{
  struct PacketBuffer *r;
  LwipStatus err;
  struct PacketBuffer *last;

  uint16_t clen = 0;
  /* If we have a loopif, SNMP counters are adjusted for it,
   * if not they are adjusted for 'netif'. */

  NetIfc*stats_if = &loop_netif;

  uint8_t schedule_poll = 0;

  SYS_ARCH_DECL_PROTECT(lev);

  lwip_assert("netif_loop_output: invalid netif", netif != nullptr);
  lwip_assert("netif_loop_output: invalid PacketBuffer", p != nullptr);

  /* Allocate a new PacketBuffer */
  r = pbuf_alloc(PBUF_LINK, p->tot_len);
  if (r == nullptr) {
    LINK_STATS_INC(link.memerr);
    LINK_STATS_INC(link.drop);
    MIB2_STATS_NETIF_INC(stats_if, ifoutdiscards);
    return ERR_MEM;
  }

  clen = pbuf_clen(r);
  /* check for overflow or too many PacketBuffer on queue */
  if (((netif->loop_cnt_current + clen) < netif->loop_cnt_current) ||
      ((netif->loop_cnt_current + clen) > LWIP_MIN(LWIP_LOOPBACK_MAX_PBUFS, 0xFFFF))) {
    free_pkt_buf(r);
    LINK_STATS_INC(link.memerr);
    LINK_STATS_INC(link.drop);
    MIB2_STATS_NETIF_INC(stats_if, ifoutdiscards);
    return ERR_MEM;
  }
  netif->loop_cnt_current = (uint16_t)(netif->loop_cnt_current + clen);


  /* Copy the whole PacketBuffer queue p into the single PacketBuffer r */
  if ((err = pbuf_copy(r, p)) != ERR_OK) {
    free_pkt_buf(r);
    LINK_STATS_INC(link.memerr);
    LINK_STATS_INC(link.drop);
    MIB2_STATS_NETIF_INC(stats_if, ifoutdiscards);
    return err;
  }

  /* Put the packet on a linked list which gets emptied through calling
     netif_poll(). */

  /* let last point to the last PacketBuffer in chain r */
  for (last = r; last->next != nullptr; last = last->next) {
    /* nothing to do here, just get to the last PacketBuffer */
  }

  SYS_ARCH_PROTECT(lev);
  if (netif->loop_first != nullptr) {
    lwip_assert("if first != NULL, last must also be != NULL", netif->loop_last != nullptr);
    netif->loop_last->next = r;
    netif->loop_last = last;
  } else {
    netif->loop_first = r;
    netif->loop_last = last;

    /* No existing packets queued, schedule poll */
    schedule_poll = 1;
  }
  sys_arch_unprotect(lev);

  /* For multithreading environment, schedule a call to netif_poll */
  if (schedule_poll) {
    tcpip_try_callback((TcpipCallbackFn)netif_poll, netif);
  }


  return ERR_OK;
}
static LwipStatus
netif_loop_output_ipv4(NetIfc*netif, struct PacketBuffer *p, const Ip4Addr *addr)
{
  ;
  return netif_loop_output(netif, p,);
}

static LwipStatus
netif_loop_output_ipv6(NetIfc*netif, struct PacketBuffer *p, const Ip6Addr *addr)
{
  ;
  return netif_loop_output(netif, p,);
}



/**
 * Call netif_poll() in the main loop of your application. This is to prevent
 * reentering non-reentrant functions like tcp_input(). Packets passed to
 * netif_loop_output() are put on a list that is passed to netif->input() by
 * netif_poll().
 */
void
netif_poll(NetIfc*netif)
{
  /* If we have a loopif, SNMP counters are adjusted for it,
   * if not they are adjusted for 'netif'. */

  SYS_ARCH_DECL_PROTECT(lev);

  lwip_assert("netif_poll: invalid netif", netif != nullptr);

  /* Get a packet from the list. With SYS_LIGHTWEIGHT_PROT=1, this is protected */
  SYS_ARCH_PROTECT(lev);
  while (netif->loop_first != nullptr) {
    struct PacketBuffer *in, *in_end;

    uint8_t clen = 1;


    in = in_end = netif->loop_first;
    while (in_end->len != in_end->tot_len) {
      lwip_assert("bogus PacketBuffer: len != tot_len but next == NULL!", in_end->next != nullptr);
      in_end = in_end->next;

      clen++;

    }

    /* adjust the number of pbufs on queue */
    netif->loop_cnt_current = (uint16_t)(netif->loop_cnt_current - clen);


    /* 'in_end' now points to the last PacketBuffer from 'in' */
    if (in_end == netif->loop_last) {
      /* this was the last PacketBuffer in the list */
      netif->loop_first = netif->loop_last = nullptr;
    } else {
      /* pop the PacketBuffer off the list */
      netif->loop_first = in_end->next;

    }
    /* De-queue the PacketBuffer from its successors on the 'loop_' list. */
    in_end->next = nullptr;
    sys_arch_unprotect(lev);

    in->if_idx = netif_get_index(netif);

    /* loopback packets are always IP packets! */
    if (ip_input(in, netif) != ERR_OK) {
      free_pkt_buf(in);
    }
    SYS_ARCH_PROTECT(lev);
  }
  sys_arch_unprotect(lev);
}

/**
 * @ingroup netif_cd
 * Allocate an index to store data in client_data member of NetIfc*.
 * Returned value is an index in mentioned array.
 * @see LWIP_NUM_NETIF_CLIENT_DATA
 */
uint8_t
netif_alloc_client_data_id(void)
{
  uint8_t result = netif_client_id;
  netif_client_id++;
  return (uint8_t)(result + LWIP_NETIF_CLIENT_DATA_INDEX_MAX);
}

/**
 * @ingroup netif_ip6
 * Change an IPv6 address of a network interface
 *
 * @param netif the network interface to change
 * @param addr_idx index of the IPv6 address
 * @param addr6 the new IPv6 address
 *
 * @note call netif_ip6_addr_set_state() to set the address valid/temptative
 */
void
netif_ip6_addr_set(NetIfc*netif, int8_t addr_idx, const Ip6Addr *addr6)
{
 

  lwip_assert("netif_ip6_addr_set: invalid netif", netif != nullptr);
  lwip_assert("netif_ip6_addr_set: invalid addr6", addr6 != nullptr);

  netif_ip6_addr_set_parts(netif, addr_idx, addr6->addr[0], addr6->addr[1],
                           addr6->addr[2], addr6->addr[3]);
}

/*
 * Change an IPv6 address of a network interface (internal version taking 4 * uint32_t)
 *
 * @param netif the network interface to change
 * @param addr_idx index of the IPv6 address
 * @param i0 word0 of the new IPv6 address
 * @param i1 word1 of the new IPv6 address
 * @param i2 word2 of the new IPv6 address
 * @param i3 word3 of the new IPv6 address
 */
void
netif_ip6_addr_set_parts(NetIfc*netif, int8_t addr_idx, uint32_t i0, uint32_t i1, uint32_t i2, uint32_t i3)
{
  IpAddr old_addr;
  IpAddr new_ipaddr;
 
  lwip_assert("netif != NULL", netif != nullptr);
  lwip_assert("invalid index", addr_idx < LWIP_IPV6_NUM_ADDRESSES);

  ip6_addr_copy(*ip_2_ip6(&old_addr), *netif_ip6_addr(netif, addr_idx));
  IpAdderSetTypeVal(old_addr, IPADDR_TYPE_V6);

  /* address is actually being changed? */
  if ((ip_2_ip6(&old_addr)->addr[0] != i0) || (ip_2_ip6(&old_addr)->addr[1] != i1) ||
      (ip_2_ip6(&old_addr)->addr[2] != i2) || (ip_2_ip6(&old_addr)->addr[3] != i3)) {
    Logf(NETIF_DEBUG | LWIP_DBG_STATE, ("netif_ip6_addr_set: netif address being changed\n"));

    make_ip_addr_ip6(&new_ipaddr, i0, i1, i2, i3);
    ip6_addr_assign_zone(ip_2_ip6(&new_ipaddr), IP6_UNICAST, netif);

    if (ip6_addr_isvalid(netif_ip6_addr_state(netif, addr_idx))) {
      netif_do_ip_addr_changed(netif_ip_addr6(netif, addr_idx), &new_ipaddr);
    }
    /* @todo: remove/readd mib2 ip6 entries? */

    ip_addr_copy(netif->ip6_addr[addr_idx], new_ipaddr);

    if (ip6_addr_isvalid(netif_ip6_addr_state(netif, addr_idx))) {
      netif_issue_reports(netif, NETIF_REPORT_TYPE_IPV6);
      NETIF_STATUS_CALLBACK(netif);
    }

    {
      netif_ext_callback_args_t args;
      args.ipv6_set.addr_index  = addr_idx;
      args.ipv6_set.old_address = &old_addr;
      netif_invoke_ext_callback(netif, LWIP_NSC_IPV6_SET, &args);
    }
  }

  Logf(NETIF_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("netif: IPv6 address %d of interface %c%c set to %s/0x%"X8_F"\n",
              addr_idx, netif->name[0], netif->name[1], ip6addr_ntoa(netif_ip6_addr(netif, addr_idx)),
              netif_ip6_addr_state(netif, addr_idx)));
}

/**
 * @ingroup netif_ip6
 * Change the state of an IPv6 address of a network interface
 * (INVALID, TEMPTATIVE, PREFERRED, DEPRECATED, where TEMPTATIVE
 * includes the number of checks done, see ip6_addr.h)
 *
 * @param netif the network interface to change
 * @param addr_idx index of the IPv6 address
 * @param state the new IPv6 address state
 */
void
netif_ip6_addr_set_state(NetIfc*netif, int8_t addr_idx, uint8_t state)
{
  uint8_t old_state;
 
  lwip_assert("netif != NULL", netif != nullptr);
  lwip_assert("invalid index", addr_idx < LWIP_IPV6_NUM_ADDRESSES);

  old_state = netif_ip6_addr_state(netif, addr_idx);
  /* state is actually being changed? */
  if (old_state != state) {
    uint8_t old_valid = old_state & IP6_ADDR_VALID;
    uint8_t new_valid = state & IP6_ADDR_VALID;
    Logf(NETIF_DEBUG | LWIP_DBG_STATE, ("netif_ip6_addr_set_state: netif address state being changed\n"));
    /* Reevaluate solicited-node multicast group membership. */
    if (netif->flags & NETIF_FLAG_MLD6) {
      nd6_adjust_mld_membership(netif, addr_idx, state);
    }

    if (old_valid && !new_valid) {
      /* address about to be removed by setting invalid */
      netif_do_ip_addr_changed(netif_ip_addr6(netif, addr_idx), nullptr);
      /* @todo: remove mib2 ip6 entries? */
    }
    netif->ip6_addr_state[addr_idx] = state;

    if (!old_valid && new_valid) {
      /* address added by setting valid */
      /* This is a good moment to check that the address is properly zoned. */
      IP6_ADDR_ZONECHECK_NETIF(netif_ip6_addr(netif, addr_idx), netif);
      /* @todo: add mib2 ip6 entries? */
      netif_issue_reports(netif, NETIF_REPORT_TYPE_IPV6);
    }
    if ((old_state & ~IP6_ADDR_TENTATIVE_COUNT_MASK) !=
        (state     & ~IP6_ADDR_TENTATIVE_COUNT_MASK)) {
      /* address state has changed -> call the callback function */
      NETIF_STATUS_CALLBACK(netif);
    }

    {
      netif_ext_callback_args_t args;
      args.ipv6_addr_state_changed.addr_index = addr_idx;
      args.ipv6_addr_state_changed.old_state  = old_state;
      args.ipv6_addr_state_changed.address    = netif_ip_addr6(netif, addr_idx);
      netif_invoke_ext_callback(netif, LWIP_NSC_IPV6_ADDR_STATE_CHANGED, &args);
    }

  }
  Logf(NETIF_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("netif: IPv6 address %d of interface %c%c set to %s/0x%"X8_F"\n",
              addr_idx, netif->name[0], netif->name[1], ip6addr_ntoa(netif_ip6_addr(netif, addr_idx)),
              netif_ip6_addr_state(netif, addr_idx)));
}

/**
 * Checks if a specific local address is present on the netif and returns its
 * index. Depending on its state, it may or may not be assigned to the
 * interface (as per RFC terminology).
 *
 * The given address may or may not be zoned (i.e., have a zone index other
 * than kIp6NoZone). If the address is zoned, it must have the correct zone
 * for the given netif, or no match will be found.
 *
 * @param netif the netif to check
 * @param ip6addr the IPv6 address to find
 * @return >= 0: address found, this is its index
 *         -1: address not found on this netif
 */
int8_t
netif_get_ip6_addr_match(NetIfc*netif, const Ip6Addr *ip6addr)
{
  int8_t i;

 

  lwip_assert("netif_get_ip6_addr_match: invalid netif", netif != nullptr);
  lwip_assert("netif_get_ip6_addr_match: invalid ip6addr", ip6addr != nullptr);

  if (ip6_addr_has_zone(ip6addr) && !ip6_addr_est_zone(ip6addr, netif)) {
    return -1; /* wrong zone, no match */
  }


  for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
    if (!ip6_addr_isinvalid(netif_ip6_addr_state(netif, i)) &&
        ip6_addr_cmp_zoneless(netif_ip6_addr(netif, i), ip6addr)) {
      return i;
    }
  }
  return -1;
}

/**
 * @ingroup netif_ip6
 * Create a link-local IPv6 address on a netif (stored in slot 0)
 *
 * @param netif the netif to create the address on
 * @param from_mac_48bit if != 0, assume hwadr is a 48-bit MAC address (std conversion)
 *                       if == 0, use hwaddr directly as interface ID
 */
void
netif_create_ip6_linklocal_address(NetIfc*netif, uint8_t from_mac_48bit)
{
  uint8_t i, addr_index;

 

  lwip_assert("netif_create_ip6_linklocal_address: invalid netif", netif != nullptr);

  /* Link-local prefix. */
  ip_2_ip6(&netif->ip6_addr[0])->addr[0] = pp_htonl(0xfe800000ul);
  ip_2_ip6(&netif->ip6_addr[0])->addr[1] = 0;

  /* Generate interface ID. */
  if (from_mac_48bit) {
    /* Assume hwaddr is a 48-bit IEEE 802 MAC. Convert to EUI-64 address. Complement Group bit. */
    ip_2_ip6(&netif->ip6_addr[0])->addr[2] = lwip_htonl((((uint32_t)(netif->hwaddr[0] ^ 0x02)) << 24) |
        ((uint32_t)(netif->hwaddr[1]) << 16) |
        ((uint32_t)(netif->hwaddr[2]) << 8) |
        (0xff));
    ip_2_ip6(&netif->ip6_addr[0])->addr[3] = lwip_htonl((uint32_t)(0xfeul << 24) |
        ((uint32_t)(netif->hwaddr[3]) << 16) |
        ((uint32_t)(netif->hwaddr[4]) << 8) |
        (netif->hwaddr[5]));
  } else {
    /* Use hwaddr directly as interface ID. */
    ip_2_ip6(&netif->ip6_addr[0])->addr[2] = 0;
    ip_2_ip6(&netif->ip6_addr[0])->addr[3] = 0;

    addr_index = 3;
    for (i = 0; (i < 8) && (i < netif->hwaddr_len); i++) {
      if (i == 4) {
        addr_index--;
      }
      ip_2_ip6(&netif->ip6_addr[0])->addr[addr_index] |= lwip_htonl(((uint32_t)(netif->hwaddr[netif->hwaddr_len - i - 1])) << (8 * (i & 0x03)));
    }
  }

  /* Set a link-local zone. Even though the zone is implied by the owning
   * netif, setting the zone anyway has two important conceptual advantages:
   * 1) it avoids the need for a ton of exceptions in internal code, allowing
   *    e.g. ip6_addr_cmp() to be used on local addresses;
   * 2) the properly zoned address is visible externally, e.g. when any outside
   *    code enumerates available addresses or uses one to bind a socket.
   * Any external code unaware of address scoping is likely to just ignore the
   * zone field, so this should not create any compatibility problems. */
  ip6_addr_assign_zone(ip_2_ip6(&netif->ip6_addr[0]), IP6_UNICAST, netif);

  /* Set address state. */

  /* Will perform duplicate address detection (DAD). */
  netif_ip6_addr_set_state(netif, 0, IP6_ADDR_TENTATIVE);

}

/**
 * @ingroup netif_ip6
 * This function allows for the easy addition of a new IPv6 address to an interface.
 * It takes care of finding an empty slot and then sets the address tentative
 * (to make sure that all the subsequent processing happens).
 *
 * @param netif netif to add the address on
 * @param ip6addr address to add
 * @param chosen_idx if != NULL, the chosen IPv6 address index will be stored here
 */
LwipStatus
netif_add_ip6_address(NetIfc*netif, const Ip6Addr *ip6addr, int8_t *chosen_idx)
{
  int8_t i;

 

  lwip_assert("netif_add_ip6_address: invalid netif", netif != nullptr);
  lwip_assert("netif_add_ip6_address: invalid ip6addr", ip6addr != nullptr);

  i = netif_get_ip6_addr_match(netif, ip6addr);
  if (i >= 0) {
    /* Address already added */
    if (chosen_idx != nullptr) {
      *chosen_idx = i;
    }
    return ERR_OK;
  }

  /* Find a free slot. The first one is reserved for link-local addresses. */
  for (i = ip6_addr_islinklocal(ip6addr) ? 0 : 1; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
    if (ip6_addr_isinvalid(netif_ip6_addr_state(netif, i))) {
      ip_addr_copy_from_ip6(netif->ip6_addr[i], *ip6addr);
      ip6_addr_assign_zone(ip_2_ip6(&netif->ip6_addr[i]), IP6_UNICAST, netif);
      netif_ip6_addr_set_state(netif, i, IP6_ADDR_TENTATIVE);
      if (chosen_idx != nullptr) {
        *chosen_idx = i;
      }
      return ERR_OK;
    }
  }

  if (chosen_idx != nullptr) {
    *chosen_idx = -1;
  }
  return ERR_VAL;
}

/** Dummy IPv6 output function for netifs not supporting IPv6
 */
static LwipStatus
netif_null_output_ip6(NetIfc*netif, struct PacketBuffer *p, const Ip6Addr *ipaddr)
{
  ;
  ;
  ;

  return ERR_IF;
}


/** Dummy IPv4 output function for netifs not supporting IPv4
 */
static LwipStatus
netif_null_output_ip4(NetIfc*netif, struct PacketBuffer *p, const Ip4Addr *ipaddr)
{
  ;
  ;
  ;

  return ERR_IF;
}


/**
* @ingroup netif
* Return the interface index for the netif with name
* or NETIF_NO_INDEX if not found/on error
*
* @param name the name of the netif
*/
uint8_t
netif_name_to_index(const char *name)
{
  NetIfc*netif = netif_find(name);
  if (netif != nullptr) {
    return netif_get_index(netif);
  }
  /* No name found, return invalid index */
  return NETIF_NO_INDEX;
}

/**
* @ingroup netif
* Return the interface name for the netif matching index
* or NULL if not found/on error
*
* @param idx the interface index of the netif
* @param name char buffer of at least NETIF_NAMESIZE bytes
*/
char *
netif_index_to_name(uint8_t idx, char *name)
{
  NetIfc*netif = netif_get_by_index(idx);

  if (netif != nullptr) {
    name[0] = netif->name[0];
    name[1] = netif->name[1];
    lwip_itoa(&name[2], NETIFC_NAME_SZ - 2, ((idx) - 1));
    return name;
  }
  return nullptr;
}

/**
* @ingroup netif
* Return the interface for the netif index
*
* @param idx index of netif to find
*/
NetIfc*
netif_get_by_index(uint8_t idx)
{
  NetIfc*netif;

 

  if (idx != NETIF_NO_INDEX) {
    for ((netif) = netif_list; (netif) != NULL; (netif) = (netif)->next) {
      if (idx == netif_get_index(netif)) {
        return netif; /* found! */
      }
    }
  }

  return nullptr;
}

/**
 * @ingroup netif
 * Find a network interface by searching for its name
 *
 * @param name the name of the netif (like netif->name) plus concatenated number
 * in ascii representation (e.g. 'en0')
 */
NetIfc*
netif_find(const char *name)
{
  NetIfc*netif;
  uint8_t num;

 

  if (name == nullptr) {
    return nullptr;
  }

  num = (uint8_t)atoi(&name[2]);

  for ((netif) = netif_list; (netif) != NULL; (netif) = (netif)->next) {
    if (num == netif->num &&
        name[0] == netif->name[0] &&
        name[1] == netif->name[1]) {
      Logf(NETIF_DEBUG, ("netif_find: found %c%c\n", name[0], name[1]));
      return netif;
    }
  }
  Logf(NETIF_DEBUG, ("netif_find: didn't find %c%c\n", name[0], name[1]));
  return nullptr;
}

/**
 * @ingroup netif
 * Add extended netif events listener
 * @param callback pointer to listener structure
 * @param fn callback function
 */
void
netif_add_ext_callback(netif_ext_callback_t *callback, netif_ext_callback_fn fn)
{
 
  lwip_assert("callback must be != NULL", callback != nullptr);
  lwip_assert("fn must be != NULL", fn != nullptr);

  callback->callback_fn = fn;
  callback->next        = ext_callback;
  ext_callback          = callback;
}

/**
 * @ingroup netif
 * Remove extended netif events listener
 * @param callback pointer to listener structure
 */
void
netif_remove_ext_callback(netif_ext_callback_t* callback)
{
  netif_ext_callback_t *last, *iter;

 
  lwip_assert("callback must be != NULL", callback != nullptr);

  if (ext_callback == nullptr) {
    return;
  }

  if (callback == ext_callback) {
    ext_callback = ext_callback->next;
  } else {
    last = ext_callback;
    for (iter = ext_callback->next; iter != nullptr; last = iter, iter = iter->next) {
      if (iter == callback) {
        lwip_assert("last != NULL", last != nullptr);
        last->next = callback->next;
        callback->next = nullptr;
        return;
      }
    }
  }
}

/**
 * Invoke extended netif status event
 * @param netif netif that is affected by change
 * @param reason change reason
 * @param args depends on reason, see reason description
 */
void
netif_invoke_ext_callback(NetIfc*netif, NetifNscReason reason, const netif_ext_callback_args_t *args)
{
  netif_ext_callback_t *callback = ext_callback;

  lwip_assert("netif must be != NULL", netif != nullptr);

  while (callback != nullptr) {
    callback->callback_fn(netif, reason, args);
    callback = callback->next;
  }
}


/**
 * @ingroup ip6
 * Select the best IPv6 source address for a given destination IPv6 address.
 *
 * This implementation follows RFC 6724 Sec. 5 to the following extent:
 * - Rules 1, 2, 3: fully implemented
 * - Rules 4, 5, 5.5: not applicable
 * - Rule 6: not implemented
 * - Rule 7: not applicable
 * - Rule 8: limited to "prefer /64 subnet match over non-match"
 *
 * For Rule 2, we deliberately deviate from RFC 6724 Sec. 3.1 by considering
 * ULAs to be of smaller scope than global addresses, to avoid that a preferred
 * ULA is picked over a deprecated global address when given a global address
 * as destination, as that would likely result in broken two-way communication.
 *
 * As long as temporary addresses are not supported (as used in Rule 7), a
 * proper implementation of Rule 8 would obviate the need to implement Rule 6.
 *
 * @param netif the netif on which to send a packet
 * @param dest the destination we are trying to reach (possibly not properly
 *             zoned)
 * @return the most suitable source address to use, or NULL if no suitable
 *         source address is found
 */
const IpAddr *
ip6_select_source_address(NetIfc*netif, const Ip6Addr *dest)
{
  const IpAddr *best_addr;
  const Ip6Addr *cand_addr;
  int8_t dest_scope, cand_scope;
  int8_t best_scope = IP6_MULTICAST_SCOPE_RESERVED;
  uint8_t i, cand_pref, cand_bits;
  uint8_t best_pref = 0;
  uint8_t best_bits = 0;

  /* Start by determining the scope of the given destination address. These
   * tests are hopefully (roughly) in order of likeliness to match. */
  if (ip6_addr_isglobal(dest)) {
    dest_scope = IP6_MULTICAST_SCOPE_GLOBAL;
  } else if (ip6_addr_islinklocal(dest) || ip6_addr_isloopback(dest)) {
    dest_scope = IP6_MULTICAST_SCOPE_LINK_LOCAL;
  } else if (ip6_addr_isuniquelocal(dest)) {
    dest_scope = IP6_MULTICAST_SCOPE_ORGANIZATION_LOCAL;
  } else if (ip6_addr_ismulticast(dest)) {
    dest_scope = ip6_addr_multicast_scope(dest);
  } else if (ip6_addr_issitelocal(dest)) {
    dest_scope = IP6_MULTICAST_SCOPE_SITE_LOCAL;
  } else {
    /* no match, consider scope global */
    dest_scope = IP6_MULTICAST_SCOPE_GLOBAL;
  }

  best_addr = nullptr;

  for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
    /* Consider only valid (= preferred and deprecated) addresses. */
    if (!ip6_addr_isvalid(netif_ip6_addr_state(netif, i))) {
      continue;
    }
    /* Determine the scope of this candidate address. Same ordering idea. */
    cand_addr = netif_ip6_addr(netif, i);
    if (ip6_addr_isglobal(cand_addr)) {
      cand_scope = IP6_MULTICAST_SCOPE_GLOBAL;
    } else if (ip6_addr_islinklocal(cand_addr)) {
      cand_scope = IP6_MULTICAST_SCOPE_LINK_LOCAL;
    } else if (ip6_addr_isuniquelocal(cand_addr)) {
      cand_scope = IP6_MULTICAST_SCOPE_ORGANIZATION_LOCAL;
    } else if (ip6_addr_issitelocal(cand_addr)) {
      cand_scope = IP6_MULTICAST_SCOPE_SITE_LOCAL;
    } else {
      /* no match, treat as low-priority global scope */
      cand_scope = IP6_MULTICAST_SCOPE_RESERVEDF;
    }
    cand_pref = ip6_addr_ispreferred(netif_ip6_addr_state(netif, i));
    /* @todo compute the actual common bits, for longest matching prefix. */
    /* We cannot count on the destination address having a proper zone
     * assignment, so do not compare zones in this case. */
    cand_bits = ip6_addr_netcmp_zoneless(cand_addr, dest); /* just 1 or 0 for now */
    if (cand_bits && ip6_addr_nethostcmp(cand_addr, dest)) {
      return netif_ip_addr6(netif, i); /* Rule 1 */
    }
    if ((best_addr == nullptr) || /* no alternative yet */
        ((cand_scope < best_scope) && (cand_scope >= dest_scope)) ||
        ((cand_scope > best_scope) && (best_scope < dest_scope)) || /* Rule 2 */
        ((cand_scope == best_scope) && ((cand_pref > best_pref) || /* Rule 3 */
        ((cand_pref == best_pref) && (cand_bits > best_bits))))) { /* Rule 8 */
      /* We found a new "winning" candidate. */
      best_addr = netif_ip_addr6(netif, i);
      best_scope = cand_scope;
      best_pref = cand_pref;
      best_bits = cand_bits;
    }
  }

  return best_addr; /* may be NULL */
}

//
// END OF FILE
//