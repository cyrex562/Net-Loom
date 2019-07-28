//
// file: netif.cpp
//

#include <autoip.h>
#include <cstdlib> /* atoi */
#include <cstring> /* memset */
#include <def.h>
#include <dhcp6.h>
#include <etharp.h>
#include <ethernet.h>
#include <igmp.h>
#include <ip.h>
#include <ip6_addr.h>
#include <ip_addr.h>
#include <lwip_debug.h>
#include <lwip_status.h>
#include <mld6.h>
#include <nd6.h>
#include <network_interface.h>
#include <opt.h>
#include <raw_priv.h>
#include <sys.h>
#include <tcp_priv.h>
#include <tcpip.h>
#include <udp.h>

inline void NETIF_STATUS_CALLBACK(NetworkInterface* n)
{
    if (n->status_callback != nullptr)
    {
        (n->status_callback)(n);
    }
}

inline void NETIF_LINK_CALLBACK(NetworkInterface* n)
{
    if (n->link_callback)
    {
        (n->link_callback)(n);
    }
}

static NetifExtCallback *ext_callback;

NetworkInterface*netif_list;

NetworkInterface*netif_default;
//
// #define netif_index_to_num(index)   ((index) - 1)
static uint8_t netif_num;

static uint8_t netif_client_id;


constexpr auto NETIF_REPORT_TYPE_IPV4 = 0x01;
constexpr auto NETIF_REPORT_TYPE_IPV6 = 0x02;
static void netif_issue_reports(NetworkInterface& netif, uint8_t report_type);

static LwipStatus netif_null_output_ip6(NetworkInterface*netif, struct PacketBuffer *p, const Ip6Addr*ipaddr);

static LwipStatus netif_null_output_ip4(NetworkInterface*netif, struct PacketBuffer *p, const Ip4Addr *ipaddr);

static LwipStatus netif_loop_output_ipv4(NetworkInterface*netif, struct PacketBuffer *p, const Ip4Addr *addr);

static LwipStatus netif_loop_output_ipv6(NetworkInterface*netif, struct PacketBuffer *p, const Ip6Addr*addr);



// static NetworkInterface* loop_netif;

/**
 * Initialize a lwip network interface structure for a loopback interface
 *
 * @param netif the lwip network interface structure for this loopif
 * @return ERR_OK if the loopif is initialized
 *         ERR_MEM if private data couldn't be allocated
 */
static LwipStatus init_loop_netif(NetworkInterface& netif)
{
    // lwip_assert("netif_loopif_init: invalid netif", netif != nullptr);
    /* initialize the snmp variables and counters inside the NetworkInterface*
      * ifSpeed: no assumption can be made!
      */ // MIB2_INIT_NETIF(netif, snmp_ifType_softwareLoopback, 0);
    netif.name[0] = 'l';
    netif.name[1] = 'o';
    netif.output = netif_loop_output_ipv4;
    netif.output_ip6 = netif_loop_output_ipv6;
    netif.igmp = true; // netif_set_flags(netif, NETIF_FLAG_IGMP);
    // NETIF_SET_CHECKSUM_CTRL(netif, NETIF_CHECKSUM_DISABLE_ALL);
    return ERR_OK;
}

///
///
///
void init_netif_module()
{
    Ip4Addr loop_ipaddr{};
    Ip4Addr loop_netmask{};
    Ip4Addr loop_gw{};
    Ipv4AddrFromBytes(&loop_gw, 127, 0, 0, 1);
    Ipv4AddrFromBytes(&loop_ipaddr, 127, 0, 0, 1);
    Ipv4AddrFromBytes(&loop_netmask, 255, 0, 0, 0);
    add_netif(loop_netif,
              &loop_ipaddr,
              &loop_netmask,
              &loop_gw,
              nullptr);
    ip_addr_ip6_host(&loop_netif->ip6_addr[0], 0, 0, 0, 0x00000001UL);
    loop_netif->ip6_addr_state[0] = IP6_ADDR_VALID;
    set_netif_link_up(loop_netif);
    set_netif_up(loop_netif);
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
input_netif(PacketBuffer& pkt_buf, NetworkInterface& netif)
{


  lwip_assert("netif_input: invalid pbuf", pkt_buf != nullptr);
  lwip_assert("netif_input: invalid netif", netif != nullptr);

  if (netif->flags & (NETIF_FLAG_ETH_ARP | NETIF_FLAG_ETH)) {
    return ethernet_input(pkt_buf, netif);
  } else

    return ip_input(pkt_buf, netif);
}

/**
 * @ingroup netif
 * Add a network interface to the list of lwIP netifs.
 *
 * Same as @ref netif_add but without IPv4 addresses
 */
NetworkInterface&
add_netif_no_addr(NetworkInterface& netif, uint8_t& state)
{
  return add_netif(netif,

                   nullptr, nullptr, nullptr,

                   state);
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
/// ingress packets up in the protocol layer stack.\n
/// It is recommended to use a function that passes the input directly
/// to the stack (netif_input(), NO_SYS=1 mode) or via sending a
/// message to TCPIP thread (tcpip_input(), NO_SYS=0 mode).\n
/// These functions use netif flags NETIF_FLAG_ETHARP and NETIF_FLAG_ETHERNET
/// to decide whether to forward to ethernet_input() or ip_input().
/// In other words, the functions only work when the netif
/// driver is implemented correctly!\n
/// Most members of NetworkInterface* should be be initialized by the
/// netif init function = netif driver (init parameter of this function).\n
/// IPv6: Don't forget to call netif_create_ip6_linklocal_address() after
/// setting the MAC address in NetworkInterface*.hwaddr
/// (IPv6 requires a link-local address).
///
/// @return netif, or NULL if failed.
///
NetworkInterface add_netif(NetworkInterface& netif,
                           const Ip4Addr& ipaddr,
                           const Ip4Addr& netmask,
                           const Ip4Addr& gw,
                           uint8_t* state)
{

    // if (netif_default != nullptr)
    // {
    //     lwip_assert("single netif already set", false);
    //     return nullptr;
    // } //
    // if (netif == nullptr)
    // {
    //     return nullptr;
    // } //
    // if (ipaddr == nullptr)
    // {
    //     Ip4Addr addr = create_ip4_addr_any();
    //     // ipaddr = convert_ip_addr_to_ip4_addr(&addr);
    //     ipaddr = &addr;
    // }
    // if (netmask == nullptr)
    // {
    //     Ip4Addr addr = create_ip4_addr_any();
    //     netmask = &addr;
    // }
    // if (gw == nullptr)
    // {
    //     Ip4Addr addr = create_ip4_addr_any();
    //     gw = &addr;
    // } 
    
    /* reset new interface configuration state */
    auto i = 0;
    zero_ip_addr_ip4(netif.ip4_addresses[i]);
    zero_ip_addr_ip4(netif.ip4_netmask);
    zero_ip_addr_ip4(netif.ip4_gw);
    netif.output = netif_null_output_ip4;
    for (int8_t i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++)
    {
        zero_ip_addr_ip6(netif.ip6_addresses[i]);
        netif.ip6_addr_states[i] = IP6_ADDR_INVALID;
        netif.ip6_addr_valid_life[i] = (0);
        netif.ip6_addr_pref_life[i] = (0);
    }
    netif.output_ip6 = netif_null_output_ip6;
    // NETIF_SET_CHECKSUM_CTRL(netif, NETIF_CHECKSUM_ENABLE_ALL);
    netif.mtu = 0;
    // netif.flags = 0;
    // memset(netif.client_data, 0, sizeof(netif.client_data));
    /* IPv6 address autoconfiguration not enabled by default */
    netif.ip6_autoconfig_enabled = 0;
    nd6_restart_netif(netif);
    netif.status_callback = nullptr;
    netif.link_callback = nullptr;
    netif.igmp_mac_filter = nullptr;
    netif.mld_mac_filter = nullptr;
    netif.loop_first = nullptr;
    netif.loop_last = nullptr; /* remember netif specific state information data */
    netif.state = state;
    netif.if_num = netif_num;
    netif.input = input;
    netif_reset_hints(netif);
    netif.loop_cnt_current = 0;
    set_netif_addr(netif, ipaddr, netmask, gw);
    /* call user specified initialization function for netif */
    if (init(netif) != ERR_OK)
    {
        return nullptr;
    } /* Initialize the MTU for IPv6 to the one set by the netif driver.
     This can be updated later by RA. */
    netif.mtu6 = netif.mtu;
    /* Assign a unique netif number in the range [0..254], so that (num+1) can
        serve as an interface index that fits in a uint8_t.
        We assume that the new netif has not yet been added to the list here.
        This algorithm is O(n^2), but that should be OK for lwIP.
        */
    {
        NetworkInterface* netif2;
        do
        {
            if (netif.if_num == 255)
            {
                netif.if_num = 0;
            }
            int num_netifs = 0;
            for (netif2 = netif_list; netif2 != nullptr; netif2 = netif2->next)
            {
                lwip_assert("netif already added", netif2 != netif);
                num_netifs++;
                lwip_assert("too many netifs, max. supported number is 255",
                            num_netifs <= 255);
                if (netif2->if_num == netif.if_num)
                {
                    netif.if_num++;
                    break;
                }
            }
        }
        while (netif2 != nullptr);
    }
    if (netif.if_num == 254)
    {
        netif_num = 0;
    }
    else
    {
        netif_num = (uint8_t)(netif.if_num + 1);
    } /* add this netif to the list */
    netif.next = netif_list;
    netif_list = netif;
    // mib2_netif_added(netif); /* start IGMP processing */
    if (netif.flags & NETIF_FLAG_IGMP)
    {
        igmp_start(netif);
    }
    Logf(true, "netif: added interface %c%c IP", netif.name[0], netif.name[1]);
    Logf(true, " addr ");
    // ip4_addr_debug_print(true, ipaddr)
    // ;
    Logf(true, (" netmask "));
    // ip4_addr_debug_print(true, netmask)
    // ;
    Logf(true, (" gw "));
    // ip4_addr_debug_print(true, gw)
    // ;
    Logf(true, ("\n"));
    netif_invoke_ext_callback(netif, LWIP_NSC_NETIF_ADDED, nullptr);
    return netif;
}

static void
netif_do_ip_addr_changed(const IpAddr& old_addr, const IpAddr& new_addr)
{

  tcp_netif_ip_addr_changed(old_addr, new_addr);

  udp_netif_ip_addr_changed(old_addr, new_addr);

  raw_netif_ip_addr_changed(old_addr, new_addr);

}

static bool netif_do_set_ipaddr(NetworkInterface& netif, const Ip4Addr& ipaddr, IpAddr& old_addr)
{
  // lwip_assert("invalid pointer", ipaddr != nullptr);
  // lwip_assert("invalid pointer", old_addr != nullptr);

  /* address is actually being changed? */
  if (ip4_addr_cmp(ipaddr, get_netif_ip4_addr(netif,)) == 0) {
    IpAddr new_addr{};
      copy_ip4_addr(new_addr.u_addr.ip4, ipaddr);
    set_ip_addr_type_val(new_addr, IPADDR_TYPE_V4);

    copy_ip_addr(old_addr, get_netif_ip4_addr(netif,));

    Logf(true, ("netif_set_ipaddr: netif address being changed\n"));
    netif_do_ip_addr_changed(old_addr, new_addr);

    // mib2_remove_ip4(netif);
    // mib2_remove_route_ip4(0, netif);
    /* set new IP address to netif */
    ip4_addr_set(netif.ip_addr.u_addr.ip4, ipaddr);
    set_ip_addr_type_val(netif.ip_addr, IPADDR_TYPE_V4);
    // mib2_add_ip4(netif);
    // mib2_add_route_ip4(0, netif);

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
 * @param addr the new IP address
 *
 * @note call netif_set_addr() if you also want to change netmask and
 * default gateway
 */
void set_net_if_addr2(NetworkInterface& netif, const Ip4Addr& addr)
{
    IpAddr old_addr; /* Don't propagate NULL pointer (IPv4 ANY) to subsequent functions */
    if (addr == nullptr)
    {
        addr = nullptr;
    }
    if (netif_do_set_ipaddr(netif, addr, &old_addr))
    {
        // netif_ext_callback_args_t args{};
        // args. ipv4_changed.old_address = &old_addr;
        // netif_invoke_ext_callback(netif, LWIP_NSC_IPV4_ADDRESS_CHANGED, &args);
    }
}

static int
netif_do_set_netmask(NetworkInterface*netif, const Ip4Addr *netmask, IpAddr *old_nm)
{
  /* address is actually being changed? */
  if (ip4_addr_cmp(netmask, get_netif_ip4_netmask(netif,)) == 0) {
    lwip_assert("invalid pointer", old_nm != nullptr);
    copy_ip_addr(old_nm, netif_ip_netmask4(netif));

    // mib2_remove_route_ip4(0, netif);
    /* set new netmask to netif */
    ip4_addr_set((&netif->ip4_netmask.u_addr.ip4), netmask);
    set_ip_addr_type_val(netif->ip4_netmask, IPADDR_TYPE_V4);
    // mib2_add_route_ip4(0, netif);
//    Logf(true | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("netif: netmask of interface %c%c set to %d.%d.%d.%d\n",
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
void set_netif_netmask(NetworkInterface& netif, const Ip4Addr& netmask)
{
    IpAddr old_nm_val;
    IpAddr* old_nm = &old_nm_val;
    /* Don't propagate NULL pointer (IPv4 ANY) to subsequent functions */
    if (netmask == nullptr)
    {
        netmask = nullptr;
    }
    if (netif_do_set_netmask(netif, netmask, old_nm))
    {
        netif_ext_callback_args_t args; // args.ipv4_changed.old_netmask = old_nm;
        netif_invoke_ext_callback(netif, LWIP_NSC_IPV4_NETMASK_CHANGED, &args);
    }
}

static int
netif_do_set_gw(NetworkInterface*netif, const Ip4Addr *gw, IpAddr *old_gw)
{
  /* address is actually being changed? */
  if (ip4_addr_cmp(gw, get_netif_ip4_gw(netif,)) == 0) {

    lwip_assert("invalid pointer", old_gw != nullptr);
    copy_ip_addr(old_gw, netif_ip_gw4(netif));


    ip4_addr_set(&netif->ip4_gw.u_addr.ip4, gw);
    set_ip_addr_type_val(netif->ip4_gw, IPADDR_TYPE_V4);
//    Logf(true | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("netif: GW address of interface %c%c set to %d.%d.%d.%d\n",
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
set_netif_gw(NetworkInterface& netif, const Ip4Addr& gw)
{

  IpAddr old_gw_val;
  IpAddr *old_gw = &old_gw_val;





  /* Don't propagate NULL pointer (IPv4 ANY) to subsequent functions */
  if (gw == nullptr) {
    gw = nullptr;
  }

  if (netif_do_set_gw(netif, gw, old_gw)) {

    netif_ext_callback_args_t args;
    // args.ipv4_changed.old_gw = old_gw;
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
bool netif_set_addr(NetworkInterface& netif,
                    const Ip4Addr& ipaddr,
                    const Ip4Addr& netmask,
                    const Ip4Addr& gw)
{
    IpAddr* old_nm = nullptr;
    IpAddr* old_gw = nullptr;
    IpAddr old_addr;

    /* Don't propagate NULL pointer (IPv4 ANY) to subsequent functions */
    // if (ipaddr == nullptr)
    // {
    //     ipaddr = nullptr;
    // }
    // if (netmask == nullptr)
    // {
    //     netmask = nullptr;
    // }
    // if (gw == nullptr)
    // {
    //     gw = nullptr;
    // }
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

    return true;
}


/**
 * @ingroup netif
 * Remove a network interface from the list of lwIP netifs.
 *
 * @param netif the network interface to remove
 */
void
remove_netif(NetworkInterface& netif)
{
    if (netif == nullptr) {
    return;
  }

  netif_invoke_ext_callback(netif, LWIP_NSC_NETIF_REMOVED, nullptr);

  if (!ip4_addr_isany_val(*get_netif_ip4_addr(netif,))) {
    netif_do_ip_addr_changed(get_netif_ip4_addr(netif,), nullptr);
  }

  /* stop IGMP processing */
  if (netif->flags & NETIF_FLAG_IGMP) {
    igmp_stop(netif);
  }

  for (int i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
    if (is_ip6_addr_valid(get_netif_ip6_addr_state(netif, i))) {
      netif_do_ip_addr_changed(get_netif_ip6_addr_info(netif, i), nullptr);
    }
  }

  /* stop MLD processing */
  mld6_stop(netif);

  if (is_netif_up(netif)) {
    /* set netif down before removing (call callback function) */
    set_netif_down(netif);
  }

  // mib2_remove_ip4(netif);

  /* this netif is default? */
  if (netif_default == netif) {
    /* reset default netif */
    set_netif_default(nullptr);
  }

  /*  is it the first netif? */
  if (netif_list == netif) {
    netif_list = netif->next;
  } else {
    /*  look for netif further down the list */
    NetworkInterface*tmp_netif;
    for ((tmp_netif) = netif_list; (tmp_netif) != nullptr; (tmp_netif) = (tmp_netif)->next) {
      if (tmp_netif->next == netif) {
        tmp_netif->next = netif->next;
        break;
      }
    }
    if (tmp_netif == nullptr) {
      return; /* netif is not on the list */
    }
  }

  // mib2_netif_removed(netif);
  if (netif->remove_callback) {
    netif->remove_callback(netif);
  }

  Logf(true, ("netif_remove: removed netif\n") );
}

/**
 * @ingroup netif
 * Set a network interface as the default network interface
 * (used to output all packets for which no specific route is found)
 *
 * @param netif the default network interface
 */
void
set_netif_default(NetworkInterface& netif)
{


  if (netif == nullptr) {
    /* remove default route */
    // mib2_remove_route_ip4(1, netif);
  } else {
    /* install default route */
    // mib2_add_route_ip4(1, netif);
  }
  netif_default = netif;
  Logf(true, "netif: setting default interface %c%c\n",
           netif ? netif->name[0] : '\'', netif ? netif->name[1] : '\'');
}

/**
 * @ingroup netif
 * Bring an interface up, available for processing
 * traffic.
 */
void
set_netif_up(NetworkInterface& netif)
{




  if (!(netif->flags & NETIF_FLAG_UP)) {
    netif_set_flags(netif, NETIF_FLAG_UP);

    // MIB2_COPY_SYSUPTIME_TO(&netif->ts);

    NETIF_STATUS_CALLBACK(netif);


    {
      netif_ext_callback_args_t args;
      // args.status_changed.state = 1;
      netif_invoke_ext_callback(netif, LWIP_NSC_STATUS_CHANGED, &args);
    }


    netif_issue_reports(netif, NETIF_REPORT_TYPE_IPV4 | NETIF_REPORT_TYPE_IPV6);

    nd6_restart_netif(netif);

  }
}

/** Send ARP/IGMP/MLD/RS events, e.g. on link-up/netif-up or addr-change
 */
static void
netif_issue_reports(NetworkInterface& netif, uint8_t report_type)
{
  // lwip_assert("netif_issue_reports: invalid netif", netif != nullptr);

  /* Only send reports when both link and admin states are up */
  if (!(netif.link_up) ||
      !(netif.up)) {
    return;
  }


  if ((report_type & NETIF_REPORT_TYPE_IPV4) &&
      !ip4_addr_isany_val(*get_netif_ip4_addr(netif,))) {

    /* For Ethernet network interfaces, we would like to send a "gratuitous ARP" */
    if (netif.eth_arp) {
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
set_netif_down(NetworkInterface& netif)
{




  if (netif->flags & NETIF_FLAG_UP) {

    {
      netif_ext_callback_args_t args;
      // args.status_changed.state = 0;
      netif_invoke_ext_callback(netif, LWIP_NSC_STATUS_CHANGED, &args);
    }


    netif_clear_flags(netif, NETIF_FLAG_UP);
    // MIB2_COPY_SYSUPTIME_TO(&netif->ts);


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
netif_set_status_callback(NetworkInterface*netif, netif_status_callback_fn status_callback)
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
netif_set_remove_callback(NetworkInterface*netif, netif_status_callback_fn remove_callback)
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
set_netif_link_up(NetworkInterface& netif)
{




  if (!(netif->flags & NETIF_FLAG_LINK_UP)) {
    netif_set_flags(netif, NETIF_FLAG_LINK_UP);

    // dhcp_network_changed(netif);

    autoip_network_changed(netif);


    netif_issue_reports(netif, NETIF_REPORT_TYPE_IPV4 | NETIF_REPORT_TYPE_IPV6);
    nd6_restart_netif(netif);

    NETIF_LINK_CALLBACK(netif);
    {
      netif_ext_callback_args_t args;
      // args.link_changed.state = 1;
      netif_invoke_ext_callback(netif, LWIP_NSC_LINK_CHANGED, &args);
    }
  }
}

/**
 * @ingroup netif
 * Called by a driver when its link goes down
 */
void
set_netif_link_down(NetworkInterface& netif)
{




  if (netif->flags & NETIF_FLAG_LINK_UP) {
    netif_clear_flags(netif, NETIF_FLAG_LINK_UP);
    NETIF_LINK_CALLBACK(netif);
    {
      netif_ext_callback_args_t args;
      // args.link_changed.state = 0;
      netif_invoke_ext_callback(netif, LWIP_NSC_LINK_CHANGED, &args);
    }

  }
}

/**
 * @ingroup netif
 * Set callback to be called when link is brought up/down
 */
void
netif_set_link_callback(NetworkInterface*netif, netif_status_callback_fn link_callback)
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
 * @param pkt_buf the (IP) packet to 'send'
 * @return ERR_OK if the packet has been sent
 *         ERR_MEM if the PacketBuffer used to copy the packet couldn't be allocated
 */
LwipStatus
output_netif_loop(NetworkInterface& netif, PacketBuffer& pkt_buf)
{
    LwipStatus err;
  struct PacketBuffer *last;

  uint16_t clen = 0;
  /* If we have a loopif, SNMP counters are adjusted for it,
   * if not they are adjusted for 'netif'. */

  NetworkInterface* stats_if = loop_netif;

  uint8_t schedule_poll = 0;


  lwip_assert("netif_loop_output: invalid netif", netif != nullptr);
  lwip_assert("netif_loop_output: invalid PacketBuffer", pkt_buf != nullptr);

  /* Allocate a new PacketBuffer */
  struct PacketBuffer* r = pbuf_alloc(PBUF_LINK, pkt_buf->tot_len);
  if (r == nullptr) {
    // LINK_STATS_INC(link.memerr);
    // LINK_STATS_INC(link.drop);
    // MIB2_STATS_NETIF_INC(stats_if, ifoutdiscards);
    return ERR_MEM;
  }

  clen = pbuf_clen(r);
  /* check for overflow or too many PacketBuffer on queue */
  if (((netif->loop_cnt_current + clen) < netif->loop_cnt_current) ||
      ((netif->loop_cnt_current + clen) > std::min(LWIP_LOOPBACK_MAX_PBUFS, 0xFFFF))) {
    free_pkt_buf(r);
    // LINK_STATS_INC(link.memerr);
    // LINK_STATS_INC(link.drop);
    // MIB2_STATS_NETIF_INC(stats_if, ifoutdiscards);
    return ERR_MEM;
  }
  netif->loop_cnt_current = (uint16_t)(netif->loop_cnt_current + clen);


  /* Copy the whole PacketBuffer queue p into the single PacketBuffer r */
  if ((err = pbuf_copy(r, pkt_buf)) != ERR_OK) {
    free_pkt_buf(r);
    // LINK_STATS_INC(link.memerr);
    // LINK_STATS_INC(link.drop);
    // MIB2_STATS_NETIF_INC(stats_if, ifoutdiscards);
    return err;
  }

  /* Put the packet on a linked list which gets emptied through calling
     netif_poll(). */

  /* let last point to the last PacketBuffer in chain r */
  for (last = r; last->next != nullptr; last = last->next) {
    /* nothing to do here, just get to the last PacketBuffer */
  }


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


  /* For multithreading environment, schedule a call to netif_poll */
  if (schedule_poll) {
    tcpip_try_callback((TcpipCallbackFn)poll_netif, (uint8_t*) netif);
  }


  return ERR_OK;
}
static LwipStatus
netif_loop_output_ipv4(NetworkInterface*netif, struct PacketBuffer *p, const Ip4Addr *addr)
{
  NetworkInterface* loop_netif = nullptr;
  return output_netif_loop(netif, p);
}

static LwipStatus
netif_loop_output_ipv6(NetworkInterface*netif, struct PacketBuffer *p, const Ip6Addr *addr)
{
  NetworkInterface* loop_netif = nullptr;
  return output_netif_loop(netif, p);
}



/**
 * Call netif_poll() in the main loop of your application. This is to prevent
 * reentering non-reentrant functions like tcp_input(). Packets passed to
 * netif_loop_output() are put on a list that is passed to netif->input() by
 * netif_poll().
 */
void
poll_netif(NetworkInterface*netif)
{
  /* If we have a loopif, SNMP counters are adjusted for it,
   * if not they are adjusted for 'netif'. */

  lwip_assert("netif_poll: invalid netif", netif != nullptr);

  /* Get a packet from the list. With SYS_LIGHTWEIGHT_PROT=1, this is protected */
  while (netif->loop_first != nullptr) {
    struct PacketBuffer*in_end;

    uint8_t clen = 1;


    struct PacketBuffer* in = in_end = netif->loop_first;
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

    in->if_idx = get_and_inc_netif_num(netif);

    /* loopback packets are always IP packets! */
    if (ip_input(in, netif) != ERR_OK) {
      free_pkt_buf(in);
    }

  }

}

/**
 * @ingroup netif_cd
 * Allocate an index to store data in client_data member of NetworkInterface*.
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
 * @param index index of the IPv6 address
 * @param addr_info the new IPv6 address
 *
 * @note call netif_ip6_addr_set_state() to set the address valid/temptative
 */
void
set_netif_ip6_addr(NetworkInterface& netif, size_t index, Ip6AddrInfo& addr_info)
{


  lwip_assert("netif_ip6_addr_set: invalid netif", netif != nullptr);
  lwip_assert("netif_ip6_addr_set: invalid addr6", addr_info != nullptr);

  set_netif_ip6_addr_parts(netif, index, addr_info->addr[0], addr_info->addr[1],
                           addr_info->addr[2], addr_info->addr[3]);
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
set_netif_ip6_addr_parts(NetworkInterface& netif, size_t index, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
{
  IpAddr old_addr;
  IpAddr new_ipaddr;

  lwip_assert("netif != NULL", netif != nullptr);
  lwip_assert("invalid index", index < LWIP_IPV6_NUM_ADDRESSES);

  copy_ip6_addr((&old_addr.u_addr.ip6), get_netif_ip6_addr(netif, index));
  set_ip_addr_type_val(old_addr, IPADDR_TYPE_V6);

  /* address is actually being changed? */
  if (((&old_addr.u_addr.ip6)->addr[0] != a) || ((&old_addr.u_addr.ip6)->addr[1] != b) ||
      ((&old_addr.u_addr.ip6)->addr[2] != c) || ((&old_addr.u_addr.ip6)->addr[3] != d)) {
    Logf(true, ("netif_ip6_addr_set: netif address being changed\n"));

    make_ip_addr_ip6(&new_ipaddr, a, b, c, d);
    assign_ip6_addr_zone((&new_ipaddr.u_addr.ip6), IP6_UNICAST, netif,);

    if (is_ip6_addr_valid(get_netif_ip6_addr_state(netif, index))) {
      netif_do_ip_addr_changed(get_netif_ip6_addr_info(netif, index), &new_ipaddr);
    }
    /* @todo: remove/readd mib2 ip6 entries? */

    copy_ip_addr(&netif->ip6_addr[index], &new_ipaddr);

    if (is_ip6_addr_valid(get_netif_ip6_addr_state(netif, index))) {
      netif_issue_reports(netif, NETIF_REPORT_TYPE_IPV6);
      NETIF_STATUS_CALLBACK(netif);
    }

    {
      netif_ext_callback_args_t args;
      // args.ipv6_set.addr_index  = addr_idx;
      // args.ipv6_set.old_address = &old_addr;
      netif_invoke_ext_callback(netif, LWIP_NSC_IPV6_SET, &args);
    }
  }

  Logf(true, "netif: IPv6 address %d of interface %c%c set to %s/0x%x\n",
              index, netif->name[0], netif->name[1], ip6_addr_ntoa(get_netif_ip6_addr(netif, index)),
              get_netif_ip6_addr_state(netif, index));
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
netif_ip6_addr_set_state(NetworkInterface& netif, int8_t addr_idx, Ip6AddrState state)
{
    lwip_assert("netif != NULL", netif != nullptr);
  lwip_assert("invalid index", addr_idx < LWIP_IPV6_NUM_ADDRESSES);

  uint8_t old_state = get_netif_ip6_addr_state(netif, addr_idx);
  /* state is actually being changed? */
  if (old_state != state) {
    uint8_t old_valid = old_state & IP6_ADDR_VALID;
    uint8_t new_valid = state & IP6_ADDR_VALID;
    Logf(true, ("netif_ip6_addr_set_state: netif address state being changed\n"));
    /* Reevaluate solicited-node multicast group membership. */
    if (netif->mld6) {
      nd6_adjust_mld_membership(netif, addr_idx, state);
    }

    if (old_valid && !new_valid) {
      /* address about to be removed by setting invalid */
      netif_do_ip_addr_changed(get_netif_ip6_addr_info(netif, addr_idx), nullptr);
      /* @todo: remove mib2 ip6 entries? */
    }
    netif->ip6_addr_state[addr_idx] = state;

    if (!old_valid && new_valid) {
      /* address added by setting valid */
      /* This is a good moment to check that the address is properly zoned. */
      // IP6_ADDR_ZONECHECK_NETIF(netif_ip6_addr(netif, addr_idx), netif);
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
      args.ipv6_addr_state_changed.address    = get_netif_ip6_addr_info(netif, addr_idx);
      netif_invoke_ext_callback(netif, LWIP_NSC_IPV6_ADDR_STATE_CHANGED, &args);
    }

  }
  Logf(true, "netif: IPv6 address %d of interface %c%c set to %s/0x%x\n",
              addr_idx, netif->name[0], netif->name[1], ip6_addr_ntoa(get_netif_ip6_addr(netif, addr_idx)),
              get_netif_ip6_addr_state(netif, addr_idx));
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
 * @param addr the IPv6 address to find
 * @return >= 0: address found, this is its index
 *         -1: address not found on this netif
 */
size_t
get_netif_ip6_addr_match_idx(NetworkInterface& netif, const Ip6Addr& addr)
{
    lwip_assert("netif_get_ip6_addr_match: invalid netif", netif != nullptr);
  lwip_assert("netif_get_ip6_addr_match: invalid ip6addr", addr != nullptr);

  if (ip6_addr_has_zone(addr) && !est_ip6_addr_zone(addr, netif)) {
    return -1; /* wrong zone, no match */
  }


  for (int8_t i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
    if (!is_ip6_addr_state_invalid(get_netif_ip6_addr_state(netif, i)) &&
        cmp_ip6_addr_zoneless(get_netif_ip6_addr(netif, i), addr)) {
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
size_t
create_netif_ip6_link_local_addr(NetworkInterface& netif, bool from_mac_48bit)
{
    lwip_assert("netif_create_ip6_linklocal_address: invalid netif", netif != nullptr);

  /* Link-local prefix. */
  (&netif->ip6_addr[0].u_addr.ip6)->addr[0] = pp_htonl(0xfe800000ul);
  (&netif->ip6_addr[0].u_addr.ip6)->addr[1] = 0;

  /* Generate interface ID. */
  if (from_mac_48bit) {
    /* Assume hwaddr is a 48-bit IEEE 802 MAC. Convert to EUI-64 address. Complement Group bit. */
    (&netif->ip6_addr[0].u_addr.ip6)->addr[2] = lwip_htonl((((uint32_t)(netif->hwaddr[0] ^ 0x02)) << 24) |
        ((uint32_t)(netif->hwaddr[1]) << 16) |
        ((uint32_t)(netif->hwaddr[2]) << 8) |
        (0xff));
    (&netif->ip6_addr[0].u_addr.ip6)->addr[3] = lwip_htonl((uint32_t)(0xfeul << 24) |
        ((uint32_t)(netif->hwaddr[3]) << 16) |
        ((uint32_t)(netif->hwaddr[4]) << 8) |
        (netif->hwaddr[5]));
  } else {
    /* Use hwaddr directly as interface ID. */
    (&netif->ip6_addr[0].u_addr.ip6)->addr[2] = 0;
    (&netif->ip6_addr[0].u_addr.ip6)->addr[3] = 0;

    uint8_t addr_index = 3;
    for (uint8_t i = 0; (i < 8) && (i < netif->hwaddr_len); i++) {
      if (i == 4) {
        addr_index--;
      }
      (&netif->ip6_addr[0].u_addr.ip6)->addr[addr_index] |= lwip_htonl(((uint32_t)(netif->hwaddr[netif->hwaddr_len - i - 1])) << (8 * (i & 0x03)));
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
  assign_ip6_addr_zone((&netif->ip6_addr[0].u_addr.ip6), IP6_UNICAST, netif,);

  /* Set address state. */

  /* Will perform duplicate address detection (DAD). */
  set_netif_ip6_addr_state(netif, 0, IP6_ADDR_TENTATIVE);

}

/**
 * @ingroup netif_ip6
 * This function allows for the easy addition of a new IPv6 address to an interface.
 * It takes care of finding an empty slot and then sets the address tentative
 * (to make sure that all the subsequent processing happens).
 *
 * @param netif netif to add the address on
 * @param ip6addr address to add
 * @param out_index if != NULL, the chosen IPv6 address index will be stored here
 */
LwipStatus
add_netif_ip6_addr(NetworkInterface& netif, const Ip6Addr& ip6addr, size_t& out_index)
{
    lwip_assert("netif_add_ip6_address: invalid netif", netif != nullptr);
  lwip_assert("netif_add_ip6_address: invalid ip6addr", ip6addr != nullptr);

  int8_t i = get_netif_ip6_addr_match_idx(netif, ip6addr);
  if (i >= 0) {
    /* Address already added */
    if (out_index != nullptr) {
      *out_index = i;
    }
    return ERR_OK;
  }

  /* Find a free slot. The first one is reserved for link-local addresses. */
  for (i = ip6_addr_islinklocal(ip6addr) ? 0 : 1; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
    if (is_ip6_addr_state_invalid(get_netif_ip6_addr_state(netif, i))) {
      ip_addr_copy_from_ip6(&netif->ip6_addr[i], ip6addr);
      assign_ip6_addr_zone((&netif->ip6_addr[i].u_addr.ip6), IP6_UNICAST, netif,);
      set_netif_ip6_addr_state(netif, i, IP6_ADDR_TENTATIVE);
      if (out_index != nullptr) {
        *out_index = i;
      }
      return ERR_OK;
    }
  }

  if (out_index != nullptr) {
    *out_index = -1;
  }
  return ERR_VAL;
}

/** Dummy IPv6 output function for netifs not supporting IPv6
 */
static LwipStatus
netif_null_output_ip6(NetworkInterface*netif, struct PacketBuffer *p, const Ip6Addr *ipaddr)
{
    return ERR_IF;
}


/** Dummy IPv4 output function for netifs not supporting IPv4
 */
static LwipStatus
netif_null_output_ip4(NetworkInterface*netif, struct PacketBuffer *p, const Ip4Addr *ipaddr)
{
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
netif_name_to_index(std::string& name)
{
  NetworkInterface*netif = find_netif(name);
  if (netif != nullptr) {
    return get_and_inc_netif_num(netif);
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
std::string netif_index_to_name(uint8_t idx, std::string& name)
{
  NetworkInterface*netif = get_netif_by_index(idx);

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
NetworkInterface
get_netif_by_index(size_t idx)
{
  NetworkInterface*netif;



  if (idx != NETIF_NO_INDEX) {
    for ((netif) = netif_list; (netif) != nullptr; (netif) = (netif)->next) {
      if (idx == get_and_inc_netif_num(netif)) {
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
NetworkInterface
find_netif(std::string& name)
{
  NetworkInterface*netif;
  if (name == nullptr) {
    return nullptr;
  }

  uint8_t num = (uint8_t)atoi(&name[2]);

  for ((netif) = netif_list; (netif) != nullptr; (netif) = (netif)->next) {
    if (num == netif->if_num &&
        name[0] == netif->name[0] &&
        name[1] == netif->name[1]) {
      Logf(true, "netif_find: found %c%c\n", name[0], name[1]);
      return netif;
    }
  }
  Logf(true, "netif_find: didn't find %c%c\n", name[0], name[1]);
  return nullptr;
}

/**
 * @ingroup netif
 * Add extended netif events listener
 * @param callback pointer to listener structure
 * @param fn callback function
 */
void
netif_add_ext_callback(NetifExtCallback *callback, NetifExtCallbackFn fn)
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
netif_remove_ext_callback(NetifExtCallback* callback)
{
    lwip_assert("callback must be != NULL", callback != nullptr);

  if (ext_callback == nullptr) {
    return;
  }

  if (callback == ext_callback) {
    ext_callback = ext_callback->next;
  } else {
    NetifExtCallback* last = ext_callback;
    for (NetifExtCallback* iter = ext_callback->next; iter != nullptr; last = iter, iter = iter->next) {
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
netif_invoke_ext_callback(NetworkInterface*netif, NetifNscReason reason, const netif_ext_callback_args_t *args)
{
  NetifExtCallback *callback = ext_callback;

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
const Ip6AddrInfo
select_ip6_src_addr(const NetworkInterface& netif, const Ip6AddrInfo& dest)
{
    int8_t dest_scope, cand_scope;
    int8_t best_scope = IP6_MULTICAST_SCOPE_RESERVED;
    uint8_t best_pref = 0;
    uint8_t best_bits = 0;
    /* Start by determining the scope of the given destination address. These
      * tests are hopefully (roughly) in order of likeliness to match. */
    if (is_ip6_addr_global(dest))
    {
        dest_scope = IP6_MULTICAST_SCOPE_GLOBAL;
    }
    else if (ip6_addr_islinklocal(dest) || is_ip6_addr_loopback(dest))
    {
        dest_scope = IP6_MULTICAST_SCOPE_LINK_LOCAL;
    }
    else if (is_ip6_addr_unique_local(dest))
    {
        dest_scope = IP6_MULTICAST_SCOPE_ORGANIZATION_LOCAL;
    }
    else if (is_ip6_addr_mcast(dest))
    {
        dest_scope = get_ip6_addr_mcast_scope(dest);
    }
    else if (is_ip6_addr_site_local(dest))
    {
        dest_scope = IP6_MULTICAST_SCOPE_SITE_LOCAL;
    }
    else
    {
        /* no match, consider scope global */
        dest_scope = IP6_MULTICAST_SCOPE_GLOBAL;
    }
    const IpAddr* best_addr = nullptr;
    for (uint8_t i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++)
    {
        /* Consider only valid (= preferred and deprecated) addresses. */
        if (!is_ip6_addr_valid(get_netif_ip6_addr_state(netif, i)))
        {
            continue;
        } /* Determine the scope of this candidate address. Same ordering idea. */
        const Ip6Addr* cand_addr = get_netif_ip6_addr(netif, i);
        if (is_ip6_addr_global(cand_addr))
        {
            cand_scope = IP6_MULTICAST_SCOPE_GLOBAL;
        }
        else if (ip6_addr_islinklocal(cand_addr))
        {
            cand_scope = IP6_MULTICAST_SCOPE_LINK_LOCAL;
        }
        else if (is_ip6_addr_unique_local(cand_addr))
        {
            cand_scope = IP6_MULTICAST_SCOPE_ORGANIZATION_LOCAL;
        }
        else if (is_ip6_addr_site_local(cand_addr))
        {
            cand_scope = IP6_MULTICAST_SCOPE_SITE_LOCAL;
        }
        else
        {
            /* no match, treat as low-priority global scope */
            cand_scope = IP6_MULTICAST_SCOPE_RESERVEDF;
        }
        uint8_t cand_pref = is_ip6_addr_preferred(get_netif_ip6_addr_state(netif, i));
        /* @todo compute the actual common bits, for longest matching prefix. */
        /* We cannot count on the destination address having a proper zone
            * assignment, so do not compare zones in this case. */
        uint8_t cand_bits = cmp_ip6_net_zoneless(cand_addr, dest); /* just 1 or 0 for now */
        if (cand_bits && ip6_addr_hosts_equal(cand_addr, dest))
        {
            return get_netif_ip6_addr_info(netif, i); /* Rule 1 */
        }
        if ((best_addr == nullptr) || /* no alternative yet */ ((cand_scope < best_scope)
            && (cand_scope >= dest_scope)) || ((cand_scope > best_scope) && (best_scope <
            dest_scope)) || /* Rule 2 */ ((cand_scope == best_scope) && ((cand_pref >
            best_pref) || /* Rule 3 */ ((cand_pref == best_pref) && (cand_bits > best_bits
        )))))
        {
            /* Rule 8 */ /* We found a new "winning" candidate. */
            best_addr = get_netif_ip6_addr_info(netif, i);
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