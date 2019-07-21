
#include <opt.h>
#include <lwip_debug.h>
#include <autoip.h>
#include <def.h>
#include <icmp.h>
#include <inet_chksum.h>
#include <ip.h>
#include <ip4_frag.h>
#include <netif.h>
#include <stats.h>
#include <tcp_priv.h>
#include <udp.h>
#include <iana.h>


/**
 * LWIP_HOOK_IP4_ROUTE_SRC(src, dest):
 * Source-based routing for IPv4 - called from ip_route() (IPv4)
 * Signature:\code{.c}
 *   NetIfc*my_hook(const Ip4Addr *src, const Ip4Addr *dest);
 * \endcode
 * Arguments:
 * - src: local/source IPv4 address
 * - dest: destination IPv4 address
 * Returns values:
 * - the destination netif
 * - NULL if no destination netif is found. In that case, ip_route() continues as normal.
 */
inline NetIfc* hook_ip4_route_src(const Ip4Addr* src, const Ip4Addr* dest)
{
    return nullptr;
}

/** Set this to 0 in the rare case of wanting to call an extra function to
 * generate the IP checksum (in contrast to calculating it on-the-fly). */

/** Some defines for DHCP to let link-layer-addressed packets through while the
 * netif is down.
 * To use this in your own application/protocol, define LWIP_IP_ACCEPT_UDP_PORT(port)
 * to return 1 if the port is accepted and 0 if the port is not accepted.
 */
inline bool ip4_accept_udp_port(const uint16_t dst_port)
{
    return ((dst_port) == pp_ntohs(12345));
} 

/* accept DHCP client port and custom port */
inline bool ip_accept_link_layer_addressed_port(const uint16_t port)
{
    return (((port) == pp_ntohs(LWIP_IANA_PORT_DHCP_CLIENT)) || (ip4_accept_udp_port(port))
    );
} 

/** The IP header ID of the next outgoing IP packet */
static uint16_t ip_id; /** The default netif used for multicast */
static NetIfc* ip4_default_multicast_netif;

/**
 * @ingroup ip4
 * Set a default netif for IPv4 multicast. */
void ip4_set_default_multicast_netif(NetIfc* default_multicast_netif)
{
    ip4_default_multicast_netif = default_multicast_netif;
}

/**
 * Source based IPv4 routing must be fully implemented in
 * LWIP_HOOK_IP4_ROUTE_SRC(). This function only provides the parameters.
 */
NetIfc* ip4_route_src(const Ip4Addr* src, const Ip4Addr* dest)
{
    if (src != nullptr)
    {
        /* when src==NULL, the hook is called from ip4_route(dest) */
        NetIfc* netif = hook_ip4_route_src(src, dest);
        if (netif != nullptr)
        {
            return netif;
        }
    }
    return ip4_route(dest);
}

/**
 * Finds the appropriate network interface for a given IP address. It
 * searches the list of network interfaces linearly. A match is found
 * if the masked IP address of the network interface equals the masked
 * IP address given to the function.
 *
 * @param dest the destination IP address for which to find the route
 * @return the netif on which to send to reach dest
 */
NetIfc* ip4_route(const Ip4Addr* dest)
{
    NetIfc* netif;
    
    /* Use administratively selected interface for multicast by default */
    if (ip4_addr_ismulticast(dest) && ip4_default_multicast_netif)
    {
        return ip4_default_multicast_netif;
    } /* bug #54569: in case LWIP_SINGLE_NETIF=1 and Logf() disabled, the following loop is optimized away */
    ; /* iterate through netifs */
    for ((netif) = netif_list; (netif) != nullptr; (netif) = (netif)->next)
    {
        /* is the netif up, does it have a link and a valid address? */
        if (netif_is_up(netif) && netif_is_link_up(netif) && !ip4_addr_isany_val(
            *get_net_ifc_ip4_addr(netif)))
        {
            /* network mask matches? */
            if (ip4_addr_netcmp(dest,
                                get_net_ifc_ip4_addr(netif),
                                netif_ip4_netmask(netif)))
            {
                /* return netif on which to forward IP packet */
                return netif;
            } /* gateway matches on a non broadcast interface? (i.e. peer in a point to point interface) */
            if (((netif->flags & NETIF_FLAG_BCAST) == 0) && ip4_addr_cmp(
                dest,
                netif_ip4_gw(netif)))
            {
                /* return netif on which to forward IP packet */
                return netif;
            }
        }
    }

  /* loopif is disabled, looopback traffic is passed through any netif */
  if (ip4_addr_isloopback(dest)) {
    /* don't check for link on loopback traffic */
    if (netif_default != nullptr && netif_is_up(netif_default)) {
      return netif_default;
    }
    /* default netif is not up, just use any netif for loopback traffic */
    for ((netif) = netif_list; (netif) != nullptr; (netif) = (netif)->next) {
      if (netif_is_up(netif)) {
        return netif;
      }
    }
    return nullptr;
  }


  netif = LWIP_HOOK_IP4_ROUTE_SRC(NULL, dest);
  if (netif != nullptr) {
    return netif;
  }

  netif = LWIP_HOOK_IP4_ROUTE(dest);
  if (netif != nullptr) {
    return netif;
  }

    if ((netif_default == nullptr) || !netif_is_up(netif_default) || !
        netif_is_link_up(netif_default) || ip4_addr_isany_val(
            *get_net_ifc_ip4_addr(netif_default)) || ip4_addr_isloopback(dest))
    {
        /* No matching netif found and default netif is not usable.
           If this is not good enough for you, use LWIP_HOOK_IP4_ROUTE() */
        //    Logf(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("ip4_route: No route to %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
        //                ip4_addr1_16(dest), ip4_addr2_16(dest), ip4_addr3_16(dest), ip4_addr4_16(dest)));
        return nullptr;
    }
    return netif_default;
}


/**
 * Determine whether an IP address is in a reserved set of addresses
 * that may not be forwarded, or whether datagrams to that destination
 * may be forwarded.
 * @param p the packet to forward
 * @return 1: can forward 0: discard
 */
static int
ip4_canforward(struct PacketBuffer *p)
{
  uint32_t addr = lwip_htonl(get_ip4_addr(ip4_current_dest_addr()));

  int ret = LWIP_HOOK_IP4_CANFORWARD(p, addr);
  if (ret >= 0) {
    return ret;
  }


  if (p->flags & PBUF_FLAG_LLBCAST) {
    /* don't route link-layer broadcasts */
    return 0;
  }
  if ((p->flags & PBUF_FLAG_LLMCAST) || IP_MULTICAST(addr)) {
    /* don't route link-layer multicasts (use LWIP_HOOK_IP4_CANFORWARD instead) */
    return 0;
  }
  if (IP_EXPERIMENTAL(addr)) {
    return 0;
  }
  if (IP_CLASSA(addr)) {
    uint32_t net = addr & IP_CLASSA_NET;
    if ((net == 0) || (net == ((uint32_t)IP_LOOPBACKNET << IP_CLASSA_NSHIFT))) {
      /* don't route loopback packets */
      return 0;
    }
  }
  return 1;
}

/**
 * Forwards an IP packet. It finds an appropriate route for the
 * packet, decrements the TTL value of the packet, adjusts the
 * checksum and outputs the packet on the appropriate interface.
 *
 * @param p the packet to forward (p->payload points to IP header)
 * @param iphdr the IP header of the input packet
 * @param inp the netif on which this packet was received
 */
static void
ip4_forward(struct PacketBuffer *p, struct Ip4Hdr *iphdr, NetIfc*inp)
{
  NetIfc*netif;

  PERF_START;
  ;

  if (!ip4_canforward(p)) {
    goto return_noroute;
  }

  /* RFC3927 2.7: do not forward link-local addresses */
  if (ip4_addr_islinklocal(ip4_current_dest_addr())) {
    Logf(IP_DEBUG, ("ip4_forward: not forwarding LLA %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
                           ip4_addr1_16(ip4_current_dest_addr()), ip4_addr2_16(ip4_current_dest_addr()),
                           ip4_addr3_16(ip4_current_dest_addr()), ip4_addr4_16(ip4_current_dest_addr())));
    goto return_noroute;
  }

  /* Find network interface where to forward this IP packet to. */
  netif = ip4_route_src(ip4_current_src_addr(), ip4_current_dest_addr());
  if (netif == nullptr) {
    Logf(IP_DEBUG, ("ip4_forward: no forwarding route for %"U16_F".%"U16_F".%"U16_F".%"U16_F" found\n",
                           ip4_addr1_16(ip4_current_dest_addr()), ip4_addr2_16(ip4_current_dest_addr()),
                           ip4_addr3_16(ip4_current_dest_addr()), ip4_addr4_16(ip4_current_dest_addr())));
    /* @todo: send ICMP_DUR_NET? */
    goto return_noroute;
  }

  /* Do not forward packets onto the same network interface on which
   * they arrived. */
  if (netif == inp) {
    Logf(IP_DEBUG, ("ip4_forward: not bouncing packets back on incoming interface.\n"));
    goto return_noroute;
  }


  /* decrement TTL */
  IPH_TTL_SET(iphdr, IPH_TTL(iphdr) - 1);
  /* send ICMP if TTL == 0 */
  if (IPH_TTL(iphdr) == 0) {
    

    /* Don't send ICMP messages in response to ICMP messages */
    if (IPH_PROTO(iphdr) != IP_PROTO_ICMP) {
      icmp_time_exceeded(p, ICMP_TE_TTL);
    }

    return;
  }

  /* Incrementally update the IP checksum. */
  if (IPH_CHKSUM(iphdr) >= PpHtons(0xffffU - 0x100)) {
    IPH_CHKSUM_SET(iphdr, (uint16_t)(IPH_CHKSUM(iphdr) + PpHtons(0x100) + 1));
  } else {
    IPH_CHKSUM_SET(iphdr, (uint16_t)(IPH_CHKSUM(iphdr) + PpHtons(0x100)));
  }

  Logf(IP_DEBUG, ("ip4_forward: forwarding packet to %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
                         ip4_addr1_16(ip4_current_dest_addr()), ip4_addr2_16(ip4_current_dest_addr()),
                         ip4_addr3_16(ip4_current_dest_addr()), ip4_addr4_16(ip4_current_dest_addr())));

  IP_STATS_INC(ip.fw);
  
  IP_STATS_INC(ip.xmit);

  PERF_STOP("ip4_forward");
  /* don't fragment if interface has mtu set to 0 [loopif] */
  if (netif->mtu && (p->tot_len > netif->mtu)) {
    if ((IPH_OFFSET(iphdr) & PP_NTOHS(IP_DF)) == 0) {

      ip4_frag(p, netif, ip4_current_dest_addr());

    } else {

      /* send ICMP Destination Unreachable code 4: "Fragmentation Needed and DF Set" */
      icmp_dest_unreach(p, ICMP_DUR_FRAG);

    }
    return;
  }
  /* transmit PacketBuffer on chosen interface */
  netif->output(netif, p, ip4_current_dest_addr());
  return;
return_noroute:
  
}


/** Return true if the current input packet should be accepted on this netif */
static int
ip4_input_accept(NetIfc*netif)
{
//  Logf(IP_DEBUG, ("ip_input: iphdr->dest 0x%"X32_F" netif->ip_addr 0x%"X32_F" (0x%"X32_F", 0x%"X32_F", 0x%"X32_F")\n",
//                         ip4_addr_get_u32(ip4_current_dest_addr()), ip4_addr_get_u32(netif_ip4_addr(netif)),
//                         ip4_addr_get_u32(ip4_current_dest_addr()) & ip4_addr_get_u32(netif_ip4_netmask(netif)),
//                         ip4_addr_get_u32(netif_ip4_addr(netif)) & ip4_addr_get_u32(netif_ip4_netmask(netif)),
//                         ip4_addr_get_u32(ip4_current_dest_addr()) & ~ip4_addr_get_u32(netif_ip4_netmask(netif))));

  /* interface is up and configured? */
  if ((netif_is_up(netif)) && (!ip4_addr_isany_val(*get_net_ifc_ip4_addr(netif)))) {
    /* unicast to this interface address? */
    if (ip4_addr_cmp(ip4_current_dest_addr(), get_net_ifc_ip4_addr(netif)) ||
        /* or broadcast on this interface network address? */
        ip4_addr_isbroadcast(ip4_current_dest_addr(), netif)

        || (get_ip4_addr(ip4_current_dest_addr()) == PP_HTONL(IPADDR_LOOPBACK))

       ) {
      Logf(IP_DEBUG, ("ip4_input: packet accepted on interface %c%c\n",
               netif->name[0], netif->name[1]));
      /* accept on this netif */
      return 1;
    }

    /* connections to link-local addresses must persist after changing
        the netif's address (RFC3927 ch. 1.9) */
    if (autoip_accept_packet(netif, ip4_current_dest_addr())) {
      Logf(IP_DEBUG, ("ip4_input: LLA packet accepted on interface %c%c\n",
                             netif->name[0], netif->name[1]));
      /* accept on this netif */
      return 1;
    }

  }
  return 0;
}

/**
 * This function is called by the network interface device driver when
 * an IP packet is received. The function does the basic checks of the
 * IP header such as packet size being at least larger than the header
 * size etc. If the packet was not destined for us, the packet is
 * forwarded (using ip_forward). The IP checksum is always checked.
 *
 * Finally, the packet is sent to the upper layer protocol input function.
 *
 * @param p the received IP packet (p->payload points to IP header)
 * @param inp the netif on which this packet was received
 * @return ERR_OK if the packet was processed (could return ERR_* if it wasn't
 *         processed, but currently always returns ERR_OK)
 */
LwipStatus
ip4_input(struct PacketBuffer *p, NetIfc*inp)
{
  const struct Ip4Hdr *iphdr;
  NetIfc*netif;
  uint16_t iphdr_hlen;
  uint16_t iphdr_len;

  int check_ip_src = 1;


  raw_input_state_t raw_status;


  LWIP_ASSERT_CORE_LOCKED();

  IP_STATS_INC(ip.recv);
  

  /* identify the IP header */
  iphdr = (struct Ip4Hdr *)p->payload;
  if (get_ip4_hdr_version(iphdr) != 4) {
//    Logf(IP_DEBUG | LWIP_DBG_LEVEL_WARNING, ("IP packet dropped due to bad version number %"U16_F"\n", (uint16_t)IPH_V(iphdr)));
    ip4_debug_print(p);
    pbuf_free(p);
    IP_STATS_INC(ip.err);
    IP_STATS_INC(ip.drop);
    
    return ERR_OK;
  }

#ifdef LWIP_HOOK_IP4_INPUT
  if (LWIP_HOOK_IP4_INPUT(p, inp)) {
    /* the packet has been eaten */
    return ERR_OK;
  }
#endif

  /* obtain IP header length in bytes */
  iphdr_hlen = IPH_HL_BYTES(iphdr);
  /* obtain ip length in bytes */
  iphdr_len = lwip_ntohs(get_ip4_hdr_len(iphdr));

  /* Trim PacketBuffer. This is especially required for packets < 60 bytes. */
  if (iphdr_len < p->tot_len) {
    pbuf_realloc(p, iphdr_len);
  }

  /* header length exceeds first PacketBuffer length, or ip length exceeds total PacketBuffer length? */
  if ((iphdr_hlen > p->len) || (iphdr_len > p->tot_len) || (iphdr_hlen < kIp4HdrLen)) {
    if (iphdr_hlen < kIp4HdrLen) {
//      Logf(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
//                  ("ip4_input: short IP header (%"U16_F" bytes) received, IP packet dropped\n", iphdr_hlen));
    }
    if (iphdr_hlen > p->len) {
//      Logf(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
//                  ("IP header (len %"U16_F") does not fit in first PacketBuffer (len %"U16_F"), IP packet dropped.\n",
//                   iphdr_hlen, p->len));
    }
    if (iphdr_len > p->tot_len) {
//      Logf(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
//                  ("IP (len %"U16_F") is longer than PacketBuffer (len %"U16_F"), IP packet dropped.\n",
//                   iphdr_len, p->tot_len));
    }
    /* free (drop) packet pbufs */
    pbuf_free(p);
    IP_STATS_INC(ip.lenerr);
    IP_STATS_INC(ip.drop);
    
    return ERR_OK;
  }

  /* verify checksum */

  is_netif_checksum_enabled(inp, NETIF_CHECKSUM_CHECK_IP) {
    if (inet_chksum(iphdr, iphdr_hlen) != 0) {

//      Logf(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
//                  ("Checksum (0x%"X16_F") failed, IP packet dropped.\n", inet_chksum(iphdr, iphdr_hlen)));
      ip4_debug_print(p);
      pbuf_free(p);
      IP_STATS_INC(ip.chkerr);
      IP_STATS_INC(ip.drop);
      
      return ERR_OK;
    }
  }


  /* copy IP addresses to aligned IpAddr */
  copy_ip4_addr_to_ip_addr(ip_data.current_iphdr_dest, iphdr->dest);
  copy_ip4_addr_to_ip_addr(ip_data.current_iphdr_src, iphdr->src);

  /* match packet against an interface, i.e. is this packet for us? */
  if (ip4_addr_ismulticast(ip4_current_dest_addr())) {

    if ((inp->flags & NETIF_FLAG_IGMP) && (igmp_lookfor_group(inp, ip4_current_dest_addr()))) {
      /* IGMP snooping switches need 0.0.0.0 to be allowed as source address (RFC 4541) */
      Ip4Addr allsystems;
      Ipv4AddrFromBytes(&allsystems, 224, 0, 0, 1);
      if (ip4_addr_cmp(ip4_current_dest_addr(), &allsystems) &&
          ip4_addr_isany(ip4_current_src_addr())) {
        check_ip_src = 0;
      }
      netif = inp;
    } else {
      netif = nullptr;
    }

  } else {
    /* start trying with inp. if that's not acceptable, start walking the
       list of configured netifs. */
    if (ip4_input_accept(inp)) {
      netif = inp;
    } else {
      netif = nullptr;

      /* Packets sent to the loopback address must not be accepted on an
       * interface that does not have the loopback address assigned to it,
       * unless a non-loopback interface is used for loopback traffic. */
      if (!ip4_addr_isloopback(ip4_current_dest_addr()))

      {

        NETIF_FOREACH(netif) {
          if (netif == inp) {
            /* we checked that before already */
            continue;
          }
          if (ip4_input_accept(netif)) {
            break;
          }
        }

      }
    }
  }


  /* Pass DHCP messages regardless of destination address. DHCP traffic is addressed
   * using link layer addressing (such as Ethernet MAC) so we must not filter on IP.
   * According to RFC 1542 section 3.1.1, referred by RFC 2131).
   *
   * If you want to accept private broadcast communication while a netif is down,
   * define LWIP_IP_ACCEPT_UDP_PORT(dst_port), e.g.:
   *
   * #define LWIP_IP_ACCEPT_UDP_PORT(dst_port) ((dst_port) == PP_NTOHS(12345))
   */
  if (netif == nullptr) {
    /* remote port is DHCP server? */
    if (IPH_PROTO(iphdr) == IP_PROTO_UDP) {
      const struct udp_hdr *udphdr = (const struct udp_hdr *)((const uint8_t *)iphdr + iphdr_hlen);
      Logf(IP_DEBUG | LWIP_DBG_TRACE, ("ip4_input: UDP packet to DHCP client port %"U16_F"\n",
                                              lwip_ntohs(udphdr->dest)));
      if (IP_ACCEPT_LINK_LAYER_ADDRESSED_PORT(udphdr->dest)) {
        Logf(IP_DEBUG | LWIP_DBG_TRACE, ("ip4_input: DHCP packet accepted.\n"));
        netif = inp;
        check_ip_src = 0;
      }
    }
  }


  /* broadcast or multicast packet source address? Compliant with RFC 1122: 3.2.1.3 */

  if (check_ip_src

      /* DHCP servers need 0.0.0.0 to be allowed as source address (RFC 1.1.2.2: 3.2.1.3/a) */
      && !ip4_addr_isany_val(*ip4_current_src_addr())

     )

  {
    if ((ip4_addr_isbroadcast(ip4_current_src_addr(), inp)) ||
        (ip4_addr_ismulticast(ip4_current_src_addr()))) {
      /* packet source is not valid */
      Logf(IP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING, ("ip4_input: packet source is not valid.\n"));
      /* free (drop) packet pbufs */
      pbuf_free(p);
      IP_STATS_INC(ip.drop);
      
      
      return ERR_OK;
    }
  }

  /* packet not for us? */
  if (netif == nullptr) {
    /* packet not for us, route or discard */
    Logf(IP_DEBUG | LWIP_DBG_TRACE, ("ip4_input: packet not for us.\n"));

    /* non-broadcast packet? */
    if (!ip4_addr_isbroadcast(ip4_current_dest_addr(), inp)) {
      /* try to forward IP packet on (other) interfaces */
      ip4_forward(p, (struct Ip4Hdr *)p->payload, inp);
    } else

    {
      IP_STATS_INC(ip.drop);
      
      
    }
    pbuf_free(p);
    return ERR_OK;
  }
  /* packet consists of multiple fragments? */
  if ((IPH_OFFSET(iphdr) & pp_htons(IP_OFFMASK | IP_MF)) != 0) {

//    Logf(IP_DEBUG, ("IP packet is a fragment (id=0x%04"X16_F" tot_len=%"U16_F" len=%"U16_F" MF=%"U16_F" offset=%"U16_F"), calling ip4_reass()\n",
//                           lwip_ntohs(IPH_ID(iphdr)), p->tot_len, lwip_ntohs(IPH_LEN(iphdr)), (uint16_t)!!(IPH_OFFSET(iphdr) & PpHtons(IP_MF)), (uint16_t)((lwip_ntohs(IPH_OFFSET(iphdr)) & IP_OFFMASK) * 8)));
    /* reassemble the packet*/
    p = ip4_reass(p);
    /* packet not fully reassembled yet? */
    if (p == nullptr) {
      return ERR_OK;
    }
    iphdr = (const struct Ip4Hdr *)p->payload;

  }


  /* there is an extra "router alert" option in IGMP messages which we allow for but do not police */
  if ((iphdr_hlen > IP_HLEN) &&  (IPH_PROTO(iphdr) != IP_PROTO_IGMP)) {

    Logf(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("IP packet dropped since there were IP options (while IP_OPTIONS_ALLOWED == 0).\n"));
    pbuf_free(p);
    IP_STATS_INC(ip.opterr);
    IP_STATS_INC(ip.drop);
    /* unsupported protocol feature */
    
    return ERR_OK;
  }


  /* send to upper layers */
  Logf(IP_DEBUG, ("ip4_input: \n"));
  ip4_debug_print(p);
//  Logf(IP_DEBUG, ("ip4_input: p->len %"U16_F" p->tot_len %"U16_F"\n", p->len, p->tot_len));

  ip_data.current_netif = netif;
  ip_data.current_input_netif = inp;
  ip_data.current_ip4_header = iphdr;
  ip_data.current_ip_header_tot_len = IPH_HL_BYTES(iphdr);

  /* raw input did not eat the packet? */
  raw_status = raw_input(p, inp);
  if (raw_status != RAW_INPUT_EATEN)

  {
    pbuf_remove_header(p, iphdr_hlen); /* Move to payload, no check necessary. */

    switch (IPH_PROTO(iphdr)) {

      case IP_PROTO_UDP:

      case IP_PROTO_UDPLITE:

        
        udp_input(p, inp);
        break;


      case IP_PROTO_TCP:
        
        tcp_input(p, inp);
        break;

      case IP_PROTO_ICMP:
        
        icmp_input(p, inp);
        break;

      case IP_PROTO_IGMP:
        igmp_input(p, inp, ip4_current_dest_addr());
        break;

      default:

        if (raw_status == RAW_INPUT_DELIVERED) {
          
        } else

        {

          /* send ICMP destination protocol unreachable unless is was a broadcast */
          if (!ip4_addr_isbroadcast(ip4_current_dest_addr(), netif) &&
              !ip4_addr_ismulticast(ip4_current_dest_addr())) {
            pbuf_header_force(p, (int16_t)iphdr_hlen); /* Move to ip header, no check necessary. */
            icmp_dest_unreach(p, ICMP_DUR_PROTO);
          }


//          Logf(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("Unsupported transport protocol %"U16_F"\n", (uint16_t)IPH_PROTO(iphdr)));

          IP_STATS_INC(ip.proterr);
          IP_STATS_INC(ip.drop);
          
        }
        pbuf_free(p);
        break;
    }
  }

  /* @todo: this is not really necessary... */
  ip_data.current_netif = nullptr;
  ip_data.current_input_netif = nullptr;
  ip_data.current_ip4_header = nullptr;
  ip_data.current_ip_header_tot_len = 0;
  ip4_addr_set_any(ip4_current_src_addr());
  ip4_addr_set_any(ip4_current_dest_addr());

  return ERR_OK;
}

/**
 * Sends an IP packet on a network interface. This function constructs
 * the IP header and calculates the IP header checksum. If the source
 * IP address is NULL, the IP address of the outgoing network
 * interface is filled in as source address.
 * If the destination IP address is LWIP_IP_HDRINCL, p is assumed to already
 * include an IP header and p->payload points to it instead of the data.
 *
 * @param p the packet to send (p->payload points to the data, e.g. next
            protocol header; if dest == LWIP_IP_HDRINCL, p already includes an
            IP header and p->payload points to that IP header)
 * @param src the source IP address to send from (if src == IP4_ADDR_ANY, the
 *         IP  address of the netif used to send is used as source address)
 * @param dest the destination IP address to send the packet to
 * @param ttl the TTL value to be set in the IP header
 * @param tos the TOS value to be set in the IP header
 * @param proto the PROTOCOL to be set in the IP header
 * @param netif the netif on which to send this packet
 * @return ERR_OK if the packet was sent OK
 *         ERR_BUF if p doesn't have enough space for IP/LINK headers
 *         returns errors returned by netif->output
 *
 * @note ip_id: RFC791 "some host may be able to simply use
 *  unique identifiers independent of destination"
 */
LwipStatus
ip4_output_if(struct PacketBuffer *p, const Ip4Addr *src, const Ip4Addr *dest,
              uint8_t ttl, uint8_t tos,
              uint8_t proto, NetIfc*netif)
{
#if IP_OPTIONS_SEND
  return ip4_output_if_opt(p, src, dest, ttl, tos, proto, netif, NULL, 0);
}

/**
 * Same as ip_output_if() but with the possibility to include IP options:
 *
 * @ param ip_options pointer to the IP options, copied into the IP header
 * @ param optlen length of ip_options
 */
LwipStatus
ip4_output_if_opt(struct PacketBuffer *p, const Ip4Addr *src, const Ip4Addr *dest,
                  uint8_t ttl, uint8_t tos, uint8_t proto, NetIfc*netif, uint8_t *ip_options,
                  uint16_t optlen)
{
#endif /* IP_OPTIONS_SEND */
  const Ip4Addr *src_used = src;
  if (dest != nullptr) {
      if (ip4_addr_isany(src)) {
          src_used = get_net_ifc_ip4_addr(netif);
      }
  }

#if IP_OPTIONS_SEND
  return ip4_output_if_opt_src(p, src_used, dest, ttl, tos, proto, netif,
                               ip_options, optlen);
#else /* IP_OPTIONS_SEND */
  return ip4_output_if_src(p, src_used, dest, ttl, tos, proto, netif);
#endif /* IP_OPTIONS_SEND */
  }

  /**
 * Same as ip_output_if() but 'src' address is not replaced by netif address
 * when it is 'any'.
 */
  LwipStatus
  ip4_output_if_src(struct PacketBuffer *p,
                    const Ip4Addr *src,
                    const Ip4Addr *dest,
                    uint8_t ttl,
                    uint8_t tos,
                    uint8_t proto,
                    NetIfc*netif)
  {
#if IP_OPTIONS_SEND
  return ip4_output_if_opt_src(p, src, dest, ttl, tos, proto, netif, NULL, 0);
}

/**
 * Same as ip_output_if_opt() but 'src' address is not replaced by netif address
 * when it is 'any'.
 */
LwipStatus
ip4_output_if_opt_src(struct PacketBuffer *p, const Ip4Addr *src, const Ip4Addr *dest,
                      uint8_t ttl, uint8_t tos, uint8_t proto, NetIfc*netif, uint8_t *ip_options,
                      uint16_t optlen)
{
#endif /* IP_OPTIONS_SEND */
      struct Ip4Hdr *iphdr;
      Ip4Addr dest_addr;
#if CHECKSUM_GEN_IP_INLINE
      uint32_t chk_sum = 0;
#endif /* CHECKSUM_GEN_IP_INLINE */

      LWIP_ASSERT_CORE_LOCKED();
      LWIP_IP_CHECK_PBUF_REF_COUNT_FOR_TX(p);

      

      /* Should the IP header be generated or is it already included in p? */
      if (dest != nullptr)
      {
          uint16_t ip_hlen = kIp4HdrLen;

    uint16_t optlen_aligned = 0;
    if (optlen != 0) {

      int i;

      if (optlen > (IP_HLEN_MAX - IP_HLEN)) {
        /* optlen too long */
        Logf(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("ip4_output_if_opt: optlen too long\n"));
        IP_STATS_INC(ip.err);
        
        return ERR_VAL;
      }
      /* round up to a multiple of 4 */
      optlen_aligned = (uint16_t)((optlen + 3) & ~3);
      ip_hlen = (uint16_t)(ip_hlen + optlen_aligned);
      /* First write in the IP options */
      if (pbuf_add_header(p, optlen_aligned)) {
        Logf(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("ip4_output_if_opt: not enough room for IP options in PacketBuffer\n"));
        IP_STATS_INC(ip.err);
        
        return ERR_BUF;
      }
      MEMCPY(p->payload, ip_options, optlen);
      if (optlen < optlen_aligned) {
        /* zero the remaining bytes */
        memset(((char *)p->payload) + optlen, 0, (size_t)(optlen_aligned - optlen));
      }

      for (i = 0; i < optlen_aligned / 2; i++) {
        chk_sum += ((uint16_t *)p->payload)[i];
      }

    }

          /* generate IP header */
          if (pbuf_add_header(p, kIp4HdrLen))
          {
              Logf(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("ip4_output: not enough room for IP header in PacketBuffer\n"));

              IP_STATS_INC(ip.err);
              
              return ERR_BUF;
          }

          iphdr = (struct Ip4Hdr *)p->payload;
          lwip_assert("check that first PacketBuffer can hold struct Ip4Hdr",
                      (p->len >= sizeof(struct Ip4Hdr)));

          IPH_TTL_SET(iphdr, ttl);
          set_ip4_hdr_proto(iphdr, proto);

          chk_sum += PP_NTOHS(proto | (ttl << 8));


          /* dest cannot be NULL here */
          copy_ip4_addr(iphdr->dest, *dest);

          chk_sum += get_ip4_addr(&iphdr->dest) & 0xFFFF;
          chk_sum += get_ip4_addr(&iphdr->dest) >> 16;


          set_ip4_hdr_vhl(iphdr, 4, ip_hlen / 4);
          set_ip4_hdr_tos(iphdr, tos);

          chk_sum += PP_NTOHS(tos | (iphdr->_v_hl << 8));

          IPH_LEN_SET(iphdr, lwip_htons(p->tot_len));

          chk_sum += iphdr->_len;

          set_ip4_hdr_offset(iphdr, 0);
          IPH_ID_SET(iphdr, lwip_htons(ip_id));

          chk_sum += iphdr->_id;

          ++ip_id;

          if (src == nullptr)
          {
              copy_ip4_addr(iphdr->src, *IP4_ADDR_ANY4);
          } else
          {
              /* src cannot be NULL here */
              copy_ip4_addr(iphdr->src, *src);
          }

          chk_sum += get_ip4_addr(&iphdr->src) & 0xFFFF;
          chk_sum += get_ip4_addr(&iphdr->src) >> 16;
          chk_sum = (chk_sum >> 16) + (chk_sum & 0xFFFF);
          chk_sum = (chk_sum >> 16) + chk_sum;
          chk_sum = ~chk_sum;
          IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_IP) {
              iphdr->_chksum = (uint16_t)chk_sum; /* network order */
          }

    else {
      IPH_CHKSUM_SET(iphdr, 0);
    }

      } else
      {
          /* IP header already included in p */
          if (p->len < kIp4HdrLen)
          {
              Logf(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("ip4_output: LWIP_IP_HDRINCL but PacketBuffer is too short\n"));
              IP_STATS_INC(ip.err);
              
              return ERR_BUF;
          }
          iphdr = (struct Ip4Hdr *)p->payload;
          copy_ip4_addr(dest_addr, iphdr->dest);
          dest = &dest_addr;
      }

      IP_STATS_INC(ip.xmit);

      //  Logf(IP_DEBUG, ("ip4_output_if: %c%c%"U16_F"\n", netif->name[0], netif->name[1], (uint16_t)netif->num));
      ip4_debug_print(p);


  if (ip4_addr_cmp(dest, netif_ip4_addr(netif))

      || ip4_addr_isloopback(dest)

     ) {
    /* Packet to self, enqueue it for loopback */
    Logf(IP_DEBUG, ("netif_loop_output()"));
    return netif_loop_output(netif, p,);
  }

  if ((p->flags & PBUF_FLAG_MCASTLOOP) != 0) {
    netif_loop_output(netif, p,);
  }


      /* don't fragment if interface has mtu set to 0 [loopif] */
      if (netif->mtu && (p->tot_len > netif->mtu))
      {
          return ip4_frag(p, netif, dest);
      }


      //  Logf(IP_DEBUG, ("ip4_output_if: call netif->output()\n"));
      return netif->output(netif, p, dest);
  }

  /**
 * Simple interface to ip_output_if. It finds the outgoing network
 * interface and calls upon ip_output_if to do the actual work.
 *
 * @param p the packet to send (p->payload points to the data, e.g. next
            protocol header; if dest == LWIP_IP_HDRINCL, p already includes an
            IP header and p->payload points to that IP header)
 * @param src the source IP address to send from (if src == IP4_ADDR_ANY, the
 *         IP  address of the netif used to send is used as source address)
 * @param dest the destination IP address to send the packet to
 * @param ttl the TTL value to be set in the IP header
 * @param tos the TOS value to be set in the IP header
 * @param proto the PROTOCOL to be set in the IP header
 *
 * @return ERR_RTE if no route is found
 *         see ip_output_if() for more return values
 */
  LwipStatus
  ip4_output(struct PacketBuffer *p,
             const Ip4Addr *src,
             const Ip4Addr *dest,
             uint8_t ttl,
             uint8_t tos,
             uint8_t proto)
  {
      NetIfc*netif;

      LWIP_IP_CHECK_PBUF_REF_COUNT_FOR_TX(p);

      if ((netif = ip4_route_src(src, dest)) == nullptr)
      {
          //    Logf(IP_DEBUG, ("ip4_output: No route to %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
          //                           ip4_addr1_16(dest), ip4_addr2_16(dest), ip4_addr3_16(dest), ip4_addr4_16(dest)));
          IP_STATS_INC(ip.rterr);
          return ERR_RTE;
      }

      return ip4_output_if(p, src, dest, ttl, tos, proto, netif);
  }


  /** Like ip_output, but takes and addr_hint pointer that is passed on to netif->addr_hint
 *  before calling ip_output_if.
 *
 * @param p the packet to send (p->payload points to the data, e.g. next
            protocol header; if dest == LWIP_IP_HDRINCL, p already includes an
            IP header and p->payload points to that IP header)
 * @param src the source IP address to send from (if src == IP4_ADDR_ANY, the
 *         IP  address of the netif used to send is used as source address)
 * @param dest the destination IP address to send the packet to
 * @param ttl the TTL value to be set in the IP header
 * @param tos the TOS value to be set in the IP header
 * @param proto the PROTOCOL to be set in the IP header
 * @param netif_hint netif output hint pointer set to netif->hint before
 *        calling ip_output_if()
 *
 * @return ERR_RTE if no route is found
 *         see ip_output_if() for more return values
 */
  LwipStatus
  ip4_output_hinted(struct PacketBuffer *p,
                    const Ip4Addr *src,
                    const Ip4Addr *dest,
                    uint8_t ttl,
                    uint8_t tos,
                    uint8_t proto,
                    NetIfc*cHint *netif_hint)
  {
      NetIfc*netif;
      LwipStatus err;

      LWIP_IP_CHECK_PBUF_REF_COUNT_FOR_TX(p);

      if ((netif = ip4_route_src(src, dest)) == nullptr) {
          Logf(IP_DEBUG,
               ("ip4_output: No route to %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
                   ip4_addr1_16(dest), ip4_addr2_16(dest), ip4_addr3_16(dest), ip4_addr4_16(dest)));
          IP_STATS_INC(ip.rterr);
          return ERR_RTE;
      }

      NETIF_SET_HINTS(netif, netif_hint);
      err = ip4_output_if(p, src, dest, ttl, tos, proto, netif);
      NETIF_RESET_HINTS(netif);

      return err;
  }

  
