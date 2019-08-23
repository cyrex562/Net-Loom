///
/// file: ip4.cpp
/// 

#include <lwip_debug.h>
#include <autoip.h>
#include <def.h>
#include <icmp.h>
#include <inet_chksum.h>
#include <ip.h>
#include <ip4_frag.h>
#include <network_interface.h>
#include <tcp_priv.h>
#include <udp.h>
#include <iana.h>
#include "raw_priv.h"
#include <vector>


/**
 * Source based IPv4 routing must be fully implemented in
 * LWIP_HOOK_IP4_ROUTE_SRC(). This function only provides the parameters.
 */
LwipStatus
source_route_ip4_addr(const Ip4AddrInfo& src,
                      const Ip4AddrInfo& dest,
                      NetworkInterface& out_netif,
                      const std::vector<NetworkInterface>& netifs)
{
    // todo: lookup source in ip rules for routing and then get the appropriate next hop, using that to find the appropriate netif.
    return STATUS_E_NOT_IMPLEMENTED;
}

///
/// Find network interface for destination IP.
///
LwipStatus
get_netif_for_dst_ip4_addr(const Ip4Addr& dst_addr,
                           const std::vector<NetworkInterface>& netifs_to_check,
                           NetworkInterface& found_netif)
{

    for (const auto& netif : netifs_to_check)
    {
        if (ip4_addr_is_mcast(dst_addr))
        {
            for (auto grp: netif.igmp_groups)
            {
               if (grp.group_address.addr == dst_addr.addr)
               {
                   found_netif = netif;
                   return STATUS_SUCCESS;
               }
            }
        }

        for (auto addr_info : netif.ip4_addresses)
        {
            auto net = get_ip4_addr_net(dst_addr, addr_info.netmask);
            if (net.addr == addr_info.network.addr)
            {
                found_netif = netif;
                return STATUS_SUCCESS;
            }
        }

    }

    return STATUS_NOT_FOUND;
}


///
/// Determine whether an IP address is in a reserved set of addresses
/// that may not be forwarded, or whether datagrams to that destination
/// may be forwarded.
/// @param pkt_buf the packet to forward
/// @return 1: can forward 0: discard
///
bool
can_forward_ip4_pkt(PacketBuffer& pkt_buf)
{
    Ip4Addr dst_addr{};
    // todo: get lowest (closest to wire) IP4 header from pkt_buf, then check if it is able to be forwarded.
    // todo: get dest address in packet
    // don't route link-layer broadcasts
    // if (pkt_buf.ll_broadcast)
    // {
    //     return false;
    // } /* don't route link-layer multicasts (use LWIP_HOOK_IP4_CANFORWARD instead) */
    // if (pkt_buf.ll_multicast || is_ip4_addr_multicast(dst_addr))
    // {
    //     return false;
    // } // todo: make whether we care about experimental IP addresses an configurable option
    if (is_ip4_experimental(dst_addr.addr))
    {
        return false;
    }
    if (is_ip4_class_a(dst_addr.addr))
    {
        const uint32_t net = dst_addr.addr & IP4_CLASS_A_NET;
        if (net == 0 || net == uint32_t(IP_LOOPBACKNET) << IP4_CLASS_A_NSHIFT)
        {
            /* don't route loopback packets */
            return false;
        }
    }
    return true;
} 


/**
 *
 * Forwards an IP packet. It finds an appropriate route for the
 * packet, decrements the TTL value of the packet, adjusts the
 * checksum and outputs the packet on the appropriate interface.
 *
 * pkt_buf the packet to forward (p->payload points to IP header)
 * netifs a collection of valid network interfaces that can be used to send the packet.
 *
 */
static LwipStatus
forward_ip4_pkt(PacketBuffer& pkt_buf, const std::vector<NetworkInterface>& netifs)
{
    // todo: get Ip4AddrInfo src/dst from pkt_buf / network interface
    Ip4AddrInfo dst_addr{};
    Ip4AddrInfo src_addr{};
    if (!can_forward_ip4_pkt(pkt_buf))
    {
        return STATUS_E_ROUTING;
    } /* RFC3927 2.7: do not forward link-local addresses */
    if (is_ip4_addr_link_local(dst_addr.address))
    {
        return STATUS_E_ROUTING;
    } /* Find network interface where to forward this IP packet to. */
    NetworkInterface out_netif{};
    const auto rc = source_route_ip4_addr(src_addr, dst_addr, out_netif, netifs);
    if (rc != STATUS_SUCCESS)
    {
        return rc;
    } /* decrement TTL */ // todo: get ip4 hdr from packet
    Ip4Hdr hdr{};
    set_ip4_hdr_ttl(hdr, get_ip4_hdr_ttl(hdr) - 1); /* send ICMP if TTL == 0 */
    if (get_ip4_hdr_ttl(hdr) == 0)
    {
        /* Don't send ICMP messages in response to ICMP messages */
        if (get_ip4_hdr_proto(hdr) != IP_PROTO_ICMP)
        {
            icmp_time_exceeded(pkt_buf, ICMP_TE_TTL);
        }
        return STATUS_SUCCESS;
    } /* Incrementally update the IP checksum. */
    if (get_ip4_hdr_checksum(hdr) >= pp_htons(0xffffU - 0x100))
    {
        set_ip4_hdr_checksum(hdr,
                             (uint16_t)(get_ip4_hdr_checksum(hdr) + pp_htons(0x100) + 1));
    }
    else
    {
        set_ip4_hdr_checksum(hdr,
                             (uint16_t)(get_ip4_hdr_checksum(hdr) + pp_htons(0x100)));
    } /* don't fragment if interface has mtu set to 0 [loopif] */
    if (out_netif.mtu && pkt_buf.bytes.size() > out_netif.mtu)
    {
        if ((get_ip4_hdr_offset(hdr) & pp_ntohs(IP4_DF_FLAG)) == 0)
        {
            ip4_frag(pkt_buf, out_netif, dst_addr.address);
        }
        else
        {
            /* send ICMP Destination Unreachable code 4: "Fragmentation Needed and DF Set" */
            icmp_dest_unreach(pkt_buf, ICMP_DUR_FRAG);
        }
        return STATUS_SUCCESS;
    } /* transmit PacketBuffer on chosen interface */
    // netif->output(netif, pkt_buf, curr_dst_addr);
    // todo: send packet on outbound interface
    return STATUS_SUCCESS;
} ///
/// Return true if the current input packet should be accepted on this netif
/// 
static bool
ip4_input_accept(NetworkInterface& netif)
{
    Ip4AddrInfo curr_dst_addr{};
    Ip4AddrInfo curr_src_addr{};
    //  Logf(true, ("ip_input: iphdr->dest 0x%x netif->ip_addr 0x%x (0x%x, 0x%x, 0x%x)\n",
    //                         ip4_addr_get_u32(ip4_current_dest_addr()), ip4_addr_get_u32(netif_ip4_addr(netif)),
    //                         ip4_addr_get_u32(ip4_current_dest_addr()) & ip4_addr_get_u32(netif_ip4_netmask(netif)),
    //                         ip4_addr_get_u32(netif_ip4_addr(netif)) & ip4_addr_get_u32(netif_ip4_netmask(netif)),
    //                         ip4_addr_get_u32(ip4_current_dest_addr()) & ~ip4_addr_get_u32(netif_ip4_netmask(netif))));
    /* interface is up and configured? */
    Ip4AddrInfo out_ip4_addr_info{};
    get_netif_ip4_addr(netif, curr_dst_addr);
    if (is_netif_up(netif) && !is_ip4_addr_any(out_ip4_addr_info.address))
    {
        /* unicast to this interface address? */
        if (is_ip4_addr_equal(curr_dst_addr.address, out_ip4_addr_info.address) ||
            /* or broadcast on this interface network address? */
            netif_is_ip4_addr_bcast(curr_dst_addr.address, netif) ||
            get_ip4_addr_u32(curr_dst_addr.address) == pp_htonl(
                make_ip4_addr_loopback().addr))
        {
            return true;
        } /* connections to link-local addresses must persist after changing
            the netif's address (RFC3927 ch. 1.9) */
        if (autoip_accept_packet(netif, curr_dst_addr.address))
        {
            /* accept on this netif */
            return true;
        }
    }
    return false;
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
 * @param pkt_buf the received IP packet (p->payload points to IP header)
 * @param netif the netif on which this packet was received
 * @return ERR_OK if the packet was processed (could return ERR_* if it wasn't
 *         processed, but currently always returns ERR_OK)
 */
bool
ip4_input(PacketBuffer& pkt_buf, NetworkInterface& netif, std::vector<NetworkInterface>& interfaces)
{
    auto check_ip_src = 1;
    Ip4AddrInfo curr_dst_addr{};
    Ip4AddrInfo curr_src_addr{};
    Ip4Hdr curr_dst_hdr{};
    Ip4Hdr curr_src_hdr{};
    /* identify the IP header */
    auto ip4_hdr_ptr = reinterpret_cast<Ip4Hdr *>(pkt_buf.bytes.data());
    if (get_ip4_hdr_version2(ip4_hdr_ptr) != 4)
    {
        return false;
    }

    /* obtain IP header length in bytes */
    size_t iphdr_hlen = get_ip4_hdr_hdr_len_bytes2(ip4_hdr_ptr);

    /* obtain ip length in bytes */
    size_t iphdr_len = lwip_ntohs(get_ip4_hdr_len2(ip4_hdr_ptr));

    /* Trim PacketBuffer. This is especially required for packets < 60 bytes. */
    if (iphdr_len < pkt_buf.bytes.capacity())
    {
        // pbuf_realloc(p);
    }

    /* header length exceeds first PacketBuffer length, or ip length exceeds total PacketBuffer length? */
    if (iphdr_hlen > pkt_buf.bytes.size() || iphdr_len > pkt_buf.bytes.capacity() || iphdr_hlen < IP4_HDR_LEN)
    {
        if (iphdr_hlen < IP4_HDR_LEN)
        {
            //      Logf(true | LWIP_DBG_LEVEL_SERIOUS,
            //                  ("ip4_input: short IP header (%d bytes) received, IP packet dropped\n", iphdr_hlen));
        }
        if (iphdr_hlen > pkt_buf.bytes.size())
        {
            //      Logf(true | LWIP_DBG_LEVEL_SERIOUS,
            //                  ("IP header (len %d) does not fit in first PacketBuffer (len %d), IP packet dropped.\n",
            //                   iphdr_hlen, p->len));
        }
        if (iphdr_len > pkt_buf.bytes.capacity())
        {
            //      Logf(true | LWIP_DBG_LEVEL_SERIOUS,
            //                  ("IP (len %d) is longer than PacketBuffer (len %d), IP packet dropped.\n",
            //                   iphdr_len, p->tot_len));
        }

        /* free (drop) packet pbufs */
        return false;
    } /* verify checksum */
    if (is_netif_checksum_enabled(netif, NETIF_CHECKSUM_CHECK_IP))
    {
        if (inet_chksum((uint8_t*)ip4_hdr_ptr, iphdr_hlen) != 0)
        {
            return false;
        }
    } /* copy IP addresses to aligned IpAddr */
    // copy_ip4_addr_to_ip_addr(&curr_dst_hdr->dest, &iphdr->dest);
    // copy_ip4_addr_to_ip_addr(curr_src_hdr->src, iphdr->src);
    /* match packet against an interface, i.e. is this packet for us? */
    if (ip4_addr_is_mcast(curr_dst_addr.address))
    {
        IgmpGroup found_igmp_group{};
        if (netif.igmp_allowed && find_igmp_group(netif, curr_dst_addr, found_igmp_group))
        {
            /* IGMP snooping switches need 0.0.0.0 to be allowed as source address (RFC 4541) */
            Ip4Addr allsystems{};
            make_ip4_addr_host_from_bytes(allsystems, 224, 0, 0, 1);
            if (is_ip4_addr_equal(curr_dst_addr.address, allsystems) && ip4_addr_isany(
                curr_src_addr.address))
            {
                check_ip_src = 0;
            }
        }
    }
    else
    {
        /* start trying with inp. if that's not acceptable, start walking the
           list of configured netifs. */
        if (!ip4_input_accept(netif))
        {
            /* Packets sent to the loopback address must not be accepted on an
                  * interface that does not have the loopback address assigned to it,
                  * unless a non-loopback interface is used for loopback traffic. */
            if (!is_ip4_addr_loopback(curr_dst_addr.address))
            {
                for (netif = netif_list; netif != nullptr; netif = netif->next)
                {
                    if (netif == netif)
                    {
                        /* we checked that before already */
                        continue;
                    }
                    if (ip4_input_accept(netif))
                    {
                        break;
                    }
                }
            }
        }
    } /* Pass DHCP messages regardless of destination address. DHCP traffic is addressed
   * using link layer addressing (such as Ethernet MAC) so we must not filter on IP.
   * According to RFC 1542 section 3.1.1, referred by RFC 2131).
   *
   * If you want to accept private broadcast communication while a netif is down,
   * define LWIP_IP_ACCEPT_UDP_PORT(dst_port), e.g.:
   *
   * #define LWIP_IP_ACCEPT_UDP_PORT(dst_port) ((dst_port) == pp_ntohs(12345))
   */
    if (netif == nullptr)
    {
        /* remote port is DHCP server? */
        if (get_ip4_hdr_proto(ip4_hdr_ptr) == IP_PROTO_UDP)
        {
            const auto udphdr = (UdpHdr *)(reinterpret_cast<const uint8_t *>(ip4_hdr_ptr) +
                iphdr_hlen);
            Logf(true,
                 "ip4_input: UDP packet to DHCP client port %d\n",
                 lwip_ntohs(udphdr->dest));
            if (ip_accept_link_layer_addressed_port(udphdr->dest))
            {
                Logf(true, "ip4_input: DHCP packet accepted.\n");
                netif = netif;
                check_ip_src = 0;
            }
        }
    } /* broadcast or multicast packet source address? Compliant with RFC 1122: 3.2.1.3 */
    if (check_ip_src
        /* DHCP servers need 0.0.0.0 to be allowed as source address (RFC 1.1.2.2: 3.2.1.3/a) */
        && !ip4_addr_isany_val(*curr_src_addr))
    {
        if (ip4_addr_isbroadcast(curr_src_addr, netif) || ip4_addr_is_mcast(
            curr_src_addr))
        {
            /* packet source is not valid */
            Logf(true, "ip4_input: packet source is not valid.\n");
            /* free (drop) packet pbufs */
            free_pkt_buf(pkt_buf);
            return STATUS_SUCCESS;
        }
    } /* packet not for us? */
    if (netif == nullptr)
    {
        /* packet not for us, route or discard */
        Logf(true, "ip4_input: packet not for us.\n"); /* non-broadcast packet? */
        if (!ip4_addr_isbroadcast(curr_dst_addr, netif))
        {
            /* try to forward IP packet on (other) interfaces */
            forward_ip4_pkt(pkt_buf, , netif);
        }
        else
        {
        }
        free_pkt_buf(pkt_buf);
        return STATUS_SUCCESS;
    } /* packet consists of multiple fragments? */
    if ((get_ip4_hdr_offset(ip4_hdr_ptr) & pp_htons(IP4_OFF_MASK | IP4_MF_FLAG)) != 0)
    {
        //    Logf(true, ("IP packet is a fragment (id=0x%04"X16_F" tot_len=%d len=%d MF=%d offset=%d), calling ip4_reass()\n",
        //                           lwip_ntohs(IPH_ID(iphdr)), p->tot_len, lwip_ntohs(IPH_LEN(iphdr)), (uint16_t)!!(IPH_OFFSET(iphdr) & PpHtons(IP_MF)), (uint16_t)((lwip_ntohs(IPH_OFFSET(iphdr)) & IP_OFFMASK) * 8)));
        /* reassemble the packet*/
        pkt_buf = ip4_reass(pkt_buf); /* packet not fully reassembled yet? */
        if (pkt_buf == nullptr)
        {
            return STATUS_SUCCESS;
        }
        ip4_hdr_ptr = (const struct Ip4Hdr *)pkt_buf.payload;
    } /* there is an extra "router alert" option in IGMP messages which we allow for but do not police */
    if (iphdr_hlen > get_ip4_hdr_hdr_len(ip4_hdr_ptr) && get_ip4_hdr_proto(ip4_hdr_ptr) !=
        IP_PROTO_IGMP)
    {
        Logf(true,
             "IP packet dropped since there were IP options (while IP_OPTIONS_ALLOWED == 0).\n");
        free_pkt_buf(pkt_buf); /* unsupported protocol feature */
        return STATUS_SUCCESS;
    } /* send to upper layers */
    Logf(true, "ip4_input: \n"); // ip_data.current_netif = netif;
    // ip_data.current_input_netif = inp;
    // ip_data.current_ip4_header = iphdr;
    // ip_data.current_ip_header_tot_len = IPH_HL_BYTES(iphdr);
    /* raw input did not eat the packet? */
    raw_input_state_t raw_status = raw_input(pkt_buf, netif);
    if (raw_status != RAW_INPUT_EATEN)
    {
        // pbuf_remove_header(p, iphdr_hlen); /* Move to payload, no check necessary. */
        switch (get_ip4_hdr_proto(ip4_hdr_ptr))
        {
        case IP_PROTO_UDP: case IP_PROTO_UDPLITE:
            udp_input(pkt_buf, netif);
            break;
        case IP_PROTO_TCP:
            tcp_input(pkt_buf, netif);
            break;
        case IP_PROTO_ICMP: // icmp_input(p, inp);
            break;
        case IP_PROTO_IGMP: // igmp_input(p, inp, ip4_current_dest_addr());
            break;
        default:
            if (raw_status == RAW_INPUT_DELIVERED)
            {
            }
            else
            {
                /* send ICMP destination protocol unreachable unless is was a broadcast */
                if (!ip4_addr_isbroadcast(curr_dst_addr, netif) && !ip4_addr_is_mcast(
                    curr_dst_addr))
                {
                    // pbuf_header_force(p, (int16_t)iphdr_hlen); /* Move to ip header, no check necessary. */
                    icmp_dest_unreach(pkt_buf, ICMP_DUR_PROTO);
                } //          Logf(true | LWIP_DBG_LEVEL_SERIOUS, ("Unsupported transport protocol %d\n", (uint16_t)IPH_PROTO(iphdr)));
            }
            free_pkt_buf(pkt_buf);
            break;
        }
    } /* @todo: this is not really necessary... */ // ip_data.current_netif = nullptr;
    // ip_data.current_input_netif = nullptr;
    // ip_data.current_ip4_header = nullptr;
    // ip_data.current_ip_header_tot_len = 0;
    ip4_addr_set_any(curr_src_addr);
    ip4_addr_set_any(curr_dst_addr);
    return STATUS_SUCCESS;
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
ip4_output_if(PacketBuffer& p,
              const Ip4AddrInfo& src,
              const Ip4AddrInfo& dest,
              uint8_t ttl,
              uint8_t tos,
              uint8_t proto,
              NetworkInterface& netif)
{
  return ip4_output_if_opt(p, src, dest, ttl, tos, proto, netif, nullptr, 0);
}

/**
 * Same as ip_output_if() but with the possibility to include IP options:
 *
 * @ param ip_options pointer to the IP options, copied into the IP header
 * @ param optlen length of ip_options
 */
LwipStatus
ip4_output_if_opt(struct PacketBuffer* p,
                  const Ip4Addr* src,
                  const Ip4Addr* dest,
                  uint8_t ttl,
                  uint8_t tos,
                  uint8_t proto,
                  NetworkInterface* netif,
                  uint8_t* ip_options,
                  uint16_t optlen)
{
    const Ip4Addr* src_used = src;
    if (dest != nullptr) {
        if (ip4_addr_isany(src)) {
            src_used = get_netif_ip4_addr(netif,);
        }
    }


    return ip4_output_if_opt_src(p,
                                 src_used,
                                 dest,
                                 ttl,
                                 tos,
                                 proto,
                                 netif,
                                 ip_options,
                                 optlen);
}

  /**
 * Same as ip_output_if() but 'src' address is not replaced by netif address
 * when it is 'any'.
 */
  LwipStatus
  ip4_output_if_src(PacketBuffer& p,
                    const Ip4AddrInfo& src,
                    const Ip4AddrInfo& dest,
                    uint8_t ttl,
                    uint8_t tos,
                    uint8_t proto,
                    NetworkInterface& netif)
  {

  return ip4_output_if_opt_src(p, src, dest, ttl, tos, proto, netif, nullptr, 0);
}

/**
 * Same as ip_output_if_opt() but 'src' address is not replaced by netif address
 * when it is 'any'.
 */
LwipStatus
ip4_output_if_opt_src(struct PacketBuffer *p, const Ip4Addr *src, const Ip4Addr *dest,
                      uint8_t ttl, uint8_t tos, uint8_t proto, NetworkInterface*netif, uint8_t *ip_options,
                      uint16_t optlen)
{
      struct Ip4Hdr *iphdr;
      Ip4Addr dest_addr{};
      uint32_t chk_sum = 0;

      /* Should the IP header be generated or is it already included in p? */
      if (dest != nullptr)
      {
          uint16_t ip_hlen = IP4_HDR_LEN;

    uint16_t optlen = 0;
    if (optlen != 0) {
        if (optlen > IP4_HDR_LEN_MAX - IP4_HDR_LEN) {
        /* optlen too long */
        Logf(true, "ip4_output_if_opt: optlen too long\n");
     
        
        return ERR_VAL;
      }
      /* round up to a multiple of 4 */
      auto optlen_aligned = (uint16_t)(optlen + 3 & ~3);
      ip_hlen = (uint16_t)(ip_hlen + optlen_aligned);
      /* First write in the IP options */
      // if (pbuf_add_header(p, optlen_aligned)) {
      //   Logf(true, "ip4_output_if_opt: not enough room for IP options in PacketBuffer\n");
      //   
      //   return ERR_BUF;
      // }
      memcpy(p->payload, ip_options, optlen);
      if (optlen < optlen_aligned) {
        /* zero the remaining bytes */
        memset((char *)p->payload + optlen, 0, (size_t)(optlen_aligned - optlen));
      }

      for (int i = 0; i < optlen_aligned / 2; i++) {
        chk_sum += ((uint16_t *)p->payload)[i];
      }

    }

          /* generate IP header */
          // if (pbuf_add_header(p, IP4_HDR_LEN))
          // {
          //     Logf(true, "ip4_output: not enough room for IP header in PacketBuffer\n");
          //
          //     
          //     return ERR_BUF;
          // }

          iphdr = (struct Ip4Hdr *)p->payload;
          lwip_assert("check that first PacketBuffer can hold struct Ip4Hdr",
                      p->len >= sizeof(struct Ip4Hdr));

          set_ip4_hdr_ttl(iphdr, ttl);
          set_ip4_hdr_proto(iphdr, proto);

          chk_sum += pp_ntohs(proto | ttl << 8);


          /* dest cannot be NULL here */
          copy_ip4_addr(&iphdr->dest, dest);

          chk_sum += get_ip4_addr_u32(&iphdr->dest) & 0xFFFF;
          chk_sum += get_ip4_addr_u32(&iphdr->dest) >> 16;


          set_ip4_hdr_vhl(iphdr, 4, ip_hlen / 4);
          set_ip4_hdr_tos(iphdr, tos);

          chk_sum += pp_ntohs(tos | iphdr->_v_hl << 8);

          set_ip4_hdr_len(iphdr, lwip_htons(p->tot_len));

          chk_sum += iphdr->_len;

          set_ip4_hdr_offset(iphdr, 0);
          set_ip4_hdr_id(iphdr, lwip_htons(ip_id));

          chk_sum += iphdr->_id;

          ++ip_id;

          if (src == nullptr)
          {
              copy_ip4_addr(&iphdr->src, nullptr);
          } else
          {
              /* src cannot be NULL here */
              copy_ip4_addr(&iphdr->src, src);
          }

          chk_sum += get_ip4_addr_u32(&iphdr->src) & 0xFFFF;
          chk_sum += get_ip4_addr_u32(&iphdr->src) >> 16;
          chk_sum = (chk_sum >> 16) + (chk_sum & 0xFFFF);
          chk_sum = (chk_sum >> 16) + chk_sum;
          chk_sum = ~chk_sum;
          if(is_netif_checksum_enabled(netif, NETIF_CHECKSUM_GEN_IP)) {
              iphdr->_chksum = (uint16_t)chk_sum; /* network order */
          }

    else {
      set_ip4_hdr_checksum(iphdr, 0);
    }

      } else
      {
          /* IP header already included in p */
          if (p->len < IP4_HDR_LEN)
          {
              Logf(true, "ip4_output: LWIP_IP_HDRINCL but PacketBuffer is too short\n");
              
              return ERR_BUF;
          }
          iphdr = (struct Ip4Hdr *)p->payload;
          copy_ip4_addr(&dest_addr, &iphdr->dest);
          dest = &dest_addr;
      }


      //  Logf(true, ("ip4_output_if: %c%c%d\n", netif->name[0], netif->name[1], (uint16_t)netif->num));


  // if (ip4_addr_cmp(dest, netif_ip_addr4(netif))
  //
  //     || ip4_addr_isloopback(dest)
  //
  //    ) {
  //   /* Packet to self, enqueue it for loopback */
  //   Logf(true, ("netif_loop_output()"));
  //   return netif_loop_output(netif, p,);
  // }

  // if (p->multicast_loop != 0) {
  //   send_pkt_to_netif_loop(netif, p);
  // }


      /* don't fragment if interface has mtu set to 0 [loopif] */
      if (netif->mtu && p->tot_len > netif->mtu)
      {
          return ip4_frag(p, netif, dest);
      }


      //  Logf(true, ("ip4_output_if: call netif->output()\n"));
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
  ip4_output(PacketBuffer& p,
             const Ip4AddrInfo& src,
             const Ip4AddrInfo& dest,
             uint8_t ttl,
             uint8_t tos,
             uint8_t proto)
  {
      NetworkInterface*netif;

      // LWIP_IP_CHECK_PBUF_REF_COUNT_FOR_TX(p);

      if ((netif = source_route_ip4_addr(src, dest,,)) == nullptr)
      {
          //    Logf(true, ("ip4_output: No route to %d.%d.%d.%d\n",
          //                           ip4_addr1_16(dest), ip4_addr2_16(dest), ip4_addr3_16(dest), ip4_addr4_16(dest)));
          // IP_STATS_INC(ip.rterr);
          return STATUS_E_ROUTING;
      }

      return ip4_output_if(p, src, dest, ttl, tos, proto, netif);
  }


/// Like ip_output, but takes and addr_hint pointer that is passed on to netif->addr_hint
///  before calling ip_output_if.
///
/// p: the packet to send (p->payload points to the data, e.g. next
///         protocol header; if dest == LWIP_IP_HDRINCL, p already includes an
///         IP header and p->payload points to that IP header)
/// src: the source IP address to send from (if src == IP4_ADDR_ANY, the
///         IP  address of the netif used to send is used as source address)
/// dest: the destination IP address to send the packet to
/// ttl: the TTL value to be set in the IP header
/// tos: the TOS value to be set in the IP header
/// proto: the PROTOCOL to be set in the IP header
/// netif_hint: netif output hint pointer set to netif->hint before
///        calling ip_output_if()
///
/// returns: ERR_RTE if no route is found
///         see ip_output_if() for more return values
///
LwipStatus
ip4_output_hinted(struct PacketBuffer* pkt_buf,
                  const Ip4Addr* src,
                  const Ip4Addr* dest,
                  uint8_t ttl,
                  uint8_t tos,
                  uint8_t proto,
                  NetIfcHint* netif_hint)
{
    NetworkInterface* netif;

    // LWIP_IP_CHECK_PBUF_REF_COUNT_FOR_TX(p);

    if ((netif = source_route_ip4_addr(src, dest,,)) == nullptr) {
        // Logf(true,
        //      ("ip4_output: No route to %d.%d.%d.%d\n",
        //          ip4_addr1_16(dest), ip4_addr2_16(dest), ip4_addr3_16(dest), ip4_addr4_16(dest)));
        // IP_STATS_INC(ip.rterr);
        return STATUS_E_ROUTING;
    }

    netif_set_hints(netif, netif_hint);
    LwipStatus err = ip4_output_if(pkt_buf, src, dest, ttl, tos, proto, netif);
    netif_reset_hints(netif);

    return err;
}

  
