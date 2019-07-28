/**
 * @file
 *
 * IPv6 layer.
 */ /*
 * Copyright (c) 2010 Inico Technologies Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Ivan Delamer <delamer@inicotech.com>
 *
 *
 * Please coordinate changes and requests with Ivan Delamer
 * <delamer@inicotech.com>
 */
#include <def.h>
#include <dhcp6.h>
#include <icmp6.h>
#include <ip.h>
#include <ip6.h>
#include <ip6_addr.h>
#include <ip6_frag.h>
#include <mld6.h>
#include <nd6.h>
#include <network_interface.h>
#include <opt.h>
#include <raw_priv.h>
#include <tcp_priv.h>
#include <udp.h>

/**
 * Finds the appropriate network interface for a given IPv6 address. It tries to select
 * a netif following a sequence of heuristics:
 * 1) if there is only 1 netif, return it
 * 2) if the destination is a zoned address, match its zone to a netif
 * 3) if the either the source or destination address is a scoped address,
 *    match the source address's zone (if set) or address (if not) to a netif
 * 4) tries to match the destination subnet to a configured address
 * 5) tries to find a router-announced route
 * 6) tries to match the (unscoped) source address to the netif
 * 7) returns the default netif, if configured
 *
 * Note that each of the two given addresses may or may not be properly zoned.
 *
 * @param src the source IPv6 address, if known
 * @param dest the destination IPv6 address for which to find the route
 * @return the netif on which to send to reach dest
 */
NetworkInterface*
ip6_route(const Ip6Addr* src, const Ip6Addr* dest)
{
    NetworkInterface* netif_default = nullptr;
    NetworkInterface* netif;
    int8_t i;
    if ((netif_list != nullptr) && (netif_list->next == nullptr)) {
        if (!is_netif_up(netif_list) || !is_netif_link_up(netif_list) || (
            ip6_addr_has_zone(dest) && !est_ip6_addr_zone(dest, netif_list))) {
            return nullptr;
        }
        return netif_list;
    } /* Special processing for zoned destination addresses. This includes link-
   * local unicast addresses and interface/link-local multicast addresses. Use
   * the zone to find a matching netif. If the address is not zoned, then there
   * is technically no "wrong" netif to choose, and we leave routing to other
   * rules; in most cases this should be the scoped-source rule below. */
    if (ip6_addr_has_zone(dest)) {
        /* Find a netif based on the zone. For custom mappings, one zone may map
                          * to multiple netifs, so find one that can actually send a packet. */
        for ((netif) = netif_list; (netif) != nullptr; (netif) = (netif)->next) {
            if (est_ip6_addr_zone(dest, netif) && is_netif_up(netif) && is_netif_link_up(
                netif)) {
                return netif;
            }
        } /* No matching netif found. Do no try to route to a different netif,
     * as that would be a zone violation, resulting in any packets sent to
     * that netif being dropped on output. */
        return nullptr;
    } /* Special processing for scoped source and destination addresses. If we get
   * here, the destination address does not have a zone, so either way we need
   * to look at the source address, which may or may not have a zone. If it
   * does, the zone is restrictive: there is (typically) only one matching
   * netif for it, and we should avoid routing to any other netif as that would
   * result in guaranteed zone violations. For scoped source addresses that do
   * not have a zone, use (only) a netif that has that source address locally
   * assigned. This case also applies to the loopback source address, which has
   * an implied link-local scope. If only the destination address is scoped
   * (but, again, not zoned), we still want to use only the source address to
   * determine its zone because that's most likely what the user/application
   * wants, regardless of whether the source address is scoped. Finally, some
   * of this story also applies if scoping is disabled altogether. */
    if (ip6_addr_has_scope(dest, IP6_UNKNOWN) || ip6_addr_has_scope(src, IP6_UNICAST) ||
        is_ip6_addr_loopback(src)) {
        if (ip6_addr_has_zone(src)) {
            /* Find a netif matching the source zone (relatively cheap). */
            for ((netif) = netif_list; (netif) != nullptr; (netif) = (netif)->next) {
                if (is_netif_up(netif) && is_netif_link_up(netif) && est_ip6_addr_zone(
                    src,
                    netif)) {
                    return netif;
                }
            }
        }
        else {
            /* Find a netif matching the source address (relatively expensive). */
            for ((netif) = netif_list; (netif) != nullptr; (netif) = (netif)->next) {
                if (!is_netif_up(netif) || !is_netif_link_up(netif)) {
                    continue;
                }
                for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
                    if (is_ip6_addr_valid(get_netif_ip6_addr_state(netif, i)) &&
                        cmp_ip6_addr_zoneless(src, get_netif_ip6_addr(netif, i))) {
                        return netif;
                    }
                }
            }
        } /* Again, do not use any other netif in this case, as that could result in
     * zone boundary violations. */
        return nullptr;
    } /* We come here only if neither source nor destination is scoped. */
    if (netif != nullptr) {
        return netif;
    } /* See if the destination subnet matches a configured address. In accordance
   * with RFC 5942, dynamically configured addresses do not have an implied
   * local subnet, and thus should be considered /128 assignments. However, as
   * such, the destination address may still match a local address, and so we
   * still need to check for exact matches here. By (lwIP) policy, statically
   * configured addresses do always have an implied local /64 subnet. */
    for ((netif) = netif_list; (netif) != nullptr; (netif) = (netif)->next) {
        if (!is_netif_up(netif) || !is_netif_link_up(netif)) {
            continue;
        }
        for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
            if (is_ip6_addr_valid(get_netif_ip6_addr_state(netif, i)) &&
                ip6_addr_on_same_net(dest, get_netif_ip6_addr(netif, i)) && (
                    is_netif_ip6_addr_static(netif, i) || ip6_addr_hosts_equal(
                        dest,
                        get_netif_ip6_addr(netif, i)))) {
                return netif;
            }
        }
    } /* Get the netif for a suitable router-announced route. */
    netif = nd6_find_route(dest);
    if (netif != nullptr) {
        return netif;
    } /* Try with the netif that matches the source address. Given the earlier rule
   * for scoped source addresses, this applies to unscoped addresses only. */
    if (!is_ip6_addr_any(src)) {
        for ((netif) = netif_list; (netif) != nullptr; (netif) = (netif)->next) {
            if (!is_netif_up(netif) || !is_netif_link_up(netif)) {
                continue;
            }
            for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
                if (is_ip6_addr_valid(get_netif_ip6_addr_state(netif, i)) && cmp_ip6_addr(
                    src,
                    get_netif_ip6_addr(netif, i))) {
                    return netif;
                }
            }
        }
    } /* loopif is disabled, loopback traffic is passed through any netif */
    if (is_ip6_addr_loopback(dest)) {
        /* don't check for link on loopback traffic */
        if (netif_default != nullptr && is_netif_up(netif_default)) {
            return netif_default;
        } /* default netif is not up, just use any netif for loopback traffic */
        for ((netif) = netif_list; (netif) != nullptr; (netif) = (netif)->next) {
            if (is_netif_up(netif)) {
                return netif;
            }
        }
        return nullptr;
    } /* no matching netif found, use default netif, if up */
    if ((netif_default == nullptr) || !is_netif_up(netif_default) || !is_netif_link_up(
        netif_default)) {
        return nullptr;
    }
    return nullptr;
}


/* no matching netif found, use default netif, if up */
// if
// ((netif_default
// ==
// nullptr
// )
// ||
// !
// netif_is_up (netif_default)
// ||
// !
// netif_is_link_up (netif_default)
// )
//  {
//     return nullptr;
//   }
// return
// netif_default;
// }


/**
 * Forwards an IPv6 packet. It finds an appropriate route for the
 * packet, decrements the HL value of the packet, and outputs
 * the packet on the appropriate interface.
 *
 * @param p the packet to forward (p->payload points to IP header)
 * @param iphdr the IPv6 header of the input packet
 * @param inp the netif on which this packet was received
 */
static void
ip6_forward(struct PacketBuffer* p,
            struct Ip6Hdr* iphdr,
            NetworkInterface* inp,
            Ip6Addr* dest_addr,
            Ip6Addr* src_addr)
{
    /* do not forward link-local or loopback addresses */
    if (ip6_addr_islinklocal(dest_addr) || is_ip6_addr_loopback(dest_addr)) {
        Logf(true, ("ip6_forward: not forwarding link-local address.\n"));
        return;
    } /* Find network interface where to forward this IP packet to. */
    Ip6Addr ip6_any_addr{};
    set_ip6_addr_any(&ip6_any_addr);
    auto netif = ip6_route(&ip6_any_addr, dest_addr);
    if (netif == nullptr) {
        /* Don't send ICMP messages in response to ICMP messages */
        if (IP6H_NEXTH(iphdr) != IP6_NEXTH_ICMP6) {
            icmp6_dest_unreach(p, ICMP6_DUR_NO_ROUTE);
        }
        return;
    } /* Do not forward packets with a zoned (e.g., link-local) source address
   * outside of their zone. We determined the zone a bit earlier, so we know
   * that the address is properly zoned here, so we can safely use has_zone.
   * Also skip packets with a loopback source address (link-local implied). */
    if ((ip6_addr_has_zone(src_addr) && ! est_ip6_addr_zone(src_addr, netif)) ||
        is_ip6_addr_loopback(src_addr)) { }
    // Do not forward packets onto the same network interface on which they arrived.
    if (netif == inp) {
        Logf(true,
             ("ip6_forward: not bouncing packets back on incoming interface.\n"));
        return;
    } /* decrement HL */ /* send ICMP6 if HL == 0 */
    set_ip6_hdr_hop_limit(iphdr, IP6H_HOPLIM(iphdr) - 1);
    if (IP6H_HOPLIM(iphdr) == 0) {
        /* Don't send ICMP messages in response to ICMP messages */
        if (IP6H_NEXTH(iphdr) != IP6_NEXTH_ICMP6) {
            icmp6_time_exceeded(p, ICMP6_TE_HL);
        }
        return;
    }
    if (netif->mtu && (p->tot_len > netif->mtu)) {
        /* Don't send ICMP messages in response to ICMP messages */
        if (IP6H_NEXTH(iphdr) != IP6_NEXTH_ICMP6) {
            icmp6_packet_too_big(p, netif->mtu);
        }
        return;
    } /* transmit PacketBuffer on chosen interface */
    netif->output_ip6(netif, p, dest_addr);
}


// Return true if the current input packet should be accepted on this netif
static int
ip6_input_accept(NetworkInterface* netif, Ip6Addr* src_addr, Ip6Addr* dest_addr)
{
    /* interface is up? */
    if (is_netif_up(netif)) {
        /* unicast to this interface address? address configured? */
        /* If custom scopes are used, the destination zone will be tested as
                           * part of the local-address comparison, but we need to test the source
                           * scope as well (e.g., is this interface on the same link?). */
        for (uint8_t i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
            // if (ip6_addr_isvalid(netif_ip6_addr_state(netif, i)) && ip6_addr_cmp(
            //         dest_addr,
            //         netif_ip6_addr(netif, i)) && (!ip6_addr_has_zone(src_addr)) ||
            //     ip6_addr_rest_zone(src_addr, netif))
            // )
            // {
            //     /* accept on this netif */
            //     return 1;
            // }
        }
    }
    return 0;
}


/**
 * This function is called by the network interface device driver when
 * an IPv6 packet is received. The function does the basic checks of the
 * IP header such as packet size being at least larger than the header
 * size etc. If the packet was not destined for us, the packet is
 * forwarded (using ip6_forward).
 *
 * Finally, the packet is sent to the upper layer protocol input function.
 *
 * @param p the received IPv6 packet (p->payload points to IPv6 header)
 * @param inp the netif on which this packet was received
 * @return ERR_OK if the packet was processed (could return ERR_* if it wasn't
 *         processed, but currently always returns ERR_OK)
 */
LwipStatus
ip6_input(struct PacketBuffer* p, NetworkInterface* inp)
{
    NetworkInterface* netif;
    uint8_t* nexth;
    uint16_t hlen_tot; /* the current header length */ /* identify the IP header */
    Ip6Hdr* ip6_hdr = reinterpret_cast<Ip6Hdr *>(p->payload);
    if (get_ip6_hdr_v(ip6_hdr) != 6) {
        Logf(true,
             "IPv6 packet dropped due to bad version number %d\n",
             get_ip6_hdr_v(ip6_hdr));
        free_pkt_buf(p);
        return ERR_OK;
    }


    // if (LWIP_HOOK_IP6_INPUT(p, inp)) {
    //   /* the packet has been eaten */
    //   return ERR_OK;
    // }


    /* header length exceeds first PacketBuffer length, or ip length exceeds total PacketBuffer length? */
    if ((IP6_HDR_LEN > p->len) || (IP6H_PLEN(ip6_hdr) > (p->tot_len - IP6_HDR_LEN))) {
        if (IP6_HDR_LEN > p->len) {
            Logf(true,
                 "IPv6 header (len %d) does not fit in first PacketBuffer (len %d), IP packet dropped.\n",
                 (uint16_t)IP6_HDR_LEN,
                 p->len);
        }
        if ((IP6H_PLEN(ip6_hdr) + IP6_HDR_LEN) > p->tot_len) {
            Logf(true,
                 "IPv6 (plen %d) is longer than PacketBuffer (len %d), IP packet dropped.\n",
                 (uint16_t)(IP6H_PLEN(ip6_hdr) + IP6_HDR_LEN),
                 p->tot_len);
        }
        /* free (drop) packet pbufs */
        free_pkt_buf(p);
        return ERR_OK;
    }

    /* Trim PacketBuffer. This should have been done at the netif layer,
     * but we'll do it anyway just to be sure that its done. */
    pbuf_realloc(p);

    /* copy IP addresses to aligned Ip6Address */
    // todo: get curr dst and src ip addr from somewhere
    IpAddr curr_dst_addr{};
    IpAddr curr_src_addr{};
    memcpy(&curr_dst_addr.u_addr.ip6.addr, &ip6_hdr->dest, sizeof(Ip6Addr));
    memcpy(&curr_src_addr.u_addr.ip6.addr, &ip6_hdr->src, sizeof(Ip6Addr));

    /* Don't accept virtual IPv4 mapped IPv6 addresses.
     * Don't accept multicast source addresses. */
    if (is_ip6_addr_ip4_mapped_ip6((&curr_dst_addr.u_addr.ip6)) ||
        is_ip6_addr_ip4_mapped_ip6((&curr_src_addr.u_addr.ip6)) ||
        is_ip6_addr_mcast((&curr_src_addr.u_addr.ip6))) {
        /* free (drop) packet pbufs */
        free_pkt_buf(p);
        return ERR_OK;
    }

    /* Set the appropriate zone identifier on the addresses. */
    assign_ip6_addr_zone(&curr_dst_addr.u_addr.ip6, IP6_UNKNOWN, inp,);
    assign_ip6_addr_zone(&curr_src_addr.u_addr.ip6, IP6_UNICAST, inp,);

    /* current header pointer. */
    // todo: set current_ip6_hdr;
    // ip_data.current_ip6_header = ip6_hdr;

    /* In netif, used in case we need to send ICMPv6 packets back. */
    // ip_data.current_netif = inp;
    // ip_data.current_input_netif = inp;
    // todo: set current netif

    /* match packet against an interface, i.e. is this packet for us? */
    if (is_ip6_addr_mcast(&curr_dst_addr.u_addr.ip6)) {
        /* Always joined to multicast if-local and link-local all-nodes group. */
        if (is_ip6_addr_all_nodes_if_local(&curr_dst_addr.u_addr.ip6) ||
            ip6_addr_isallnodes_linklocal(&curr_dst_addr.u_addr.ip6)) {
            netif = inp;
        }

        else if (mld6_lookfor_group(inp, &curr_dst_addr.u_addr.ip6)) {
            netif = inp;
        }

        else {
            netif = nullptr;
        }
    }
    else {
        /* start trying with inp. if that's not acceptable, start walking the
           list of configured netifs. */
        if (ip6_input_accept(inp, &curr_src_addr.u_addr.ip6, &curr_dst_addr.u_addr.ip6)) {
            netif = inp;
        }
        else {
            netif = nullptr;


            /* The loopback address is to be considered link-local. Packets to it
              * should be dropped on other interfaces, as per RFC 4291 Sec. 2.5.3.
              * Its implied scope means packets *from* the loopback address should
              * not be accepted on other interfaces, either. These requirements
              * cannot be implemented in the case that loopback traffic is sent
              * across a non-loopback interface, however. */
            if (is_ip6_addr_loopback(&curr_dst_addr.u_addr.ip6) ||
                is_ip6_addr_loopback(&curr_src_addr.u_addr.ip6)) {
                goto netif_found;
            }


            for ((netif) = netif_list; (netif) != nullptr; (netif) = (netif)->next) {
                if (netif == inp) {
                    /* we checked that before already */
                    continue;
                }
                if (ip6_input_accept(netif, &curr_src_addr.u_addr.ip6, &curr_dst_addr.u_addr.ip6)) {
                    break;
                }
            }

        }
    netif_found:
        Logf(true,
             "ip6_input: packet accepted on interface %c%c\n",
             netif ? netif->name[0] : 'X',
             netif ? netif->name[1] : 'X');
    }

    /* "::" packet source address? (used in duplicate address detection) */
    if (is_ip6_addr_any(&curr_src_addr.u_addr.ip6) &&
        (!is_ip6_addr_solicited_node(&curr_dst_addr.u_addr.ip6))) {
        /* packet source is not valid */
        /* free (drop) packet pbufs */
        Logf(true, ("ip6_input: packet with src ANY_ADDRESS dropped\n"));
        free_pkt_buf(p);
        goto ip6_input_cleanup;
    }

    /* packet not for us? */
    if (netif == nullptr) {
        /* packet not for us, route or discard */
        Logf(true, ("ip6_input: packet not for us.\n"));

        /* non-multicast packet? */
        if (!is_ip6_addr_mcast(&curr_dst_addr.u_addr.ip6)) {
            /* try to forward IP packet on (other) interfaces */
            ip6_forward(p, ip6_hdr, inp, &curr_dst_addr.u_addr.ip6, & curr_src_addr.u_addr.ip6);
        }

        free_pkt_buf(p);
        goto ip6_input_cleanup;
    }

    /* current netif pointer. */
    // ip_data.current_netif = netif;
    // todo: set current netif

    /* Save next header type. */
    uint8_t next_hdr = IP6H_NEXTH(ip6_hdr);
    *nexth = next_hdr;

    /* Init header length. */
    uint16_t hlen = hlen_tot = IP6_HDR_LEN;

    /* Move to payload. */
    pbuf_remove_header(p, IP6_HDR_LEN);

    /* Process known option extension headers, if present. */
    while (*nexth != IP6_NEXTH_NONE) {
        switch (*nexth) {
        case IP6_NEXTH_HOPBYHOP:

            int32_t opt_offset;
            struct Ip6HopByHopHdr* hbh_hdr;
            struct Ip6OptionHdr* opt_hdr;
            Logf(true, ("ip6_input: packet with Hop-by-Hop options header\n"));

            /* Get and check the header length, while staying in packet bounds. */
            hbh_hdr = (struct Ip6HopByHopHdr *)p->payload;

            /* Get next header type. */
            *nexth = IP6_HBH_NEXTH(hbh_hdr);

            /* Get the header length. */
            hlen = (uint16_t)(8 * (1 + hbh_hdr->_hlen));

            if ((p->len < 8) || (hlen > p->len)) {
                Logf(true,
                     "IPv6 options header (hlen %d) does not fit in first PacketBuffer (len %d), IPv6 packet dropped.\n",
                     hlen,
                     p->len);
                /* free (drop) packet pbufs */
                free_pkt_buf(p);
                return ERR_OK;
            }
            if (true) {
                int32_t opt_offset;
                struct Ip6OptionHdr* opt_hdr;
                Logf(true, ("ip6_input: packet with Destination options header\n"));

                struct Ip6DestHdr* dest_hdr = (struct Ip6DestHdr *)p->payload;

                /* Get next header type. */
                *nexth = IP6_DEST_NEXTH(dest_hdr);

                /* Get the header length. */
                hlen = 8 * (1 + dest_hdr->_hlen);
                if ((p->len < 8) || (hlen > p->len)) {
                    Logf(true,
                         "IPv6 options header (hlen %d) does not fit in first PacketBuffer (len %d), IPv6 packet dropped.\n",
                         hlen,
                         p->len);
                    /* free (drop) packet pbufs */
                    free_pkt_buf(p);
                    return ERR_OK;
                } /* Trim PacketBuffer. This should have been done at the netif layer,
   * but we'll do it anyway just to be sure that its done. */
                pbuf_realloc(p);
                /* copy IP addresses to aligned Ip6Address */
                memcpy(&curr_dst_addr.u_addr.ip6.addr, &ip6_hdr->dest, sizeof(Ip6Addr));
                memcpy(&curr_src_addr.u_addr.ip6.addr, &ip6_hdr->src, sizeof(Ip6Addr));
            }
            /* Don't accept virtual IPv4 mapped IPv6 addresses.
              * Don't accept multicast source addresses. */
            if (is_ip6_addr_ip4_mapped_ip6(&curr_dst_addr.u_addr.ip6) ||
                is_ip6_addr_ip4_mapped_ip6(&curr_src_addr.u_addr.ip6) ||
                is_ip6_addr_mcast(&curr_src_addr.u_addr.ip6)) {
                Logf(true, ("ip6_input: packet with Routing header\n"));

                Ip6RouteHdr* rout_hdr = (struct Ip6RouteHdr *)p->payload;

                /* Get next header type. */
                *nexth = get_ip6_route_hdr_nexth(rout_hdr);

                /* Get the header length. */
                hlen = 8 * (1 + rout_hdr->_hlen);

                if ((p->len < 8) || (hlen > p->len)) {
                    Logf(true,
                         "IPv6 options header (hlen %d) does not fit in first PacketBuffer (len %d), IPv6 packet dropped.\n",
                         hlen,
                         p->len);
                    /* free (drop) packet pbufs */
                    free_pkt_buf(p);
                    return ERR_OK;
                } /* Set the appropriate zone identifier on the addresses. */
                assign_ip6_addr_zone(&curr_dst_addr.u_addr.ip6, IP6_UNKNOWN, inp,);
                assign_ip6_addr_zone(&curr_dst_addr.u_addr.ip6, IP6_UNICAST, inp,);
                /* current header pointer. */
                // ip_data.current_ip6_header = ip6_hdr;
                // todo: set current ip6 hdr
                /* In netif, used in case we need to send ICMPv6 packets back. */
                // ip_data.current_netif = inp;
                // todo: set current ip6 hdr
                // ip_data.current_input_netif = inp;
                /* match packet against an interface, i.e. is this packet for us? */
                if (is_ip6_addr_mcast(&curr_dst_addr.u_addr.ip6)) {
                    /* Always joined to multicast if-local and link-local all-nodes group. */
                    if (is_ip6_addr_all_nodes_if_local(&curr_dst_addr.u_addr.ip6) ||
                        ip6_addr_isallnodes_linklocal(&curr_dst_addr.u_addr.ip6)) {
                        netif = inp;
                    }
                    else if (mld6_lookfor_group(inp, &curr_dst_addr.u_addr.ip6)) {
                        netif = inp;
                    }
                    else {
                        netif = nullptr;
                    }
                }
                else {
                    Logf(true, ("ip6_input: packet with Fragment header\n"));

                    Ip6FragHdr* frag_hdr = (Ip6FragHdr*)p->payload;

                    /* Get next header type. */
                    *nexth = IP6_FRAG_NEXTH(frag_hdr);

                    /* Fragment Header length. */
                    hlen = 8;

                    /* Make sure this header fits in current PacketBuffer. */
                    if (hlen > p->len) {
                        Logf(true,
                             "IPv6 options header (hlen %d) does not fit in first PacketBuffer (len %d), IPv6 packet dropped.\n",
                             hlen,
                             p->len);
                        /* free (drop) packet pbufs */
                        free_pkt_buf(p);
                        goto ip6_input_cleanup;
                    } /* packet not for us? */
                    if (netif == nullptr) {
                        /* packet not for us, route or discard */
                        Logf(true, ("ip6_input: packet not for us.\n"));
                        /* non-multicast packet? */
                        if (!is_ip6_addr_mcast(&curr_dst_addr.u_addr.ip6)) {
                            /* try to forward IP packet on (other) interfaces */
                            ip6_forward(p, ip6_hdr, inp, &curr_src_addr.u_addr.ip6, &curr_dst_addr.u_addr.ip6);
                        }
                        free_pkt_buf(p);
                        goto ip6_input_cleanup;
                    } /* current netif pointer. */
                    // ip_data.current_netif = netif; /* Save next header type. */
                    // todo: set current netif
                    *nexth = IP6H_NEXTH(ip6_hdr); /* Init header length. */
                    uint16_t hlen = hlen_tot = IP6_HDR_LEN; /* Move to payload. */
                    pbuf_remove_header(p, IP6_HDR_LEN);
                    /* Process known option extension headers, if present. */
                    while (*nexth != IP6_NEXTH_NONE) {
                        switch (*nexth) {
                        case IP6_NEXTH_HOPBYHOP:
                            {
                                Logf(true, ("ip6_input: packet with Hop-by-Hop options header\n"));
                                /* Get and check the header length, while staying in packet bounds. */
                                Ip6HopByHopHdr* hbh_hdr = (Ip6HopByHopHdr *)p->payload;
                                /* Get next header type. */
                                *nexth = IP6_HBH_NEXTH(hbh_hdr); /* Get the header length. */
                                hlen = (uint16_t)(8 * (1 + hbh_hdr->_hlen));
                                if ((p->len < 8) || (hlen > p->len)) {
                                    Logf(true,
                                         "IPv6 options header (hlen %d) does not fit in first PacketBuffer (len %d), IPv6 packet dropped.\n",
                                         hlen,
                                         p->len);
                                    /* free (drop) packet pbufs */
                                    free_pkt_buf(p);
                                    goto ip6_input_cleanup;
                                }
                                hlen_tot = uint16_t(hlen_tot + hlen);
                                /* The extended option header starts right after Hop-by-Hop header. */
                                int32_t opt_offset = IP6_HBH_HLEN;
                                while (opt_offset < hlen) {
                                    auto opt_dlen = 0;
                                    auto* opt_hdr = (struct Ip6OptionHdr *)((uint8_t *)hbh_hdr +
                                        opt_offset);
                                    switch (IP6_OPT_TYPE(opt_hdr)) {
                                        /* @todo: process IPV6 Hop-by-Hop option data */
                                    case IP6_PAD1_OPTION:
                                        /* PAD1 option doesn't have length and value field */ opt_dlen = -1;
                                        break;
                                    case IP6_PADN_OPTION:
                                        opt_dlen = IP6_OPT_DLEN(opt_hdr);
                                        break;
                                    case IP6_ROUTER_ALERT_OPTION:
                                        opt_dlen = IP6_OPT_DLEN(opt_hdr);
                                        break;
                                    case IP6_JUMBO_OPTION:
                                        opt_dlen = IP6_OPT_DLEN(opt_hdr);
                                        break;
                                    default: /* Check 2 MSB of Hop-by-Hop header type. */ switch (
                                            IP6_OPT_TYPE_ACTION(opt_hdr)) {
                                        case 1: /* Discard the packet. */ Logf(
                                                true,
                                                ("ip6_input: packet with invalid Hop-by-Hop option type dropped.\n"
                                                ));
                                            free_pkt_buf(p);
                                            goto ip6_input_cleanup;
                                        case 2: /* Send ICMP Parameter Problem */
                                            icmp6_param_problem(
                                                p,
                                                ICMP6_PP_OPTION,
                                                (uint8_t*)opt_hdr);
                                            Logf(true,
                                                 ("ip6_input: packet with invalid Hop-by-Hop option type dropped.\n"
                                                 ));
                                            free_pkt_buf(p);
                                            goto ip6_input_cleanup;
                                        case 3:
                                            /* Send ICMP Parameter Problem if destination address is not a multicast address */
                                            if (!is_ip6_addr_mcast(&curr_dst_addr.u_addr.ip6)) {
                                                icmp6_param_problem(p, ICMP6_PP_OPTION, (uint8_t*)opt_hdr);
                                            }
                                            Logf(true,
                                                 ("ip6_input: packet with invalid Hop-by-Hop option type dropped.\n"
                                                 ));
                                            free_pkt_buf(p);
                                            goto ip6_input_cleanup;
                                        default: /* Skip over this option. */ opt_dlen =
                                                IP6_OPT_DLEN(opt_hdr);
                                            break;
                                        }
                                        break;
                                    } /* Adjust the offset to move to the next extended option header */
                                    opt_offset = opt_offset + IP6_OPT_HLEN + opt_dlen;
                                }
                                pbuf_remove_header(p, hlen);
                                break;
                            }
                        case IP6_NEXTH_DESTOPTS:
                            {
                                Logf(true, ("ip6_input: packet with Destination options header\n"));
                                struct Ip6DestHdr* dest_hdr = (struct Ip6DestHdr *)p->payload;
                                /* Get next header type. */
                                *nexth = IP6_DEST_NEXTH(dest_hdr); /* Get the header length. */
                                hlen = 8 * (1 + dest_hdr->_hlen);
                                if ((p->len < 8) || (hlen > p->len)) {
                                    Logf(true,
                                         "IPv6 options header (hlen %d) does not fit in first PacketBuffer (len %d), IPv6 packet dropped.\n",
                                         hlen,
                                         p->len);
                                    /* free (drop) packet pbufs */
                                    free_pkt_buf(p);
                                    goto ip6_input_cleanup;
                                }
                                hlen_tot = (uint16_t)(hlen_tot + hlen);
                                /* The extended option header starts right after Destination header. */
                                int32_t opt_offset = IP6_DEST_HLEN;
                                while (opt_offset < hlen) {
                                    int32_t opt_dlen = 0;
                                    struct Ip6OptionHdr* opt_hdr = (struct Ip6OptionHdr *)((uint8_t *)dest_hdr +
                                        opt_offset);
                                    switch (IP6_OPT_TYPE(opt_hdr)) {
                                        /* @todo: process IPV6 Destination option data */
                                    case IP6_PAD1_OPTION:
                                        /* PAD1 option deosn't have length and value field */ opt_dlen = -1;
                                        break;
                                    case IP6_PADN_OPTION:
                                        opt_dlen = IP6_OPT_DLEN(opt_hdr);
                                        break;
                                    case IP6_ROUTER_ALERT_OPTION:
                                        opt_dlen = IP6_OPT_DLEN(opt_hdr);
                                        break;
                                    case IP6_JUMBO_OPTION:
                                        opt_dlen = IP6_OPT_DLEN(opt_hdr);
                                        break;
                                    case IP6_HOME_ADDRESS_OPTION:
                                        opt_dlen = IP6_OPT_DLEN(opt_hdr);
                                        break;
                                    default: /* Check 2 MSB of Destination header type. */ switch (
                                            IP6_OPT_TYPE_ACTION(opt_hdr)) {
                                        case 1: /* Discard the packet. */ Logf(
                                                true,
                                                ("ip6_input: packet with invalid destination option type dropped.\n"
                                                ));
                                            free_pkt_buf(p);

                                            goto ip6_input_cleanup;
                                        case 2: /* Send ICMP Parameter Problem */ icmp6_param_problem(
                                                p,
                                                ICMP6_PP_OPTION,
                                                (uint8_t*)opt_hdr);
                                            Logf(true,
                                                 ("ip6_input: packet with invalid destination option type dropped.\n"
                                                 ));
                                            free_pkt_buf(p);

                                            goto ip6_input_cleanup;
                                        case 3:
                                            /* Send ICMP Parameter Problem if destination address is not a multicast address */
                                            if (!is_ip6_addr_mcast(&curr_dst_addr.u_addr.ip6)) {
                                                icmp6_param_problem(p, ICMP6_PP_OPTION, (uint8_t*)opt_hdr);
                                            }
                                            Logf(true,
                                                 ("ip6_input: packet with invalid destination option type dropped.\n"
                                                 ));
                                            free_pkt_buf(p);

                                            goto ip6_input_cleanup;
                                        default: /* Skip over this option. */ opt_dlen =
                                                IP6_OPT_DLEN(opt_hdr);
                                            break;
                                        }
                                        break;
                                    } /* Adjust the offset to move to the next extended option header */
                                    opt_offset = opt_offset + IP6_OPT_HLEN + opt_dlen;
                                }
                                pbuf_remove_header(p, hlen);
                                break;
                            }
                        case IP6_NEXTH_ROUTING:
                            {
                                Logf(true, ("ip6_input: packet with Routing header\n"));
                                struct Ip6RouteHdr* rout_hdr = (struct Ip6RouteHdr *)p->payload;
                                /* Get next header type. */
                                *nexth = get_ip6_route_hdr_nexth(rout_hdr); /* Get the header length. */
                                hlen = 8 * (1 + rout_hdr->_hlen);
                                if ((p->len < 8) || (hlen > p->len)) {
                                    Logf(true,
                                         "IPv6 options header (hlen %d) does not fit in first PacketBuffer (len %d), IPv6 packet dropped.\n",
                                         hlen,
                                         p->len);
                                    /* free (drop) packet pbufs */
                                    free_pkt_buf(p);
                                    goto ip6_input_cleanup;
                                } /* Skip over this header. */
                                hlen_tot = (uint16_t)(hlen_tot + hlen);
                                /* if segment left value is 0 in routing header, ignore the option */
                                if (get_ip6_route_hdr_seg_left(rout_hdr)) {
                                    /* The length field of routing option header must be even */
                                    if (rout_hdr->_hlen & 0x1) {
                                        /* Discard and send parameter field error */
                                        icmp6_param_problem(p, ICMP6_PP_FIELD, &rout_hdr->_hlen);
                                        Logf(true,
                                             ("ip6_input: packet with invalid routing type dropped\n"));
                                        free_pkt_buf(p);
                                        goto ip6_input_cleanup;
                                    }
                                    switch (get_ip6_route_hdr_type(rout_hdr)) {
                                        /* TODO: process routing by the type */
                                    case IP6_ROUT_TYPE2:
                                        break;
                                    case IP6_ROUT_RPL:
                                        break;
                                    default:
                                        /* Discard unrecognized routing type and send parameter field error */
                                        uint8_t route_hdr_type = get_ip6_route_hdr_type(rout_hdr);
                                        icmp6_param_problem(p, ICMP6_PP_FIELD, &route_hdr_type);
                                        Logf(true,
                                             ("ip6_input: packet with invalid routing type dropped\n"));
                                        free_pkt_buf(p);
                                        goto ip6_input_cleanup;
                                    }
                                }
                                pbuf_remove_header(p, hlen);
                                break;
                            }
                        case IP6_NEXTH_FRAGMENT:
                            {
                                Logf(true, ("ip6_input: packet with Fragment header\n"));
                                Ip6FragHdr* frag_hdr = (Ip6FragHdr *)p->payload;
                                /* Get next header type. */
                                *nexth = IP6_FRAG_NEXTH(frag_hdr); /* Fragment Header length. */
                                hlen = 8; /* Make sure this header fits in current PacketBuffer. */
                                if (hlen > p->len) {
                                    Logf(true,
                                         "IPv6 options header (hlen %d) does not fit in first PacketBuffer (len %d), IPv6 packet dropped.\n",
                                         hlen,
                                         p->len);
                                    /* free (drop) packet pbufs */
                                    free_pkt_buf(p);
                                    goto ip6_input_cleanup;
                                }
                                hlen_tot = (uint16_t)(hlen_tot + hlen);
                                /* check payload length is multiple of 8 octets when mbit is set */
                                if (IP6_FRAG_MBIT(frag_hdr) && (IP6H_PLEN(ip6_hdr) & 0x7)) {
                                    /* ipv6 payload length is not multiple of 8 octets */
                                    icmp6_param_problem(p,
                                                        ICMP6_PP_FIELD,
                                                        (uint8_t*)&ip6_hdr->_plen);
                                    Logf(true,
                                         ("ip6_input: packet with invalid payload length dropped\n"));
                                    free_pkt_buf(p);
                                    goto ip6_input_cleanup;
                                } /* Offset == 0 and more_fragments == 0? */
                                if ((frag_hdr->_fragment_offset & pp_htons(
                                    IP6_FRAG_OFFSET_MASK | IP6_FRAG_MORE_FLAG)) == 0) {
                                    /* This is a 1-fragment packet. Skip this header and continue. */
                                    pbuf_remove_header(p, hlen);
                                }
                                else {
                                    /* reassemble the packet */
                                    // ip_data.current_ip_header_tot_len = hlen_tot;
                                    // todo: set hlen_tot
                                    p = ip6_reass(p); /* packet not fully reassembled yet? */
                                    if (p == nullptr) {
                                        goto ip6_input_cleanup;
                                    } /* Returned p point to IPv6 header.
         * Update all our variables and pointers and continue. */
                                    ip6_hdr = (struct Ip6Hdr *)p->payload;
                                    *nexth = IP6H_NEXTH(ip6_hdr);
                                    hlen = hlen_tot = IP6_HDR_LEN;
                                    pbuf_remove_header(p, IP6_HDR_LEN);
                                }
                                break;
                            }
                        default:
                            goto options_done;
                        }
                        if (*nexth == IP6_NEXTH_HOPBYHOP) {
                            /* Hop-by-Hop header comes only as a first option */
                            icmp6_param_problem(p, ICMP6_PP_HEADER, nexth);
                            Logf(true,
                                 ("ip6_input: packet with Hop-by-Hop options header dropped (only valid as a first option)\n"
                                 ));
                            free_pkt_buf(p);

                            goto ip6_input_cleanup;
                        }
                    }
                }

            options_done:

                /* send to upper layers */
                Logf(true, ("ip6_input: \n"));

                Logf(true, "ip6_input: p->len %d p->tot_len %d\n", p->len, p->tot_len);

                // ip_data.current_ip_header_tot_len = hlen_tot;


                /* p points to IPv6 header again for raw_input. */
                pbuf_add_header_force(p, hlen_tot);
                /* raw input did not eat the packet? */
                raw_input_state_t raw_status = raw_input(p, inp);
                if (raw_status != RAW_INPUT_EATEN) {
                    /* Point to payload. */
                    pbuf_remove_header(p, hlen_tot);

                    switch (*nexth) {
                    case IP6_NEXTH_NONE:
                        free_pkt_buf(p);
                        break;

                    case IP6_NEXTH_UDP:

                    case IP6_NEXTH_UDPLITE:

                        udp_input(p, inp);
                        break;


                    case IP6_NEXTH_TCP:
                        tcp_input(p, inp);
                        break;


                    case IP6_NEXTH_ICMP6:
                        icmp6_input(p, inp);
                        break;

                    default:

                        if (raw_status == RAW_INPUT_DELIVERED) {
                            /* @todo: ipv6 mib in-delivers? */
                        }
                        else {
                            /* p points to IPv6 header again for raw_input. */
                            pbuf_add_header_force(p, hlen_tot);
                            /* send ICMP parameter problem unless it was a multicast or ICMPv6 */
                            if ((!is_ip6_addr_mcast(&curr_dst_addr.u_addr.ip6)) && (
                                IP6H_NEXTH(ip6_hdr) != IP6_NEXTH_ICMP6)) {
                                icmp6_param_problem(p, ICMP6_PP_HEADER, nexth);
                            }
                            Logf(true,
                                 "ip6_input: Unsupported transport protocol %d\n",
                                 (uint16_t)
                                 IP6H_NEXTH(ip6_hdr));

                        }
                        free_pkt_buf(p);
                        break;
                    }

                    Logf(true,
                         "ip6_input: Unsupported transport protocol %d\n",
                         (uint16_t)IP6H_NEXTH(ip6_hdr));

                }

                free_pkt_buf(p);
                break;
            }
        }
    }
ip6_input_cleanup:
    // ip_data.current_netif = NULL;
    // ip_data.current_input_netif = NULL;
    // ip_data.current_ip6_header = NULL;
    // ip_data.current_ip_header_tot_len = 0;
    zero_ip6_addr(&curr_src_addr.u_addr.ip6);
    zero_ip6_addr(&curr_dst_addr.u_addr.ip6);
    return ERR_OK;
}


/**
* Sends an IPv6 packet on a network interface. This function constructs
* the IPv6 header. If the source IPv6 address is NULL, the IPv6 "ANY" address is
* used as source (usually during network startup). If the source IPv6 address it
* IP6_ADDR_ANY, the most appropriate IPv6 address of the outgoing network
* interface is filled in as source address. If the destination IPv6 address is
* LWIP_IP_HDRINCL, p is assumed to already include an IPv6 header and
* p->payload points to it instead of the data.
*
* @param p the packet to send (p->payload points to the data, e.g. next
protocol header; if dest == LWIP_IP_HDRINCL, p already includes an
IPv6 header and p->payload points to that IPv6 header)
* @param src the source IPv6 address to send from (if src == IP6_ADDR_ANY, an
*         IP address of the netif is selected and used as source address.
*         if src == NULL, IP6_ADDR_ANY is used as source) (src is possibly not
*         properly zoned)
* @param dest the destination IPv6 address to send the packet to (possibly not
*             properly zoned)
* @param hl the Hop Limit value to be set in the IPv6 header
* @param tc the Traffic Class value to be set in the IPv6 header
* @param nexth the Next Header to be set in the IPv6 header
* @param netif the netif on which to send this packet
* @return ERR_OK if the packet was sent OK
*         ERR_BUF if p doesn't have enough space for IPv6/LINK headers
*         returns errors returned by netif->output_ip6
*/
LwipStatus
ip6_output_if(struct PacketBuffer* p,
              const Ip6Addr* src,
              const Ip6Addr* dest,
              uint8_t hl,
              uint8_t tc,
              uint8_t nexth,
              NetworkInterface* netif)
{
    Ip6Addr src_used{};
    copy_ip6_addr(&src_used, src);
    // todo: previous LWIP_HDR_INCL
    if (dest) {
        if (src != nullptr && is_ip6_addr_any(src)) {

            const IpAddr* sel_src_addr = select_ip6_src_addr(netif, dest);
            copy_ip6_addr(&src_used, &sel_src_addr->u_addr.ip6);
            if (is_ip6_addr_any(&src_used)) {
                /* No appropriate source address was found for this packet. */
                Logf(true,
                     ("ip6_output: No suitable source address for packet.\n"));
                return ERR_RTE;
            }
        }
    }
    return ip6_output_if_src(p, &src_used, dest, hl, tc, nexth, netif);
}


/**
* Same as ip6_output_if() but 'src' address is not replaced by netif address
* when it is 'any'.
*/
LwipStatus
ip6_output_if_src(struct PacketBuffer* pbuf,
                  Ip6Addr* src,
                  const Ip6Addr* dest,
                  uint8_t hl,
                  uint8_t tc,
                  uint8_t nexth,
                  NetworkInterface* netif)
{
    struct Ip6Hdr* ip6hdr;
    Ip6Addr dest_addr{};

    // LWIP_IP_CHECK_PBUF_REF_COUNT_FOR_TX(p);

    /* Should the IPv6 header be generated or is it already included in p? */
    if (dest != nullptr) {
        /* If the destination address is scoped but lacks a zone, add a zone now,
         * based on the outgoing interface. The lower layers (e.g., nd6) absolutely
         * require addresses to be properly zoned for correctness. In some cases,
         * earlier attempts will have been made to add a zone to the destination,
         * but this function is the only one that is called in all (other) cases,
         * so we must do this here. */
        if (ip6_addr_lacks_zone(dest, IP6_UNKNOWN)) {
            copy_ip6_addr(&dest_addr, dest);
            assign_ip6_addr_zone(&dest_addr, IP6_UNKNOWN, netif,);
            dest = &dest_addr;
        } /* generate IPv6 header */
        if (pbuf_add_header(pbuf, IP6_HDR_LEN)) {
            Logf(true,
                 ("ip6_output: not enough room for IPv6 header in PacketBuffer\n"));
            return ERR_BUF;
        }
        ip6hdr = (struct Ip6Hdr *)pbuf->payload;
        lwip_assert("check that first PacketBuffer can hold Ip6Hdr",
                    (pbuf->len >= sizeof(struct Ip6Hdr)));
        set_ip6_hdr_hop_limit(ip6hdr, hl);
        IP6H_NEXTH_SET(ip6hdr, nexth); /* dest cannot be NULL here */
        ip6_addr_copy_to_packed(&ip6hdr->dest, dest);
        get_ip6_hdr_vTCFL_SET(ip6hdr, 6, tc, 0);
        set_ip6_hdr_plen(ip6hdr, uint16_t(pbuf->tot_len - IP6_HDR_LEN));
        if (src == nullptr) {
            set_ip6_addr_any(src);
        } /* src cannot be NULL here */
        ip6_addr_copy_to_packed(&ip6hdr->src, src);
    }
    else {
        /* IP header already included in p */
        ip6hdr = (struct Ip6Hdr *)pbuf->payload;
        ip6_addr_copy_from_packed(&dest_addr, &ip6hdr->dest);
        assign_ip6_addr_zone(&dest_addr, IP6_UNKNOWN, netif,);
        dest = &dest_addr;
    }

    ip6hdr = (Ip6Hdr *)pbuf->payload;
    lwip_assert("check that first PacketBuffer can hold Ip6Hdr",
                (pbuf->len >= sizeof(Ip6Hdr)));

    set_ip6_hdr_hop_limit(ip6hdr, hl);
    IP6H_NEXTH_SET(ip6hdr, nexth);

    /* dest cannot be NULL here */
    ip6_addr_copy_to_packed(&ip6hdr->dest, dest);

    get_ip6_hdr_vTCFL_SET(ip6hdr, 6, tc, 0);
    set_ip6_hdr_plen(ip6hdr, (uint16_t)(pbuf->tot_len - IP6_HDR_LEN));

    // if (src == nullptr) {
    //     src = IP6_ADDR_ANY6;
    // }
    /* src cannot be NULL here */
    ip6_addr_copy_to_packed(&ip6hdr->src, src);
    for (int i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
        if (is_ip6_addr_valid(get_netif_ip6_addr_state(netif, i)) &&
            cmp_ip6_addr(dest, get_netif_ip6_addr(netif, i))) {
            /* Packet to self, enqueue it for loopback */
            Logf(true, ("netif_loop_output()\n"));
            NetworkInterface* loop_netif = nullptr;
            return output_netif_loop(netif, pbuf);
        }
    }
    Logf(true, ("netif->output_ip6()\n"));
    return netif->output_ip6(netif, pbuf, dest);
}



/**
 * Simple interface to ip6_output_if. It finds the outgoing network
 * interface and calls upon ip6_output_if to do the actual work.
 *
 * @param p the packet to send (p->payload points to the data, e.g. next
            protocol header; if dest == LWIP_IP_HDRINCL, p already includes an
            IPv6 header and p->payload points to that IPv6 header)
 * @param src the source IPv6 address to send from (if src == IP6_ADDR_ANY, an
 *         IP address of the netif is selected and used as source address.
 *         if src == NULL, IP6_ADDR_ANY is used as source)
 * @param dest the destination IPv6 address to send the packet to
 * @param hl the Hop Limit value to be set in the IPv6 header
 * @param tc the Traffic Class value to be set in the IPv6 header
 * @param nexth the Next Header to be set in the IPv6 header
 *
 * @return ERR_RTE if no route is found
 *         see ip_output_if() for more return values
 */
LwipStatus
ip6_output(struct PacketBuffer* p,
           Ip6Addr* src,
           Ip6Addr* dest,
           uint8_t hl,
           uint8_t tc,
           uint8_t nexth)
{
    NetworkInterface* netif;
    Ip6Addr src_addr{};
    Ip6Addr dest_addr{};
    // LWIP_IP_CHECK_PBUF_REF_COUNT_FOR_TX(p);
    if (dest) {
        netif = ip6_route(src, dest);
    }
    else {
        /* IP header included in p, read addresses. */
        struct Ip6Hdr* ip6hdr = (struct Ip6Hdr *)p->payload;
        ip6_addr_copy_from_packed(&src_addr, &ip6hdr->src);
        ip6_addr_copy_from_packed(&dest_addr, &ip6hdr->dest);
        netif = ip6_route(&src_addr, &dest_addr);
    }
    if (netif == nullptr) {
        Logf(true,
             "ip6_output: no route for %x:%x:%x:%x:%x:%x:%x:%x\n", get_ip6_addr_u16_blk(dest),
                 IP6_ADDR_BLOCK2(dest), IP6_ADDR_BLOCK3(dest), IP6_ADDR_BLOCK4(dest),
                 IP6_ADDR_BLOCK5(dest), IP6_ADDR_BLOCK6(dest), IP6_ADDR_BLOCK7(dest),
                 IP6_ADDR_BLOCK8(dest));
        return ERR_RTE;
    }
    return ip6_output_if(p, src, dest, hl, tc, nexth, netif);
} /** Like ip6_output, but takes and addr_hint pointer that is passed on to netif->addr_hint
 *  before calling ip6_output_if.
 *
 * @param p the packet to send (p->payload points to the data, e.g. next
            protocol header; if dest == LWIP_IP_HDRINCL, p already includes an
            IPv6 header and p->payload points to that IPv6 header)
 * @param src the source IPv6 address to send from (if src == IP6_ADDR_ANY, an
 *         IP address of the netif is selected and used as source address.
 *         if src == NULL, IP6_ADDR_ANY is used as source)
 * @param dest the destination IPv6 address to send the packet to
 * @param hl the Hop Limit value to be set in the IPv6 header
 * @param tc the Traffic Class value to be set in the IPv6 header
 * @param nexth the Next Header to be set in the IPv6 header
 * @param netif_hint netif output hint pointer set to netif->hint before
 *        calling ip_output_if()
 *
 * @return ERR_RTE if no route is found
 *         see ip_output_if() for more return values
 */
LwipStatus
ip6_output_hinted(struct PacketBuffer* p,
                  const Ip6Addr* src,
                  const Ip6Addr* dest,
                  uint8_t hl,
                  uint8_t tc,
                  uint8_t nexth,
                  NetIfcHint* netif_hint)
{
    NetworkInterface* netif;
    Ip6Addr src_addr, dest_addr;
    if (dest) {
        netif = ip6_route(src, dest);
    }
    else {
        /* IP header included in p, read addresses. */
        struct Ip6Hdr* ip6hdr = (struct Ip6Hdr *)p->payload;
        ip6_addr_copy_from_packed(&src_addr, &ip6hdr->src);
        ip6_addr_copy_from_packed(&dest_addr, &ip6hdr->dest);
        netif = ip6_route(&src_addr, &dest_addr);
    }
    if (netif == nullptr) {
        Logf(true,
             "ip6_output: no route for %x:%x:%x:%x:%x:%x:%x:%x\n", get_ip6_addr_u16_blk(dest),
                 IP6_ADDR_BLOCK2(dest), IP6_ADDR_BLOCK3(dest), IP6_ADDR_BLOCK4(dest),
                 IP6_ADDR_BLOCK5(dest), IP6_ADDR_BLOCK6(dest), IP6_ADDR_BLOCK7(dest),
                 IP6_ADDR_BLOCK8(dest));
        return ERR_RTE;
    }
    netif_set_hints(netif, netif_hint);
    LwipStatus err = ip6_output_if(p, src, dest, hl, tc, nexth, netif);
    netif_reset_hints(netif);
    return err;
} /**
 * Add a hop-by-hop options header with a router alert option and padding.
 *
 * Used by MLD when sending a Multicast listener report/done message.
 *
 * @param p the packet to which we will prepend the options header
 * @param nexth the next header protocol number (e.g. IP6_NEXTH_ICMP6)
 * @param value the value of the router alert option data (e.g. IP6_ROUTER_ALERT_VALUE_MLD)
 * @return ERR_OK if hop-by-hop header was added, ERR_* otherwise
 */
LwipStatus
ip6_options_add_hbh_ra(struct PacketBuffer* p, uint8_t nexth, uint8_t value)
{
    uint32_t offset = 0; /* fixed 4 bytes for router alert option and 2 bytes padding */
    const uint8_t hlen = (sizeof(struct Ip6OptionHdr) * 2) + IP6_ROUTER_ALERT_DLEN;
    /* Move pointer to make room for hop-by-hop options header. */
    if (pbuf_add_header(p, sizeof(struct Ip6HopByHopHdr) + hlen)) {
        Logf(true, ("ip6_options: no space for options header\n"));
        return ERR_BUF;
    } /* Set fields of Hop-by-Hop header */
    Ip6HopByHopHdr* hbh_hdr = (struct Ip6HopByHopHdr *)p->payload;
    hbh_hdr->_nexth = nexth;
    hbh_hdr->_hlen = 0;
    offset = IP6_HBH_HLEN;
    /* Set router alert options to Hop-by-Hop extended option header */
    Ip6OptionHdr* opt_hdr = (struct Ip6OptionHdr *)((uint8_t *)hbh_hdr + offset);
    opt_hdr->_opt_type = IP6_ROUTER_ALERT_OPTION;
    opt_hdr->_opt_dlen = IP6_ROUTER_ALERT_DLEN;
    offset += IP6_OPT_HLEN; /* Set router alert option data */
    uint8_t* opt_data = (uint8_t *)hbh_hdr + offset;
    opt_data[0] = value;
    opt_data[1] = 0;
    offset += IP6_OPT_DLEN(opt_hdr);
    /* add 2 bytes padding to make 8 bytes Hop-by-Hop header length */
    opt_hdr = (struct Ip6OptionHdr *)((uint8_t *)hbh_hdr + offset);
    opt_hdr->_opt_type = IP6_PADN_OPTION;
    opt_hdr->_opt_dlen = 0;
    return ERR_OK;
}
//
// END OF FILE
//
