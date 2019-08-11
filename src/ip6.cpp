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
#include <util.h>

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
 * @param out_netif Retrieved netif on success, empy on failure
 * @param interfaces a collection of interfaces to check.
 * @return STATUS_OK if suitable interface found, STATUS_NOT_FOUND otherwise.
 */
LwipStatus
route_ip6_packet(const Ip6AddrInfo& src,
                 const Ip6AddrInfo& dest,
                 NetworkInterface& out_netif,
                 std::vector<NetworkInterface> interfaces)
{
    if (interfaces.size() == 1) {
        out_netif = interfaces[0];
        return STATUS_SUCCESS;
    }

    for (auto& it : interfaces) {
        if (!is_netif_up(it) || !is_netif_link_up(it)) {
            continue;
        }



        if (ip6_addr_has_zone(dest)) {
            if (rest_ip6_addr_zone(dest, it)) {
                out_netif = it;
                return STATUS_SUCCESS;
            } 
        }

        if (ip6_addr_has_scope(dest, IP6_UNKNOWN) | ip6_addr_has_scope(src, IP6_UNICAST) || ip6_addr_is_loopback(src)) {
            if (ip6_addr_has_zone(src)) {
                if (rest_ip6_addr_zone(src, it)) {
                    out_netif = it;
                    return STATUS_SUCCESS;
                }

                for (auto &ip : it.ip6_addresses) {
                     if (ip6_addr_is_valid(ip) && cmp_ip6_addr_zoneless(src.addr, ip.addr)) {
                         out_netif = it;
                         return STATUS_SUCCESS;
                     }
                }

               
                    
            }
        }

        for (auto& ip : it.ip6_addresses) {
            if (ip6_addr_is_valid(ip) && ip6_addr_on_same_net(dest, ip) && ip6_addr_is_static(ip) || ip6_addr_hosts_equal(dest, ip)) {
                out_netif = it;
                return STATUS_SUCCESS;
            }

            if (!ip6_addr_is_any(src) && ip6_addr_is_valid(ip) && ip6_addr_equal(src, ip)) {
                out_netif = it;
                return STATUS_SUCCESS;
            }
        }

        if (ip6_addr_is_loopback(dest) && it.netif_type == NETIF_TYPE_LOOPBACK) {
            out_netif = it;
            return STATUS_SUCCESS;
        }
    }

    NetworkInterface nd6_route_found_if{};
    const auto nd6_find_route_status = nd6_find_route(dest, nd6_route_found_if);
    if (nd6_find_route_status == STATUS_SUCCESS) {
        out_netif = nd6_route_found_if;
        return nd6_find_route_status;
    }

    NetworkInterface def_netif{};
    if(get_default_netif(interfaces, def_netif) == STATUS_SUCCESS) {
        if (is_netif_up(def_netif) && is_netif_link_up(def_netif)) {
            out_netif = def_netif;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}


/**
 * Forwards an IPv6 packet. It finds an appropriate route for the
 * packet, decrements the HL value of the packet, and outputs
 * the packet on the appropriate interface.
 *
 * @param pkt_buf the packet to forward (p->payload points to IP header)
 * @param iphdr the IPv6 header of the input packet
 * @param in_netif the netif on which this packet was received
 * @param dest_addr
 * @param src_addr
 */
LwipStatus
forward_ip6_packet(PacketBuffer& pkt_buf,
                   Ip6Hdr& iphdr,
                   NetworkInterface& in_netif,
                   Ip6AddrInfo& dest_addr,
                   Ip6AddrInfo& src_addr,
                   std::vector<NetworkInterface>& interfaces)
{
    /* do not forward link-local or loopback addresses */
    if (ip6_addr_is_linklocal(dest_addr) || ip6_addr_is_loopback(dest_addr)) {
        Logf(true, ("ip6_forward: not forwarding link-local address.\n"));
        return STATUS_ERROR;
    } 
    
    /* Find network interface where to forward this IP packet to. */
    Ip6AddrInfo ip6_any_addr{};
    set_ip6_addr_any(ip6_any_addr);
    NetworkInterface dest_netif{};
    if(route_ip6_packet(ip6_any_addr, dest_addr, dest_netif, interfaces) !=STATUS_SUCCESS) {
        if (get_ip6_hdr_next_hop(iphdr) != IP6_NEXTH_ICMP6) {
            // todo: send to queue for ICMP to handle
            icmp6_dest_unreach(pkt_buf, ICMP6_DUR_NO_ROUTE);
        }

        return STATUS_E_ROUTING;
    }

     /* Do not forward packets with a zoned (e.g., link-local) source address
   * outside of their zone. We determined the zone a bit earlier, so we know
   * that the address is properly zoned here, so we can safely use has_zone.
   * Also skip packets with a loopback source address (link-local implied). */
    if (ip6_addr_has_zone(src_addr) && ! rest_ip6_addr_zone(src_addr, dest_netif) ||
        ip6_addr_is_loopback(src_addr)) {
        return STATUS_E_ROUTING;
    }


    // Do not forward packets onto the same network interface on which they arrived.
    if (dest_netif.name == in_netif.name) {
        Logf(true,
             ("ip6_forward: not bouncing packets back on incoming interface.\n"));
        return STATUS_E_ROUTING;
    } 
    
    // decrement HL and send ICMP6 if HL == 0
    set_ip6_hdr_hop_limit(iphdr, get_ip6_hdr_hop_limit(iphdr) - 1);
    if (get_ip6_hdr_hop_limit(iphdr) == 0) {
        // Don't send ICMP messages in response to ICMP messages
        if (get_ip6_hdr_next_hop(iphdr) != IP6_NEXTH_ICMP6) {
            icmp6_time_exceeded(pkt_buf, ICMP6_TE_HL);
        }
        return STATUS_E_ROUTING;
    }

    if (dest_netif.mtu && (pkt_buf.data.size() > dest_netif.mtu)) {
        /* Don't send ICMP messages in response to ICMP messages */
        if (get_ip6_hdr_next_hop(iphdr) != IP6_NEXTH_ICMP6) {
            icmp6_packet_too_big(pkt_buf, dest_netif.mtu);
        }
        return STATUS_E_ROUTING;
    } 
    
    // transmit PacketBuffer on chosen interface
    return ip6_output_if(pkt_buf, src_addr, dest_addr, iphdr._hoplim, get_ip6_hdr_tc(iphdr), iphdr._nexth, dest_netif);
}


// Return true if the current input packet should be accepted on this netif
bool
check_accept_ip6_pkt(const NetworkInterface& netif,
                     const Ip6AddrInfo& src_addr,
                     const Ip6AddrInfo& dest_addr)
{
    /* interface is up? */
    if (is_netif_up(netif)) {
        /* unicast to this interface address? address configured? */
        /* If custom scopes are used, the destination zone will be tested as
                                         * part of the local-address comparison, but we need to test the source
                                         * scope as well (e.g., is this interface on the same link?). */
        for (auto& addr : netif.ip6_addresses) {
            if (ip6_addr_is_valid(addr) && ip6_addr_equal(dest_addr, addr) && (!
                ip6_addr_has_zone(src_addr) || rest_ip6_addr_zone(src_addr, netif))) {
                return true;
            }
        }
    }
    return false;
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
 * @param pkt_buf the received IPv6 packet (p->payload points to IPv6 header)
 * @param in_netif the netif on which this packet was received
 * @return ERR_OK if the packet was processed (could return ERR_* if it wasn't
 *         processed, but currently always returns ERR_OK)
 */
LwipStatus
recv_ip6_pkt(PacketBuffer& pkt_buf, NetworkInterface& in_netif)
{
    NetworkInterface* netif;
    uint8_t* nexth;
    uint16_t hlen_tot; /* the current header length */ /* identify the IP header */

    Ip6Hdr ip6_hdr{};
    uint32_t v_tc_fl = 0;
    if (u8_vector_to_u32(pkt_buf.data), 0) == STATUS_ERROR) {
    }
    ip6_hdr = ((pkt_buf.data[0] >> 24) & 0xff) | ((pkt_buf.data[1] >> 16) & 0xff) | ((pkt_buf.data[2] >> 8) & 0xff) | (pkt_buf.data[3] & 0xff);

    Ip6Hdr* ip6_hdr = reinterpret_cast<Ip6Hdr *>(pkt_buf->payload);

    if (get_ip6_hdr_v(ip6_hdr) != 6) {
        Logf(true,
             "IPv6 packet dropped due to bad version number %d\n",
             get_ip6_hdr_v(ip6_hdr));
        free_pkt_buf(pkt_buf);
        return STATUS_SUCCESS;
    }


    // if (LWIP_HOOK_IP6_INPUT(p, inp)) {
    //   /* the packet has been eaten */
    //   return ERR_OK;
    // }


    /* header length exceeds first PacketBuffer length, or ip length exceeds total PacketBuffer length? */
    if ((IP6_HDR_LEN > pkt_buf->len) || (IP6H_PLEN(ip6_hdr) > (pkt_buf->tot_len - IP6_HDR_LEN))) {
        if (IP6_HDR_LEN > pkt_buf->len) {
            Logf(true,
                 "IPv6 header (len %d) does not fit in first PacketBuffer (len %d), IP packet dropped.\n",
                 (uint16_t)IP6_HDR_LEN,
                 pkt_buf->len);
        }
        if ((IP6H_PLEN(ip6_hdr) + IP6_HDR_LEN) > pkt_buf->tot_len) {
            Logf(true,
                 "IPv6 (plen %d) is longer than PacketBuffer (len %d), IP packet dropped.\n",
                 (uint16_t)(IP6H_PLEN(ip6_hdr) + IP6_HDR_LEN),
                 pkt_buf->tot_len);
        }
        /* free (drop) packet pbufs */
        free_pkt_buf(pkt_buf);
        return STATUS_SUCCESS;
    }

    /* Trim PacketBuffer. This should have been done at the netif layer,
     * but we'll do it anyway just to be sure that its done. */
    // pbuf_realloc(p);

    /* copy IP addresses to aligned Ip6Address */
    // todo: get curr dst and src ip addr from somewhere
    IpAddrInfo curr_dst_addr{};
    IpAddrInfo curr_src_addr{};
    memcpy(&curr_dst_addr.u_addr.ip6.addr, &ip6_hdr->dest, sizeof(Ip6Addr));
    memcpy(&curr_src_addr.u_addr.ip6.addr, &ip6_hdr->src, sizeof(Ip6Addr));

    /* Don't accept virtual IPv4 mapped IPv6 addresses.
     * Don't accept multicast source addresses. */
    if (is_ip6_addr_ip4_mapped_ip6((&curr_dst_addr.u_addr.ip6)) ||
        is_ip6_addr_ip4_mapped_ip6((&curr_src_addr.u_addr.ip6)) ||
        is_ip6_addr_mcast((&curr_src_addr.u_addr.ip6))) {
        /* free (drop) packet pbufs */
        free_pkt_buf(pkt_buf);
        return STATUS_SUCCESS;
    }

    /* Set the appropriate zone identifier on the addresses. */
    assign_ip6_addr_zone(&curr_dst_addr.u_addr.ip6, IP6_UNKNOWN, in_netif,);
    assign_ip6_addr_zone(&curr_src_addr.u_addr.ip6, IP6_UNICAST, in_netif,);

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
            netif = in_netif;
        }

        else if (mld6_lookfor_group(in_netif, &curr_dst_addr.u_addr.ip6)) {
            netif = in_netif;
        }

        else {
            netif = nullptr;
        }
    }
    else {
        /* start trying with inp. if that's not acceptable, start walking the
           list of configured netifs. */
        if (check_accept_ip6_pkt(in_netif, &curr_src_addr.u_addr.ip6, &curr_dst_addr.u_addr.ip6)) {
            netif = in_netif;
        }
        else {
            netif = nullptr;


            /* The loopback address is to be considered link-local. Packets to it
              * should be dropped on other interfaces, as per RFC 4291 Sec. 2.5.3.
              * Its implied scope means packets *from* the loopback address should
              * not be accepted on other interfaces, either. These requirements
              * cannot be implemented in the case that loopback traffic is sent
              * across a non-loopback interface, however. */
            if (ip6_addr_is_loopback(&curr_dst_addr.u_addr.ip6) ||
                ip6_addr_is_loopback(&curr_src_addr.u_addr.ip6)) {
                goto netif_found;
            }


            for ((netif) = netif_list; (netif) != nullptr; (netif) = (netif)->next) {
                if (netif == in_netif) {
                    /* we checked that before already */
                    continue;
                }
                if (check_accept_ip6_pkt(netif, &curr_src_addr.u_addr.ip6, &curr_dst_addr.u_addr.ip6)) {
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
    if (ip6_addr_is_any(&curr_src_addr.u_addr.ip6) &&
        (!is_ip6_addr_solicited_node(&curr_dst_addr.u_addr.ip6))) {
        /* packet source is not valid */
        /* free (drop) packet pbufs */
        Logf(true, ("ip6_input: packet with src ANY_ADDRESS dropped\n"));
        free_pkt_buf(pkt_buf);
        goto ip6_input_cleanup;
    }

    /* packet not for us? */
    if (netif == nullptr) {
        /* packet not for us, route or discard */
        Logf(true, ("ip6_input: packet not for us.\n"));

        /* non-multicast packet? */
        if (!is_ip6_addr_mcast(&curr_dst_addr.u_addr.ip6)) {
            /* try to forward IP packet on (other) interfaces */
            forward_ip6_packet(pkt_buf, ip6_hdr, in_netif, &curr_dst_addr.u_addr.ip6, & curr_src_addr.u_addr.ip6,);
        }

        free_pkt_buf(pkt_buf);
        goto ip6_input_cleanup;
    }

    /* current netif pointer. */
    // ip_data.current_netif = netif;
    // todo: set current netif

    /* Save next header type. */
    uint8_t next_hdr = get_ip6_hdr_next_hop(ip6_hdr);
    *nexth = next_hdr;

    /* Init header length. */
    uint16_t hlen = hlen_tot = IP6_HDR_LEN;

    /* Move to payload. */
    // pbuf_remove_header(p, IP6_HDR_LEN);

    /* Process known option extension headers, if present. */
    while (*nexth != IP6_NEXTH_NONE) {
        switch (*nexth) {
        case IP6_NEXTH_HOPBYHOP:

            int32_t opt_offset;
            struct Ip6HopByHopHdr* hbh_hdr;
            struct Ip6OptionHdr* opt_hdr;
            Logf(true, ("ip6_input: packet with Hop-by-Hop options header\n"));

            /* Get and check the header length, while staying in packet bounds. */
            hbh_hdr = (struct Ip6HopByHopHdr *)pkt_buf->payload;

            /* Get next header type. */
            *nexth = IP6_HBH_NEXTH(hbh_hdr);

            /* Get the header length. */
            hlen = (uint16_t)(8 * (1 + hbh_hdr->_hlen));

            if ((pkt_buf->len < 8) || (hlen > pkt_buf->len)) {
                Logf(true,
                     "IPv6 options header (hlen %d) does not fit in first PacketBuffer (len %d), IPv6 packet dropped.\n",
                     hlen,
                     pkt_buf->len);
                /* free (drop) packet pbufs */
                free_pkt_buf(pkt_buf);
                return STATUS_SUCCESS;
            }
            if (true) {
                int32_t opt_offset;
                struct Ip6OptionHdr* opt_hdr;
                Logf(true, ("ip6_input: packet with Destination options header\n"));

                struct Ip6DestHdr* dest_hdr = (struct Ip6DestHdr *)pkt_buf->payload;

                /* Get next header type. */
                *nexth = IP6_DEST_NEXTH(dest_hdr);

                /* Get the header length. */
                hlen = 8 * (1 + dest_hdr->_hlen);
                if ((pkt_buf->len < 8) || (hlen > pkt_buf->len)) {
                    Logf(true,
                         "IPv6 options header (hlen %d) does not fit in first PacketBuffer (len %d), IPv6 packet dropped.\n",
                         hlen,
                         pkt_buf->len);
                    /* free (drop) packet pbufs */
                    free_pkt_buf(pkt_buf);
                    return STATUS_SUCCESS;
                } /* Trim PacketBuffer. This should have been done at the netif layer,
   * but we'll do it anyway just to be sure that its done. */
                // pbuf_realloc(p);
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

                Ip6RouteHdr* rout_hdr = (struct Ip6RouteHdr *)pkt_buf->payload;

                /* Get next header type. */
                *nexth = get_ip6_route_hdr_nexth(rout_hdr);

                /* Get the header length. */
                hlen = 8 * (1 + rout_hdr->_hlen);

                if ((pkt_buf->len < 8) || (hlen > pkt_buf->len)) {
                    Logf(true,
                         "IPv6 options header (hlen %d) does not fit in first PacketBuffer (len %d), IPv6 packet dropped.\n",
                         hlen,
                         pkt_buf->len);
                    /* free (drop) packet pbufs */
                    free_pkt_buf(pkt_buf);
                    return STATUS_SUCCESS;
                } /* Set the appropriate zone identifier on the addresses. */
                assign_ip6_addr_zone(&curr_dst_addr.u_addr.ip6, IP6_UNKNOWN, in_netif,);
                assign_ip6_addr_zone(&curr_dst_addr.u_addr.ip6, IP6_UNICAST, in_netif,);
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
                        netif = in_netif;
                    }
                    else if (mld6_lookfor_group(in_netif, &curr_dst_addr.u_addr.ip6)) {
                        netif = in_netif;
                    }
                    else {
                        netif = nullptr;
                    }
                }
                else {
                    Logf(true, ("ip6_input: packet with Fragment header\n"));

                    Ip6FragHdr* frag_hdr = (Ip6FragHdr*)pkt_buf->payload;

                    /* Get next header type. */
                    *nexth = IP6_FRAG_NEXTH(frag_hdr);

                    /* Fragment Header length. */
                    hlen = 8;

                    /* Make sure this header fits in current PacketBuffer. */
                    if (hlen > pkt_buf->len) {
                        Logf(true,
                             "IPv6 options header (hlen %d) does not fit in first PacketBuffer (len %d), IPv6 packet dropped.\n",
                             hlen,
                             pkt_buf->len);
                        /* free (drop) packet pbufs */
                        free_pkt_buf(pkt_buf);
                        goto ip6_input_cleanup;
                    } /* packet not for us? */
                    if (netif == nullptr) {
                        /* packet not for us, route or discard */
                        Logf(true, ("ip6_input: packet not for us.\n"));
                        /* non-multicast packet? */
                        if (!is_ip6_addr_mcast(&curr_dst_addr.u_addr.ip6)) {
                            /* try to forward IP packet on (other) interfaces */
                            forward_ip6_packet(pkt_buf, ip6_hdr, in_netif, &curr_src_addr.u_addr.ip6, &curr_dst_addr.u_addr.ip6,);
                        }
                        free_pkt_buf(pkt_buf);
                        goto ip6_input_cleanup;
                    } /* current netif pointer. */
                    // ip_data.current_netif = netif; /* Save next header type. */
                    // todo: set current netif
                    *nexth = get_ip6_hdr_next_hop(ip6_hdr); /* Init header length. */
                    uint16_t hlen = hlen_tot = IP6_HDR_LEN; /* Move to payload. */
                    // pbuf_remove_header(p, IP6_HDR_LEN);
                    /* Process known option extension headers, if present. */
                    while (*nexth != IP6_NEXTH_NONE) {
                        switch (*nexth) {
                        case IP6_NEXTH_HOPBYHOP:
                            {
                                Logf(true, ("ip6_input: packet with Hop-by-Hop options header\n"));
                                /* Get and check the header length, while staying in packet bounds. */
                                Ip6HopByHopHdr* hbh_hdr = (Ip6HopByHopHdr *)pkt_buf->payload;
                                /* Get next header type. */
                                *nexth = IP6_HBH_NEXTH(hbh_hdr); /* Get the header length. */
                                hlen = (uint16_t)(8 * (1 + hbh_hdr->_hlen));
                                if ((pkt_buf->len < 8) || (hlen > pkt_buf->len)) {
                                    Logf(true,
                                         "IPv6 options header (hlen %d) does not fit in first PacketBuffer (len %d), IPv6 packet dropped.\n",
                                         hlen,
                                         pkt_buf->len);
                                    /* free (drop) packet pbufs */
                                    free_pkt_buf(pkt_buf);
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
                                            free_pkt_buf(pkt_buf);
                                            goto ip6_input_cleanup;
                                        case 2: /* Send ICMP Parameter Problem */
                                            icmp6_param_problem(
                                                pkt_buf,
                                                ICMP6_PP_OPTION,
                                                (uint8_t*)opt_hdr);
                                            Logf(true,
                                                 ("ip6_input: packet with invalid Hop-by-Hop option type dropped.\n"
                                                 ));
                                            free_pkt_buf(pkt_buf);
                                            goto ip6_input_cleanup;
                                        case 3:
                                            /* Send ICMP Parameter Problem if destination address is not a multicast address */
                                            if (!is_ip6_addr_mcast(&curr_dst_addr.u_addr.ip6)) {
                                                icmp6_param_problem(pkt_buf, ICMP6_PP_OPTION, (uint8_t*)opt_hdr);
                                            }
                                            Logf(true,
                                                 ("ip6_input: packet with invalid Hop-by-Hop option type dropped.\n"
                                                 ));
                                            free_pkt_buf(pkt_buf);
                                            goto ip6_input_cleanup;
                                        default: /* Skip over this option. */ opt_dlen =
                                                IP6_OPT_DLEN(opt_hdr);
                                            break;
                                        }
                                        break;
                                    } /* Adjust the offset to move to the next extended option header */
                                    opt_offset = opt_offset + IP6_OPT_HLEN + opt_dlen;
                                }
                                // pbuf_remove_header(p, hlen);
                                break;
                            }
                        case IP6_NEXTH_DESTOPTS:
                            {
                                Logf(true, ("ip6_input: packet with Destination options header\n"));
                                struct Ip6DestHdr* dest_hdr = (struct Ip6DestHdr *)pkt_buf->payload;
                                /* Get next header type. */
                                *nexth = IP6_DEST_NEXTH(dest_hdr); /* Get the header length. */
                                hlen = 8 * (1 + dest_hdr->_hlen);
                                if ((pkt_buf->len < 8) || (hlen > pkt_buf->len)) {
                                    Logf(true,
                                         "IPv6 options header (hlen %d) does not fit in first PacketBuffer (len %d), IPv6 packet dropped.\n",
                                         hlen,
                                         pkt_buf->len);
                                    /* free (drop) packet pbufs */
                                    free_pkt_buf(pkt_buf);
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
                                            free_pkt_buf(pkt_buf);

                                            goto ip6_input_cleanup;
                                        case 2: /* Send ICMP Parameter Problem */ icmp6_param_problem(
                                                pkt_buf,
                                                ICMP6_PP_OPTION,
                                                (uint8_t*)opt_hdr);
                                            Logf(true,
                                                 ("ip6_input: packet with invalid destination option type dropped.\n"
                                                 ));
                                            free_pkt_buf(pkt_buf);

                                            goto ip6_input_cleanup;
                                        case 3:
                                            /* Send ICMP Parameter Problem if destination address is not a multicast address */
                                            if (!is_ip6_addr_mcast(&curr_dst_addr.u_addr.ip6)) {
                                                icmp6_param_problem(pkt_buf, ICMP6_PP_OPTION, (uint8_t*)opt_hdr);
                                            }
                                            Logf(true,
                                                 ("ip6_input: packet with invalid destination option type dropped.\n"
                                                 ));
                                            free_pkt_buf(pkt_buf);

                                            goto ip6_input_cleanup;
                                        default: /* Skip over this option. */ opt_dlen =
                                                IP6_OPT_DLEN(opt_hdr);
                                            break;
                                        }
                                        break;
                                    } /* Adjust the offset to move to the next extended option header */
                                    opt_offset = opt_offset + IP6_OPT_HLEN + opt_dlen;
                                }
                                // pbuf_remove_header(p, hlen);
                                break;
                            }
                        case IP6_NEXTH_ROUTING:
                            {
                                Logf(true, ("ip6_input: packet with Routing header\n"));
                                struct Ip6RouteHdr* rout_hdr = (struct Ip6RouteHdr *)pkt_buf->payload;
                                /* Get next header type. */
                                *nexth = get_ip6_route_hdr_nexth(rout_hdr); /* Get the header length. */
                                hlen = 8 * (1 + rout_hdr->_hlen);
                                if ((pkt_buf->len < 8) || (hlen > pkt_buf->len)) {
                                    Logf(true,
                                         "IPv6 options header (hlen %d) does not fit in first PacketBuffer (len %d), IPv6 packet dropped.\n",
                                         hlen,
                                         pkt_buf->len);
                                    /* free (drop) packet pbufs */
                                    free_pkt_buf(pkt_buf);
                                    goto ip6_input_cleanup;
                                } /* Skip over this header. */
                                hlen_tot = (uint16_t)(hlen_tot + hlen);
                                /* if segment left value is 0 in routing header, ignore the option */
                                if (get_ip6_route_hdr_seg_left(rout_hdr)) {
                                    /* The length field of routing option header must be even */
                                    if (rout_hdr->_hlen & 0x1) {
                                        /* Discard and send parameter field error */
                                        icmp6_param_problem(pkt_buf, ICMP6_PP_FIELD, &rout_hdr->_hlen);
                                        Logf(true,
                                             ("ip6_input: packet with invalid routing type dropped\n"));
                                        free_pkt_buf(pkt_buf);
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
                                        icmp6_param_problem(pkt_buf, ICMP6_PP_FIELD, &route_hdr_type);
                                        Logf(true,
                                             ("ip6_input: packet with invalid routing type dropped\n"));
                                        free_pkt_buf(pkt_buf);
                                        goto ip6_input_cleanup;
                                    }
                                }
                                // pbuf_remove_header(p, hlen);
                                break;
                            }
                        case IP6_NEXTH_FRAGMENT:
                            {
                                Logf(true, ("ip6_input: packet with Fragment header\n"));
                                Ip6FragHdr* frag_hdr = (Ip6FragHdr *)pkt_buf->payload;
                                /* Get next header type. */
                                *nexth = IP6_FRAG_NEXTH(frag_hdr); /* Fragment Header length. */
                                hlen = 8; /* Make sure this header fits in current PacketBuffer. */
                                if (hlen > pkt_buf->len) {
                                    Logf(true,
                                         "IPv6 options header (hlen %d) does not fit in first PacketBuffer (len %d), IPv6 packet dropped.\n",
                                         hlen,
                                         pkt_buf->len);
                                    /* free (drop) packet pbufs */
                                    free_pkt_buf(pkt_buf);
                                    goto ip6_input_cleanup;
                                }
                                hlen_tot = (uint16_t)(hlen_tot + hlen);
                                /* check payload length is multiple of 8 octets when mbit is set */
                                if (IP6_FRAG_MBIT(frag_hdr) && (IP6H_PLEN(ip6_hdr) & 0x7)) {
                                    /* ipv6 payload length is not multiple of 8 octets */
                                    icmp6_param_problem(pkt_buf,
                                                        ICMP6_PP_FIELD,
                                                        (uint8_t*)&ip6_hdr->_plen);
                                    Logf(true,
                                         ("ip6_input: packet with invalid payload length dropped\n"));
                                    free_pkt_buf(pkt_buf);
                                    goto ip6_input_cleanup;
                                } /* Offset == 0 and more_fragments == 0? */
                                if ((frag_hdr->_fragment_offset & pp_htons(
                                    IP6_FRAG_OFFSET_MASK | IP6_FRAG_MORE_FLAG)) == 0) {
                                    /* This is a 1-fragment packet. Skip this header and continue. */
                                    // pbuf_remove_header(p, hlen);
                                }
                                else {
                                    /* reassemble the packet */
                                    // ip_data.current_ip_header_tot_len = hlen_tot;
                                    // todo: set hlen_tot
                                    pkt_buf = ip6_reass(pkt_buf); /* packet not fully reassembled yet? */
                                    if (pkt_buf == nullptr) {
                                        goto ip6_input_cleanup;
                                    } /* Returned p point to IPv6 header.
         * Update all our variables and pointers and continue. */
                                    ip6_hdr = (struct Ip6Hdr *)pkt_buf->payload;
                                    *nexth = get_ip6_hdr_next_hop(ip6_hdr);
                                    hlen = hlen_tot = IP6_HDR_LEN;
                                    // pbuf_remove_header(p, IP6_HDR_LEN);
                                }
                                break;
                            }
                        default:
                            goto options_done;
                        }
                        if (*nexth == IP6_NEXTH_HOPBYHOP) {
                            /* Hop-by-Hop header comes only as a first option */
                            icmp6_param_problem(pkt_buf, ICMP6_PP_HEADER, nexth);
                            Logf(true,
                                 ("ip6_input: packet with Hop-by-Hop options header dropped (only valid as a first option)\n"
                                 ));
                            free_pkt_buf(pkt_buf);

                            goto ip6_input_cleanup;
                        }
                    }
                }

            options_done:

                /* send to upper layers */
                Logf(true, ("ip6_input: \n"));

                Logf(true, "ip6_input: p->len %d p->tot_len %d\n", pkt_buf->len, pkt_buf->tot_len);

                // ip_data.current_ip_header_tot_len = hlen_tot;


                /* p points to IPv6 header again for raw_input. */
                // pbuf_add_header_force(p, hlen_tot);
                /* raw input did not eat the packet? */
                raw_input_state_t raw_status = raw_input(pkt_buf, in_netif);
                if (raw_status != RAW_INPUT_EATEN) {
                    /* Point to payload. */
                    // pbuf_remove_header(p, hlen_tot);

                    switch (*nexth) {
                    case IP6_NEXTH_NONE:
                        free_pkt_buf(pkt_buf);
                        break;

                    case IP6_NEXTH_UDP:

                    case IP6_NEXTH_UDPLITE:

                        udp_input(pkt_buf, in_netif);
                        break;


                    case IP6_NEXTH_TCP:
                        tcp_input(pkt_buf, in_netif);
                        break;


                    case IP6_NEXTH_ICMP6:
                        icmp6_input(pkt_buf, in_netif);
                        break;

                    default:

                        if (raw_status == RAW_INPUT_DELIVERED) {
                            /* @todo: ipv6 mib in-delivers? */
                        }
                        else {
                            /* p points to IPv6 header again for raw_input. */
                            // pbuf_add_header_force(p, hlen_tot);
                            /* send ICMP parameter problem unless it was a multicast or ICMPv6 */
                            if ((!is_ip6_addr_mcast(&curr_dst_addr.u_addr.ip6)) && (
                                get_ip6_hdr_next_hop(ip6_hdr) != IP6_NEXTH_ICMP6)) {
                                icmp6_param_problem(pkt_buf, ICMP6_PP_HEADER, nexth);
                            }
                            Logf(true,
                                 "ip6_input: Unsupported transport protocol %d\n",
                                 (uint16_t)
                                 get_ip6_hdr_next_hop(ip6_hdr));

                        }
                        free_pkt_buf(pkt_buf);
                        break;
                    }

                    Logf(true,
                         "ip6_input: Unsupported transport protocol %d\n",
                         (uint16_t)get_ip6_hdr_next_hop(ip6_hdr));

                }

                free_pkt_buf(pkt_buf);
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
    return STATUS_SUCCESS;
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
ip6_output_if(PacketBuffer& p,
              const Ip6AddrInfo& src,
              const Ip6AddrInfo& dest,
              uint8_t hl,
              uint8_t tc,
              uint8_t nexth,
              NetworkInterface& netif)
{
    Ip6Addr src_used{};
    copy_ip6_addr(&src_used, src);
    // todo: previous LWIP_HDR_INCL
    if (dest) {
        if (src != nullptr && ip6_addr_is_any(src)) {

            const IpAddrInfo* sel_src_addr = select_ip6_src_addr(netif, dest,);
            copy_ip6_addr(&src_used, &sel_src_addr->u_addr.ip6);
            if (ip6_addr_is_any(&src_used)) {
                /* No appropriate source address was found for this packet. */
                Logf(true,
                     ("ip6_output: No suitable source address for packet.\n"));
                return STATUS_E_ROUTING;
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
ip6_output_if_src(PacketBuffer& pbuf,
                  Ip6AddrInfo& src,
                  const <unknown>& dest,
                  uint8_t hl,
                  uint8_t tc,
                  uint8_t nexth,
                  NetworkInterface& netif)
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
        // if (pbuf_add_header(pbuf, IP6_HDR_LEN)) {
        //     Logf(true,
        //          ("ip6_output: not enough room for IPv6 header in PacketBuffer\n"));
        //     return ERR_BUF;
        // }
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
        if (ip6_addr_is_valid(get_netif_ip6_addr_state(netif, i)) &&
            ip6_addr_equal(dest, get_netif_ip6_addr(netif, i))) {
            /* Packet to self, enqueue it for loopback */
            Logf(true, ("netif_loop_output()\n"));
            NetworkInterface* loop_netif = nullptr;
            return send_pkt_to_netif_loop(netif, pbuf);
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
        netif = route_ip6_packet(src, dest,,);
    }
    else {
        /* IP header included in p, read addresses. */
        struct Ip6Hdr* ip6hdr = (struct Ip6Hdr *)p->payload;
        ip6_addr_copy_from_packed(&src_addr, &ip6hdr->src);
        ip6_addr_copy_from_packed(&dest_addr, &ip6hdr->dest);
        netif = route_ip6_packet(&src_addr, &dest_addr,,);
    }
    if (netif == nullptr) {
        Logf(true,
             "ip6_output: no route for %x:%x:%x:%x:%x:%x:%x:%x\n", get_ip6_addr_u16_blk(dest),
                 IP6_ADDR_BLOCK2(dest), IP6_ADDR_BLOCK3(dest), IP6_ADDR_BLOCK4(dest),
                 IP6_ADDR_BLOCK5(dest), IP6_ADDR_BLOCK6(dest), IP6_ADDR_BLOCK7(dest),
                 IP6_ADDR_BLOCK8(dest));
        return STATUS_E_ROUTING;
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
        netif = route_ip6_packet(src, dest,,);
    }
    else {
        /* IP header included in p, read addresses. */
        struct Ip6Hdr* ip6hdr = (struct Ip6Hdr *)p->payload;
        ip6_addr_copy_from_packed(&src_addr, &ip6hdr->src);
        ip6_addr_copy_from_packed(&dest_addr, &ip6hdr->dest);
        netif = route_ip6_packet(&src_addr, &dest_addr,,);
    }
    if (netif == nullptr) {
        Logf(true,
             "ip6_output: no route for %x:%x:%x:%x:%x:%x:%x:%x\n", get_ip6_addr_u16_blk(dest),
                 IP6_ADDR_BLOCK2(dest), IP6_ADDR_BLOCK3(dest), IP6_ADDR_BLOCK4(dest),
                 IP6_ADDR_BLOCK5(dest), IP6_ADDR_BLOCK6(dest), IP6_ADDR_BLOCK7(dest),
                 IP6_ADDR_BLOCK8(dest));
        return STATUS_E_ROUTING;
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
    // if (pbuf_add_header(p, sizeof(struct Ip6HopByHopHdr) + hlen)) {
    //     Logf(true, ("ip6_options: no space for options header\n"));
    //     return ERR_BUF;
    // } /* Set fields of Hop-by-Hop header */
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
    return STATUS_SUCCESS;
}
//
// END OF FILE
//
