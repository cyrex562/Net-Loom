/**
 * @file
 *
 * IPv6 version of ICMP, as per RFC 4443.
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
#include <opt.h>
#include <icmp6.h>
#include <ip6.h>
#include <ip6_addr.h>
#include <inet_chksum.h>
#include <packet_buffer.h>
#include <netif.h>
#include <nd6.h>
#include <ip.h>
#include <cstring>

/* Forward declarations */
static void icmp6_send_response(struct PacketBuffer* p,
                                uint8_t code,
                                uint32_t data,
                                uint8_t type);
static void icmp6_send_response_with_addrs(struct PacketBuffer* p,
                                           uint8_t code,
                                           uint32_t data,
                                           uint8_t type,
                                           const Ip6Addr* src_addr,
                                           const Ip6Addr* dest_addr);
static void icmp6_send_response_with_addrs_and_netif(struct PacketBuffer* p,
                                                     uint8_t code,
                                                     uint32_t data,
                                                     uint8_t type,
                                                     const Ip6Addr* src_addr,
                                                     const Ip6Addr* dest_addr,
                                                     NetIfc* netif); /**
 * Process an input ICMPv6 message. Called by ip6_input.
 *
 * Will generate a reply for echo requests. Other messages are forwarded
 * to nd6_input, or mld6_input.
 *
 * @param p the mld packet, p->payload pointing to the icmpv6 header
 * @param inp the netif on which this packet was received
 */
void icmp6_input(struct PacketBuffer* p, NetIfc* inp)
{
    struct PacketBuffer* r;
    const Ip6Addr* reply_src; /* Check that ICMPv6 header fits in payload */
    if (p->len < sizeof(struct Icmp6Hdr))
    {
        /* drop short packets */
        pbuf_free(p);
        return;
    }
    struct Icmp6Hdr* icmp6hdr = (struct Icmp6Hdr *)p->payload;
    is_netif_checksum_enabled(inp, NETIF_CHECKSUM_CHECK_ICMP6)
    {
        if (ip6_chksum_pseudo(p,
                              IP6_NEXTH_ICMP6,
                              p->tot_len,
                              ip6_current_src_addr(),
                              ip6_current_dest_addr()) != 0)
        {
            /* Checksum failed */
            pbuf_free(p);
            return;
        }
    }

    switch (icmp6hdr->type)
    {
    case ICMP6_TYPE_NA: /* Neighbor advertisement */ case ICMP6_TYPE_NS:
        /* Neighbor solicitation */ case ICMP6_TYPE_RA: /* Router advertisement */ case
    ICMP6_TYPE_RD: /* Redirect */ case ICMP6_TYPE_PTB: /* Packet too big */
        nd6_input(p, inp);
        return;
    case ICMP6_TYPE_RS:

        /* @todo implement router functionality */

        break;

  case ICMP6_TYPE_MLQ:
  case ICMP6_TYPE_MLR:
  case ICMP6_TYPE_MLD:
    mld6_input(p, inp);
    return;

    case ICMP6_TYPE_EREQ:

        /* multicast destination address? */ if (ip6_addr_ismulticast(
            ip6_current_dest_addr()))
        {
            /* drop */
            pbuf_free(p);
            return;
        }

        /* Allocate reply. */
        r = pbuf_alloc(PBUF_IP, p->tot_len, PBUF_RAM);
        if (r == nullptr)
        {
            /* drop */
            pbuf_free(p);
            return;
        } /* Copy echo request. */
        if (pbuf_copy(r, p) != ERR_OK)
        {
            /* drop */
            pbuf_free(p);
            pbuf_free(r);
            return;
        } /* Determine reply source IPv6 address. */

    if (ip6_addr_ismulticast(ip6_current_dest_addr())) {
      reply_src = ip_2_ip6(ip6_select_source_address(inp, ip6_current_src_addr()));
      if (reply_src == nullptr) {
        /* drop */
        pbuf_free(p);
        pbuf_free(r);
        
        return;
      }
    }
    else

        {
            reply_src = ip6_current_dest_addr();
        } /* Set fields in reply. */
        ((struct Icmp6EchoHdr *)(r->payload))->type = ICMP6_TYPE_EREP;
        ((struct Icmp6EchoHdr *)(r->payload))->chksum = 0;

        is_netif_checksum_enabled(inp, NETIF_CHECKSUM_GEN_ICMP6)
        {
            ((struct Icmp6EchoHdr *)(r->payload))->chksum = ip6_chksum_pseudo(r,
                                                                              IP6_NEXTH_ICMP6,
                                                                              r->tot_len,
                                                                              reply_src,
                                                                              ip6_current_src_addr());
        }

        /* Send reply. */
        ip6_output_if(r,
                      reply_src,
                      ip6_current_src_addr(),
                      LWIP_ICMP6_HL,
                      0,
                      IP6_NEXTH_ICMP6,
                      inp);
        pbuf_free(r);
        break;
    default:
        break;
    }
    pbuf_free(p);
} /**
 * Send an icmpv6 'destination unreachable' packet.
 *
 * This function must be used only in direct response to a packet that is being
 * received right now. Otherwise, address zones would be lost.
 *
 * @param p the input packet for which the 'unreachable' should be sent,
 *          p->payload pointing to the IPv6 header
 * @param c ICMPv6 code for the unreachable type
 */
void icmp6_dest_unreach(struct PacketBuffer* p, enum icmp6_dur_code c)
{
    icmp6_send_response(p, c, 0, ICMP6_TYPE_DUR);
} /**
 * Send an icmpv6 'packet too big' packet.
 *
 * This function must be used only in direct response to a packet that is being
 * received right now. Otherwise, address zones would be lost.
 *
 * @param p the input packet for which the 'packet too big' should be sent,
 *          p->payload pointing to the IPv6 header
 * @param mtu the maximum mtu that we can accept
 */
void icmp6_packet_too_big(struct PacketBuffer* p, uint32_t mtu)
{
    icmp6_send_response(p, 0, mtu, ICMP6_TYPE_PTB);
} /**
 * Send an icmpv6 'time exceeded' packet.
 *
 * This function must be used only in direct response to a packet that is being
 * received right now. Otherwise, address zones would be lost.
 *
 * @param p the input packet for which the 'time exceeded' should be sent,
 *          p->payload pointing to the IPv6 header
 * @param c ICMPv6 code for the time exceeded type
 */
void icmp6_time_exceeded(struct PacketBuffer* p, enum Icmp6TeCode c)
{
    icmp6_send_response(p, c, 0, ICMP6_TYPE_TE);
} /**
 * Send an icmpv6 'time exceeded' packet, with explicit source and destination
 * addresses.
 *
 * This function may be used to send a response sometime after receiving the
 * packet for which this response is meant. The provided source and destination
 * addresses are used primarily to retain their zone information.
 *
 * @param p the input packet for which the 'time exceeded' should be sent,
 *          p->payload pointing to the IPv6 header
 * @param c ICMPv6 code for the time exceeded type
 * @param src_addr source address of the original packet, with zone information
 * @param dest_addr destination address of the original packet, with zone
 *                  information
 */
void icmp6_time_exceeded_with_addrs(struct PacketBuffer* p,
                                    enum Icmp6TeCode c,
                                    const Ip6Addr* src_addr,
                                    const Ip6Addr* dest_addr)
{
    icmp6_send_response_with_addrs(p, c, 0, ICMP6_TYPE_TE, src_addr, dest_addr);
} /**
 * Send an icmpv6 'parameter problem' packet.
 *
 * This function must be used only in direct response to a packet that is being
 * received right now. Otherwise, address zones would be lost and the calculated
 * offset would be wrong (calculated against ip6_current_header()).
 *
 * @param p the input packet for which the 'param problem' should be sent,
 *          p->payload pointing to the IP header
 * @param c ICMPv6 code for the param problem type
 * @param pointer the pointer to the byte where the parameter is found
 */
void icmp6_param_problem(struct PacketBuffer* p,
                         enum icmp6_pp_code c,
                         const void* pointer)
{
    uint32_t pointer_u32 = (uint32_t)((const uint8_t *)pointer - (const uint8_t *)
        ip6_current_header());
    icmp6_send_response(p, c, pointer_u32, ICMP6_TYPE_PP);
} /**
 * Send an ICMPv6 packet in response to an incoming packet.
 * The packet is sent *to* ip_current_src_addr() on ip_current_netif().
 *
 * @param p the input packet for which the response should be sent,
 *          p->payload pointing to the IPv6 header
 * @param code Code of the ICMPv6 header
 * @param data Additional 32-bit parameter in the ICMPv6 header
 * @param type Type of the ICMPv6 header
 */
static void icmp6_send_response(struct PacketBuffer* p,
                                uint8_t code,
                                uint32_t data,
                                uint8_t type)
{
    NetIfc* netif = ip_current_netif();
    lwip_assert("icmpv6 packet not a direct response", netif != nullptr);
    const Ip6Addr* reply_dest = ip6_current_src_addr();
    /* Select an address to use as source. */
    Ip6Addr reply_src = ip6_select_source_address(netif, reply_dest)->u_addr.ip6;
    icmp6_send_response_with_addrs_and_netif(p,
                                             code,
                                             data,
                                             type,
                                             &reply_src,
                                             reply_dest,
                                             netif);
} 


/**
 * Send an ICMPv6 packet in response to an incoming packet.
 *
 * Call this function if the packet is NOT sent as a direct response to an
 * incoming packet, but rather sometime later (e.g. for a fragment reassembly
 * timeout). The caller must provide the zoned source and destination addresses
 * from the original packet with the src_addr and dest_addr parameters. The
 * reason for this approach is that while the addresses themselves are part of
 * the original packet, their zone information is not, thus possibly resulting
 * in a link-local response being sent over the wrong link.
 *
 * @param p the input packet for which the response should be sent,
 *          p->payload pointing to the IPv6 header
 * @param code Code of the ICMPv6 header
 * @param data Additional 32-bit parameter in the ICMPv6 header
 * @param type Type of the ICMPv6 header
 * @param src_addr original source address
 * @param dest_addr original destination address
 */
static void icmp6_send_response_with_addrs(struct PacketBuffer* p,
                                           uint8_t code,
                                           uint32_t data,
                                           uint8_t type,
                                           const Ip6Addr* src_addr,
                                           const Ip6Addr* dest_addr)
{
    /* Get the destination address and netif for this ICMP message. */
    lwip_assert("must provide both source and destination", src_addr != nullptr);
    lwip_assert("must provide both source and destination", dest_addr != nullptr);
    /* Special case, as ip6_current_xxx is either NULL, or points
        to a different packet than the one that expired. */
    ip6_addr_zonecheck(src_addr);
    ip6_addr_zonecheck(dest_addr); /* Swap source and destination for the reply. */
    auto reply_dest = src_addr;
    auto reply_src = dest_addr;
    NetIfc* netif = ip6_route(reply_src, reply_dest);
    if (netif == nullptr)
    {
        return;
    }
    icmp6_send_response_with_addrs_and_netif(p,
                                             code,
                                             data,
                                             type,
                                             reply_src,
                                             reply_dest,
                                             netif);
} 


/**
 * Send an ICMPv6 packet (with srd/dst address and netif given).
 *
 * @param p the input packet for which the response should be sent,
 *          p->payload pointing to the IPv6 header
 * @param code Code of the ICMPv6 header
 * @param data Additional 32-bit parameter in the ICMPv6 header
 * @param type Type of the ICMPv6 header
 * @param reply_src source address of the packet to send
 * @param reply_dest destination address of the packet to send
 * @param netif netif to send the packet
 */
static void icmp6_send_response_with_addrs_and_netif(struct PacketBuffer* p,
                                                     uint8_t code,
                                                     uint32_t data,
                                                     uint8_t type,
                                                     const Ip6Addr* reply_src,
                                                     const Ip6Addr* reply_dest,
                                                     NetIfc* netif)
{
    struct PacketBuffer* q;
    struct Icmp6Hdr* icmp6hdr; /* ICMPv6 header + IPv6 header + data */
    q = pbuf_alloc(PBUF_IP,
                   sizeof(struct Icmp6Hdr) + IP6_HDR_LEN + LWIP_ICMP6_DATASIZE,
                   PBUF_RAM);
    if (q == nullptr)
    {
        Logf(ICMP_DEBUG,
             ("icmp_time_exceeded: failed to allocate PacketBuffer for ICMPv6 packet.\n"
             ));
        return;
    }
    lwip_assert("check that first PacketBuffer can hold icmp 6message",
                (q->len >= (sizeof(struct Icmp6Hdr) + IP6_HDR_LEN + LWIP_ICMP6_DATASIZE)));
    icmp6hdr = (struct Icmp6Hdr *)q->payload;
    icmp6hdr->type = type;
    icmp6hdr->code = code;
    icmp6hdr->data = lwip_htonl(data); /* copy fields from original packet */
    SMEMCPY((uint8_t *)q->payload + sizeof(struct Icmp6Hdr),
            (uint8_t *)p->payload,
            IP6_HDR_LEN + LWIP_ICMP6_DATASIZE); /* calculate checksum */
    icmp6hdr->chksum = 0;

    is_netif_checksum_enabled(netif, NETIF_CHECKSUM_GEN_ICMP6)
    {
        icmp6hdr->chksum = ip6_chksum_pseudo(q,
                                             IP6_NEXTH_ICMP6,
                                             q->tot_len,
                                             reply_src,
                                             reply_dest);
    }

    ip6_output_if(q, reply_src, reply_dest, LWIP_ICMP6_HL, 0, IP6_NEXTH_ICMP6, netif);
    pbuf_free(q);
}
