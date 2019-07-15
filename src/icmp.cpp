/**
 * @file
 * ICMP - Internet Control Message Protocol
 *
 */ /*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
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
 * Author: Adam Dunkels <adam@sics.se>
 *
 */ /* Some ICMP messages should be passed to the transport protocols. This
   is not implemented. */
#include "opt.h"
// #if LWIP_IPV4 && LWIP_ICMP /* don't build if not configured for use in lwipopts.h */
#include "def.h"
#include "icmp.h"
#include "inet_chksum.h"
#include "ip.h"
#include "lwip_debug.h"
#include <cstring>
constexpr auto kIcmpDestUnreachDatasize = 8; /**
 * Processes ICMP input packets, called from ip_input().
 *
 * Currently only processes icmp echo requests and sends
 * out the echo response.
 *
 * @param p the icmp echo request packet, p->payload pointing to the icmp header
 * @param inp the netif on which this packet was received
 */
void icmp_input(struct PacketBuffer* p, NetIfc* inp)
{
    uint8_t type;
    uint8_t code;
    struct IcmpEchoHdr* iecho;
    const Ip4Addr* src;
    const struct Ip4Hdr* iphdr_in = ip4_current_header();
    uint16_t hlen = IPH_HL_BYTES(iphdr_in);
    if (hlen < kIp4HdrLen)
    {
        //    Logf(ICMP_DEBUG, ("icmp_input: short IP header (%"S16_F" bytes) received\n", hlen));
        goto lenerr;
    }
    if (p->len < sizeof(uint16_t) * 2)
    {
        //    Logf(ICMP_DEBUG, ("icmp_input: short ICMP (%"U16_F" bytes) received\n", p->tot_len));
        goto lenerr;
    }
    type = *static_cast<uint8_t *>(p->payload);
#ifdef LWIP_DEBUG
  code = *(((uint8_t *)p->payload) + 1);
  /* if debug is enabled but debug statement below is somehow disabled: */
  ;
#endif /* LWIP_DEBUG */
    switch (type)
    {
    case ICMP_ER: /* This is OK, echo reply might have been parsed by a raw PCB
         (as obviously, an echo request has been sent, too). */ break;
    case ICMP_ECHO:
        src = ip4_current_dest_addr(); /* multicast destination address? */
        if (ip4_addr_ismulticast(ip4_current_dest_addr()))
        {
            /* For multicast, use address of receiving interface as source address */
            src = get_net_ifc_ip4_addr(inp);
        } /* broadcast destination address? */
        if (ip4_addr_isbroadcast(ip4_current_dest_addr(), ip_current_netif()))
        {
            /* For broadcast, use address of receiving interface as source address */
            src = get_net_ifc_ip4_addr(inp);
        }
        Logf(ICMP_DEBUG, ("icmp_input: ping\n"));
        if (p->tot_len < sizeof(struct IcmpEchoHdr))
        {
            Logf(ICMP_DEBUG, ("icmp_input: bad ICMP echo received\n"));
            goto lenerr;
        }
        IfNetifChecksumEnabled(inp, NETIF_CHECKSUM_CHECK_ICMP)
        {
            if (inet_chksum_pbuf(p) != 0)
            {
                Logf(ICMP_DEBUG,
                     ("icmp_input: checksum failed for received ICMP echo\n"));
                pbuf_free(p);
                return;
            }
        }
        if (pbuf_add_header(p, hlen + PBUF_LINK_HLEN + PBUF_LINK_ENCAPSULATION_HLEN))
        {
            /* p is not big enough to contain link headers
             * allocate a new one and copy p into it
             */
            struct PacketBuffer* r;
            uint16_t alloc_len = (uint16_t)(p->tot_len + hlen);
            if (alloc_len < p->tot_len)
            {
                Logf(ICMP_DEBUG,
                     ("icmp_input: allocating new PacketBuffer failed (tot_len overflow)\n"
                     ));
                goto icmperr;
            } /* allocate new packet buffer with space for link headers */
            r = pbuf_alloc(PBUF_LINK, alloc_len, PBUF_RAM);
            if (r == nullptr)
            {
                Logf(ICMP_DEBUG, ("icmp_input: allocating new PacketBuffer failed\n"));
                goto icmperr;
            }
            if (r->len < hlen + sizeof(struct IcmpEchoHdr))
            {
                Logf(ICMP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                     ("first PacketBuffer cannot hold the ICMP header"));
                pbuf_free(r);
                goto icmperr;
            } /* copy the ip header */
            MEMCPY(r->payload, iphdr_in, hlen);
            /* switch r->payload back to icmp header (cannot fail) */
            if (pbuf_remove_header(r, hlen))
            {
                lwip_assert("icmp_input: moving r->payload to icmp header failed\n", 0);
                pbuf_free(r);
                goto icmperr;
            } /* copy the rest of the packet without ip header */
            if (pbuf_copy(r, p) != ERR_OK)
            {
                Logf(ICMP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                     ("icmp_input: copying to new PacketBuffer failed"));
                pbuf_free(r);
                goto icmperr;
            } /* free the original p */
            pbuf_free(p);
            /* we now have an identical copy of p that has room for link headers */
            p = r;
        }
        else
        {
            /* restore p->payload to point to icmp header (cannot fail) */
            if (pbuf_remove_header(p,
                                   hlen + PBUF_LINK_HLEN + PBUF_LINK_ENCAPSULATION_HLEN))
            {
                lwip_assert("icmp_input: restoring original p->payload failed\n", 0);
                goto icmperr;
            }
        } /* At this point, all checks are OK. */
        /* We generate an answer by switching the dest and src ip addresses,
              * setting the icmp type to ECHO_RESPONSE and updating the checksum. */
        iecho = static_cast<struct IcmpEchoHdr *>(p->payload);
        if (pbuf_add_header(p, hlen))
        {
            Logf(ICMP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                 ("Can't move over header in packet"));
        }
        else
        {
            auto iphdr = static_cast<struct Ip4Hdr *>(p->payload);
            copy_ip4_addr(&iphdr->src, src);
            copy_ip4_addr(&iphdr->dest, ip4_current_src_addr());
            IcmphTypeSet(iecho, ICMP_ER);
            IfNetifChecksumEnabled(inp, NETIF_CHECKSUM_GEN_ICMP)
            {
                /* adjust the checksum */
                if (iecho->chksum > PpHtons(0xffffU - (ICMP_ECHO << 8)))
                {
                    iecho->chksum = uint16_t(iecho->chksum + PpHtons(uint16_t(ICMP_ECHO << 8)) + 1);
                }
                else
                {
                    iecho->chksum = uint16_t(iecho->chksum + PpHtons(ICMP_ECHO << 8));
                }
            }
            else
            {
                iecho->chksum = 0;
            } /* Set the correct TTL and recalculate the header checksum. */
            IPH_TTL_SET(iphdr, ICMP_TTL);
            IPH_CHKSUM_SET(iphdr, 0);
            IfNetifChecksumEnabled(inp, NETIF_CHECKSUM_GEN_IP)
            {
                IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, hlen));
            } /* increase number of messages attempted to send */
            /* increase number of echo replies attempted to send */
            /* send an ICMP packet */
            const auto ret = ip4_output_if(p, src, nullptr, ICMP_TTL, 0, IP_PROTO_ICMP, inp);
            if (ret != ERR_OK)
            {
                Logf(ICMP_DEBUG,
                     ("icmp_input: ip_output_if returned an error: %s\n", lwip_strerr(ret)
                     ));
            }
        }
        break;
    default:
        if (type == ICMP_DUR)
        {
        }
        else if (type == ICMP_TE)
        {
        }
        else if (type == ICMP_PP)
        {
        }
        else if (type == ICMP_SQ)
        {
        }
        else if (type == ICMP_RD)
        {
        }
        else if (type == ICMP_TS)
        {
        }
        else if (type == ICMP_TSR)
        {
        }
        else if (type == ICMP_AM)
        {
        }
        else if (type == ICMP_AMR)
        {
        } //      Logf(ICMP_DEBUG, ("icmp_input: ICMP type %"S16_F" code %"S16_F" not supported.\n",
        //                               (int16_t)type, (int16_t)code));
    }
    pbuf_free(p);
    return;
lenerr: pbuf_free(p);
    return;
#if LWIP_ICMP_ECHO_CHECK_INPUT_PBUF_LEN || !LWIP_MULTICAST_PING || !LWIP_BROADCAST_PING
icmperr: pbuf_free(p);
    return;
#endif /* LWIP_ICMP_ECHO_CHECK_INPUT_PBUF_LEN || !LWIP_MULTICAST_PING || !LWIP_BROADCAST_PING */
} /**
 * Send an icmp 'destination unreachable' packet, called from ip_input() if
 * the transport layer protocol is unknown and from udp_input() if the local
 * port is not bound.
 *
 * @param p the input packet for which the 'unreachable' should be sent,
 *          p->payload pointing to the IP header
 * @param t type of the 'unreachable' packet
 */
void icmp_dest_unreach(struct PacketBuffer* p, enum icmp_dur_type t)
{
    icmp_send_response(p, ICMP_DUR, t);
} /**
 * Send a 'time exceeded' packet, called from ip_forward() if TTL is 0.
 *
 * @param p the input packet for which the 'time exceeded' should be sent,
 *          p->payload pointing to the IP header
 * @param t type of the 'time exceeded' packet
 */
void icmp_time_exceeded(struct PacketBuffer* p, enum icmp_te_type t)
{
    icmp_send_response(p, ICMP_TE, t);
} /**
 * Send an icmp packet in response to an incoming packet.
 *
 * @param p the input packet for which the 'unreachable' should be sent,
 *          p->payload pointing to the IP header
 * @param type Type of the ICMP header
 * @param code Code of the ICMP header
 */
static void icmp_send_response(struct PacketBuffer* p, uint8_t type, uint8_t code)
{
    struct PacketBuffer* q;
    struct Ip4Hdr* iphdr; /* we can use the echo header here */
    struct IcmpEchoHdr* icmphdr;
    Ip4Addr iphdr_src;
    NetIfc* netif; /* increase number of messages attempted to send */
    /* ICMP header + IP header + 8 bytes of data */
    q = pbuf_alloc(PBUF_IP,
                   sizeof(struct IcmpEchoHdr) + kIp4HdrLen + kIcmpDestUnreachDatasize,
                   PBUF_RAM);
    if (q == nullptr)
    {
        Logf(ICMP_DEBUG,
             ("icmp_time_exceeded: failed to allocate PacketBuffer for ICMP packet.\n"));
        return;
    }
    lwip_assert("check that first PacketBuffer can hold icmp message",
                (q->len >= (sizeof(struct IcmpEchoHdr) + kIp4HdrLen +
                    kIcmpDestUnreachDatasize)));
    iphdr = (struct Ip4Hdr *)p->payload;
    Logf(ICMP_DEBUG, ("icmp_time_exceeded from "));

    Logf(ICMP_DEBUG, (" to "));
    Logf(ICMP_DEBUG, ("\n"));
    icmphdr = (struct IcmpEchoHdr *)q->payload;
    icmphdr->type = type;
    icmphdr->code = code;
    icmphdr->id = 0;
    icmphdr->seqno = 0; /* copy fields from original packet */
    SMEMCPY((uint8_t *)q->payload + sizeof(struct IcmpEchoHdr),
            (uint8_t *)p->payload,
            kIp4HdrLen + kIcmpDestUnreachDatasize);
    copy_ip4_addr(&iphdr_src, &iphdr->src);
    netif = ip4_route(&iphdr_src);
    if (netif != nullptr)
    {
        /* calculate checksum */
        icmphdr->chksum = 0;
        IfNetifChecksumEnabled(netif, NETIF_CHECKSUM_GEN_ICMP)
        {
            icmphdr->chksum = inet_chksum(icmphdr, q->len);
        }
        ip4_output_if(q, nullptr, &iphdr_src, ICMP_TTL, 0, IP_PROTO_ICMP, netif);
    }
    pbuf_free(q);
}
