/**
 * @file
 * IPv4 API
 */

/*
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
 */
#pragma once
#include "packet_buffer.h"
#include "ip4_addr.h"
#include "lwip_error.h"
#include "netif.h"
#include "arch.h"


 /** This is the packed version of Ip4Addr,
     used in network headers that are itself packed */


struct Ip4AddrPacked {
    uint32_t addr;
} ;


typedef struct Ip4AddrPacked Ip4AddrPT;

/* Size of the IPv4 header. Same as 'sizeof(struct Ip4Hdr)'. */
constexpr auto IP_HLEN = 20;
/* Maximum size of the IPv4 header with options. */
constexpr auto IP_HLEN_MAX = 60;

constexpr auto IP_RF = 0x8000U        /* reserved fragment flag */;
constexpr auto IP_DF = 0x4000U        /* don't fragment flag */;
#define IP_MF 0x2000U        /* more fragments flag */
#define IP_OFFMASK 0x1fffU   /* mask for fragmenting bits */

/* The IPv4 header */
struct Ip4Hdr
{
    /* version / header length */
    uint8_t _v_hl; /* type of service */
    uint8_t _tos; /* total length */
    uint16_t _len; /* identification */
    int16_t _id; /* fragment offset field */
    uint16_t _offset; /* time to live */
    uint8_t _ttl; /* protocol*/
    uint8_t _proto; /* checksum */
    uint16_t _chksum; /* source and destination IP addresses */
    Ip4Addr src;
    Ip4Addr dest;
};

/* Macros to get struct Ip4Hdr fields: */
#define IPH_V(hdr)  ((hdr)->_v_hl >> 4)
#define IPH_HL(hdr) ((hdr)->_v_hl & 0x0f)
#define IPH_HL_BYTES(hdr) ((uint8_t)(IPH_HL(hdr) * 4))
#define IPH_TOS(hdr) ((hdr)->_tos)
#define IPH_LEN(hdr) ((hdr)->_len)
#define IPH_ID(hdr) ((hdr)->_id)
#define IPH_OFFSET(hdr) ((hdr)->_offset)
#define IPH_OFFSET_BYTES(hdr) ((uint16_t)((lwip_ntohs(IPH_OFFSET(hdr)) & IP_OFFMASK) * 8U))
#define IPH_TTL(hdr) ((hdr)->_ttl)
#define IPH_PROTO(hdr) ((hdr)->_proto)
#define IPH_CHKSUM(hdr) ((hdr)->_chksum)

/* Macros to set struct Ip4Hdr fields: */
#define IPH_VHL_SET(hdr, v, hl) (hdr)->_v_hl = (uint8_t)((((v) << 4) | (hl)))
#define IPH_TOS_SET(hdr, tos) (hdr)->_tos = (tos)
#define IPH_LEN_SET(hdr, len) (hdr)->_len = (len)
#define IPH_ID_SET(hdr, id) (hdr)->_id = (id)
#define IPH_OFFSET_SET(hdr, off) (hdr)->_offset = (off)
#define IPH_TTL_SET(hdr, ttl) (hdr)->_ttl = (uint8_t)(ttl)
#define IPH_PROTO_SET(hdr, proto) (hdr)->_proto = (uint8_t)(proto)
#define IPH_CHKSUM_SET(hdr, chksum) (hdr)->_chksum = (chksum)



#ifdef __cplusplus
extern "C" {
#endif

constexpr auto kLwipIpv4SrcRouting = 1;


/** Currently, the function ip_output_if_opt() is only used with IGMP */
#define IP_OPTIONS_SEND   (LWIP_IPV4 && LWIP_IGMP)

#define ip_init() /* Compatibility define, no init needed. */
NetIfc*ip4_route(const Ip4Addr *dest);

NetIfc*ip4_route_src(const Ip4Addr *src, const Ip4Addr *dest);

LwipError ip4_input(struct PacketBuffer *p, NetIfc*inp);
LwipError ip4_output(struct PacketBuffer *p, const Ip4Addr *src, const Ip4Addr *dest,
       uint8_t ttl, uint8_t tos, uint8_t proto);
LwipError ip4_output_if(struct PacketBuffer *p, const Ip4Addr *src, const Ip4Addr *dest,
       uint8_t ttl, uint8_t tos, uint8_t proto, NetIfc*netif);
LwipError ip4_output_if_src(struct PacketBuffer *p, const Ip4Addr *src, const Ip4Addr *dest,
       uint8_t ttl, uint8_t tos, uint8_t proto, NetIfc*netif);

LwipError ip4_output_hinted(struct PacketBuffer *p, const Ip4Addr *src, const Ip4Addr *dest,
       uint8_t ttl, uint8_t tos, uint8_t proto, NetIfc*cHint *netif_hint);


LwipError ip4_output_if_opt(struct PacketBuffer *p, const Ip4Addr *src, const Ip4Addr *dest,
       uint8_t ttl, uint8_t tos, uint8_t proto, NetIfc*netif, void *ip_options,
       uint16_t optlen);
LwipError ip4_output_if_opt_src(struct PacketBuffer *p, const Ip4Addr *src, const Ip4Addr *dest,
       uint8_t ttl, uint8_t tos, uint8_t proto, NetIfc*netif, void *ip_options,
       uint16_t optlen);

void  ip4_set_default_multicast_netif(NetIfc** default_multicast_netif);


#define ip4_netif_get_local_ip(netif) (((netif) != NULL) ? netif_ip_addr4(netif) : NULL)


void ip4_debug_print(struct PacketBuffer *p);


#ifdef __cplusplus
}
#endif


