/**
 * @file
 *
 * IPv6 layer.
 */

/*
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
#pragma once

#include <opt.h>
#include <ip6_addr.h>
#include <def.h>
#include <packet_buffer.h>
#include <netif.h>
#include <lwip_status.h>


 /** This is the packed version of Ip6Addr,
     used in network headers that are itself packed */



constexpr auto IP6_HDR_LEN = 40;

enum Ip6NextHdr
{
    IP6_NEXTH_HOPBYHOP = 0,
    IP6_NEXTH_TCP =6,
    IP6_NEXTH_UDP =17,
    IP6_NEXTH_ENCAPS =41,
    IP6_NEXTH_ROUTING =43,
    IP6_NEXTH_FRAGMENT =44,
    IP6_NEXTH_ICMP6 =58,
    IP6_NEXTH_NONE =59,
    IP6_NEXTH_DESTOPTS =60,
    IP6_NEXTH_UDPLITE =136,
};


/** The IPv6 header. */



struct Ip6Hdr {
    /** version / traffic class / flow label */
    uint32_t _v_tc_fl;
    /** payload length */
    uint16_t _plen;
    /** next header */
    uint8_t _nexth;
    /** hop limit */
    uint8_t _hoplim;
    /** source and destination IP addresses */
    Ip6AddrWireFmt src;
    Ip6AddrWireFmt dest;
} ;

inline uint32_t get_ip6_hdr_v(Ip6Hdr* hdr)
{
    return ((lwip_ntohl((hdr)->_v_tc_fl) >> 28) & 0x0f);
}

inline uint32_t get_ip6_hdr_tc(Ip6Hdr* hdr)
{
    return ((lwip_ntohl((hdr)->_v_tc_fl) >> 20) & 0xff);
}

inline uint32_t IP6H_FL(Ip6Hdr* hdr)
{
    return (lwip_ntohl((hdr)->_v_tc_fl) & 0x000fffff);
}

inline uint16_t IP6H_PLEN(Ip6Hdr* hdr)
{
    return (lwip_ntohs((hdr)->_plen));
}

inline uint8_t IP6H_NEXTH(Ip6Hdr* hdr)
{
    return ((hdr)->_nexth);
}

inline uint8_t* IP6H_NEXTH_P(Ip6Hdr* hdr)
{
    return (reinterpret_cast<uint8_t *>(hdr) + 6);
}

inline uint8_t IP6H_HOPLIM(Ip6Hdr* hdr)
{
    return ((hdr)->_hoplim);
}

inline void get_ip6_hdr_vTCFL_SET(Ip6Hdr* hdr, uint32_t v, uint32_t tc, uint32_t fl)
{
    (hdr)->_v_tc_fl = (lwip_htonl(
        (((uint32_t)(v)) << 28) | (((uint32_t)(tc)) << 20) | (fl)));
}

inline void IP6H_PLEN_SET(Ip6Hdr* hdr, uint32_t plen)
{
    (hdr)->_plen = lwip_htons(plen);
}

inline void IP6H_NEXTH_SET(Ip6Hdr* hdr, uint8_t nexth){ (hdr)->_nexth = (nexth);}

inline uint8_t IP6H_HOPLIM_SET(Ip6Hdr* hdr, uint8_t hl)
{
    (hdr)->_hoplim = (uint8_t)(hl);
}

/* ipv6 extended options header */
#define IP6_PAD1_OPTION             0

#define IP6_PADN_OPTION             1

#define IP6_ROUTER_ALERT_OPTION     5

#define IP6_JUMBO_OPTION            194

#define IP6_HOME_ADDRESS_OPTION     201

#define IP6_ROUTER_ALERT_DLEN       2
#define IP6_ROUTER_ALERT_VALUE_MLD  0

struct ip6_opt_hdr {
    /* router alert option type */
    uint8_t _opt_type;
    /* router alert option data len */
    int8_t _opt_dlen;
} ;

#define IP6_OPT_HLEN 2
#define IP6_OPT_TYPE_ACTION(hdr) ((((hdr)->_opt_type) >> 6) & 0x3)
#define IP6_OPT_TYPE_CHANGE(hdr) ((((hdr)->_opt_type) >> 5) & 0x1)
#define IP6_OPT_TYPE(hdr) ((hdr)->_opt_type)
#define IP6_OPT_DLEN(hdr) ((hdr)->_opt_dlen)

/* Hop-by-Hop header. */
#define IP6_HBH_HLEN    2

struct ip6_hbh_hdr {
    /* next header */
    uint8_t _nexth;
    /* header length in 8-octet units */
    uint8_t _hlen;
} ;

#define IP6_HBH_NEXTH(hdr) ((hdr)->_nexth)

/* Destination header. */
#define IP6_DEST_HLEN   2

struct ip6_dest_hdr {
    /* next header */
    uint8_t _nexth;
    /* header length in 8-octet units */
    uint8_t _hlen;
} ;
#define IP6_DEST_NEXTH(hdr) ((hdr)->_nexth)

/* Routing header */
#define IP6_ROUT_TYPE2  2
#define IP6_ROUT_RPL    3

struct ip6_rout_hdr {
    /* next header */
    uint8_t _next;
    /* reserved */
    uint8_t _hlen;
    /* fragment offset */
    uint8_t _routing_type;
    /* fragmented packet identification */
    uint8_t _segments_left;
} ;
#define IP6_ROUT_NEXTH(hdr) ((hdr)->_nexth)
#define IP6_ROUT_TYPE(hdr) ((hdr)->_routing_type)
#define IP6_ROUT_SEG_LEFT(hdr) ((hdr)->_segments_left)

/* Fragment header. */
#define IP6_FRAG_HLEN    8
#define IP6_FRAG_OFFSET_MASK    0xfff8
#define IP6_FRAG_MORE_FLAG      0x0001

struct Ip6FragHdr
{
    /* next header */
    uint8_t _nexth; /* reserved */
    uint8_t reserved; /* fragment offset */
    uint16_t _fragment_offset; /* fragmented packet identification */
    uint32_t _identification;
};

#define IP6_FRAG_NEXTH(hdr) ((hdr)->_nexth)
#define IP6_FRAG_MBIT(hdr) (lwip_ntohs((hdr)->_fragment_offset) & 0x1)
#define IP6_FRAG_ID(hdr) (lwip_ntohl((hdr)->_identification))


//#if LWIP_IPV6  /* don't build if not configured for use in lwipopts.h */


NetIfc*ip6_route(const Ip6Addr *src, const Ip6Addr *dest);


LwipStatus         ip6_input(struct PacketBuffer *p, NetIfc* inp);
LwipStatus         ip6_output(struct PacketBuffer *p, const Ip6Addr *src, const Ip6Addr *dest,
                         uint8_t hl, uint8_t tc, uint8_t nexth);
LwipStatus         ip6_output_if(struct PacketBuffer *p, const Ip6Addr *src, const Ip6Addr *dest,
                            uint8_t hl, uint8_t tc, uint8_t nexth, NetIfc*netif);
LwipStatus         ip6_output_if_src(struct PacketBuffer *pbuf,
                                     Ip6Addr* src,
                                     const Ip6Addr *dest,
                                     uint8_t hl,
                                     uint8_t tc,
                                     uint8_t nexth,
                                     NetIfc*netif);

LwipStatus         ip6_output_hinted(struct PacketBuffer *p, const Ip6Addr *src, const Ip6Addr *dest);

LwipStatus         ip6_options_add_hbh_ra(struct PacketBuffer * p, uint8_t nexth, uint8_t value);



#define true_print(p)

inline void ip6_addr_select_zone(Ip6Addr* dest, Ip6Addr* src)
{
    const auto selected_netif = ip6_route((src), (dest));
    if (selected_netif != nullptr)
    {
        ip6_addr_assign_zone((dest), IP6_UNKNOWN, selected_netif);
    }
}