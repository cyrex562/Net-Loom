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

#include "ns_config.h"
#include "ns_ip6_addr.h"
#include "ns_def.h"
#include "ns_packet.h"
#include "ns_network_interface.h"
#include "ns_status.h"
#include "ns_util.h"


/** This is the packed version of Ip6Address,
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
    Ip6Addr src;
    Ip6Addr dest;
} ;


inline uint32_t
get_ip6_hdr_v(Ip6Hdr* hdr)
{
    return ((ns_ntohl((hdr)->_v_tc_fl) >> 28) & 0x0f);
}

inline uint32_t get_ip6_hdr_tc(Ip6Hdr& hdr)
{
    return ((ns_ntohl((hdr)._v_tc_fl) >> 20) & 0xff);
}

inline uint32_t IP6H_FL(Ip6Hdr* hdr)
{
    return (ns_ntohl((hdr)->_v_tc_fl) & 0x000fffff);
}

inline uint16_t IP6H_PLEN(Ip6Hdr* hdr)
{
    return (ns_ntohs((hdr)->_plen));
}

inline uint8_t get_ip6_hdr_next_hop(Ip6Hdr& hdr)
{
    return hdr._nexth;
}

inline uint8_t* IP6H_NEXTH_P(Ip6Hdr* hdr)
{
    return (reinterpret_cast<uint8_t *>(hdr) + 6);
}


inline uint8_t
get_ip6_hdr_hop_limit(Ip6Hdr& hdr)
{
    return hdr._hoplim;
}

inline void get_ip6_hdr_vTCFL_SET(Ip6Hdr* hdr, uint32_t v, uint32_t tc, uint32_t fl)
{
    (hdr)->_v_tc_fl = (lwip_htonl(
        (((uint32_t)(v)) << 28) | (((uint32_t)(tc)) << 20) | (fl)));
}

inline void set_ip6_hdr_plen(Ip6Hdr* hdr, uint32_t plen)
{
    (hdr)->_plen = ns_htons(plen);
}

inline void IP6H_NEXTH_SET(Ip6Hdr* hdr, uint8_t nexth){ (hdr)->_nexth = (nexth);}

inline void set_ip6_hdr_hop_limit(Ip6Hdr& hdr, const uint8_t hop_limit)
{
    hdr._hoplim = hop_limit;
}


/* ipv6 extended options header */
enum Ipv6ExtOpts
{
    IP6_PAD1_OPTION =0,

    IP6_PADN_OPTION =1,

    IP6_ROUTER_ALERT_OPTION =5,

    IP6_JUMBO_OPTION =194,

    IP6_HOME_ADDRESS_OPTION =201,
};


constexpr auto IP6_ROUTER_ALERT_DLEN = 2;
constexpr auto IP6_ROUTER_ALERT_VALUE_MLD = 0;

struct Ip6OptionHdr {
    /* router alert option type */
    uint8_t _opt_type;
    /* router alert option data len */
    int8_t _opt_dlen;
} ;

constexpr auto IP6_OPT_HLEN = 2;


inline uint8_t
IP6_OPT_TYPE_ACTION(Ip6OptionHdr* hdr)
{
    return ((((hdr)->_opt_type) >> 6) & 0x3);
}


inline uint8_t
IP6_OPT_TYPE_CHANGE(Ip6OptionHdr* hdr)
{
    return ((((hdr)->_opt_type) >> 5) & 0x1);
}


inline uint8_t
IP6_OPT_TYPE(Ip6OptionHdr* hdr)
{
    return ((hdr)->_opt_type);
}


inline int8_t
IP6_OPT_DLEN(Ip6OptionHdr* hdr)
{
    return ((hdr)->_opt_dlen);
}

/* Hop-by-Hop header. */
constexpr auto IP6_HBH_HLEN = 2;

struct Ip6HopByHopHdr {
    /* next header */
    uint8_t _nexth;
    /* header length in 8-octet units */
    uint8_t _hlen;
} ;

inline uint8_t IP6_HBH_NEXTH(Ip6HopByHopHdr* hdr){return ((hdr)->_nexth);}

/* Destination header. */
constexpr auto IP6_DEST_HLEN  = 2;

struct Ip6DestHdr {
    /* next header */
    uint8_t _nexth;
    /* header length in 8-octet units */
    uint8_t _hlen;
} ;
inline uint8_t IP6_DEST_NEXTH(Ip6DestHdr* hdr){return ((hdr)->_nexth);}

/* Routing header */
constexpr auto IP6_ROUT_TYPE2 = 2;
constexpr auto IP6_ROUT_RPL = 3;

struct Ip6RouteHdr {
    /* next header */
    uint8_t _next;
    /* reserved */
    uint8_t _hlen;
    /* fragment offset */
    uint8_t _routing_type;
    /* fragmented packet identification */
    uint8_t _segments_left;
} ;


inline uint8_t
get_ip6_route_hdr_nexth(Ip6RouteHdr* hdr)
{
    return ((hdr)->_next);
}


inline uint8_t
get_ip6_route_hdr_type(Ip6RouteHdr* hdr)
{
    return ((hdr)->_routing_type);
}


inline uint8_t
get_ip6_route_hdr_seg_left(Ip6RouteHdr* hdr)
{
    return ((hdr)->_segments_left);
}

/* Fragment header. */
// constexpr auto IP6_FRAG_OFFSET_MASK = 8;
constexpr auto IP6_FRAG_OFFSET_MASK = 0xfff8;
constexpr auto IP6_FRAG_MORE_FLAG = 0x0001;

struct Ip6FragHdr
{
    /* next header */
    uint8_t _nexth; /* reserved */
    uint8_t reserved; /* fragment offset */
    uint16_t _fragment_offset; /* fragmented packet identification */
    uint32_t _identification;
};


inline uint8_t
IP6_FRAG_NEXTH(Ip6FragHdr* hdr)
{
    return ((hdr)->_nexth);
}


inline uint8_t
IP6_FRAG_MBIT(Ip6FragHdr* hdr)
{
    return (ns_ntohs((hdr)->_fragment_offset) & 0x1);
}


inline uint32_t
IP6_FRAG_ID(Ip6FragHdr* hdr)
{
    return (ns_ntohl((hdr)->_identification));
}


//#if LWIP_IPV6  /* don't build if not configured for use in lwipopts.h */
NsStatus
route_ip6_packet(const Ip6AddrInfo& src, const Ip6AddrInfo& dest, NetworkInterface& out_netif, std::vector
                 <NetworkInterface> interfaces);


NsStatus         recv_ip6_pkt(PacketContainer& pkt_buf, NetworkInterface& in_netif);
NsStatus         ip6_output(PacketContainer& p,
                              const Ip6AddrInfo& src,
                              const Ip6AddrInfo& dest,
                              uint8_t hl,
                              uint8_t tc,
                              uint8_t nexth);
NsStatus         ip6_output_if(PacketContainer& p,
                                 const Ip6AddrInfo& src,
                                 const Ip6AddrInfo& dest,
                                 uint8_t hl,
                                 uint8_t tc,
                                 uint8_t nexth,
                                 NetworkInterface& netif);
NsStatus         ip6_output_if_src(PacketContainer& pbuf,
                                     Ip6AddrInfo& src,
                                     const Ip6AddrInfo& dest,
                                     uint8_t hl,
                                     uint8_t tc,
                                     uint8_t nexth,
                                     NetworkInterface& netif);


NsStatus         ip6_output_hinted(struct PacketContainer *p, const Ip6Addr *src, const Ip6Addr *dest);


NsStatus         ip6_options_add_hbh_ra(struct PacketContainer * p, uint8_t nexth, uint8_t value);


NsStatus
forward_ip6_packet(PacketContainer& pkt_buf,
                   Ip6Hdr& iphdr,
                   NetworkInterface& in_netif,
                   Ip6AddrInfo& dest_addr,
                   Ip6AddrInfo& src_addr,
                   std::vector<NetworkInterface>& interfaces);


inline NsStatus
select_ip6_addr_zone(Ip6AddrInfo& dest, const Ip6AddrInfo& src, const std::vector<NetworkInterface>& interfaces)
{
    NetworkInterface selected_netif{};
    if(route_ip6_packet((src), (dest), selected_netif, interfaces) == STATUS_SUCCESS) {
        assign_ip6_addr_zone(dest, IP6_UNKNOWN, selected_netif);
        return STATUS_SUCCESS;
    }
    return STATUS_ERROR;
}


bool
check_accept_ip6_pkt(const NetworkInterface& netif, const Ip6AddrInfo& src_addr, const Ip6AddrInfo& dest_addr);


//
// END OF FILE
//