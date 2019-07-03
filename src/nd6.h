/**
 * @file
 *
 * Neighbor discovery and stateless address autoconfiguration for IPv6.
 * Aims to be compliant with RFC 4861 (Neighbor discovery) and RFC 4862
 * (Address autoconfiguration).
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

#ifndef LWIP_HDR_ND6_H
#define LWIP_HDR_ND6_H

#include "opt.h"


 /** Neighbor solicitation message header. */
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct ns_header {
    PACK_STRUCT_FLD_8(uint8_t type);
    PACK_STRUCT_FLD_8(uint8_t code);
    PACK_STRUCT_FIELD(uint16_t chksum);
    PACK_STRUCT_FIELD(uint32_t reserved);
    PACK_STRUCT_FLD_S(ip6_addr_p_t target_address);
    /* Options follow. */
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "epstruct.h"
#endif

/** Neighbor advertisement message header. */
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct na_header {
    PACK_STRUCT_FLD_8(uint8_t type);
    PACK_STRUCT_FLD_8(uint8_t code);
    PACK_STRUCT_FIELD(uint16_t chksum);
    PACK_STRUCT_FLD_8(uint8_t flags);
    PACK_STRUCT_FLD_8(uint8_t reserved[3]);
    PACK_STRUCT_FLD_S(ip6_addr_p_t target_address);
    /* Options follow. */
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "epstruct.h"
#endif
#define ND6_FLAG_ROUTER      (0x80)
#define ND6_FLAG_SOLICITED   (0x40)
#define ND6_FLAG_OVERRIDE    (0x20)

/** Router solicitation message header. */
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct rs_header {
    PACK_STRUCT_FLD_8(uint8_t type);
    PACK_STRUCT_FLD_8(uint8_t code);
    PACK_STRUCT_FIELD(uint16_t chksum);
    PACK_STRUCT_FIELD(uint32_t reserved);
    /* Options follow. */
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "epstruct.h"
#endif

/** Router advertisement message header. */
#define ND6_RA_FLAG_MANAGED_ADDR_CONFIG (0x80)
#define ND6_RA_FLAG_OTHER_CONFIG (0x40)
#define ND6_RA_FLAG_HOME_AGENT (0x20)
#define ND6_RA_PREFERENCE_MASK (0x18)
#define ND6_RA_PREFERENCE_HIGH (0x08)
#define ND6_RA_PREFERENCE_MEDIUM (0x00)
#define ND6_RA_PREFERENCE_LOW (0x18)
#define ND6_RA_PREFERENCE_DISABLED (0x10)
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct ra_header {
    PACK_STRUCT_FLD_8(uint8_t type);
    PACK_STRUCT_FLD_8(uint8_t code);
    PACK_STRUCT_FIELD(uint16_t chksum);
    PACK_STRUCT_FLD_8(uint8_t current_hop_limit);
    PACK_STRUCT_FLD_8(uint8_t flags);
    PACK_STRUCT_FIELD(uint16_t router_lifetime);
    PACK_STRUCT_FIELD(uint32_t reachable_time);
    PACK_STRUCT_FIELD(uint32_t retrans_timer);
    /* Options follow. */
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "epstruct.h"
#endif

/** Redirect message header. */
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct redirect_header {
    PACK_STRUCT_FLD_8(uint8_t type);
    PACK_STRUCT_FLD_8(uint8_t code);
    PACK_STRUCT_FIELD(uint16_t chksum);
    PACK_STRUCT_FIELD(uint32_t reserved);
    PACK_STRUCT_FLD_S(ip6_addr_p_t target_address);
    PACK_STRUCT_FLD_S(ip6_addr_p_t destination_address);
    /* Options follow. */
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "epstruct.h"
#endif

/** Link-layer address option. */
#define ND6_OPTION_TYPE_SOURCE_LLADDR (0x01)
#define ND6_OPTION_TYPE_TARGET_LLADDR (0x02)
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct lladdr_option {
    PACK_STRUCT_FLD_8(uint8_t type);
    PACK_STRUCT_FLD_8(uint8_t length);
    PACK_STRUCT_FLD_8(uint8_t addr[NETIF_MAX_HWADDR_LEN]);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "epstruct.h"
#endif

/** Prefix information option. */
#define ND6_OPTION_TYPE_PREFIX_INFO (0x03)
#define ND6_PREFIX_FLAG_ON_LINK (0x80)
#define ND6_PREFIX_FLAG_AUTONOMOUS (0x40)
#define ND6_PREFIX_FLAG_ROUTER_ADDRESS (0x20)
#define ND6_PREFIX_FLAG_SITE_PREFIX (0x10)
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct prefix_option {
    PACK_STRUCT_FLD_8(uint8_t type);
    PACK_STRUCT_FLD_8(uint8_t length);
    PACK_STRUCT_FLD_8(uint8_t prefix_length);
    PACK_STRUCT_FLD_8(uint8_t flags);
    PACK_STRUCT_FIELD(uint32_t valid_lifetime);
    PACK_STRUCT_FIELD(uint32_t preferred_lifetime);
    PACK_STRUCT_FLD_8(uint8_t reserved2[3]);
    PACK_STRUCT_FLD_8(uint8_t site_prefix_length);
    PACK_STRUCT_FLD_S(ip6_addr_p_t prefix);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "epstruct.h"
#endif

/** Redirected header option. */
#define ND6_OPTION_TYPE_REDIR_HDR (0x04)
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct redirected_header_option {
    PACK_STRUCT_FLD_8(uint8_t type);
    PACK_STRUCT_FLD_8(uint8_t length);
    PACK_STRUCT_FLD_8(uint8_t reserved[6]);
    /* Portion of redirected packet follows. */
    /* PACK_STRUCT_FLD_8(uint8_t redirected[8]); */
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "epstruct.h"
#endif

/** MTU option. */
#define ND6_OPTION_TYPE_MTU (0x05)
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct mtu_option {
    PACK_STRUCT_FLD_8(uint8_t type);
    PACK_STRUCT_FLD_8(uint8_t length);
    PACK_STRUCT_FIELD(uint16_t reserved);
    PACK_STRUCT_FIELD(uint32_t mtu);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "epstruct.h"
#endif

/** Route information option. */
#define ND6_OPTION_TYPE_ROUTE_INFO (24)
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct route_option {
    PACK_STRUCT_FLD_8(uint8_t type);
    PACK_STRUCT_FLD_8(uint8_t length);
    PACK_STRUCT_FLD_8(uint8_t prefix_length);
    PACK_STRUCT_FLD_8(uint8_t preference);
    PACK_STRUCT_FIELD(uint32_t route_lifetime);
    PACK_STRUCT_FLD_S(ip6_addr_p_t prefix);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "epstruct.h"
#endif

/** Recursive DNS Server Option. */
#define ND6_OPTION_TYPE_RDNSS (25)
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct rdnss_option {
    PACK_STRUCT_FLD_8(uint8_t type);
    PACK_STRUCT_FLD_8(uint8_t length);
    PACK_STRUCT_FIELD(uint16_t reserved);
    PACK_STRUCT_FIELD(uint32_t lifetime);
    PACK_STRUCT_FLD_S(ip6_addr_p_t rdnss_address[1]);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "epstruct.h"
#endif

#define SIZEOF_RDNSS_OPTION_BASE 8 /* size without addresses */


#if LWIP_IPV6  /* don't build if not configured for use in lwipopts.h */

#include "ip6_addr.h"
#include "err.h"

#ifdef __cplusplus
extern "C" {
#endif

/** 1 second period */
#define ND6_TMR_INTERVAL 1000

/** Router solicitations are sent in 4 second intervals (see RFC 4861, ch. 6.3.7) */
#ifndef ND6_RTR_SOLICITATION_INTERVAL
#define ND6_RTR_SOLICITATION_INTERVAL  4000
#endif

struct pbuf;
struct netif;

void nd6_tmr(void);
void nd6_input(struct pbuf *p, struct netif *inp);
void nd6_clear_destination_cache(void);
struct netif *nd6_find_route(const ip6_addr_t *ip6addr);
err_t nd6_get_next_hop_addr_or_queue(struct netif *netif, struct pbuf *q, const ip6_addr_t *ip6addr, const uint8_t **hwaddrp);
uint16_t nd6_get_destination_mtu(const ip6_addr_t *ip6addr, struct netif *netif);
#if LWIP_ND6_TCP_REACHABILITY_HINTS
void nd6_reachability_hint(const ip6_addr_t *ip6addr);
#endif /* LWIP_ND6_TCP_REACHABILITY_HINTS */
void nd6_cleanup_netif(struct netif *netif);
#if LWIP_IPV6_MLD
void nd6_adjust_mld_membership(struct netif *netif, s8_t addr_idx, uint8_t new_state);
#endif /* LWIP_IPV6_MLD */
void nd6_restart_netif(struct netif *netif);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_IPV6 */

#endif /* LWIP_HDR_ND6_H */
