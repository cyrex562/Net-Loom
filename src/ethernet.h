/**
 * @file
 * Ethernet input function - handles INCOMING ethernet level traffic
 * To be used in most low-level netif implementations
 */

/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * Copyright (c) 2003-2004 Leon Woestenberg <leon.woestenberg@axon.tv>
 * Copyright (c) 2003-2004 Axon Digital Design B.V., The Netherlands.
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

#ifndef LWIP_HDR_NETIF_ETHERNET_H
#define LWIP_HDR_NETIF_ETHERNET_H

#include "opt.h"
#include "pbuf.h"
#include "netif.h"
#include "ethernet.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ETH_HWADDR_LEN
#ifdef ETHARP_HWADDR_LEN
#define ETH_HWADDR_LEN    ETHARP_HWADDR_LEN /* compatibility mode */
#else
#define ETH_HWADDR_LEN    6
#endif
#endif


#ifdef PACK_STRUCT_USE_INCLUDES
#  include "bpstruct.h"
#endif
    PACK_STRUCT_BEGIN
        /** An Ethernet MAC address */
        struct eth_addr {
        PACK_STRUCT_FLD_8(uint8_t addr[ETH_HWADDR_LEN]);
    } PACK_STRUCT_STRUCT;
    PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "epstruct.h"
#endif

        /** Initialize a struct eth_addr with its 6 bytes (takes care of correct braces) */
#define ETH_ADDR(b0, b1, b2, b3, b4, b5) {{b0, b1, b2, b3, b4, b5}}

#ifdef PACK_STRUCT_USE_INCLUDES
#  include "bpstruct.h"
#endif
        PACK_STRUCT_BEGIN
        /** Ethernet header */
        struct eth_hdr {
#if ETH_PAD_SIZE
        PACK_STRUCT_FLD_8(uint8_t padding[ETH_PAD_SIZE]);
#endif
        PACK_STRUCT_FLD_S(struct eth_addr dest);
        PACK_STRUCT_FLD_S(struct eth_addr src);
        PACK_STRUCT_FIELD(uint16_t type);
    } PACK_STRUCT_STRUCT;
    PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "epstruct.h"
#endif

#define SIZEOF_ETH_HDR (14 + ETH_PAD_SIZE)

#ifdef PACK_STRUCT_USE_INCLUDES
#  include "bpstruct.h"
#endif
        PACK_STRUCT_BEGIN
        /** VLAN header inserted between ethernet header and payload
         * if 'type' in ethernet header is ETHTYPE_VLAN.
         * See IEEE802.Q */
        struct eth_vlan_hdr {
        PACK_STRUCT_FIELD(uint16_t prio_vid);
        PACK_STRUCT_FIELD(uint16_t tpid);
    } PACK_STRUCT_STRUCT;
    PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "epstruct.h"
#endif

#define SIZEOF_VLAN_HDR 4
#define VLAN_ID(vlan_hdr) (lwip_htons((vlan_hdr)->prio_vid) & 0xFFF)

        /** The 24-bit IANA IPv4-multicast OUI is 01-00-5e: */
#define LL_IP4_MULTICAST_ADDR_0 0x01
#define LL_IP4_MULTICAST_ADDR_1 0x00
#define LL_IP4_MULTICAST_ADDR_2 0x5e

/** IPv6 multicast uses this prefix */
#define LL_IP6_MULTICAST_ADDR_0 0x33
#define LL_IP6_MULTICAST_ADDR_1 0x33

#define eth_addr_cmp(addr1, addr2) (memcmp((addr1)->addr, (addr2)->addr, ETH_HWADDR_LEN) == 0)


#if LWIP_ARP || LWIP_ETHERNET

/** Define this to 1 and define LWIP_ARP_FILTER_NETIF_FN(pbuf, netif, type)
 * to a filter function that returns the correct netif when using multiple
 * netifs on one hardware interface where the netif's low-level receive
 * routine cannot decide for the correct netif (e.g. when mapping multiple
 * IP addresses to one hardware interface).
 */
#ifndef LWIP_ARP_FILTER_NETIF
#define LWIP_ARP_FILTER_NETIF 0
#endif

err_t ethernet_input(struct pbuf *p, struct netif *netif);
err_t ethernet_output(struct netif* netif, struct pbuf* p, const struct eth_addr* src, const struct eth_addr* dst, uint16_t eth_type);

extern const struct eth_addr ethbroadcast, ethzero;

#endif /* LWIP_ARP || LWIP_ETHERNET */

#ifdef __cplusplus
}
#endif

#endif /* LWIP_HDR_NETIF_ETHERNET_H */
