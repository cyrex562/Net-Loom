/**
 * @file
 * Ethernet common functions
 *
 * @defgroup ethernet Ethernet
 * @ingroup callbackstyle_api
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
 */

#include "opt.h"
#include "def.h"

#include "etharp.h"

#include "ethernet.h"

#include "ieee.h"

#include "ip.h"

#include "lwip_debug.h"

#include "ppp_opts.h"

#include "pppoe.h"

#include "lwip_snmp.h"

#include "stats.h"

#include <cstring>

#ifdef LWIP_HOOK_FILENAME
#include LWIP_HOOK_FILENAME
#endif

const struct EthAddr kEthbroadcast = {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
const struct EthAddr kEthzero = {{0, 0, 0, 0, 0, 0}};

/**
 * @ingroup lwip_nosys
 * Process received ethernet frames. Using this function instead of directly
 * calling ip_input and passing ARP frames through etharp in ethernetif_input,
 * the ARP cache is protected from concurrent access.\n
 * Don't call directly, pass to netif_add() and call netif->input().
 *
 * @param p the received packet, p->payload pointing to the ethernet header
 * @param netif the network interface on which the packet was received
 *
 * @see LWIP_HOOK_UNKNOWN_ETH_PROTOCOL
 * @see ETHARP_SUPPORT_VLAN
 * @see LWIP_HOOK_VLAN_CHECK
 */
LwipError
ethernet_input(struct PacketBuffer* p, NetIfc* netif)
{
    uint16_t next_hdr_offset = kSizeofEthHdr;


    LWIP_ASSERT_CORE_LOCKED();

    if (p->len <= kSizeofEthHdr)
    {
        /* a packet with only an ethernet header (or less) is not valid for us */
        ETHARP_STATS_INC(etharp.proterr);
        ETHARP_STATS_INC(etharp.drop);
        // TODO: remove or fix missing ifinerrors
        // MIB2_STATS_NETIF_INC(netif, ifinerrors);
        goto free_and_return;
    }

    if (p->if_idx == NETIF_NO_INDEX)
    {
        p->if_idx = netif_get_index(netif);
    }

    /* points to packet payload, which starts with an Ethernet header */
    auto ethhdr = static_cast<struct EthHdr *>(p->payload);

    auto type = ethhdr->type;

    if (type == pp_htons(ETHTYPE_VLAN))
    {
        struct EthVlanHdr* vlan = (struct EthVlanHdr *)(((char *)ethhdr) + kSizeofEthHdr);
        next_hdr_offset = kSizeofEthHdr + kSizeofVlanHdr;
        if (p->len <= kSizeofEthHdr + kSizeofVlanHdr)
        {
            /* a packet with only an ethernet/vlan header (or less) is not valid for us */
            ETHARP_STATS_INC(etharp.proterr);
            ETHARP_STATS_INC(etharp.drop);
            // MIB2_STATS_NETIF_INC(netif, ifinerrors);
            goto free_and_return;
        }


        // if (!LWIP_HOOK_VLAN_CHECK(netif, ethhdr, vlan))
        // {
        //     if (!ETHARP_VLAN_CHECK_FN(ethhdr, vlan))
        //     {
        //         if (VlanId(vlan) != ETHARP_VLAN_CHECK)
        //         {
        //             /* silently ignore this packet: not for our VLAN */
        //             pbuf_free(p);
        //             return ERR_OK;
        //         }
        //
        //         type = vlan->tpid;
        //     }
        // }
    }

    // netif = LWIP_ARP_FILTER_NETIF_FN(p, netif, lwip_htons(type));


    if (ethhdr->dest.addr[0] & 1)
    {
        /* this might be a multicast or broadcast packet */
        if (ethhdr->dest.addr[0] == kLLIp4McastAddrOui[0])
        {
            if ((ethhdr->dest.addr[1] == kLLIp4McastAddrOui[1]) &&
                (ethhdr->dest.addr[2] == kLLIp4McastAddrOui[2]))
            {
                /* mark the PacketBuffer as link-layer multicast */
                p->flags |= PBUF_FLAG_LLMCAST;
            }
        }
        else if ((ethhdr->dest.addr[0] == kLLIp6McastAddrPrefix[0]) &&
            (ethhdr->dest.addr[1] == kLLIp6McastAddrPrefix[1]))
        {
            /* mark the PacketBuffer as link-layer multicast */
            p->flags |= PBUF_FLAG_LLMCAST;
        }

        else if (eth_addr_cmp(&ethhdr->dest, &kEthbroadcast))
        {
            /* mark the pbuf as link-layer broadcast */
            p->flags |= PBUF_FLAG_LLBCAST;
        }
    }

    switch (type)
    {
        /* IP packet? */
    case pp_htons(ETHTYPE_IP):
        if (!(netif->flags & kNetifFlagEtharp))
        {
            goto free_and_return;
        }
        /* skip Ethernet header (min. size checked above) */
        if (pbuf_remove_header(p, next_hdr_offset))
        {
            //        Logf(ETHARP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
            //                    ("ethernet_input: IPv4 packet dropped, too short (%"U16_F"/%"U16_F")\n",
            //                     p->tot_len, next_hdr_offset));
            //        Logf(ETHARP_DEBUG | LWIP_DBG_TRACE, ("Can't move over header in packet"));
            goto free_and_return;
        }
        else
        {
            /* pass to IP layer */
            ip4_input(p, netif);
        }
        break;

    case pp_htons(ETHTYPE_ARP):
        if (!(netif->flags & kNetifFlagEtharp))
        {
            goto free_and_return;
        }
        /* skip Ethernet header (min. size checked above) */
        if (pbuf_remove_header(p, next_hdr_offset))
        {
            //        Logf(ETHARP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
            //                    ("ethernet_input: ARP response packet dropped, too short (%"U16_F"/%"U16_F")\n",
            //                     p->tot_len, next_hdr_offset));
            //        Logf(ETHARP_DEBUG | LWIP_DBG_TRACE, ("Can't move over header in packet"));
            ETHARP_STATS_INC(etharp.lenerr);
            ETHARP_STATS_INC(etharp.drop);
            goto free_and_return;
        }
        else
        {
            /* pass p to ARP module */
            etharp_input(p, netif);
        }
        break;

    case pp_htons(ETHTYPE_PPPOEDISC): /* PPP Over Ethernet Discovery Stage */
        pppoe_disc_input(netif, p);
        break;

    case pp_htons(ETHTYPE_PPPOE): /* PPP Over Ethernet Session Stage */
        pppoe_data_input(netif, p);
        break;
    case pp_htons(ETHTYPE_IPV6): /* IPv6 */
        /* skip Ethernet header */
        if ((p->len < next_hdr_offset) || pbuf_remove_header(p, next_hdr_offset))
        {
            // Logf(ETHARP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
            //      ("ethernet_input: IPv6 packet dropped, too short (%"U16_F"/%"U16_F")\n",
            //          p->tot_len, next_hdr_offset));
            goto free_and_return;
        }
        else
        {
            /* pass to IPv6 layer */
            ip6_input(p, netif);
        }
        break;


    default:
        // if (LWIP_HOOK_UNKNOWN_ETH_PROTOCOL(p, netif) == ERR_OK)
        // {
        //     break;
        // }
        // ETHARP_STATS_INC(etharp.proterr);
        // ETHARP_STATS_INC(etharp.drop);
        // MIB2_STATS_NETIF_INC(netif, ifinunknownprotos);
        goto free_and_return;
    }

    /* This means the PacketBuffer is freed or consumed,
       so the caller doesn't have to free it again */
    return ERR_OK;

free_and_return:
    pbuf_free(p);
    return ERR_OK;
}

/**
 * @ingroup ethernet
 * Send an ethernet packet on the network using netif->linkoutput().
 * The ethernet header is filled in before sending.
 *
 * @see LWIP_HOOK_VLAN_SET
 *
 * @param netif the lwIP network interface on which to send the packet
 * @param p the packet to send. PacketBuffer layer must be @ref PBUF_LINK.
 * @param src the source MAC address to be copied into the ethernet header
 * @param dst the destination MAC address to be copied into the ethernet header
 * @param eth_type ethernet type (@ref lwip_ieee_eth_type)
 * @return ERR_OK if the packet was sent, any other LwipError on failure
 */
LwipError ethernet_output(NetIfc* netif, struct PacketBuffer* p,
                          EthAddr* src, EthAddr* dst,
                          uint16_t eth_type)
{
    struct EthHdr* ethhdr;
    uint16_t eth_type_be = lwip_htons(eth_type);


    // s32_t vlan_prio_vid = LWIP_HOOK_VLAN_SET(netif, p, src, dst, eth_type);
    // if (vlan_prio_vid >= 0)
    // {
    //     struct eth_vlan_hdr* vlanhdr;
    //
    //     LWIP_ASSERT("prio_vid must be <= 0xFFFF", vlan_prio_vid <= 0xFFFF);
    //
    //     if (pbuf_add_header(p, SIZEOF_ETH_HDR + SIZEOF_VLAN_HDR) != 0)
    //     {
    //         goto pbuf_header_failed;
    //     }
    //     vlanhdr = (struct eth_vlan_hdr *)(((uint8_t *)p->payload) + SIZEOF_ETH_HDR);
    //     vlanhdr->tpid = eth_type_be;
    //     vlanhdr->prio_vid = lwip_htons((uint16_t)vlan_prio_vid);
    //
    //     eth_type_be = PpHtons(ETHTYPE_VLAN);
    // }
    // else
    //
    // {
    //     if (pbuf_add_header(p, kSizeofEthHdr) != 0)
    //     {
    //         goto pbuf_header_failed;
    //     }
    // }

    LWIP_ASSERT_CORE_LOCKED();

    ethhdr = (struct EthHdr *)p->payload;
    ethhdr->type = eth_type_be;
    SMEMCPY(&ethhdr->dest, dst, ETH_HWADDR_LEN);
    SMEMCPY(&ethhdr->src, src, ETH_HWADDR_LEN);

    lwip_assert("netif->hwaddr_len must be 6 for ethernet_output!",
                (netif->hwaddr_len == ETH_HWADDR_LEN));
    // Logf(ETHARP_DEBUG | LWIP_DBG_TRACE,
    //      ("ethernet_output: sending packet %p\n", (void *)p));

    /* send the packet */
    areturn netif->linkoutput(netif, p);

pbuf_header_failed:
    Logf(ETHARP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS,
         ("ethernet_output: could not allocate room for header.\n"));
    LINK_STATS_INC(link.lenerr);
    return ERR_BUF;
}
