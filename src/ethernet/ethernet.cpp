///
/// file: ethernet.cpp
///

#define NOMINMAX

#include "ns_def.h"
#include "eth_arp.h"
#include "ethernet.h"
#include "netloom_ieee.h"
#include "ip.h"
#include "netloom_debug.h"
#include "pppoe.h"
#include <cstring>


const struct MacAddress ETH_BCAST_ADDR = {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
const struct MacAddress ETH_ZERO_ADDR = {{0, 0, 0, 0, 0, 0}};





/**
 * @ingroup lwip_nosys
 * Process received ethernet frames. Using this function instead of directly
 * calling ip_input and passing ARP frames through etharp in ethernetif_input,
 * the ARP cache is protected from concurrent access.\n
 * Don't call directly, pass to netif_add() and call netif->input().
 *
 * @param pkt_buf the received packet, p->payload pointing to the ethernet header
 * @param net_ifc the network interface on which the packet was received
 *
 * @see LWIP_HOOK_UNKNOWN_ETH_PROTOCOL
 * @see ETHARP_SUPPORT_VLAN
 * @see LWIP_HOOK_VLAN_CHECK
 */
NsStatus
ethernet_input(PacketContainer& pkt_buf, NetworkInterface& net_ifc)
{
    uint16_t next_hdr_offset = kSizeofEthHdr;


    if (pkt_buf.len <= kSizeofEthHdr) {
        /* a packet with only an ethernet header (or less) is not valid for us */
        // TODO: remove or fix missing ifinerrors
        // MIB2_STATS_NETIF_INC(netif, ifinerrors);
        free_pkt_buf(pkt_buf);
        return STATUS_SUCCESS;
    }

    if (pkt_buf.input_netif_idx == NETIF_NO_INDEX) {
        pkt_buf.input_netif_idx = get_and_inc_netif_num(net_ifc);
    }

    /* points to packet payload, which starts with an Ethernet header */
    auto ethhdr = reinterpret_cast<struct EthHdr *>(pkt_buf.payload);

    auto type = ethhdr->type;

    if (type == pp_htons(ETHTYPE_VLAN)) {
        auto* vlan = (struct EthVlanHdr *)(((char *)ethhdr) + kSizeofEthHdr);
        next_hdr_offset = kSizeofEthHdr + VLAN_HDR_LEN;
        if (pkt_buf.len <= kSizeofEthHdr + VLAN_HDR_LEN) {
            /* a packet with only an ethernet/vlan header (or less) is not valid for us */
            // MIB2_STATS_NETIF_INC(netif, ifinerrors);
            free_pkt_buf(pkt_buf);
            return STATUS_SUCCESS;
        }


        // if (!LWIP_HOOK_VLAN_CHECK(netif, ethhdr, vlan))
        // {
        //     if (!ETHARP_VLAN_CHECK_FN(ethhdr, vlan))
        //     {
        //         if (get_vlan_id(vlan) != ETHARP_VLAN_CHECK)
        //         {
        //             /* silently ignore this packet: not for our VLAN */
        //             free_pkt_buf(p);
        //             return ERR_OK;
        //         }
        //
        //         type = vlan->tpid;
        //     }
        // }
    }

    // netif = LWIP_ARP_FILTER_NETIF_FN(p, netif, lwip_htons(type));


    if (ethhdr->dest.bytes[0] & 1) {
        /* this might be a multicast or broadcast packet */
        if (ethhdr->dest.bytes[0] == LNK_LYR_MCAST_ADDR_OUI[0]) {
            if ((ethhdr->dest.bytes[1] == LNK_LYR_MCAST_ADDR_OUI[1]) &&
                (ethhdr->dest.bytes[2] == LNK_LYR_MCAST_ADDR_OUI[2])) {
                /* mark the PacketBuffer as link-layer multicast */
                // pkt_buf.ll_multicast = true;
            }
        }
        else if ((ethhdr->dest.bytes[0] == LNK_LYR_IP6_MCAST_ADDR_PREFIX[0]) &&
            (ethhdr->dest.bytes[1] == LNK_LYR_IP6_MCAST_ADDR_PREFIX[1])) {
            /* mark the PacketBuffer as link-layer multicast */
            // pkt_buf.ll_multicast = true;
        }

        else if (eth_addr_cmp(&ethhdr->dest, &ETH_BCAST_ADDR)) {
            /* mark the pbuf as link-layer broadcast */
            // pkt_buf.ll_broadcast = true;
        }
    }

    if (type == pp_htons(ETHTYPE_IP)) {
        if (!(net_ifc->flags & NETIF_FLAG_ETH_ARP)) {
            free_pkt_buf(pkt_buf);
            return STATUS_SUCCESS;
        }
        /* skip Ethernet header (min. size checked above) */
        // if (pbuf_remove_header(pkt_buf, next_hdr_offset)) {
        //     //        Logf(true | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
        //     //                    ("ethernet_input: IPv4 packet dropped, too short (%d/%d)\n",
        //     //                     p->tot_len, next_hdr_offset));
        //     //        Logf(true | LWIP_DBG_TRACE, ("Can't move over header in packet"));
        //     free_pkt_buf(pkt_buf);
        //     return STATUS_OK;
        // }
        // else {
        //     /* pass to IP layer */
        //     ip4_input(pkt_buf, net_ifc);
        // }

    }
    else if (type == pp_htons(ETHTYPE_ARP)) {
        if (!(net_ifc->flags & NETIF_FLAG_ETH_ARP)) {
            free_pkt_buf(pkt_buf);
            return STATUS_SUCCESS;
        }
        /* skip Ethernet header (min. size checked above) */
        // if (pbuf_remove_header(pkt_buf, next_hdr_offset)) {
        //
        //     free_pkt_buf(pkt_buf);
        //     return STATUS_OK;
        // }
        // else {
        //     /* pass p to ARP module */
        //     etharp_input(pkt_buf, net_ifc);
        // }


    }
    else if (type == pp_htons(ETHTYPE_PPPOEDISC)) {

        pppoe_disc_input(net_ifc, pkt_buf,);


    }
    else if (type == pp_htons(ETHTYPE_PPPOE)) {

        pppoe_data_input(net_ifc, pkt_buf);

    }
    else if (type == pp_htons(ETHTYPE_IPV6)) {
        /* skip Ethernet header */
        // if ((pkt_buf.len < next_hdr_offset) || pbuf_remove_header(pkt_buf, next_hdr_offset)) {
        //     // Logf(true | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
        //     //      ("ethernet_input: IPv6 packet dropped, too short (%d/%d)\n",
        //     //          p->tot_len, next_hdr_offset));
        //     free_pkt_buf(pkt_buf);
        //     return STATUS_OK;
        // }
        // else {
        //     /* pass to IPv6 layer */
        //     ip6_input(pkt_buf, net_ifc);
        // }
    }
    else {
        // if (LWIP_HOOK_UNKNOWN_ETH_PROTOCOL(p, netif) == ERR_OK)
        // {
        //     break;
        // }
        // ETHARP_STATS_INC(etharp.proterr);
        // ETHARP_STATS_INC(etharp.drop);
        // MIB2_STATS_NETIF_INC(netif, ifinunknownprotos);
        free_pkt_buf(pkt_buf);
        return STATUS_SUCCESS;
    }

    /* This means the PacketBuffer is freed or consumed,
       so the caller doesn't have to free it again */
    return STATUS_SUCCESS;
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
 * @return ERR_OK if the packet was sent, any other LwipStatus on failure
 */
NsStatus
ethernet_output(NetworkInterface* netif,
                struct PacketContainer* p,
                MacAddress* src,
                MacAddress* dst,
                uint16_t eth_type)
{
    uint16_t eth_type_be = ns_htons(eth_type);


    // int32_t vlan_prio_vid = LWIP_HOOK_VLAN_SET(netif, p, src, dst, eth_type);
    // if (vlan_prio_vid >= 0)
    // {
    //     struct eth_vlan_hdr* vlanhdr;
    //
    //     lwip_assert("prio_vid must be <= 0xFFFF", vlan_prio_vid <= 0xFFFF);
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


    struct EthHdr* ethhdr = (struct EthHdr *)p->payload;
    ethhdr->type = eth_type_be;
    memcpy(&ethhdr->dest, dst, MAC_ADDR_LEN);
    memcpy(&ethhdr->src, src, MAC_ADDR_LEN);

    ns_assert("netif->hwaddr_len must be 6 for ethernet_output!",
                (netif->hwaddr_len == MAC_ADDR_LEN));
    // Logf(true | LWIP_DBG_TRACE,
    //      ("ethernet_output: sending packet %p\n", (uint8_t *)p));

    /* send the packet */
    return netif->linkoutput(netif, p);

    // pbuf_header_failed:
    //     Logf(true | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS,
    //          ("ethernet_output: could not allocate room for header.\n"));
    //     LINK_STATS_INC(link.lenerr);
    //     return ERR_BUF;
}
