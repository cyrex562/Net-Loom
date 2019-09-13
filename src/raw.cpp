/**
 * @file
 * Implementation of raw protocol PCBs for low-level handling of
 * different types of protocols besides (or overriding) those
 * already available in lwIP.\n
 * See also @ref raw_raw
 *
 * @defgroup raw_raw RAW
 * @ingroup callbackstyle_api
 * Implementation of raw protocol PCBs for low-level handling of
 * different types of protocols besides (or overriding) those
 * already available in lwIP.\n
 * @see @ref api
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
 */
#include "opt.h"
#include "def.h"
#include "inet_chksum.h"
#include "ip.h"
#include "ip6.h"
#include "ip6_addr.h"
#include "ip_addr.h"
#include "network_interface.h"
#include "raw.h"
#include "raw_priv.h"
#include <cstring>
/** The list of RAW PCBs */ // static struct raw_pcb *raw_pcbs;

inline bool
match_pcb_ip_addr(RawPcb* pcb, IpAddrInfo* ipaddr)
{
    return (get_ip_addr_type(&pcb->local_ip) == get_ip_addr_type(ipaddr));
}

static uint8_t
raw_input_local_match(RawPcb& pcb, bool broadcast)
{
    NetworkInterface* current_input_netif = nullptr;
    IpAddrInfo* curr_dst_addr = nullptr; /* check if PCB is bound to specific netif */
    if ((pcb->netif_idx != NETIF_NO_INDEX) && (pcb->netif_idx != get_and_inc_netif_num(
        current_input_netif)))
    {
        return 0;
    } /* Dual-stack: PCBs listening to any IP type also listen to any IP address */
    if (is_ip_addr_any_type(pcb->local_ip))
    {
        if ((broadcast != 0) && !ip_get_option((IpPcb*)pcb, SOF_BROADCAST))
        {
            return 0;
        }
        return 1;
    } /* Only need to check PCB if incoming IP version matches PCB IP version */
    if (match_pcb_ip_addr(pcb, curr_dst_addr))
    {
        /* Special case: IPv4 broadcast: receive all broadcasts
         * Note: broadcast variable can only be 1 if it is an IPv4 broadcast */
        if (broadcast != 0)
        {
            if (ip_get_option((IpPcb*)pcb, SOF_BROADCAST))

            {
                if (ip4_addr_isany((pcb.local_ip.u_addr.ip4.address)))
                {
                    return 1;
                }
            }
        }
        else /* Handle IPv4 and IPv6: catch all or exact match */
            if (is_ip_addr_any(&pcb->local_ip) || compare_ip_addr(
                &pcb->local_ip,
                curr_dst_addr))
            {
                return 1;
            }
    }
    return 0;
} /**
 * Determine if in incoming IP packet is covered by a RAW PCB
 * and if so, pass it to a user-provided receive callback function.
 *
 * Given an incoming IP datagram (as a chain of pbufs) this function
 * finds a corresponding RAW PCB and calls the corresponding receive
 * callback function.
 *
 * @param p PacketBuffer to be demultiplexed to a RAW PCB.
 * @param inp network interface on which the datagram was received.
 * @return - 1 if the packet has been eaten by a RAW PCB receive
 *           callback function. The caller MAY NOT not reference the
 *           packet any longer, and MAY NOT call free_pkt_buf().
 * @return - 0 if packet is not eaten (PacketBuffer is still referenced by the
 *           caller).
 *
 */
raw_input_state_t
raw_input(struct PacketBuffer* p, NetworkInterface* inp)
{
    int16_t proto;
    auto ret = RAW_INPUT_NONE;
    IpAddrInfo* curr_dst_addr = nullptr;
    NetworkInterface* curr_ip_netif = nullptr;
    IpAddrInfo* curr_src_addr = nullptr;
    RawPcb* raw_pcbs;
    const uint8_t broadcast = netif_is_ip4_addr_bcast(curr_dst_addr, curr_ip_netif);
    if (get_ip_hdr_version(p->payload) == 6)
    {
        auto* ip6_hdr = reinterpret_cast<struct Ip6Hdr *>(p->payload);
        proto = get_ip6_hdr_next_hop(ip6_hdr);
    }
    else
    {
        proto = get_ip4_hdr_proto(reinterpret_cast<struct Ip4Hdr *>(p->payload));
    }
    struct RawPcb* prev = nullptr;
    auto pcb = raw_pcbs; /* loop through all raw pcbs until the packet is eaten by one */
    /* this allows multiple pcbs to match against the packet by design */
    while (pcb != nullptr)
    {
        if ((pcb->protocol == proto) && raw_input_local_match(pcb, broadcast) && (((pcb->
            flags & RAW_FLAGS_CONNECTED) == 0) || compare_ip_addr(
            &pcb->remote_ip,
            curr_src_addr)))
        {
            /* receive callback function available? */
            if (pcb->recv != nullptr)
            {
                void* old_payload = p->payload;
                ret = RAW_INPUT_DELIVERED;
                /* the receive callback function did not eat the packet? */
                uint8_t eaten = pcb->recv(pcb->recv_arg, pcb, p, curr_src_addr);
                if (eaten != 0)
                {
                    /* receive function ate the packet */
                    p = nullptr;
                    if (prev != nullptr)
                    {
                        /* move the pcb to the front of raw_pcbs so that is
                           found faster next time */
                        prev->next = pcb->next;
                        pcb->next = raw_pcbs;
                        raw_pcbs = pcb;
                    }
                    return RAW_INPUT_EATEN;
                }
                else
                {
                    /* sanity-check that the receive callback did not alter the PacketBuffer */
                    lwip_assert(
                        "raw pcb recv callback altered PacketBuffer payload pointer without eating packet",
                        p->payload == old_payload);
                }
            } /* no receive callback function was set for this raw PCB */
        } /* drop the packet */
        prev = pcb;
        pcb = pcb->next;
    }
    return ret;
} /**
 * @ingroup raw_raw
 * Bind a RAW PCB.
 *
 * @param pcb RAW PCB to be bound with a local address ipaddr.
 * @param ipaddr local IP address to bind with. Use IP4_ADDR_ANY to
 * bind to all local interfaces.
 *
 * @return lwIP error code.
 * - ERR_OK. Successful. No error occurred.
 * - ERR_USE. The specified IP address is already bound to by
 * another RAW PCB.
 *
 * @see raw_disconnect()
 */
LwipStatus
raw_bind(struct RawPcb* pcb, const IpAddrInfo* ipaddr)
{
    if ((pcb == nullptr) || (ipaddr == nullptr))
    {
        return ERR_VAL;
    }
    set_ip_addr(&pcb->local_ip, ipaddr);
    /* If the given IP address should have a zone but doesn't, assign one now.
      * This is legacy support: scope-aware callers should always provide properly
      * zoned source addresses. */
    if (ip_addr_is_v6(&pcb->local_ip) && ip6_addr_lacks_zone(
        (&pcb->local_ip.u_addr.ip6),
        IP6_UNKNOWN))
    {
        select_ip6_addr_zone((&pcb->local_ip.u_addr.ip6), (&pcb->local_ip.u_addr.ip6),);
    }
    return STATUS_SUCCESS;
} /**
 * @ingroup raw_raw
 * Bind an RAW PCB to a specific netif.
 * After calling this function, all packets received via this PCB
 * are guaranteed to have come in via the specified netif, and all
 * outgoing packets will go out via the specified netif.
 *
 * @param pcb RAW PCB to be bound with netif.
 * @param netif netif to bind to. Can be NULL.
 *
 * @see raw_disconnect()
 */
void
raw_bind_netif(struct RawPcb* pcb, const NetworkInterface* netif)
{
    if (netif != nullptr)
    {
        pcb->netif_idx = get_and_inc_netif_num(netif);
    }
    else
    {
        pcb->netif_idx = NETIF_NO_INDEX;
    }
} /**
 * @ingroup raw_raw
 * Connect an RAW PCB. This function is required by upper layers
 * of lwip. Using the raw api you could use raw_sendto() instead
 *
 * This will associate the RAW PCB with the remote address.
 *
 * @param pcb RAW PCB to be connected with remote address ipaddr and port.
 * @param ipaddr remote IP address to connect with.
 *
 * @return lwIP error code
 *
 * @see raw_disconnect() and raw_sendto()
 */
LwipStatus
raw_connect(struct RawPcb* pcb, const IpAddrInfo* ipaddr)
{
    if ((pcb == nullptr) || (ipaddr == nullptr))
    {
        return ERR_VAL;
    }
    set_ip_addr(&pcb->remote_ip, ipaddr);
    /* If the given IP address should have a zone but doesn't, assign one now,
      * using the bound address to make a more informed decision when possible. */
    if (ip_addr_is_v6(&pcb->remote_ip) && ip6_addr_lacks_zone(
        (&pcb->remote_ip.u_addr.ip6),
        IP6_UNKNOWN))
    {
        select_ip6_addr_zone((&pcb->remote_ip.u_addr.ip6), (&pcb->local_ip.u_addr.ip6),);
    }
    raw_set_flags(pcb, RAW_FLAGS_CONNECTED);
    return STATUS_SUCCESS;
} /**
 * @ingroup raw_raw
 * Disconnect a RAW PCB.
 *
 * @param pcb the raw pcb to disconnect.
 */
void
raw_disconnect(struct RawPcb* pcb)
{
    /* reset remote address association */
    if (is_ip_addr_any(&pcb->local_ip))
    {
        auto any_addr = ip_addr_create_any();
        copy_ip_addr(&pcb->remote_ip, &any_addr);
    }
    else
    {
        set_ip_addr_any(ip_addr_is_v6(&pcb->remote_ip), &pcb->remote_ip);
    }
    pcb->netif_idx = NETIF_NO_INDEX; /* mark PCB as unconnected */
    raw_clear_flags(pcb, RAW_FLAGS_CONNECTED);
} /**
 * @ingroup raw_raw
 * Set the callback function for received packets that match the
 * raw PCB's protocol and binding.
 *
 * The callback function MUST either
 * - eat the packet by calling free_pkt_buf() and returning non-zero. The
 *   packet will not be passed to other raw PCBs or other protocol layers.
 * - not free the packet, and return zero. The packet will be matched
 *   against further PCBs and/or forwarded to another protocol layers.
 */
void
raw_recv(struct RawPcb* pcb, raw_recv_fn recv, void* recv_arg)
{
    /* remember recv() callback and user data */
    pcb->recv = recv;
    pcb->recv_arg = recv_arg;
} /**
 * @ingroup raw_raw
 * Send the raw IP packet to the given address. An IP header will be prepended
 * to the packet, unless the RAW_FLAGS_HDRINCL flag is set on the PCB. In that
 * case, the packet must include an IP header, which will then be sent as is.
 *
 * @param pcb the raw pcb which to send
 * @param p the IP payload to send
 * @param ipaddr the destination address of the IP packet
 *
 */
LwipStatus
raw_sendto(struct RawPcb* pcb, struct PacketBuffer* p, const IpAddrInfo* ipaddr)
{
    NetworkInterface* netif;
    const IpAddrInfo* src_ip;
    if ((pcb == nullptr) || (ipaddr == nullptr) || !match_ip_addr_pcb_version(
        (IpPcb*)pcb,
        ipaddr))
    {
        return ERR_VAL;
    }
    Logf(true, ("raw_sendto\n"));
    if (pcb->netif_idx != NETIF_NO_INDEX)
    {
        // todo: get collection of netifs to send
        // netif = get_netif_by_index(pcb->netif_idx);
    }
    else
    {
        netif = nullptr;
        if (is_ip_addr_mcast(ipaddr))
        {
            /* For multicast-destined packets, use the user-provided interface index to
             * determine the outgoing interface, if an interface index is set and a
             * matching netif can be found. Otherwise, fall back to regular routing. */
            // todo: get current netif
            // netif = get_netif_by_index(pcb->mcast_ifindex);
        }
        if (netif == nullptr)

        {
            netif = ip_route(&pcb->local_ip, ipaddr,);
        }
    }
    if (netif == nullptr)
    {
        Logf(true, ("raw_sendto: No route to "));
        // ip_addr_debug_print(true | LWIP_DBG_LEVEL_WARNING, ipaddr);
        return STATUS_E_ROUTING;
    }
    if (is_ip_addr_any(&pcb->local_ip) || is_ip_addr_mcast(&pcb->local_ip))
    {
        /* use outgoing network interface IP address as source address */
        src_ip = netif_get_local_ip(netif, ipaddr);
        if (src_ip == nullptr)
        {
            return STATUS_E_ROUTING;
        }
    }
    else
    {
        /* use RAW PCB local IP address as source address */
        src_ip = &pcb->local_ip;
    }
    return raw_sendto_if_src(pcb, p, ipaddr, netif, src_ip);
} /**
 * @ingroup raw_raw
 * Send the raw IP packet to the given address, using a particular outgoing
 * netif and source IP address. An IP header will be prepended to the packet,
 * unless the RAW_FLAGS_HDRINCL flag is set on the PCB. In that case, the
 * packet must include an IP header, which will then be sent as is.
 *
 * @param pcb RAW PCB used to send the data
 * @param p chain of pbufs to be sent
 * @param dst_ip destination IP address
 * @param netif the netif used for sending
 * @param src_ip source IP address
 */
LwipStatus
raw_sendto_if_src(RawPcb& pcb,
                  PacketBuffer& p,
                  const IpAddrInfo& dst_ip,
                  NetworkInterface& netif,
                  const IpAddrInfo& src_ip)
{
    LwipStatus err = {};
    PacketBuffer q; /* q will be sent down the stack */
    if ((pcb == nullptr) || (dst_ip == nullptr) || (netif == nullptr) || (src_ip ==
            nullptr) || !match_ip_addr_pcb_version((IpPcb*)pcb, src_ip) || !
        match_ip_addr_pcb_version((IpPcb*)pcb, dst_ip))
    {
        return ERR_VAL;
    } // const uint16_t header_size = (
    //
    //     is_ip_addr_v6(dst_ip) ? IP6_HDR_LEN : get_ip4_hdr_hdr_len());
    uint16_t header_size = 0xff;
    /* Handle the HDRINCL option as an exception: none of the code below applies
      * to this case, and sending the packet needs to be done differently too. */
    if (pcb->flags & RAW_FLAGS_HDRINCL)
    {
        /* A full header *must* be present in the first PacketBuffer of the chain, as the
         * output routines may access its fields directly. */
        if (p->len < header_size)
        {
            return ERR_VAL;
        } /* @todo multicast loop support, if at all desired for this scenario.. */
        netif_set_hints(netif, pcb->netif_hints);
        // err = ip_output_if_hdrincl(p, src_ip, dst_ip, netif);
        netif_reset_hints(netif);
        return err;
    } /* packet too large to add an IP header without causing an overflow? */
    if ((uint16_t)(p->tot_len + header_size) < p->tot_len)
    {
        return ERR_MEM;
    } /* not enough space to add an IP header to first PacketBuffer in given p chain? */
    // if (pbuf_add_header(p, header_size))
    // {
    //     /* allocate header in new PacketBuffer */
    //     // q = pbuf_alloc(); /* new header PacketBuffer could not be allocated? */
    //     q = PacketBuffer();
    //     if (q == nullptr)
    //     {
    //         Logf(true,
    //              ("raw_sendto: could not allocate header\n"));
    //         return ERR_MEM;
    //     }
    //     if (p->tot_len != 0)
    //     {
    //         /* chain header q in front of given PacketBuffer p */
    //         pbuf_chain(q, p);
    //     } /* { first PacketBuffer q points to header PacketBuffer } */
    //     Logf(true,
    //          "raw_sendto: added header PacketBuffer %p before given PacketBuffer %p\n",
    //          (uint8_t *)q,
    //          (uint8_t *)p);
    // }
    // else
    // {
    //     /* first PacketBuffer q equals given PacketBuffer */
    //     q = p;
    //     if (pbuf_remove_header(q, header_size))
    //     {
    //         lwip_assert("Can't restore header we just removed!", false);
    //         return ERR_MEM;
    //     }
    // }
    if (is_ip_addr_v4(dst_ip))
    {
        /* broadcast filter? */
        if (!ip_get_option((IpPcb*)pcb, SOF_BROADCAST) && netif_is_ip4_addr_bcast(
            dst_ip,
            netif))
        {
            Logf(true,
                 "raw_sendto: SOF_BROADCAST not enabled on pcb %p\n",
                 (uint8_t *)pcb);
            /* free any temporary header PacketBuffer allocated by pbuf_header() */
            if (q != p)
            {
                free_pkt_buf(q);
            }
            return ERR_VAL;
        }
    } /* Multicast Loop? */
    if (((pcb->flags & RAW_FLAGS_MULTICAST_LOOP) != 0) && is_ip_addr_mcast(dst_ip))
    {
        // q->multicast_loop = true;
    } /* If requested, based on the IPV6_CHECKSUM socket option per RFC3542,
     compute the checksum and update the checksum in the payload. */
    if (ip_addr_is_v6(dst_ip) && pcb->chksum_reqd)
    {
        uint16_t chksum = ip6_chksum_pseudo(p,
                                            pcb->protocol,
                                            p->tot_len,
                                            &src_ip->u_addr.ip6,
                                            &dst_ip->u_addr.ip6);
        lwip_assert("Checksum must fit into first PacketBuffer",
                    p->len >= (pcb->chksum_offset + 2));
        memcpy(((uint8_t *)p->payload) + pcb->chksum_offset, &chksum, sizeof(uint16_t));
    } /* Determine TTL to use */
    uint8_t ttl = (is_ip_addr_mcast(dst_ip) ? raw_get_multicast_ttl(pcb) : pcb->ttl);
    netif_set_hints(netif, pcb->netif_hints);
    err = ip_output_if(q, src_ip, dst_ip, ttl, pcb->tos, pcb->protocol, netif);
    netif_reset_hints(netif); /* did we chain a header earlier? */
    if (q != p)
    {
        /* free the header */
        free_pkt_buf(q);
    }
    return err;
} /**
 * @ingroup raw_raw
 * Send the raw IP packet to the address given by raw_connect()
 *
 * @param pcb the raw pcb which to send
 * @param p the IP payload to send
 *
 */
LwipStatus
raw_send(struct RawPcb* pcb, struct PacketBuffer* p)
{
    return raw_sendto(pcb, p, &pcb->remote_ip);
} /**
 * @ingroup raw_raw
 * Remove an RAW PCB.
 *
 * @param pcb RAW PCB to be removed. The PCB is removed from the list of
 * RAW PCB's and the data structure is freed from memory.
 *
 * @see raw_new()
 */
void
raw_remove(struct RawPcb* pcb)
{
    // todo: fixme
    /* pcb to be removed is first in list? */ // if (raw_pcbs == pcb) {
    //   /* make list start at 2nd pcb */
    //   raw_pcbs = raw_pcbs->next;
    //   /* pcb not 1st in list */
    // } else {
    //   for (struct RawPcb* pcb2 = raw_pcbs; pcb2 != nullptr; pcb2 = pcb2->next) {
    //     /* find pcb in raw_pcbs list */
    //     if (pcb2->next != nullptr && pcb2->next == pcb) {
    //       /* remove pcb from list */
    //       pcb2->next = pcb->next;
    //       break;
    //     }
    //   }
    // }
    // memp_free(MEMP_RAW_PCB, pcb);
} /**
 * @ingroup raw_raw
 * Create a RAW PCB.
 *
 * @return The RAW PCB which was created. NULL if the PCB data structure
 * could not be allocated.
 *
 * @param proto the protocol number of the IPs payload (e.g. IP_PROTO_ICMP)
 *
 * @see raw_remove()
 */
struct RawPcb*
raw_new(uint8_t proto)
{
    Logf(true, ("raw_new\n"));
    // struct RawPcb* pcb = (struct RawPcb *)memp_malloc(MEMP_RAW_PCB);
    auto pcb = new RawPcb; /* could allocate RAW PCB? */
    if (pcb != nullptr)
    {
        /* initialize PCB to all zeroes */
        memset(pcb, 0, sizeof(struct RawPcb));
        pcb->protocol = proto;
        pcb->ttl = RAW_TTL;
        raw_set_multicast_ttl(pcb, RAW_TTL); // pcb->next = raw_pcbs;
        // raw_pcbs = pcb;
    }
    return pcb;
} /**
 * @ingroup raw_raw
 * Create a RAW PCB for specific IP type.
 *
 * @return The RAW PCB which was created. NULL if the PCB data structure
 * could not be allocated.
 *
 * @param type IP address type, see @ref lwip_ip_addr_type definitions.
 * If you want to listen to IPv4 and IPv6 (dual-stack) packets,
 * supply @ref IPADDR_TYPE_ANY as argument and bind to @ref IP_ANY_TYPE.
 * @param proto the protocol number (next header) of the IPv6 packet payload
 *              (e.g. IP6_NEXTH_ICMP6)
 *
 * @see raw_remove()
 */
struct RawPcb*
raw_new_ip_type(IpAddrType type, uint8_t proto)
{
    struct RawPcb* pcb = raw_new(proto);
    if (pcb != nullptr)
    {
        set_ip_addr_type(pcb->local_ip, type);
        set_ip_addr_type(pcb->remote_ip, type);
    }
    return pcb;
} /** This function is called from netif.c when address is changed
 *
 * @param old_addr IP address of the netif before change
 * @param new_addr IP address of the netif after change
 */
void
raw_netif_ip_addr_changed(const IpAddrInfo* old_addr, const IpAddrInfo* new_addr)
{
    if (!is_ip_addr_any(old_addr) && !is_ip_addr_any(new_addr))
    {
        // for (struct RawPcb* rpcb = raw_pcbs; rpcb != nullptr; rpcb = rpcb->next) {
        //   /* PCB bound to current local interface address? */
        //   if (compare_ip_addr(&rpcb->local_ip, old_addr)) {
        //     /* The PCB is bound to the old ipaddr and
        //      * is set to bound to the new one instead */
        //     copy_ip_addr(rpcb->local_ip, *new_addr);
        //   }
        // }
    }
}
