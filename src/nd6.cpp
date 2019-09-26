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

#define NOMINMAX
#include "netloom_config.h"
#include "nd6.h"
#include "nd6_priv.h"
#include "icmp6.h"
#include "packet.h"
#include "ip6.h"
#include "ip6_addr.h"
#include "inet_chksum.h"
#include "network_interface.h"
#include "mld6.h"
#include "dhcp6.h"
#include "dns.h"

#include <cstring>
#include <algorithm>


/* Router tables. */
struct nd6_neighbor_cache_entry neighbor_cache[LWIP_ND6_NUM_NEIGHBORS];
struct nd6_destination_cache_entry destination_cache[LWIP_ND6_NUM_DESTINATIONS];
struct nd6_prefix_list_entry prefix_list[LWIP_ND6_NUM_PREFIXES];
struct nd6_router_list_entry default_router_list[LWIP_ND6_NUM_ROUTERS];

/* Default values, can be updated by a RA message. */
uint32_t reachable_time = LWIP_ND6_REACHABLE_TIME;
uint32_t retrans_timer = LWIP_ND6_RETRANS_TIMER; /* @todo implement this value in timer */

/* Index for cache entries. */
static uint8_t nd6_cached_neighbor_index;
static size_t nd6_cached_destination_index;

/* Multicast address holder. */
static Ip6Addr multicast_address;
static uint8_t nd6_tmr_rs_reduction;

/* Static buffer to parse RA packet options */
union ra_options
{
    struct LnkLyrAddrOpt lladdr;
    struct MtuOpt mtu;
    struct PrefixOpt prefix;
    struct RdnssOpt rdnss;
};


static union ra_options nd6_ra_buffer;

/* Forward declarations. */
static int8_t nd6_find_neighbor_cache_entry(const Ip6Addr* ip6addr);

static int8_t nd6_new_neighbor_cache_entry(void);

static void nd6_free_neighbor_cache_entry(int8_t i);

static int16_t nd6_find_destination_cache_entry(const Ip6Addr* ip6addr);

static int16_t nd6_new_destination_cache_entry(void);

static int nd6_is_prefix_in_netif(const Ip6Addr* ip6addr, NetworkInterface* netif);

static int8_t nd6_select_router(const Ip6Addr* ip6addr, NetworkInterface* netif);

static int8_t nd6_get_router(const Ip6Addr* router_addr, NetworkInterface* netif);

static int8_t nd6_new_router(const Ip6Addr* router_addr, NetworkInterface* netif);

static int8_t nd6_get_onlink_prefix(const Ip6Addr* prefix, NetworkInterface* netif);

static int8_t nd6_new_onlink_prefix(const Ip6Addr* prefix, NetworkInterface* netif);

static int8_t nd6_get_next_hop_entry(const Ip6Addr* ip6addr, NetworkInterface* netif);

static NsStatus nd6_queue_packet(int8_t neighbor_index, struct PacketContainer* q);


enum Nd6SendFlags
{
    ND6_SEND_FLAG_MULTICAST_DEST = 0x01,
    ND6_SEND_FLAG_ALLNODES_DEST = 0x02,
    ND6_SEND_FLAG_ANY_SRC =0x04,
};


static void nd6_send_ns(NetworkInterface* netif, const Ip6Addr* target_addr, uint8_t flags);

static void nd6_send_na(NetworkInterface* netif, const Ip6Addr* target_addr, uint8_t flags);

static void nd6_send_neighbor_cache_probe(struct nd6_neighbor_cache_entry* entry, uint8_t flags);

static NsStatus nd6_send_rs(NetworkInterface* netif);

static void nd6_free_q(struct nd6_q_entry* q);

static void nd6_send_q(int8_t i);


///
/// A local address has been determined to be a duplicate. Take the appropriate
/// action(s) on the address and the interface as a whole.
///
/// netif: the netif that owns the address
/// addr_idx: the index of the address detected to be a duplicate
///
static void nd6_duplicate_addr_detected(NetworkInterface& netif, int8_t addr_idx)
{
    /* Mark the address as duplicate, but leave its lifetimes alone. If this was
     * a manually assigned address, it will remain in existence as duplicate, and
     * as such be unusable for any practical purposes until manual intervention.
     * If this was an autogenerated address, the address will follow normal
     * expiration rules, and thus disappear once its valid lifetime expires. */
    set_netif_ip6_addr_state(netif, addr_idx, IP6_ADDR_DUPLICATED);
    /* If the affected address was the link-local address that we use to generate
        * all other addresses, then we should not continue to use those derived
        * addresses either, so mark them as duplicate as well. For autoconfig-only
        * setups, this will make the interface effectively unusable, approaching the
        * intention of RFC 4862 Sec. 5.4.5. @todo implement the full requirements */
    if (addr_idx == 0)
    {
        for (int8_t i = 1; i < LWIP_IPV6_NUM_ADDRESSES; i++)
        {
            if (!is_ip6_addr_state_invalid(get_netif_ip6_addr_state(netif, i)) && !
                is_netif_ip6_addr_static(netif, i))
            {
                set_netif_ip6_addr_state(netif, i, IP6_ADDR_DUPLICATED);
            }
        }
    }
}


///
/// We received a router advertisement that contains a prefix with the
/// autoconfiguration flag set. Add or update an associated autogenerated
/// address.
///
/// netif: the netif on which the router advertisement arrived
/// prefix_opt: a pointer to the prefix option data
/// prefix_addr: an aligned copy of the prefix address
///
static void
nd6_process_autoconfig_prefix(NetworkInterface& netif,
                              PrefixOpt& prefix_opt,
                              const Ip6Addr& prefix_addr)
{
    Ip6Addr ip6_addr{};
    Ip6AddrState addr_state;
    int8_t i;

    /// The caller already checks RFC 4862 Sec. 5.5.3 points (a) and (b). We do the rest,
    ///  starting with checks for (c) and (d) here.
    auto valid_life = lwip_htonl(prefix_opt.valid_lifetime);
    auto pref_life = lwip_htonl(prefix_opt.preferred_lifetime);
    if (pref_life > valid_life || prefix_opt.prefix_length != 64) {
        /// silently ignore this prefix for autoconfiguration purposes
        return;
    }

    /// If an autogenerated address already exists for this prefix, update its
    /// lifetimes. An address is considered autogenerated if 1) it is not static
    /// (i.e., manually assigned), and 2) there is an advertised autoconfiguration
    /// prefix for it (the one we are processing here). This does not necessarily
    /// exclude the possibility that the address was actually assigned by, say,
    /// DHCPv6. If that distinction becomes important in the future, more state
    /// must be kept. As explained elsewhere we also update lifetimes of tentative
    /// and duplicate addresses. Skip address slot 0 (the link-local address).
    for (i = 1; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
        // addr_state = netif_ip6_addr_state(netif, i);
        addr_state = netif.ip6_addr_states[i];
        if (addr_state != IP6_ADDR_INVALID && netif.ip6_addr_valid_life[i] != 0 &&
            ip6_addr_on_same_net(prefix_addr, netif.ip6_addresses[i].u_addr.ip6))
        {
            /* Update the valid lifetime, as per RFC 4862 Sec. 5.5.3 point (e).
             * The valid lifetime will never drop to zero as a result of this. */
            const auto remaining_life = netif.ip6_addr_valid_life[i];
            if (valid_life > ND6_2HRS || valid_life > remaining_life) {
                netif.ip6_addr_valid_life[i] = 0;
            }
            else if (remaining_life > ND6_2HRS) {
                netif.ip6_addr_valid_life[i] = ND6_2HRS;
                // netif_ip6_addr_set_valid_life(netif, i, ND6_2HRS);
            }

            /* Update the preferred lifetime. No bounds checks are needed here. In
             * rare cases the advertisement may un-deprecate the address, though.
             * Deprecation is left to the timer code where it is handled anyway. */
            if (pref_life > 0 && addr_state == IP6_ADDR_DEPRECATED) {
                netif.ip6_addr_states[i] = IP6_ADDR_PREFERRED;
            }
            // netif_ip6_addr_set_pref_life(netif, i, pref_life);
            netif.ip6_addr_pref_life[i] = pref_life;
            return; /* there should be at most one matching address */
        }
    }

    /* No autogenerated address exists for this prefix yet. See if we can add a
     * new one. However, if IPv6 autoconfiguration is administratively disabled,
     * do not generate new addresses, but do keep updating lifetimes for existing
     * addresses. Also, when adding new addresses, we must protect explicitly
     * against a valid lifetime of zero, because again, we use that as a special
     * value. The generated address would otherwise expire immediately anyway.
     * Finally, the original link-local address must be usable at all. We start
     * creating addresses even if the link-local address is still in tentative
     * state though, and deal with the fallout of that upon DAD collision. */
    addr_state = get_netif_ip6_addr_state(netif, 0);
    if (netif.ip6_autoconfig_enabled == false || valid_life == (0) ||
        is_ip6_addr_state_invalid(addr_state) || is_ip6_addr_duplicated(addr_state)) {
        return;
    }

    /// Construct the new address that we intend to use, and then see if that
    /// address really does not exist. It might have been added manually, after
    /// all. As a side effect, find a free slot. Note that we cannot use
    /// netif_add_ip6_address() here, as it would return ERR_OK if the address
    /// already did exist, resulting in that address being given lifetimes. */
    set_ip6_addr(ip6_addr,
                 prefix_addr.word[0],
                 prefix_addr.word[1],
                 netif.ip6_addresses[0].u_addr.ip6.word[2],
                 netif.ip6_addresses[0].u_addr.ip6.word[3]);
    assign_ip6_addr_zone(ip6_addr, IP6_UNICAST, netif,);

    int8_t free_idx = 0;
    for (i = 1; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
        if (!is_ip6_addr_state_invalid(get_netif_ip6_addr_state(netif, i))) {
            if (ip6_addr_equal(ip6_addr, netif.ip6_addresses[i].u_addr.ip6)) {
                return; /* formed address already exists */
            }
        }
        else if (free_idx == 0) {
            free_idx = i;
        }
    }
    if (free_idx == 0) {
        return; /* no address slots available, try again on next advertisement */
    }

    /* Assign the new address to the interface. */
    netif.ip6_addresses[free_idx].addr = ip6_addr;
    set_netif_ip6_addr_valid_life(netif, free_idx, valid_life);
    set_netif_ip6_addr_pref_life(netif, free_idx, pref_life);
    set_netif_ip6_addr_state(netif, free_idx, IP6_ADDR_TENTATIVE);
}


/**
 * Process an incoming neighbor discovery message
 *
 * @param p the nd packet, p->payload pointing to the icmpv6 header
 * @param inp the netif on which this packet was received
 */
void
nd6_input(struct PacketContainer* p, NetworkInterface* inp)
{
    uint8_t msg_type;
    int8_t i;
    int16_t dest_idx;

    // ND6_STATS_INC(nd6.recv);

    msg_type = *((uint8_t *)p->payload);
    switch (msg_type) {
    case ICMP6_TYPE_NA: /* Neighbor Advertisement. */
        {
            struct NeighAdvHdr* na_hdr;
            struct LnkLyrAddrOpt* lladdr_opt;
            Ip6Addr target_address;

            /* Check that na header fits in packet. */
            if (p->len < (sizeof(struct NeighAdvHdr))) {
                /* @todo debug message */
                free_pkt_buf(p);
                // ND6_STATS_INC(nd6.lenerr);
                // ND6_STATS_INC(nd6.drop);
                return;
            }

            na_hdr = (struct NeighAdvHdr *)p->payload;

            /* Create an aligned, zoned copy of the target address. */
            ip6_addr_copy_from_packed(&target_address, (&na_hdr->target_address));
            assign_ip6_addr_zone(&target_address, IP6_UNICAST, inp,);

            Ip6Hdr* curr_hdr = nullptr;

            /* Check a subset of the other RFC 4861 Sec. 7.1.2 requirements. */
            if (get_ip6_hdr_hop_limit(curr_hdr) != ND6_HOPLIM || na_hdr->code != 0 ||
                ip6_addr_is_mcast(&target_address)) {
                free_pkt_buf(p);
                // ND6_STATS_INC(nd6.proterr);
                // ND6_STATS_INC(nd6.drop);
                return;
            }

            /* @todo RFC MUST: if IP destination is multicast, Solicited flag is zero */
            /* @todo RFC MUST: all included options have a length greater than zero */

            /* Unsolicited NA?*/
            Ip6Addr* curr_dst_addr = nullptr;
            if (ip6_addr_is_mcast(curr_dst_addr)) {
                /* This is an unsolicited NA.
                 * link-layer changed?
                 * part of DAD mechanism? */


                /* If the target address matches this netif, it is a DAD response. */
                for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
                    if (!is_ip6_addr_state_invalid(get_netif_ip6_addr_state(inp, i)) &&
                        !is_ip6_addr_duplicated(get_netif_ip6_addr_state(inp, i)) &&
                        ip6_addr_equal(&target_address, get_netif_ip6_addr(inp, i))) {
                        /* We are using a duplicate address. */
                        nd6_duplicate_addr_detected(inp, i);

                        free_pkt_buf(p);
                        return;
                    }
                }


                /* Check that link-layer address option also fits in packet. */
                if (p->len < (sizeof(struct NeighAdvHdr) + 2)) {
                    /* @todo debug message */
                    free_pkt_buf(p);
                    return;
                }

                lladdr_opt = reinterpret_cast<struct LnkLyrAddrOpt *>(static_cast<uint8_t*>(p->payload) + sizeof(struct
                    NeighAdvHdr));

                if (p->len < (sizeof(struct NeighAdvHdr) + (lladdr_opt->length << 3))) {
                    /* @todo debug message */
                    free_pkt_buf(p);
                    return;
                }

                /* This is an unsolicited NA, most likely there was a LLADDR change. */
                i = nd6_find_neighbor_cache_entry(&target_address);
                if (i >= 0) {
                    if (na_hdr->flags & ND6_FLAG_OVERRIDE) {
                        memcpy(neighbor_cache[i].lladdr, lladdr_opt->addr, inp->hwaddr_len);
                    }
                }
            }
            else {
                /* This is a solicited NA.
                 * neighbor address resolution response?
                 * neighbor unreachability detection response? */

                /* Find the cache entry corresponding to this na. */
                i = nd6_find_neighbor_cache_entry(&target_address);
                if (i < 0) {
                    /* We no longer care about this target address. drop it. */
                    free_pkt_buf(p);
                    return;
                }

                /* Update cache entry. */
                if ((na_hdr->flags & ND6_FLAG_OVERRIDE) ||
                    (neighbor_cache[i].state == ND6_INCOMPLETE)) {
                    /* Check that link-layer address option also fits in packet. */
                    if (p->len < (sizeof(struct NeighAdvHdr) + 2)) {
                        /* @todo debug message */
                        free_pkt_buf(p);
                        return;
                    }

                    lladdr_opt = (struct LnkLyrAddrOpt *)((uint8_t*)p->payload + sizeof(struct NeighAdvHdr));

                    if (p->len < (sizeof(struct NeighAdvHdr) + (lladdr_opt->length << 3))) {
                        /* @todo debug message */
                        return;
                    }

                    memcpy(neighbor_cache[i].lladdr, lladdr_opt->addr, inp->hwaddr_len);
                }

                neighbor_cache[i].netif = inp;
                neighbor_cache[i].state = ND6_REACHABLE;
                neighbor_cache[i].counter.reachable_time = reachable_time;

                /* Send queued packets, if any. */
                if (neighbor_cache[i].q != nullptr) {
                    nd6_send_q(i);
                }
            }

            break; /* ICMP6_TYPE_NA */
        }
    case ICMP6_TYPE_NS: /* Neighbor solicitation. */
        {
            struct ns_header* ns_hdr;
            struct LnkLyrAddrOpt* lladdr_opt;
            Ip6Addr target_address;
            uint8_t accepted;

            /* Check that ns header fits in packet. */
            if (p->len < sizeof(struct ns_header)) {
                /* @todo debug message */
                free_pkt_buf(p);
                return;
            }

            ns_hdr = (struct ns_header *)p->payload;

            /* Create an aligned, zoned copy of the target address. */
            ip6_addr_copy_from_packed(&target_address, &ns_hdr->target_address);
            assign_ip6_addr_zone(&target_address, IP6_UNICAST, inp,);

            /* Check a subset of the other RFC 4861 Sec. 7.1.1 requirements. */
            Ip6Hdr* curr_ip6_hdr = nullptr;
            if (get_ip6_hdr_hop_limit(curr_ip6_hdr) != ND6_HOPLIM || ns_hdr->code != 0 ||
                ip6_addr_is_mcast(&target_address)) {
                free_pkt_buf(p);
                return;
            }

            /* @todo RFC MUST: all included options have a length greater than zero */
            /* @todo RFC MUST: if IP source is 'any', destination is solicited-node multicast address */
            /* @todo RFC MUST: if IP source is 'any', there is no source LL address option */

            /* Check if there is a link-layer address provided. Only point to it if in this buffer. */
            if (p->len >= (sizeof(struct ns_header) + 2)) {
                lladdr_opt = (struct LnkLyrAddrOpt *)((uint8_t*)p->payload + sizeof(struct ns_header));
                if (p->len < (sizeof(struct ns_header) + (lladdr_opt->length << 3))) {
                    lladdr_opt = nullptr;
                }
            }
            else {
                lladdr_opt = nullptr;
            }

            /* Check if the target address is configured on the receiving netif. */
            accepted = 0;
            Ip6Addr* curr_src_addr = nullptr;
            for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; ++i) {
                if ((ip6_addr_is_valid(get_netif_ip6_addr_state(inp, i)) ||
                        (is_ip6_addr_tentative(get_netif_ip6_addr_state(inp, i)) &&
                            ip6_addr_is_any(curr_src_addr))) &&
                    ip6_addr_equal(&target_address, get_netif_ip6_addr(inp, i))) {
                    accepted = 1;
                    break;
                }
            }

            /* NS not for us? */
            if (!accepted) {
                free_pkt_buf(p);
                return;
            }

            /* Check for ANY address in src (DAD algorithm). */

            if (ip6_addr_is_any(curr_src_addr)) {
                /* Sender is validating this address. */
                for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; ++i) {
                    if (!is_ip6_addr_state_invalid(get_netif_ip6_addr_state(inp, i)) &&
                        ip6_addr_equal(&target_address, get_netif_ip6_addr(inp, i))) {
                        /* Send a NA back so that the sender does not use this address. */
                        nd6_send_na(inp, get_netif_ip6_addr(inp, i), ND6_FLAG_OVERRIDE | ND6_SEND_FLAG_ALLNODES_DEST);
                        if (is_ip6_addr_tentative(get_netif_ip6_addr_state(inp, i))) {
                            /* We shouldn't use this address either. */
                            nd6_duplicate_addr_detected(inp, i);
                        }
                    }
                }
            }
            else {
                /* Sender is trying to resolve our address. */
                /* Verify that they included their own link-layer address. */
                if (lladdr_opt == nullptr) {
                    /* Not a valid message. */
                    free_pkt_buf(p);
                    return;
                }

                i = nd6_find_neighbor_cache_entry(curr_src_addr);
                if (i >= 0) {
                    /* We already have a record for the solicitor. */
                    if (neighbor_cache[i].state == ND6_INCOMPLETE) {
                        neighbor_cache[i].netif = inp;
                        memcpy(neighbor_cache[i].lladdr, lladdr_opt->addr, inp->hwaddr_len);

                        /* Delay probe in case we get confirmation of reachability from upper layer (TCP). */
                        neighbor_cache[i].state = ND6_DELAY;
                        neighbor_cache[i].counter.delay_time = LWIP_ND6_DELAY_FIRST_PROBE_TIME / ND6_TMR_INTERVAL;
                    }
                }
                else {
                    /* Add their IPv6 address and link-layer address to neighbor cache.
                     * We will need it at least to send a unicast NA message, but most
                     * likely we will also be communicating with this node soon. */
                    i = nd6_new_neighbor_cache_entry();
                    if (i < 0) {
                        /* We couldn't assign a cache entry for this neighbor.
                         * we won't be able to reply. drop it. */
                        free_pkt_buf(p);

                        return;
                    }
                    neighbor_cache[i].netif = inp;
                    memcpy(neighbor_cache[i].lladdr, lladdr_opt->addr, inp->hwaddr_len);
                    set_ip6_addr(&(neighbor_cache[i].next_hop_address), curr_src_addr);

                    /* Receiving a message does not prove reachability: only in one direction.
                     * Delay probe in case we get confirmation of reachability from upper layer (TCP). */
                    neighbor_cache[i].state = ND6_DELAY;
                    neighbor_cache[i].counter.delay_time = LWIP_ND6_DELAY_FIRST_PROBE_TIME / ND6_TMR_INTERVAL;
                }

                /* Send back a NA for us. Allocate the reply PacketBuffer. */
                nd6_send_na(inp, &target_address, ND6_FLAG_SOLICITED | ND6_FLAG_OVERRIDE);
            }

            break; /* ICMP6_TYPE_NS */
        }
    case ICMP6_TYPE_RA: /* Router Advertisement. */
        {
            struct ra_header* ra_hdr;
            uint8_t* buffer; /* Used to copy options. */
            uint16_t offset;

            /* There can be multiple RDNSS options per RA */
            uint8_t rdnss_server_idx = 0;


            /* Check that RA header fits in packet. */
            if (p->len < sizeof(struct ra_header)) {
                /* @todo debug message */
                free_pkt_buf(p);

                return;
            }

            ra_hdr = (struct ra_header *)p->payload;

            /* Check a subset of the other RFC 4861 Sec. 6.1.2 requirements. */
            Ip6Addr* curr_src_addr = nullptr;
            Ip6Hdr* curr_hdr = nullptr;
            if (!ip6_addr_is_linklocal(curr_src_addr) ||
                get_ip6_hdr_hop_limit(curr_hdr) != ND6_HOPLIM || ra_hdr->code != 0) {
                free_pkt_buf(p);

                return;
            }

            /* @todo RFC MUST: all included options have a length greater than zero */

            /* If we are sending RS messages, stop. */

            /* ensure at least one solicitation is sent (see RFC 4861, ch. 6.3.7) */
            if ((inp->rtr_solicit_count < LWIP_ND6_MAX_MULTICAST_SOLICIT) ||
                (nd6_send_rs(inp) == STATUS_SUCCESS)) {
                inp->rtr_solicit_count = 0;
            }
            else {
                inp->rtr_solicit_count = 1;
            }


            /* Get the matching default router entry. */
            i = nd6_get_router(curr_src_addr, inp);
            if (i < 0) {
                /* Create a new router entry. */
                i = nd6_new_router(curr_src_addr, inp);
            }

            if (i < 0) {
                /* Could not create a new router entry. */
                free_pkt_buf(p);
                return;
            }

            /* Re-set invalidation timer. */
            default_router_list[i].invalidation_timer = ns_htons(ra_hdr->router_lifetime);

            /* Re-set default timer values. */

            if (ra_hdr->retrans_timer > 0) {
                retrans_timer = lwip_htonl(ra_hdr->retrans_timer);
            }
            if (ra_hdr->reachable_time > 0) {
                reachable_time = lwip_htonl(ra_hdr->reachable_time);
            }


            /* @todo set default hop limit... */
            /* ra_hdr->current_hop_limit;*/

            /* Update flags in local entry (incl. preference). */
            default_router_list[i].flags = ra_hdr->flags;

            /* Trigger DHCPv6 if enabled */
            dhcp6_nd6_ra_trigger(inp,
                                 ra_hdr->flags & ND6_RA_FLAG_MANAGED_ADDR_CONFIG,
                                 ra_hdr->flags & ND6_RA_FLAG_OTHER_CONFIG);


            /* Offset to options. */
            offset = sizeof(struct ra_header);

            /* Process each option. */
            while ((p->tot_len - offset) >= 2) {
                uint8_t option_type;
                uint16_t option_len;
                int option_len8 = get_pbuf_byte_at(p, offset + 1);
                if (option_len8 <= 0) {
                    /* read beyond end or zero length */
                    goto lenerr_drop_free_return;
                }
                option_len = ((uint8_t)option_len8) << 3;
                if (option_len > p->tot_len - offset) {
                    /* short packet (option does not fit in) */
                    goto lenerr_drop_free_return;
                }
                if (p->len == p->tot_len) {
                    /* no need to copy from contiguous PacketBuffer */
                    buffer = &((uint8_t*)p->payload)[offset];
                }
                else {
                    /* check if this option fits into our buffer */
                    if (option_len > sizeof(nd6_ra_buffer)) {
                        option_type = get_pbuf_byte_at(p, offset);
                        /* invalid option length */
                        if (option_type != ND6_OPTION_TYPE_RDNSS) {
                            goto lenerr_drop_free_return;
                        }
                        /* we allow RDNSS option to be longer - we'll just drop some servers */
                        option_len = sizeof(nd6_ra_buffer);
                    }
                    buffer = (uint8_t*)&nd6_ra_buffer;
                    option_len = pbuf_copy_partial(p, (uint8_t*)&nd6_ra_buffer, option_len, offset);
                }
                option_type = buffer[0];
                switch (option_type) {
                case ND6_OPTION_TYPE_SOURCE_LLADDR:
                    {
                        struct LnkLyrAddrOpt* lladdr_opt;
                        if (option_len < sizeof(struct LnkLyrAddrOpt)) {
                            goto lenerr_drop_free_return;
                        }
                        lladdr_opt = (struct LnkLyrAddrOpt *)buffer;
                        if ((default_router_list[i].neighbor_entry != nullptr) &&
                            (default_router_list[i].neighbor_entry->state == ND6_INCOMPLETE)) {
                            memcpy(default_router_list[i].neighbor_entry->lladdr, lladdr_opt->addr, inp->hwaddr_len);
                            default_router_list[i].neighbor_entry->state = ND6_REACHABLE;
                            default_router_list[i].neighbor_entry->counter.reachable_time = reachable_time;
                        }
                        break;
                    }
                case ND6_OPTION_TYPE_MTU:
                    {
                        struct MtuOpt* mtu_opt;
                        uint32_t mtu32;
                        if (option_len < sizeof(struct MtuOpt)) {
                            goto lenerr_drop_free_return;
                        }
                        mtu_opt = (struct MtuOpt *)buffer;
                        mtu32 = lwip_htonl(mtu_opt->mtu);
                        if ((mtu32 >= 1280) && (mtu32 <= 0xffff)) {

                            if (inp->mtu) {
                                /* don't set the mtu for IPv6 higher than the netif driver supports */
                                inp->mtu6 = std::min(inp->mtu, (uint16_t)mtu32);
                            }
                            else {
                                inp->mtu6 = (uint16_t)mtu32;
                            }

                        }
                        break;
                    }
                case ND6_OPTION_TYPE_PREFIX_INFO:
                    {
                        struct PrefixOpt* prefix_opt;
                        Ip6Addr prefix_addr;
                        if (option_len < sizeof(struct PrefixOpt)) {
                            goto lenerr_drop_free_return;
                        }

                        prefix_opt = (struct PrefixOpt *)buffer;

                        /* Get a memory-aligned copy of the prefix. */
                        ip6_addr_copy_from_packed(&prefix_addr, &prefix_opt->prefix);
                        assign_ip6_addr_zone(&prefix_addr, IP6_UNICAST, inp,);

                        if (!ip6_addr_is_linklocal(&prefix_addr)) {
                            if ((prefix_opt->flags & ND6_PREFIX_FLAG_ON_LINK) &&
                                (prefix_opt->prefix_length == 64)) {
                                /* Add to on-link prefix list. */
                                uint32_t valid_life;
                                int8_t prefix;

                                valid_life = lwip_htonl(prefix_opt->valid_lifetime);

                                /* find cache entry for this prefix. */
                                prefix = nd6_get_onlink_prefix(&prefix_addr, inp);
                                if (prefix < 0 && valid_life > 0) {
                                    /* Create a new cache entry. */
                                    prefix = nd6_new_onlink_prefix(&prefix_addr, inp);
                                }
                                if (prefix >= 0) {
                                    prefix_list[prefix].invalidation_timer = valid_life;
                                }
                            }

                            if (prefix_opt->flags & ND6_PREFIX_FLAG_AUTONOMOUS) {
                                /* Perform processing for autoconfiguration. */
                                nd6_process_autoconfig_prefix(inp, prefix_opt, &prefix_addr);
                            }

                        }

                        break;
                    }
                case ND6_OPTION_TYPE_ROUTE_INFO:
                    /* @todo implement preferred routes.
                    struct route_option * route_opt;
                    route_opt = (struct route_option *)buffer;*/

                    break;

                case ND6_OPTION_TYPE_RDNSS:
                    {
                        uint8_t num, n;
                        uint16_t copy_offset = offset + SIZEOF_RDNSS_OPTION_BASE;
                        struct RdnssOpt* rdnss_opt;
                        if (option_len < SIZEOF_RDNSS_OPTION_BASE) {
                            goto lenerr_drop_free_return;
                        }

                        rdnss_opt = (struct RdnssOpt *)buffer;
                        num = (rdnss_opt->length - 1) / 2;
                        for (n = 0; (rdnss_server_idx < DNS_MAX_SERVERS) && (n < num); n++) {
                            IpAddrInfo rdnss_address;

                            /* Copy directly from PacketBuffer to get an aligned, zoned copy of the prefix. */
                            if (pbuf_copy_partial(p, (uint8_t*)&rdnss_address, sizeof(Ip6Addr), copy_offset) == sizeof(
                                Ip6Addr)) {
                                (rdnss_address.type = IP_ADDR_TYPE_V6);
                                assign_ip6_addr_zone((&rdnss_address.u_addr.ip6), IP6_UNKNOWN, inp,);

                                if (pp_htonl(rdnss_opt->lifetime) > 0) {
                                    /* TODO implement Lifetime > 0 */
                                    dns_setserver(&rdnss_address, );
                                }
                                else {
                                    /* TODO implement DNS removal in dns.c */
                                    uint8_t s;
                                    for (s = 0; s < DNS_MAX_SERVERS; s++) {
                                        const IpAddrInfo addr = dns_getserver(s,);
                                        if (ip_addr_eq(&addr, &rdnss_address)) {
                                            dns_setserver(nullptr, );
                                        }
                                    }
                                }
                            }
                        }
                        break;
                    }

                default:
                    /* Unrecognized option, abort. */
                    // ND6_STATS_INC(nd6.proterr);
                    break;
                }
                /* option length is checked earlier to be non-zero to make sure loop ends */
                offset += 8 * (uint8_t)option_len8;
            }

            break; /* ICMP6_TYPE_RA */
        }
    case ICMP6_TYPE_RD: /* Redirect */
        {
            struct RedirectMsgHdr* redir_hdr;
            struct LnkLyrAddrOpt* lladdr_opt;
            Ip6Addr destination_address, target_address;

            /* Check that Redir header fits in packet. */
            if (p->len < sizeof(struct RedirectMsgHdr)) {
                /* @todo debug message */
                free_pkt_buf(p);
                // ND6_STATS_INC(nd6.lenerr);
                // ND6_STATS_INC(nd6.drop);
                return;
            }

            redir_hdr = (struct RedirectMsgHdr *)p->payload;

            /* Create an aligned, zoned copy of the destination address. */
            ip6_addr_copy_from_packed(&destination_address, &redir_hdr->destination_address);
            assign_ip6_addr_zone(&destination_address, IP6_UNICAST, inp,);

            /* Check a subset of the other RFC 4861 Sec. 8.1 requirements. */
            Ip6Addr* curr_src_addr = nullptr;
            Ip6Hdr* curr_hdr = nullptr;
            if (!ip6_addr_is_linklocal(curr_src_addr) ||
                get_ip6_hdr_hop_limit(curr_hdr) != ND6_HOPLIM ||
                redir_hdr->code != 0 || ip6_addr_is_mcast(&destination_address)) {
                free_pkt_buf(p);
                // ND6_STATS_INC(nd6.proterr);
                // ND6_STATS_INC(nd6.drop);
                return;
            }

            /* @todo RFC MUST: IP source address equals first-hop router for destination_address */
            /* @todo RFC MUST: ICMP target address is either link-local address or same as destination_address */
            /* @todo RFC MUST: all included options have a length greater than zero */

            if (p->len >= (sizeof(struct RedirectMsgHdr) + 2)) {
                lladdr_opt = (struct LnkLyrAddrOpt *)((uint8_t*)p->payload + sizeof(struct RedirectMsgHdr));
                if (p->len < (sizeof(struct RedirectMsgHdr) + (lladdr_opt->length << 3))) {
                    lladdr_opt = nullptr;
                }
            }
            else {
                lladdr_opt = nullptr;
            }

            /* Find dest address in cache */
            dest_idx = nd6_find_destination_cache_entry(&destination_address);
            if (dest_idx < 0) {
                /* Destination not in cache, drop packet. */
                free_pkt_buf(p);
                return;
            }

            /* Create an aligned, zoned copy of the target address. */
            ip6_addr_copy_from_packed(&target_address, &redir_hdr->target_address);
            assign_ip6_addr_zone(&target_address, IP6_UNICAST, inp,);

            /* Set the new target address. */
            copy_ip6_addr(&destination_cache[dest_idx].next_hop_addr, &target_address);

            /* If Link-layer address of other router is given, try to add to neighbor cache. */
            if (lladdr_opt != nullptr) {
                if (lladdr_opt->type == ND6_OPTION_TYPE_TARGET_LLADDR) {
                    i = nd6_find_neighbor_cache_entry(&target_address);
                    if (i < 0) {
                        i = nd6_new_neighbor_cache_entry();
                        if (i >= 0) {
                            neighbor_cache[i].netif = inp;
                            memcpy(neighbor_cache[i].lladdr, lladdr_opt->addr, inp->hwaddr_len);
                            copy_ip6_addr(&neighbor_cache[i].next_hop_address, &target_address);

                            /* Receiving a message does not prove reachability: only in one direction.
                             * Delay probe in case we get confirmation of reachability from upper layer (TCP). */
                            neighbor_cache[i].state = ND6_DELAY;
                            neighbor_cache[i].counter.delay_time = LWIP_ND6_DELAY_FIRST_PROBE_TIME / ND6_TMR_INTERVAL;
                        }
                    }
                    if (i >= 0) {
                        if (neighbor_cache[i].state == ND6_INCOMPLETE) {
                            memcpy(neighbor_cache[i].lladdr, lladdr_opt->addr, inp->hwaddr_len);
                            /* Receiving a message does not prove reachability: only in one direction.
                             * Delay probe in case we get confirmation of reachability from upper layer (TCP). */
                            neighbor_cache[i].state = ND6_DELAY;
                            neighbor_cache[i].counter.delay_time = LWIP_ND6_DELAY_FIRST_PROBE_TIME / ND6_TMR_INTERVAL;
                        }
                    }
                }
            }
            break; /* ICMP6_TYPE_RD */
        }
    case ICMP6_TYPE_PTB: /* Packet too big */
        {
            struct Icmp6Hdr* icmp6hdr; /* Packet too big message */
            Ip6Hdr* ip6hdr; /* IPv6 header of the packet which caused the error */
            uint32_t pmtu;
            Ip6Addr destination_address;

            /* Check that ICMPv6 header + IPv6 header fit in payload */
            if (p->len < (sizeof(struct Icmp6Hdr) + IP6_HDR_LEN)) {
                /* drop short packets */
                free_pkt_buf(p);
                // ND6_STATS_INC(nd6.lenerr);
                // ND6_STATS_INC(nd6.drop);
                return;
            }

            icmp6hdr = (struct Icmp6Hdr *)p->payload;
            ip6hdr = (Ip6Hdr *)((uint8_t*)p->payload + sizeof(struct Icmp6Hdr));

            /* Create an aligned, zoned copy of the destination address. */
            ip6_addr_copy_from_packed(&destination_address, &ip6hdr->dest);
            assign_ip6_addr_zone(&destination_address, IP6_UNKNOWN, inp,);

            /* Look for entry in destination cache. */
            dest_idx = nd6_find_destination_cache_entry(&destination_address);
            if (dest_idx < 0) {
                /* Destination not in cache, drop packet. */
                free_pkt_buf(p);
                return;
            }

            /* Change the Path MTU. */
            pmtu = lwip_htonl(icmp6hdr->data);
            destination_cache[dest_idx].pmtu = (uint16_t)std::min((uint16_t)pmtu, (uint16_t)0xFFFF);

            break; /* ICMP6_TYPE_PTB */
        }

    default:
        // ND6_STATS_INC(nd6.proterr);
        // ND6_STATS_INC(nd6.drop);
        break; /* default */
    }

    free_pkt_buf(p);
    return;
lenerr_drop_free_return:
    // ND6_STATS_INC(nd6.lenerr);
    // ND6_STATS_INC(nd6.drop);
    free_pkt_buf(p);
}


/**
 * Periodic timer for Neighbor discovery functions:
 *
 * - Update neighbor reachability states
 * - Update destination cache entries age
 * - Update invalidation timers of default routers and on-link prefixes
 * - Update lifetimes of our addresses
 * - Perform duplicate address detection (DAD) for our addresses
 * - Send router solicitations
 */
void
nd6_tmr(void)
{
    int8_t i;
    NetworkInterface* netif;

    /* Process neighbor entries. */
    for (i = 0; i < LWIP_ND6_NUM_NEIGHBORS; i++) {
        switch (neighbor_cache[i].state) {
        case ND6_INCOMPLETE:
            if ((neighbor_cache[i].counter.probes_sent >= LWIP_ND6_MAX_MULTICAST_SOLICIT) &&
                (!neighbor_cache[i].isrouter)) {
                /* Retries exceeded. */
                nd6_free_neighbor_cache_entry(i);
            }
            else {
                /* Send a NS for this entry. */
                neighbor_cache[i].counter.probes_sent++;
                nd6_send_neighbor_cache_probe(&neighbor_cache[i], ND6_SEND_FLAG_MULTICAST_DEST);
            }
            break;
        case ND6_REACHABLE:
            /* Send queued packets, if any are left. Should have been sent already. */
            if (neighbor_cache[i].q != nullptr) {
                nd6_send_q(i);
            }
            if (neighbor_cache[i].counter.reachable_time <= ND6_TMR_INTERVAL) {
                /* Change to stale state. */
                neighbor_cache[i].state = ND6_STALE;
                neighbor_cache[i].counter.stale_time = 0;
            }
            else {
                neighbor_cache[i].counter.reachable_time -= ND6_TMR_INTERVAL;
            }
            break;
        case ND6_STALE:
            neighbor_cache[i].counter.stale_time++;
            break;
        case ND6_DELAY:
            if (neighbor_cache[i].counter.delay_time <= 1) {
                /* Change to PROBE state. */
                neighbor_cache[i].state = ND6_PROBE;
                neighbor_cache[i].counter.probes_sent = 0;
            }
            else {
                neighbor_cache[i].counter.delay_time--;
            }
            break;
        case ND6_PROBE:
            if ((neighbor_cache[i].counter.probes_sent >= LWIP_ND6_MAX_MULTICAST_SOLICIT) &&
                (!neighbor_cache[i].isrouter)) {
                /* Retries exceeded. */
                nd6_free_neighbor_cache_entry(i);
            }
            else {
                /* Send a NS for this entry. */
                neighbor_cache[i].counter.probes_sent++;
                nd6_send_neighbor_cache_probe(&neighbor_cache[i], 0);
            }
            break;
        case ND6_NO_ENTRY:
        default:
            /* Do nothing. */
            break;
        }
    }

    /* Process destination entries. */
    for (i = 0; i < LWIP_ND6_NUM_DESTINATIONS; i++) {
        destination_cache[i].age++;
    }

    /* Process router entries. */
    for (i = 0; i < LWIP_ND6_NUM_ROUTERS; i++) {
        if (default_router_list[i].neighbor_entry != nullptr) {
            /* Active entry. */
            if (default_router_list[i].invalidation_timer <= ND6_TMR_INTERVAL / 1000) {
                for (int8_t j = 0; j < LWIP_ND6_NUM_DESTINATIONS; j++) {
                    if (ip6_addr_equal(&destination_cache[j].next_hop_addr,
                                          &default_router_list[i].neighbor_entry->next_hop_address)) {
                        set_ip6_addr_any(&destination_cache[j].destination_addr);
                    }
                }
                default_router_list[i].neighbor_entry->isrouter = 0;
                default_router_list[i].neighbor_entry = nullptr;
                default_router_list[i].invalidation_timer = 0;
                default_router_list[i].flags = 0;
            }
            else {
                default_router_list[i].invalidation_timer -= ND6_TMR_INTERVAL / 1000;
            }
        }
    }

    /* Process prefix entries. */
    for (i = 0; i < LWIP_ND6_NUM_PREFIXES; i++) {
        if (prefix_list[i].netif != nullptr) {
            if (prefix_list[i].invalidation_timer <= ND6_TMR_INTERVAL / 1000) {
                /* Entry timed out, remove it */
                prefix_list[i].invalidation_timer = 0;
                prefix_list[i].netif = nullptr;
            }
            else {
                prefix_list[i].invalidation_timer -= ND6_TMR_INTERVAL / 1000;
            }
        }
    }

    /* Process our own addresses, updating address lifetimes and/or DAD state. */
    for ((netif) = netif_list; (netif) != nullptr; (netif) = (netif)->next) {
        for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; ++i) {
            /* Step 1: update address lifetimes (valid and preferred). */
            Ip6AddrState addr_state = get_netif_ip6_addr_state(netif, i);
            /* RFC 4862 is not entirely clear as to whether address lifetimes affect
             * tentative addresses, and is even less clear as to what should happen
             * with duplicate addresses. We choose to track and update lifetimes for
             * both those types, although for different reasons:
             * - for tentative addresses, the line of thought of Sec. 5.7 combined
             *   with the potentially long period that an address may be in tentative
             *   state (due to the interface being down) suggests that lifetimes
             *   should be independent of external factors which would include DAD;
             * - for duplicate addresses, retiring them early could result in a new
             *   but unwanted attempt at marking them as valid, while retiring them
             *   late/never could clog up address slots on the netif.
             * As a result, we may end up expiring addresses of either type here.
             */
            if (!is_ip6_addr_state_invalid(addr_state) &&
                !is_netif_ip6_addr_static(netif, i)) {
                uint32_t life = is_netif_ip6_addr_life_valid(netif, i);
                if (life <= ND6_TMR_INTERVAL / 1000) {
                    /* The address has expired. */
                    set_netif_ip6_addr_valid_life(netif, i, 0);
                    set_netif_ip6_addr_pref_life(netif, i, 0);
                    set_netif_ip6_addr_state(netif, i, IP6_ADDR_INVALID);
                }
                else {
                    if (!is_ip6_addr_life_infinite(life)) {
                        life -= ND6_TMR_INTERVAL / 1000;
                        ns_assert("bad valid lifetime", life != (0));
                        set_netif_ip6_addr_valid_life(netif, i, life);
                    }
                    /* The address is still here. Update the preferred lifetime too. */
                    life = get_netif_Ip6_addr_pref_life(netif, i);
                    if (life <= ND6_TMR_INTERVAL / 1000) {
                        /* This case must also trigger if 'life' was already zero, so as to
                         * deal correctly with advertised preferred-lifetime reductions. */
                        set_netif_ip6_addr_pref_life(netif, i, 0);
                        if (addr_state == IP6_ADDR_PREFERRED)
                            set_netif_ip6_addr_state(netif, i, IP6_ADDR_DEPRECATED);
                    }
                    else if (!is_ip6_addr_life_infinite(life)) {
                        life -= ND6_TMR_INTERVAL / 1000;
                        set_netif_ip6_addr_pref_life(netif, i, life);
                    }
                }
            }
            /* The address state may now have changed, so reobtain it next. */

            /* Step 2: update DAD state. */
            addr_state = get_netif_ip6_addr_state(netif, i);
            if (is_ip6_addr_tentative(addr_state)) {
                if ((addr_state & IP6_ADDR_TENTATIVE_COUNT_MASK) >= 4) {
                    /* No NA received in response. Mark address as valid. For dynamic
                     * addresses with an expired preferred lifetime, the state is set to
                     * deprecated right away. That should almost never happen, though. */
                    addr_state = IP6_ADDR_PREFERRED;

                    if (!is_netif_ip6_addr_static(netif, i) &&
                        get_netif_Ip6_addr_pref_life(netif, i) == 0) {
                        addr_state = IP6_ADDR_DEPRECATED;
                    }

                    set_netif_ip6_addr_state(netif, i, addr_state);
                }
                else if (is_netif_up(netif) && is_netif_link_up(netif)) {
                    /* tentative: set next state by increasing by one */

                    set_netif_ip6_addr_state(netif, i, Ip6AddrState(addr_state + 1));
                    /* Send a NS for this address. Use the unspecified address as source
                     * address in all cases (RFC 4862 Sec. 5.4.2), not in the least
                     * because as it is, we only consider multicast replies for DAD. */
                    nd6_send_ns(netif,
                                get_netif_ip6_addr(netif, i),
                                ND6_SEND_FLAG_MULTICAST_DEST | ND6_SEND_FLAG_ANY_SRC);
                }
            }
        }
    }

    /* Send router solicitation messages, if necessary. */
    if (!nd6_tmr_rs_reduction) {
        nd6_tmr_rs_reduction = (ND6_RTR_SOLICITATION_INTERVAL / ND6_TMR_INTERVAL) - 1;
        for ((netif) = netif_list; (netif) != nullptr; (netif) = (netif)->next) {
            if ((netif->rtr_solicit_count > 0) && is_netif_up(netif) &&
                is_netif_link_up(netif) &&
                !is_ip6_addr_state_invalid(get_netif_ip6_addr_state(netif, 0)) &&
                !is_ip6_addr_duplicated(get_netif_ip6_addr_state(netif, 0))) {
                if (nd6_send_rs(netif) == STATUS_SUCCESS) {
                    netif->rtr_solicit_count--;
                }
            }
        }
    }
    else {
        nd6_tmr_rs_reduction--;
    }
}


/** Send a neighbor solicitation message for a specific neighbor cache entry
 *
 * @param entry the neightbor cache entry for wich to send the message
 * @param flags one of ND6_SEND_FLAG_*
 */
static void
nd6_send_neighbor_cache_probe(struct nd6_neighbor_cache_entry* entry, uint8_t flags)
{
    nd6_send_ns(entry->netif, &entry->next_hop_address, flags);
}


/**
 * Send a neighbor solicitation message
 *
 * @param netif the netif on which to send the message
 * @param target_addr the IPv6 target address for the ND message
 * @param flags one of ND6_SEND_FLAG_*
 */
static void
nd6_send_ns(NetworkInterface* netif, const Ip6Addr* target_addr, uint8_t flags)
{
    Ip6Addr src_addr{};
    uint16_t lladdr_opt_len;

    lwip_assert("target address is required", target_addr != nullptr);

    if (!(flags & ND6_SEND_FLAG_ANY_SRC) &&
        ip6_addr_is_valid(get_netif_ip6_addr_state(netif, 0))) {
        /* Use link-local address as source address. */
        auto netif_src_addr = get_netif_ip6_addr(netif, 0);
        copy_ip6_addr(&src_addr, netif_src_addr);
        /* calculate option length (in 8-byte-blocks) */
        lladdr_opt_len = ((netif->hwaddr_len + 2) + 7) >> 3;
    }
    else {
        set_ip6_addr_any(&src_addr);
        /* Option "MUST NOT be included when the source IP address is the unspecified address." */
        lladdr_opt_len = 0;
    }

    /* Allocate a packet. */
    // struct PacketBuffer* p = pbuf_alloc();
    PacketContainer p = init_pkt_buf()
    if (p == nullptr) {
        // ND6_STATS_INC(nd6.memerr);
        return;
    }

    /* Set fields. */
    struct ns_header* ns_hdr = (struct ns_header *)p->payload;

    ns_hdr->type = ICMP6_TYPE_NS;
    ns_hdr->code = 0;
    ns_hdr->chksum = 0;
    ns_hdr->reserved = 0;
    ip6_addr_copy_to_packed(&ns_hdr->target_address, target_addr);

    if (lladdr_opt_len != 0) {
        struct LnkLyrAddrOpt* lladdr_opt = (struct LnkLyrAddrOpt *)((uint8_t*)p->payload + sizeof(struct ns_header));
        lladdr_opt->type = ND6_OPTION_TYPE_SOURCE_LLADDR;
        lladdr_opt->length = (uint8_t)lladdr_opt_len;
        memcpy(lladdr_opt->addr, netif->hwaddr, netif->hwaddr_len);
    }

    /* Generate the solicited node address for the target address. */
    if (flags & ND6_SEND_FLAG_MULTICAST_DEST) {
        set_ip6_addr_solicited_node(&multicast_address, target_addr->word[3]);
        assign_ip6_addr_zone(&multicast_address, IP6_MULTICAST, netif,);
        target_addr = &multicast_address;
    }

    // IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_ICMP6)
    // {
    //     ns_hdr->chksum = ip6_chksum_pseudo(p,
    //                                        IP6_NEXTH_ICMP6,
    //                                        p->len,
    //                                        src_addr,
    //                                        target_addr);
    // }


    /* Send the packet out. */
    // ND6_STATS_INC(nd6.xmit);
    ip6_output_if(p,
                  &src_addr,
                  target_addr,
                  ND6_HOPLIM,
                  0,
                  IP6_NEXTH_ICMP6,
                  netif);
    free_pkt_buf(p);
}


/**
 * Send a neighbor advertisement message
 *
 * @param netif the netif on which to send the message
 * @param target_addr the IPv6 target address for the ND message
 * @param flags one of ND6_SEND_FLAG_*
 */
static void
nd6_send_na(NetworkInterface* netif, const Ip6Addr* target_addr, uint8_t flags)
{
    const Ip6Addr* dest_addr;
    lwip_assert("target address is required", target_addr != nullptr);

    /* Use link-local address as source address. */
    /* src_addr = netif_ip6_addr(netif, 0); */
    /* Use target address as source address. */
    const Ip6Addr* src_addr = target_addr;

    /* Allocate a packet. */
    uint16_t lladdr_opt_len = ((netif->hwaddr_len + 2) >> 3) + (
        ((netif->hwaddr_len + 2) & 0x07) ? 1 : 0);
    // struct PacketBuffer* p = pbuf_alloc();
    PacketContainer p = init_pkt_buf()
    if (p == nullptr) {
        // ND6_STATS_INC(nd6.memerr);
        return;
    }

    /* Set fields. */
    struct NeighAdvHdr* na_hdr = (struct NeighAdvHdr *)p->payload;
    struct LnkLyrAddrOpt* lladdr_opt = (struct LnkLyrAddrOpt *)((uint8_t*)p->payload +
        sizeof(struct NeighAdvHdr));

    na_hdr->type = ICMP6_TYPE_NA;
    na_hdr->code = 0;
    na_hdr->chksum = 0;
    na_hdr->flags = flags & 0xf0;
    na_hdr->reserved[0] = 0;
    na_hdr->reserved[1] = 0;
    na_hdr->reserved[2] = 0;
    ip6_addr_copy_to_packed(&na_hdr->target_address, target_addr);

    lladdr_opt->type = ND6_OPTION_TYPE_TARGET_LLADDR;
    lladdr_opt->length = (uint8_t)lladdr_opt_len;
    memcpy(lladdr_opt->addr, netif->hwaddr, netif->hwaddr_len);

    /* Generate the solicited node address for the target address. */
    if (flags & ND6_SEND_FLAG_MULTICAST_DEST) {
        set_ip6_addr_solicited_node(&multicast_address, target_addr->word[3]);
        assign_ip6_addr_zone(&multicast_address, IP6_MULTICAST, netif,);
        dest_addr = &multicast_address;
    }
    else if (flags & ND6_SEND_FLAG_ALLNODES_DEST) {
        set_ip6_addr_all_nodes_link_local(&multicast_address);
        assign_ip6_addr_zone(&multicast_address, IP6_MULTICAST, netif,);
        dest_addr = &multicast_address;
    }
    else {
        Ip6Addr* curr_src_addr = nullptr;
        dest_addr = curr_src_addr;
    }

    // IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_ICMP6)
    // {
    //     na_hdr->chksum = ip6_chksum_pseudo(p,
    //                                        IP6_NEXTH_ICMP6,
    //                                        p->len,
    //                                        src_addr,
    //                                        dest_addr);
    // }


    /* Send the packet out. */
    // ND6_STATS_INC(nd6.xmit);
    ip6_output_if(p,
                  src_addr,
                  dest_addr,
                  ND6_HOPLIM,
                  0,
                  IP6_NEXTH_ICMP6,
                  netif);
    free_pkt_buf(p);
}


/**
 * Send a router solicitation message
 *
 * @param netif the netif on which to send the message
 */
static NsStatus
nd6_send_rs(NetworkInterface* netif)
{
    Ip6Addr src_addr{};
    uint16_t lladdr_opt_len = 0;

    /* Link-local source address, or unspecified address? */
    if (ip6_addr_is_valid(get_netif_ip6_addr_state(netif, 0))) {
        auto netif_src_addr = get_netif_ip6_addr(netif, 0);
        copy_ip6_addr(&src_addr, netif_src_addr);
    }
    else {

        src_addr = make_ip6_addr_any();
    }

    /* Generate the all routers target address. */
    set_ip6_addr_all_routers_link_local(&multicast_address);
    assign_ip6_addr_zone(&multicast_address, IP6_MULTICAST, netif,);

    /* Allocate a packet. */
    if (ip6_addr_is_any(&src_addr)) {
        lladdr_opt_len = ((netif->hwaddr_len + 2) >> 3) + (((netif->hwaddr_len + 2) & 0x07) ? 1 : 0);
    }
    // struct PacketBuffer* p = pbuf_alloc();
    PacketContainer p = init_pkt_buf()
    if (p == nullptr) {
        // ND6_STATS_INC(nd6.memerr);
        return ERR_BUF;
    }

    /* Set fields. */
    struct RtrSolicitHdr* rs_hdr = (struct RtrSolicitHdr *)p->payload;

    rs_hdr->type = ICMP6_TYPE_RS;
    rs_hdr->code = 0;
    rs_hdr->chksum = 0;
    rs_hdr->reserved = 0;

    if (!(ip6_addr_is_any(&src_addr))) {
        /* Include our hw address. */
        struct LnkLyrAddrOpt* lladdr_opt = (struct LnkLyrAddrOpt *)((uint8_t*)p->payload +
            sizeof(struct RtrSolicitHdr));
        lladdr_opt->type = ND6_OPTION_TYPE_SOURCE_LLADDR;
        lladdr_opt->length = (uint8_t)lladdr_opt_len;
        memcpy(lladdr_opt->addr, netif->hwaddr, netif->hwaddr_len);
    }


    // IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_ICMP6)
    // {
    //     rs_hdr->chksum = ip6_chksum_pseudo(p,
    //                                        IP6_NEXTH_ICMP6,
    //                                        p->len,
    //                                        src_addr,
    //                                        &multicast_address);
    // }


    /* Send the packet out. */
    // ND6_STATS_INC(nd6.xmit);

    NsStatus err = ip6_output_if(p,
                                   (ip6_addr_is_any(&src_addr)) ? nullptr : &src_addr,
                                   &multicast_address,
                                   ND6_HOPLIM,
                                   0,
                                   IP6_NEXTH_ICMP6,
                                   netif);
    free_pkt_buf(p);

    return err;
}


/**
 * Search for a neighbor cache entry
 *
 * @param ip6addr the IPv6 address of the neighbor
 * @return The neighbor cache entry index that matched, -1 if no
 * entry is found
 */
static int8_t
nd6_find_neighbor_cache_entry(const Ip6Addr* ip6addr)
{
    for (int8_t i = 0; i < LWIP_ND6_NUM_NEIGHBORS; i++) {
        if (ip6_addr_equal(ip6addr, &(neighbor_cache[i].next_hop_address))) {
            return i;
        }
    }
    return -1;
}


/**
 * Create a new neighbor cache entry.
 *
 * If no unused entry is found, will try to recycle an old entry
 * according to ad-hoc "age" heuristic.
 *
 * @return The neighbor cache entry index that was created, -1 if no
 * entry could be created
 */
static int8_t
nd6_new_neighbor_cache_entry(void)
{
    int8_t i; /* First, try to find an empty entry. */
    for (i = 0; i < LWIP_ND6_NUM_NEIGHBORS; i++) {
        if (neighbor_cache[i].state == ND6_NO_ENTRY) {
            return i;
        }
    }

    /* We need to recycle an entry. in general, do not recycle if it is a router. */

    /* Next, try to find a Stale entry. */
    for (i = 0; i < LWIP_ND6_NUM_NEIGHBORS; i++) {
        if ((neighbor_cache[i].state == ND6_STALE) &&
            (!neighbor_cache[i].isrouter)) {
            nd6_free_neighbor_cache_entry(i);
            return i;
        }
    }

    /* Next, try to find a Probe entry. */
    for (i = 0; i < LWIP_ND6_NUM_NEIGHBORS; i++) {
        if ((neighbor_cache[i].state == ND6_PROBE) &&
            (!neighbor_cache[i].isrouter)) {
            nd6_free_neighbor_cache_entry(i);
            return i;
        }
    }

    /* Next, try to find a Delayed entry. */
    for (i = 0; i < LWIP_ND6_NUM_NEIGHBORS; i++) {
        if ((neighbor_cache[i].state == ND6_DELAY) &&
            (!neighbor_cache[i].isrouter)) {
            nd6_free_neighbor_cache_entry(i);
            return i;
        }
    }

    /* Next, try to find the oldest reachable entry. */
    uint32_t time = 0xfffffffful;
    int8_t j = -1;
    for (i = 0; i < LWIP_ND6_NUM_NEIGHBORS; i++) {
        if ((neighbor_cache[i].state == ND6_REACHABLE) &&
            (!neighbor_cache[i].isrouter)) {
            if (neighbor_cache[i].counter.reachable_time < time) {
                j = i;
                time = neighbor_cache[i].counter.reachable_time;
            }
        }
    }
    if (j >= 0) {
        nd6_free_neighbor_cache_entry(j);
        return j;
    }

    /* Next, find oldest incomplete entry without queued packets. */
    time = 0;
    j = -1;
    for (i = 0; i < LWIP_ND6_NUM_NEIGHBORS; i++) {
        if (
            (neighbor_cache[i].q == nullptr) &&
            (neighbor_cache[i].state == ND6_INCOMPLETE) &&
            (!neighbor_cache[i].isrouter)) {
            if (neighbor_cache[i].counter.probes_sent >= time) {
                j = i;
                time = neighbor_cache[i].counter.probes_sent;
            }
        }
    }
    if (j >= 0) {
        nd6_free_neighbor_cache_entry(j);
        return j;
    }

    /* Next, find oldest incomplete entry with queued packets. */
    time = 0;
    j = -1;
    for (i = 0; i < LWIP_ND6_NUM_NEIGHBORS; i++) {
        if ((neighbor_cache[i].state == ND6_INCOMPLETE) &&
            (!neighbor_cache[i].isrouter)) {
            if (neighbor_cache[i].counter.probes_sent >= time) {
                j = i;
                time = neighbor_cache[i].counter.probes_sent;
            }
        }
    }
    if (j >= 0) {
        nd6_free_neighbor_cache_entry(j);
        return j;
    }

    /* No more entries to try. */
    return -1;
}


/**
 * Will free any resources associated with a neighbor cache
 * entry, and will mark it as unused.
 *
 * @param i the neighbor cache entry index to free
 */
static void
nd6_free_neighbor_cache_entry(int8_t i)
{
    if ((i < 0) || (i >= LWIP_ND6_NUM_NEIGHBORS)) {
        return;
    }
    if (neighbor_cache[i].isrouter) {
        /* isrouter needs to be cleared before deleting a neighbor cache entry */
        return;
    }

    /* Free any queued packets. */
    if (neighbor_cache[i].q != nullptr) {
        nd6_free_q(neighbor_cache[i].q);
        neighbor_cache[i].q = nullptr;
    }

    neighbor_cache[i].state = ND6_NO_ENTRY;
    neighbor_cache[i].isrouter = 0;
    neighbor_cache[i].netif = nullptr;
    neighbor_cache[i].counter.reachable_time = 0;
    ip6_addr_zero(&(neighbor_cache[i].next_hop_address));
}


/**
 * Search for a destination cache entry
 *
 * @param ip6addr the IPv6 address of the destination
 * @return The destination cache entry index that matched, -1 if no
 * entry is found
 */
static int16_t
nd6_find_destination_cache_entry(const Ip6Addr* ip6addr)
{

    for (int16_t i = 0; i < LWIP_ND6_NUM_DESTINATIONS; i++) {
        if (ip6_addr_equal(ip6addr, &(destination_cache[i].destination_addr))) {
            return i;
        }
    }
    return -1;
}


/**
 * Create a new destination cache entry. If no unused entry is found,
 * will recycle oldest entry.
 *
 * @return The destination cache entry index that was created, -1 if no
 * entry was created
 */
static int16_t
nd6_new_destination_cache_entry(void)
{
    int16_t i; /* Find an empty entry. */
    for (i = 0; i < LWIP_ND6_NUM_DESTINATIONS; i++) {
        if (ip6_addr_is_any(&(destination_cache[i].destination_addr))) {
            return i;
        }
    }

    /* Find oldest entry. */
    uint32_t age = 0;
    int16_t j = LWIP_ND6_NUM_DESTINATIONS - 1;
    for (i = 0; i < LWIP_ND6_NUM_DESTINATIONS; i++) {
        if (destination_cache[i].age > age) {
            j = i;
        }
    }

    return j;
}


/**
 * Clear the destination cache.
 *
 * This operation may be necessary for consistency in the light of changing
 * local addresses and/or use of the gateway hook.
 */
void
nd6_clear_destination_cache(void)
{
    for (int i = 0; i < LWIP_ND6_NUM_DESTINATIONS; i++) {
        set_ip6_addr_any(&destination_cache[i].destination_addr);
    }
}


/**
 * Determine whether an address matches an on-link prefix or the subnet of a
 * statically assigned address.
 *
 * @param ip6addr the IPv6 address to match
 * @return 1 if the address is on-link, 0 otherwise
 */
static int
nd6_is_prefix_in_netif(const Ip6Addr* ip6addr, NetworkInterface* netif)
{
    int8_t i;

    /* Check to see if the address matches an on-link prefix. */
    for (i = 0; i < LWIP_ND6_NUM_PREFIXES; i++) {
        if ((prefix_list[i].netif == netif) &&
            (prefix_list[i].invalidation_timer > 0) &&
            ip6_addr_on_same_net(ip6addr, &(prefix_list[i].prefix))) {
            return 1;
        }
    }
    /* Check to see if address prefix matches a manually configured (= static)
     * address. Static addresses have an implied /64 subnet assignment. Dynamic
     * addresses (from autoconfiguration) have no implied subnet assignment, and
     * are thus effectively /128 assignments. See RFC 5942 for more on this. */
    for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
        if (ip6_addr_is_valid(get_netif_ip6_addr_state(netif, i)) &&
            is_netif_ip6_addr_static(netif, i) &&
            ip6_addr_on_same_net(ip6addr, get_netif_ip6_addr(netif, i))) {
            return 1;
        }
    }
    return 0;
}


/**
 * Select a default router for a destination.
 *
 * This function is used both for routing and for finding a next-hop target for
 * a packet. In the former case, the given netif is NULL, and the returned
 * router entry must be for a netif suitable for sending packets (up, link up).
 * In the latter case, the given netif is not NULL and restricts router choice.
 *
 * @param ip6addr the destination address
 * @param netif the netif for the outgoing packet, if known
 * @return the default router entry index, or -1 if no suitable
 *         router is found
 */
static int8_t
nd6_select_router(const Ip6Addr* ip6addr, NetworkInterface* netif)
{
    NetworkInterface* router_netif;
    int8_t i;
    static int8_t last_router;


    /* @todo: implement default router preference */

    /* Look for valid routers. A reachable router is preferred. */
    int8_t valid_router = -1;
    for (i = 0; i < LWIP_ND6_NUM_ROUTERS; i++) {
        /* Is the router netif both set and apppropriate? */
        if (default_router_list[i].neighbor_entry != nullptr) {
            router_netif = default_router_list[i].neighbor_entry->netif;
            if ((router_netif != nullptr) && (netif != nullptr
                                                  ? netif == router_netif
                                                  : (is_netif_up(router_netif) && is_netif_link_up(router_netif)))) {
                /* Is the router valid, i.e., reachable or probably reachable as per
                 * RFC 4861 Sec. 6.3.6? Note that we will never return a router that
                 * has no neighbor cache entry, due to the netif association tests. */
                if (default_router_list[i].neighbor_entry->state != ND6_INCOMPLETE) {
                    /* Is the router known to be reachable? */
                    if (default_router_list[i].neighbor_entry->state == ND6_REACHABLE) {
                        return i; /* valid and reachable - done! */
                    }
                    else if (valid_router < 0) {
                        valid_router = i; /* valid but not known to be reachable */
                    }
                }
            }
        }
    }
    if (valid_router >= 0) {
        return valid_router;
    }

    /* Look for any router for which we have any information at all. */
    /* last_router is used for round-robin selection of incomplete routers, as
     * recommended in RFC 4861 Sec. 6.3.6 point (2). Advance only when picking a
     * route, to select the same router as next-hop target in the common case. */
    if ((netif == nullptr) && (++last_router >= LWIP_ND6_NUM_ROUTERS)) {
        last_router = 0;
    }
    i = last_router;
    for (int8_t j = 0; j < LWIP_ND6_NUM_ROUTERS; j++) {
        if (default_router_list[i].neighbor_entry != nullptr) {
            router_netif = default_router_list[i].neighbor_entry->netif;
            if ((router_netif != nullptr) && (netif != nullptr
                                                  ? netif == router_netif
                                                  : (is_netif_up(router_netif) && is_netif_link_up(router_netif)))) {
                return i;
            }
        }
        if (++i >= LWIP_ND6_NUM_ROUTERS) {
            i = 0;
        }
    }

    /* no suitable router found. */
    return -1;
}


/**
 * Find a router-announced route to the given destination. This route may be
 * based on an on-link prefix or a default router.
 *
 * If a suitable route is found, the returned netif is guaranteed to be in a
 * suitable state (up, link up) to be used for packet transmission.
 *
 * @param addr_info the destination IPv6 address
 * @return the netif to use for the destination, or NULL if none found
 */
NsStatus
nd6_find_route(const Ip6AddrInfo& addr_info, NetworkInterface& out_addr)
{
    int8_t i;

    /* @todo decide if it makes sense to check the destination cache first */

    /* Check if there is a matching on-link prefix. There may be multiple
     * matches. Pick the first one that is associated with a suitable netif. */
    for (i = 0; i < LWIP_ND6_NUM_PREFIXES; ++i) {
        NetworkInterface* netif = prefix_list[i].netif;
        if ((netif != nullptr) && ip6_addr_on_same_net(&prefix_list[i].prefix, addr_info) &&
            is_netif_up(netif) && is_netif_link_up(netif)) {
            return netif;
        }
    }

    /* No on-link prefix match. Find a router that can forward the packet. */
    i = nd6_select_router(addr_info, nullptr);
    if (i >= 0) {
        ns_assert("selected router must have a neighbor entry",
                    default_router_list[i].neighbor_entry != nullptr);
        return default_router_list[i].neighbor_entry->netif;
    }

    return nullptr;
}


/**
 * Find an entry for a default router.
 *
 * @param router_addr the IPv6 address of the router
 * @param netif the netif on which the router is found, if known
 * @return the index of the router entry, or -1 if not found
 */
static int8_t
nd6_get_router(const Ip6Addr* router_addr, NetworkInterface* netif)
{
    // IP6_ADDR_ZONECHECK_NETIF(router_addr, netif);

    /* Look for router. */
    for (int8_t i = 0; i < LWIP_ND6_NUM_ROUTERS; i++) {
        if ((default_router_list[i].neighbor_entry != nullptr) &&
            ((netif != nullptr) ? netif == default_router_list[i].neighbor_entry->netif : 1) &&
            ip6_addr_equal(router_addr, &(default_router_list[i].neighbor_entry->next_hop_address))) {
            return i;
        }
    }

    /* router not found. */
    return -1;
}


/**
 * Create a new entry for a default router.
 *
 * @param router_addr the IPv6 address of the router
 * @param netif the netif on which the router is connected, if known
 * @return the index on the router table, or -1 if could not be created
 */
static int8_t
nd6_new_router(const Ip6Addr* router_addr, NetworkInterface* netif)
{
    // IP6_ADDR_ZONECHECK_NETIF(router_addr, netif);

    /* Do we have a neighbor entry for this router? */
    int8_t neighbor_index = nd6_find_neighbor_cache_entry(router_addr);
    if (neighbor_index < 0) {
        /* Create a neighbor entry for this router. */
        neighbor_index = nd6_new_neighbor_cache_entry();
        if (neighbor_index < 0) {
            /* Could not create neighbor entry for this router. */
            return -1;
        }
        set_ip6_addr(&(neighbor_cache[neighbor_index].next_hop_address), router_addr);
        neighbor_cache[neighbor_index].netif = netif;
        neighbor_cache[neighbor_index].q = nullptr;
        neighbor_cache[neighbor_index].state = ND6_INCOMPLETE;
        neighbor_cache[neighbor_index].counter.probes_sent = 1;
        nd6_send_neighbor_cache_probe(&neighbor_cache[neighbor_index], ND6_SEND_FLAG_MULTICAST_DEST);
    }

    /* Mark neighbor as router. */
    neighbor_cache[neighbor_index].isrouter = 1;

    /* Look for empty entry. */
    int8_t free_router_index = LWIP_ND6_NUM_ROUTERS;
    for (int8_t router_index = LWIP_ND6_NUM_ROUTERS - 1; router_index >= 0; router_index--) {
        /* check if router already exists (this is a special case for 2 netifs on the same subnet
           - e.g. wifi and cable) */
        if (default_router_list[router_index].neighbor_entry == &(neighbor_cache[neighbor_index])) {
            return router_index;
        }
        if (default_router_list[router_index].neighbor_entry == nullptr) {
            /* remember lowest free index to create a new entry */
            free_router_index = router_index;
        }
    }
    if (free_router_index < LWIP_ND6_NUM_ROUTERS) {
        default_router_list[free_router_index].neighbor_entry = &(neighbor_cache[neighbor_index]);
        return free_router_index;
    }

    /* Could not create a router entry. */

    /* Mark neighbor entry as not-router. Entry might be useful as neighbor still. */
    neighbor_cache[neighbor_index].isrouter = 0;

    /* router not found. */
    return -1;
}


/**
 * Find the cached entry for an on-link prefix.
 *
 * @param prefix the IPv6 prefix that is on-link
 * @param netif the netif on which the prefix is on-link
 * @return the index on the prefix table, or -1 if not found
 */
static int8_t
nd6_get_onlink_prefix(const Ip6Addr* prefix, NetworkInterface* netif)
{
    /* Look for prefix in list. */
    for (int8_t i = 0; i < LWIP_ND6_NUM_PREFIXES; ++i) {
        if ((ip6_addr_on_same_net(&(prefix_list[i].prefix), prefix)) &&
            (prefix_list[i].netif == netif)) {
            return i;
        }
    }

    /* Entry not available. */
    return -1;
}


/**
 * Creates a new entry for an on-link prefix.
 *
 * @param prefix the IPv6 prefix that is on-link
 * @param netif the netif on which the prefix is on-link
 * @return the index on the prefix table, or -1 if not created
 */
static int8_t
nd6_new_onlink_prefix(const Ip6Addr* prefix, NetworkInterface* netif)
{
    /* Create new entry. */
    for (int8_t i = 0; i < LWIP_ND6_NUM_PREFIXES; ++i) {
        if ((prefix_list[i].netif == nullptr) ||
            (prefix_list[i].invalidation_timer == 0)) {
            /* Found empty prefix entry. */
            prefix_list[i].netif = netif;
            set_ip6_addr(&(prefix_list[i].prefix), prefix);
            return i;
        }
    }

    /* Entry not available. */
    return -1;
}


/**
 * Determine the next hop for a destination. Will determine if the
 * destination is on-link, else a suitable on-link router is selected.
 *
 * The last entry index is cached for fast entry search.
 *
 * @param ip6addr the destination address
 * @param netif the netif on which the packet will be sent
 * @return the neighbor cache entry for the next hop, ERR_RTE if no
 *         suitable next hop was found, ERR_MEM if no cache entry
 *         could be created
 */
static int8_t
nd6_get_next_hop_entry(const Ip6Addr* ip6addr, NetworkInterface* netif)
{
    const Ip6Addr* next_hop_addr;

    int8_t i;
    // IP6_ADDR_ZONECHECK_NETIF(ip6addr, netif);


    if (netif->hints != nullptr) {
        /* per-pcb cached entry was given */
        size_t addr_hint = netif->hints->addr_hint;
        if (addr_hint < LWIP_ND6_NUM_DESTINATIONS) {
            nd6_cached_destination_index = addr_hint;
        }
    }


    /* Look for ip6addr in destination cache. */
    if (ip6_addr_equal(ip6addr, &(destination_cache[nd6_cached_destination_index].destination_addr))) {
        /* the cached entry index is the right one! */
        /* do nothing. */
        // ND6_STATS_INC(nd6.cachehit);
    }
    else {
        /* Search destination cache. */
        int16_t dst_idx = nd6_find_destination_cache_entry(ip6addr);
        if (dst_idx >= 0) {
            /* found destination entry. make it our new cached index. */
            lwip_assert("type overflow", (size_t)dst_idx < NETIF_ADDR_IDX_MAX);
            nd6_cached_destination_index = (size_t)dst_idx;
        }
        else {
            /* Not found. Create a new destination entry. */
            dst_idx = nd6_new_destination_cache_entry();
            if (dst_idx >= 0) {
                /* got new destination entry. make it our new cached index. */
                lwip_assert("type overflow", (size_t)dst_idx < NETIF_ADDR_IDX_MAX);
                nd6_cached_destination_index = (size_t)dst_idx;
            }
            else {
                /* Could not create a destination cache entry. */
                return STATUS_E_MEM;
            }

            /* Copy dest address to destination cache. */
            set_ip6_addr(&(destination_cache[nd6_cached_destination_index].destination_addr), ip6addr);

            /* Now find the next hop. is it a neighbor? */
            if (ip6_addr_is_linklocal(ip6addr) ||
                nd6_is_prefix_in_netif(ip6addr, netif)) {
                /* Destination in local link. */
                destination_cache[nd6_cached_destination_index].pmtu = get_netif_mtu6(netif);
                copy_ip6_addr(&destination_cache[nd6_cached_destination_index].next_hop_addr,
                              &destination_cache[nd6_cached_destination_index].destination_addr);

            }
            // else if ((next_hop_addr = LWIP_HOOK_ND6_GET_GW(netif, ip6addr)) != NULL) {
            //     /* Next hop for destination provided by hook function. */
            //     destination_cache[nd6_cached_destination_index].pmtu = netif->mtu;
            //     ip6_addr_set(&destination_cache[nd6_cached_destination_index].next_hop_addr, next_hop_addr);
            //
            // }
            else {
                /* We need to select a router. */
                i = nd6_select_router(ip6addr, netif);
                if (i < 0) {
                    /* No router found. */
                    set_ip6_addr_any(&(destination_cache[nd6_cached_destination_index].destination_addr));
                    return STATUS_E_ROUTING;
                }
                destination_cache[nd6_cached_destination_index].pmtu = get_netif_mtu6(netif);
                /* Start with netif mtu, correct through ICMPv6 if necessary */
                copy_ip6_addr(&destination_cache[nd6_cached_destination_index].next_hop_addr,
                              &default_router_list[i].neighbor_entry->next_hop_address);
            }
        }
    }


    if (netif->hints != nullptr) {
        /* per-pcb cached entry was given */
        netif->hints->addr_hint = nd6_cached_destination_index;
    }


    /* Look in neighbor cache for the next-hop address. */
    if (ip6_addr_equal(&(destination_cache[nd6_cached_destination_index].next_hop_addr),
                          &(neighbor_cache[nd6_cached_neighbor_index].next_hop_address))) {
        /* Cache hit. */
        /* Do nothing. */
        // ND6_STATS_INC(nd6.cachehit);
    }
    else {
        i = nd6_find_neighbor_cache_entry(&(destination_cache[nd6_cached_destination_index].next_hop_addr));
        if (i >= 0) {
            /* Found a matching record, make it new cached entry. */
            nd6_cached_neighbor_index = i;
        }
        else {
            /* Neighbor not in cache. Make a new entry. */
            i = nd6_new_neighbor_cache_entry();
            if (i >= 0) {
                /* got new neighbor entry. make it our new cached index. */
                nd6_cached_neighbor_index = i;
            }
            else {
                /* Could not create a neighbor cache entry. */
                return STATUS_E_MEM;
            }

            /* Initialize fields. */
            copy_ip6_addr(&neighbor_cache[i].next_hop_address,
                          &destination_cache[nd6_cached_destination_index].next_hop_addr);
            neighbor_cache[i].isrouter = 0;
            neighbor_cache[i].netif = netif;
            neighbor_cache[i].state = ND6_INCOMPLETE;
            neighbor_cache[i].counter.probes_sent = 1;
            nd6_send_neighbor_cache_probe(&neighbor_cache[i], ND6_SEND_FLAG_MULTICAST_DEST);
        }
    }

    /* Reset this destination's age. */
    destination_cache[nd6_cached_destination_index].age = 0;

    return nd6_cached_neighbor_index;
}


/**
 * Queue a packet for a neighbor.
 *
 * @param neighbor_index the index in the neighbor cache table
 * @param q packet to be queued
 * @return ERR_OK if succeeded, ERR_MEM if out of memory
 */
static NsStatus
nd6_queue_packet(int8_t neighbor_index, struct PacketContainer* q)
{
    NsStatus result = STATUS_E_MEM;
    int copy_needed = 0;

    struct nd6_q_entry*r;


    if ((neighbor_index < 0) || (neighbor_index >= LWIP_ND6_NUM_NEIGHBORS)) {
        return STATUS_E_INVALID_ARG;
    }

    /* IF q includes a PacketBuffer that must be copied, we have to copy the whole chain
     * into a new PBUF_RAM. See the definition of PBUF_NEEDS_COPY for details. */
    struct PacketContainer* p = q;
    while (p) {
        // if (PBUF_NEEDS_COPY(p)) {
        //     copy_needed = 1;
        //     break;
        // }
        p = p->next;
    }
    if (copy_needed) {
        /* copy the whole packet into new pbufs */
        p = pbuf_clone(q);
        while ((p == nullptr) && (neighbor_cache[neighbor_index].q != nullptr)) {
            /* Free oldest packet (as per RFC recommendation) */

            r = neighbor_cache[neighbor_index].q;
            neighbor_cache[neighbor_index].q = r->next;
            r->next = nullptr;
            nd6_free_q(r);

            p = pbuf_clone(q);
        }
    }
    else {
        /* referencing the old PacketBuffer is enough */
        p = q;
        // pbuf_ref(p);
    }
    /* packet was copied/ref'd? */
    if (p != nullptr) {
        /* queue packet ... */

        /* allocate a new nd6 queue entry */
        // new_entry = (struct nd6_q_entry *)memp_malloc(MEMP_ND6_QUEUE);
        struct nd6_q_entry* new_entry = new nd6_q_entry;
        if ((new_entry == nullptr) && (neighbor_cache[neighbor_index].q != nullptr)) {
            /* Free oldest packet (as per RFC recommendation) */
            r = neighbor_cache[neighbor_index].q;
            neighbor_cache[neighbor_index].q = r->next;
            r->next = nullptr;
            nd6_free_q(r);
            // new_entry = (struct nd6_q_entry *)memp_malloc(MEMP_ND6_QUEUE);
            new_entry = new nd6_q_entry;
        }
        if (new_entry != nullptr) {
            new_entry->next = nullptr;
            new_entry->p = p;
            if (neighbor_cache[neighbor_index].q != nullptr) {
                /* queue was already existent, append the new entry to the end */
                r = neighbor_cache[neighbor_index].q;
                while (r->next != nullptr) {
                    r = r->next;
                }
                r->next = new_entry;
            }
            else {
                /* queue did not exist, first item in queue */
                neighbor_cache[neighbor_index].q = new_entry;
            }
            Logf(LWIP_DBG_TRACE,
                 "ipv6: queued packet %p on neighbor entry %d\n", (uint8_t *)p, (int16_t)neighbor_index);
            result = STATUS_SUCCESS;
        }
        else {
            /* the pool MEMP_ND6_QUEUE is empty */
            free_pkt_buf(p);
            Logf(LWIP_DBG_TRACE, "ipv6: could not queue a copy of packet %p (out of memory)\n", (uint8_t *)p);
            /* { result == ERR_MEM } through initialization */
        }

    }
    else {
        Logf(LWIP_DBG_TRACE, "ipv6: could not queue a copy of packet %p (out of memory)\n", (uint8_t *)q
        );
        /* { result == ERR_MEM } through initialization */
    }

    return result;
}


/**
 * Free a complete queue of nd6 q entries
 *
 * @param q a queue of nd6_q_entry to free
 */
static void
nd6_free_q(struct nd6_q_entry* q)
{
    ns_assert("q != NULL", q != nullptr);
    ns_assert("q->p != NULL", q->p != nullptr);
    while (q) {
        struct nd6_q_entry* r = q;
        q = q->next;
        ns_assert("r->p != NULL", (r->p != nullptr));
        free_pkt_buf(r->p);
        delete r;
    }
}


/**
 * Send queued packets for a neighbor
 *
 * @param i the neighbor to send packets to
 */
static void
nd6_send_q(int8_t i)
{
    Ip6Addr dest;
    if ((i < 0) || (i >= LWIP_ND6_NUM_NEIGHBORS)) {
        return;
    }


    while (neighbor_cache[i].q != nullptr) {
        /* remember first in queue */
        struct nd6_q_entry* q = neighbor_cache[i].q;
        /* pop first item off the queue */
        neighbor_cache[i].q = q->next;
        /* Get ipv6 header. */
        Ip6Hdr* ip6hdr = (Ip6Hdr *)(q->p->payload);
        /* Create an aligned copy. */
        ip6_addr_copy_from_packed(&dest, &ip6hdr->dest);
        /* Restore the zone, if applicable. */
        assign_ip6_addr_zone(&dest, IP6_UNKNOWN, neighbor_cache[i].netif,);
        /* send the queued IPv6 packet */
        (neighbor_cache[i].netif)->output_ip6(neighbor_cache[i].netif, q->p, &dest);
        /* free the queued IP packet */
        free_pkt_buf(q->p);
        /* now queue entry can be freed */
        // memp_free(MEMP_ND6_QUEUE, q);
        delete q;
    }
}


/**
 * A packet is to be transmitted to a specific IPv6 destination on a specific
 * interface. Check if we can find the hardware address of the next hop to use
 * for the packet. If so, give the hardware address to the caller, which should
 * use it to send the packet right away. Otherwise, enqueue the packet for
 * later transmission while looking up the hardware address, if possible.
 *
 * As such, this function returns one of three different possible results:
 *
 * - ERR_OK with a non-NULL 'hwaddrp': the caller should send the packet now.
 * - ERR_OK with a NULL 'hwaddrp': the packet has been enqueued for later.
 * - not ERR_OK: something went wrong; forward the error upward in the stack.
 *
 * @param netif The lwIP network interface on which the IP packet will be sent.
 * @param q The PacketBuffer(s) containing the IP packet to be sent.
 * @param ip6addr The destination IPv6 address of the packet.
 * @param hwaddrp On success, filled with a pointer to a HW address or NULL (meaning
 *        the packet has been queued).
 * @return
 * - ERR_OK on success, ERR_RTE if no route was found for the packet,
 * or ERR_MEM if low memory conditions prohibit sending the packet at all.
 */
NsStatus
nd6_get_next_hop_addr_or_queue(NetworkInterface* netif,
                               struct PacketContainer* q,
                               const Ip6Addr* ip6addr,
                               const uint8_t** hwaddrp)
{
    /* Get next hop record. */
    int8_t i = nd6_get_next_hop_entry(ip6addr, netif);
    if (i < 0) {
        /* failed to get a next hop neighbor record. */
        // return i;
        return ERR_VAL;
    }

    /* Now that we have a destination record, send or queue the packet. */
    if (neighbor_cache[i].state == ND6_STALE) {
        /* Switch to delay state. */
        neighbor_cache[i].state = ND6_DELAY;
        neighbor_cache[i].counter.delay_time = LWIP_ND6_DELAY_FIRST_PROBE_TIME / ND6_TMR_INTERVAL;
    }
    /* @todo should we send or queue if PROBE? send for now, to let unicast NS pass. */
    if ((neighbor_cache[i].state == ND6_REACHABLE) ||
        (neighbor_cache[i].state == ND6_DELAY) ||
        (neighbor_cache[i].state == ND6_PROBE)) {

        /* Tell the caller to send out the packet now. */
        *hwaddrp = neighbor_cache[i].lladdr;
        return STATUS_SUCCESS;
    }

    /* We should queue packet on this interface. */
    *hwaddrp = nullptr;
    return nd6_queue_packet(i, q);
}


/**
 * Get the Path MTU for a destination.
 *
 * @param ip6addr the destination address
 * @param netif the netif on which the packet will be sent
 * @return the Path MTU, if known, or the netif default MTU
 */
uint16_t
nd6_get_destination_mtu(const Ip6Addr* ip6addr, NetworkInterface* netif)
{
    int16_t i = nd6_find_destination_cache_entry(ip6addr);
    if (i >= 0) {
        if (destination_cache[i].pmtu > 0) {
            return destination_cache[i].pmtu;
        }
    }

    if (netif != nullptr) {
        return get_netif_mtu6(netif);
    }

    return 1280; /* Minimum MTU */
}


/**
 * Provide the Neighbor discovery process with a hint that a
 * destination is reachable. Called by tcp_receive when ACKs are
 * received or sent (as per RFC). This is useful to avoid sending
 * NS messages every 30 seconds.
 *
 * @param ip6addr the destination address which is know to be reachable
 *                by an upper layer protocol (TCP)
 */
void
nd6_reachability_hint(const Ip6Addr* ip6addr)
{
    int8_t i;
    int16_t dst_idx;

    /* Find destination in cache. */
    if (ip6_addr_equal(ip6addr, &(destination_cache[nd6_cached_destination_index].destination_addr))) {
        dst_idx = nd6_cached_destination_index;
        // ND6_STATS_INC(nd6.cachehit);
    }
    else {
        dst_idx = nd6_find_destination_cache_entry(ip6addr);
    }
    if (dst_idx < 0) {
        return;
    }

    /* Find next hop neighbor in cache. */
    if (ip6_addr_equal(&(destination_cache[dst_idx].next_hop_addr),
                          &(neighbor_cache[nd6_cached_neighbor_index].next_hop_address))) {
        i = nd6_cached_neighbor_index;
        // ND6_STATS_INC(nd6.cachehit);
    }
    else {
        i = nd6_find_neighbor_cache_entry(&(destination_cache[dst_idx].next_hop_addr));
    }
    if (i < 0) {
        return;
    }

    /* For safety: don't set as reachable if we don't have a LL address yet. Misuse protection. */
    if (neighbor_cache[i].state == ND6_INCOMPLETE || neighbor_cache[i].state == ND6_NO_ENTRY) {
        return;
    }

    /* Set reachability state. */
    neighbor_cache[i].state = ND6_REACHABLE;
    neighbor_cache[i].counter.reachable_time = reachable_time;
}


/**
 * Remove all prefix, neighbor_cache and router entries of the specified netif.
 *
 * @param netif points to a network interface
 */
void
nd6_cleanup_netif(NetworkInterface* netif)
{
    uint8_t i;
    for (i = 0; i < LWIP_ND6_NUM_PREFIXES; i++) {
        if (prefix_list[i].netif == netif) {
            prefix_list[i].netif = nullptr;
        }
    }
    for (i = 0; i < LWIP_ND6_NUM_NEIGHBORS; i++) {
        if (neighbor_cache[i].netif == netif) {
            for (int8_t router_index = 0; router_index < LWIP_ND6_NUM_ROUTERS; router_index++) {
                if (default_router_list[router_index].neighbor_entry == &neighbor_cache[i]) {
                    default_router_list[router_index].neighbor_entry = nullptr;
                    default_router_list[router_index].flags = 0;
                }
            }
            neighbor_cache[i].isrouter = 0;
            nd6_free_neighbor_cache_entry(i);
        }
    }
    /* Clear the destination cache, since many entries may now have become
     * invalid for one of several reasons. As destination cache entries have no
     * netif association, use a sledgehammer approach (this can be improved). */
    nd6_clear_destination_cache();
}


/**
 * The state of a local IPv6 address entry is about to change. If needed, join
 * or leave the solicited-node multicast group for the address.
 *
 * @param netif The netif that owns the address.
 * @param addr_idx The index of the address.
 * @param new_state The new (IP6_ADDR_) state for the address.
 */
void
nd6_adjust_mld_membership(NetworkInterface* netif, int8_t addr_idx, uint8_t new_state)
{
    uint8_t old_state = get_netif_ip6_addr_state(netif, addr_idx);

    /* Determine whether we were, and should be, a member of the solicited-node
     * multicast group for this address. For tentative addresses, the group is
     * not joined until the address enters the TENTATIVE_1 (or VALID) state. */
    uint8_t old_member = (old_state != IP6_ADDR_INVALID && old_state !=
        IP6_ADDR_DUPLICATED && old_state != IP6_ADDR_TENTATIVE);
    uint8_t new_member = (new_state != IP6_ADDR_INVALID && new_state !=
        IP6_ADDR_DUPLICATED && new_state != IP6_ADDR_TENTATIVE);

    if (old_member != new_member) {
        set_ip6_addr_solicited_node(&multicast_address, get_netif_ip6_addr(netif, addr_idx)->word[3]);
        assign_ip6_addr_zone(&multicast_address, IP6_MULTICAST, netif,);

        if (new_member) {
            mld6_joingroup_netif(netif, &multicast_address);
        }
        else {
            mld6_leavegroup_netif(netif, &multicast_address);
        }
    }
}


/** Netif was added, set up, or reconnected (link up) */
void
nd6_restart_netif(NetworkInterface& netif)
{
    /* Send Router Solicitation messages (see RFC 4861, ch. 6.3.7). */
    netif->rtr_solicit_count = LWIP_ND6_MAX_MULTICAST_SOLICIT;
}
