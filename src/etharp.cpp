/**
 * @file
 * Address Resolution Protocol module for IP over Ethernet
 *
 * Functionally, ARP is divided into two parts. The first maps an IP address
 * to a physical address when sending a packet, and the second part answers
 * requests from other machines for our physical address.
 *
 * This implementation complies with RFC 826 (Ethernet ARP). It supports
 * Gratuitious ARP from RFC3220 (IP Mobility Support for IPv4) section 4.6
 * if an interface calls etharp_gratuitous(our_netif) upon address change.
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
#include "autoip.h"

#include "dhcp.h"

#include "etharp.h"

#include "ethernet.h"

#include "iana.h"

#include "ieee.h"

#include "lwip_debug.h"

#include "lwip_snmp.h"

#include "stats.h"

#include <cstring>
#include <dhcp.cpp>
#include "ip4.h"

/** Re-request a used ARP entry 1 minute before it would expire to prevent
 *  breaking a steadily used connection because the ARP entry timed out. */
#define ARP_AGE_REREQUEST_USED_UNICAST   (ARP_MAXAGE - 30)
#define ARP_AGE_REREQUEST_USED_BROADCAST (ARP_MAXAGE - 15)

/** the time an ARP entry stays pending after first request,
 *  for ARP_TMR_INTERVAL = 1000, this is
 *  10 seconds.
 *
 *  @internal Keep this number at least 2, otherwise it might
 *  run out instantly if the timeout occurs directly after a request.
 */
constexpr auto kArpMaxPending = 5;

/** ARP states */
enum EtharpState
{
    ETHARP_STATE_EMPTY = 0,
    ETHARP_STATE_PENDING,
    ETHARP_STATE_STABLE,
    ETHARP_STATE_STABLE_REREQUESTING_1,
    ETHARP_STATE_STABLE_REREQUESTING_2,
    ETHARP_STATE_STATIC
};

struct EtharpEntry;

struct EtharpEntry
{
    /** Pointer to queue of pending outgoing packets on this ARP entry. */
    struct EtharpEntry* next;
    Ip4Addr ipaddr;
    struct NetIfc* netif;
    struct EthAddr ethaddr;
    uint16_t ctime;
    uint8_t state;
    PacketBuffer* p;
};

static struct EtharpEntry arp_table[ARP_TABLE_SIZE];

static NetIfcAddrIdx etharp_cached_entry;


/** Try hard to create a new entry - we want the IP address to appear in
    the cache (even if this means removing an active entry or so). */
constexpr auto kEtharpFlagTryHard = 1;
constexpr auto kEtharpFlagFindOnly = 2;
constexpr auto kEtharpFlagStaticEntry = 4;


inline void EtharpSetAddrhint(NetIfc* netif, const int addrhint)
{
    if (((netif) != nullptr) && ((netif)->hints != nullptr))
    {
        (netif)->hints->addr_hint = (addrhint);
    }
}

static LwipError etharp_request_dst(struct NetIfc* netif, const Ip4Addr* ipaddr, const struct EthAddr* hw_dst_addr);
static LwipError etharp_raw(struct NetIfc* netif,
                            const struct EthAddr* ethsrc_addr, const struct EthAddr* ethdst_addr,
                            const struct EthAddr* hwsrc_addr, const Ip4Addr* ipsrc_addr,
                            const struct EthAddr* hwdst_addr, const Ip4Addr* ipdst_addr,
                            const uint16_t opcode);

/**
 * Free a complete queue of etharp entries
 *
 * @param q a qeueue of etharp_q_entry's to free
 */
static void
free_etharp_q(struct EtharpEntry* q)
{
    lwip_assert("q != NULL", q != nullptr);
    while (q)
    {
        const auto r = q;
        q = q->next;
        lwip_assert("r->p != NULL", (r->p != nullptr));
        pbuf_free(r->p);
        delete r;
    }
}


/** Clean up ARP table entries */
static void
etharp_free_entry(const int index)
{
    /* remove from SNMP ARP index tree */
    // mib2_remove_arp_entry(arp_table[index].netif, &arp_table[index].ipaddr);
    /* and empty packet queue */
    if (arp_table[index].next != nullptr)
    {
        /* remove all queued packets */
        //    Logf(ETHARP_DEBUG, ("etharp_free_entry: freeing entry %"U16_F", packet queue %p.\n", (uint16_t)i, (void *)(arp_table[i].q)));
        free_etharp_q(arp_table[index].next);
        arp_table[index].next = nullptr;
    }
    /* recycle entry for re-use */
    arp_table[index].state = ETHARP_STATE_EMPTY;
    /* for debugging, clean out the complete entry */
    arp_table[index].ctime = 0;
    arp_table[index].netif = nullptr;
    ip4_addr_set_zero(&arp_table[index].ipaddr);
    arp_table[index].ethaddr = kEthzero;
}

/**
 * Clears expired entries in the ARP table.
 *
 * This function should be called every ARP_TMR_INTERVAL milliseconds (1 second),
 * in order to expire entries in the ARP table.
 */
void
etharp_tmr(void)
{
    Logf(ETHARP_DEBUG, ("etharp_timer\n"));
    /* remove expired entries from the ARP table */
    for (auto i = 0; i < ARP_TABLE_SIZE; ++i)
    {
        const auto state = arp_table[i].state;
        if (state != ETHARP_STATE_EMPTY
            && (state != ETHARP_STATE_STATIC)

        )
        {
            arp_table[i].ctime++;
            if ((arp_table[i].ctime >= ARP_MAXAGE) ||
                ((arp_table[i].state == ETHARP_STATE_PENDING) &&
                    (arp_table[i].ctime >= kArpMaxPending)))
            {
                /* pending or stable entry has become old! */
                // Logf(ETHARP_DEBUG, ("etharp_timer: expired %s entry %d.\n",
                //          arp_table[i].state >= ETHARP_STATE_STABLE ? "stable" : "pending", i));
                /* clean up entries that have just been expired */
                etharp_free_entry(i);
            }
            else if (arp_table[i].state == ETHARP_STATE_STABLE_REREQUESTING_1)
            {
                /* Don't send more than one request every 2 seconds. */
                arp_table[i].state = ETHARP_STATE_STABLE_REREQUESTING_2;
            }
            else if (arp_table[i].state == ETHARP_STATE_STABLE_REREQUESTING_2)
            {
                /* Reset state to stable, so that the next transmitted packet will
                   re-send an ARP request. */
                arp_table[i].state = ETHARP_STATE_STABLE;
            }
            else if (arp_table[i].state == ETHARP_STATE_PENDING)
            {
                /* still pending, resend an ARP query */
                etharp_request(arp_table[i].netif, &arp_table[i].ipaddr);
            }
        }
    }
}

/**
 * Search the ARP table for a matching or new entry.
 *
 * If an IP address is given, return a pending or stable ARP entry that matches
 * the address. If no match is found, create a new entry with this address set,
 * but in state ETHARP_EMPTY. The caller must check and possibly change the
 * state of the returned entry.
 *
 * If ipaddr is NULL, return a initialized new entry in state ETHARP_EMPTY.
 *
 * In all cases, attempt to create new entries from an empty entry. If no
 * empty entries are available and ETHARP_FLAG_TRY_HARD flag is set, recycle
 * old entries. Heuristic choose the least important entry for recycling.
 *
 * @param ipaddr IP address to find in ARP cache, or to add if not found.
 * @param flags See @ref etharp_state
 * @param netif netif related to this address (used for NETIF_HWADDRHINT)
 *
 * @return The ARP entry index that matched or is created, ERR_MEM if no
 * entry is found or could be recycled.
 */
static int16_t
etharp_find_entry(const Ip4Addr* ipaddr, uint8_t flags, struct NetIfc* netif)
{
    int16_t old_pending = ARP_TABLE_SIZE, old_stable = ARP_TABLE_SIZE;
    int16_t empty = ARP_TABLE_SIZE;
    int16_t i = 0;
    /* oldest entry with packets on queue */
    int16_t old_queue = ARP_TABLE_SIZE;
    /* its age */
    uint16_t age_queue = 0, age_pending = 0, age_stable = 0;

    /**
     * a) do a search through the cache, remember candidates
     * b) select candidate entry
     * c) create new entry
     */

    /* a) in a single search sweep, do all of this
     * 1) remember the first empty entry (if any)
     * 2) remember the oldest stable entry (if any)
     * 3) remember the oldest pending entry without queued packets (if any)
     * 4) remember the oldest pending entry with queued packets (if any)
     * 5) search for a matching IP entry, either pending or stable
     *    until 5 matches, or all entries are searched for.
     */

    for (i = 0; i < ARP_TABLE_SIZE; ++i)
    {
        uint8_t state = arp_table[i].state;
        /* no empty entry found yet and now we do find one? */
        if ((empty == ARP_TABLE_SIZE) && (state == ETHARP_STATE_EMPTY))
        {
            // Logf(ETHARP_DEBUG, ("etharp_find_entry: found empty entry %d\n", (int)i));
            /* remember first empty entry */
            empty = i;
        }
        else if (state != ETHARP_STATE_EMPTY)
        {
            lwip_assert("state == ETHARP_STATE_PENDING || state >= ETHARP_STATE_STABLE",
                        state == ETHARP_STATE_PENDING || state >= ETHARP_STATE_STABLE);
            /* if given, does IP address match IP address in ARP entry? */
            if (ipaddr && ip4_addr_cmp(ipaddr, &arp_table[i].ipaddr)
                && ((netif == nullptr) || (netif == arp_table[i].netif))

            )
            {
                // Logf(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_find_entry: found matching entry %d\n", (int)i));
                /* found exact IP address match, simply bail out */
                return i;
            }
            /* pending entry? */
            if (state == ETHARP_STATE_PENDING)
            {
                /* pending with queued packets? */
                if (arp_table[i].next != nullptr)
                {
                    if (arp_table[i].ctime >= age_queue)
                    {
                        old_queue = i;
                        age_queue = arp_table[i].ctime;
                    }
                }
                else
                    /* pending without queued packets? */
                {
                    if (arp_table[i].ctime >= age_pending)
                    {
                        old_pending = i;
                        age_pending = arp_table[i].ctime;
                    }
                }
                /* stable entry? */
            }
            else if (state >= ETHARP_STATE_STABLE)
            {
                /* don't record old_stable for static entries since they never expire */
                if (state < ETHARP_STATE_STATIC)

                {
                    /* remember entry with oldest stable entry in oldest, its age in maxtime */
                    if (arp_table[i].ctime >= age_stable)
                    {
                        old_stable = i;
                        age_stable = arp_table[i].ctime;
                    }
                }
            }
        }
    }
    /* { we have no match } => try to create a new entry */

    /* don't create new entry, only search? */
    if (((flags & kEtharpFlagFindOnly) != 0) ||
        /* or no empty entry found and not allowed to recycle? */
        ((empty == ARP_TABLE_SIZE) && ((flags & kEtharpFlagTryHard) == 0)))
    {
        // Logf(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_find_entry: no empty entry found and not allowed to recycle\n"));
        return (int16_t)ERR_MEM;
    }

    /* b) choose the least destructive entry to recycle:
     * 1) empty entry
     * 2) oldest stable entry
     * 3) oldest pending entry without queued packets
     * 4) oldest pending entry with queued packets
     *
     * { ETHARP_FLAG_TRY_HARD is set at this point }
     */

    /* 1) empty entry available? */
    if (empty < ARP_TABLE_SIZE)
    {
        i = empty;
        // Logf(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_find_entry: selecting empty entry %d\n", (int)i));
    }
    else
    {
        /* 2) found recyclable stable entry? */
        if (old_stable < ARP_TABLE_SIZE)
        {
            /* recycle oldest stable*/
            i = old_stable;
            // Logf(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_find_entry: selecting oldest stable entry %d\n", (int)i));
            /* no queued packets should exist on stable entries */
            lwip_assert("arp_table[i].q == NULL", arp_table[i].next == nullptr);
            /* 3) found recyclable pending entry without queued packets? */
        }
        else if (old_pending < ARP_TABLE_SIZE)
        {
            /* recycle oldest pending */
            i = old_pending;
            // Logf(ETHARP_DEBUG | LWIP_DBG_TRACE,
            //      ("etharp_find_entry: selecting oldest pending entry %d (without queue)\n", (int)i));
            /* 4) found recyclable pending entry with queued packets? */
        }
        else if (old_queue < ARP_TABLE_SIZE)
        {
            /* recycle oldest pending (queued packets are free in etharp_free_entry) */
            i = old_queue;
            // Logf(ETHARP_DEBUG | LWIP_DBG_TRACE,
            //      ("etharp_find_entry: selecting oldest pending entry %d, freeing packet queue %p\n", (int)i, (void *)(
            //          arp_table[i].next)));
            /* no empty or recyclable entries found */
        }
        else
        {
            Logf(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_find_entry: no empty or recyclable entries found\n"));
            return (int16_t)ERR_MEM;
        }

        /* { empty or recyclable entry found } */
        // LWIP_ASSERT("i < ARP_TABLE_SIZE", i < ARP_TABLE_SIZE);
        etharp_free_entry(i);
    }

    lwip_assert("i < ARP_TABLE_SIZE", i < ARP_TABLE_SIZE);
    lwip_assert("arp_table[i].state == ETHARP_STATE_EMPTY",
                arp_table[i].state == ETHARP_STATE_EMPTY);

    /* IP address given? */
    if (ipaddr != nullptr)
    {
        /* set IP address */
        copy_ip4_addr(&arp_table[i].ipaddr, ipaddr);
    }
    arp_table[i].ctime = 0;

    arp_table[i].netif = netif;
    return (int16_t)i;
}

/**
 * Update (or insert) a IP/MAC address pair in the ARP cache.
 *
 * If a pending entry is resolved, any queued packets will be sent
 * at this point.
 *
 * @param netif netif related to this entry (used for NETIF_ADDRHINT)
 * @param ipaddr IP address of the inserted ARP entry.
 * @param ethaddr Ethernet address of the inserted ARP entry.
 * @param flags See @ref etharp_state
 *
 * @return
 * - ERR_OK Successfully updated ARP cache.
 * - ERR_MEM If we could not add a new ARP entry when ETHARP_FLAG_TRY_HARD was set.
 * - ERR_ARG Non-unicast address given, those will not appear in ARP cache.
 *
 * @see pbuf_free()
 */
static LwipError
etharp_update_arp_entry(struct NetIfc* netif, const Ip4Addr* ipaddr, struct EthAddr* ethaddr, uint8_t flags)
{
    int16_t i;
    lwip_assert("netif->hwaddr_len == ETH_HWADDR_LEN", netif->hwaddr_len == ETH_HWADDR_LEN);
    //  Logf(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_update_arp_entry: %"U16_F".%"U16_F".%"U16_F".%"U16_F" - %02"X16_F":%02"X16_F":%02"X16_F":%02"X16_F":%02"X16_F":%02"X16_F"\n",
    //              ip4_addr1_16(ipaddr), ip4_addr2_16(ipaddr), ip4_addr3_16(ipaddr), ip4_addr4_16(ipaddr),
    //              (uint16_t)ethaddr->addr[0], (uint16_t)ethaddr->addr[1], (uint16_t)ethaddr->addr[2],
    //              (uint16_t)ethaddr->addr[3], (uint16_t)ethaddr->addr[4], (uint16_t)ethaddr->addr[5]));
    /* non-unicast address? */
    if (ip4_addr_isany(ipaddr) ||
        ip4_addr_isbroadcast(ipaddr, netif) ||
        ip4_addr_ismulticast(ipaddr))
    {
        //    Logf(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_update_arp_entry: will not add non-unicast IP address to ARP cache\n"));
        return ERR_ARG;
    }
    /* find or create ARP entry */
    i = etharp_find_entry(ipaddr, flags, netif);
    /* bail out if no entry could be found */
    if (i < 0)
    {
        return (LwipError)i;
    }

    if (flags & kEtharpFlagStaticEntry)
    {
        /* record static type */
        arp_table[i].state = ETHARP_STATE_STATIC;
    }
    else if (arp_table[i].state == ETHARP_STATE_STATIC)
    {
        /* found entry is a static type, don't overwrite it */
        return ERR_VAL;
    }
    else

    {
        /* mark it stable */
        arp_table[i].state = ETHARP_STATE_STABLE;
    }

    /* record network interface */
    arp_table[i].netif = netif;
    /* insert in SNMP ARP index tree */
    // mib2_add_arp_entry(netif, &arp_table[i].ipaddr);

    //  Logf(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_update_arp_entry: updating stable entry %"S16_F"\n", i));
    /* update address */
    SMEMCPY(&arp_table[i].ethaddr, ethaddr, ETH_HWADDR_LEN);
    /* reset time stamp */
    arp_table[i].ctime = 0;
    /* this is where we will send out queued packets! */

    while (arp_table[i].next != NULL)
    {
        struct PacketBuffer* p;
        /* remember remainder of queue */
        auto q = arp_table[i].next;
        /* pop first item off the queue */
        arp_table[i].next = q->next;
        /* get the packet pointer */
        p = q->p;
        /* now queue entry can be freed */
        // memp_free(MEMP_ARP_QUEUE, q);
        delete q;

        /* send the queued IP packet */
        ethernet_output(netif, p, reinterpret_cast<struct EthAddr *>(netif->hwaddr), ethaddr, ETHTYPE_IP);
        /* free the queued IP packet */
        pbuf_free(p);
    }
    return ERR_OK;
}


/** Add a new static entry to the ARP table. If an entry exists for the
 * specified IP address, this entry is overwritten.
 * If packets are queued for the specified IP address, they are sent out.
 *
 * @param ipaddr IP address for the new static entry
 * @param ethaddr ethernet address for the new static entry
 * @return See return values of etharp_add_static_entry
 */
LwipError
etharp_add_static_entry(const Ip4Addr* ipaddr, struct EthAddr* ethaddr)
{
    LWIP_ASSERT_CORE_LOCKED();
    // Logf(ETHARP_DEBUG | LWIP_DBG_TRACE,
    //      ("etharp_add_static_entry: %"U16_F".%"U16_F".%"U16_F".%"U16_F" - %02"X16_F":%02"X16_F":%02"X16_F":%02"X16_F
    //          ":%02"X16_F":%02"X16_F"\n",
    //          ip4_addr1_16(ipaddr), ip4_addr2_16(ipaddr), ip4_addr3_16(ipaddr), ip4_addr4_16(ipaddr),
    //          (uint16_t)ethaddr->addr[0], (uint16_t)ethaddr->addr[1], (uint16_t)ethaddr->addr[2],
    //          (uint16_t)ethaddr->addr[3], (uint16_t)ethaddr->addr[4], (uint16_t)ethaddr->addr[5]));

    auto netif = ip4_route(ipaddr);
    if (netif == nullptr)
    {
        return ERR_RTE;
    }

    return etharp_update_arp_entry(netif, ipaddr, ethaddr, kEtharpFlagTryHard | kEtharpFlagStaticEntry);
}

/** Remove a static entry from the ARP table previously added with a call to
 * etharp_add_static_entry.
 *
 * @param ipaddr IP address of the static entry to remove
 * @return ERR_OK: entry removed
 *         ERR_MEM: entry wasn't found
 *         ERR_ARG: entry wasn't a static entry but a dynamic one
 */
LwipError
etharp_remove_static_entry(const Ip4Addr* ipaddr)
{
    int16_t i;
    LWIP_ASSERT_CORE_LOCKED();
    // Logf(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_remove_static_entry: %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
    //          ip4_addr1_16(ipaddr), ip4_addr2_16(ipaddr), ip4_addr3_16(ipaddr), ip4_addr4_16(ipaddr)));

    /* find or create ARP entry */
    i = etharp_find_entry(ipaddr, kEtharpFlagFindOnly, nullptr);
    /* bail out if no entry could be found */
    if (i < 0)
    {
        return (LwipError)i;
    }

    if (arp_table[i].state != ETHARP_STATE_STATIC)
    {
        /* entry wasn't a static entry, cannot remove it */
        return ERR_ARG;
    }
    /* entry found, free it */
    etharp_free_entry(i);
    return ERR_OK;
}


/**
 * Remove all ARP table entries of the specified netif.
 *
 * @param netif points to a network interface
 */
void
etharp_cleanup_netif(struct NetIfc* netif)
{
    int i;

    for (i = 0; i < ARP_TABLE_SIZE; ++i)
    {
        uint8_t state = arp_table[i].state;
        if ((state != ETHARP_STATE_EMPTY) && (arp_table[i].netif == netif))
        {
            etharp_free_entry(i);
        }
    }
}

/**
 * Finds (stable) ethernet/IP address pair from ARP table
 * using interface and IP address index.
 * @note the addresses in the ARP table are in network order!
 *
 * @param netif points to interface index
 * @param ipaddr points to the (network order) IP address index
 * @param eth_ret points to return pointer
 * @param ip_ret points to return pointer
 * @return table index if found, -1 otherwise
 */
ssize_t
etharp_find_addr(struct NetIfc* netif, const Ip4Addr* ipaddr,
                 struct EthAddr** eth_ret, const Ip4Addr** ip_ret)
{
    int16_t i;

    lwip_assert("eth_ret != NULL && ip_ret != NULL",
                eth_ret != nullptr && ip_ret != nullptr);


    i = etharp_find_entry(ipaddr, kEtharpFlagFindOnly, netif);
    if ((i >= 0) && (arp_table[i].state >= ETHARP_STATE_STABLE))
    {
        *eth_ret = &arp_table[i].ethaddr;
        *ip_ret = &arp_table[i].ipaddr;
        return i;
    }
    return -1;
}

/**
 * Possibility to iterate over stable ARP table entries
 *
 * @param i entry number, 0 to ARP_TABLE_SIZE
 * @param ipaddr return value: IP address
 * @param netif return value: points to interface
 * @param eth_ret return value: ETH address
 * @return 1 on valid index, 0 otherwise
 */
int
etharp_get_entry(size_t i, Ip4Addr** ipaddr, struct NetIfc** netif, struct EthAddr** eth_ret)
{
    lwip_assert("ipaddr != NULL", ipaddr != nullptr);
    lwip_assert("netif != NULL", netif != nullptr);
    lwip_assert("eth_ret != NULL", eth_ret != nullptr);

    if ((i < ARP_TABLE_SIZE) && (arp_table[i].state >= ETHARP_STATE_STABLE))
    {
        *ipaddr = &arp_table[i].ipaddr;
        *netif = arp_table[i].netif;
        *eth_ret = &arp_table[i].ethaddr;
        return 1;
    }
    else
    {
        return 0;
    }
}

/**
 * Responds to ARP requests to us. Upon ARP replies to us, add entry to cache
 * send out queued IP packets. Updates cache with snooped address pairs.
 *
 * Should be called for incoming ARP packets. The PacketBuffer in the argument
 * is freed by this function.
 *
 * @param p The ARP packet that arrived on netif. Is freed by this function.
 * @param netif The lwIP network interface on which the ARP packet PacketBuffer arrived.
 *
 * @see pbuf_free()
 */
void
etharp_input(struct PacketBuffer* p, struct NetIfc* netif)
{
    Ip4Addr sipaddr{};
    Ip4Addr dipaddr{};
    uint8_t for_us;

    LWIP_ASSERT_CORE_LOCKED();

    if (netif == nullptr)
    {
        return;
    }

    auto hdr = static_cast<struct EtharpHdr *>(p->payload);

    /* RFC 826 "Packet Reception": */
    if ((hdr->hwtype != pp_htons(LWIP_IANA_HWTYPE_ETHERNET)) ||
        (hdr->hwlen != ETH_HWADDR_LEN) ||
        (hdr->protolen != sizeof(Ip4Addr)) ||
        (hdr->proto != pp_htons(ETHTYPE_IP)))
    {
        //    Logf(ETHARP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
        //                ("etharp_input: packet dropped, wrong hw type, hwlen, proto, protolen or ethernet type (%"U16_F"/%"U16_F"/%"U16_F"/%"U16_F")\n",
        //                 hdr->hwtype, (uint16_t)hdr->hwlen, hdr->proto, (uint16_t)hdr->protolen));
        // ETHARP_STATS_INC(etharp.proterr);
        // ETHARP_STATS_INC(etharp.drop);
        pbuf_free(p);
        return;
    }
    // ETHARP_STATS_INC(etharp.recv);

    /* We have to check if a host already has configured our random
     * created link local address and continuously check if there is
     * a host with this IP-address so we can detect collisions */
    autoip_arp_reply(netif, hdr);


    /* Copy struct ip4_addr_wordaligned to aligned ip4_addr, to support compilers without
     * structure packing (not using structure copy which breaks strict-aliasing rules). */
    IpaddrWordalignedCopyToIp4AddrT(&hdr->sipaddr, &sipaddr);
    IpaddrWordalignedCopyToIp4AddrT(&hdr->dipaddr, &dipaddr);

    /* this interface is not configured? */
    if (ip4_addr_isany_val(*get_net_ifc_ip4_addr(netif)))
    {
        for_us = 0;
    }
    else
    {
        /* ARP packet directed to us? */
        for_us = uint8_t(ip4_addr_cmp(&dipaddr, get_net_ifc_ip4_addr(netif)));
    }

    /* ARP message directed to us?
        -> add IP address in ARP cache; assume requester wants to talk to us,
           can result in directly sending the queued packets for this host.
       ARP message not directed to us?
        ->  update the source IP address in the cache, if present */
    etharp_update_arp_entry(netif, &sipaddr, &(hdr->shwaddr),
                            for_us ? kEtharpFlagTryHard : kEtharpFlagFindOnly);

    /* now act on the message itself */
    switch (hdr->opcode)
    {
        /* ARP request? */
    case pp_htons(ARP_REQUEST):
        /* ARP request. If it asked for our address, we send out a
         * reply. In any case, we time-stamp any existing ARP entry,
         * and possibly send out an IP packet that was queued on it. */

        Logf(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_input: incoming ARP request\n"));
        /* ARP request for our address? */
        if (for_us)
        {
            /* send ARP response */
            etharp_raw(netif,
                       (struct EthAddr *)netif->hwaddr, &hdr->shwaddr,
                       (struct EthAddr *)netif->hwaddr, get_net_ifc_ip4_addr(netif),
                       &hdr->shwaddr, &sipaddr,
                       ARP_REPLY);
            /* we are not configured? */
        }
        else if (ip4_addr_isany_val(*get_net_ifc_ip4_addr(netif)))
        {
            /* { for_us == 0 and netif->ip_addr.addr == 0 } */
            Logf(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_input: we are unconfigured, ARP request ignored.\n"));
            /* request was not directed to us */
        }
        else
        {
            /* { for_us == 0 and netif->ip_addr.addr != 0 } */
            Logf(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_input: ARP request was not for us.\n"));
        }
        break;
    case pp_htons(ARP_REPLY):
        /* ARP reply. We already updated the ARP cache earlier. */
        Logf(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_input: incoming ARP reply\n"));

        /* DHCP wants to know about ARP replies from any host with an
         * IP address also offered to us by the DHCP server. We do not
         * want to take a duplicate IP address on a single network.
         * @todo How should we handle redundant (fail-over) interfaces? */
        dhcp_arp_reply(netif, &sipaddr);

        break;
    default:
        //      Logf(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_input: ARP unknown opcode type %"S16_F"\n", lwip_htons(hdr->opcode)));
        // ETHARP_STATS_INC(etharp.err);
        break;
    }
    /* free ARP packet */
    pbuf_free(p);
}

/** Just a small helper function that sends a PacketBuffer to an ethernet address
 * in the arp_table specified by the index 'arp_idx'.
 */
static LwipError
etharp_output_to_arp_index(struct NetIfc* netif, struct PacketBuffer* q, NetIfcAddrIdx arp_idx)
{
    lwip_assert("arp_table[arp_idx].state >= ETHARP_STATE_STABLE",
                arp_table[arp_idx].state >= ETHARP_STATE_STABLE);
    /* if arp table entry is about to expire: re-request it,
       but only if its state is ETHARP_STATE_STABLE to prevent flooding the
       network with ARP requests if this address is used frequently. */
    if (arp_table[arp_idx].state == ETHARP_STATE_STABLE)
    {
        if (arp_table[arp_idx].ctime >= ARP_AGE_REREQUEST_USED_BROADCAST)
        {
            /* issue a standard request using broadcast */
            if (etharp_request(netif, &arp_table[arp_idx].ipaddr) == ERR_OK)
            {
                arp_table[arp_idx].state = ETHARP_STATE_STABLE_REREQUESTING_1;
            }
        }
        else if (arp_table[arp_idx].ctime >= ARP_AGE_REREQUEST_USED_UNICAST)
        {
            /* issue a unicast request (for 15 seconds) to prevent unnecessary broadcast */
            if (etharp_request_dst(netif, &arp_table[arp_idx].ipaddr, &arp_table[arp_idx].ethaddr) == ERR_OK)
            {
                arp_table[arp_idx].state = ETHARP_STATE_STABLE_REREQUESTING_1;
            }
        }
    }

    return ethernet_output(netif, q, (struct EthAddr *)(netif->hwaddr), &arp_table[arp_idx].ethaddr, ETHTYPE_IP);
}

/**
 * Resolve and fill-in Ethernet address header for outgoing IP packet.
 *
 * For IP multicast and broadcast, corresponding Ethernet addresses
 * are selected and the packet is transmitted on the link.
 *
 * For unicast addresses, the packet is submitted to etharp_query(). In
 * case the IP address is outside the local network, the IP address of
 * the gateway is used.
 *
 * @param netif The lwIP network interface which the IP packet will be sent on.
 * @param q The PacketBuffer(s) containing the IP packet to be sent.
 * @param ipaddr The IP address of the packet destination.
 *
 * @return
 * - ERR_RTE No route to destination (no gateway to external networks),
 * or the return type of either etharp_query() or ethernet_output().
 */
LwipError
etharp_output(struct NetIfc* netif, struct PacketBuffer* q, const Ip4Addr* ipaddr)
{
    const struct EthAddr* dest;
    struct EthAddr mcastaddr{};
    auto dst_addr = ipaddr;

    LWIP_ASSERT_CORE_LOCKED();
    lwip_assert("netif != NULL", netif != nullptr);
    lwip_assert("q != NULL", q != nullptr);
    lwip_assert("ipaddr != NULL", ipaddr != nullptr);

    /* Determine on destination hardware address. Broadcasts and multicasts
     * are special, other IP addresses are looked up in the ARP table. */

    /* broadcast destination IP address? */
    if (ip4_addr_isbroadcast(ipaddr, netif))
    {
        /* broadcast on Ethernet also */
        dest = (const struct EthAddr *)&kEthbroadcast;
        /* multicast destination IP address? */
    }
    else if (ip4_addr_ismulticast(ipaddr))
    {
        /* Hash IP multicast address to MAC address.*/
        mcastaddr.addr[0] = kLLIp4McastAddrOui[0];
        mcastaddr.addr[1] = kLLIp4McastAddrOui[1];
        mcastaddr.addr[2] = kLLIp4McastAddrOui[2];
        mcastaddr.addr[3] = ip4_addr2(ipaddr) & 0x7f;
        mcastaddr.addr[4] = ip4_addr3(ipaddr);
        mcastaddr.addr[5] = ip4_addr4(ipaddr);
        /* destination Ethernet address is multicast */
        dest = &mcastaddr;
        /* unicast destination IP address? */
    }
    else
    {
        NetIfcAddrIdx i;
        /* outside local network? if so, this can neither be a global broadcast nor
           a subnet broadcast. */
        if (!ip4_addr_netcmp(ipaddr, get_net_ifc_ip4_addr(netif), netif_ip4_netmask(netif)) &&
            !ip4_addr_islinklocal(ipaddr))
        {
            auto iphdr = static_cast<Ip4Hdr*>(q->payload);
            /* According to RFC 3297, chapter 2.6.2 (Forwarding Rules), a packet with
               a link-local source address must always be "directly to its destination
               on the same physical link. The host MUST NOT send the packet to any
               router for forwarding". */
            if (!ip4_addr_islinklocal(&iphdr->src))

            {
                {
                    /* interface has default gateway? */
                    if (!ip4_addr_isany_val(*netif_ip4_gw(netif)))
                    {
                        /* send to hardware address of default gateway IP address */
                        dst_addr = netif_ip4_gw(netif);
                        /* no default gateway available */
                    }
                    else
                    {
                        /* no route to destination error (default gateway missing) */
                        return ERR_RTE;
                    }
                }
            }
        }

        if (netif->hints != NULL)
        {
            /* per-pcb cached entry was given */
            const auto etharp_cached_entry = netif->hints->addr_hint;
            if (etharp_cached_entry < ARP_TABLE_SIZE)
            {
                if ((arp_table[etharp_cached_entry].state >= ETHARP_STATE_STABLE) &&

                    (arp_table[etharp_cached_entry].netif == netif) &&

                    (ip4_addr_cmp(dst_addr, &arp_table[etharp_cached_entry].ipaddr)))
                {
                    /* the per-pcb-cached entry is stable and the right one! */
                    // ETHARP_STATS_INC(etharp.cachehit);
                    return etharp_output_to_arp_index(netif, q, etharp_cached_entry);
                }
            }
        }


        /* find stable entry: do this here since this is a critical path for
           throughput and etharp_find_entry() is kind of slow */
        for (i = 0; i < ARP_TABLE_SIZE; i++)
        {
            if ((arp_table[i].state >= ETHARP_STATE_STABLE) &&

                (arp_table[i].netif == netif) &&

                (ip4_addr_cmp(dst_addr, &arp_table[i].ipaddr)))
            {
                /* found an existing, stable entry */
                EtharpSetAddrhint(netif, i);
                return etharp_output_to_arp_index(netif, q, i);
            }
        }
        /* no stable entry found, use the (slower) query function:
           queue on destination Ethernet address belonging to ipaddr */
        return etharp_query(netif, dst_addr, q);
    }

    /* continuation for multicast/broadcast destinations */
    /* obtain source Ethernet address of the given interface */
    /* send packet directly on the link */
    return ethernet_output(netif, q, (struct EthAddr *)(netif->hwaddr), dest, ETHTYPE_IP);
}

/**
 * Send an ARP request for the given IP address and/or queue a packet.
 *
 * If the IP address was not yet in the cache, a pending ARP cache entry
 * is added and an ARP request is sent for the given address. The packet
 * is queued on this entry.
 *
 * If the IP address was already pending in the cache, a new ARP request
 * is sent for the given address. The packet is queued on this entry.
 *
 * If the IP address was already stable in the cache, and a packet is
 * given, it is directly sent and no ARP request is sent out.
 *
 * If the IP address was already stable in the cache, and no packet is
 * given, an ARP request is sent out.
 *
 * @param netif The lwIP network interface on which ipaddr
 * must be queried for.
 * @param ipaddr The IP address to be resolved.
 * @param q If non-NULL, a PacketBuffer that must be delivered to the IP address.
 * q is not freed by this function.
 *
 * @note q must only be ONE packet, not a packet queue!
 *
 * @return
 * - ERR_BUF Could not make room for Ethernet header.
 * - ERR_MEM Hardware address unknown, and no more ARP entries available
 *   to query for address or queue the packet.
 * - ERR_MEM Could not queue packet due to memory shortage.
 * - ERR_RTE No route to destination (no gateway to external networks).
 * - ERR_ARG Non-unicast address given, those will not appear in ARP cache.
 *
 */
LwipError
etharp_query(struct NetIfc* netif, const Ip4Addr* ipaddr, struct PacketBuffer* q)
{
    struct EthAddr* srcaddr = (struct EthAddr *)netif->hwaddr;
    LwipError result = ERR_MEM;
    int is_new_entry = 0;
    int16_t i_err;
    NetIfcAddrIdx i;

    /* non-unicast address? */
    if (ip4_addr_isbroadcast(ipaddr, netif) ||
        ip4_addr_ismulticast(ipaddr) ||
        ip4_addr_isany(ipaddr))
    {
        Logf(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_query: will not add non-unicast IP address to ARP cache\n"));
        return ERR_ARG;
    }

    /* find entry in ARP cache, ask to create entry if queueing packet */
    i_err = etharp_find_entry(ipaddr, kEtharpFlagTryHard, netif);

    /* could not find or create entry? */
    if (i_err < 0)
    {
        Logf(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_query: could not create ARP entry\n"));
        if (q)
        {
            Logf(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_query: packet dropped\n"));
            // ETHARP_STATS_INC(etharp.memerr);
        }
        return (LwipError)i_err;
    }
    lwip_assert("type overflow", (size_t)i_err < kNetifAddrIdxMax);
    i = (NetIfcAddrIdx)i_err;

    /* mark a fresh entry as pending (we just sent a request) */
    if (arp_table[i].state == ETHARP_STATE_EMPTY)
    {
        is_new_entry = 1;
        arp_table[i].state = ETHARP_STATE_PENDING;
        /* record network interface for re-sending arp request in etharp_tmr */
        arp_table[i].netif = netif;
    }

    /* { i is either a STABLE or (new or existing) PENDING entry } */
    lwip_assert("arp_table[i].state == PENDING or STABLE",
                ((arp_table[i].state == ETHARP_STATE_PENDING) ||
                    (arp_table[i].state >= ETHARP_STATE_STABLE)));

    /* do we have a new entry? or an implicit query request? */
    if (is_new_entry || (q == nullptr))
    {
        /* try to resolve it; send out ARP request */
        result = etharp_request(netif, ipaddr);
        if (result != ERR_OK)
        {
            /* ARP request couldn't be sent */
            /* We don't re-send arp request in etharp_tmr, but we still queue packets,
               since this failure could be temporary, and the next packet calling
               etharp_query again could lead to sending the queued packets. */
        }
        if (q == nullptr)
        {
            return result;
        }
    }

    /* packet given? */
    lwip_assert("q != NULL", q != nullptr);
    /* stable entry? */
    if (arp_table[i].state >= ETHARP_STATE_STABLE)
    {
        /* we have a valid IP->Ethernet address mapping */
        EtharpSetAddrhint(netif, i);
        /* send the packet */
        result = ethernet_output(netif, q, srcaddr, &(arp_table[i].ethaddr), ETHTYPE_IP);
        /* pending entry? (either just created or already pending */
    }
    else if (arp_table[i].state == ETHARP_STATE_PENDING)
    {
        /* entry is still pending, queue the given packet 'q' */
        struct PacketBuffer* p;
        int copy_needed = 0;
        /* IF q includes a PacketBuffer that must be copied, copy the whole chain into a
         * new PBUF_RAM. See the definition of PBUF_NEEDS_COPY for details. */
        p = q;
        while (p)
        {
            lwip_assert("no packet queues allowed!", (p->len != p->tot_len) || (p->next == nullptr));
            if (PbufNeedsCopy(p))
            {
                copy_needed = 1;
                break;
            }
            p = p->next;
        }
        if (copy_needed)
        {
            /* copy the whole packet into new pbufs */
            p = pbuf_clone(PBUF_LINK, PBUF_RAM, q);
        }
        else
        {
            /* referencing the old PacketBuffer is enough */
            p = q;
            pbuf_ref(p);
        }
        /* packet could be taken over? */
        if (p != nullptr)
        {
            /* queue packet ... */

            /* allocate a new arp queue entry */
            // new_entry = (struct etharp_q_entry *)memp_malloc(MEMP_ARP_QUEUE);
            auto new_entry = new EtharpEntry;
            if (new_entry != nullptr)
            {
                unsigned int qlen = 0;
                new_entry->next = 0;
                new_entry->p = p;
                if (arp_table[i].next != nullptr)
                {
                    EtharpEntry* r = arp_table[i].next;
                    qlen++;
                    while (r->next != nullptr)
                    {
                        r = r->next;
                        qlen++;
                    }
                    r->next = new_entry;
                }
                else
                {
                    /* queue did not exist, first item in queue */
                    arp_table[i].next = new_entry;
                }

                if (qlen >= ARP_QUEUE_LEN)
                {
                    EtharpEntry* old = arp_table[i].next;
                    arp_table[i].next = arp_table[i].next->next;
                    pbuf_free(old->p);
                    delete old;
                }

                // Logf(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_query: queued packet %p on ARP entry %"U16_F"\n", (void *)q, i));
                result = ERR_OK;
            }
            else
            {
                /* the pool MEMP_ARP_QUEUE is empty */
                pbuf_free(p);
                // Logf(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_query: could not queue a copy of PBUF_REF packet %p (out of memory)\n", (void *)q));
                result = ERR_MEM;
            }
        }
        else
        {
            // ETHARP_STATS_INC(etharp.memerr);
            //      Logf(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_query: could not queue a copy of PBUF_REF packet %p (out of memory)\n", (void *)q));
            result = ERR_MEM;
        }
    }
    return result;
}

/**
 * Send a raw ARP packet (opcode and all addresses can be modified)
 *
 * @param netif the lwip network interface on which to send the ARP packet
 * @param ethsrc_addr the source MAC address for the ethernet header
 * @param ethdst_addr the destination MAC address for the ethernet header
 * @param hwsrc_addr the source MAC address for the ARP protocol header
 * @param ipsrc_addr the source IP address for the ARP protocol header
 * @param hwdst_addr the destination MAC address for the ARP protocol header
 * @param ipdst_addr the destination IP address for the ARP protocol header
 * @param opcode the type of the ARP packet
 * @return ERR_OK if the ARP packet has been sent
 *         ERR_MEM if the ARP packet couldn't be allocated
 *         any other LwipError on failure
 */
static LwipError
etharp_raw(struct NetIfc* netif, const struct EthAddr* ethsrc_addr,
           const struct EthAddr* ethdst_addr,
           const struct EthAddr* hwsrc_addr, const Ip4Addr* ipsrc_addr,
           const struct EthAddr* hwdst_addr, const Ip4Addr* ipdst_addr,
           const uint16_t opcode)
{
    struct PacketBuffer* p;
    LwipError result = ERR_OK;
    struct EtharpHdr* hdr;

    lwip_assert("netif != NULL", netif != nullptr);

    /* allocate a PacketBuffer for the outgoing ARP request packet */
    p = pbuf_alloc(PBUF_LINK, kSizeofEtharpHdr, PBUF_RAM);
    /* could allocate a PacketBuffer for an ARP request? */
    if (p == nullptr)
    {
        Logf(ETHARP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS,
             ("etharp_raw: could not allocate PacketBuffer for ARP request.\n"));
        // ETHARP_STATS_INC(etharp.memerr);
        return ERR_MEM;
    }
    lwip_assert("check that first PacketBuffer can hold struct etharp_hdr",
                (p->len >= kSizeofEtharpHdr));

    hdr = (struct EtharpHdr *)p->payload;
    Logf(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_raw: sending raw ARP packet.\n"));
    hdr->opcode = lwip_htons(opcode);

    lwip_assert("netif->hwaddr_len must be the same as ETH_HWADDR_LEN for etharp!",
                (netif->hwaddr_len == ETH_HWADDR_LEN));

    /* Write the ARP MAC-Addresses */
    SMEMCPY(&hdr->shwaddr, hwsrc_addr, ETH_HWADDR_LEN);
    SMEMCPY(&hdr->dhwaddr, hwdst_addr, ETH_HWADDR_LEN);
    /* Copy struct ip4_addr_wordaligned to aligned ip4_addr, to support compilers without
     * structure packing. */
    IpaddrWordalignedCopyToIp4AddrT(&hdr->sipaddr, ipsrc_addr);
    IpaddrWordalignedCopyToIp4AddrT(&hdr->dipaddr, ipdst_addr);

    hdr->hwtype = pp_htons(LWIP_IANA_HWTYPE_ETHERNET);
    hdr->proto = pp_htons(ETHTYPE_IP);
    /* set hwlen and protolen */
    hdr->hwlen = ETH_HWADDR_LEN;
    hdr->protolen = sizeof(Ip4Addr);

    /* send ARP query */
#if LWIP_AUTOIP
  /* If we are using Link-Local, all ARP packets that contain a Link-Local
   * 'sender IP address' MUST be sent using link-layer broadcast instead of
   * link-layer unicast. (See RFC3927 Section 2.5, last paragraph) */
  if (ip4_addr_islinklocal(ipsrc_addr)) {
    ethernet_output(netif, p, ethsrc_addr, &ethbroadcast, ETHTYPE_ARP);
  } else
#endif /* LWIP_AUTOIP */
    {
        ethernet_output(netif, p, ethsrc_addr, ethdst_addr, ETHTYPE_ARP);
    }

    // ETHARP_STATS_INC(etharp.xmit);
    /* free ARP query packet */
    pbuf_free(p);
    p = nullptr;
    /* could not allocate PacketBuffer for ARP request */

    return result;
}

/**
 * Send an ARP request packet asking for ipaddr to a specific eth address.
 * Used to send unicast request to refresh the ARP table just before an entry
 * times out
 *
 * @param netif the lwip network interface on which to send the request
 * @param ipaddr the IP address for which to ask
 * @param hw_dst_addr the ethernet address to send this packet to
 * @return ERR_OK if the request has been sent
 *         ERR_MEM if the ARP packet couldn't be allocated
 *         any other LwipError on failure
 */
static LwipError
etharp_request_dst(struct NetIfc* netif, const Ip4Addr* ipaddr, const struct EthAddr* hw_dst_addr)
{
    return etharp_raw(netif, (struct EthAddr *)netif->hwaddr, hw_dst_addr,
                      (struct EthAddr *)netif->hwaddr, get_net_ifc_ip4_addr(netif), &kEthzero,
                      ipaddr, ARP_REQUEST);
}

/**
 * Send an ARP request packet asking for ipaddr.
 *
 * @param netif the lwip network interface on which to send the request
 * @param ipaddr the IP address for which to ask
 * @return ERR_OK if the request has been sent
 *         ERR_MEM if the ARP packet couldn't be allocated
 *         any other LwipError on failure
 */
LwipError
etharp_request(struct NetIfc* netif, const Ip4Addr* ipaddr)
{
    Logf(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_request: sending ARP request.\n"));
    return etharp_request_dst(netif, ipaddr, &kEthbroadcast);
}

//
// END OF FILE
//
