//
// file: etharp.cpp
//

#include <opt.h>
#include <autoip.h>

#include <dhcp.h>

#include <etharp.h>

#include <ethernet.h>

#include <iana.h>

#include <ieee.h>

#include <lwip_debug.h>

#include <cstring>
#include <dhcp.cpp>
#include <ip4.h>
#include "util.h"


/** the time an ARP entry stays pending after first request,
 *  for ARP_TMR_INTERVAL = 1000, this is
 *  10 seconds.
 *
 *  @internal Keep this number at least 2, otherwise it might
 *  run out instantly if the timeout occurs directly after a request.
 */
constexpr auto kArpMaxPending = 5;







// static struct EtharpEntry arp_table[ARP_TABLE_SIZE];
//
// static NetIfcAddrIdx etharp_cached_entry;





static LwipStatus etharp_request_dst(NetworkInterface& netif, const Ip4AddrInfo& ipaddr, const MacAddress& hw_dst_addr);


static LwipStatus send_raw_arp_pkt(NetworkInterface& netif,
                                   const MacAddress& ethsrc_addr,
                                   const MacAddress& ethdst_addr,
                                   const MacAddress& hwsrc_addr,
                                   const Ip4AddrInfo& ipsrc_addr,
                                   const MacAddress& hwdst_addr,
                                   const Ip4AddrInfo& ipdst_addr,
                                   const uint16_t opcode);


/**
 * Clears expired entries in the ARP table.
 *
 * This function should be called every ARP_TMR_INTERVAL milliseconds (1 second),
 * in order to expire entries in the ARP table.
 */
void
clear_expired_arp_entries(std::vector<EtharpEntry>& entries)
{
    for (auto it = entries.begin(); it != entries.end(); ++it)
    {
        const auto state = it->state;
        if (it->state == ETHARP_STATE_EMPTY || state == ETHARP_STATE_STATIC)
        {
            continue;
        }
        it->ctime++;
        if (it->ctime >= ARP_MAXAGE || it->state == ETHARP_STATE_PENDING && it->ctime >=
            kArpMaxPending)
        {
            entries.erase(it);
        }
        else if (it->state == ETHARP_STATE_STABLE_REREQUESTING_1)
        {
            it->state = ETHARP_STATE_STABLE_REREQUESTING_2;
        }
        else if (it->state == ETHARP_STATE_STABLE_REREQUESTING_2)
        {
            it->state = ETHARP_STATE_STABLE;
        }
        else if (it->state == ETHARP_STATE_PENDING)
        {
            auto status = etharp_request(it->netif, it->ip4_addr_info);
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
 * @param entries
 *
 * @return The ARP entry index that matched or is created, ERR_MEM if no
 * entry is found or could be recycled.
 */
LwipStatus
etharp_find_entry(const Ip4AddrInfo& ipaddr,
                  const NetworkInterface& netif,
                  std::vector<EtharpEntry>& entries,
                  bool try_hard,
                  bool find_only,
                  bool static_entry,
                  size_t& found_index)
{
    /**
    * a) do a search through the cache, remember candidates
    * b) select candidate entry
    * c) create new entry
    */
    int16_t old_pending = ARP_TABLE_SIZE; /* a) in a single search sweep, do all of this
     * 1) remember the first empty entry (if any)
     * 2) remember the oldest stable entry (if any)
     * 3) remember the oldest pending entry without queued packets (if any)
     * 4) remember the oldest pending entry with queued packets (if any)
     * 5) search for a matching IP entry, either pending or stable
     *    until 5 matches, or all entries are searched for.
     */
    int16_t old_stable = ARP_TABLE_SIZE;
    int16_t empty = ARP_TABLE_SIZE;
    int16_t i = 0; /* oldest entry with packets on queue */
    int16_t old_queue = ARP_TABLE_SIZE; /* its age */
    uint16_t age_queue = 0;
    uint16_t age_pending = 0;
    uint16_t age_stable = 0;
    for (auto& it : entries)
    {
        if (is_ip4_addr_equal(ipaddr.address, it.ip4_addr_info.address) && netif.name == it
                                                                                     .netif
                                                                                     .name
        )
        {
            found_index = i;
            return STATUS_SUCCESS;
        }
        if (it.state == ETHARP_STATE_PENDING)
        {
            if (it.ctime >= age_queue)
            {
                age_queue = it.ctime;
                old_queue = i;
            }
            if (it.ctime >= age_pending)
            {
                age_pending = it.ctime;
                old_pending = i;
            }
        }
        else if (it.state == ETHARP_STATE_STABLE)
        {
            if (it.state < ETHARP_STATE_STATIC)
            {
                if (it.ctime >= age_stable)
                {
                    age_stable = it.ctime;
                    old_stable = i;
                }
            }
        }
        i++;
    } /* { we have no match } => try to create a new entry */
    /* don't create new entry, only search? */
    if (find_only || /* or no empty entry found and not allowed to recycle? */ (empty ==
        ARP_TABLE_SIZE && !try_hard))
    {
        // Logf(true | LWIP_DBG_TRACE, ("etharp_find_entry: no empty entry found and not allowed to recycle\n"));
        return ERR_MEM;
    } /* b) choose the least destructive entry to recycle:
     * 1) empty entry
     * 2) oldest stable entry
     * 3) oldest pending entry without queued packets
     * 4) oldest pending entry with queued packets
     *
     * { ETHARP_FLAG_TRY_HARD is set at this point }
     */ /* 1) empty entry available? */
    if (empty < ARP_TABLE_SIZE)
    {
        i = empty;
        // Logf(true | LWIP_DBG_TRACE, ("etharp_find_entry: selecting empty entry %d\n", (int)i));
    }
    else
    {
        /* 2) found recyclable stable entry? */
        if (old_stable < ARP_TABLE_SIZE)
        {
            /* recycle oldest stable*/
            i = old_stable;
        }
        else if (old_pending < ARP_TABLE_SIZE)
        {
            /* recycle oldest pending */
            i = old_pending; /* 4) found recyclable pending entry with queued packets? */
        }
        else if (old_queue < ARP_TABLE_SIZE)
        {
            /* recycle oldest pending (queued packets are free in etharp_free_entry) */
            i = old_queue;
        }
        else
        {
            return ERR_MEM;
        }
        entries.erase(entries.begin() + i);
    }
    copy_ip4_addr(entries[i].ip4_addr_info.address, ipaddr.address);
    entries[i].ctime = 0;
    entries[i].netif = netif;
    found_index =i;
    return STATUS_SUCCESS;
}


/**
 * Update (or insert) a IP/MAC address pair in the ARP cache.
 *
 * If a pending entry is resolved, any queued packets will be sent
 * at this point.
 *
 * @param netif netif related to this entry (used for NETIF_ADDRHINT)
 * @param addr_info IP address of the inserted ARP entry.
 * @param mac_address Ethernet address of the inserted ARP entry.
 * @param flags See @ref etharp_state
 *
 * @return
 * - ERR_OK Successfully updated ARP cache.
 * - ERR_MEM If we could not add a new ARP entry when ETHARP_FLAG_TRY_HARD was set.
 * - ERR_ARG Non-unicast address given, those will not appear in ARP cache.
 *
 * @see free_pkt_buf()
 */
static LwipStatus
etharp_update_arp_entry(NetworkInterface& netif,
                        const Ip4AddrInfo& addr_info,
                        MacAddress& mac_address,
                        bool try_hard,
                        bool static_entry,
                        std::vector<EtharpEntry> entries,
                        bool find_only)
{

    if (ip4_addr_isany(addr_info.address) ||
        is_netif_ip4_addr_bcast(addr_info.address, netif) ||
        is_ip4_addr_multicast(addr_info.address)) {
        return STATUS_E_INVALID_ARG;
    }
    /* find or create ARP entry */
    size_t found_index = 0;
    if(etharp_find_entry(addr_info, netif, entries, try_hard, find_only, static_entry, found_index) != STATUS_SUCCESS)
    {
        return STATUS_ERROR;
    }

    if (static_entry) {
        /* record static type */
        entries[found_index].state = ETHARP_STATE_STATIC;
    }
    else if (entries[found_index].state == ETHARP_STATE_STATIC) {
        /* found entry is a static type, don't overwrite it */
        return ERR_VAL;
    }
    else {
        /* mark it stable */
        entries[found_index].state = ETHARP_STATE_STABLE;
    }

    /* record network interface */
    entries[found_index].netif = netif;
    /* insert in SNMP ARP index tree */
    // mib2_add_arp_entry(netif, &arp_table[i].ipaddr);

    //  Logf(true | LWIP_DBG_TRACE, ("etharp_update_arp_entry: updating stable entry %"S16_F"\n", i));
    /* update address */
    entries[found_index].mac_address = mac_address;

    /* reset time stamp */
    entries[found_index].ctime = 0;
    /* this is where we will send out queued packets! */

    return send_ethernet_pkt(netif, entries[found_index].pkt_buf, netif.mac_address, mac_address, ETHTYPE_IP);


    return STATUS_SUCCESS;
}


/** Add a new static entry to the ARP table. If an entry exists for the
 * specified IP address, this entry is overwritten.
 * If packets are queued for the specified IP address, they are sent out.
 *
 * @param ip4_addr_info IP address for the new static entry
 * @param mac_address ethernet address for the new static entry
 * @param interfaces
 * @param try_hard
 * @param static_entry
 * @param find_only
 * @param entries
 * @return See return values of etharp_add_static_entry
 */
LwipStatus
etharp_add_static_entry(const Ip4AddrInfo& ip4_addr_info,
                        MacAddress& mac_address,
                        std::vector<NetworkInterface>& interfaces,
                        bool try_hard,
                        bool static_entry,
                        bool find_only,
                        std::vector<EtharpEntry>& entries)
{
    NetworkInterface found_netif{};
    if( get_netif_for_dst_ip4_addr(ip4_addr_info.address,interfaces, found_netif) != STATUS_SUCCESS)
    {
        return STATUS_E_ROUTING;
    }

    return etharp_update_arp_entry(found_netif, ip4_addr_info, mac_address, try_hard, static_entry, entries, find_only);
}


/** Remove a static entry from the ARP table previously added with a call to
 * etharp_add_static_entry.
 *
 * @param ip4_addr_info IP address of the static entry to remove
 * @return ERR_OK: entry removed
 *         ERR_MEM: entry wasn't found
 *         ERR_ARG: entry wasn't a static entry but a dynamic one
 */
LwipStatus
etharp_remove_static_entry(const Ip4AddrInfo& ip4_addr_info,
                           NetworkInterface& netif,
                           std::vector<EtharpEntry>& entries,
                           bool try_hard,
                           bool find_only,
                           bool static_entry)
{
    // find or create ARP entry
    size_t index = 0;
    if (etharp_find_entry(ip4_addr_info,
                          netif,
                          entries,
                          try_hard,
                          find_only,
                          static_entry,
                          index) != STATUS_SUCCESS)
    {
        return STATUS_ERROR;
    }
    if (entries[index].state != ETHARP_STATE_STATIC)
    {
        // entry wasn't a static entry, cannot remove it
        return STATUS_E_INVALID_ARG;
    }
    // entry found, free it
    entries.erase(entries.begin() + index);
    return STATUS_SUCCESS;
}


/**
 * Remove all ARP table entries of the specified netif.
 *
 * @param netif points to a network interface
 * @param entries
 */
void
etharp_cleanup_netif(NetworkInterface& netif, std::vector<EtharpEntry>& entries)
{

    for (auto it = entries.begin(); it != entries.end(); ++it)
    {

        if (it->netif.name == netif.name)
        {
            entries.erase(it);
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
 * @param entries
 * @param try_hard
 * @param find_only
 * @param static_entry
 * @return table index if found, -1 otherwise
 */
LwipStatus
find_etharp_addr(NetworkInterface& netif,
                 const Ip4AddrInfo& ipaddr,
                 MacAddress& eth_ret,
                 Ip4AddrInfo& ip_ret,
                 std::vector<EtharpEntry>& entries,
                 const bool try_hard,
                 const bool find_only,
                 const bool static_entry)
{
    size_t found_index = 0;
    if (etharp_find_entry(ipaddr,
                          netif,
                          entries,
                          try_hard,
                          find_only,
                          static_entry,
                          found_index) != STATUS_SUCCESS)
    {
        return STATUS_ERROR;
    }
    if ((found_index >= 0) && (entries[found_index].state >= ETHARP_STATE_STABLE))
    {
        eth_ret = entries[found_index].mac_address;
        ip_ret = entries[found_index].ip4_addr_info;
        return STATUS_SUCCESS;
    }
    return STATUS_ERROR;
}


/**
 * Possibility to iterate over stable ARP table entries
 *
 * @param index entry number, 0 to ARP_TABLE_SIZE
 * @param ipaddr return value: IP address
 * @param netif return value: points to interface
 * @param eth_ret return value: ETH address
 * @param entries
 * @return 1 on valid index, 0 otherwise
 */
bool
etharp_get_entry(size_t index,
                 Ip4AddrInfo& ipaddr,
                 NetworkInterface& netif,
                 MacAddress& eth_ret,
                 std::vector<EtharpEntry> entries)
{
    if ((index < ARP_TABLE_SIZE) && (entries[index].state >= ETHARP_STATE_STABLE))
    {
        ipaddr = entries[index].ip4_addr_info;
        netif = entries[index].netif;
        eth_ret = entries[index].mac_address;
        return true;
    }
    return false;
}


/**
 * Responds to ARP requests to us. Upon ARP replies to us, add entry to cache
 * send out queued IP packets. Updates cache with snooped address pairs.
 *
 * Should be called for incoming ARP packets. The PacketBuffer in the argument
 * is freed by this function.
 *
 * @param pkt_buf The ARP packet that arrived on netif. Is freed by this function.
 * @param netif The lwIP network interface on which the ARP packet PacketBuffer arrived.
 *
 * @see free_pkt_buf()
 */
LwipStatus
recv_etharp(PacketBuffer& pkt_buf, NetworkInterface& netif)
{
    Ip4Addr sipaddr{};
    Ip4Addr dipaddr{};
    uint8_t for_us;



    auto hdr = reinterpret_cast<struct EtharpHdr *>(pkt_buf->payload);
    /* RFC 826 "Packet Reception": */
    if ((hdr->hwtype != pp_htons(LWIP_IANA_HWTYPE_ETHERNET)) || (hdr->hwlen !=
        ETH_ADDR_LEN) || (hdr->protolen != sizeof(Ip4Addr)) || (hdr->proto != pp_htons(
        ETHTYPE_IP)))
    {
        //    Logf(true | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
        //                ("etharp_input: packet dropped, wrong hw type, hwlen, proto, protolen or ethernet type (%d/%d/%d/%d)\n",
        //                 hdr->hwtype, (uint16_t)hdr->hwlen, hdr->proto, (uint16_t)hdr->protolen));
        // ETHARP_STATS_INC(etharp.proterr);
        // ETHARP_STATS_INC(etharp.drop);
        free_pkt_buf(pkt_buf);
        return;
    } // ETHARP_STATS_INC(etharp.recv);
    /* We have to check if a host already has configured our random
     * created link local address and continuously check if there is
     * a host with this IP-address so we can detect collisions */
    autoip_arp_reply(netif, hdr);
    /* Copy struct ip4_addr_wordaligned to aligned ip4_addr, to support compilers without
        * structure packing (not using structure copy which breaks strict-aliasing rules). */
    IpaddrWordalignedCopyToIp4AddrT(&hdr->sipaddr, &sipaddr);
    IpaddrWordalignedCopyToIp4AddrT(&hdr->dipaddr, &dipaddr);
    /* this interface is not configured? */
    if (ip4_addr_isany_val(*get_netif_ip4_addr(netif, , )))
    {
        for_us = 0;
    }
    else
    {
        /* ARP packet directed to us? */
        for_us = uint8_t(is_ip4_addr_equal(&dipaddr, get_netif_ip4_addr(netif, , )));
    } /* ARP message directed to us?
        -> add IP address in ARP cache; assume requester wants to talk to us,
           can result in directly sending the queued packets for this host.
       ARP message not directed to us?
        ->  update the source IP address in the cache, if present */
    etharp_update_arp_entry(netif, &sipaddr, &(hdr->shwaddr), , , , );
    /* now act on the message itself */ /* ARP request? */
    if (hdr->opcode == pp_htons(ARP_REQUEST))
    {
        /* ARP request. If it asked for our address, we send out a
         * reply. In any case, we time-stamp any existing ARP entry,
         * and possibly send out an IP packet that was queued on it. */
        Logf(true, ("etharp_input: incoming ARP request\n"));
        /* ARP request for our address? */
        if (for_us)
        {
            /* send ARP response */
            send_raw_arp_pkt(netif,
                             (struct MacAddress *)netif->hwaddr,
                             &hdr->shwaddr,
                             (struct MacAddress *)netif->hwaddr,
                             get_netif_ip4_addr(netif, , ),
                             &hdr->shwaddr,
                             &sipaddr,
                             ARP_REPLY); /* we are not configured? */
        }
        else if (ip4_addr_isany_val(*get_netif_ip4_addr(netif, , )))
        {
            /* { for_us == 0 and netif->ip_addr.addr == 0 } */
            Logf(true, ("etharp_input: we are unconfigured, ARP request ignored.\n"));
            /* request was not directed to us */
        }
        else
        {
            /* { for_us == 0 and netif->ip_addr.addr != 0 } */
            Logf(true, ("etharp_input: ARP request was not for us.\n"));
        }
    }
    else if (hdr->opcode == pp_htons(ARP_REPLY))
    {
        /* ARP reply. We already updated the ARP cache earlier. */
        Logf(true, ("etharp_input: incoming ARP reply\n"));
        /* DHCP wants to know about ARP replies from any host with an
                * IP address also offered to us by the DHCP server. We do not
                * want to take a duplicate IP address on a single network.
                * @todo How should we handle redundant (fail-over) interfaces? */
        dhcp_arp_reply(netif, &sipaddr);
    }
    else
    {
        //      Logf(true | LWIP_DBG_TRACE, ("etharp_input: ARP unknown opcode type %"S16_F"\n", lwip_htons(hdr->opcode)));
        // ETHARP_STATS_INC(etharp.err);
    } /* free ARP packet */
    free_pkt_buf(pkt_buf);
}


/** Just a small helper function that sends a PacketBuffer to an ethernet address
 * in the arp_table specified by the index 'arp_idx'.
 */
static LwipStatus
etharp_output_to_arp_index(struct NetworkInterface* netif, struct PacketBuffer* q, NetIfcAddrIdx arp_idx)
{
    lwip_assert("arp_table[arp_idx].state >= ETHARP_STATE_STABLE",
                arp_table[arp_idx].state >= ETHARP_STATE_STABLE);
    /* if arp table entry is about to expire: re-request it,
       but only if its state is ETHARP_STATE_STABLE to prevent flooding the
       network with ARP requests if this address is used frequently. */
    if (arp_table[arp_idx].state == ETHARP_STATE_STABLE) {
        if (arp_table[arp_idx].ctime >= ARP_AGE_REREQUEST_USED_BROADCAST) {
            /* issue a standard request using broadcast */
            if (etharp_request(netif, &arp_table[arp_idx].ipaddr) == STATUS_SUCCESS) {
                arp_table[arp_idx].state = ETHARP_STATE_STABLE_REREQUESTING_1;
            }
        }
        else if (arp_table[arp_idx].ctime >= ARP_AGE_REREQUEST_USED_UNICAST) {
            /* issue a unicast request (for 15 seconds) to prevent unnecessary broadcast */
            if (etharp_request_dst(netif, &arp_table[arp_idx].ipaddr, &arp_table[arp_idx].MacAddress) == STATUS_SUCCESS) {
                arp_table[arp_idx].state = ETHARP_STATE_STABLE_REREQUESTING_1;
            }
        }
    }

    return send_ethernet_pkt(netif, q, (struct MacAddress *)(netif->hwaddr), &arp_table[arp_idx].MacAddress, ETHTYPE_IP);
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
LwipStatus
etharp_output(struct NetworkInterface* netif, struct PacketBuffer* q, const Ip4Addr* ipaddr)
{
    const struct MacAddress* dest;
    struct MacAddress mcastaddr{};
    auto dst_addr = ipaddr;


    lwip_assert("netif != NULL", netif != nullptr);
    lwip_assert("q != NULL", q != nullptr);
    lwip_assert("ipaddr != NULL", ipaddr != nullptr);

    /* Determine on destination hardware address. Broadcasts and multicasts
     * are special, other IP addresses are looked up in the ARP table. */

    /* broadcast destination IP address? */
    if (ip4_addr_isbroadcast(ipaddr, netif)) {
        /* broadcast on Ethernet also */
        dest = (const struct MacAddress *)&ETH_BCAST_ADDR;
        /* multicast destination IP address? */
    }
    else if (is_ip4_addr_multicast(ipaddr)) {
        /* Hash IP multicast address to MAC address.*/
        mcastaddr.bytes[0] = LNK_LYR_MCAST_ADDR_OUI[0];
        mcastaddr.bytes[1] = LNK_LYR_MCAST_ADDR_OUI[1];
        mcastaddr.bytes[2] = LNK_LYR_MCAST_ADDR_OUI[2];
        mcastaddr.bytes[3] = ip4_addr2(ipaddr) & 0x7f;
        mcastaddr.bytes[4] = ip4_addr3(ipaddr);
        mcastaddr.bytes[5] = ip4_addr4(ipaddr);
        /* destination Ethernet address is multicast */
        dest = &mcastaddr;
        /* unicast destination IP address? */
    }
    else {
        /* outside local network? if so, this can neither be a global broadcast nor
           a subnet broadcast. */
        if (!cmp_ip4_addr_net(ipaddr, get_netif_ip4_addr(netif,,), get_netif_ip4_netmask(netif,)) &&
            !is_ip4_addr_link_local(ipaddr)) {
            auto iphdr = reinterpret_cast<Ip4Hdr&>(q->payload);
            /* According to RFC 3297, chapter 2.6.2 (Forwarding Rules), a packet with
               a link-local source address must always be "directly to its destination
               on the same physical link. The host MUST NOT send the packet to any
               router for forwarding". */
            if (!is_ip4_addr_link_local(&iphdr->src)) {
                {
                    /* interface has default gateway? */
                    if (!ip4_addr_isany_val(*get_netif_ip4_gw(netif,))) {
                        /* send to hardware address of default gateway IP address */
                        dst_addr = get_netif_ip4_gw(netif,);
                        /* no default gateway available */
                    }
                    else {
                        /* no route to destination error (default gateway missing) */
                        return STATUS_E_ROUTING;
                    }
                }
            }
        }

        if (netif->hints != nullptr) {
            /* per-pcb cached entry was given */
            const auto etharp_cached_entry = netif->hints->addr_hint;
            if (etharp_cached_entry < ARP_TABLE_SIZE) {
                if ((arp_table[etharp_cached_entry].state >= ETHARP_STATE_STABLE) &&

                    (arp_table[etharp_cached_entry].netif == netif) &&

                    (is_ip4_addr_equal(dst_addr, &arp_table[etharp_cached_entry].ipaddr))) {
                    /* the per-pcb-cached entry is stable and the right one! */
                    // ETHARP_STATS_INC(etharp.cachehit);
                    return etharp_output_to_arp_index(netif, q, etharp_cached_entry);
                }
            }
        }


        /* find stable entry: do this here since this is a critical path for
           throughput and etharp_find_entry() is kind of slow */
        for (NetIfcAddrIdx i = 0; i < ARP_TABLE_SIZE; i++) {
            if ((arp_table[i].state >= ETHARP_STATE_STABLE) &&

                (arp_table[i].netif == netif) &&

                (is_ip4_addr_equal(dst_addr, &arp_table[i].ipaddr))) {
                /* found an existing, stable entry */
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
    return send_ethernet_pkt(netif, q, (struct MacAddress *)(netif->hwaddr), dest, ETHTYPE_IP);
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
LwipStatus
etharp_query(struct NetworkInterface* netif, const Ip4Addr* ipaddr, struct PacketBuffer* q)
{
    struct MacAddress* srcaddr = (struct MacAddress *)netif->hwaddr;
    LwipStatus result = ERR_MEM;
    int is_new_entry = 0; /* non-unicast address? */
    if (ip4_addr_isbroadcast(ipaddr, netif) ||
        is_ip4_addr_multicast(ipaddr) ||
        ip4_addr_isany(ipaddr)) {
        Logf(true, ("etharp_query: will not add non-unicast IP address to ARP cache\n"));
        return STATUS_E_INVALID_ARG;
    }

    /* find entry in ARP cache, ask to create entry if queueing packet */
    int16_t i_err = etharp_find_entry(ipaddr, netif, ,,,,);

    /* could not find or create entry? */
    if (i_err < 0) {
        Logf(true, ("etharp_query: could not create ARP entry\n"));
        if (q) {
            Logf(true, ("etharp_query: packet dropped\n"));
            // ETHARP_STATS_INC(etharp.memerr);
        }
        return (LwipStatus)i_err;
    }
    lwip_assert("type overflow", (size_t)i_err < NETIF_ADDR_IDX_MAX);
    NetIfcAddrIdx i = (NetIfcAddrIdx)i_err;

    /* mark a fresh entry as pending (we just sent a request) */
    if (arp_table[i].state == ETHARP_STATE_EMPTY) {
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
    if (is_new_entry || (q == nullptr)) {
        /* try to resolve it; send out ARP request */
        result = etharp_request(netif, ipaddr);
        if (result != STATUS_SUCCESS) {
            /* ARP request couldn't be sent */
            /* We don't re-send arp request in etharp_tmr, but we still queue packets,
               since this failure could be temporary, and the next packet calling
               etharp_query again could lead to sending the queued packets. */
        }
        if (q == nullptr) {
            return result;
        }
    }

    /* packet given? */
    lwip_assert("q != NULL", q != nullptr);
    /* stable entry? */
    if (arp_table[i].state >= ETHARP_STATE_STABLE) {
        /* we have a valid IP->Ethernet address mapping */
        /* send the packet */
        result = send_ethernet_pkt(netif, q, srcaddr, &(arp_table[i].MacAddress), ETHTYPE_IP);
        /* pending entry? (either just created or already pending */
    }
    else if (arp_table[i].state == ETHARP_STATE_PENDING) {
        int copy_needed = 0;
        /* IF q includes a PacketBuffer that must be copied, copy the whole chain into a
         * new PBUF_RAM. See the definition of PBUF_NEEDS_COPY for details. */
        struct PacketBuffer* p = q;
        while (p) {
            lwip_assert("no packet queues allowed!", (p->len != p->tot_len) || (p->next == nullptr));
            // if (PbufNeedsCopy(p)) {
            //     copy_needed = 1;
            //     break;
            // }
            p = p->next;
        }
        if (copy_needed) {
            /* copy the whole packet into new pbufs */
            p = pbuf_clone(q);
        }
        else {
            /* referencing the old PacketBuffer is enough */
            p = q;
            // pbuf_ref(p);
        }
        /* packet could be taken over? */
        if (p != nullptr) {
            /* queue packet ... */

            /* allocate a new arp queue entry */
            // new_entry = (struct etharp_q_entry *)memp_malloc(MEMP_ARP_QUEUE);
            auto new_entry = new EtharpEntry;
            if (new_entry != nullptr) {
                unsigned int qlen = 0;
                new_entry->next = nullptr;
                new_entry->pkt_buf = p;
                if (arp_table[i].next != nullptr) {
                    EtharpEntry* r = arp_table[i].next;
                    qlen++;
                    while (r->next != nullptr) {
                        r = r->next;
                        qlen++;
                    }
                    r->next = new_entry;
                }
                else {
                    /* queue did not exist, first item in queue */
                    arp_table[i].next = new_entry;
                }

                if (qlen >= ARP_QUEUE_LEN) {
                    EtharpEntry* old = arp_table[i].next;
                    arp_table[i].next = arp_table[i].next->next;
                    free_pkt_buf(old->pkt_buf);
                    delete old;
                }

                // Logf(true | LWIP_DBG_TRACE, ("etharp_query: queued packet %p on ARP entry %d\n", (void *)q, i));
                result = STATUS_SUCCESS;
            }
            else {
                /* the pool MEMP_ARP_QUEUE is empty */
                free_pkt_buf(p);
                // Logf(true | LWIP_DBG_TRACE, ("etharp_query: could not queue a copy of PBUF_REF packet %p (out of memory)\n", (uint8_t *)q));
                result = ERR_MEM;
            }
        }
        else {
            // ETHARP_STATS_INC(etharp.memerr);
            //      Logf(true | LWIP_DBG_TRACE, ("etharp_query: could not queue a copy of PBUF_REF packet %p (out of memory)\n", (uint8_t *)q));
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
 *         any other LwipStatus on failure
 */
static LwipStatus
send_raw_arp_pkt(NetworkInterface& netif,
                 const MacAddress& ethsrc_addr,
                 const MacAddress& ethdst_addr,
                 const MacAddress& hwsrc_addr,
                 const Ip4AddrInfo& ipsrc_addr,
                 const MacAddress& hwdst_addr,
                 const Ip4AddrInfo& ipdst_addr,
                 const uint16_t opcode)
{
    /* allocate a PacketBuffer for the outgoing ARP request packet */
    PacketBuffer packet_buffer{};
    EtharpHdr etharp_hdr{};
    etharp_hdr.opcode = lwip_htons(opcode);
    etharp_hdr.shwaddr = hwsrc_addr;
    etharp_hdr.dhwaddr = hwdst_addr;
    etharp_hdr.sipaddr = ipsrc_addr.address;
    etharp_hdr.dipaddr = ipdst_addr.address;
    etharp_hdr.hwtype = pp_htons(LWIP_IANA_HWTYPE_ETHERNET);
    etharp_hdr.proto = pp_htons(ETHTYPE_IP);
    etharp_hdr.hwlen = ETH_ADDR_LEN;
    etharp_hdr.protolen = sizeof(Ip4Addr);

    packet_buffer.data = std::vector<uint8_t>(reinterpret_cast<uint8_t*>(&etharp_hdr),
                                              reinterpret_cast<uint8_t*>(&etharp_hdr) + sizeof(EtharpHdr));

    /* send ARP query */

    /* If we are using Link-Local, all ARP packets that contain a Link-Local
     * 'sender IP address' MUST be sent using link-layer broadcast instead of
     * link-layer unicast. (See RFC3927 Section 2.5, last paragraph) */
    if (is_ip4_addr_link_local(ipsrc_addr)) {
        return send_ethernet_pkt(netif, packet_buffer, ethsrc_addr, ETH_BCAST_ADDR, ETHTYPE_ARP);
    }
        return send_ethernet_pkt(netif, packet_buffer, ethsrc_addr, ethdst_addr, ETHTYPE_ARP);
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
 *         any other LwipStatus on failure
 */
static LwipStatus
etharp_request_dst(NetworkInterface& netif, const Ip4AddrInfo& ipaddr, const MacAddress& hw_dst_addr)
{
    Ip4AddrInfo src_ip4_addr{};
    if (get_netif_ip4_addr(netif, ipaddr, src_ip4_addr) != STATUS_SUCCESS)
    {
        return STATUS_ERROR;
    }

    return send_raw_arp_pkt(netif,
                            netif.mac_address,
                            hw_dst_addr,
                            netif.mac_address,
                            src_ip4_addr,
                            ETH_ZERO_ADDR,
                            ipaddr,
                            ARP_REQUEST);
}


/**
 * Send an ARP request packet asking for ipaddr.
 *
 * @param netif the lwip network interface on which to send the request
 * @param ipaddr the IP address for which to ask
 * @return ERR_OK if the request has been sent
 *         ERR_MEM if the ARP packet couldn't be allocated
 *         any other LwipStatus on failure
 */
LwipStatus
etharp_request(NetworkInterface& netif, const Ip4AddrInfo& ipaddr)
{
    Logf(true, ("etharp_request: sending ARP request.\n"));
    return etharp_request_dst(netif, ipaddr, ETH_BCAST_ADDR);
}


//
// END OF FILE
//
