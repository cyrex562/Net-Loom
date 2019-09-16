/**
 * @file etharp.cpp
 */
#include "etharp.h"
#include "opt.h"
#include "autoip.h"
#include "dhcp.h"
#include "ethernet.h"
#include "iana.h"
#include "ieee.h"
#include "lwip_debug.h"
#include <dhcp.cpp>
#include "ip4.h"
#include "util.h"
#include "spdlog/spdlog.h"
#include <cstring>
#include <vector>


/**
 * Clears expired entries in the ARP table.
 *
 * This function should be called every ARP_TMR_INTERVAL milliseconds (1 second),
 * in order to expire entries in the ARP table.
 */
bool
clear_expired_arp_entries(std::vector<EtharpEntry>& entries)
{
    for (auto it = entries.begin(); it != entries.end(); ++it) {
        const auto state = it->state;
        if (it->state == ETHARP_STATE_EMPTY || state == ETHARP_STATE_STATIC) { continue; }
        it->ctime++;
        if (it->ctime >= ARP_MAXAGE || it->state == ETHARP_STATE_PENDING && it->ctime >=
            ARP_MAX_PENDING) { entries.erase(it); }
        else if (it->state == ETHARP_STATE_STABLE_REREQUESTING_1) {
            it->state = ETHARP_STATE_STABLE_REREQUESTING_2;
        }
        else if (it->state == ETHARP_STATE_STABLE_REREQUESTING_2) {
            it->state = ETHARP_STATE_STABLE;
        }
        else if (it->state == ETHARP_STATE_PENDING) {
            if (!etharp_request(it->netif, it->ip_addr)) { }
        }
    }
    return true;
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
 * @param ip_addr IP address to find in ARP cache, or to add if not found.
 * @param flags See @ref etharp_state
 * @param netif netif related to this address (used for NETIF_HWADDRHINT)
 * @param entries
 *
 * @return The ARP entry index that matched or is created, ERR_MEM if no
 * entry is found or could be recycled.
 */
std::tuple<bool, size_t>
etharp_find_entry(const Ip4Addr& ip_addr,
                  const NetworkInterface& netif,
                  std::vector<EtharpEntry>& entries)
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
    size_t found_index = 0;
    for (auto& it : entries) {
        if ((ip_addr.u32 == it.ip_addr.u32) && netif.name == it.netif.name) {
            found_index = i;
            return std::make_tuple(true, found_index);
        }
        if (it.state == ETHARP_STATE_PENDING) {
            if (it.ctime >= age_queue) {
                age_queue = it.ctime;
                old_queue = i;
            }
            if (it.ctime >= age_pending) {
                age_pending = it.ctime;
                old_pending = i;
            }
        }
        else if (it.state == ETHARP_STATE_STABLE) {
            if (it.state < ETHARP_STATE_STATIC) {
                if (it.ctime >= age_stable) {
                    age_stable = it.ctime;
                    old_stable = i;
                }
            }
        }
        i++;
    }
    /* { we have no match } => try to create a new entry */
    /* don't create new entry, only search? */
    if (empty == ARP_TABLE_SIZE) {
        // Logf(true | LWIP_DBG_TRACE, ("etharp_find_entry: no empty entry found and not allowed to recycle\n"));
        return std::make_tuple(false, found_index);
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
    if (empty < ARP_TABLE_SIZE) { i = empty; }
    else {
        /* 2) found recyclable stable entry? */
        if (old_stable < ARP_TABLE_SIZE) {
            /* recycle oldest stable*/
            i = old_stable;
        }
        else if (old_pending < ARP_TABLE_SIZE) {
            /* recycle oldest pending */
            i = old_pending; /* 4) found recyclable pending entry with queued packets? */
        }
        else if (old_queue < ARP_TABLE_SIZE) {
            /* recycle oldest pending (queued packets are free in etharp_free_entry) */
            i = old_queue;
        }
        else { return std::make_tuple(false, found_index); }
        entries.erase(entries.begin() + i);
    }
    (entries[i].ip_addr = ip_addr);
    entries[i].ctime = 0;
    entries[i].netif = netif;
    found_index = i;
    return std::make_tuple(true, found_index);
}


/**
 * Update (or insert) a IP/MAC address pair in the ARP cache.
 *
 * If a pending entry is resolved, any queued packets will be sent
 * at this point.
 *
 * @param netif netif related to this entry (used for NETIF_ADDRHINT)
 * @param ip_addr IP address of the inserted ARP entry.
 * @param mac_address Ethernet address of the inserted ARP entry.
 * @param try_hard
 * @param static_entry
 * @param entries
 * @param flags See @ref etharp_state
 *
 * @return
 * - ERR_OK Successfully updated ARP cache.
 * - ERR_MEM If we could not add a new ARP entry when ETHARP_FLAG_TRY_HARD was set.
 * - ERR_ARG Non-unicast address given, those will not appear in ARP cache.
 *
 * @see free_pkt_buf()
 */
bool
etharp_update_arp_entry(NetworkInterface& netif,
                        const Ip4Addr& ip_addr,
                        MacAddress& mac_address,
                        bool static_entry,
                        std::vector<EtharpEntry> entries)
{
    if ((ip_addr.u32 == IP4_ADDR_ANY_U32) || netif_is_ip4_addr_bcast(ip_addr, netif) ||
        ip4_addr_is_mcast(ip_addr)) { return false; }
    /* find or create ARP entry */
    size_t found_index = 0;
    bool ok = true;
    std::make_tuple(ok, found_index) = etharp_find_entry(ip_addr, netif, entries);
    if (!ok) { return false; }
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
    return send_ethernet_pkt(netif,
                             entries[found_index].pkt_buf,
                             netif.mac_address,
                             mac_address,
                             ETHTYPE_IP);
}


/**
 * Add a new static entry to the ARP table. If an entry exists for the
 * specified IP address, this entry is overwritten.
 * If packets are queued for the specified IP address, they are sent out.
 *
 * @param ip_addr IP address for the new static entry
 * @param mac_address ethernet address for the new static entry
 * @param interfaces
 * @param try_hard
 * @param static_entry
 * @param find_only
 * @param entries
 * @return See return values of etharp_add_static_entry
 */
bool
etharp_add_static_entry(const Ip4Addr& ip_addr,
                        MacAddress& mac_address,
                        std::vector<NetworkInterface>& interfaces,
                        bool static_entry,
                        std::vector<EtharpEntry>& entries)
{
    NetworkInterface found_netif{};
    bool ok;
    std::tie(ok, found_netif) = get_netif_for_dst_ip4_addr(ip_addr, interfaces);
    if (!ok) { return false; }
    return etharp_update_arp_entry(found_netif,
                                   ip_addr,
                                   mac_address,
                                   static_entry,
                                   entries);
}


/** Remove a static entry from the ARP table previously added with a call to
 * etharp_add_static_entry.
 *
 * @param ip4_addr_info IP address of the static entry to remove
 * @param netif
 * @param entries
 * @return ERR_OK: entry removed
 *         ERR_MEM: entry wasn't found
 *         ERR_ARG: entry wasn't a static entry but a dynamic one
 */
bool
etharp_remove_static_entry(const Ip4AddrInfo& ip4_addr_info,
                           NetworkInterface& netif,
                           std::vector<EtharpEntry>& entries)
{
    // find or create ARP entry
    size_t index = 0;
    bool ok;
    std::tie(ok, index) = etharp_find_entry(ip4_addr_info.address, netif, entries);
    if (!ok) { return false; }
    if (entries[index].state != ETHARP_STATE_STATIC) {
        // entry wasn't a static entry, cannot remove it
        return false;
    }
    // entry found, free it
    entries.erase(entries.begin() + index);
    return false;
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
    for (auto it = entries.begin(); it != entries.end(); ++it) {
        if (it->netif.name == netif.name) { entries.erase(it); }
    }
}


/**
 * Finds (stable) ethernet/IP address pair from ARP table
 * using interface and IP address index.
 * @note the addresses in the ARP table are in network order!
 *
 * @param net_ifc points to interface index
 * @param ip_addr points to the (network order) IP address index
 * @param entries
 * @return table index if found, -1 otherwise
 */
std::tuple<bool, size_t, MacAddress, Ip4Addr>
find_etharp_addr(NetworkInterface& net_ifc,
                 const Ip4Addr& ip_addr,
                 std::vector<EtharpEntry>& entries)
{
    size_t found_index = 0;
    bool ok;
    MacAddress ret_mac_addr{};
    Ip4Addr ret_ip_addr{};
    std::tie(ok, found_index) = etharp_find_entry(ip_addr, net_ifc, entries);
    if (!ok) { return std::make_tuple(false, found_index, ret_mac_addr, ret_ip_addr); }
    if ((found_index >= 0) && (entries[found_index].state >= ETHARP_STATE_STABLE)) {
        ret_mac_addr = entries[found_index].mac_address;
        ret_ip_addr = entries[found_index].ip_addr;
        return std::make_tuple(true, found_index, ret_mac_addr, ret_ip_addr);
    }
    return std::make_tuple(false, found_index, ret_mac_addr, ret_ip_addr);
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
std::tuple<bool, NetworkInterface, MacAddress, Ip4Addr>
etharp_get_entry(size_t index, std::vector<EtharpEntry> entries)
{
    if ((index < ARP_TABLE_SIZE) && (entries[index].state >= ETHARP_STATE_STABLE)) {
        return std::make_tuple(true,
                               entries[index].netif,
                               entries[index].mac_address,
                               entries[index].ip_addr);
    }
    NetworkInterface empty_netif{};
    MacAddress empty_mac_address{};
    Ip4Addr empty_ip_addr{};
    return std::make_tuple(false, empty_netif, empty_mac_address, empty_ip_addr);
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
 * @param entries
 *
 * @see free_pkt_buf()
 */
bool
etharp_recv(PacketBuffer& pkt_buf,
            NetworkInterface& netif,
            DhcpContext& ctx,
            std::vector<EtharpEntry>& entries)
{
    Ip4Addr sipaddr{};
    const Ip4Addr dipaddr{};
    auto for_us = false;
    EtharpHdr hdr{};
    memcpy(&hdr, pkt_buf.data.data(), sizeof(EtharpHdr));

    /* RFC 826 "Packet Reception": */
    if ((hdr.hwtype != pp_htons(LWIP_IANA_HWTYPE_ETHERNET)) || (hdr.hwlen != ETH_ADDR_LEN)
        || (hdr.protolen != sizeof(Ip4Addr)) || (hdr.proto != pp_htons(ETHTYPE_IP))) {
        return false;
    }

    /*
     * We have to check if a host already has configured our random
     * created link local address and continuously check if there is
     * a host with this IP-address so we can detect collisions
     */
    autoip_arp_reply(netif, hdr, );

    /*
     * Copy struct ip4_addr_wordaligned to aligned ip4_addr, to support compilers
     * without structure packing (not using structure copy which breaks strict-aliasing
     * rules).
     */
    hdr.sipaddr = sipaddr;
    hdr.dipaddr = dipaddr;

    /* this interface is not configured? */
    Ip4AddrInfo dst_addr{};
    dst_addr.address = dipaddr;
    Ip4AddrInfo netif_ip_addr{};
    auto ok = true;
    std::tie(ok, netif_ip_addr) = get_netif_ip4_addr(netif, dipaddr);
    if (!ok) { return false; }
    if ((dipaddr.u32 == IP4_ADDR_ANY_U32)) { for_us = false; }
    else {
        /* ARP packet directed to us? */
        for_us = (dipaddr.u32 == netif_ip_addr.address.u32);
    }

    /*
     * ARP message directed to us?
        -> add IP address in ARP cache; assume requester wants to talk to us,
           can result in directly sending the queued packets for this host.
       ARP message not directed to us?
        ->  update the source IP address in the cache, if present
    */
    // Ip4AddrInfo sipaddr_info{};
    // sipaddr_info.address = sipaddr;
    etharp_update_arp_entry(netif, sipaddr, hdr.shwaddr, false, entries);
    /* now act on the message itself */
    /* ARP request? */
    if (hdr.opcode == pp_htons(ARP_REQUEST)) {
        /* ARP request. If it asked for our address, we send out a
         * reply. In any case, we time-stamp any existing ARP entry,
         * and possibly send out an IP packet that was queued on it. */
        /* ARP request for our address? */
        if (for_us) {
            /* send ARP response */
            send_raw_arp_pkt(netif,
                             netif.mac_address,
                             hdr.shwaddr,
                             netif.mac_address,
                             netif_ip_addr.address,
                             hdr.shwaddr,
                             sipaddr,
                             ARP_REPLY);
        }
            /* we are not configured? */ else if ((netif_ip_addr.address.u32 ==
            IP4_ADDR_ANY_U32)) {
            spdlog::info("etharp_input: we are unconfigured, ARP request ignored.\n");
        }
        else {
            /* { for_us == 0 and netif->ip_addr.addr != 0 } */
            spdlog::info("etharp_input: ARP request was not for us.\n");
        }
    }
    else if (hdr.opcode == pp_htons(ARP_REPLY)) {
        /* ARP reply. We already updated the ARP cache earlier. */
        spdlog::info("etharp_input: incoming ARP reply\n");
        /*
         * DHCP wants to know about ARP replies from any host with an IP address also
         * offered to us by the DHCP server. We do not want to take a duplicate IP
         * address on a single network.
         * @todo How should we handle redundant (fail-over) interfaces?
         */
        if (!dhcp_arp_reply(netif, sipaddr, ctx)) { return false; }
    }
    else {
        //      Logf(true | LWIP_DBG_TRACE, ("etharp_input: ARP unknown opcode type %"S16_F"\n", lwip_htons(hdr->opcode)));
        // ETHARP_STATS_INC(etharp.err);
    }
    /* free ARP packet */
    // free_pkt_buf(pkt_buf);
    return true;
}


/**
 * Just a small helper function that sends a PacketBuffer to an ethernet address in the
 * arp_table specified by the index 'arp_idx'.
 */
bool
etharp_output_to_arp_index(NetworkInterface& netif,
                           PacketBuffer& packet,
                           NetIfcAddrIdx arp_idx,
                           std::vector<EtharpEntry>& arp_table)
{
    if (arp_table.size() <= arp_idx) { return false; }

    /* if arp table entry is about to expire: re-request it,
          but only if its state is ETHARP_STATE_STABLE to prevent flooding the
          network with ARP requests if this address is used frequently. */
    if (arp_table[arp_idx].state == ETHARP_STATE_STABLE) {
        if (arp_table[arp_idx].ctime >= ARP_AGE_REREQUEST_USED_BROADCAST) {
            /* issue a standard request using broadcast */
            if (etharp_request(netif, arp_table[arp_idx].ip_addr)) {
                arp_table[arp_idx].state = ETHARP_STATE_STABLE_REREQUESTING_1;
            }
        }
        else if (arp_table[arp_idx].ctime >= ARP_AGE_REREQUEST_USED_UNICAST) {
            /* issue a unicast request (for 15 seconds) to prevent unnecessary broadcast */
            if (etharp_request_dst(netif,
                                   arp_table[arp_idx].ip_addr,
                                   arp_table[arp_idx].mac_address) == STATUS_SUCCESS) {
                arp_table[arp_idx].state = ETHARP_STATE_STABLE_REREQUESTING_1;
            }
        }
    }
    return send_ethernet_pkt(netif,
                             packet,
                             netif.mac_address,
                             arp_table[arp_idx].mac_address,
                             ETHTYPE_IP);
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
 * @param packet The PacketBuffer(s) containing the IP packet to be sent.
 * @param ip_addr
 * @param entries
 * @param ip_addr_info The IP address of the packet destination.
 *
 * @return
 * - ERR_RTE No route to destination (no gateway to external networks),
 * or the return type of either etharp_query() or ethernet_output().
 */
bool
etharp_output(NetworkInterface& netif,
              PacketBuffer& packet,
              const Ip4Addr& ip_addr,
              std::vector<EtharpEntry>& entries)
{
    MacAddress dest;
    MacAddress mcast_addr;
    auto dst_addr = ip_addr;

    /* Determine on destination hardware address. Broadcasts and multicasts
     * are special, other IP addresses are looked up in the ARP table. */

    /* broadcast destination IP address? */
    if (netif_is_ip4_addr_bcast(ip_addr, netif)) {
        /* broadcast on Ethernet also */
        dest = make_bcast_eth_addr();
        /* multicast destination IP address? */
    }
    else if (ip4_addr_is_mcast(ip_addr)) {
        /* Hash IP multicast address to MAC address.*/
        mcast_addr.bytes[0] = LNK_LYR_MCAST_ADDR_OUI[0];
        mcast_addr.bytes[1] = LNK_LYR_MCAST_ADDR_OUI[1];
        mcast_addr.bytes[2] = LNK_LYR_MCAST_ADDR_OUI[2];
        mcast_addr.bytes[3] = ip4_addr2(ip_addr) & 0x7f;
        mcast_addr.bytes[4] = ip4_addr3(ip_addr);
        mcast_addr.bytes[5] = ip4_addr4(ip_addr);
        /* destination Ethernet address is multicast */
        dest = mcast_addr;
        /* unicast destination IP address? */
    }
        /* outside local network? if so, this can neither be a global broadcast nor
               a subnet broadcast. */ else if (!netif_ip4_addr_in_net(netif, ip_addr) &&
        !ip4_addr_is_link_local(ip_addr)) {
        auto iphdr = reinterpret_cast<Ip4Hdr*>(packet.data.data());
        /* According to RFC 3297, chapter 2.6.2 (Forwarding Rules), a packet with
                      a link-local source address must always be "directly to its destination
                      on the same physical link. The host MUST NOT send the packet to any
                      router for forwarding". */
        if (!ip4_addr_is_link_local(iphdr->src)) {
            {
                /* interface has default gateway? */
                bool ok;
                Ip4Addr gw;
                std::tie(ok, gw) = get_netif_ip4_gw(netif, ip_addr);
                if (ok) {
                    /* send to hardware address of default gateway IP address */
                    dst_addr = gw;
                } /* no default gateway available */ else { return false; }
            }
        }
    }
    else {
        // todo: look for cached arp entry
        /* no stable entry found, use the (slower) query function:
           queue on destination Ethernet address belonging to ipaddr */
        return etharp_query(netif, dst_addr, packet, entries);
    }

    /* continuation for multicast/broadcast destinations */
    /* obtain source Ethernet address of the given interface */
    /* send packet directly on the link */
    return send_ethernet_pkt(netif, packet, netif.mac_address, dest, ETHTYPE_IP);
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
 * @param net_ifc
 * @param ip_addr
 * @param packet
 * @param netif The lwIP network interface on which ipaddr
 * must be queried for.
 * @param addr The IP address to be resolved.
 * @param pkt If non-NULL, a PacketBuffer that must be delivered to the IP address.
 * q is not freed by this function.
 * @param entries
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
bool
etharp_query(NetworkInterface& net_ifc,
             const Ip4Addr& ip_addr,
             PacketBuffer& packet,
             std::vector<EtharpEntry>& entries)
{
    auto src_mac = netif.mac_address;
    bool is_new_entry = 0; /* non-unicast address? */
    if (netif_is_ip4_addr_bcast(addr, netif) || ip4_addr_is_mcast(addr) ||
        (addr.u32 == IP4_ADDR_ANY_U32)) { return false; }

    /* find entry in ARP cache, ask to create entry if queueing packet */
    size_t index = 0;
    bool ok;
    std::tie(ok, index) = etharp_find_entry(addr, netif, entries);
    if (!ok) { return false; }

    /* mark a fresh entry as pending (we just sent a request) */
    if (entries[index].state == ETHARP_STATE_EMPTY) {
        is_new_entry = true;
        entries[index].state = ETHARP_STATE_PENDING;
        /* record network interface for re-sending arp request in etharp_tmr */
        entries[index].netif = netif;
    }

    /* do we have a new entry? or an implicit query request? */
    if (is_new_entry) {
        /* try to resolve it; send out ARP request */
        ok = etharp_request(netif, addr);
    }

    /* packet given? */
    /* stable entry? */
    if (arp_table[i].state >= ETHARP_STATE_STABLE) {
        /* we have a valid IP->Ethernet address mapping */
        /* send the packet */
        result = send_ethernet_pkt(netif,
                                   pkt,
                                   srcaddr,
                                   &(arp_table[i].MacAddress),
                                   ETHTYPE_IP);
        /* pending entry? (either just created or already pending */
    }
    else if (arp_table[i].state == ETHARP_STATE_PENDING) {
        int copy_needed = 0;
        /* IF q includes a PacketBuffer that must be copied, copy the whole chain into a
         * new PBUF_RAM. See the definition of PBUF_NEEDS_COPY for details. */
        struct PacketBuffer* p = pkt;
        while (p) {
            lwip_assert("no packet queues allowed!",
                        (p->len != p->tot_len) || (p->next == nullptr));
            // if (PbufNeedsCopy(p)) {
            //     copy_needed = 1;
            //     break;
            // }
            p = p->next;
        }
        if (copy_needed) {
            /* copy the whole packet into new pbufs */
            p = pbuf_clone(pkt);
        }
        else {
            /* referencing the old PacketBuffer is enough */
            p = pkt;
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
static bool
send_raw_arp_pkt(NetworkInterface& netif,
                 const MacAddress& ethsrc_addr,
                 const MacAddress& ethdst_addr,
                 const MacAddress& hwsrc_addr,
                 const Ip4Addr& ipsrc_addr,
                 const MacAddress& hwdst_addr,
                 const Ip4Addr& ipdst_addr,
                 const uint16_t opcode)
{
    /* allocate a PacketBuffer for the outgoing ARP request packet */
    PacketBuffer packet_buffer{};
    EtharpHdr etharp_hdr{};
    etharp_hdr.opcode = lwip_htons(opcode);
    etharp_hdr.shwaddr = hwsrc_addr;
    etharp_hdr.dhwaddr = hwdst_addr;
    etharp_hdr.sipaddr = ipsrc_addr;
    etharp_hdr.dipaddr = ipdst_addr;
    etharp_hdr.hwtype = pp_htons(LWIP_IANA_HWTYPE_ETHERNET);
    etharp_hdr.proto = pp_htons(ETHTYPE_IP);
    etharp_hdr.hwlen = ETH_ADDR_LEN;
    etharp_hdr.protolen = sizeof(Ip4Addr);
    packet_buffer.data = std::vector<uint8_t>(
        reinterpret_cast<uint8_t*>(&etharp_hdr),
        reinterpret_cast<uint8_t*>(&etharp_hdr) + sizeof(EtharpHdr));

    /* send ARP query */

    /* If we are using Link-Local, all ARP packets that contain a Link-Local
     * 'sender IP address' MUST be sent using link-layer broadcast instead of
     * link-layer unicast. (See RFC3927 Section 2.5, last paragraph) */
    if (ip4_addr_is_link_local(ipsrc_addr)) {
        return send_ethernet_pkt(netif,
                                 packet_buffer,
                                 ethsrc_addr,
                                 ETH_BCAST_ADDR,
                                 ETHTYPE_ARP);
    }
    return send_ethernet_pkt(netif,
                             packet_buffer,
                             ethsrc_addr,
                             ethdst_addr,
                             ETHTYPE_ARP);
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
bool
etharp_request_dst(NetworkInterface& netif,
                   const Ip4Addr& ipaddr,
                   const MacAddress& hw_dst_addr)
{
    Ip4AddrInfo src_ip4_addr{};
    auto ok = true;
    std::tie(ok, src_ip4_addr) = get_netif_ip4_addr(netif, ipaddr);
    if (!ok) { return false; }
    return send_raw_arp_pkt(netif,
                            netif.mac_address,
                            hw_dst_addr,
                            netif.mac_address,
                            src_ip4_addr.address,
                            ETH_ZERO_ADDR,
                            ipaddr,
                            ARP_REQUEST);
}


/**
 * Send an ARP request packet asking for ipaddr.
 *
 * @param netif the lwip network interface on which to send the request
 * @param ip_addr the IP address for which to ask
 * @return ERR_OK if the request has been sent
 *         ERR_MEM if the ARP packet couldn't be allocated
 *         any other LwipStatus on failure
 */
bool
etharp_request(NetworkInterface& netif, const Ip4Addr& ip_addr)
{
    return etharp_request_dst(netif, ip_addr, ETH_BCAST_ADDR);
}


//
// END OF FILE
//
