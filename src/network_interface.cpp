/**
 * @file network_interface.cpp
 */
#include "dhcp6.h"
#include "etharp.h"
#include "ip6_addr.h"
#include "ip_addr.h"
#include "lwip_status.h"
#include "network_interface.h"
#include "sys.h"


/**
 * Initialize a lwip network interface structure for a loopback interface
 *  @param netif the lwip network interface structure for this loopif
 *  @param if_name the name of the interface, default is "lo"
 *  @return ERR_OK if the loopif is initialized
 *      ERR_MEM if private data couldn't be allocated
 */
LwipStatus
init_loop_netif(NetworkInterface& netif, const std::string& if_name)
{
    // todo: when creating interface check if one with same name already exists.
    netif.name = if_name;
    netif.netif_type = NETIF_TYPE_LOOPBACK;
    netif.igmp_allowed = true;
    return STATUS_SUCCESS;
}


/**
 *
 */
std::vector<NetworkInterface>
init_netif_module()
{
    std::vector<NetworkInterface> network_interfaces;
    return network_interfaces;
}

/**
 * Check out the type of the network interface and read using required function.
 */
LwipStatus
recv_netif_bytes(NetworkInterface& netif,
                 std::vector<uint8_t>& recvd_bytes,
                 const size_t max_recv_count)
{
    // todo: based on the netif, read bytes from a source, e.g. for pcap netif: capture packets, for socket, read, for serial read, for ethernet/wifi, perform raw read, etc.
    return STATUS_E_NOT_IMPLEMENTED;
}


/**
 * Add a network interface to the list of lwIP netifs.
 * @param netif the netif to add to the collection of interfaces
 * @param interfaces the collection of interfaces to add
 */
bool
add_netif(NetworkInterface& netif, std::vector<NetworkInterface>& interfaces)
{
    interfaces.push_back(netif);
    return true;
}


/**
 *
 */
LwipStatus
notify_netif_addr_changed(const IpAddrInfo& old_addr, const IpAddrInfo& new_addr)
{
    // todo: notify message bus that a netif's address has changed.
    return STATUS_E_NOT_IMPLEMENTED;
}


/**
 * Locate the old ip address in the netif's collections and replace it.
 */
bool set_netif_ip4_addr(NetworkInterface& netif, const Ip4Addr& new_ip4_addr, const Ip4Addr& old_ip4_addr)
{
    auto result = false;
    auto addr_it = netif.ip4_addresses.begin();
    for (addr_it; addr_it != netif.ip4_addresses.end(); ++addr_it) {
        if (is_ip4_addr_equal(addr_it->address, old_ip4_addr)) {
            addr_it->address = new_ip4_addr;
            result = true;
            break;
        }
    }

    return result;
}


 bool
set_netif_ip4_netmask(NetworkInterface& netif, const Ip4Addr& new_netmask, const Ip4Addr& old_netmask)
{
    auto result = false;

     auto addr_it = netif.ip4_addresses.begin();
    for (addr_it; addr_it != netif.ip4_addresses.end(); ++addr_it) {
        if (is_ip4_addr_equal(addr_it->netmask, old_netmask)) {
            addr_it->netmask = new_netmask;
            result = true;
            break;
        }
    }

    return result;
}


bool
set_netif_ip4_gw(NetworkInterface& netif, const Ip4Addr& new_gw, const Ip4Addr& old_gw)
{
    auto result = false;

    auto addr_it = netif.ip4_addresses.begin();
    for (addr_it; addr_it != netif.ip4_addresses.end(); ++addr_it) {
        if (is_ip4_addr_equal(addr_it->gateway, old_gw)) {
            addr_it->netmask = new_gw;
            result = true;
            break;
        }
    }

    return result;
}

/**
 * Remove a network interface from the list of lwIP netifs.
 *
 * @param netif the network interface to remove
 * @param interfaces the collection of interfaces to remove the netif from.
 * @return true if element was removed, false otherwise.
 */
bool
remove_netif(NetworkInterface& netif, std::vector<NetworkInterface> interfaces)
{
    auto result = false;

    auto matching_index = -1;
    for (int i = 0; i < interfaces.size(); i++) {
        auto ifc = interfaces[i];
        if (interfaces[i].name == netif.name) {
            matching_index = i;
            break;
        }
    }

    if (matching_index >= 0) {
        interfaces.erase(interfaces.begin()+matching_index);
        result = true;
    }

    return result;
}

/**
 * @ingroup netif
 * Set a network interface as the default network interface
 * (used to output all packets for which no specific route is found)
 *
 * @param netif the default network interface
 * @param interfaces
 */
bool
set_netif_default(NetworkInterface& netif, std::vector<NetworkInterface> interfaces)
{
    // step 1: set whichever interface is currently the default to false;
    // step 2: set whichever interface was requested to the new default
    auto result = false;
    auto found = false;
    auto old_def_idx = 0;
    auto i = 0;
    for (auto& interface : interfaces)
    {
        if
        (interface.default_interface
        )
 {
            interface.default_interface = false;
            old_def_idx = i;
            break;
        }
        i
        ++;
    }
    for (auto& interface : interfaces)
    {
        if
        (interface
        .
        if_name
        ==
        netif
        .
        if_name
        )
 {
            interface.default_interface = true;
            found = true;
            break;
        }
    }
    if (!found)
    {
        interfaces[old_def_idx].default_interface = true;
    }
    else
    {
        result = true;
    }
    return result;
}


/**
 * Bring an interface up, available for processing
 * traffic.
 */
bool
set_netif_up(NetworkInterface& netif, std::vector<NetworkInterface> interfaces)
{
    auto result = false;
    for (auto& interface : interfaces) {
        if (interface.if_name == netif.if_name) {
            interface.up = true;
            result = true;
            break;

        }
    }

    return result;
}


/**
  * Bring an interface down, disabling any traffic processing.
 */
bool
set_netif_down(NetworkInterface& netif, std::vector<NetworkInterface> interfaces)
{
    auto result = false;
    for (auto& interface : interfaces) {
        if (interface.if_name == netif.if_name) {
            interface.up = false;
            result = true;
            break;

        }
    }

    return result;
}


/**
 * Called by a driver when its link goes up
 */
bool
set_netif_link_up(NetworkInterface& netif, std::vector<NetworkInterface> interfaces)
{
    auto result = false;
    for (auto& interface : interfaces) {
        if (interface.if_name == netif.if_name) {
            interface.link_up = true;
            result = true;
            break;

        }
    }

    return result;
}

/**
 * Called by a driver when its link goes down
 */
bool
set_netif_link_down(NetworkInterface& netif, std::vector<NetworkInterface> interfaces)
{
    auto result = false;
    for (auto& interface : interfaces) {
        if (interface.if_name == netif.if_name) {
            interface.link_up = false;
            result = true;
            break;

        }
    }

    return result;
}


/**
 * Send an IP packet to be received on the same netif (loopif-like).
 * The PacketBuffer is simply copied and handed back to netif->input.
 * In multithreaded mode, this is done directly since netif->input must put
 * the packet on a queue.
 * In callback mode, the packet is put on an internal queue and is fed to
 * netif->input by netif_poll().
 *
 * @param netif the lwip network interface structure
 * @param pkt_buf the (IP) packet to 'send'
 * @return ERR_OK if the packet has been sent
 *         ERR_MEM if the PacketBuffer used to copy the packet couldn't be allocated
 */
LwipStatus
send_pkt_to_netif_loop(NetworkInterface& netif, PacketBuffer& pkt_buf)
{
    // todo: determine netif type and insert packet into netif's packet buffer.
    return STATUS_E_NOT_IMPLEMENTED;
}


/**
 * Check for more packets to send receive
 */
LwipStatus
poll_netif(NetworkInterface& netif)
{
    // todo: implement
    return STATUS_E_NOT_IMPLEMENTED;
}



/**
 * Change an IPv6 address of a network interface
 *
 * @param netif the network interface to change
 * @param old_addr_info the old Ipv6 Addr Info to replace
 * @param new_addr_info the new Ipv6 Addr Info to use.
 * @return true if replaced, false otherwise.
 */
bool
set_netif_ip6_addr_info(NetworkInterface& netif,
                        Ip6AddrInfo& old_addr_info,
                        Ip6AddrInfo& new_addr_info)
{
    auto result = false;
    for (auto& it : netif.ip6_addresses) {
        if (ip6_addr_equal(it, old_addr_info) && is_ip6_zone_equal(
            old_addr_info,
            new_addr_info)) {
            it.addr = new_addr_info.addr;
            it.address_state = new_addr_info.address_state;
            it.netmask = new_addr_info.netmask;
            it.valid_life = new_addr_info.valid_life;
            it.preferred_life = new_addr_info.preferred_life;
            it.zone = new_addr_info.zone;
            result = true;
            break;
        }
    }
    return result;
}

/**
 * Checks if a specific local address is present on the netif and returns its
 * index. Depending on its state, it may or may not be assigned to the
 * interface (as per RFC terminology).
 *
 * The given address may or may not be zoned (i.e., have a zone index other
 * than kIp6NoZone). If the address is zoned, it must have the correct zone
 * for the given netif, or no match will be found.
 *
 * @param netif the netif to check
 * @param addr_info the IPv6 address to find
 * @return >= 0: address found, this is its index
 *         -1: address not found on this netif
 */
int
get_netif_ip6_addr_idx(NetworkInterface& netif, const Ip6AddrInfo& addr_info)
{
    auto result = -1;
    auto found_index = 0;

    for (auto& it : netif.ip6_addresses) {
        if (ip6_addr_equal(it, addr_info)) {
            result = found_index;
            break;
        }
        found_index++;
    }

    return result;
}


/**
 * Get the collection index for the interface matching the specified name.
* @param name the name of the netif
* @param interfaces the collection of interfaces to check.
* @return -1 if not found, >= 0 if found -- index of element in collection.
*/
int
netif_name_to_index(std::string& name, const std::vector<NetworkInterface>& interfaces)
{
    auto result = -1;
    for (auto& it : interfaces) {
        if (name == it.name) {
            result = it.number;
        }
    }

    return result;
}



/**
 * @ingroup ip6
 * Select the best IPv6 source address for a given destination IPv6 address.
 *
 * This implementation follows RFC 6724 Sec. 5 to the following extent:
 * - Rules 1, 2, 3: fully implemented
 * - Rules 4, 5, 5.5: not applicable
 * - Rule 6: not implemented
 * - Rule 7: not applicable
 * - Rule 8: limited to "prefer /64 subnet match over non-match"
 *
 * For Rule 2, we deliberately deviate from RFC 6724 Sec. 3.1 by considering
 * ULAs to be of smaller scope than global addresses, to avoid that a preferred
 * ULA is picked over a deprecated global address when given a global address
 * as destination, as that would likely result in broken two-way communication.
 *
 * As long as temporary addresses are not supported (as used in Rule 7), a
 * proper implementation of Rule 8 would obviate the need to implement Rule 6.
 *
 * @param netif the netif on which to send a packet
 * @param dest_addr the destination we are trying to reach (possibly not properly
 *             zoned)
 * @param out_src_addr
 * @return the most suitable source address to use, or NULL if no suitable
 *         source address is found
 */
std::tuple<bool, Ip6AddrInfo>
netif_select_ip6_src_addr(const NetworkInterface& netif, const Ip6AddrInfo& dest_addr)
{
    LwipStatus result = STATUS_SUCCESS;
    Ip6MulticastScope dest_scope;
    Ip6MulticastScope cand_scope;
    auto best_scope = IP6_MULTICAST_SCOPE_RESERVED;
    uint8_t best_pref = 0;
    uint8_t best_bits = 0;

    /* Start by determining the scope of the given destination address. These
      * tests are hopefully (roughly) in order of likeliness to match. */
    if (is_ip6_addr_global(dest_addr.addr)) {
        dest_scope = IP6_MULTICAST_SCOPE_GLOBAL;
    }
    else if (ip6_addr_is_linklocal(dest_addr) || ip6_addr_is_loopback(dest_addr)) {
        dest_scope = IP6_MULTICAST_SCOPE_LINK_LOCAL;
    }
    else if (is_ip6_addr_unique_local(dest_addr.addr)) {
        dest_scope = IP6_MULTICAST_SCOPE_ORGANIZATION_LOCAL;
    }
    else if (is_ip6_addr_mcast(dest_addr.addr)) {
        dest_scope = get_ip6_addr_mcast_scope(dest_addr.addr);
    }
    else if (is_ip6_addr_site_local(dest_addr.addr)) {
        dest_scope = IP6_MULTICAST_SCOPE_SITE_LOCAL;
    }
    else {
        /* no match, consider scope global */
        dest_scope = IP6_MULTICAST_SCOPE_GLOBAL;
    }
    Ip6AddrInfo best_addr{};
    for (auto& it : netif.ip6_addresses) {
        /* Consider only valid (= preferred and deprecated) addresses. */
        if (!ip6_addr_is_valid(it)) {
            continue;
        }
        /* Determine the scope of this candidate address. Same ordering idea. */
        auto cand_addr = it.addr;
        if (is_ip6_addr_global(cand_addr)) {
            cand_scope = IP6_MULTICAST_SCOPE_GLOBAL;
        }
        else if (ip6_addr_is_linklocal(it)) {
            cand_scope = IP6_MULTICAST_SCOPE_LINK_LOCAL;
        }
        else if (is_ip6_addr_unique_local(cand_addr)) {
            cand_scope = IP6_MULTICAST_SCOPE_ORGANIZATION_LOCAL;
        }
        else if (is_ip6_addr_site_local(cand_addr)) {
            cand_scope = IP6_MULTICAST_SCOPE_SITE_LOCAL;
        }
        else {
            /* no match, treat as low-priority global scope */
            cand_scope = IP6_MULTICAST_SCOPE_RESERVEDF;
        }
        const auto cand_pref = is_ip6_addr_preferred(it.address_state);
        /* @todo compute the actual common bits, for longest matching prefix. */
        /* We cannot count on the destination address having a proper zone
            * assignment, so do not compare zones in this case. */
        const uint8_t cand_bits = cmp_ip6_net_zoneless(cand_addr, dest_addr.addr); /* just 1 or 0 for now */
        if (cand_bits && ip6_addr_hosts_equal(it, dest_addr)) {
            out_src_addr = it; /* Rule 1 */
            result = STATUS_SUCCESS;
            break;
        }
        /* no alternative yet */
        if (cand_scope < best_scope
            && cand_scope >= dest_scope || cand_scope > best_scope && best_scope <
            dest_scope || /* Rule 2 */ cand_scope == best_scope && (cand_pref >
                best_pref || /* Rule 3 */ cand_pref == best_pref && cand_bits > best_bits)) {
            /* Rule 8 */ /* We found a new "winning" candidate. */
            best_addr = it;
            best_scope = cand_scope;
            best_pref = cand_pref;
            best_bits = cand_bits;
        }
    }
    out_src_addr = best_addr; /* may be NULL */
    return result;
}

//
// END OF FILE
//
