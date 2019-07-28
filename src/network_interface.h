//
// netif API (to be used from TCPIP thread)
//

#pragma once

#include <lwip_status.h>
#include <packet_buffer.h>
#include <mac_address.h>
#include <ip_addr.h>
#include <ip4_addr.h>
#include <ip6_addr.h>
#include <igmp_grp.h>
#include "dhcp.h"
#include <vector>
struct Ip6Addr;

/* Throughout this file, IP addresses are expected to be in
 * the same byte order as in IP_PCB. */

/** Must be the maximum of all used hardware address lengths
    across all types of interfaces in use.
    This does not have to be changed, normally. */

/** The size of a fully constructed netif name which the
 * netif can be identified by in APIs. Composed of
 * 2 chars, 3 (max) digits, and 1 \0
 */
constexpr auto NETIFC_NAME_SZ = 6;

/**
 * @defgroup netif_flags Flags
 * @ingroup netif
 * @{
 */

/** Whether the network interface is 'up'. This is
 * a software flag used to control whether this network
 * interface is enabled and processes traffic.
 * It must be set by the startup code before this netif can be used
 * (also for dhcp/autoip).
 */
// enum NetIfcFlag : uint8_t
// {
//     NETIF_FLAG_UP = 0x01U,
//     /** If set, the netif has broadcast capability.
//     * Set by the netif driver in its init function. */
//     NETIF_FLAG_BCAST = 0x02U,
//     /** If set, the interface has an active link
//     *  (set by the network interface driver).
//     * Either set by the netif driver in its init function (if the link
//     * is up at that time) or at a later point once the link comes up
//     * (if link detection is supported by the hardware). */
//     NETIF_FLAG_LINK_UP = 0x04U,
//     /** If set, the netif is an ethernet device using ARP.
//     * Set by the netif driver in its init function.
//     * Used to check input packet types and use of DHCP. */
//     NETIF_FLAG_ETH_ARP = 0x08U,
//     /** If set, the netif is an ethernet device. It might not use
//     * ARP or TCP/IP if it is used for PPPoE only.
//     */
//     NETIF_FLAG_ETH = 0x10U,
//     /** If set, the netif has IGMP capability.
//     * Set by the netif driver in its init function. */
//     NETIF_FLAG_IGMP = 0x20U,
//     /** If set, the netif has MLD6 capability.
//     * Set by the netif driver in its init function. */
//     NETIF_FLAG_MLD6 = 0x40U,
// };


/**
 * @}
 */

enum LwipInternalNetifClientDataIndex {
  LWIP_NETIF_CLIENT_DATA_INDEX_DHCP,
  LWIP_NETIF_CLIENT_DATA_INDEX_AUTOIP,
  LWIP_NETIF_CLIENT_DATA_INDEX_IGMP,
  LWIP_NETIF_CLIENT_DATA_INDEX_DHCP6,
  LWIP_NETIF_CLIENT_DATA_INDEX_MLD6,
  LWIP_NETIF_CLIENT_DATA_INDEX_MAX
};


constexpr auto NETIF_CHECKSUM_GEN_IP = 0x0001;
constexpr auto NETIF_CHECKSUM_GEN_UDP = 0x0002;
constexpr auto NETIF_CHECKSUM_GEN_TCP = 0x0004;
constexpr auto NETIF_CHECKSUM_GEN_ICMP = 0x0008;
constexpr auto NETIF_CHECKSUM_GEN_ICMP6 = 0x0010;
constexpr auto NETIF_CHECKSUM_CHECK_IP = 0x0100;
constexpr auto NETIF_CHECKSUM_CHECK_UDP = 0x0200;
constexpr auto NETIF_CHECKSUM_CHECK_TCP = 0x0400;
constexpr auto NETIF_CHECKSUM_CHECK_ICMP = 0x0800;
constexpr auto NETIF_CHECKSUM_CHECK_ICMP6 = 0x1000;
constexpr auto NETIF_CHECKSUM_ENABLE_ALL = 0xFFFF;
constexpr auto NETIF_CHECKSUM_DISABLE_ALL = 0x0000;


struct NetworkInterface;

/** MAC Filter Actions, these are passed to a netif's igmp_mac_filter or
 * mld_mac_filter callback function. */
enum NetifMacFilterAction {
  /** Delete a filter entry */
      NETIF_DEL_MAC_FILTER = 0,
  /** Add a filter entry */
      NETIF_ADD_MAC_FILTER = 1
};

//
// Function prototype for netif init functions. Set up flags and output/linkoutput
// callback functions in this function.
//
// netif: The netif to initialize
// returns LwipStatus
//
using NetifInitFn = LwipStatus (*)(NetworkInterface*);

/** Function prototype for netif->input functions. This function is saved as 'input'
 * callback function in the netif struct. Call it when a packet has been received.
 *
 * @param p The received packet, copied into a PacketBuffer
 * @param inp The netif which received the packet
 * @return ERR_OK if the packet was handled
 *         != ERR_OK is the packet was NOT handled, in this case, the caller has
 *                   to free the PacketBuffer
 */
using NetifInputFn = LwipStatus (*)(PacketBuffer*, NetworkInterface*);


// Function prototype for netif->output functions. Called by lwIP when a packet
// shall be sent. For ethernet netif, set this to 'etharp_output' and set
// 'linkoutput'.
//
// @param netif
// @param netif The netif which shall send a packet
// @param p The packet to send (p->payload points to IP header)
// @param ipaddr The IP address to which the packet shall be sent
//
using netif_output_fn = LwipStatus (*)(NetworkInterface*,
                                       PacketBuffer*,
                                       const Ip4Addr*);


/** Function prototype for netif->output_ip6 functions. Called by lwIP when a packet
 * shall be sent. For ethernet netif, set this to 'ethip6_output' and set
 * 'linkoutput'.
 *
 * @param netif The netif which shall send a packet
 * @param p The packet to send (p->payload points to IP header)
 * @param ipaddr The IPv6 address to which the packet shall be sent
 */
using netif_output_ip6_fn = LwipStatus (*)(NetworkInterface*,
                                           PacketBuffer*,
                                           const Ip6Addr*);

/** Function prototype for netif->linkoutput functions. Only used for ethernet
 * netifs. This function is called by ARP when a packet shall be sent.
 *
 * @param netif The netif which shall send a packet
 * @param p The packet to send (raw ethernet packet)
 */
using netif_linkoutput_fn = LwipStatus (*)(NetworkInterface*, PacketBuffer*);
/** Function prototype for netif status- or link-callback functions. */
using netif_status_callback_fn = void (*)(NetworkInterface*);

/** Function prototype for netif igmp_mac_filter functions */
using NetifIgmpMacFilterFn = LwipStatus (*)(NetworkInterface*,
                                                const Ip4Addr*,
                                                NetifMacFilterAction);

/** Function prototype for netif mld_mac_filter functions */
using netif_mld_mac_filter_fn = LwipStatus (*)( NetworkInterface*,
                                                const Ip6Addr*,
                                                NetifMacFilterAction);

/** @ingroup netif_cd
 * Set client data. Obtain ID from netif_alloc_client_data_id().
 */

/** @ingroup netif_cd
 * Get client data. Obtain ID from netif_alloc_client_data_id().
 */


uint8_t netif_alloc_client_data_id();

using NetIfcAddrIdx = uint16_t;

constexpr auto NETIF_ADDR_IDX_MAX = 0x7FFF;

struct NetIfcHint
{
    NetIfcAddrIdx addr_hint;
};


// todo: move functions and callbacks out of struct
//  NetifInputFn input; /** This function is called by the IP module when it wants
   // *  to send a packet on the interface. This function typically
   // *  first resolves the hardware address, then sends the packet.
   // *  For ethernet physical layer, this is usually etharp_output() */
   //  netif_output_fn output; /** This function is called by ethernet_output() when it wants
   // *  to send a packet on the interface. This function outputs
   // *  the PacketBuffer as-is on the link medium. */
   //  netif_linkoutput_fn linkoutput;
   //  /** This function is called by the IPv6 module when it wants
   //          *  to send a packet on the interface. This function typically
   //          *  first resolves the hardware address, then sends the packet.
   //          *  For ethernet physical layer, this is usually ethip6_output() */
   //  netif_output_ip6_fn output_ip6;
   //  /** This function is called when the netif state is set to up or down
   //          */
   //  netif_status_callback_fn status_callback;
   //  /** This function is called when the netif link is set to up or down
   //          */
   //  netif_status_callback_fn link_callback;
   //  /** This function is called when the netif has been removed */
   //  netif_status_callback_fn remove_callback;
    // NetifIgmpMacFilterFn igmp_mac_filter;
    // /** This function could be called to add or delete an entry in the IPv6 multicast
    //            filter table of the ethernet MAC. */
    // netif_mld_mac_filter_fn mld_mac_filter;

/// Generic data structure used for all lwIP network interfaces.
/// The following fields should be filled in by the initialization
///  function for the device driver: hwaddr_len, hwaddr[], mtu, flags */
struct NetworkInterface
{
    std::vector<Ip4AddrInfo> ip4_addresses;

    std::vector<Ip6AddrInfo> ip6_addresses;

    void* state; // TODO: replace with different struct
    DhcpContext dhcp_ctx;

    std::vector<IgmpGroup> igmp_groups;

    std::string hostname;

    uint16_t checksum_flags;

    uint16_t mtu; /// maximum transfer unit (in bytes)
    uint16_t mtu6; /// maximum transfer unit (in bytes), updated by RA 
    MacAddress mac_address;

    bool up;

    bool broadcast;

    bool link_up;

    bool eth_arp;

    bool ethernet;

    bool igmp;

    bool mld6;

    bool ip6_autoconfig_enabled;

    std::string if_name;

    uint32_t if_num; /// Number of Router Solicitation messages that remain to be sent. 
    uint8_t rtr_solicit_count;

    uint64_t timestamp;

    uint16_t loop_cnt_current;
};

//
//
//
inline bool is_netif_checksum_enabled(const NetworkInterface& netif, const uint16_t checksum_flag)
{
    return (netif.checksum_flags & checksum_flag) != 0;
}

void init_netif_module();


NetworkInterface&
add_netif_no_addr(NetworkInterface& netif, uint8_t& state);


NetworkInterface add_netif(NetworkInterface& netif,
                           const Ip4Addr& ipaddr,
                           const Ip4Addr& netmask,
                           const Ip4Addr& gw,
                           uint8_t *state);

bool set_netif_addr(NetworkInterface& netif,
                    const Ip4Addr& ipaddr,
                    const Ip4Addr& netmask,
                    const Ip4Addr& gw);

void remove_netif(NetworkInterface& netif);

/* Returns a network interface given its name. The name is of the form
   "et0", where the first two letters are the "name" field in the
   netif structure, and the digit is in the num field in the same
   structure. */
NetworkInterface
find_netif(std::string& name);

void set_netif_default(NetworkInterface& netif);

void set_net_if_addr2(NetworkInterface& netif, const Ip4Addr& addr);
void set_netif_netmask(NetworkInterface& netif, const Ip4Addr& netmask);
void set_netif_gw(NetworkInterface& netif, const Ip4Addr& gw);



//
// Get Ip4 Address from the NetworkInterface
inline Ip4AddrInfo
get_netif_ip4_addr_info(const NetworkInterface& netif, const size_t index = 0)
{
    return netif.ip4_addresses[index];
}

//
//
//
inline Ip4Addr
get_netif_ip4_netmask(const NetworkInterface& netif, const size_t index = 0)
{
    return netif.ip4_addresses[index].netmask;
}



inline Ip4Addr
get_netif_ip4_gw(const NetworkInterface& netif, const size_t index)
{
    return netif.ip4_addresses[index].gateway;
}

struct IpAddr;


inline Ip4Addr
get_netif_ip4_addr(const NetworkInterface& netif, const size_t index)
{
    return netif.ip4_addresses[index].address;
}


void set_netif_up(NetworkInterface& netif);
void set_netif_down(NetworkInterface& netif);

inline bool is_netif_up(NetworkInterface& netif)
{
    return netif.up;
}

// void netif_set_status_callback(struct NetworkInterface *netif, netif_status_callback_fn status_callback);

// void netif_set_remove_callback(struct NetworkInterface *netif, netif_status_callback_fn remove_callback);


void set_netif_link_up(NetworkInterface& netif);
void set_netif_link_down(NetworkInterface& netif);


inline bool is_netif_link_up(NetworkInterface& netif)
{

    return netif.link_up;
}

// void netif_set_link_callback(struct NetworkInterface *netif, netif_status_callback_fn link_callback);


/** @ingroup netif */
inline void set_netif_hostname(NetworkInterface& netif, std::string& hostname)
{
   netif.hostname = hostname;
}

/** @ingroup netif */
inline std::string
get_netif_hostname(NetworkInterface& netif)
{
    return netif.hostname;
}

LwipStatus output_netif_loop(NetworkInterface& netif, PacketBuffer& pkt_buf);

void poll_netif(NetworkInterface& netif);

void poll_all_netifs();


LwipStatus input_netif(PacketBuffer& pkt_buf, NetworkInterface& netif);


///
///
///
inline Ip6AddrInfo
get_netif_ip6_addr_info(const NetworkInterface& netif, const size_t index)
{
    return netif.ip6_addresses[index];
}


inline Ip6Addr
get_netif_ip6_addr(const NetworkInterface& netif, const size_t index)
{
    return netif.ip6_addresses[index].addr;
}


void set_netif_ip6_addr(NetworkInterface& netif, size_t index, Ip6AddrInfo& addr_info);


void
set_netif_ip6_addr_parts(NetworkInterface& netif,
                         size_t index,
                         uint32_t a,
                         uint32_t b,
                         uint32_t c,
                         uint32_t d);

inline Ip6AddrState get_netif_ip6_addr_state(const NetworkInterface& netif, const size_t index)
{
    return netif.ip6_addresses[index].address_state;
}


void set_netif_ip6_addr_state(NetworkInterface& netif, size_t index, Ip6AddrState state);


size_t
get_netif_ip6_addr_match_idx(NetworkInterface& netif, const Ip6Addr& addr);


size_t
create_netif_ip6_link_local_addr(NetworkInterface& netif, bool from_mac_48bit);

LwipStatus add_netif_ip6_addr(NetworkInterface& netif, const Ip6Addr& ip6addr, size_t& out_index);



inline bool is_netif_ip6_addr_life_valid(NetworkInterface& netif, size_t index)
{
    return netif.ip6_addresses[index].valid_life > 0;
}

inline void set_netif_ip6_addr_valid_life(NetworkInterface& netif, const size_t i, const uint32_t secs)
{
   netif.ip6_addresses[i].valid_life = secs;
}

inline uint32_t get_netif_Ip6_addr_pref_life(NetworkInterface& netif, const size_t i)
{
    return netif.ip6_addresses[i].preferred_life;
}

inline void set_netif_ip6_addr_pref_life(NetworkInterface& netif, size_t i, uint32_t secs)
{
    netif.ip6_addresses[i].preferred_life = secs;
}

inline bool is_netif_ip6_addr_static(NetworkInterface& netif, size_t i)
{
    return is_netif_ip6_addr_life_valid(netif, i);
}

inline uint32_t get_netif_mtu6(NetworkInterface& netif)
{
    return netif.mtu6;
}

// inline void netif_set_hints(NetworkInterface& netif, NetIfcHint& netifhint)
// {
//     netif.hints.push_back(netifhint);
// }


// inline void netif_reset_hints(NetworkInterface& netif)
// {
//     netif.hints.clear();
// }


uint8_t netif_name_to_index(std::string& name);


std::string netif_index_to_name(uint8_t idx, std::string& name);


NetworkInterface
get_netif_by_index(size_t idx);

/* Interface indexes always start at 1 per RFC 3493, section 4, num starts at 0 (internal index is 0..254)*/
inline uint8_t get_and_inc_netif_num(const NetworkInterface& netif)
{
    return netif.if_num + 1;
}

constexpr auto NETIF_NO_INDEX = -1;

/**
 * @ingroup netif
 * Extended netif status callback (NSC) reasons flags.
 * May be extended in the future!
 */
using NetifNscReason = uint16_t;

/* used for initialization only */
constexpr auto LWIP_NSC_NONE = 0x0000;
/** netif was added. arg: NULL. Called AFTER netif was added. */
constexpr auto LWIP_NSC_NETIF_ADDED = 0x0001;
/** netif was removed. arg: NULL. Called BEFORE netif is removed. */
constexpr auto LWIP_NSC_NETIF_REMOVED = 0x0002;
/** link changed */
constexpr auto LWIP_NSC_LINK_CHANGED = 0x0004;
/** netif administrative status changed.\n
  * up is called AFTER netif is set up.\n
  * down is called BEFORE the netif is actually set down. */
constexpr auto LWIP_NSC_STATUS_CHANGED = 0x0008;
/** IPv4 address has changed */
constexpr auto LWIP_NSC_IPV4_ADDRESS_CHANGED = 0x0010;
/** IPv4 gateway has changed */
constexpr auto LWIP_NSC_IPV4_GATEWAY_CHANGED = 0x0020;
/** IPv4 netmask has changed */
constexpr auto LWIP_NSC_IPV4_NETMASK_CHANGED = 0x0040;
/** called AFTER IPv4 address/gateway/netmask changes have been applied */
constexpr auto LWIP_NSC_IPV4_SETTINGS_CHANGED = 0x0080;
/** IPv6 address was added */
constexpr auto LWIP_NSC_IPV6_SET = 0x0100;
/** IPv6 address state has changed */
constexpr auto LWIP_NSC_IPV6_ADDR_STATE_CHANGED = 0x0200;
//
// /** @ingroup netif
//  * Argument supplied to netif_ext_callback_fn.
//  */
// union netif_ext_callback_args_t
// {
//     /** Args to LWIP_NSC_LINK_CHANGED callback */
//     struct link_changed
//     {
//         /** 1: up; 0: down */
//         uint8_t state;
//     }; /** Args to LWIP_NSC_STATUS_CHANGED callback */
//     struct status_changed
//     {
//         /** 1: up; 0: down */
//         uint8_t state;
//     }; /** Args to LWIP_NSC_IPV4_ADDRESS_CHANGED|LWIP_NSC_IPV4_GATEWAY_CHANGED|LWIP_NSC_IPV4_NETMASK_CHANGED|LWIP_NSC_IPV4_SETTINGS_CHANGED callback */
//     struct ipv4_changed
//     {
//         /** Old IPv4 address */
//         const IpAddr* old_address;
//         const IpAddr* old_netmask;
//         const IpAddr* old_gw;
//     }; /** Args to LWIP_NSC_IPV6_SET callback */
//     struct ipv6_set
//     {
//         /** Index of changed IPv6 address */
//         int8_t addr_index; /** Old IPv6 address */
//         const IpAddr* old_address;
//     }; /** Args to LWIP_NSC_IPV6_ADDR_STATE_CHANGED callback */
//     struct ipv6_addr_state_changed_s
//     {
//         /** Index of affected IPv6 address */
//         int8_t addr_index; /** Old IPv6 address state */
//         uint8_t old_state; /** Affected IPv6 address */
//         const IpAddr* address;
//     } ipv6_addr_state_changed;
// };

// /**
//  * @ingroup netif
//  * Function used for extended netif status callbacks
//  * Note: When parsing reason argument, keep in mind that more reasons may be added in the future!
//  * @param netif
//  * @param netif netif that is affected by change
//  * @param reason change reason
//  * @param args depends on reason, see reason description
//  */
// typedef void (*NetifExtCallbackFn)(struct NetworkInterface* netif,
//                                       NetifNscReason reason,
//                                       const netif_ext_callback_args_t* args);

// struct NetifExtCallback
// {
//     NetifExtCallbackFn callback_fn;
//     struct NetifExtCallback* next;
// };

// #define NETIF_DECLARE_EXT_CALLBACK(name) static netif_ext_callback_t name;
// void netif_add_ext_callback(NetifExtCallback* callback, NetifExtCallbackFn fn);
// void netif_remove_ext_callback(NetifExtCallback* callback);
// void netif_invoke_ext_callback(struct NetworkInterface* netif, NetifNscReason reason, const netif_ext_callback_args_t* args);

//
//
//
inline bool est_ip6_addr_zone(const Ip6AddrInfo& addr_info, const NetworkInterface& netif)
{
    return cmp_ip6_addr_zone(addr_info, (Ip6AddrZone)get_and_inc_netif_num(netif));
}

// Verify that the given IPv6 address is properly zoned for the given netif.
//
//
// inline void IP6_ADDR_ZONECHECK_NETIF(const Ip6Address& ip6addr, NetworkInterface& netif)
// {
//     lwip_assert("IPv6 netif zone check failed",
//                 ip6_addr_has_scope(ip6addr, IP6_UNKNOWN)
//                     ? ip6_addr_has_zone(ip6addr)
//                         ip6_addr_est_zone(ip6addr, netif))
//                     : !ip6_addr_has_zone(ip6addr));
// }


/**
 * Assign a zone index to an IPv6 address, based on a network interface. If the
 * given address has a scope, the assigned zone index is that scope's zone of
 * the given netif; otherwise, the assigned zone index is "no zone".
 *
 * This default implementation follows the default model of RFC 4007, where
 * only interface-local and link-local scopes are defined, and the zone index
 * of both of those scopes always equals the index of the network interface.
 * As such, this default implementation need not distinguish between different
 * constrained scopes when assigning the zone.
 *
 * @param addr_info the IPv6 address; its address part is examined, and its zone
 *                index is assigned.
 * @param type address type; see @ref lwip_ipv6_scope_type.
 * @param netif the network interface (const).
 */
inline void
assign_ip6_addr_zone(Ip6AddrInfo& addr_info,
                     const Ip6AddrScopeType type,
                     const NetworkInterface& netif,
                     size_t index = 0)
{
    if (ip6_addr_has_scope(addr_info.addr, type))
    {
        set_ip6_addr_zone(addr_info, (Ip6AddrZone)get_and_inc_netif_num(netif));
    }
    else
    {
        set_ip6_addr_zone(addr_info, (Ip6AddrZone)0);
    }
}


const Ip6AddrInfo
select_ip6_src_addr(const NetworkInterface& netif, const Ip6AddrInfo& dest);


inline Ip4Addr
get_netif_ip4_local_ip(const NetworkInterface& netif, const size_t index)
{
    return get_netif_ip4_addr(netif, index);
}

inline const Ip6AddrInfo
ip6_netif_get_local_ip(const NetworkInterface& netif, const Ip6AddrInfo& dest)
{
    return select_ip6_src_addr(netif, dest);
}





///
/// Get list head of IGMP groups for netif.
/// Note: The allsystems group IP is contained in the list as first entry.
/// @see @ref netif_set_igmp_mac_filter()
///
inline IgmpGroup get_netif_igmp_group(NetworkInterface& netif, size_t index)
{
    return netif.igmp_groups[index];
}


///
/// Search for a group in the netif's igmp group list
///
/// @param ifp the network interface for which to look
/// @param addr the group ip address to search for
/// @return a struct igmp_group* if the group has been found,
///         NULL if the group wasn't found.
///
inline IgmpGroup
igmp_lookfor_group(NetworkInterface& ifp, const Ip4Addr& addr)
{
    for (auto group: ifp.igmp_groups)
    {
        if (ip4_addr_cmp(group.group_address, addr))
        {
            return group;
        }
    }

    return IgmpGroup{};
}


std::string
get_netif_name_for_index(uint32_t ifindex, std::string& ifname);


uint32_t
get_netif_index_for_name(std::string& ifname);


inline bool is_netif_ip4_addr_bcast(const Ip4Addr& addr, const NetworkInterface& netif)
{
    for (auto info : netif.ip4_addresses)
    {
        if (ip4_addr_cmp(info.broadcast_address, addr))
        {
            return true;
        }
    }

    return false;
}

//
// END OF FILE
//