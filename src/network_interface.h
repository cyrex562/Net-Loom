//
// netif API (to be used from TCPIP thread)
//

#pragma once

#include "lwip_status.h"
#include "packet_buffer.h"
#include "mac_address.h"
#include "ip4_addr.h"
#include "ip6_addr.h"
#include "igmp_grp.h"
#include "dhcp_context.h"
#include "dhcp6_context.h"
#include <vector>
#include "auto_ip_state.h"
#include "mld6_group.h"
#include "pcap_if_private.h"
#include "ip_addr.h"
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


enum NetifType
{
    NETIF_TYPE_LOOPBACK,
    NETIF_TYPE_SUBINTERFACE,
    NETIF_TYPE_ETHER,
    NETIF_TYPE_PCAP,
    NETIF_TYPE_BOND,
    NETIF_TYPE_SERIAL,
    NETIF_TYPE_NULL,
    NETIF_TYPE_FILE,
    NETIF_TYPE_SOCKET,
};


constexpr auto NETIF_NO_INDEX = -1;


using NetifNscReason = uint16_t;


struct IpAddrInfo;


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

constexpr auto NETIF_REPORT_TYPE_IPV4 = 0x01;
constexpr auto NETIF_REPORT_TYPE_IPV6 = 0x02;

constexpr auto NETIF_ADDR_IDX_MAX = 0x7FFF;

/** MAC Filter Actions, these are passed to a netif's igmp_mac_filter or
 * mld_mac_filter callback function. */
enum NetifMacFilterAction {
  /** Delete a filter entry */
      NETIF_DEL_MAC_FILTER = 0,
  /** Add a filter entry */
      NETIF_ADD_MAC_FILTER = 1
};


using NetIfcAddrIdx = uint16_t;


struct NetIfcHint
{
    NetIfcAddrIdx addr_hint;
};

struct NetworkInterfaceFlags
{
    bool up;
    bool broadcast;
    bool link_up;
    bool eth_arp;
    bool ethernet;
    bool igmp;
    bool mld6;
    bool ip6_autoconfig_enabled;
    bool default_interface;
    bool passive;
};

/**
 * Generic data structure used for all lwIP network interfaces.
 * The following fields should be filled in by the initialization
 * function for the device driver: hwaddr_len, hwaddr[], mtu, flags
 */
struct NetworkInterface
{
    NetifType netif_type;
    std::vector<Ip4AddrInfo> ip4_addresses;
    std::vector<Ip6AddrInfo> ip6_addresses;
    // void* state; // TODO: replace with different struct
    // DhcpContext dhcp_ctx;
    // Dhcp6Context dhcp6_ctx;
    // AutoipState auto_ip_state;
    // MldGroup mld_group;
    // PcapInterface pcap_if_private;
    std::vector<IgmpGroup> igmp_groups;
    std::string hostname;
    uint16_t checksum_flags;
    uint16_t mtu; /** maximum transfer unit (in bytes) */
    uint16_t mtu6; /** maximum transfer unit (in bytes), updated by RA */
    MacAddress mac_address;
    NetworkInterfaceFlags flags;
    std::string name;
    uint32_t number;
    /** Number of Router Solicitation messages that remain to be sent. */
    uint8_t rtr_solicit_count;
    uint64_t timestamp;
    uint16_t loop_cnt_current;
    std::queue<PacketBuffer> rx_buffer;
    std::queue<PacketBuffer> tx_buffer;
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


/**
 *
 */
inline bool is_netif_checksum_enabled(const NetworkInterface& netif, const uint16_t checksum_flag)
{
    return (netif.checksum_flags & checksum_flag) != 0;
}


/**
 *
 */
inline Ip4Addr
get_netif_ip4_netmask(const NetworkInterface& netif, const size_t index = 0)
{
    return netif.ip4_addresses[index].netmask;
}


/**
 *
 */
inline std::tuple<bool, Ip4Addr>
get_netif_ip4_gw(const NetworkInterface& netif, const Ip4Addr& addr1)
{
    for (auto& addr2 : netif.ip4_addresses)
    {
        if (cmp_ip4_addr_net(addr1, addr2.netmask, addr2.address))
        {
            if (!ip4_addr_isany(addr2.gateway))
            {
                return std::make_tuple(true, addr2.gateway);
            }
        }
    }
    Ip4Addr empty{};
    return std::make_tuple(false, empty);
}


/**
 *
 */
inline std::tuple<bool, Ip4AddrInfo>
get_netif_ip4_addr(const NetworkInterface& netif, const Ip4Addr& dest_addr)
{
    for (auto& it : netif.ip4_addresses) {
        if (it.address.u32 == dest_addr.u32) {
            return std::make_tuple(true, it);
        }
    }
    Ip4AddrInfo empty{};
    return std::make_tuple(false, empty);
}


inline LwipStatus
get_default_netif(const std::vector<NetworkInterface>& interfaces,
                  NetworkInterface& out_netif)
{
    for (auto& ifc : interfaces) {
        if (ifc.flags.default_interface) {
            out_netif = ifc;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}


/**
 *
 */
inline bool is_netif_up(const NetworkInterface& netif)
{
    return netif.flags.up;
}


inline bool find_igmp_group(NetworkInterface& netif, Ip4AddrInfo& addr, IgmpGroup& found_igmp_group)
{
    for (auto& it : netif.igmp_groups)
    {
        if(is_ip4_addr_equal(it.group_address, addr.address))
        {
            found_igmp_group = it;
            return true;
        }
    }

    return false;
}



/**
 *
 */
inline bool is_netif_link_up(const NetworkInterface& netif)
{

    return netif.flags.link_up;
}


/**
 *
 */
inline void set_netif_hostname(NetworkInterface& netif, const std::string& hostname)
{
   netif.hostname = hostname;
}


/**
 *
 */
inline Ip6Addr
get_netif_ip6_addr(const NetworkInterface& netif, const size_t index)
{
    return netif.ip6_addresses[index].addr;
}


/**
 *
 */
inline Ip6AddrState get_netif_ip6_addr_state(const NetworkInterface& netif, const size_t index)
{
    return netif.ip6_addresses[index].address_state;
}


/**
 *
 */
// inline bool is_netif_ip6_addr_life_valid(NetworkInterface& netif, size_t index)
// {
//     return netif.ip6_addresses[index].valid_life > 0;
// }


/**
 *
 */
inline void set_netif_ip6_addr_valid_life(NetworkInterface& netif, const size_t i, const uint32_t secs)
{
   netif.ip6_addresses[i].valid_life = secs;
}


/**
 *
 */
inline uint32_t get_netif_Ip6_addr_pref_life(NetworkInterface& netif, const size_t i)
{
    return netif.ip6_addresses[i].preferred_life;
}


/**
 *
 */
inline void set_netif_ip6_addr_pref_life(NetworkInterface& netif, size_t i, uint32_t secs)
{
    netif.ip6_addresses[i].preferred_life = secs;
}


/**
 *
 */
// inline bool is_netif_ip6_addr_static(NetworkInterface& netif, size_t i)
// {
//     return is_netif_ip6_addr_life_valid(netif, i);
// }


/**
 *
 */
inline uint32_t get_netif_mtu6(NetworkInterface& netif)
{
    return netif.mtu6;
}


/**
 * Interface indexes always start at 1 per RFC 3493, section 4, num starts at 0 (internal index is 0..254)
 */
inline uint8_t
get_and_inc_netif_num(const NetworkInterface& netif)
{
    return netif.number + 1;
}


/**
 *
 */
inline bool
rest_ip6_addr_zone(const Ip6AddrInfo& addr_info, const NetworkInterface& netif)
{
    return cmp_ip6_addr_zone(addr_info, Ip6AddrZone(get_and_inc_netif_num(netif)));
}


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
                     const NetworkInterface& netif)
{
    if (ip6_addr_has_scope(addr_info, type)) {
        set_ip6_addr_zone(addr_info, Ip6AddrZone(get_and_inc_netif_num(netif)));
    }
    else {
        set_ip6_addr_zone(addr_info, Ip6AddrZone(0));
    }
}


/**
 *
 */
inline std::tuple<bool, Ip4Addr>
get_netif_ip4_local_ip(const NetworkInterface& netif, const Ip4Addr& dest_ip_addr)
{
    bool ok = true;
    Ip4AddrInfo ip_addr{};
    std::tie(ok, ip_addr) = get_netif_ip4_addr(netif, dest_ip_addr);
    return std::make_tuple(ok, ip_addr.address);
}


/**
 * Get list head of IGMP groups for netif.
 * Note: The allsystems group IP is contained in the list as first entry.
 *
*/
inline IgmpGroup get_netif_igmp_group(NetworkInterface& netif, size_t index)
{
    return netif.igmp_groups[index];
}


inline bool netif_is_ip4_addr_bcast(const Ip4Addr& addr, const NetworkInterface& netif)
{
    for (auto info : netif.ip4_addresses)
    {
        if (is_ip4_addr_equal(info.broadcast_address, addr))
        {
            return true;
        }
    }

    return false;
}

inline bool netif_ip4_addr_in_net(NetworkInterface& netif, const Ip4Addr& addr)
{
    for (auto info : netif.ip4_addresses)
    {
        if (cmp_ip4_addr_net(info.address, addr, info.netmask))
        {
            return true;
        }
    }

    return false;
}


std::tuple<bool, Ip6AddrInfo>
netif_select_ip6_src_addr(const NetworkInterface& netif, const Ip6AddrInfo& dest_addr);


/**
 *
 */
inline std::tuple<bool, Ip6AddrInfo>
get_netif_ip6_local_ip(const NetworkInterface& netif, const Ip6AddrInfo& dest)
{
    Ip6AddrInfo out_addr{};
    const auto status = netif_select_ip6_src_addr(netif, dest);
    return status;
}


std::vector<NetworkInterface> init_netif_module();

bool
add_netif(NetworkInterface& netif, std::vector<NetworkInterface>& interfaces);


bool remove_netif(NetworkInterface& netif, std::vector<NetworkInterface> interfaces);


bool set_netif_default(NetworkInterface& netif, std::vector<NetworkInterface> interfaces);


bool set_netif_down(NetworkInterface& netif, std::vector<NetworkInterface> interfaces);


int netif_name_to_index(std::string& name, const std::vector<NetworkInterface>& interfaces);


int get_netif_ip6_addr_idx(NetworkInterface& netif, const Ip6AddrInfo& addr_info);


bool set_netif_ip6_addr_info(NetworkInterface& netif, Ip6AddrInfo& old_addr_info, Ip6AddrInfo& new_addr_info);


bool set_netif_link_up(NetworkInterface& netif, std::vector<NetworkInterface> interfaces);

bool set_netif_link_down(NetworkInterface& netif, std::vector<NetworkInterface> interfaces);


LwipStatus send_pkt_to_netif_loop(NetworkInterface& netif, PacketBuffer& pkt_buf);

LwipStatus poll_netif(NetworkInterface& netif);

LwipStatus recv_netif_bytes(NetworkInterface& netif, std::vector<uint8_t>& recvd_bytes, const size_t max_recv_count);


LwipStatus init_loop_netif(NetworkInterface& netif, const std::string& if_name = "lo");


bool set_netif_ip4_gw(NetworkInterface& netif, const Ip4Addr& new_gw, const Ip4Addr& old_gw);


bool set_netif_ip4_addr(NetworkInterface& netif, const Ip4Addr& new_ip4_addr, const Ip4Addr& old_ip4_addr);

/**
 * remove specified Ip4 address from
 */
inline bool netif_remove_ip4_addr(NetworkInterface& netif, const Ip4Addr& ip_to_remove)
{
    auto deleted = false;
    for (auto it = netif.ip4_addresses.begin(); it != netif.ip4_addresses.end(); it++)
    {
        if (it->address.u32 == ip_to_remove.u32)
        {
            netif.ip4_addresses.erase(it);
            deleted = true;
            break;
        }
    }

    return deleted;
}


bool netif_upsert_ip4(NetworkInterface& netif, Ip4AddrInfo& addr_info)
{
    bool updated = false;
    for (auto& info : netif.ip4_addresses)
    {
        if (cmp_ip4_addr_net(addr_info.address, info.address, info.netmask))
        {
            info.address = addr_info.address;
            updated = true;
            break;
        }
    }

    if (!updated)
    {
        netif.ip4_addresses.push_back(addr_info);
    }

    return true;
}


/**
 * Get netif for IP.
 */
inline std::tuple<bool, IpAddrInfo>
netif_get_local_ip(const NetworkInterface& netif, const IpAddrInfo& dest_addr_info)
{
    auto ok = true;
    IpAddrInfo out_addr_info{};
    Ip6AddrInfo ip6_addr_info{};
    if (ip_addr_is_v6(dest_addr_info)) {
        std::tie(ok, ip6_addr_info) = get_netif_ip6_local_ip(netif,
                                                             dest_addr_info.u_addr.ip6);
        out_addr_info.u_addr.ip6 = ip6_addr_info;
        return std::make_tuple(ok, out_addr_info);
    }
    Ip4AddrInfo ip4_addr_info{};
    Ip4Addr ip4_addr{};
    std::tie(ok, ip4_addr) = get_netif_ip4_local_ip(netif,
                                                    dest_addr_info.u_addr.ip4.address);
    ip4_addr_info.address = ip4_addr;
    out_addr_info.u_addr.ip4 = ip4_addr_info;
    return std::make_tuple(ok, out_addr_info);
}

//
// END OF FILE
//