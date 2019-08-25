//
// file: ip6_addr.h
//
#pragma once

#include "def.h"
#include "lwip_debug.h"
#include <string>
#include <array>


constexpr auto IP6_ADDR_STR_LEN_MAX = 46;
constexpr auto IP6_LINK_LOCAL_MASK_1 = 0xffc00000UL;
constexpr auto IP6_LINK_LOCAL_MASK_2 = 0xfe800000UL;
constexpr auto IP6_MCAST_MASK_1 = 0xff8f0000UL;
constexpr auto IP6_MCAST_MASK_2 = 0xff010000UL;
constexpr auto IP6_SUBNET_ID_MASK = 0x0000ffffUL;
constexpr auto IP6_ADDR_LIFE_INFINITE = 0xffffffffUL;
constexpr auto IP6_ADDR_GLOBAL_MASK_1 = 0xe0000000UL;
constexpr auto IP6_MCAST_LINK_LOCAL_MASK_1 = 0xff020000UL;
constexpr auto IP6_ADDR_GLOBAL_MASK_2 = 0x20000000UL;
constexpr auto IP6_ADDR_LOOPBACK_MASK = 0x00000001UL;
constexpr auto IP6_ADDR_SITE_LOCAL_MASK_1 = 0xffc00000UL;
constexpr auto IP6_ADDR_SITE_LOCAL_MASK_2 = 0xfec00000UL;
constexpr auto IP6_ADDR_UNIQUE_LOCAL_MASK_1 = 0xfe000000UL;
constexpr auto IP6_ADDR_UNIQUE_LOCAL_MASK_2 = 0xfc000000UL;
constexpr auto IP6_ADDR_MAPPED_MASK = 0x0000FFFFUL;
constexpr auto IP6_ADDR_MCAST_MASK_1 = 0xff000000UL;
constexpr auto IP6_ADDR_MCAST_MASK_2 = 0xff000000UL;
constexpr auto IP6_ADDR_MCAST_MASK_3 = 0x00100000UL;
constexpr auto IP6_ADDR_MCAST_MASK_4 = 0x00200000UL;
constexpr auto IP6_ADDR_MCAST_MASK_5 = 0x00400000UL;
constexpr auto IP6_ADDR_MCAST_MASK_6 = 0xff8f0000UL;
constexpr auto IP6_ADDR_MCAST_MASK_7 = 0xff040000UL;


///
///  IPv6 address states. 
///  
enum Ip6AddrState
{
    IP6_ADDR_INVALID = 0x00,
    IP6_ADDR_TENTATIVE = 0x08,
    IP6_ADDR_TENTATIVE_1 = 0x09,
    IP6_ADDR_TENTATIVE_2 = 0x0,
    IP6_ADDR_TENTATIVE_3 = 0x0,
    IP6_ADDR_TENTATIVE_4 = 0x0,
    IP6_ADDR_TENTATIVE_5 = 0x0,
    IP6_ADDR_TENTATIVE_6 = 0x0,
    IP6_ADDR_TENTATIVE_7 = 0x0,
    IP6_ADDR_VALID = 0x10,
    /* This bit marks an address as valid (preferred or deprecated) */
    IP6_ADDR_PREFERRED = 0x30,
    IP6_ADDR_DEPRECATED = 0x10,
    /* Same as VALID (valid but not preferred) */
    IP6_ADDR_DUPLICATED = 0x40,
    /* Failed DAD test, not valid */
    IP6_ADDR_TENTATIVE_COUNT_MASK = 0x07,
    /* 1-7 probes sent */
};


///
///
///
enum Ip6AddrZone : uint8_t
{
    IP6_NO_ZONE = 0,
};


/** Symbolic constants for the 'type' parameters in some of the macros.
 * These exist for efficiency only, allowing the macros to avoid certain tests
 * when the address is known not to be of a certain type. Dead code elimination
 * will do the rest. IP6_MULTICAST is supported but currently not optimized.
 * @see ip6_addr_has_scope, ip6_addr_assign_zone, ip6_addr_lacks_zone.
 */
enum Ip6AddrScopeType {
  /** Unknown */
  IP6_UNKNOWN = 0,
  /** Unicast */
  IP6_UNICAST = 1,
  /** Multicast */
  IP6_MULTICAST = 2
};



///
///
///
enum Ip6MulticastScope: uint8_t
{
    IP6_MULTICAST_SCOPE_RESERVED =0x0,
    IP6_MULTICAST_SCOPE_RESERVED0 =0x0,
    IP6_MULTICAST_SCOPE_INTERFACE_LOCAL =0x1,
    IP6_MULTICAST_SCOPE_LINK_LOCAL =0x2,
    IP6_MULTICAST_SCOPE_RESERVED3 =0x3,
    IP6_MULTICAST_SCOPE_ADMIN_LOCAL =0x4,
    IP6_MULTICAST_SCOPE_SITE_LOCAL =0x5,
    IP6_MULTICAST_SCOPE_ORGANIZATION_LOCAL =0x8,
    IP6_MULTICAST_SCOPE_GLOBAL =0xe,
    IP6_MULTICAST_SCOPE_RESERVEDF =0xf,
};


// This is the aligned version of Ip6Address used as local variable, on the stack, etc.
// struct Ip6Address
// {
//     uint32_t addr[4];
//     Ip6Zone zone;
// };

// struct Ip6HdrAddr
// {
//     uint32_t addr[4];  // NOLINT(cppcoreguidelines-avoid-c-arrays)
// };

struct Ip6Addr
{
    uint32_t word[4];  // NOLINT
};


struct Ip6AddrInfo
{
    Ip6AddrZone zone;
    Ip6Addr addr;
    uint32_t netmask;
    uint32_t valid_life;
    uint32_t preferred_life;
    Ip6AddrState address_state;
};


bool ip6_addr_is_static(Ip6AddrInfo& addr_info)
{
    return addr_info.valid_life > 0;
}

///
///
///
bool
ip6_addr_aton(std::string& out_addr_str, Ip6Addr& in_addr);


/// 
/// returns ptr to static buffer; not reentrant!
/// 
std::string ip6_addr_ntoa(const Ip6Addr& addr);


///
///
///
std::string ip6addr_ntoa_r(const Ip6Addr& addr);


/// 
/// Does the given IPv6 address have a zone set? (0/1)
/// 
inline bool
ip6_addr_has_zone(const Ip6AddrInfo& addr_info)
{
    return addr_info.zone != IP6_NO_ZONE;
}


/// 
/// Set the zone field of an IPv6 address to a particular value.
/// 
inline void
set_ip6_addr_zone(Ip6AddrInfo& addr_info, const Ip6AddrZone zone)
{
    addr_info.zone = Ip6AddrZone(zone);
}


/// 
/// Clear the zone field of an IPv6 address, setting it to "no zone".
/// 
inline void
clear_ip6_addr_zone(Ip6AddrInfo& addr_info)
{
    addr_info.zone = IP6_NO_ZONE;
}


/// 
/// Is the zone field of the given IPv6 address equal to the given zone index?  (0/1)
/// 
inline bool
cmp_ip6_addr_zone(const Ip6AddrInfo& addr_info, const Ip6AddrZone zone)
{
    return addr_info.zone == zone;
}


/// 
/// Are the zone fields of the given IPv6 addresses equal? (0/1)  This macro must only be
///  used on IPv6 addresses of the same scope.
///  
inline bool
cmp_ip6_addr_zone2(const Ip6AddrInfo& addr_info1, const Ip6AddrInfo& addr_info2)
{
    return addr_info1.zone == addr_info2.zone;
}


///
///
///
inline bool
ip6_addr_is_linklocal(const Ip6AddrInfo& addr_info)
{
    return (addr_info.addr.word[0] & pp_htonl(IP6_LINK_LOCAL_MASK_1)) == pp_htonl(
        IP6_LINK_LOCAL_MASK_2);
}


///
///
///
inline bool
ip6_addr_is_multicast_if_local(const Ip6AddrInfo& addr_info)
{
    return (addr_info.addr.word[0] & pp_htonl(IP6_MCAST_MASK_1)) == pp_htonl(IP6_MCAST_MASK_2);
}


///
///
///
inline bool
ip6_addr_is_multicast_link_local(const Ip6AddrInfo& addr_info)
{
    return (addr_info.addr.word[0] & pp_htonl(IP6_MCAST_MASK_1)) == pp_htonl(
        IP6_MCAST_LINK_LOCAL_MASK_1);
}


/**
 *  Determine whether an IPv6 address has a constrained scope, and as such is
 *  meaningful only if accompanied by a zone index to identify the scope's zone.
 *  The given address type may be used to eliminate at compile time certain
 *  checks that will evaluate to false at run time anyway.
 * 
 *  This default implementation follows the default model of RFC 4007, where
 *  only interface-local and link-local scopes are defined.
 * 
 *  Even though the unicast loopback address does have an implied link-local
 *  scope, in this implementation it does not have an explicitly assigned zone
 *  index. As such it should not be tested for in this macro.
 * 
 *  @param ip6_addr the IPv6 address (const); only its address part is examined.
 *  @param type address type; see @ref lwip_ipv6_scope_type.
 *  @return 1 if the address has a constrained scope, 0 if it does not.
 * 
*/
inline bool ip6_addr_has_scope(const Ip6AddrInfo& ip6_addr, const Ip6AddrScopeType type)
{
    return ip6_addr_is_linklocal(ip6_addr) || type != IP6_UNICAST && (
        ip6_addr_is_multicast_if_local(ip6_addr) || ip6_addr_is_multicast_link_local(ip6_addr)
    );
} 


/**
 * Does the given IPv6 address have a scope, and as such should also have a zone to be meaningful, but does not actually have a zone? (0/1)
 */
inline bool
ip6_addr_lacks_zone(const Ip6AddrInfo& addr_info, const Ip6AddrScopeType scope_type)
{
    return !ip6_addr_has_zone(addr_info) && ip6_addr_has_scope(addr_info, scope_type);
}


/**
 *
 */
inline bool
cmp_ip6_addr_zoneless(const Ip6Addr& addr1, const Ip6Addr& addr2)
{
    return addr1.word[0] == addr2.word[0] && addr1.word[1] == addr2.word[1] && addr1.word[
        2] == addr2.word[2] && addr1.word[3] == addr2.word[3];
}


/**
 *
 */
inline bool
ip6_addr_equal(const Ip6AddrInfo& addr1, const Ip6AddrInfo& addr2)
{
    return addr1.addr.word[0] == addr2.addr.word[0] && addr1.addr.word[1] == addr2
                                                                             .addr.word[1]
        && addr1.addr.word[2] == addr2.addr.word[2] && addr1.addr.word[3] == addr2
                                                                             .addr.word[3
        ];
}


inline bool
is_ip6_zone_equal(const Ip6AddrInfo& info1, const Ip6AddrInfo& info2)
{
    return info1.zone == info2.zone;
}


///
///  Set an IPv6 partial address given by byte-parts
///  
inline void
set_ip6_addr_part(Ip6Addr& addr,
                  const size_t index,
                  const uint32_t a,
                  const uint32_t b,
                  const uint32_t c,
                  const uint32_t d)
{
    addr.word[index] = pp_htonl(make_u32(a, b, c, d));
} 

/**
 * Set a full IPv6 address by passing the 4 uint32_t indices in network byte order (use 
 * pp_htonl() for constants) 
*/
inline void
set_ip6_addr(Ip6AddrInfo& addr_info,
             const uint32_t a,
             const uint32_t b,
             const uint32_t c,
             const uint32_t d)
{
    addr_info.addr.word[0] = a;
    addr_info.addr.word[1] = b;
    addr_info.addr.word[2] = c;
    addr_info.addr.word[3] = d;
    clear_ip6_addr_zone(addr_info);
}


/// 
/// Access address in 16-bit block
/// 
inline uint16_t get_ip6_addr_u16_blk(const Ip6Addr& addr, size_t block)
{
    if (block == 1)
    {
        return (uint16_t)(lwip_htonl(addr.word[0]) >> 16 & 0xffff);
    }
    if (block == 2)
    {
        return (uint16_t)(lwip_htonl(addr.word[0]) & 0xffff);
    }
    if (block == 3)
    {
        return (uint16_t)(lwip_htonl(addr.word[1]) >> 16 & 0xffff);
    }
    if (block == 4)
    {
        return (uint16_t)(lwip_htonl(addr.word[1]) & 0xffff);
    }
    if (block == 5)
    {
        return (uint16_t)(lwip_htonl(addr.word[2]) >> 16 & 0xffff);
    }
    if (block == 6)
    {
        return (uint16_t)(lwip_htonl(addr.word[2]) & 0xffff);
    }
    if (block == 7)
    {
        return (uint16_t)(lwip_htonl(addr.word[3]) >> 16 & 0xffff);
    }
    if (block == 8)
    {
        return (uint16_t)(lwip_htonl(addr.word[3]) & 0xffff);
    }
}


/// 
/// Safely copy one IPv6 address to another (src may be NULL)
/// 
inline void set_ip6_addr(Ip6AddrInfo& daddr, const Ip6AddrInfo& saddr)
{
    daddr.addr.word[0] = saddr.addr.word[0];
    daddr.addr.word[1] = saddr.addr.word[1];
    daddr.addr.word[2] = saddr.addr.word[2];
    daddr.addr.word[3] = saddr.addr.word[3];
    set_ip6_addr_zone(daddr, saddr.zone);
}


/// 
/// Set complete address to zero 
/// 
inline void zero_ip6_addr(Ip6AddrInfo& addr_info)
{
    addr_info.addr.word[0] = 0;
    addr_info.addr.word[1] = 0;
    addr_info.addr.word[2] = 0;
    addr_info.addr.word[3] = 0;
    addr_info.zone = IP6_NO_ZONE;
}


/// 
/// Set address to ipv6 'any' (no need for lwip_htonl())
/// 
inline void set_ip6_addr_any(Ip6AddrInfo& addr_info)
{
    zero_ip6_addr(addr_info);
}


/// 
/// Set address to ipv6 loopback address 
/// 
inline void set_ip6_addr_loopback(Ip6AddrInfo& addr_info)
{
    addr_info.addr.word[0] = 0;
    addr_info.addr.word[1] = 0;
    addr_info.addr.word[2] = 0;
    addr_info.addr.word[3] = pp_htonl(0x00000001UL);
    clear_ip6_addr_zone(addr_info);
}


/// 
/// Safely copy one IPv6 address to another and change byte order from host- to network-order.
/// 
inline void set_ip6_addr_hton(Ip6AddrInfo& dest, Ip6AddrInfo& src)
{
    dest.addr.word[0] = lwip_htonl(src.addr.word[0]);
    dest.addr.word[1] = lwip_htonl(src.addr.word[1]);
    dest.addr.word[2] = lwip_htonl(src.addr.word[2]);
    dest.addr.word[3] = lwip_htonl(src.addr.word[3]);
    set_ip6_addr_zone(dest, src.zone);
}


/// 
/// Compare IPv6 networks, ignoring zone information. To be used sparingly!
/// 
inline bool
cmp_ip6_net_zoneless(const Ip6Addr& addr1, const Ip6Addr& addr2)
{
    return addr1.word[0] == addr2.word[0] && addr1.word[1] == addr2.word[1];
}


///
/// Determine if two IPv6 address are on the same network.
///
/// @param addr_info1 IPv6 address 1
/// @param addr_info2 IPv6 address 2
/// @return 1 if the network identifiers of both address match, 0 if not
///
inline bool
ip6_addr_on_same_net(const Ip6AddrInfo& addr_info1, const Ip6AddrInfo& addr_info2)
{
    return cmp_ip6_net_zoneless(addr_info1.addr, addr_info2.addr) && cmp_ip6_addr_zone2(
        addr_info1,
        addr_info2);
} 


/**
 * Exact-host comparison *after* ip6_addr_netcmp() succeeded, for efficiency.
 */
inline bool
ip6_addr_hosts_equal(const Ip6AddrInfo& addr1, const Ip6AddrInfo& addr2)
{
    return addr1.addr.word[2] == addr2.addr.word[2] && 
        addr1.addr.word[3] == addr2.addr.word[3];
}


///
/// Compare IPv6 address to packed address and zone
/// 
inline bool
cmp_ip6_addr2(const Ip6AddrInfo& addr_info, const Ip6Addr& addr, const Ip6AddrZone zone)
{
    return addr_info.addr.word[0] == addr.word[0] && addr_info.addr.word[1] == addr.word[1
        ] && addr_info.addr.word[2] == addr.word[2] && addr_info.addr.word[3] == addr.word
        [3] && cmp_ip6_addr_zone(addr_info, zone);
}


/**
 *
 */
inline uint32_t get_ip6_subnet_id(Ip6Addr& addr)
{
    return lwip_htonl(addr.word[2]) & IP6_SUBNET_ID_MASK;
}


/**
 *
 */
inline bool
ip6_addr_is_any(const Ip6AddrInfo& addr)
{
    return addr.addr.word[0] == 0 && addr.addr.word[1] == 0 
    && addr.addr.word[2] == 0 && addr.addr.word[3] == 0;
}


/**
 *
 */
inline bool
ip6_addr_is_loopback(const Ip6AddrInfo& addr)
{
    return addr.addr.word[0] == 0UL && addr.addr.word[1] == 0UL && addr.addr.word[2] == 0UL && 
        addr.addr.word[3] == pp_htonl(IP6_ADDR_LOOPBACK_MASK);
}


/**
 *
 */
inline bool
is_ip6_addr_global(const Ip6Addr& addr)
{
    return (addr.word[0] & pp_htonl(IP6_ADDR_GLOBAL_MASK_1)) == pp_htonl(
        IP6_ADDR_GLOBAL_MASK_2);
}


/**
 *
 */
inline bool
is_ip6_addr_site_local(const Ip6Addr& addr)
{
    return (addr.word[0] & pp_htonl(IP6_ADDR_SITE_LOCAL_MASK_1)) == pp_htonl(
        IP6_ADDR_SITE_LOCAL_MASK_2);
}


///
///
///
inline bool is_ip6_addr_unique_local(const Ip6Addr& addr)
{
    return (addr.word[0] & pp_htonl(IP6_ADDR_UNIQUE_LOCAL_MASK_1)) == pp_htonl(IP6_ADDR_UNIQUE_LOCAL_MASK_2);
}


///
///
///
inline bool
is_ip6_addr_ip4_mapped_ip6(const Ip6Addr& addr)
{
    return addr.word[0] == 0 && addr.word[1] == 0 && addr.word[2] == pp_htonl(
        IP6_ADDR_MAPPED_MASK);
}


///
///
///
inline bool
is_ip6_addr_mcast(const Ip6Addr& addr)
{
    return (addr.word[0] & pp_htonl(IP6_ADDR_MCAST_MASK_1)) == pp_htonl(
        IP6_ADDR_MCAST_MASK_2);
}


///
///
///
inline uint32_t
get_ip6_addr_mcast_transient_flag(const Ip6Addr& addr)
{
    return addr.word[0] & pp_htonl(IP6_ADDR_MCAST_MASK_3);
}


///
///
///
inline uint32_t
get_ip6_addr_mcast_prefix_flag(const Ip6Addr& addr)
{
    return addr.word[0] & pp_htonl(IP6_ADDR_MCAST_MASK_4);
}


///
///
///
inline uint32_t
get_ip6_addr_mcast_rendezvous_flag(const Ip6Addr& addr)
{
    return addr.word[0] & pp_htonl(IP6_ADDR_MCAST_MASK_5);
}


///
///
///
inline Ip6MulticastScope
get_ip6_addr_mcast_scope(const Ip6Addr& addr)
{
    return Ip6MulticastScope(lwip_htonl(addr.word[0]) >> 16 & 0xf);
}





inline bool
is_ip6_addr_mcast_admin_local(Ip6Addr& addr)
{
    return (addr.word[0] & pp_htonl(IP6_ADDR_MCAST_MASK_6)) == pp_htonl(
        IP6_ADDR_MCAST_MASK_7);
}

constexpr auto IP6_ADDR_MCAST_MASK_8 = 0xff8f0000UL;
constexpr auto IP6_ADDR_MCAST_MASK_9 = 0xff050000UL;


inline bool
is_ip6_addr_mcast_site_local(Ip6Addr& addr)
{
    return (addr.word[0] & pp_htonl(IP6_ADDR_MCAST_MASK_8)) == pp_htonl(
        IP6_ADDR_MCAST_MASK_9);
}

constexpr auto IP6_ADDR_MCAST_MASK_10 = 0xff8f0000UL;
constexpr auto IP6_ADDR_MCAST_MASK_11 = 0xff080000UL;

inline bool
is_ip6_addr_mcast_org_local(Ip6Addr& addr)
{
    return (addr.word[0] & pp_htonl(IP6_ADDR_MCAST_MASK_10)) == pp_htonl(IP6_ADDR_MCAST_MASK_11);
}

constexpr auto IP6_ADDR_MCAST_MASK_12 = 0xff0e0000UL;

inline bool is_ip6_addr_mcast_global(Ip6Addr& addr)
{
    return (addr.word[0] & pp_htonl(IP6_ADDR_MCAST_MASK_10)) == pp_htonl(IP6_ADDR_MCAST_MASK_12);
}

constexpr auto IP6_ADDR_IF_LOCAL_MASK_1 = 0xff010000UL;

/// Scoping note: while interface-local and link-local multicast addresses do
/// have a scope (i.e., they are meaningful only in the context of a particular
/// interface), the following functions are not assigning or comparing zone
/// indices. The reason for this is backward compatibility. Any call site that
/// produces a non-global multicast address must assign a multicast address as
/// appropriate itself. */
inline bool is_ip6_addr_all_nodes_if_local(Ip6Addr& addr)
{
    return addr.word[0] == pp_htonl(0xff010000UL) && addr.word[1] == 0UL
        && addr.word[2] == 0UL && addr.word[3] == pp_htonl(0x00000001UL);
}

constexpr auto IP6_ADDR_LINK_LOCAL_MASK_2 = 0xff020000UL;
constexpr auto IP6_ADDR_LINK_LOCAL_MASK_3 = 0x00000001UL;


inline bool
ip6_addr_isallnodes_linklocal(Ip6Addr& addr)
{
    return addr.word[0] == pp_htonl(IP6_ADDR_LINK_LOCAL_MASK_2) && addr.word[1] ==
        0UL && addr.word[2] == 0UL && addr.word[3] == pp_htonl(
            IP6_ADDR_LINK_LOCAL_MASK_3);
}

inline void set_ip6_addr_all_nodes_link_local(Ip6AddrInfo& addr_info)
{
    addr_info.addr.word[0] = pp_htonl(IP6_ADDR_LINK_LOCAL_MASK_2);
    addr_info.addr.word[1] = 0;
    addr_info.addr.word[2] = 0;
    addr_info.addr.word[3] = pp_htonl(IP6_ADDR_LINK_LOCAL_MASK_3);
    clear_ip6_addr_zone(addr_info);
}

constexpr auto IP6_ADDR_LINK_LOCAL_MASK_4 = 0x00000002UL;

inline bool is_ip6_addr_all_routers_link_local(Ip6Addr& addr)
{
    return addr.word[0] == pp_htonl(IP6_ADDR_LINK_LOCAL_MASK_2) && addr.word[1] == 0UL
        && addr.word[2] == 0UL && addr.word[3] == pp_htonl(IP6_ADDR_LINK_LOCAL_MASK_4);
}



inline void set_ip6_addr_all_routers_link_local(Ip6AddrInfo& addr_info)
{
    addr_info.addr.word[0] = pp_htonl(IP6_ADDR_LINK_LOCAL_MASK_2);
    addr_info.addr.word[1] = 0;
    addr_info.addr.word[2] = 0;
    addr_info.addr.word[3] = pp_htonl(IP6_ADDR_LINK_LOCAL_MASK_4);
    clear_ip6_addr_zone(addr_info);
}


constexpr auto IP6_ADDR_SOLICITED_NODE_MASK_1 = 0x00000001UL;
constexpr auto IP6_ADDR_SOLICITED_NODE_MASK_2 = 0xff000000UL;


inline bool
is_ip6_addr_solicited_node(Ip6Addr& addr)
{
    return addr.word[0] == pp_htonl(IP6_ADDR_LINK_LOCAL_MASK_2) && addr.word[2] ==
        pp_htonl(IP6_ADDR_SOLICITED_NODE_MASK_1) && (addr.word[3] &
            pp_htonl(IP6_ADDR_SOLICITED_NODE_MASK_2)) == pp_htonl(
            IP6_ADDR_SOLICITED_NODE_MASK_2);
}


inline void set_ip6_addr_solicited_node(Ip6AddrInfo& addr_info, uint32_t if_id)
{
    addr_info.addr.word[0] = pp_htonl(IP6_ADDR_LINK_LOCAL_MASK_2);
    addr_info.addr.word[1] = 0;
    addr_info.addr.word[2] = pp_htonl(IP6_ADDR_SOLICITED_NODE_MASK_1);
    addr_info.addr.word[3] = pp_htonl(IP6_ADDR_SOLICITED_NODE_MASK_2) | if_id;
    clear_ip6_addr_zone(addr_info);
}



inline bool cmp_ip6_addr_solicited_nodes(Ip6Addr& target_addr, Ip6Addr& solicit_addr)
{
    return target_addr.word[0] == pp_htonl(IP6_ADDR_LINK_LOCAL_MASK_2) && target_addr.word[1] == 0 &&
        target_addr.word[2] == pp_htonl(IP6_ADDR_SOLICITED_NODE_MASK_1) && target_addr.word[3] == (
            pp_htonl(IP6_ADDR_SOLICITED_NODE_MASK_2) | solicit_addr.word[3]);
}



inline bool is_ip6_addr_state_invalid(Ip6AddrState addr_state)
{
    return addr_state == IP6_ADDR_INVALID;
}

inline bool is_ip6_addr_tentative(Ip6AddrState addr_state)
{
    return addr_state & IP6_ADDR_TENTATIVE;
}

/**
 *
 */
inline bool ip6_addr_is_valid(const Ip6AddrInfo& addr_info)
{
    return addr_info.address_state & IP6_ADDR_VALID;
}


// Include valid, preferred, and deprecated.
inline bool is_ip6_addr_preferred(Ip6AddrState addr_state)
{
    return addr_state == IP6_ADDR_PREFERRED;
}

inline bool is_ip6_addr_deprecated(Ip6AddrState addr_state)
{
    return addr_state == IP6_ADDR_DEPRECATED;
}


///
///
///
inline bool is_ip6_addr_duplicated(Ip6AddrState addr_state)
{
    return addr_state == IP6_ADDR_DUPLICATED;
}


///
///
///
inline bool is_ip6_addr_life_static(uint32_t addr_life)
{
    return addr_life == 0;
}


///
///
///
inline bool is_ip6_addr_life_infinite(uint32_t addr_life)
{
    return addr_life == IP6_ADDR_LIFE_INFINITE;
}


///
///
///
inline Ip6AddrInfo make_ip6_addr_any()
{
    Ip6AddrInfo info{};
    info.addr.word[0] = 0;
    info.addr.word[1] = 0;
    info.addr.word[2] = 0;
    info.addr.word[3] = 0;
    info.zone = IP6_NO_ZONE;
    return info;
}


///
///
///
inline void set_ip6_addr_any2(Ip6AddrInfo& info)
{
    info.addr.word[0] = 0;
    info.addr.word[1] = 0;
    info.addr.word[2] = 0;
    info.addr.word[3] = 0;
    info.zone = IP6_NO_ZONE;
}


///
///
///
inline Ip6Addr
make_ip6_addr_host(const uint32_t a, const uint32_t b, const uint32_t c, const uint32_t d)
{
    Ip6Addr addr = {pp_htonl(a), pp_htonl(b), pp_htonl(c), pp_htonl(d)};
    return addr;
}


///
/// Copy IPv6 address - faster than ip6_addr_set: no NULL check
/// 
inline void copy_ip6_addr(Ip6Addr& dest, const Ip6Addr& src)
{
    dest.word[0] = src.word[0];
    dest.word[1] = src.word[1];
    dest.word[2] = src.word[2];
    dest.word[3] = src.word[3];
}



//
// END OF FILE
//