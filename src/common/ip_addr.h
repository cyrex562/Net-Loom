#pragma once
#include "ip4_addr.h"
#include "ip6_addr.h"

//
// IP address types for use in IpAddr.type member.
//
enum IpAddrType : uint8_t
{
    IP_ADDR_TYPE_NOT_SET = 0,
    /** IPv4 */
    IP_ADDR_TYPE_V4 = 4U,
    /** IPv6 */
    IP_ADDR_TYPE_V6 = 6U,
    /** IPv4+IPv6 ("dual-stack") */
    IP_ADDR_TYPE_ANY = 46U
};

///
/// Unified Ip Address struct
///
struct IpAddrInfo
{
    union
    {
        Ip6AddrInfo ip6;
        Ip4AddrInfo ip4;
    } u_addr;

    IpAddrType type;
};

struct NetworkInterface;


/**
 *
 */
int ip_addr_aton(const char* cp, IpAddrInfo* addr);

/**
 *
 */
inline void
ip_addr_clear(IpAddrInfo& ipaddr)
{
    ipaddr.u_addr.ip6.addr.word[0] = 0;
    ipaddr.u_addr.ip6.addr.word[1] = 0;
    ipaddr.u_addr.ip6.addr.word[2] = 0;
    ipaddr.u_addr.ip6.addr.word[3] = 0;
    clear_ip6_addr_zone(ipaddr.u_addr.ip6);
}

/**
 *
 */
inline void
copy_ip4_addr_to_ip_addr(IpAddrInfo& dest, Ip4Addr& src)
{
    ip_addr_clear(dest);
    dest.u_addr.ip4.address = src;
    dest.type = IP_ADDR_TYPE_V4;
}


/**
 *
 */
inline void
ip_addr_set_ip4_u32(IpAddrInfo& ipaddr, const uint32_t val)
{
    ip_addr_clear(ipaddr);
    ipaddr.u_addr.ip4.address.u32 = val;
    (ipaddr.type = IP_ADDR_TYPE_V4);
}


/**
 *
 */
inline void
ip_addr_set_any(IpAddrInfo& ipaddr, const bool is_ipv6 = false)
{
    if (is_ipv6) {
        set_ip6_addr_any(ipaddr.u_addr.ip6);
        (ipaddr.type = IP_ADDR_TYPE_V6);
    }
    else {
        (ipaddr.u_addr.ip4.address.u32 = IP4_ADDR_ANY_U32);
        (ipaddr.type = IP_ADDR_TYPE_V4);
        ip_addr_clear(ipaddr);
    }
}


/**
 *
 */
inline void
ip_addr_set_loopback(IpAddrInfo& ipaddr, const bool is_ipv6 = false)
{
    if (is_ipv6)
    {
        ip6_addr_set_loopback(ipaddr.u_addr.ip6);
        (ipaddr.type = IP_ADDR_TYPE_V6);
    }
    else
    {
        (ipaddr.u_addr.ip4.address.u32 = pp_htonl(IP4_ADDR_LOOPBACK_U32));
        (ipaddr.type = IP_ADDR_TYPE_V4);
        ip_addr_clear(ipaddr);
    }
}


/**
 *
 */
inline bool
ip_addr_eq(const IpAddrInfo& addr1, const IpAddrInfo& addr2)
{
    if ((addr1.type) != (addr2.type))
    {
        return false;
    }
    if ((addr1.type == IP_ADDR_TYPE_V6))
    {
        return ip6_addr_equal(addr1.u_addr.ip6, addr2.u_addr.ip6);
    }
    return addr1.u_addr.ip4.address.u32 == addr2.u_addr.ip4.address.u32;
}


/**
 *
 */
inline bool
ip_addr_is_any(const IpAddrInfo& ipaddr)
{
    if ((ipaddr.type == IP_ADDR_TYPE_V6))
    {
        return ip6_addr_is_any(ipaddr.u_addr.ip6);
    }
    return (ipaddr.u_addr.ip4.address.u32 == IP4_ADDR_ANY_U32);
}


/**
 *
 */
inline bool
ip_addr_is_mcast(const IpAddrInfo& ipaddr)
{
    if ((ipaddr.type == IP_ADDR_TYPE_V6))
    {
        return ip6_addr_is_mcast(ipaddr.u_addr.ip6.addr);
    }
    return ip4_addr_is_mcast(ipaddr.u_addr.ip4.address);
}


/**
 *
 */
inline bool
ip_addr_is_loopback(const IpAddrInfo& ipaddr)
{
    if (((ipaddr.type == IP_ADDR_TYPE_V6)))
    {
        return ip6_addr_is_loopback(ipaddr.u_addr.ip6);
    }
    return ip4_addr_is_loopback(ipaddr.u_addr.ip4.address);
}


/**
 *
 */
inline bool
ip_addr_is_link_local(const IpAddrInfo& ipaddr)
{
    if ((ipaddr.type == IP_ADDR_TYPE_V6))
    {
        return ip6_addr_is_linklocal(ipaddr.u_addr.ip6);
    }
    return ip4_addr_is_link_local(ipaddr.u_addr.ip4.address);
}


/**
 *
 */
inline IpAddrInfo
ip_addr_create_ip6_u32(
                 const uint32_t i0,
                 const uint32_t i1,
                 const uint32_t i2,
                 const uint32_t i3)
{
    IpAddrInfo ipaddr{};
    set_ip6_addr(ipaddr.u_addr.ip6, i0, i1, i2, i3);
    return ipaddr;
}


/**
 *
 */
inline IpAddrInfo
ip_addr_create_ip6_u32_host(const uint32_t i0,
                            const uint32_t i1,
                            const uint32_t i2,
                            const uint32_t i3)
{
    return ip_addr_create_ip6_u32(pp_htonl(i0), pp_htonl(i1), pp_htonl(i2), pp_htonl(i3));
}


/**
 *
 */
inline IpAddrInfo
ip_addr_create_ip4_bcast()
{
    IpAddrInfo addr{};
    addr.u_addr.ip4.address.u32 = make_u32(255, 255, 255, 255);
    addr.type = IP_ADDR_TYPE_V4;
    return addr;
}


/**
 *
 */
inline IpAddrInfo ip_addr_create_ip4_any()
{
    IpAddrInfo addr{};
    addr.u_addr.ip4.address.u32 = make_u32(0,0,0,0);
    addr.type = IP_ADDR_TYPE_V4;
    // ReSharper disable CppSomeObjectMembersMightNotBeInitialized
    return addr;
    // ReSharper restore CppSomeObjectMembersMightNotBeInitialized
}


/**
 *
 */
inline IpAddrInfo ip_addr_create_ip6_any() {
    IpAddrInfo addr{};
    addr.u_addr.ip6.addr.word[0] = 0;
    addr.u_addr.ip6.addr.word[1] = 0;
    addr.u_addr.ip6.addr.word[2] = 0;
    addr.u_addr.ip6.addr.word[3] = 0;
    addr.u_addr.ip6.zone = IP6_NO_ZONE;
    addr.type = IP_ADDR_TYPE_V6;
    return addr;
}


/**
 *
 */
inline IpAddrInfo ip_addr_create_any()
{
    IpAddrInfo addr{};
    addr.u_addr.ip6.addr.word[0] = 0;
    addr.u_addr.ip6.addr.word[1] = 0;
    addr.u_addr.ip6.addr.word[2] = 0;
    addr.u_addr.ip6.addr.word[3] = 0;
    addr.u_addr.ip6.zone = IP6_NO_ZONE;
    addr.type = IP_ADDR_TYPE_ANY;
    return addr;
}


/**
 *
 */
inline void ip_addr_zero(IpAddrInfo& ip)
{
    ip = ip_addr_create_any();
}

//
// END OF FILE
//