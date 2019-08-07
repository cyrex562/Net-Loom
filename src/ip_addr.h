#pragma once
#include <ip4_addr.h>
#include <ip6_addr.h>

//
// IP address types for use in IpAddr.type member.
//
enum IpAddrType
{
    /** IPv4 */
    IPADDR_TYPE_V4 = 0U,
    /** IPv6 */
    IPADDR_TYPE_V6 = 6U,
    /** IPv4+IPv6 ("dual-stack") */
    IPADDR_TYPE_ANY = 46U
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


///
///
///
int ipaddr_aton(const char* cp, IpAddrInfo* addr);


///
///
///
inline bool
is_ip_addr_v4(const IpAddrInfo& addr)
{
    return addr.type == IPADDR_TYPE_V4;
} 

///
///
///
inline IpAddrType
get_ip_addr_type(const IpAddrInfo& ipaddr)
{
    return ipaddr.type;
} 

///
///
///
inline bool
is_ip_addr_any_type(const IpAddrInfo& ipaddr)
{
    return get_ip_addr_type(ipaddr) == IPADDR_TYPE_ANY;
} 

///
///
///
inline bool
is_ip_addr_v6(const IpAddrInfo& ipaddr)
{
    return get_ip_addr_type(ipaddr) == IPADDR_TYPE_V6;
}


///
///
///
inline void
set_ip_addr_type(IpAddrInfo& ipaddr, const IpAddrType iptype)
{
    ipaddr.type = iptype;
}


///
///
///
inline void
clear_ip_addr(IpAddrInfo& ipaddr)
{
    ipaddr.u_addr.ip6.addr.word[0] = 0;
    ipaddr.u_addr.ip6.addr.word[1] = 0;
    ipaddr.u_addr.ip6.addr.word[2] = 0;
    ipaddr.u_addr.ip6.addr.word[3] = 0;
    clear_ip6_addr_zone(ipaddr.u_addr.ip6);
}


///
///
///
inline void
copy_ip_addr(IpAddrInfo& daddr, const IpAddrInfo& saddr)
{
    daddr.type = saddr.type;
    if (saddr.type == IPADDR_TYPE_V6)
    {
        copy_ip6_addr(daddr.u_addr.ip6.addr, saddr.u_addr.ip6.addr);
    }
    else
    {
        copy_ip4_addr(daddr.u_addr.ip4.address, saddr.u_addr.ip4.address);
        clear_ip_addr(daddr);
    }
}


///
///
///
inline void
copy_ip6_addr_to_ip_addr(IpAddrInfo& dest, Ip6Addr& src)
{
    copy_ip6_addr(dest.u_addr.ip6.addr, src);
    dest.type = IPADDR_TYPE_V6;
}


///
///
///
inline void
copy_ip4_addr_to_ip_addr(IpAddrInfo& dest, Ip4Addr& src)
{
    copy_ip4_addr(dest.u_addr.ip4.address, src);
    set_ip_addr_type(dest, IPADDR_TYPE_V4);
    clear_ip_addr(dest);
}


///
///
///
inline void set_ip_addr_ip4_u32(IpAddrInfo& ipaddr, const uint32_t val)
{
    set_ip4_addr_u32(ipaddr.u_addr.ip4.address, val);
    set_ip_addr_type(ipaddr, IPADDR_TYPE_V4);
    clear_ip_addr(ipaddr);
}


///
///
///
inline IpAddrInfo
set_ip_addr_ip4_u32_val(IpAddrInfo& ipaddr, const uint32_t val)
{
    set_ip4_addr_u32(ipaddr.u_addr.ip4.address, val);
    set_ip_addr_type(ipaddr, IPADDR_TYPE_V4);
    clear_ip_addr(ipaddr);
    return ipaddr;
}


///
///
///
inline uint32_t
get_ip4_addr_u32_from_ip_addr(const IpAddrInfo& ipaddr)
{
    if (is_ip_addr_v4(ipaddr))
    {
        return get_ip4_addr_u32(ipaddr.u_addr.ip4.address);
    }
    return 0;
}


///
///
///
inline void
set_ip_addr(IpAddrInfo& dest, const IpAddrInfo& src)
{
    set_ip_addr_type(dest, get_ip_addr_type(src));
    if (is_ip_addr_v6(src))
    {
        set_ip6_addr(dest.u_addr.ip6, src.u_addr.ip6);
    }
    else
    {
        copy_ip4_addr(dest.u_addr.ip4.address, src.u_addr.ip4.address);
        clear_ip_addr(dest);
    }
}


///
///
///
inline void
zero_ip_addr_ip4(IpAddrInfo& ipaddr)
{
    zero_ip4_addr(ipaddr.u_addr.ip4.address);
    set_ip_addr_type(ipaddr, IPADDR_TYPE_V4);
}


///
///
///
inline void
zero_ip_addr_ip6(IpAddrInfo& ipaddr)
{
    zero_ip6_addr(ipaddr.u_addr.ip6);
    set_ip_addr_type(ipaddr, IPADDR_TYPE_V6);
}



///
///
///
inline void
set_ip_addr_any(const bool is_ipv6, IpAddrInfo& ipaddr)
{
    if (is_ipv6)
    {
        set_ip6_addr_any(ipaddr.u_addr.ip6);
        set_ip_addr_type(ipaddr, IPADDR_TYPE_V6);
    }
    else
    {
        set_ip4_addr_any(ipaddr.u_addr.ip4.address);
        set_ip_addr_type(ipaddr, IPADDR_TYPE_V4);
        clear_ip_addr(ipaddr);
    }
}


///
///
///
inline void
set_ip_addr_loopback(const bool is_ipv6, IpAddrInfo& ipaddr)
{
    if (is_ipv6)
    {
        set_ip6_addr_loopback(ipaddr.u_addr.ip6);
        set_ip_addr_type(ipaddr, IPADDR_TYPE_V6);
    }
    else
    {
        set_ip4_addr_loopback(ipaddr.u_addr.ip4.address);
        set_ip_addr_type(ipaddr, IPADDR_TYPE_V4);
        clear_ip_addr(ipaddr);
    }
}


///
///
///
inline bool
compare_ip_addr(const IpAddrInfo& addr1, const IpAddrInfo& addr2)
{
    if (get_ip_addr_type(addr1) != get_ip_addr_type(addr2))
    {
        return false;
    }
    if (is_ip_addr_v6(addr1))
    {
        return ip6_addr_equal(addr1.u_addr.ip6, addr2.u_addr.ip6);
    }
    return is_ip4_addr_equal(addr1.u_addr.ip4.address, addr2.u_addr.ip4.address);
}


///
///
///
inline bool
is_ip_addr_any(const IpAddrInfo& ipaddr)
{
    if (is_ip_addr_v6(ipaddr))
    {
        return ip6_addr_is_any(ipaddr.u_addr.ip6);
    }
    return ip4_addr_isany(ipaddr.u_addr.ip4.address);
}


///
///
///
inline bool
is_ip_addr_mcast(const IpAddrInfo& ipaddr)
{
    if (is_ip_addr_v6(ipaddr))
    {
        return is_ip6_addr_mcast(ipaddr.u_addr.ip6.addr);
    }
    return is_ip4_addr_multicast(ipaddr.u_addr.ip4.address);
}


/**
 *
 */
inline bool
is_ip_addr_loopback(const IpAddrInfo& ipaddr)
{
    if ((is_ip_addr_v6(ipaddr)))
    {
        return ip6_addr_is_loopback(ipaddr.u_addr.ip6);
    }
    return is_ip4_addr_loopback(ipaddr.u_addr.ip4.address);
}


/**
 *
 */
inline bool
is_ip_addr_link_local(const IpAddrInfo& ipaddr)
{
    if (is_ip_addr_v6(ipaddr))
    {
        return ip6_addr_is_linklocal(ipaddr.u_addr.ip6);
    }
    return is_ip4_addr_link_local(ipaddr.u_addr.ip4);
}


///
///
///
inline void
make_ip_addr_ip6(IpAddrInfo& ipaddr,
                 const uint32_t i0,
                 const uint32_t i1,
                 const uint32_t i2,
                 const uint32_t i3)
{
    set_ip6_addr(ipaddr.u_addr.ip6, i0, i1, i2, i3);
}


/**
 *
 */
inline void
ip_addr_ip6_host(struct IpAddrInfo& ipaddr,
                 const uint32_t i0,
                 const uint32_t i1,
                 const uint32_t i2,
                 const uint32_t i3)
{
    make_ip_addr_ip6(ipaddr, pp_htonl(i0), pp_htonl(i1), pp_htonl(i2), pp_htonl(i3));
}


/**
 *
 */
inline IpAddrInfo create_ip_addr_ip4_bcast()
{
    IpAddrInfo addr{};
    addr.u_addr.ip4.address.addr = make_u32(255,255,255,255);
    addr.type = IPADDR_TYPE_V4;
    // ReSharper disable once CppSomeObjectMembersMightNotBeInitialized
    return addr;
}


/**
 *
 */
inline IpAddrInfo create_ip_addr_ip4_any()
{
    IpAddrInfo addr{};
    addr.u_addr.ip4.address.addr = make_u32(0,0,0,0);
    addr.type = IPADDR_TYPE_V4;
    // ReSharper disable CppSomeObjectMembersMightNotBeInitialized
    return addr;
    // ReSharper restore CppSomeObjectMembersMightNotBeInitialized
}


/**
 *
 */
inline IpAddrInfo create_ip_addr_ip6_any() {
    IpAddrInfo addr{};
    addr.u_addr.ip6.addr.word[0] = 0;
    addr.u_addr.ip6.addr.word[1] = 0;
    addr.u_addr.ip6.addr.word[2] = 0;
    addr.u_addr.ip6.addr.word[3] = 0;
    addr.u_addr.ip6.zone = IP6_NO_ZONE;
    addr.type = IPADDR_TYPE_V6;
    return addr;
}


///
///
///
inline IpAddrInfo create_ip_addr_any()
{
    IpAddrInfo addr{};
    addr.u_addr.ip6.addr.word[0] = 0;
    addr.u_addr.ip6.addr.word[1] = 0;
    addr.u_addr.ip6.addr.word[2] = 0;
    addr.u_addr.ip6.addr.word[3] = 0;
    addr.u_addr.ip6.zone = IP6_NO_ZONE;
    addr.type = IPADDR_TYPE_ANY;
    return addr;
}


///
///
///
inline void zero_ip_addr(IpAddrInfo& ip)
{
    ip = create_ip_addr_any();
}

//
// END OF FILE
//