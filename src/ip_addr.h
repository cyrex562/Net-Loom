#pragma once

#include <cstring>
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
inline void set_ip_addr_type(IpAddrInfo& ipaddr, const IpAddrType iptype)
{
    ipaddr.type = iptype;
}



//
// Convert generic ip address to specific protocol version
//
inline const Ip4Addr* convert_ip_addr_to_ip4_addr(const IpAddrInfo* ipaddr)
{
    return &ipaddr->u_addr.ip4;
}

/** @ingroup ip4addr */
inline void new_ip_addr_ip4_u8(IpAddrInfo* ipaddr, const uint8_t a, const uint8_t b, const uint8_t c, const uint8_t d)
{
    make_ip4_addr_host_from_bytes(&ipaddr->u_addr.ip4, a, b, c, d);
    set_ip_addr_type(*ipaddr, IPADDR_TYPE_V4);
}

/** Copy the zone field from the second IPv6 address to the first one. */
inline void ip6_addr_copy_zone(Ip6Addr& ip6addr1, const Ip6Addr& ip6addr2)
{
    ip6addr1.zone = ip6addr2.zone;
}

//
//
//
/** Copy IPv6 address - faster than ip6_addr_set: no NULL check */
inline void copy_ip6_addr(Ip6Addr& dest, const Ip6Addr& src)
{
    dest.addr[0] = src.addr[0];
    dest.addr[1] = src.addr[1];
    dest.addr[2] = src.addr[2];
    dest.addr[3] = src.addr[3];
    dest.zone = src.zone;
}

inline void copy_ip4_addr(Ip4Addr& dest, const Ip4Addr& src)
{
    dest.addr = src.addr;
}

//
//
//
inline void clear_ip_addr(IpAddrInfo& ipaddr)
{
    ipaddr.u_addr.ip6.addr[1] = 0;
    ipaddr.u_addr.ip6.addr[2] = 0;
    ipaddr.u_addr.ip6.addr[3] = 0;
    clear_ip6_addr_zone(ipaddr.u_addr.ip6);
}

//
//
//
inline void copy_ip_addr(IpAddrInfo& daddr, const IpAddrInfo& saddr)
{
    daddr.type = saddr.type;
    if (saddr.type == IPADDR_TYPE_V6)
    {
        copy_ip6_addr(daddr.u_addr.ip6, saddr.u_addr.ip6);
    }
    else
    {
        copy_ip4_addr(daddr.u_addr.ip4, saddr.u_addr.ip4);
        clear_ip_addr(daddr);
    }
}

//
//
//
inline void copy_ip6_addr_to_ip_addr(IpAddrInfo& dest, Ip6Addr& src)
{
    copy_ip6_addr(dest.u_addr.ip6, src);
    dest.type = IPADDR_TYPE_V6;
}

//
//
//
inline void copy_ip4_addr_to_ip_addr(IpAddrInfo& dest, Ip4Addr& src)
{
    copy_ip4_addr(dest.u_addr.ip4, src);
    set_ip_addr_type(dest, IPADDR_TYPE_V4);
    clear_ip_addr(dest);
}


//
//
//
inline void set_ip_addr_ip4_u32(IpAddrInfo& ipaddr, const uint32_t val)
{
    set_ip4_addr_u32(ipaddr.u_addr.ip4, val);
    set_ip_addr_type(ipaddr, IPADDR_TYPE_V4);
    clear_ip_addr(ipaddr);
}

//
//
//
inline IpAddrInfo set_ip_addr_ip4_u32_val(IpAddrInfo& ipaddr, const uint32_t val)
{
    set_ip4_addr_u32(ipaddr.u_addr.ip4, val);
    set_ip_addr_type(ipaddr, IPADDR_TYPE_V4);
    clear_ip_addr(ipaddr);
    return ipaddr;
}

//
//
//
inline uint32_t get_ip4_addr_u32_from_ip_addr(const IpAddrInfo& ipaddr)
{
    if (is_ip_addr_v4(ipaddr))
    {
        return get_ip4_addr_u32(ipaddr.u_addr.ip4);
    }
    return 0;
}

//
//
//
inline void set_ip_addr(IpAddrInfo& dest, const IpAddrInfo& src)
{
    set_ip_addr_type(dest, get_ip_addr_type(src));
    if (is_ip_addr_v6(src))
    {
        set_ip6_addr(dest.u_addr.ip6, src.u_addr.ip6);
    }
    else
    {
        copy_ip4_addr(dest.u_addr.ip4, src.u_addr.ip4);
        clear_ip_addr(dest);
    }
}

//
//
//
// inline void zero_ip_addr(IpAddr* ipaddr)
// {
//     ip6_addr_set_zero(&ipaddr->u_addr.ip6);
//     ipaddr->type = IPADDR_TYPE_V4;
// }


//
//
//
inline void zero_ip_addr_ip4(IpAddrInfo& ipaddr)
{
    zero_ip4_addr(ipaddr.u_addr.ip4);
    set_ip_addr_type(ipaddr, IPADDR_TYPE_V4);
}


//
//
//
inline void zero_ip_addr_ip6(IpAddrInfo& ipaddr)
{
    zero_ip6_addr(ipaddr.u_addr.ip6);
    set_ip_addr_type(ipaddr, IPADDR_TYPE_V6);
}



//
//
//
inline void set_ip_addr_any(bool is_ipv6, IpAddrInfo& ipaddr)
{
    if (is_ipv6)
    {
        set_ip6_addr_any(ipaddr.u_addr.ip6);
        set_ip_addr_type(ipaddr, IPADDR_TYPE_V6);
    }
    else
    {
        ip4_addr_set_any(ipaddr.u_addr.ip4);
        set_ip_addr_type(ipaddr, IPADDR_TYPE_V4);
        clear_ip_addr(ipaddr);
    }
}

//
//
//
inline IpAddrInfo set_ip_addr_any_val(const bool is_ipv6, IpAddrInfo& ipaddr)
{
    if (is_ipv6)
    {
        set_ip6_addr_any(ipaddr.u_addr.ip6);
        set_ip_addr_type(ipaddr, IPADDR_TYPE_V6);
    }
    else
    {
        ip4_addr_set_any(ipaddr.u_addr.ip4);
        set_ip_addr_type(ipaddr, IPADDR_TYPE_V4);
        clear_ip_addr(ipaddr);
    }
    return ipaddr;
}

//
//
//
inline void set_ip_addr_loopback(const bool is_ipv6, IpAddrInfo& ipaddr)
{
    if (is_ipv6)
    {
        set_ip6_addr_loopback(ipaddr.u_addr.ip6);
        set_ip_addr_type(ipaddr, IPADDR_TYPE_V6);
    }
    else
    {
        set_ip4_addr_loopback(ipaddr.u_addr.ip4);
        set_ip_addr_type(ipaddr, IPADDR_TYPE_V4);
        clear_ip_addr(ipaddr);
    }
}


// inline void set_ip_addr_loopback_val(bool is_ipv6, IpAddr& ipaddr)
// {
//     if (is_ipv6)
//     {
//         ip6_addr_set_loopback(ipaddr.u_addr.ip6);
//         set_ip_addr_type_val(ipaddr, IPADDR_TYPE_V6);
//     }
//     else
//     {
//         ip4_addr_set_loopback(ipaddr.u_addr.ip4);
//         set_ip_addr_type_val(ipaddr, IPADDR_TYPE_V4);
//         clear_ip_addr(ipaddr);
//     }
// }


//
//
//
inline void set_ip_addr_hton(IpAddrInfo& dest, IpAddrInfo& src)
{
    if (is_ip_addr_v6(src))
    {
        set_ip6_addr_hton(dest.u_addr.ip6, src.u_addr.ip6);
        set_ip_addr_type(dest, IPADDR_TYPE_V6);
    }
    else
    {
        set_ip4_addr_hton(dest.u_addr.ip4, src.u_addr.ip4);
        set_ip_addr_type(dest, IPADDR_TYPE_V4);
        clear_ip_addr(dest);
    }
}


//
//
//
inline void get_ip_addr_net(IpAddrInfo& target, IpAddrInfo& host, IpAddrInfo& netmask)
{
    if (is_ip_addr_v6(host))
    {
        zero_ip4_addr(target.u_addr.ip4);
        set_ip_addr_type(target, IPADDR_TYPE_V6);
    }
    else
    {
        get_ip4_addr_net(target.u_addr.ip4,
                             host.u_addr.ip4,
                            netmask.u_addr.ip4);
        set_ip_addr_type(target, IPADDR_TYPE_V4);
    }
}


//
//
//
inline void ip_addr_copy_from_ip6_packed(IpAddrInfo* daddr, const Ip6Addr* saddr)
{
    memcpy(&daddr->u_addr.ip6, saddr, sizeof(Ip6Addr));
}


inline void ip_addr_copy_from_ip6(IpAddrInfo* daddr, const Ip6Addr* saddr)
{
    memcpy(&daddr->u_addr.ip6, saddr, sizeof(Ip6Addr));
}

inline bool compare_ip_addr_mask(IpAddrInfo& addr1, IpAddrInfo& addr2, IpAddrInfo& mask)
{
    if (is_ip_addr_v6(addr1) && is_ip_addr_v6(addr2))
    {
        return false;
    }
    return cmp_ip4_addr_net(addr1.u_addr.ip4, addr2.u_addr.ip4, mask.u_addr.ip4);
}


inline bool compare_ip_addr(const IpAddrInfo& addr1, const IpAddrInfo& addr2)
{
    if (get_ip_addr_type(addr1) != get_ip_addr_type(addr2))
    {
        return false;
    }
    if (is_ip_addr_v6(addr1))
    {
        return cmp_ip6_addr(addr1.u_addr.ip6, addr2.u_addr.ip6);
    }
    return cmp_ip4_addr(addr1.u_addr.ip4, addr2.u_addr.ip4);
}


inline bool compare_ip_addr_zoneless(const IpAddrInfo& addr1, const IpAddrInfo& addr2)
{
    if ((get_ip_addr_type(addr1) != get_ip_addr_type(addr2)))
    {
        return false;
    }
    if (is_ip_addr_v6(addr1))
    {
        return cmp_ip6_addr_zoneless(addr1.u_addr.ip6, addr2.u_addr.ip6);
    }
    return cmp_ip4_addr(addr1.u_addr.ip4, addr2.u_addr.ip4);
}



inline bool is_ip_addr_any(const IpAddrInfo& ipaddr)
{
    if (is_ip_addr_v6(ipaddr))
    {
        return is_ip6_addr_any(ipaddr.u_addr.ip6);
    }
    return ip4_addr_isany(ipaddr.u_addr.ip4);
}




// inline bool ip_addr_isany_val(const IpAddr ipaddr)
// {
//     if (is_ip_addr_ip6_val(ipaddr))
//     {
//         return ip6_addr_isany_val(*convert_ip_addr_to_ip6_addr(&ipaddr));
//     }
//     return ip4_addr_isany_val(*convert_ip_addr_to_ip4_addr(&ipaddr));
// }





inline bool ip_addr_ismulticast(const IpAddrInfo& ipaddr)
{
    if (is_ip_addr_v6(ipaddr))
    {
        return is_ip6_addr_mcast(ipaddr.u_addr.ip6);
    }
    return is_ip4_addr_multicast(ipaddr.u_addr.ip4);
}


inline bool ip_addr_isloopback(const IpAddrInfo& ipaddr)
{
    if ((is_ip_addr_v6(ipaddr)))
    {
        return is_ip6_addr_loopback(ipaddr.u_addr.ip6);
    }
    return is_ip4_addr_loopback(ipaddr.u_addr.ip4);
}


inline bool ip_addr_islinklocal(const IpAddrInfo& ipaddr)
{
    if (is_ip_addr_v6(ipaddr))
    {
        return ip6_addr_islinklocal(ipaddr.u_addr.ip6);
    }
    return is_ip4_addr_link_local(ipaddr.u_addr.ip4);
}

// #define ip_addr_debug_print(debug, ipaddr) do { if(is_ip_addr_v6(ipaddr)) { \
//   ip6_addr_debug_print(debug, ip_2_ip6(ipaddr)); } else { \
//   ip4_addr_debug_print(debug, ip_2_ip4(ipaddr)); }}while(0)


// #define ip_addr_debug_print_val(debug, ipaddr) do { if(IP_IS_V6_VAL(ipaddr)) { \
//   ip6_addr_debug_print_val(debug, *ip_2_ip6(&(ipaddr))); } else { \
//   ip4_addr_debug_print_val(debug, *ip_2_ip4(&(ipaddr))); }}while(0)
std::string
ipaddr_ntoa(const IpAddrInfo& addr);


std::string
ipaddr_ntoa_r(const IpAddrInfo& addr);
int ipaddr_aton(const char* cp, IpAddrInfo* addr);

/** @ingroup ipaddr */
inline void ip4_2_ipv4_mapped_ipv6(Ip6Addr& ip6_addr, Ip4Addr& ip4addr)
{
    (ip6_addr).addr[3] = (ip4addr).addr;
    (ip6_addr).addr[2] = pp_htonl(0x0000FFFFUL);
    (ip6_addr).addr[1] = 0;
    (ip6_addr).addr[0] = 0;
    clear_ip6_addr_zone(ip6_addr);
}

/** @ingroup ipaddr */
inline void unmap_ipv4_mapped_ipv6(Ip4Addr* ip4addr, Ip6Addr* ip6addr)
{
    (ip4addr)->addr = (ip6addr)->addr[3];
}

// inline bool IP46_ADDR_ANY(IpAddrType type) {
//   return (((type) == IPADDR_TYPE_V6) ? Ip6Address : IP4_ADDR_ANY);
// }

inline void make_ip_addr_ip6(IpAddrInfo& ipaddr, uint32_t i0, uint32_t i1, uint32_t i2, uint32_t i3)
{
    set_ip6_addr(ipaddr.u_addr.ip6, i0, i1, i2, i3);
}

inline void ip_addr_ip6_host(struct IpAddrInfo& ipaddr, uint32_t i0, uint32_t i1, uint32_t i2, uint32_t i3)
{
    make_ip_addr_ip6(ipaddr, pp_htonl(i0), pp_htonl(i1), pp_htonl(i2), pp_htonl(i3));
}


inline IpAddrInfo create_ip_addr_ip4_bcast()
{
    IpAddrInfo addr{};
    addr.u_addr.ip4.addr = make_u32(255,255,255,255);
    addr.type = IPADDR_TYPE_V4;
    return addr;
}

inline Ip4Addr make_ip4_bcast_addr()
{
    return create_ip_addr_ip4_bcast().u_addr.ip4;
}


inline IpAddrInfo create_ip_addr_ip4_any()
{
    IpAddrInfo addr{};
    addr.u_addr.ip4.addr = make_u32(0,0,0,0);
    addr.type = IPADDR_TYPE_V4;
    return addr;
}

inline IpAddrInfo ip_addr_ip6_any() {
    IpAddrInfo addr{};
    addr.u_addr.ip6.addr[0] = 0;
    addr.u_addr.ip6.addr[1] = 0;
    addr.u_addr.ip6.addr[2] = 0;
    addr.u_addr.ip6.addr[3] = 0;
    addr.u_addr.ip6.zone = IP6_NO_ZONE;
    addr.type = IPADDR_TYPE_V6;
    return addr;
}

inline IpAddrInfo kIpAddrAny()
{
    IpAddrInfo addr{};
    addr.u_addr.ip6.addr[0] = 0;
    addr.u_addr.ip6.addr[1] = 0;
    addr.u_addr.ip6.addr[2] = 0;
    addr.u_addr.ip6.addr[3] = 0;
    addr.u_addr.ip6.zone = IP6_NO_ZONE;
    addr.type = IPADDR_TYPE_ANY;
    return addr;
}

inline void zero_ip_addr(IpAddrInfo* ip)
{
    ip->u_addr.ip6.addr[0] = 0;
    ip->u_addr.ip6.addr[1] = 0;
    ip->u_addr.ip6.addr[2] = 0;
    ip->u_addr.ip6.addr[3] = 0;
}

inline IpAddrInfo make_ip_addr_ip6_any()
{
    return {0,0,0,0, IP6_NO_ZONE, IPADDR_TYPE_ANY};
}

inline IpAddrInfo make_ip_addr_any()
{
    return make_ip_addr_ip6_any();
}

//
// END OF FILE
//