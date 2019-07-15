#pragma once

#include "ip6_addr.h"
#include "ip4_addr.h"
#include <cstring>

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

//
// Unified Ip Address struct
//
struct IpAddr
{
    union
    {
        Ip6Addr ip6;
        Ip4Addr ip4;
    } u_addr;

    IpAddrType type;
};

struct NetIfc;

extern const struct IpAddr kIpAddrAnyType;

inline IpAddr Ipaddr4Init(const uint32_t u32_val)
{
    return {{{{u32_val, 0ul, 0ul, 0ul}, kIp6NoZone}}, IPADDR_TYPE_V4};
}

inline IpAddr IpAddr4InitBytes(const uint8_t a,
                               const uint8_t b,
                               const uint8_t c,
                               const uint8_t d)
{
    return Ipaddr4Init(PP_HTONL(LwipMakeu32(a, b, c, d)));
}

inline IpAddr Ipaddr6Init(const uint32_t a,
                          const uint32_t b,
                          const uint32_t c,
                          const uint32_t d)
{
    return {{{{a, b, c, d}, kIp6NoZone}}, IPADDR_TYPE_V6};
}

inline IpAddr Ipaddr6InitHost(const uint32_t a,
                              const uint32_t b,
                              const uint32_t c,
                              const uint32_t d)
{
    return {
            {{{PP_HTONL(a), PP_HTONL(b), PP_HTONL(c), PP_HTONL(d)}, kIp6NoZone}},
        IPADDR_TYPE_V6
    };
}

inline IpAddrType get_ip_addr_type(const IpAddr* ipaddr)
{
    return ipaddr->type;
}

inline bool IpIsAnyTypeVal(const IpAddr ipaddr)
{
    return get_ip_addr_type(&ipaddr) == IPADDR_TYPE_ANY;
}

inline IpAddr IpaddrAnyTypeInit()
{
    return {{{{0ul, 0ul, 0ul, 0ul}, kIp6NoZone}}, IPADDR_TYPE_ANY};
}

inline bool IpIsV4Val(IpAddr ipaddr)
{
    return get_ip_addr_type(&ipaddr) == IPADDR_TYPE_V4;
}

inline bool IpIsV6Val(IpAddr ipaddr)
{
    return get_ip_addr_type(&ipaddr) == IPADDR_TYPE_V6;
}

inline bool IpIsV4(IpAddr* ipaddr)
{
    return ipaddr == nullptr || IpIsV4Val(*ipaddr);
}

inline bool is_ip_v6(const IpAddr* ipaddr)
{
    return ipaddr != nullptr && IpIsV6Val(*ipaddr);
}

inline IpAddr set_ip_addr_type_val(IpAddr ipaddr, const IpAddrType iptype)
{
    ipaddr.type = iptype;
    return ipaddr;
}

inline void set_ip_addr_type(IpAddr* ipaddr, const IpAddrType iptype)
{
    ipaddr->type = iptype;
}

inline size_t get_ip_addr_raw_size(const IpAddr ipaddr)
{
    if (get_ip_addr_type(&ipaddr) == IPADDR_TYPE_V4)
        return sizeof(Ip4Addr);
    return sizeof(Ip6Addr);
} 

//
// Convert generic ip address to specific protocol version
//
inline const Ip6Addr* convert_ip_addr_to_ip6_addr(const IpAddr* ipaddr)
{
    return &ipaddr->u_addr.ip6;
}


//
// Convert generic ip address to specific protocol version
//
inline const Ip4Addr* convert_ip_addr_to_ip4_addr(const IpAddr* ipaddr)
{
    return &ipaddr->u_addr.ip4;
}

//
//
//
inline IpAddr create_new_any_ip_addr()
{
    IpAddr new_addr = {};
    memcpy(&new_addr, &kIpAddrAnyType, sizeof(IpAddr));
    return new_addr;
}

/** @ingroup ip4addr */
inline void new_ip_addr_ip4_u8(IpAddr* ipaddr, uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    Ipv4AddrFromBytes(&ipaddr->u_addr.ip4, a, b, c, d);
    set_ip_addr_type_val(*ipaddr, IPADDR_TYPE_V4);
}

/** Copy the zone field from the second IPv6 address to the first one. */
inline void ip6_addr_copy_zone(Ip6Addr* ip6addr1, const Ip6Addr* ip6addr2)
{
    ip6addr1->zone = ip6addr2->zone;
}

//
//
//
/** Copy IPv6 address - faster than ip6_addr_set: no NULL check */
inline void copy_ip6_addr(Ip6Addr* dest, const Ip6Addr* src)
{
    dest->addr[0] = src->addr[0];
    dest->addr[1] = src->addr[1];
    dest->addr[2] = src->addr[2];
    dest->addr[3] = src->addr[3];
    ip6_addr_copy_zone(dest, src);
}

inline void copy_ip4_addr(Ip4Addr* dest, const Ip4Addr* src)
{
    dest->addr = src->addr;
}

//
//
//
inline void clear_ip_addr(IpAddr* ipaddr)
{
    ipaddr->u_addr.ip6.addr[1] = 0;
    ipaddr->u_addr.ip6.addr[2] = 0;
    ipaddr->u_addr.ip6.addr[3] = 0;
    ip6_addr_clear_zone(&ipaddr->u_addr.ip6);
}

//
//
//
inline void copy_ip_addr(IpAddr* dest, const IpAddr* src)
{
    dest->type = get_ip_addr_type(src);
    if (is_ip_v6(src))
    {
        copy_ip6_addr(&dest->u_addr.ip6, &src->u_addr.ip6);
    }
    else
    {
        copy_ip4_addr(&dest->u_addr.ip4, &src->u_addr.ip4);
        clear_ip_addr(dest);
    }
}

//
//
//
inline void copy_ip6_addr_to_ip_addr(IpAddr* dest, Ip6Addr* src)
{
    copy_ip6_addr(&dest->u_addr.ip6, src);
    dest->type = IPADDR_TYPE_V6;
}

//
//
//
inline void copy_ip4_addr_to_ip_addr(IpAddr* dest, Ip4Addr* src)
{
    copy_ip4_addr(&dest->u_addr.ip4, src);
    set_ip_addr_type_val(*dest, IPADDR_TYPE_V4);
    clear_ip_addr(dest);
}


//
//
//
inline void set_ip_addr_ip4_u32(IpAddr* ipaddr, const uint32_t val)
{
    if (ipaddr)
    {
        SetIp4AddrU32(&ipaddr->u_addr.ip4, val);
        set_ip_addr_type(ipaddr, IPADDR_TYPE_V4);
        clear_ip_addr(ipaddr);
    }
}

//
//
//
inline IpAddr set_ip_addr_ip4_u32_val(IpAddr ipaddr, const uint32_t val)
{
    SetIp4AddrU32(&ipaddr.u_addr.ip4, val);
    set_ip_addr_type_val(ipaddr, IPADDR_TYPE_V4);
    clear_ip_addr(&ipaddr);
    return ipaddr;
}

//
//
//
inline uint32_t get_ip4_addr_u32_from_ip_addr(IpAddr* ipaddr)
{
    if (ipaddr && IpIsV4(ipaddr))
        return ip4_addr_get_u32(&ipaddr->u_addr.ip4);
    return 0;
} 

//
//
//
inline void set_ip_addr(IpAddr* dest, IpAddr* src)
{
    set_ip_addr_type(dest, get_ip_addr_type(src));
    if (is_ip_v6(src))
    {
        ip6_addr_set(&dest->u_addr.ip6, &src->u_addr.ip6);
    }
    else
    {
        ip4_addr_set(&dest->u_addr.ip4, &src->u_addr.ip4);
        clear_ip_addr(dest);
    }
}

//
//
//
inline void zero_ip_addr(IpAddr* ipaddr)
{
    ip6_addr_set_zero(&ipaddr->u_addr.ip6);
    ipaddr->type = IPADDR_TYPE_V4;
}


//
//
//
inline void zerp_ip_addr_ip4(IpAddr* ipaddr)
{
    ip4_addr_set_zero(&ipaddr->u_addr.ip4);
    set_ip_addr_type(ipaddr, IPADDR_TYPE_V4);
}


//
//
//
inline void zero_ip_addr_ip6(IpAddr* ipaddr)
{
    ip6_addr_set_zero(&ipaddr->u_addr.ip6);
    set_ip_addr_type(ipaddr, IPADDR_TYPE_V6);
}



//
//
//
inline void set_ip_addr_any(bool is_ipv6, IpAddr* ipaddr)
{
    if (is_ipv6)
    {
        ip6_addr_set_any(&ipaddr->u_addr.ip6);
        set_ip_addr_type(ipaddr, IPADDR_TYPE_V6);
    }
    else
    {
        ip4_addr_set_any(&ipaddr->u_addr.ip4);
        set_ip_addr_type(ipaddr, IPADDR_TYPE_V4);
        clear_ip_addr(ipaddr);
    }
}

//
//
//
inline IpAddr set_ip_addr_any_val(const bool is_ipv6, IpAddr ipaddr)
{
    if (is_ipv6)
    {
        ip6_addr_set_any(&ipaddr.u_addr.ip6);
        set_ip_addr_type_val(ipaddr, IPADDR_TYPE_V6);
    }
    else
    {
        ip4_addr_set_any(&ipaddr.u_addr.ip4);
        set_ip_addr_type_val(ipaddr, IPADDR_TYPE_V4);
        clear_ip_addr(&ipaddr);
    }
    return ipaddr;
}

//
//
//
inline void set_ip_addr_loopback(const bool is_ipv6, IpAddr* ipaddr)
{
    if (is_ipv6)
    {
        ip6_addr_set_loopback(&ipaddr->u_addr.ip6);
        set_ip_addr_type(ipaddr, IPADDR_TYPE_V6);
    }
    else
    {
        ip4_addr_set_loopback(&ipaddr->u_addr.ip4);
        set_ip_addr_type(ipaddr, IPADDR_TYPE_V4);
        clear_ip_addr(ipaddr);
    }
}

/** @ingroup ipaddr */
inline void set_ip_addr_loopback_val(bool is_ipv6, IpAddr ipaddr)
{
    if (is_ipv6)
    {
        ip6_addr_set_loopback(&ipaddr.u_addr.ip6);
        set_ip_addr_type_val(ipaddr, IPADDR_TYPE_V6);
    }
    else
    {
        ip4_addr_set_loopback(&ipaddr.u_addr.ip4);
        set_ip_addr_type_val(ipaddr, IPADDR_TYPE_V4);
        clear_ip_addr(&ipaddr);
    }
}

/** @ingroup ipaddr */
inline void set_ip_addr_hton(IpAddr* dest, IpAddr* src)
{
    if (is_ip_v6(src))
    {
        ip6_addr_set_hton(&dest->u_addr.ip6, &src->u_addr.ip6);
        set_ip_addr_type(dest, IPADDR_TYPE_V6);
    }
    else
    {
        ip4_addr_set_hton(&dest->u_addr.ip4, &src->u_addr.ip4);
        set_ip_addr_type(dest, IPADDR_TYPE_V4);
        clear_ip_addr(dest);
    }
}


/** @ingroup ipaddr */
inline void get_ip_addr_net(IpAddr* target, IpAddr* host, IpAddr* netmask)
{
    if (is_ip_v6(host))
    {
        ip4_addr_set_zero(&target->u_addr.ip4);
        set_ip_addr_type(target, IPADDR_TYPE_V6);
    }
    else
    {
        ip4_addr_get_network(&target->u_addr.ip4,
                             &host->u_addr.ip4,
                             &netmask->u_addr.ip4);
        set_ip_addr_type(target, IPADDR_TYPE_V4);
    }
}

/** @ingroup ipaddr */
inline bool compare_ip_addr_mask(IpAddr* addr1, IpAddr* addr2, IpAddr* mask)
{
    return is_ip_v6(addr1) && is_ip_v6(addr2)
               ? false
               : ip4_addr_netcmp(&addr1->u_addr.ip4,
                                 &addr2->u_addr.ip4,
                                 &mask->u_addr.ip4);
}

/** @ingroup ipaddr */
inline bool compare_ip_addr(const IpAddr* addr1, const IpAddr* addr2)
{
    return get_ip_addr_type(addr1) != get_ip_addr_type(addr2)
               ? false
               : is_ip_v6(addr1)
               ? ip6_addr_cmp(&addr1->u_addr.ip6, &addr2->u_addr.ip6)
               : ip4_addr_cmp(&addr1->u_addr.ip4, &addr2->u_addr.ip4);
}


/** @ingroup ipaddr */
inline bool compare_ip_addr_zoneless(IpAddr* addr1, IpAddr* addr2)
{
    if ((get_ip_addr_type(addr1) != get_ip_addr_type(addr2)))
        return false;
    if (is_ip_v6(addr1))
        return ip6_addr_cmp_zoneless(&addr1->u_addr.ip6, &addr2->u_addr.ip6);
    return ip4_addr_cmp(&addr1->u_addr.ip4, &addr2->u_addr.ip4);
} 


/** @ingroup ipaddr */
inline bool is_ip_addr_any(IpAddr* ipaddr)
{
    if (((ipaddr) == nullptr))
        return true;
    if (is_ip_v6(ipaddr))
        return ip6_addr_isany(&ipaddr->u_addr.ip6);
    return ip4_addr_isany(&ipaddr->u_addr.ip4);
} 


inline bool ip_addr_isany_val(IpAddr ipaddr)
{
    if (IpIsV6Val(ipaddr))
        return ip6_addr_isany_val(*convert_ip_addr_to_ip6_addr(&ipaddr));
    return ip4_addr_isany_val(*convert_ip_addr_to_ip4_addr(&ipaddr));
}


inline bool ip_addr_isbroadcast(IpAddr* ipaddr, NetIfc* netif)
{
    return ((is_ip_v6(ipaddr)) ? 0 : ip4_addr_isbroadcast(&ipaddr->u_addr.ip4, netif));
}


inline bool ip_addr_ismulticast(IpAddr* ipaddr)
{
    if (is_ip_v6(ipaddr))
        return ip6_addr_ismulticast(&ipaddr->u_addr.ip6);
    return ip4_addr_ismulticast(&ipaddr->u_addr.ip4);
} 


inline bool ip_addr_isloopback(IpAddr* ipaddr)
{
    if ((is_ip_v6(ipaddr)))
        return ip6_addr_isloopback(&ipaddr->u_addr.ip6);
    return ip4_addr_isloopback(&ipaddr->u_addr.ip4);
} 



inline bool ip_addr_islinklocal(IpAddr* ipaddr)
{
    if (is_ip_v6(ipaddr))
        return ip6_addr_islinklocal(&ipaddr->u_addr.ip6);
    return ip4_addr_islinklocal(&ipaddr->u_addr.ip4);
}

// #define ip_addr_debug_print(debug, ipaddr) do { if(IpIsV6(ipaddr)) { \
//   ip6_addr_debug_print(debug, ip_2_ip6(ipaddr)); } else { \
//   ip4_addr_debug_print(debug, ip_2_ip4(ipaddr)); }}while(0)


// #define ip_addr_debug_print_val(debug, ipaddr) do { if(IP_IS_V6_VAL(ipaddr)) { \
//   ip6_addr_debug_print_val(debug, *ip_2_ip6(&(ipaddr))); } else { \
//   ip4_addr_debug_print_val(debug, *ip_2_ip4(&(ipaddr))); }}while(0)


char *ipaddr_ntoa(const IpAddr *addr);
char* ipaddr_ntoa_r(const IpAddr* addr, char* buf, int buflen);
int ipaddr_aton(const char* cp, IpAddr* addr);

/** @ingroup ipaddr */
inline void ip4_2_ipv4_mapped_ipv6(Ip6Addr* ip6_addr, Ip4Addr* ip4addr)
{
    (ip6_addr)->addr[3] = (ip4addr)->addr;
    (ip6_addr)->addr[2] = PP_HTONL(0x0000FFFFUL);
    (ip6_addr)->addr[1] = 0;
    (ip6_addr)->addr[0] = 0;
    ip6_addr_clear_zone(ip6_addr);
}

/** @ingroup ipaddr */
inline void unmap_ipv4_mapped_ipv6(Ip4Addr* ip4addr, Ip6Addr* ip6addr)
{
    (ip4addr)->addr = (ip6addr)->addr[3];
}

// inline bool IP46_ADDR_ANY(IpAddrType type) {
//   return (((type) == IPADDR_TYPE_V6) ? Ip6Addr : IP4_ADDR_ANY);
// }

inline void IP_ADDR6(IpAddr* ipaddr, uint32_t i0, uint32_t i1, uint32_t i2, uint32_t i3)
{
    IP6_ADDR(&ipaddr->u_addr.ip6, i0, i1, i2, i3);
}         

inline void IP_ADDR6_HOST(struct IpAddr* ipaddr, uint32_t i0, uint32_t i1, uint32_t i2, uint32_t i3)
{
    IP_ADDR6(ipaddr, PP_HTONL(i0), PP_HTONL(i1), PP_HTONL(i2), PP_HTONL(i3));
}

extern const IpAddr kIpAddrAny;
extern const IpAddr kIpAddrBroadcast;

/**
 * @ingroup ip4addr
 * Can be used as a fixed/const IpAddr
 * for the IP wildcard.
 * Defined to @ref IP4_ADDR_ANY when IPv4 is enabled.
 * Defined to @ref IP6_ADDR_ANY in IPv6 only systems.
 * Use this if you can handle IPv4 _AND_ IPv6 addresses.
 * Use @ref IP4_ADDR_ANY or @ref IP6_ADDR_ANY when the IP
 * type matters.
 */

/**
 * @ingroup ip4addr
 * Can be used as a fixed/const IpAddr
 * for the IPv4 wildcard and the broadcast address
 */
constexpr auto kIp4AddrAny = &kIpAddrAny;
/**
 * @ingroup ip4addr
 * Can be used as a fixed/const Ip4Addr
 * for the wildcard and the broadcast address
 */
// constexpr auto IP4_ADDR_ANY4 = &kIpAddrAny.u_addr.ip4;

/** @ingroup ip4addr */
constexpr auto IP_ADDR_BROADCAST = &kIpAddrBroadcast;
/** @ingroup ip4addr */
constexpr auto IP4_ADDR_BROADCAST = &kIpAddrBroadcast.u_addr.ip4;

    extern const IpAddr ip6_addr_any;

/** 
 * @ingroup ip6addr
 * IP6_ADDR_ANY can be used as a fixed IpAddr
 * for the IPv6 wildcard address
 */
constexpr auto kIp6AddrAny = &ip6_addr_any;
/**
 * @ingroup ip6addr
 * IP6_ADDR_ANY6 can be used as a fixed Ip6Addr
 * for the IPv6 wildcard address
 */
constexpr auto kIp6AddrAny6 = &ip6_addr_any.u_addr.ip6;

// 
constexpr auto kIpAnyType = &kIpAddrAnyType;

//
// END OF FILE
//