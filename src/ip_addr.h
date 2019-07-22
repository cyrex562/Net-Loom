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

inline IpAddr init_ip_addr_ip4(const uint32_t u32_val)
{
    return {{{{u32_val, 0UL, 0UL, 0UL}, kIp6NoZone}}, IPADDR_TYPE_V4};
}

//
//
//

inline IpAddr init_ip_addr_ip4_bytes(const uint8_t a,
                               const uint8_t b,
                               const uint8_t c,
                               const uint8_t d)
{
    return init_ip_addr_ip4(pp_htonl(make_u32(a, b, c, d)));
}

//
//
//
inline IpAddr init_ip_addr_ip6(const uint32_t a,
                          const uint32_t b,
                          const uint32_t c,
                          const uint32_t d)
{
    return {{{{a, b, c, d}, kIp6NoZone}}, IPADDR_TYPE_V6};
}

//
//
//
inline IpAddr init_ip_addr_ip6_host(const uint32_t a,
                              const uint32_t b,
                              const uint32_t c,
                              const uint32_t d)
{
    return {
            {{{pp_htonl(a), pp_htonl(b), pp_htonl(c), pp_htonl(d)}, kIp6NoZone}},
        IPADDR_TYPE_V6
    };
}

//
//
//
inline IpAddrType get_ip_addr_type(const IpAddr* ipaddr)
{
    return ipaddr->type;
}

//
//
//
inline bool is_ip_addr_any_type_val(const IpAddr ipaddr)
{
    return get_ip_addr_type(&ipaddr) == IPADDR_TYPE_ANY;
}

//
//
//
inline IpAddr init_ip_addr_any_type()
{
    return {{{{0UL, 0UL, 0UL, 0ul}, kIp6NoZone}}, IPADDR_TYPE_ANY};
}

//
//
//
inline bool is_ip_addr_ip4_val(const IpAddr ipaddr)
{
    return get_ip_addr_type(&ipaddr) == IPADDR_TYPE_V4;
}

inline bool is_ip_addr_ip6_val(const IpAddr ipaddr)
{
    return get_ip_addr_type(&ipaddr) == IPADDR_TYPE_V6;
}

inline bool is_ip_addr_ip4(const IpAddr* ipaddr)
{
    return ipaddr == nullptr || is_ip_addr_ip4_val(*ipaddr);
}

inline bool is_ip_addr_v6(const IpAddr* ipaddr)
{
    return ipaddr != nullptr && is_ip_addr_ip6_val(*ipaddr);
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
    memcpy(&new_addr, &kIpAddrAnyType, sizeof(const IpAddr));
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
    if (is_ip_addr_v6(src))
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
    if (ipaddr != nullptr)
    {
        set_ip4_addr_u32(&ipaddr->u_addr.ip4, val);
        set_ip_addr_type(ipaddr, IPADDR_TYPE_V4);
        clear_ip_addr(ipaddr);
    }
}

//
//
//
inline IpAddr set_ip_addr_ip4_u32_val(IpAddr ipaddr, const uint32_t val)
{
    set_ip4_addr_u32(&ipaddr.u_addr.ip4, val);
    set_ip_addr_type_val(ipaddr, IPADDR_TYPE_V4);
    clear_ip_addr(&ipaddr);
    return ipaddr;
}

//
//
//
inline uint32_t get_ip4_addr_u32_from_ip_addr(const IpAddr* ipaddr)
{
    if ((ipaddr != nullptr) && is_ip_addr_ip4(ipaddr))
    {
        return get_ip4_addr(&ipaddr->u_addr.ip4);
    }
    return 0;
}

//
//
//
inline void set_ip_addr(IpAddr* dest, const IpAddr* src)
{
    set_ip_addr_type(dest, get_ip_addr_type(src));
    if (is_ip_addr_v6(src))
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
// inline void zero_ip_addr(IpAddr* ipaddr)
// {
//     ip6_addr_set_zero(&ipaddr->u_addr.ip6);
//     ipaddr->type = IPADDR_TYPE_V4;
// }


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
    if (is_ip_addr_v6(src))
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
    if (is_ip_addr_v6(host))
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
    return is_ip_addr_v6(addr1) && is_ip_addr_v6(addr2)
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
               : is_ip_addr_v6(addr1)
               ? ip6_addr_cmp(&addr1->u_addr.ip6, &addr2->u_addr.ip6)
               : ip4_addr_cmp(&addr1->u_addr.ip4, &addr2->u_addr.ip4);
}


/** @ingroup ipaddr */
inline bool compare_ip_addr_zoneless(IpAddr* addr1, IpAddr* addr2)
{
    if ((get_ip_addr_type(addr1) != get_ip_addr_type(addr2)))
        return false;
    if (is_ip_addr_v6(addr1))
        return ip6_addr_cmp_zoneless(&addr1->u_addr.ip6, &addr2->u_addr.ip6);
    return ip4_addr_cmp(&addr1->u_addr.ip4, &addr2->u_addr.ip4);
}


/** @ingroup ipaddr */
inline bool is_ip_addr_any(IpAddr* ipaddr)
{
    if (((ipaddr) == nullptr))
        return true;
    if (is_ip_addr_v6(ipaddr))
        return ip6_addr_isany(&ipaddr->u_addr.ip6);
    return ip4_addr_isany(&ipaddr->u_addr.ip4);
}


inline bool ip_addr_isany_val(IpAddr ipaddr)
{
    if (is_ip_addr_ip6_val(ipaddr))
        return ip6_addr_isany_val(*convert_ip_addr_to_ip6_addr(&ipaddr));
    return ip4_addr_isany_val(*convert_ip_addr_to_ip4_addr(&ipaddr));
}


inline bool ip_addr_isbroadcast(IpAddr* ipaddr, NetIfc* netif)
{
    return ((is_ip_addr_v6(ipaddr)) ? 0 : ip4_addr_isbroadcast(&ipaddr->u_addr.ip4, netif));
}


inline bool ip_addr_ismulticast(IpAddr* ipaddr)
{
    if (is_ip_addr_v6(ipaddr))
        return ip6_addr_ismulticast(&ipaddr->u_addr.ip6);
    return ip4_addr_ismulticast(&ipaddr->u_addr.ip4);
}


inline bool ip_addr_isloopback(IpAddr* ipaddr)
{
    if ((is_ip_addr_v6(ipaddr)))
        return ip6_addr_isloopback(&ipaddr->u_addr.ip6);
    return ip4_addr_isloopback(&ipaddr->u_addr.ip4);
}



inline bool ip_addr_islinklocal(IpAddr* ipaddr)
{
    if (is_ip_addr_v6(ipaddr))
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
    (ip6_addr)->addr[2] = pp_htonl(0x0000FFFFUL);
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
    set_ip6_addr(&ipaddr->u_addr.ip6, i0, i1, i2, i3);
}

inline void IP_ADDR6_HOST(struct IpAddr* ipaddr, uint32_t i0, uint32_t i1, uint32_t i2, uint32_t i3)
{
    IP_ADDR6(ipaddr, pp_htonl(i0), pp_htonl(i1), pp_htonl(i2), pp_htonl(i3));
}


inline IpAddr kIpAddrIp4Broadcast()
{
    IpAddr addr{};
    addr.u_addr.ip4.addr = make_u32(255,255,255,255);
    addr.type = IPADDR_TYPE_V4;
    return addr;
}


inline IpAddr kIpAddrIp4Any()
{
    IpAddr addr{};
    addr.u_addr.ip4.addr = make_u32(0,0,0,0);
    addr.type = IPADDR_TYPE_V4;
    return addr;
}

inline IpAddr kIpAddrIp6Any() {
    IpAddr addr{};
    addr.u_addr.ip6.addr[0] = 0;
    addr.u_addr.ip6.addr[1] = 0;
    addr.u_addr.ip6.addr[2] = 0;
    addr.u_addr.ip6.addr[3] = 0;
    addr.u_addr.ip6.zone = kIp6NoZone;
    addr.type = IPADDR_TYPE_V6;
    return addr;
}

inline IpAddr kIpAddrAny()
{
    IpAddr addr{};
    addr.u_addr.ip6.addr[0] = 0;
    addr.u_addr.ip6.addr[1] = 0;
    addr.u_addr.ip6.addr[2] = 0;
    addr.u_addr.ip6.addr[3] = 0;
    addr.u_addr.ip6.zone = kIp6NoZone;
    addr.type = IPADDR_TYPE_ANY;
    return addr;
}

inline void zero_ip_addr(IpAddr* ip)
{
    ip->u_addr.ip6.addr[0] = 0;
    ip->u_addr.ip6.addr[1] = 0;
    ip->u_addr.ip6.addr[2] = 0;
    ip->u_addr.ip6.addr[3] = 0;
}



//
// END OF FILE
//