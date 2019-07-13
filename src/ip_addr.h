/**
 * @file
 * IP address API (common IPv4 and IPv6)
 */

/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */
#pragma once

#include "ip6_addr.h"
#include "ip4_addr.h"
#include <cstring>
#ifdef __cplusplus
extern "C" {
#endif


struct IpAddr;

/** @ingroup ipaddr
 * IP address types for use in IpAddr.type member.
 * @see tcp_new_ip_type(), udp_new_ip_type(), raw_new_ip_type().
 */
enum IpAddrType {
  /** IPv4 */
  IPADDR_TYPE_V4 =   0U,
  /** IPv6 */
  IPADDR_TYPE_V6 =   6U,
  /** IPv4+IPv6 ("dual-stack") */
  IPADDR_TYPE_ANY = 46U
};

// Unified Ip Address struct
struct IpAddr
{
    union
    {
        Ip6Addr ip6;
        Ip4Addr ip4;
    } u_addr; 
    IpAddrType type;
};

extern const struct IpAddr kIpAddrAnyType;

inline IpAddr Ipaddr4Init(const uint32_t u32_val)
{
    return {{{{u32_val, 0ul, 0ul, 0ul}  , kIp6NoZone}}, IPADDR_TYPE_V4};
}

inline IpAddr IpAddr4InitBytes(const uint8_t a, const uint8_t b, const uint8_t c, const uint8_t d)
{
    return Ipaddr4Init(PP_HTONL(LwipMakeu32(a, b, c, d)));
}

inline IpAddr Ipaddr6Init(const uint32_t a, const uint32_t b, const uint32_t c, const uint32_t d)
{
    return {{{{a, b, c, d}  , kIp6NoZone}}, IPADDR_TYPE_V6};
}

inline IpAddr IPADDR6_INIT_HOST(const uint32_t a,
                                const uint32_t b,
                                const uint32_t c,
                                const uint32_t d)
{
    return {
            {{{PP_HTONL(a), PP_HTONL(b), PP_HTONL(c), PP_HTONL(d)}   , kIp6NoZone}},
        IPADDR_TYPE_V6
    };
}

inline IpAddrType GetIpAddrType(const IpAddr* ipaddr)
{
    return ((ipaddr)->type);
}

inline bool IpIsAnyTypeVal(const IpAddr ipaddr) {
  return (GetIpAddrType(&ipaddr) == IPADDR_TYPE_ANY);
}

inline IpAddr IpaddrAnyTypeInit()
{
    return {{{{0ul, 0ul, 0ul, 0ul}, kIp6NoZone}}, IPADDR_TYPE_ANY};
}

inline bool IpIsV4Val(IpAddr ipaddr)
{
    return (GetIpAddrType(&ipaddr) == IPADDR_TYPE_V4);
}

inline bool IpIsV6Val(IpAddr ipaddr)
{
    return (GetIpAddrType(&ipaddr) == IPADDR_TYPE_V6);
}

inline bool IpIsV4(IpAddr* ipaddr)
{
    return (((ipaddr) == nullptr) || IpIsV4Val(*(ipaddr)));
}

inline bool IpIsV6(const IpAddr* ipaddr)
{
    return (((ipaddr) != nullptr) && IpIsV6Val(*(ipaddr)));
}

inline IpAddr IpAdderSetTypeVal(IpAddr ipaddr, const IpAddrType iptype)
{
    (ipaddr).type = (iptype);
    return ipaddr;
}

inline void IpSetType(IpAddr* ipaddr, const IpAddrType iptype)
{
    ipaddr->type = iptype;
}

inline size_t IpAddrRawSize(IpAddr ipaddr) {
  return (GetIpAddrType(&ipaddr) == IPADDR_TYPE_V4 ? sizeof(Ip4Addr)
                                            : sizeof(Ip6Addr));
}





/** @ingroup ip6addr
 * Convert generic ip address to specific protocol version
 */
inline Ip6Addr* ip_2_ip6(IpAddr* ipaddr) {
    return   (&((ipaddr)->u_addr.ip6));
}
/** @ingroup ip4addr
 * Convert generic ip address to specific protocol version
 */
inline Ip4Addr* ip_2_ip4(IpAddr* ipaddr) {
    return   (&((ipaddr)->u_addr.ip4));
}




inline IpAddr make_new_any_ip_addr()
{
    IpAddr new_addr = {};
    memcpy(&new_addr, &kIpAddrAnyType, sizeof(IpAddr));
    return new_addr;
}

/** @ingroup ip4addr */
inline void IP_ADDR4(IpAddr* ipaddr, uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    Ipv4AddrFromBytes(ip_2_ip4(ipaddr), a, b, c, d);
    IpAdderSetTypeVal(*(ipaddr), IPADDR_TYPE_V4); 
}
/** @ingroup ip6addr */
// #define IP_ADDR6(ipaddr,i0,i1,i2,i3)  do { IP6_ADDR(ip_2_ip6(ipaddr),i0,i1,i2,i3); \
//                                            IpAdderSetTypeVal(*(ipaddr), IPADDR_TYPE_V6); } while(0)
/** @ingroup ip6addr */
// #define IP_ADDR6_HOST(ipaddr,i0,i1,i2,i3)  IP_ADDR6(ipaddr,PP_HTONL(i0),PP_HTONL(i1),PP_HTONL(i2),PP_HTONL(i3))




/** Copy the zone field from the second IPv6 address to the first one. */
inline void ip6_addr_copy_zone(Ip6Addr* ip6addr1, const Ip6Addr* ip6addr2)
{
    ((ip6addr1)->zone = (ip6addr2)->zone);
}

//
//
//
/** Copy IPv6 address - faster than ip6_addr_set: no NULL check */
inline void ip6_addr_copy(Ip6Addr* dest, const Ip6Addr* src)
{
    (dest)->addr[0] = (src)->addr[0];
    (dest)->addr[1] = (src)->addr[1];
    (dest)->addr[2] = (src)->addr[2];
    (dest)->addr[3] = (src)->addr[3];
    ip6_addr_copy_zone((dest), (src));
}

inline void ip4_addr_copy(Ip4Addr* dest, const Ip4Addr* src)
{
    ((dest)->addr = (src)->addr);
}

inline void ip_clear_no4(IpAddr* ipaddr)
{
    ip_2_ip6(ipaddr)->addr[1] = ip_2_ip6(ipaddr)->addr[2] = ip_2_ip6(ipaddr)->addr[3] = 0;
    ip6_addr_clear_zone(ip_2_ip6(ipaddr));
}

/** @ingroup ipaddr */
inline void ip_addr_copy(IpAddr* dest, const IpAddr* src)
{
    dest->type = GetIpAddrType(src);
    if (IpIsV6(src))
    {
        ip6_addr_copy(&dest->u_addr.ip6, &src->u_addr.ip6);
    }
    else
    {
        ip4_addr_copy(&dest->u_addr.ip4, &src->u_addr.ip4);
        ip_clear_no4(dest);
    }
}

/** @ingroup ip6addr */
#define ip_addr_copy_from_ip6(dest, src)      do{ \
  ip6_addr_copy(*ip_2_ip6(&(dest)), src); IpAdderSetTypeVal(dest, IPADDR_TYPE_V6); }while(0)
/** @ingroup ip6addr */
#define ip_addr_copy_from_ip6_packed(dest, src)      do{ \
  ip6_addr_copy_from_packed(*ip_2_ip6(&(dest)), src); IpAdderSetTypeVal(dest, IPADDR_TYPE_V6); }while(0)
/** @ingroup ip4addr */
inline void ip_addr_copy_from_ip4(IpAddr* dest, Ip4Addr* src)
{
    ip4_addr_copy(&dest->u_addr.ip4, src);
    IpAdderSetTypeVal(*dest, IPADDR_TYPE_V4);
    ip_clear_no4(dest);
}


/** @ingroup ip4addr */
#define ip_addr_set_ip4_u32(ipaddr, val)  do{if(ipaddr){ip4_addr_set_u32(ip_2_ip4(ipaddr), val); \
  IP_SET_TYPE(ipaddr, IPADDR_TYPE_V4); ip_clear_no4(ipaddr); }}while(0)
/** @ingroup ip4addr */
#define ip_addr_set_ip4_u32_val(ipaddr, val)  do{ ip4_addr_set_u32(ip_2_ip4(&(ipaddr)), val); \
  IpAdderSetTypeVal(ipaddr, IPADDR_TYPE_V4); ip_clear_no4(&ipaddr); }while(0)
/** @ingroup ip4addr */
#define ip_addr_get_ip4_u32(ipaddr)  (((ipaddr) && IP_IS_V4(ipaddr)) ? \
  ip4_addr_get_u32(ip_2_ip4(ipaddr)) : 0)
/** @ingroup ipaddr */
#define ip_addr_set(dest, src) do{ IP_SET_TYPE(dest, GetIpAddrType(src)); if(IpIsV6(src)){ \
  ip6_addr_set(ip_2_ip6(dest), ip_2_ip6(src)); }else{ \
  ip4_addr_set(ip_2_ip4(dest), ip_2_ip4(src)); ip_clear_no4(dest); }}while(0)
/** @ingroup ipaddr */
#define ip_addr_set_ipaddr(dest, src) ip_addr_set(dest, src)
/** @ingroup ipaddr */
#define ip_addr_set_zero(ipaddr)     do{ \
  ip6_addr_set_zero(ip_2_ip6(ipaddr)); IP_SET_TYPE(ipaddr, 0); }while(0)
/** @ingroup ip5addr */
#define ip_addr_set_zero_ip4(ipaddr)     do{ \
  ip6_addr_set_zero(ip_2_ip6(ipaddr)); IP_SET_TYPE(ipaddr, IPADDR_TYPE_V4); }while(0)
/** @ingroup ip6addr */
#define ip_addr_set_zero_ip6(ipaddr)     do{ \
  ip6_addr_set_zero(ip_2_ip6(ipaddr)); IP_SET_TYPE(ipaddr, IPADDR_TYPE_V6); }while(0)
/** @ingroup ipaddr */
#define ip_addr_set_any(is_ipv6, ipaddr)      do{if(is_ipv6){ \
  ip6_addr_set_any(ip_2_ip6(ipaddr)); IP_SET_TYPE(ipaddr, IPADDR_TYPE_V6); }else{ \
  ip4_addr_set_any(ip_2_ip4(ipaddr)); IP_SET_TYPE(ipaddr, IPADDR_TYPE_V4); ip_clear_no4(ipaddr); }}while(0)
/** @ingroup ipaddr */
#define ip_addr_set_any_val(is_ipv6, ipaddr)      do{if(is_ipv6){ \
  ip6_addr_set_any(ip_2_ip6(&(ipaddr))); IpAdderSetTypeVal(ipaddr, IPADDR_TYPE_V6); }else{ \
  ip4_addr_set_any(ip_2_ip4(&(ipaddr))); IpAdderSetTypeVal(ipaddr, IPADDR_TYPE_V4); ip_clear_no4(&ipaddr); }}while(0)
/** @ingroup ipaddr */
#define ip_addr_set_loopback(is_ipv6, ipaddr) do{if(is_ipv6){ \
  ip6_addr_set_loopback(ip_2_ip6(ipaddr)); IP_SET_TYPE(ipaddr, IPADDR_TYPE_V6); }else{ \
  ip4_addr_set_loopback(ip_2_ip4(ipaddr)); IP_SET_TYPE(ipaddr, IPADDR_TYPE_V4); ip_clear_no4(ipaddr); }}while(0)
/** @ingroup ipaddr */
#define ip_addr_set_loopback_val(is_ipv6, ipaddr) do{if(is_ipv6){ \
  ip6_addr_set_loopback(ip_2_ip6(&(ipaddr))); IpAdderSetTypeVal(ipaddr, IPADDR_TYPE_V6); }else{ \
  ip4_addr_set_loopback(ip_2_ip4(&(ipaddr))); IpAdderSetTypeVal(ipaddr, IPADDR_TYPE_V4); ip_clear_no4(&ipaddr); }}while(0)
/** @ingroup ipaddr */
#define ip_addr_set_hton(dest, src)  do{if(IpIsV6(src)){ \
  ip6_addr_set_hton(ip_2_ip6(dest), ip_2_ip6(src)); IP_SET_TYPE(dest, IPADDR_TYPE_V6); }else{ \
  ip4_addr_set_hton(ip_2_ip4(dest), ip_2_ip4(src)); IP_SET_TYPE(dest, IPADDR_TYPE_V4); ip_clear_no4(ipaddr); }}while(0)
/** @ingroup ipaddr */
#define ip_addr_get_network(target, host, netmask) do{if(IpIsV6(host)){ \
  ip4_addr_set_zero(ip_2_ip4(target)); IP_SET_TYPE(target, IPADDR_TYPE_V6); } else { \
  ip4_addr_get_network(ip_2_ip4(target), ip_2_ip4(host), ip_2_ip4(netmask)); IP_SET_TYPE(target, IPADDR_TYPE_V4); }}while(0)
/** @ingroup ipaddr */
#define ip_addr_netcmp(addr1, addr2, mask) ((IpIsV6(addr1) && IpIsV6(addr2)) ? \
  0 : \
  ip4_addr_netcmp(ip_2_ip4(addr1), ip_2_ip4(addr2), mask))

/** Compare IPv6 addresses, ignoring zone information. To be used sparingly! */






/** @ingroup ipaddr */
inline bool ip_addr_cmp(const IpAddr* addr1, const IpAddr* addr2)
{
    return ((GetIpAddrType(addr1) != GetIpAddrType(addr2))
                ? 0
                : (IpIsV6(addr1)
                       ? ip6_addr_cmp(&addr1->u_addr.ip6, &addr2->u_addr.ip6)
                       : ip4_addr_cmp(&addr1->u_addr.ip4, &addr2->u_addr.ip4)));
}

/** @ingroup ipaddr */
#define ip_addr_cmp_zoneless(addr1, addr2)    ((GetIpAddrType(addr1) != GetIpAddrType(addr2)) ? 0 : (IP_IS_V6_VAL(*(addr1)) ? \
  ip6_addr_cmp_zoneless(ip_2_ip6(addr1), ip_2_ip6(addr2)) : \
  ip4_addr_cmp(ip_2_ip4(addr1), ip_2_ip4(addr2))))
/** @ingroup ipaddr */
#define ip_addr_isany(ipaddr)        (((ipaddr) == NULL) ? 1 : ((IpIsV6(ipaddr)) ? \
  ip6_addr_isany(ip_2_ip6(ipaddr)) : \
  ip4_addr_isany(ip_2_ip4(ipaddr))))


/** @ingroup ipaddr */
inline bool ip_addr_isany_val(IpAddr ipaddr)
{
    return ((IpIsV6Val(ipaddr))
                ? ip6_addr_isany_val(*ip_2_ip6(&(ipaddr)))
                : ip4_addr_isany_val(*ip_2_ip4(&(ipaddr))));
}


/** @ingroup ipaddr */
#define ip_addr_isbroadcast(ipaddr, netif) ((IpIsV6(ipaddr)) ? \
  0 : \
  ip4_addr_isbroadcast(ip_2_ip4(ipaddr), netif))
/** @ingroup ipaddr */
#define ip_addr_ismulticast(ipaddr)  ((IpIsV6(ipaddr)) ? \
  ip6_addr_ismulticast(ip_2_ip6(ipaddr)) : \
  ip4_addr_ismulticast(ip_2_ip4(ipaddr)))
/** @ingroup ipaddr */
#define ip_addr_isloopback(ipaddr)  ((IpIsV6(ipaddr)) ? \
  ip6_addr_isloopback(ip_2_ip6(ipaddr)) : \
  ip4_addr_isloopback(ip_2_ip4(ipaddr)))
/** @ingroup ipaddr */
#define ip_addr_islinklocal(ipaddr)  ((IpIsV6(ipaddr)) ? \
  ip6_addr_islinklocal(ip_2_ip6(ipaddr)) : \
  ip4_addr_islinklocal(ip_2_ip4(ipaddr)))
#define ip_addr_debug_print(debug, ipaddr) do { if(IpIsV6(ipaddr)) { \
  ip6_addr_debug_print(debug, ip_2_ip6(ipaddr)); } else { \
  ip4_addr_debug_print(debug, ip_2_ip4(ipaddr)); }}while(0)
#define ip_addr_debug_print_val(debug, ipaddr) do { if(IP_IS_V6_VAL(ipaddr)) { \
  ip6_addr_debug_print_val(debug, *ip_2_ip6(&(ipaddr))); } else { \
  ip4_addr_debug_print_val(debug, *ip_2_ip4(&(ipaddr))); }}while(0)
char *ipaddr_ntoa(const IpAddr *addr);
char* ipaddr_ntoa_r(const IpAddr* addr, char* buf, int buflen);
int ipaddr_aton(const char* cp, IpAddr* addr);

/** @ingroup ipaddr */
// #define IPADDR_STRLEN_MAX   IP6ADDR_STRLEN_MAX

/** @ingroup ipaddr */
#define ip4_2_ipv4_mapped_ipv6(ip6addr, ip4addr) do { \
  (ip6addr)->addr[3] = (ip4addr)->addr; \
  (ip6addr)->addr[2] = PP_HTONL(0x0000FFFFUL); \
  (ip6addr)->addr[1] = 0; \
  (ip6addr)->addr[0] = 0; \
  ip6_addr_clear_zone(ip6addr); } while(0);

/** @ingroup ipaddr */
#define unmap_ipv4_mapped_ipv6(ip4addr, ip6addr) \
  (ip4addr)->addr = (ip6addr)->addr[3];

#define IP46_ADDR_ANY(type) (((type) == IPADDR_TYPE_V6)? IP6_ADDR_ANY : IP4_ADDR_ANY)

// #define IP_ADDR_PCB_VERSION_MATCH(addr, pcb)          1
// #define IP_ADDR_PCB_VERSION_MATCH_EXACT(pcb, ipaddr)  1
//
// #define ip_addr_set_any_val(is_ipv6, ipaddr)          ip_addr_set_any(is_ipv6, &(ipaddr))
// #define ip_addr_set_loopback_val(is_ipv6, ipaddr)     ip_addr_set_loopback(is_ipv6, &(ipaddr))
//
// #define IPADDR4_INIT(u32val)                    { u32val }
// #define IPADDR4_INIT_BYTES(a,b,c,d)             IPADDR4_INIT(PP_HTONL(LWIP_MAKEU32(a,b,c,d)))
// #define IP_IS_V4_VAL(ipaddr)                    1
// #define IP_IS_V6_VAL(ipaddr)                    0
// #define IP_IS_V4(ipaddr)                        1
// #define IP_IS_V6(ipaddr)                        0
// #define IP_IS_ANY_TYPE_VAL(ipaddr)              0
// #define IP_SET_TYPE_VAL(ipaddr, iptype)
// #define IP_SET_TYPE(ipaddr, iptype)
// #define IP_GET_TYPE(ipaddr)                     IPADDR_TYPE_V4
// #define IP_ADDR_RAW_SIZE(ipaddr)                sizeof(Ip4Addr)
// #define IP_ADDR4(ipaddr,a,b,c,d)                Ipv4AddrFromBytes(ipaddr,a,b,c,d)
//
// #define ip_addr_copy(dest, src)                 ip4_addr_copy(dest, src)
// #define ip_addr_copy_from_ip4(dest, src)        ip4_addr_copy(dest, src)
// #define ip_addr_set_ip4_u32(ipaddr, val)        ip4_addr_set_u32(ip_2_ip4(ipaddr), val)
// #define ip_addr_set_ip4_u32_val(ipaddr, val)    ip_addr_set_ip4_u32(&(ipaddr), val)
// #define ip_addr_get_ip4_u32(ipaddr)             ip4_addr_get_u32(ip_2_ip4(ipaddr))
// #define ip_addr_set(dest, src)                  ip4_addr_set(dest, src)
// #define ip_addr_set_ipaddr(dest, src)           ip4_addr_set(dest, src)
// #define ip_addr_set_zero(ipaddr)                ip4_addr_set_zero(ipaddr)
// #define ip_addr_set_zero_ip4(ipaddr)            ip4_addr_set_zero(ipaddr)
// #define ip_addr_set_any(is_ipv6, ipaddr)        ip4_addr_set_any(ipaddr)
// #define ip_addr_set_loopback(is_ipv6, ipaddr)   ip4_addr_set_loopback(ipaddr)
// #define ip_addr_set_hton(dest, src)             ip4_addr_set_hton(dest, src)
// #define ip_addr_get_network(target, host, mask) ip4_addr_get_network(target, host, mask)
// #define ip_addr_netcmp(addr1, addr2, mask)      ip4_addr_netcmp(addr1, addr2, mask)
// #define ip_addr_cmp(addr1, addr2)               ip4_addr_cmp(addr1, addr2)
// #define ip_addr_isany(ipaddr)                   ip4_addr_isany(ipaddr)
// #define ip_addr_isany_val(ipaddr)               ip4_addr_isany_val(ipaddr)
// #define ip_addr_isloopback(ipaddr)              ip4_addr_isloopback(ipaddr)
// #define ip_addr_islinklocal(ipaddr)             ip4_addr_islinklocal(ipaddr)
// #define ip_addr_isbroadcast(addr, netif)        ip4_addr_isbroadcast(addr, netif)
// #define ip_addr_ismulticast(ipaddr)             ip4_addr_ismulticast(ipaddr)
// #define ip_addr_debug_print(debug, ipaddr)      ip4_addr_debug_print(debug, ipaddr)
// #define ip_addr_debug_print_val(debug, ipaddr)  ip4_addr_debug_print_val(debug, ipaddr)
// #define ipaddr_ntoa(ipaddr)                     ip4addr_ntoa(ipaddr)
// #define ipaddr_ntoa_r(ipaddr, buf, buflen)      ip4addr_ntoa_r(ipaddr, buf, buflen)
// #define ipaddr_aton(cp, addr)                   ip4addr_aton(cp, addr)

// #define IPADDR_STRLEN_MAX   IP4ADDR_STRLEN_MAX
//
// #define IP46_ADDR_ANY(type) (IP4_ADDR_ANY)
//
// #define IPADDR6_INIT(a, b, c, d)                { { a, b, c, d } IPADDR6_ZONE_INIT }
// #define IPADDR6_INIT_HOST(a, b, c, d)           { { PP_HTONL(a), PP_HTONL(b), PP_HTONL(c), PP_HTONL(d) } IPADDR6_ZONE_INIT }
// #define IP_IS_V4_VAL(ipaddr)                    0
// #define IP_IS_V6_VAL(ipaddr)                    1
// #define IP_IS_V4(ipaddr)                        0
// #define IP_IS_V6(ipaddr)                        1
// // #define IP_IS_ANY_TYPE_VAL(ipaddr)              0
// #define IP_SET_TYPE_VAL(ipaddr, iptype)
// #define IP_SET_TYPE(ipaddr, iptype)
// #define IP_GET_TYPE(ipaddr)                     IPADDR_TYPE_V6
// #define IP_ADDR_RAW_SIZE(ipaddr)                sizeof(Ip6Addr)
// #define ip_2_ip6(ipaddr)                        (ipaddr)

inline void IP_ADDR6(IpAddr* ipaddr, uint32_t i0, uint32_t i1, uint32_t i2, uint32_t i3)
{
    IP6_ADDR(&ipaddr->u_addr.ip6, i0, i1, i2, i3);
}         

inline void IP_ADDR6_HOST(struct IpAddr* ipaddr, uint32_t i0, uint32_t i1, uint32_t i2, uint32_t i3)
{
    IP_ADDR6(ipaddr, PP_HTONL(i0), PP_HTONL(i1), PP_HTONL(i2), PP_HTONL(i3));
}

// #define ip_addr_copy(dest, src)                 ip6_addr_copy(dest, src)
// #define ip_addr_copy_from_ip6(dest, src)        ip6_addr_copy(dest, src)
// #define ip_addr_copy_from_ip6_packed(dest, src) ip6_addr_copy_from_packed(dest, src)
// #define ip_addr_set(dest, src)                  ip6_addr_set(dest, src)
// #define ip_addr_set_ipaddr(dest, src)           ip6_addr_set(dest, src)
// #define ip_addr_set_zero(ipaddr)                ip6_addr_set_zero(ipaddr)
// #define ip_addr_set_zero_ip6(ipaddr)            ip6_addr_set_zero(ipaddr)
// #define ip_addr_set_any(is_ipv6, ipaddr)        ip6_addr_set_any(ipaddr)
// #define ip_addr_set_loopback(is_ipv6, ipaddr)   ip6_addr_set_loopback(ipaddr)
// #define ip_addr_set_hton(dest, src)             ip6_addr_set_hton(dest, src)
// #define ip_addr_get_network(target, host, mask) ip6_addr_set_zero(target)
// #define ip_addr_netcmp(addr1, addr2, mask)      0
// #define ip_addr_cmp(addr1, addr2)               ip6_addr_cmp(addr1, addr2)
// #define ip_addr_cmp_zoneless(addr1, addr2)      ip6_addr_cmp_zoneless(addr1, addr2)
// #define ip_addr_isany(ipaddr)                   ip6_addr_isany(ipaddr)
// #define ip_addr_isany_val(ipaddr)               ip6_addr_isany_val(ipaddr)
// #define ip_addr_isloopback(ipaddr)              ip6_addr_isloopback(ipaddr)
// #define ip_addr_islinklocal(ipaddr)             ip6_addr_islinklocal(ipaddr)
// #define ip_addr_isbroadcast(addr, netif)        0
// #define ip_addr_ismulticast(ipaddr)             ip6_addr_ismulticast(ipaddr)
// #define ip_addr_debug_print(debug, ipaddr)      ip6_addr_debug_print(debug, ipaddr)
// #define ip_addr_debug_print_val(debug, ipaddr)  ip6_addr_debug_print_val(debug, ipaddr)
// #define ipaddr_ntoa(ipaddr)                     ip6addr_ntoa(ipaddr)
// #define ipaddr_ntoa_r(ipaddr, buf, buflen)      ip6addr_ntoa_r(ipaddr, buf, buflen)
// #define ipaddr_aton(cp, addr)                   ip6addr_aton(cp, addr)
//
// #define IPADDR_STRLEN_MAX   IP6ADDR_STRLEN_MAX
//
// #define IP46_ADDR_ANY(type) (IP6_ADDR_ANY)

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
constexpr auto kIp4AddrAny = (&kIpAddrAny);
/**
 * @ingroup ip4addr
 * Can be used as a fixed/const Ip4Addr
 * for the wildcard and the broadcast address
 */
constexpr auto IP4_ADDR_ANY4 = ((&kIpAddrAny.u_addr.ip4));

/** @ingroup ip4addr */
constexpr auto IP_ADDR_BROADCAST = (&kIpAddrBroadcast);
/** @ingroup ip4addr */
constexpr auto IP4_ADDR_BROADCAST = ((&kIpAddrBroadcast.u_addr.ip4));

    extern const IpAddr ip6_addr_any;

/** 
 * @ingroup ip6addr
 * IP6_ADDR_ANY can be used as a fixed IpAddr
 * for the IPv6 wildcard address
 */
constexpr auto kIp6AddrAny = (&ip6_addr_any);
/**
 * @ingroup ip6addr
 * IP6_ADDR_ANY6 can be used as a fixed Ip6Addr
 * for the IPv6 wildcard address
 */
constexpr auto kIp6AddrAny6 = ((&ip6_addr_any.u_addr.ip6));

// 
constexpr auto kIpAnyType = (&kIpAddrAnyType);


#ifdef __cplusplus
}
#endif
