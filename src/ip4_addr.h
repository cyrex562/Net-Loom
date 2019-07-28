/**
 * @file
 * IPv4 address API
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
#include <def.h>
#include <string>


/** This is the aligned version of Ip4Addr,
   used as local variable, on the stack, etc. */
struct Ip4Addr
{
    uint32_t addr;
};

struct Ip4AddrInfo
{
    Ip4Addr address;
    Ip4Addr netmask;
    Ip4Addr broadcast_address;
    Ip4Addr network;
    Ip4Addr gateway; // todo: track separately in routing table
};



/* used by IP4_ADDR_ANY and IP_ADDR_BROADCAST in ip_addr.h */
inline Ip4Addr init_ip4_addr_bytes(const uint8_t a,
                                   const uint8_t b,
                                   const uint8_t c,
                                   const uint8_t d)
{
    const Ip4Addr addr = {make_u32(a, b, c, d)};
    return addr;
}


inline void zero_ip4_addr(Ip4Addr* ip)
{
    ip->addr = 0;
}

inline Ip4Addr create_ip4_addr_any()
{
   return {0};
}

inline Ip4Addr ip4_addr_bcast()
{
    return {make_u32(255,255,255,255)};
}

/* Forward declaration to not include netif.h */
struct NetworkInterface;

/** 255.255.255.255 */
inline Ip4Addr ip4_addr_none() {
    return {uint32_t(0xffffffffUL)};
}


//constexpr uint32_t kIpaddrNone = ;
/** 127.0.0.1 */

inline Ip4Addr ip4_addr_loopback() {
    return {uint32_t(0x7f000001UL)};
}

/** 0.0.0.0 */
constexpr uint32_t IP4_ADDR_ANY4 = uint32_t(0x00000000UL);
/** 255.255.255.255 */
constexpr uint32_t IP4_ADDR_BCAST = uint32_t(0xffffffffUL);

/* Definitions of the bits in an Internet address integer.

   On subnets, host and network parts are found according to
   the subnet mask, not these masks.  */
inline bool is_ip4_class_a(const uint32_t a)
{
    return (uint32_t(a) & 0x80000000UL) == 0;
}

constexpr auto IP4_CLASS_A_NET = 0xff000000;
constexpr auto IP4_CLASS_A_NSHIFT = 24;
constexpr auto IP4_CLASS_A_HOST = (0xffffffff & ~IP4_CLASS_A_NET);
constexpr auto IP4_CLASS_A_MAX     =  128;

inline bool IsIp4ClassB(const uint32_t a)
{
    return (uint32_t(a) & 0xc0000000UL) == 0x80000000UL;
}

constexpr auto IP_CLASSB_NET = 0xffff0000;
constexpr auto IP_CLASSB_NSHIFT = 16;
constexpr auto IP_CLASSB_HOST   =   (0xffffffff & ~IP_CLASSB_NET);
constexpr auto IP_CLASSB_MAX   =    65536;

inline bool IP_CLASSC(const uint32_t a) {return       ((((uint32_t)(a)) & 0xe0000000UL) == 0xc0000000UL);}
constexpr auto IP_CLASSC_NET   =    0xffffff00;
constexpr auto IP_CLASSC_NSHIFT  =  8;
constexpr auto IP_CLASSC_HOST   =   (0xffffffff & ~IP_CLASSC_NET);

inline bool IP_CLASSD(const uint32_t a){return        (((uint32_t)(a) & 0xf0000000UL) == 0xe0000000UL);}
constexpr auto IP_CLASSD_NET   =    0xf0000000   ;       /* These ones aren't really */
constexpr auto IP_CLASSD_NSHIFT  =  28    ;              /*   net and host fields, but */
constexpr auto IP_CLASSD_HOST   =   0x0fffffff   ;       /*   routing needn't know. */
inline bool IP_MULTICAST(const uint32_t a){return     IP_CLASSD(a);}

inline bool IP_EXPERIMENTAL(const uint32_t a){ return (((uint32_t)(a) & 0xf0000000UL) == 0xf0000000UL);}
inline bool IP_BADCLASS(const uint32_t a)   {return   (((uint32_t)(a) & 0xf0000000UL) == 0xf0000000UL);}

constexpr auto IP_LOOPBACKNET   =   127;                 /* official! */

/** Set an IP address given by the four byte-parts */
inline void Ipv4AddrFromBytes(Ip4Addr* ipaddr, const uint8_t a, const uint8_t b, const uint8_t c, const uint8_t d) {
    (ipaddr)->addr = pp_htonl(make_u32(a, b, c, d));
}

/** Copy IP address - faster than ip4_addr_set: no NULL check */

/** Safely copy one IP address to another (src may be NULL) */
inline void ip4_addr_set(Ip4Addr& dest, const Ip4Addr& src)
{
    // ((dest).addr = ((src) == nullptr ? 0 : (src).addr));
    dest.addr = src.addr;
}



/** Set complete address to zero */
inline void ip4_addr_set_zero(Ip4Addr& ipaddr)
{
    ipaddr.addr = 0;
}
/** Set address to IPADDR_ANY (no need for lwip_htonl()) */
inline void ip4_addr_set_any(Ip4Addr& ipaddr)
{
    ipaddr.addr = 0;
}



/** Set address to loopback address */
inline void ip4_addr_set_loopback(Ip4Addr& ipaddr)
{
    ((ipaddr).addr = pp_htonl(ip4_addr_loopback().addr));
}


/** Check if an address is in the loopback region */
inline bool ip4_addr_isloopback(const Ip4Addr& ipaddr)
{
    return (ipaddr.addr & pp_htonl(IP4_CLASS_A_NET)) == pp_htonl(
        uint32_t(IP_LOOPBACKNET) << 24);
}


/** Safely copy one IP address to another and change byte order
 * from host- to network-order. */
inline void ip4_addr_set_hton(Ip4Addr& dest, Ip4Addr& src)
{
    dest.addr =  lwip_htonl(src.addr);
}


/** IPv4 only: set the IP address given as an uint32_t */
inline void set_ip4_addr_u32(Ip4Addr& dest_ipaddr, uint32_t src_u32)
{
    ((dest_ipaddr).addr = (src_u32));
}
/** IPv4 only: get the IP address as an uint32_t */
inline uint32_t get_ip4_addr(const Ip4Addr& src_ipaddr)
{
    return ((src_ipaddr).addr);
}

/** Get the network address by combining host address with netmask */
inline Ip4Addr get_ip4_addr_net(const Ip4Addr& host, const Ip4Addr& netmask)
{
    return {host.addr & netmask.addr};

}
/**
 * Determine if two address are on the same network.
 *
 * @arg addr1 IP address 1
 * @arg addr2 IP address 2
 * @arg mask network identifier mask
 * @return !0 if the network identifiers of both address match
 */
inline bool ip4_addr_netcmp(const Ip4Addr& addr1,
                            const Ip4Addr& addr2,
                            const Ip4Addr& mask)
{
    return (((addr1).addr & (mask).addr) == ((addr2).addr & (mask).addr));
}

inline bool ip4_addr_cmp(const Ip4Addr& addr1, const Ip4Addr& addr2)
{
    return addr1.addr == addr2.addr;
}

//
// todo: document
//
inline bool ip4_addr_isany_val(const Ip4Addr addr1)
{
    return addr1.addr == IP4_ADDR_ANY4;
}


inline bool ip4_addr_isany(const Ip4Addr& addr1)
{
    return addr1.addr == IP4_ADDR_ANY4;
}


bool ip4_addr_netmask_valid(uint32_t netmask);

///
///
///
inline bool ip_addr_netmask_valid(Ip4Addr* netmask){return ip4_addr_netmask_valid((netmask)->addr);}

///
///
///
inline bool ip4_addr_ismulticast(const Ip4Addr& addr1)
{
    return (((addr1).addr & pp_htonl(0xf0000000UL)) == pp_htonl(0xe0000000UL));
}

///
///
///
inline bool ip4_addr_islinklocal(const Ip4Addr& addr1)
{
    return (addr1.addr & pp_htonl(0xffff0000UL)) == pp_htonl(0xa9fe0000UL);
}

// #define ip4_addr_debug_print_parts(debug, a, b, c, d) \
//   Logf(debug, ("%d.%d.%d.%" d, a, b, c, d))
// #define ip4_addr_debug_print(debug, ipaddr) \
//   ip4_addr_debug_print_parts(debug, \
//                       (uint16_t)((ipaddr) != NULL ? ip4_addr1_16(ipaddr) : 0),       \
//                       (uint16_t)((ipaddr) != NULL ? ip4_addr2_16(ipaddr) : 0),       \
//                       (uint16_t)((ipaddr) != NULL ? ip4_addr3_16(ipaddr) : 0),       \
//                       (uint16_t)((ipaddr) != NULL ? ip4_addr4_16(ipaddr) : 0))
// #define ip4_addr_debug_print_val(debug, ipaddr) \
//   ip4_addr_debug_print_parts(debug, \
//                       ip4_addr1_16_val(ipaddr),       \
//                       ip4_addr2_16_val(ipaddr),       \
//                       ip4_addr3_16_val(ipaddr),       \
//                       ip4_addr4_16_val(ipaddr))

/* Get one byte from the 4-byte address */
inline uint8_t
ip4_addr_get_byte(const Ip4Addr* ipaddr, const size_t idx)
{
    return reinterpret_cast<const uint8_t*>(&ipaddr->addr)[idx];
}

inline uint8_t
ip4_addr1(const Ip4Addr* ipaddr)
{
    return ip4_addr_get_byte(ipaddr, 0);
}


inline uint8_t
ip4_addr2(const Ip4Addr* ipaddr)
{
    return ip4_addr_get_byte(ipaddr, 1);
}


inline uint8_t
ip4_addr3(const Ip4Addr* ipaddr)
{
    return ip4_addr_get_byte(ipaddr, 2);
}


inline uint8_t
ip4_addr4(const Ip4Addr* ipaddr)
{
    return ip4_addr_get_byte(ipaddr, 3);
}
/* Get one byte from the 4-byte address, but argument is 'Ip4Addr',
 * not a pointer */
// #define ip4_addr_get_byte_val(ipaddr, idx) ((uint8_t)(((ipaddr).addr >> (idx * 8)) & 0xff))
// #define ip4_addr1_val(ipaddr) ip4_addr_get_byte_val(ipaddr, 0)
// #define ip4_addr2_val(ipaddr) ip4_addr_get_byte_val(ipaddr, 1)
// #define ip4_addr3_val(ipaddr) ip4_addr_get_byte_val(ipaddr, 2)
// #define ip4_addr4_val(ipaddr) ip4_addr_get_byte_val(ipaddr, 3)
/* These are cast to uint16_t, with the intent that they are often arguments
 * to printf using the d format from cc.h. */
// #define ip4_addr1_16(ipaddr) ((uint16_t)ip4_addr1(ipaddr))
// #define ip4_addr2_16(ipaddr) ((uint16_t)ip4_addr2(ipaddr))
// #define ip4_addr3_16(ipaddr) ((uint16_t)ip4_addr3(ipaddr))
// #define ip4_addr4_16(ipaddr) ((uint16_t)ip4_addr4(ipaddr))
// #define ip4_addr1_16_val(ipaddr) ((uint16_t)ip4_addr1_val(ipaddr))
// #define ip4_addr2_16_val(ipaddr) ((uint16_t)ip4_addr2_val(ipaddr))
// #define ip4_addr3_16_val(ipaddr) ((uint16_t)ip4_addr3_val(ipaddr))
// #define ip4_addr4_16_val(ipaddr) ((uint16_t)ip4_addr4_val(ipaddr))

constexpr auto IP4ADDR_STRLEN_MAX = 16;

/** For backwards compatibility */
// inline const char* ip_ntoa(Ip4Addr* ipaddr){return  ipaddr_ntoa(ipaddr);}

int32_t lwip_ipaddr_addr(const char *cp);


std::string lwip_ip4addr_ntoa_r(const Ip4Addr& addr, std::string& buf);


bool lwip_ip4addr_aton(std::string& cp, Ip4Addr& addr);


std::string lwip_ip4addr_ntoa(const Ip4Addr& addr);


bool
is_ip4_addr_experimental(Ip4Addr& dst_addr)
{
    // todo: check for membership in a IANA address space reserved for experimentation.
    return false;
}

// END OF FILE