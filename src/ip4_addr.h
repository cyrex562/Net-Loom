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
#include "def.h"

/** This is the aligned version of Ip4Addr,
   used as local variable, on the stack, etc. */
struct Ip4Addr
{
    uint32_t addr;
};

/* Forward declaration to not include netif.h */
struct NetIfc;

/** 255.255.255.255 */
constexpr uint32_t kIpaddrNone = uint32_t(0xffffffffUL);
/** 127.0.0.1 */
constexpr uint32_t kIpaddrLoopback = uint32_t(0x7f000001UL);
/** 0.0.0.0 */
constexpr uint32_t kIp4AddrAny4 = uint32_t(0x00000000UL);
/** 255.255.255.255 */
constexpr uint32_t kIpaddrBroadcast = uint32_t(0xffffffffUL);

/* Definitions of the bits in an Internet address integer.

   On subnets, host and network parts are found according to
   the subnet mask, not these masks.  */
inline bool IsIp4ClassA(const uint32_t a)
{
    return (uint32_t(a) & 0x80000000UL) == 0;
}

constexpr auto Ip4ClassANet = 0xff000000;
constexpr auto Ip4ClassANShift = 24;
constexpr auto Ip4ClassAHost = (0xffffffff & ~Ip4ClassANet);
constexpr auto Ip4ClassAMax     =  128;

inline bool IsIp4ClassB(const uint32_t a)
{
    return (uint32_t(a) & 0xc0000000UL) == 0x80000000UL;
}

#define IP_CLASSB_NET       0xffff0000
#define IP_CLASSB_NSHIFT    16
#define IP_CLASSB_HOST      (0xffffffff & ~IP_CLASSB_NET)
#define IP_CLASSB_MAX       65536

#define IP_CLASSC(a)        ((((uint32_t)(a)) & 0xe0000000UL) == 0xc0000000UL)
#define IP_CLASSC_NET       0xffffff00
#define IP_CLASSC_NSHIFT    8
#define IP_CLASSC_HOST      (0xffffffff & ~IP_CLASSC_NET)

#define IP_CLASSD(a)        (((uint32_t)(a) & 0xf0000000UL) == 0xe0000000UL)
#define IP_CLASSD_NET       0xf0000000          /* These ones aren't really */
#define IP_CLASSD_NSHIFT    28                  /*   net and host fields, but */
#define IP_CLASSD_HOST      0x0fffffff          /*   routing needn't know. */
#define IP_MULTICAST(a)     IP_CLASSD(a)

#define IP_EXPERIMENTAL(a)  (((uint32_t)(a) & 0xf0000000UL) == 0xf0000000UL)
#define IP_BADCLASS(a)      (((uint32_t)(a) & 0xf0000000UL) == 0xf0000000UL)

#define IP_LOOPBACKNET      127                 /* official! */

/** Set an IP address given by the four byte-parts */
inline void Ipv4AddrFromBytes(Ip4Addr* ipaddr, const uint8_t a, const uint8_t b, const uint8_t c, const uint8_t d) {
    (ipaddr)->addr = PP_HTONL(LwipMakeu32(a, b, c, d));
}

/** Copy IP address - faster than ip4_addr_set: no NULL check */

/** Safely copy one IP address to another (src may be NULL) */
inline void ip4_addr_set(Ip4Addr* dest, Ip4Addr* src)
{
    ((dest)->addr = ((src) == nullptr ? 0 : (src)->addr));
}



/** Set complete address to zero */
inline void ip4_addr_set_zero(Ip4Addr* ipaddr)
{
    ((ipaddr)->addr = 0);
}
/** Set address to IPADDR_ANY (no need for lwip_htonl()) */
inline void ip4_addr_set_any(Ip4Addr* ipaddr)
{
    ((ipaddr)->addr = 0);
}



/** Set address to loopback address */
inline void ip4_addr_set_loopback(Ip4Addr* ipaddr)
{
    ((ipaddr)->addr = PP_HTONL(kIpaddrLoopback));
}


/** Check if an address is in the loopback region */
inline bool ip4_addr_isloopback(Ip4Addr* ipaddr)
{
    return (ipaddr->addr & PP_HTONL(Ip4ClassANet)) == PP_HTONL(
        uint32_t(IP_LOOPBACKNET) << 24);
}


/** Safely copy one IP address to another and change byte order
 * from host- to network-order. */
inline void ip4_addr_set_hton(Ip4Addr* dest, Ip4Addr* src)
{
    ((dest)->addr = ((src) == nullptr ? 0 : lwip_htonl((src)->addr)));
}


/** IPv4 only: set the IP address given as an uint32_t */
inline void SetIp4AddrU32(Ip4Addr* dest_ipaddr, uint32_t src_u32)
{
    ((dest_ipaddr)->addr = (src_u32));
}
/** IPv4 only: get the IP address as an uint32_t */
inline uint32_t ip4_addr_get_u32(const Ip4Addr* src_ipaddr)
{
    return ((src_ipaddr)->addr);
}

/** Get the network address by combining host address with netmask */
inline void ip4_addr_get_network(Ip4Addr* target, Ip4Addr* host, Ip4Addr* netmask)
{
    ((target)->addr = ((host)->addr) & ((netmask)->addr));
}
/**
 * Determine if two address are on the same network.
 *
 * @arg addr1 IP address 1
 * @arg addr2 IP address 2
 * @arg mask network identifier mask
 * @return !0 if the network identifiers of both address match
 */
inline bool ip4_addr_netcmp(const Ip4Addr* addr1, const Ip4Addr* addr2, const Ip4Addr* mask)
{
    return (((addr1)->addr & (mask)->addr) == ((addr2)->addr & (mask)->addr));
}

inline bool ip4_addr_cmp(const Ip4Addr* addr1, const Ip4Addr* addr2)
{
    return ((addr1)->addr == (addr2)->addr);
}

//
// todo: document
//
inline bool ip4_addr_isany_val(const Ip4Addr addr1)
{
    return addr1.addr == kIp4AddrAny4;
}


inline bool ip4_addr_isany(const Ip4Addr* addr1)
{
    return addr1 == nullptr || addr1->addr == kIp4AddrAny4;
}

uint8_t ip4_addr_isbroadcast_u32(uint32_t addr, const struct NetIfc *netif);


inline bool ip4_addr_isbroadcast(Ip4Addr *addr1, NetIfc *netif) {
  return ip4_addr_isbroadcast_u32((addr1)->addr, netif);
}


#define ip_addr_netmask_valid(netmask) ip4_addr_netmask_valid((netmask)->addr)
uint8_t ip4_addr_netmask_valid(uint32_t netmask);

inline bool ip4_addr_ismulticast(Ip4Addr* addr1)
{
    return (((addr1)->addr & PP_HTONL(0xf0000000UL)) == PP_HTONL(0xe0000000UL));
}

inline bool ip4_addr_islinklocal(Ip4Addr* addr1)
{
    return (addr1->addr & PP_HTONL(0xffff0000UL)) == PP_HTONL(0xa9fe0000UL);
}

#define ip4_addr_debug_print_parts(debug, a, b, c, d) \
  Logf(debug, ("%" U16_F ".%" U16_F ".%" U16_F ".%" U16_F, a, b, c, d))
#define ip4_addr_debug_print(debug, ipaddr) \
  ip4_addr_debug_print_parts(debug, \
                      (uint16_t)((ipaddr) != NULL ? ip4_addr1_16(ipaddr) : 0),       \
                      (uint16_t)((ipaddr) != NULL ? ip4_addr2_16(ipaddr) : 0),       \
                      (uint16_t)((ipaddr) != NULL ? ip4_addr3_16(ipaddr) : 0),       \
                      (uint16_t)((ipaddr) != NULL ? ip4_addr4_16(ipaddr) : 0))
#define ip4_addr_debug_print_val(debug, ipaddr) \
  ip4_addr_debug_print_parts(debug, \
                      ip4_addr1_16_val(ipaddr),       \
                      ip4_addr2_16_val(ipaddr),       \
                      ip4_addr3_16_val(ipaddr),       \
                      ip4_addr4_16_val(ipaddr))

/* Get one byte from the 4-byte address */
#define ip4_addr_get_byte(ipaddr, idx) (((const uint8_t*)(&(ipaddr)->addr))[idx])
#define ip4_addr1(ipaddr) ip4_addr_get_byte(ipaddr, 0)
#define ip4_addr2(ipaddr) ip4_addr_get_byte(ipaddr, 1)
#define ip4_addr3(ipaddr) ip4_addr_get_byte(ipaddr, 2)
#define ip4_addr4(ipaddr) ip4_addr_get_byte(ipaddr, 3)
/* Get one byte from the 4-byte address, but argument is 'Ip4Addr',
 * not a pointer */
#define ip4_addr_get_byte_val(ipaddr, idx) ((uint8_t)(((ipaddr).addr >> (idx * 8)) & 0xff))
#define ip4_addr1_val(ipaddr) ip4_addr_get_byte_val(ipaddr, 0)
#define ip4_addr2_val(ipaddr) ip4_addr_get_byte_val(ipaddr, 1)
#define ip4_addr3_val(ipaddr) ip4_addr_get_byte_val(ipaddr, 2)
#define ip4_addr4_val(ipaddr) ip4_addr_get_byte_val(ipaddr, 3)
/* These are cast to uint16_t, with the intent that they are often arguments
 * to printf using the U16_F format from cc.h. */
#define ip4_addr1_16(ipaddr) ((uint16_t)ip4_addr1(ipaddr))
#define ip4_addr2_16(ipaddr) ((uint16_t)ip4_addr2(ipaddr))
#define ip4_addr3_16(ipaddr) ((uint16_t)ip4_addr3(ipaddr))
#define ip4_addr4_16(ipaddr) ((uint16_t)ip4_addr4(ipaddr))
#define ip4_addr1_16_val(ipaddr) ((uint16_t)ip4_addr1_val(ipaddr))
#define ip4_addr2_16_val(ipaddr) ((uint16_t)ip4_addr2_val(ipaddr))
#define ip4_addr3_16_val(ipaddr) ((uint16_t)ip4_addr3_val(ipaddr))
#define ip4_addr4_16_val(ipaddr) ((uint16_t)ip4_addr4_val(ipaddr))

#define IP4ADDR_STRLEN_MAX  16

/** For backwards compatibility */
#define ip_ntoa(ipaddr)  ipaddr_ntoa(ipaddr)

uint32_t ipaddr_addr(const char *cp);
int ip4addr_aton(const char *cp, const Ip4Addr* addr);
/** returns ptr to static buffer; not reentrant! */
char *ip4addr_ntoa(const Ip4Addr *addr);
char *ip4addr_ntoa_r(const Ip4Addr *addr, char *buf, int buflen);

// END OF FILE