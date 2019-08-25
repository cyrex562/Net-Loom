///
/// file: ip4_addr.h
/// 

#pragma once
#include "def.h"
#include <string>


/// Forward declaration to not include netif.h
struct NetworkInterface;


/// 0.0.0.0
constexpr uint32_t IP4_ADDR_ANY_U32 = uint32_t(0x00000000UL);

/// 255.255.255.255
constexpr uint32_t IP4_ADDR_BCAST_U32 = uint32_t(0xffffffffUL);


constexpr auto IP4_ADDR_NONE_U32 = 0xffffffffUL;


//constexpr uint32_t kIpaddrNone = ;
/** 127.0.0.1 */
constexpr auto IP4_ADDR_LOOPBACK_U32 = 0x7f000001UL;


/// This is the aligned version of Ip4Addr, used as local variable, on the stack, etc.
struct Ip4Addr
{
    uint32_t u32;
};


///
struct Ip4AddrInfo
{
    Ip4Addr address;
    Ip4Addr netmask;
    Ip4Addr broadcast_address;
    Ip4Addr network;
    Ip4Addr gateway; // todo: track separately in routing table
};


/// used by IP4_ADDR_ANY and IP_ADDR_BROADCAST in ip_addr.h
inline Ip4Addr
make_ip4_addr_from_bytes(const uint8_t a,
                         const uint8_t b,
                         const uint8_t c,
                         const uint8_t d)
{
    const Ip4Addr addr = {make_u32(a, b, c, d)};
    return addr;
}


///
///
///
inline bool
is_ip4_addr_any(const Ip4Addr& addr)
{ 
    return addr.u32 == IP4_ADDR_ANY_U32;
}


///
///
///
inline void ip4_addr_zero(Ip4Addr& addr)
{
    addr.u32 = IP4_ADDR_ANY_U32;
}

///
///
///
inline Ip4Addr ip4_addr_create_any()
{
   return {IP4_ADDR_ANY_U32};
}


///
///
///
inline void set_ip4_addr_any(Ip4Addr& addr)
{
    addr.u32 = IP4_ADDR_ANY_U32;
}


///
///
///
inline Ip4Addr make_ip4_addr_bcast()
{
    return {make_u32(255,255,255,255)};
}



/** 255.255.255.255 */
inline Ip4Addr make_ip4_addr_none() {
    return {IP4_ADDR_NONE_U32};
}





inline Ip4Addr make_ip4_addr_loopback() {
    return {IP4_ADDR_LOOPBACK_U32};
}


/* Definitions of the bits in an Internet address integer.

   On subnets, host and network parts are found according to
   the subnet mask, not these masks.  */

constexpr auto IP4_CLASS_A_MASK = 0x80000000UL;
constexpr auto IP4_CLASS_A_NET = 0xff000000;
constexpr auto IP4_CLASS_A_NSHIFT = 24;
constexpr auto IP4_CLASS_A_HOST = (0xffffffff & ~IP4_CLASS_A_NET);
constexpr auto IP4_CLASS_A_MAX     =  128;


inline bool
is_ip4_class_a(const uint32_t a)
{
    return (a & IP4_CLASS_A_MASK) == 0;
}

constexpr auto IP_CLASS_B_MASK = 0xc0000000UL;
constexpr auto IP_CLASS_B_MASK_2 = 0x80000000UL;
constexpr auto IP_CLASSB_NET = 0xffff0000;
constexpr auto IP_CLASSB_NSHIFT = 16;
constexpr auto IP_CLASSB_HOST   =   (0xffffffff & ~IP_CLASSB_NET);
constexpr auto IP_CLASSB_MAX   =    65536;


inline bool
is_ip4_class_b(const uint32_t a)
{
    return (a & IP_CLASS_B_MASK) == IP_CLASS_B_MASK_2;
}

constexpr auto IP_CLASSC_NET   =    0xffffff00;
constexpr auto IP_CLASSC_NSHIFT  =  8;
constexpr auto IP_CLASSC_HOST   =   (0xffffffff & ~IP_CLASSC_NET);
constexpr auto IP4_CLASS_C_MASK = 0xe0000000UL;
constexpr auto IP4_CLASS_C_MASK_2 = 0xc0000000UL;


inline bool
is_ip4_class_c(const uint32_t a)
{
    return (a & IP4_CLASS_C_MASK) == IP4_CLASS_C_MASK_2;
}

constexpr auto IP_CLASSD_NET   =    0xf0000000   ;       /* These ones aren't really */
constexpr auto IP_CLASSD_NSHIFT  =  28    ;              /*   net and host fields, but */
constexpr auto IP_CLASSD_HOST   =   0x0fffffff   ;       /*   routing needn't know. */
constexpr auto IP4_CLASSD_MASK = 0xf0000000UL;
constexpr auto IP4_CLASSD_MASK_2 = 0xe0000000UL;


inline bool
is_ip4_class_d(const uint32_t a)
{
    return (a & IP4_CLASSD_MASK) == IP4_CLASSD_MASK_2;
}


inline bool
is_ip4_multicast(const uint32_t a)
{
    return is_ip4_class_d(a);
}

constexpr auto IP4_EXPERIMENTAL_MASK = 0xf0000000UL;
constexpr auto IP4_EXPERIMENTAL_MASK_2 = 0xf0000000UL;


inline bool
is_ip4_experimental(const uint32_t a)
{
    return (a & IP4_EXPERIMENTAL_MASK) == IP4_EXPERIMENTAL_MASK_2;
}


inline bool
is_ip4_bad_class(const uint32_t a)
{
    return (a & IP4_EXPERIMENTAL_MASK) == IP4_EXPERIMENTAL_MASK_2;
}

constexpr auto IP_LOOPBACKNET   =   127;                 /* official! */

/** Set an IP address given by the four byte-parts */
inline Ip4Addr
ip4_addr_create_hbo(const uint8_t a,
                              const uint8_t b,
                              const uint8_t c,
                              const uint8_t d)
{
    Ip4Addr ipaddr{};
    (ipaddr).u32 = pp_htonl(make_u32(a, b, c, d));
    return ipaddr;
}

inline void copy_ip4_addr(Ip4Addr& dest, const Ip4Addr& src)
{
    // ((dest).addr = ((src) == nullptr ? 0 : (src).addr));
    dest.u32 = src.u32;
}

/// Set address to loopback address
inline void set_ip4_addr_loopback(Ip4Addr& ipaddr)
{
    ((ipaddr).u32 = pp_htonl(make_ip4_addr_loopback().u32));
}


/// Check if an address is in the loopback region 
inline bool is_ip4_addr_loopback(const Ip4Addr& ipaddr)
{
    return (ipaddr.u32 & pp_htonl(IP4_CLASS_A_NET)) == pp_htonl(
        uint32_t(IP_LOOPBACKNET) << 24);
}


/// Safely copy one IP address to another and change byte order from host- to network-order
inline void
set_ip4_addr_hton(Ip4Addr& dest, Ip4Addr& src)
{
    dest.u32 = lwip_htonl(src.u32);
}


/// IPv4 only: set the IP address given as an uint32_t 
inline void set_ip4_addr_u32(Ip4Addr& dest_ipaddr, uint32_t src_u32)
{
    ((dest_ipaddr).u32 = (src_u32));
}



/** IPv4 only: get the IP address as an uint32_t */
inline uint32_t get_ip4_addr_u32(const Ip4Addr& src_ipaddr)
{
    return ((src_ipaddr).u32);
}

/** Get the network address by combining host address with netmask */
inline Ip4Addr get_ip4_addr_net(const Ip4Addr& host, const Ip4Addr& netmask)
{
    return {host.u32 & netmask.u32};

}
/**
 * Determine if two address are on the same network.
 *
 * @arg addr1 IP address 1
 * @arg addr2 IP address 2
 * @arg mask network identifier mask
 * @return !0 if the network identifiers of both address match
 */
inline bool cmp_ip4_addr_net(const Ip4Addr& addr1,
                            const Ip4Addr& addr2,
                            const Ip4Addr& mask)
{
    return (((addr1).u32 & (mask).u32) == ((addr2).u32 & (mask).u32));
}


inline bool is_ip4_addr_equal(const Ip4Addr& addr1, const Ip4Addr& addr2)
{
    return addr1.u32 == addr2.u32;
}


inline bool ip4_addr_isany(const Ip4Addr& addr1)
{
    return addr1.u32 == IP4_ADDR_ANY_U32;
}


bool is_ip4_netmask_valid(uint32_t netmask);

///
///
///
inline bool
is_ip4_addr_netmask_valid_2(Ip4Addr& netmask)
{
    return is_ip4_netmask_valid((netmask).u32);
}

constexpr auto IP4_ADDR_MCAST_MASK_1 = 0xf0000000UL;
constexpr auto IP4_ADDR_MCAST_MASK_2 = 0xe0000000UL;

///
///
///
inline bool
ip4_addr_is_mcast(const Ip4Addr& addr1)
{
    return (((addr1).u32 & pp_htonl(IP4_ADDR_MCAST_MASK_1)) == pp_htonl(
        IP4_ADDR_MCAST_MASK_2));
}


constexpr auto IP4_ADDR_LINK_LOCAL_MASK_1 = 0xffff0000UL;
constexpr auto IP4_ADDR_LINK_LOCAL_MASK_2 = 0xa9fe0000UL;

/**
 *
 */
inline bool
ip4_addr_is_link_local(const Ip4Addr& address)
{
    return (address.u32 & pp_htonl(IP4_ADDR_LINK_LOCAL_MASK_1)) == pp_htonl(
        IP4_ADDR_LINK_LOCAL_MASK_2);
}

/**
 * Get one byte from the 4-byte address
 */
inline uint8_t
get_ip4_addr_byte(const Ip4Addr& ipaddr, const size_t idx)
{
    if (idx == 0)
    {
        return ipaddr.u32 & 0xff000000UL;
    }
    if (idx == 1)
    {
        return ipaddr.u32 & 0x00ff0000UL;
    }
    if (idx == 2)
    {
        return ipaddr.u32 & 0x0000ff00UL;
    }
    if (idx == 3)
    {
        return ipaddr.u32 & 0x000000ffUL;
    }
    else
    {
        return 0;
    }
}

inline uint8_t
ip4_addr1(const Ip4Addr& ipaddr)
{
    return get_ip4_addr_byte(ipaddr, 0);
}


inline uint8_t
ip4_addr2(const Ip4Addr& ipaddr)
{
    return get_ip4_addr_byte(ipaddr, 1);
}


inline uint8_t
ip4_addr3(const Ip4Addr& ipaddr)
{
    return get_ip4_addr_byte(ipaddr, 2);
}


inline uint8_t
ip4_addr4(const Ip4Addr& ipaddr)
{
    return get_ip4_addr_byte(ipaddr, 3);
}

constexpr auto IP4_ADDR_STRLEN_MAX = 16;

std::string ip4_addr_ntoa_r(const Ip4Addr& addr);


bool ip4_addr_aton(std::string& cp, Ip4Addr& addr);


std::string ip4_addr_ntoa(const Ip4Addr& addr);

// END OF FILE