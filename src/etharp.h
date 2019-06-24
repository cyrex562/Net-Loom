/* ARP has been moved to core/ipv4, provide this #include for compatibility only */
//#include "etharp.h"
//#include "ethernet.h"

#pragma once

#include "opt.h"

#if LWIP_ARP || LWIP_ETHERNET /* don't build if not configured for use in lwipopts.h */

#include "pbuf.h"
#include "ip4_addr.h"
#include "netif.h"
#include "ip4.h"
#include "ethernet.h"
#include "arch.h"

#ifndef ETHARP_HWADDR_LEN
#define ETHARP_HWADDR_LEN     ETH_HWADDR_LEN
#endif

#if LWIP_IPV4 && LWIP_ARP /* don't build if not configured for use in lwipopts.h */

/**
 * struct ip4_addr_wordaligned is used in the definition of the ARP packet format in
 * order to support compilers that don't have structure packing.
 */
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct ip4_addr_wordaligned {
    PACK_STRUCT_FIELD(uint16_t addrw[2]);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "epstruct.h"
#endif

/** MEMCPY-like copying of IP addresses where addresses are known to be
 * 16-bit-aligned if the port is correctly configured (so a port could define
 * this to copying 2 uint16_t's) - no NULL-pointer-checking needed. */
#ifndef IPADDR_WORDALIGNED_COPY_TO_IP4_ADDR_T
#define IPADDR_WORDALIGNED_COPY_TO_IP4_ADDR_T(dest, src) SMEMCPY(dest, src, sizeof(ip4_addr_t))
#endif

 /** MEMCPY-like copying of IP addresses where addresses are known to be
 * 16-bit-aligned if the port is correctly configured (so a port could define
 * this to copying 2 uint16_t's) - no NULL-pointer-checking needed. */
#ifndef IPADDR_WORDALIGNED_COPY_FROM_IP4_ADDR_T
#define IPADDR_WORDALIGNED_COPY_FROM_IP4_ADDR_T(dest, src) SMEMCPY(dest, src, sizeof(ip4_addr_t))
#endif

#ifdef PACK_STRUCT_USE_INCLUDES
#  include "bpstruct.h"
#endif
    PACK_STRUCT_BEGIN
    /** the ARP message, see RFC 826 ("Packet format") */
    struct etharp_hdr {
    PACK_STRUCT_FIELD(uint16_t hwtype);
    PACK_STRUCT_FIELD(uint16_t proto);
    PACK_STRUCT_FLD_8(u8_t  hwlen);
    PACK_STRUCT_FLD_8(u8_t  protolen);
    PACK_STRUCT_FIELD(uint16_t opcode);
    PACK_STRUCT_FLD_S(struct eth_addr shwaddr);
    PACK_STRUCT_FLD_S(struct ip4_addr_wordaligned sipaddr);
    PACK_STRUCT_FLD_S(struct eth_addr dhwaddr);
    PACK_STRUCT_FLD_S(struct ip4_addr_wordaligned dipaddr);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "epstruct.h"
#endif

#define SIZEOF_ETHARP_HDR 28

/* ARP message types (opcodes) */
enum etharp_opcode {
    ARP_REQUEST = 1,
    ARP_REPLY = 2
};

#ifdef __cplusplus
extern "C" {
#endif

    /** 1 seconds period */
#define ARP_TMR_INTERVAL 1000

#if ARP_QUEUEING
/** struct for queueing outgoing packets for unknown address
  * defined here to be accessed by memp.h
  */
    struct etharp_q_entry {
        struct etharp_q_entry* next;
        struct pbuf* p;
    };
#endif /* ARP_QUEUEING */

#define etharp_init() /* Compatibility define, no init needed. */
    void etharp_tmr(void);
    ssize_t etharp_find_addr(struct netif* netif, const ip4_addr_t* ipaddr,
        struct eth_addr** eth_ret, const ip4_addr_t** ip_ret);
    int etharp_get_entry(size_t i, ip4_addr_t** ipaddr, struct netif** netif, struct eth_addr** eth_ret);
    err_t etharp_output(struct netif* netif, struct pbuf* q, const ip4_addr_t* ipaddr);
    err_t etharp_query(struct netif* netif, const ip4_addr_t* ipaddr, struct pbuf* q);
    err_t etharp_request(struct netif* netif, const ip4_addr_t* ipaddr);
    /** For Ethernet network interfaces, we might want to send "gratuitous ARP";
     *  this is an ARP packet sent by a node in order to spontaneously cause other
     *  nodes to update an entry in their ARP cache.
     *  From RFC 3220 "IP Mobility Support for IPv4" section 4.6. */
#define etharp_gratuitous(netif) etharp_request((netif), netif_ip4_addr(netif))
    void etharp_cleanup_netif(struct netif* netif);

#if ETHARP_SUPPORT_STATIC_ENTRIES
    err_t etharp_add_static_entry(const ip4_addr_t* ipaddr, struct eth_addr* ethaddr);
    err_t etharp_remove_static_entry(const ip4_addr_t* ipaddr);
#endif /* ETHARP_SUPPORT_STATIC_ENTRIES */

    void etharp_input(struct pbuf* p, struct netif* netif);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_IPV4 && LWIP_ARP */
#endif /* LWIP_ARP || LWIP_ETHERNET */