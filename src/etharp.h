/* ARP has been moved to core/ipv4, provide this #include for compatibility only */
//#include "etharp.h"
//#include "ethernet.h"

#pragma once

#include "opt.h"
#include "PacketBuffer.h"
#include "ip4_addr.h"
#include "netif.h"
#include "ip4.h"
#include "ethernet.h"
#include "arch.h"

/**
 * struct ip4_addr_wordaligned is used in the definition of the ARP packet format in
 * order to support compilers that don't have structure packing.
 */

struct ip4_addr_wordaligned
{
    uint16_t addrw[2];
};


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


/** the ARP message, see RFC 826 ("Packet format") */
struct etharp_hdr
{
    uint16_t hwtype;
    uint16_t proto;
    uint8_t hwlen;
    uint8_t protolen;
    uint16_t opcode;
    struct EthernetAddress shwaddr;
    struct ip4_addr_wordaligned sipaddr;
    struct EthernetAddress dhwaddr;
    struct ip4_addr_wordaligned dipaddr;
};


#define SIZEOF_ETHARP_HDR 28

/* ARP message types (opcodes) */
enum etharp_opcode
{
    ARP_REQUEST = 1,
    ARP_REPLY = 2
};

#ifdef __cplusplus
extern "C" {
#endif

/** 1 seconds period */
#define ARP_TMR_INTERVAL 1000


/** struct for queueing outgoing packets for unknown address
  * defined here to be accessed by memp.h
  */
    struct etharp_q_entry {
        struct etharp_q_entry* next;
        struct PacketBuffer* p;
    };


typedef int64_t ssize_t;

#define etharp_init() /* Compatibility define, no init needed. */
void etharp_tmr(void);
ssize_t etharp_find_addr(struct netif* netif,
                         const LwipIpv4Addr* ipaddr,
                         struct EthernetAddress** eth_ret,
                         const LwipIpv4Addr** ip_ret);
int etharp_get_entry(size_t i, LwipIpv4Addr** ipaddr, struct netif** netif, struct EthernetAddress** eth_ret);
LwipError etharp_output(struct netif* netif, struct PacketBuffer* q, const LwipIpv4Addr* ipaddr);
LwipError etharp_query(struct netif* netif, const LwipIpv4Addr* ipaddr, struct PacketBuffer* q);
LwipError etharp_request(struct netif* netif, const LwipIpv4Addr* ipaddr);
/** For Ethernet network interfaces, we might want to send "gratuitous ARP";
 *  this is an ARP packet sent by a node in order to spontaneously cause other
 *  nodes to update an entry in their ARP cache.
 *  From RFC 3220 "IP Mobility Support for IPv4" section 4.6. */
#define etharp_gratuitous(netif) etharp_request((netif), netif_ip4_addr(netif))
void etharp_cleanup_netif(struct netif* netif);

#if ETHARP_SUPPORT_STATIC_ENTRIES
    LwipError etharp_add_static_entry(const ip4_addr_t* ipaddr, struct EthernetAddress* ethaddr);
    LwipError etharp_remove_static_entry(const ip4_addr_t* ipaddr);
#endif /* ETHARP_SUPPORT_STATIC_ENTRIES */

void etharp_input(struct PacketBuffer* p, struct netif* netif);

#ifdef __cplusplus
}
#endif

