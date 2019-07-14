/* ARP has been moved to core/ipv4, provide this #include for compatibility only */
//#include "etharp.h"
//#include "ethernet.h"

#pragma once

#include "arch.h"

#include "ethernet.h"

#include "ip4_addr.h"
#include "netif.h"
#include "opt.h"

#include "packet_buffer.h"


/**
 * struct ip4_addr_wordaligned is used in the definition of the ARP packet format in
 * order to support compilers that don't have structure packing.
 */

struct Ip4AddrWordaligned
{
    uint16_t addrw[2];
};


/** MEMCPY-like copying of IP addresses where addresses are known to be
 * 16-bit-aligned if the port is correctly configured (so a port could define
 * this to copying 2 uint16_t's) - no NULL-pointer-checking needed. */
inline bool IpaddrWordalignedCopyToIp4AddrT(Ip4AddrWordaligned* dest, const Ip4Addr* src)
{
    SMEMCPY(dest, src, sizeof(Ip4Addr));
    return true;
}
    


/** MEMCPY-like copying of IP addresses where addresses are known to be
* 16-bit-aligned if the port is correctly configured (so a port could define
* this to copying 2 uint16_t's) - no NULL-pointer-checking needed. */
inline void IpaddrWordalignedCopyFromIp4AddrT(IpAddr* dest, const Ip4AddrWordaligned* src)
{
    SMEMCPY(dest, src, sizeof(Ip4Addr));
}
    
// the ARP message, see RFC 826 ("Packet format")
struct EtharpHdr
{
    uint16_t hwtype;
    uint16_t proto;
    uint8_t hwlen;
    uint8_t protolen;
    uint16_t opcode;
    struct EthAddr shwaddr;
    struct Ip4AddrWordaligned sipaddr;
    struct EthAddr dhwaddr;
    struct Ip4AddrWordaligned dipaddr;
};

constexpr auto kSizeofEtharpHdr = 28;

/* ARP message types (opcodes) */
enum EtharpOpcode
{
    ARP_REQUEST = 1,
    ARP_REPLY = 2
};

#ifdef __cplusplus
extern "C" {
#endif

/** 1 seconds period */
constexpr auto kArpTmrInterval = 1000;

/** struct for queueing outgoing packets for unknown address
  * defined here to be accessed by memp.h
  */
struct EtharpQEntry
{
    struct EtharpQEntry* next;
    struct PacketBuffer* p;
};

typedef int64_t ssize_t;

inline void etharp_init() {} /* Compatibility define, no init needed. */
void etharp_tmr(void);
ssize_t etharp_find_addr(struct NetIfc* netif, const Ip4Addr* ipaddr,
    struct EthAddr** eth_ret, const Ip4Addr** ip_ret);
int etharp_get_entry(size_t i, Ip4Addr** ipaddr, struct NetIfc** netif, struct EthAddr** eth_ret);
LwipError etharp_output(struct NetIfc* netif, struct PacketBuffer* q, const Ip4Addr* ipaddr);
LwipError etharp_query(struct NetIfc* netif, const Ip4Addr* ipaddr, struct PacketBuffer* q);
LwipError etharp_request(struct NetIfc* netif, const Ip4Addr* ipaddr);
/** For Ethernet network interfaces, we might want to send "gratuitous ARP";
 *  this is an ARP packet sent by a node in order to spontaneously cause other
 *  nodes to update an entry in their ARP cache.
 *  From RFC 3220 "IP Mobility Support for IPv4" section 4.6. */
inline LwipError etharp_gratuitous(struct NetIfc* netif)
{
    return etharp_request((netif), netif_ip4_addr(netif));
}

void etharp_cleanup_netif(struct NetIfc* netif);

LwipError etharp_add_static_entry(const Ip4Addr* ipaddr, struct EthAddr* ethaddr);
LwipError etharp_remove_static_entry(const Ip4Addr* ipaddr);

void etharp_input(struct PacketBuffer* p, struct NetIfc* netif);

#ifdef __cplusplus
}
#endif
