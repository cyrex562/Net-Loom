#pragma once

#include <arch.h>
#include <ethernet.h>
#include <ip4_addr.h>
#include <network_interface.h>
#include <packet_buffer.h>
#include <vector>


/** ARP states */
enum EtharpState
{
    ETHARP_STATE_EMPTY = 0,
    ETHARP_STATE_PENDING,
    ETHARP_STATE_STABLE,
    ETHARP_STATE_STABLE_REREQUESTING_1,
    ETHARP_STATE_STABLE_REREQUESTING_2,
    ETHARP_STATE_STATIC
};


/** ARP message types (opcodes) */
enum EtharpOpcode
{
    ARP_REQUEST = 1,
    ARP_REPLY = 2
};

typedef int64_t ssize_t;

constexpr auto SIZEOF_ETHARP_HDR = 28;

/** 1 seconds period */
constexpr auto ARP_TIMER_INTERVAL = 1000;


/** Re-request a used ARP entry 1 minute before it would expire to prevent
 *  breaking a steadily used connection because the ARP entry timed out. */
constexpr auto ARP_AGE_REREQUEST_USED_UNICAST = (ARP_MAXAGE - 30);

constexpr auto ARP_AGE_REREQUEST_USED_BROADCAST = (ARP_MAXAGE - 15);

/** Try hard to create a new entry - we want the IP address to appear in
    the cache (even if this means removing an active entry or so). */
constexpr auto ETHARP_FLAG_TRY_HARD = 1;
constexpr auto ETHARP_FLAG_FIND_ONLY = 2;
constexpr auto ETHARP_FLAG_STATIC_ENTRY = 4;


/**
 * the ARP message, see RFC 826 ("Packet format")
 *
 */
struct EtharpHdr
{
    uint16_t hwtype;

    uint16_t proto;

    uint8_t hwlen;

    uint8_t protolen;

    uint16_t opcode;

    struct MacAddress shwaddr;

    struct Ip4Addr sipaddr;

    struct MacAddress dhwaddr;

    struct Ip4Addr dipaddr;
};


/**
 * struct for queueing outgoing packets for unknown address
 * defined here to be accessed by memp.h
 */
struct EtharpQEntry
{
    struct EtharpQEntry* next;
    struct PacketBuffer* p;
};


struct EtharpEntry
{
    Ip4AddrInfo ip4_addr_info{};
    struct NetworkInterface netif;
    struct MacAddress mac_address{};
    uint64_t ctime{};
    EtharpState state;
    PacketBuffer pkt_buf;
};




inline void etharp_init() {} /* Compatibility define, no init needed. */


void
clear_expired_arp_entries(std::vector<EtharpEntry>& entries);


LwipStatus
find_etharp_addr(NetworkInterface& netif,
                 const Ip4Addr& ipaddr,
                 MacAddress& eth_ret,
                 const Ip4Addr& ip_ret,
                 std::vector<EtharpEntry>& entries,
                 bool try_hard,
                 bool find_only,
                 bool static_entry);


int
etharp_get_entry(size_t i,
                 Ip4Addr** ipaddr,
                 struct NetworkInterface** netif,
                 struct MacAddress** eth_ret);


LwipStatus
etharp_output(struct NetworkInterface* netif,
              struct PacketBuffer* q,
              const Ip4Addr* ipaddr);


LwipStatus
etharp_query(struct NetworkInterface* netif,
             const Ip4Addr* ipaddr,
             struct PacketBuffer* q);


LwipStatus
etharp_request(NetworkInterface& netif, const Ip4AddrInfo& ipaddr);


LwipStatus
etharp_find_entry(const Ip4AddrInfo& ipaddr,
                  const NetworkInterface& netif,
                  std::vector<EtharpEntry>& entries,
                  bool try_hard,
                  bool find_only,
                  bool static_entry,
                  size_t& found_index);


/** For Ethernet network interfaces, we might want to send "gratuitous ARP";
 *  this is an ARP packet sent by a node in order to spontaneously cause other
 *  nodes to update an entry in their ARP cache.
 *  From RFC 3220 "IP Mobility Support for IPv4" section 4.6.
 *
 *  @param netif the NetworkInterface to send the message from.
 *  @param dest_addr the index of the IPv4 address to use as the source address.
 *  @return STATUS_OK on success; an error message otherwise.
 */
inline LwipStatus
etharp_gratuitous(NetworkInterface& netif, Ip4AddrInfo& dest_addr)
{
    Ip4AddrInfo found_addr{};
    if (get_netif_ip4_addr(netif, dest_addr, found_addr) != STATUS_SUCCESS)
    {
        return STATUS_ERROR;
    }

    return etharp_request(netif, found_addr);
}



/**
 * struct ip4_addr_wordaligned is used in the definition of the ARP packet format in
 * order to support compilers that don't have structure packing.
 */

struct Ip4AddrWordaligned
{
    uint16_t addrw[2];
};


/** memcpy-like copying of IP addresses where addresses are known to be
 * 16-bit-aligned if the port is correctly configured (so a port could define
 * this to copying 2 uint16_t's) - no NULL-pointer-checking needed. */
inline bool IpaddrWordalignedCopyToIp4AddrT(Ip4AddrWordaligned* dest, const Ip4Addr* src)
{
    memcpy(dest,src,sizeof(Ip4Addr));
    return true;
}



/** memcpy-like copying of IP addresses where addresses are known to be
* 16-bit-aligned if the port is correctly configured (so a port could define
* this to copying 2 uint16_t's) - no NULL-pointer-checking needed. */
inline void IpaddrWordalignedCopyFromIp4AddrT(IpAddrInfo* dest, const Ip4AddrWordaligned* src)
{
    memcpy(dest,src,sizeof(Ip4Addr));
}

void etharp_cleanup_netif(NetworkInterface& netif, std::vector<EtharpEntry>& entries);

LwipStatus etharp_add_static_entry(const Ip4AddrInfo& ip4_addr_info, MacAddress& mac_address, std::vector<NetworkInterface>&
                                   interfaces,
                                   bool try_hard,
                                   bool static_entry,
                                   bool find_only,
                                   std::vector<EtharpEntry>& entries);
LwipStatus etharp_remove_static_entry(const Ip4AddrInfo& ip4_addr_info, NetworkInterface& netif, std::vector<EtharpEntry>&
                                      entries,
                                      bool try_hard,
                                      bool find_only,
                                      bool static_entry);

void etharp_input(struct PacketBuffer* p, struct NetworkInterface* netif);


