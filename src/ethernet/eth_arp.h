#pragma once
#include "ethernet.h"
#include "ip4_addr.h"
#include "network_interface.h"
#include "packet.h"
#include "mac_address.h"
#include <vector>
#include "dhcp_context.h"



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



/** the time an ARP entry stays pending after first request,
 *  for ARP_TMR_INTERVAL = 1000, this is
 *  10 seconds.
 *
 *  @internal Keep this number at least 2, otherwise it might
 *  run out instantly if the timeout occurs directly after a request.
 */
constexpr auto ARP_MAX_PENDING = 5;
using ssize_t = int64_t;

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
    MacAddress shwaddr;
    Ip4Addr sipaddr;
    MacAddress dhwaddr;
    Ip4Addr dipaddr;
};


/**
 * struct for queueing outgoing packets for unknown address
 * defined here to be accessed by memp.h
 */
struct EtharpQEntry
{
    struct EtharpQEntry* next;
    struct PacketContainer* p;
};


struct EtharpEntry
{
    Ip4Addr ip_addr{};
    struct NetworkInterface netif;
    struct MacAddress mac_address{};
    uint64_t ctime{};
    EtharpState state{};
    PacketContainer pkt_buf;
};




inline void etharp_init() {} /* Compatibility define, no init needed. */
bool
clear_expired_arp_entries(std::vector<EtharpEntry>& entries);


std::tuple<bool, size_t, MacAddress, Ip4Addr>
find_etharp_addr(NetworkInterface& net_ifc,
                 const Ip4Addr& ip_addr,
                 std::vector<EtharpEntry>& entries);

std::tuple<bool, NetworkInterface, MacAddress, Ip4Addr>
etharp_get_entry(size_t index, std::vector<EtharpEntry> entries);


bool
etharp_output(NetworkInterface& netif,
              PacketContainer& packet,
              const Ip4AddrInfo& ip_addr_info);


bool
etharp_query(NetworkInterface& netif,
             const Ip4Addr& addr,
             PacketContainer& packet,
             std::vector<EtharpEntry>& entries);


bool
etharp_request(NetworkInterface& netif, const Ip4Addr& ip_addr);


std::tuple<bool, size_t>
etharp_find_entry(const Ip4Addr& ip_addr,
                  const NetworkInterface& netif,
                  std::vector<EtharpEntry>& entries);


/** For Ethernet network interfaces, we might want to send "gratuitous ARP";
 *  this is an ARP packet sent by a node in order to spontaneously cause other
 *  nodes to update an entry in their ARP cache.
 *  From RFC 3220 "IP Mobility Support for IPv4" section 4.6.
 *
 *  @param netif the NetworkInterface to send the message from.
 *  @param dest_addr the index of the IPv4 address to use as the source address.
 *  @return STATUS_OK on success; an error message otherwise.
 */
inline bool
etharp_gratuitous(NetworkInterface& netif, Ip4Addr& dest_addr)
{
    bool ok = true;
    Ip4AddrInfo addr{};
    std::tie(ok, addr) = get_netif_ip4_addr(netif, dest_addr);
    if (!ok)
    {
        return false;
    }

    return etharp_request(netif, addr.address);
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


bool
etharp_add_static_entry(const Ip4Addr& ip_addr,
                        MacAddress& mac_address,
                        std::vector<NetworkInterface>& interfaces,
                        bool static_entry,
                        std::vector<EtharpEntry>& entries);


bool
etharp_remove_static_entry(const Ip4AddrInfo& ip4_addr_info,
                           NetworkInterface& netif,
                           std::vector<EtharpEntry>&
                           entries);


bool
etharp_recv(PacketContainer& pkt_buf, NetworkInterface& netif, DhcpContext& ctx, std::vector<EtharpEntry>& entries);


bool
etharp_request_dst(NetworkInterface& netif,
                   const Ip4Addr& ipaddr,
                   const MacAddress& hw_dst_addr);


bool
send_raw_arp_pkt(NetworkInterface& netif,
                 const MacAddress& ethsrc_addr,
                 const MacAddress& ethdst_addr,
                 const MacAddress& hwsrc_addr,
                 const Ip4Addr& ipsrc_addr,
                 const MacAddress& hwdst_addr,
                 const Ip4Addr& ipdst_addr,
                 const uint16_t opcode);


//
// END OF FILE
//
