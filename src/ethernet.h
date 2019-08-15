//
// file: ethernet.h
//

#pragma once
#include <opt.h>
#include <packet_buffer.h>
#include <network_interface.h>
#include <ethernet.h>
#include <mac_address.h>
#include <cstring>


/// Ethernet header
struct EthHdr
{
    struct MacAddress dest;
    struct MacAddress src;
    uint16_t type;
};

constexpr auto kSizeofEthHdr = (14 + ETH_PAD_SIZE);

/** VLAN header inserted between ethernet header and payload
* if 'type' in ethernet header is ETHTYPE_VLAN.
* See IEEE802.Q */
struct EthVlanHdr
{
    uint16_t prio_vid;
    uint16_t tpid;
};

constexpr auto VLAN_HDR_LEN = 4;

inline uint16_t get_vlan_id(EthVlanHdr* vlan_hdr)
{
    return (lwip_htons((vlan_hdr)->prio_vid) & 0xFFF);
} 

/// The 24-bit IANA IPv4-multicast OUI is 01-00-5e:
constexpr uint8_t LNK_LYR_MCAST_ADDR_OUI[] = {0x01, 0x00, 0x5e};

/// IPv6 multicast uses this prefix
constexpr uint8_t LNK_LYR_IP6_MCAST_ADDR_PREFIX[] = {0x33, 0x33};

///
inline bool cmp_eth_addr(const MacAddress* addr1, const MacAddress* addr2)
{
    return (memcmp((addr1)->bytes, (addr2)->bytes, ETH_ADDR_LEN) == 0);
}

///
LwipStatus ethernet_input(PacketBuffer& pkt_buf, NetworkInterface& net_ifc);

///
LwipStatus send_ethernet_pkt(NetworkInterface& netif,
                           PacketBuffer& p,
                           const MacAddress& src,
                           const MacAddress& dst,
                           uint16_t eth_type);

extern const struct MacAddress ETH_BCAST_ADDR;

extern const struct MacAddress ETH_ZERO_ADDR;

//
// end of file
//
