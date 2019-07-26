//
// file: ethernet.h
//

#pragma once
#include <opt.h>
#include <packet_buffer.h>
#include <network_interface.h>
#include <ethernet.h>
#include <cstring>

constexpr auto ETH_ADDR_LEN = 6;

struct EthAddr
{
    uint8_t addr[ETH_ADDR_LEN];
}; 


/// Initialize a struct EthAddr with its 6 bytes (takes care of correct braces)
inline EthAddr make_eth_addr_from_bytes(const uint8_t b0,
                                    const uint8_t b1,
                                    const uint8_t b2,
                                    const uint8_t b3,
                                    const uint8_t b4,
                                    const uint8_t b5)
{
    return {
        b0,
        b1,
        b2,
        b3,
        b4,
        b5
    };
} 

/// Ethernet header
struct EthHdr
{
    struct EthAddr dest;
    struct EthAddr src;
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
inline bool cmp_eth_addr(const EthAddr* addr1, const EthAddr* addr2)
{
    return (memcmp((addr1)->addr, (addr2)->addr, ETH_ADDR_LEN) == 0);
}

///
LwipStatus ethernet_input(struct PacketBuffer* p, struct NetworkInterface* netif);

///
LwipStatus ethernet_output(struct NetworkInterface* netif,
                      struct PacketBuffer* p,
                      const struct EthAddr* src,
                      const struct EthAddr* dst,
                      uint16_t eth_type);

extern const struct EthAddr ETH_BCAST_ADDR;

extern const struct EthAddr ETH_ZERO_ADDR;

//
// end of file
//
