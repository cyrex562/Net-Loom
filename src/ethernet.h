#pragma once
#include "opt.h"
#include "packet_buffer.h"
#include "netif.h"
#include "ethernet.h"
#include <cstring>
#ifdef __cplusplus
extern "C" {
#endif
constexpr auto ETH_HWADDR_LEN = 6; // An Ethernet MAC address
struct EthAddr
{
    uint8_t addr[ETH_HWADDR_LEN];
}; /** Initialize a struct EthAddr with its 6 bytes (takes care of correct braces) */
inline EthAddr MakeEthAddrFromBytes(uint8_t b0,
                                    uint8_t b1,
                                    uint8_t b2,
                                    uint8_t b3,
                                    uint8_t b4,
                                    uint8_t b5)
{
    return {
        b0,
        b1,
        b2,
        b3,
        b4,
        b5
    };
} /** Ethernet header */
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

constexpr auto kSizeofVlanHdr = 4;

inline uint16_t VlanId(EthVlanHdr* vlan_hdr)
{
    return (lwip_htons((vlan_hdr)->prio_vid) & 0xFFF);
} /** The 24-bit IANA IPv4-multicast OUI is 01-00-5e: */
constexpr uint8_t kLLIp4McastAddrOui[] = {0x01, 0x00, 0x5e};
/** IPv6 multicast uses this prefix */
constexpr uint8_t kLLIp6McastAddrPrefix[] = {0x33, 0x33};

inline bool eth_addr_cmp(EthAddr* addr1, EthAddr* addr2)
{
    return (memcmp((addr1)->addr, (addr2)->addr, ETH_HWADDR_LEN) == 0);
}

LwipError ethernet_input(struct PacketBuffer* p, struct NetIfc* netif);
LwipError ethernet_output(struct NetIfc* netif,
                      struct PacketBuffer* p,
                      const struct EthAddr* src,
                      const struct EthAddr* dst,
                      uint16_t eth_type);
extern const struct EthAddr kEthbroadcast;
extern const struct EthAddr kEthzero;
#ifdef __cplusplus
}
#endif
