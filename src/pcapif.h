#pragma once

#include <lwip_status.h>
#include <network_interface.h>
#include "pcapif_helper.h"
#include "pcap.h"
// #include "pcap/pcap.h"
/* Define those to better describe your network interface.
   For now, we use 'e0', 'e1', 'e2' and so on */
// #define IFNAME0                       'e'
// #define IFNAME1                       '0'


constexpr auto GUID_LEN = 128;
constexpr auto PCAPIF_LINKCHECK_INTERVAL_MS = 500;
constexpr auto ETH_MIN_FRAME_LEN = 60U;
constexpr auto ETH_MAX_FRAME_LEN = 1518U;
constexpr auto ADAPTER_NAME_LEN = 128;
constexpr auto ADAPTER_DESC_LEN = 128;
constexpr auto PCAPIF_LOOPBACKFILTER_NUM_TX_PACKETS = 128;

/* link state notification macro */

// #define PCAPIF_NOTIFY_LINKSTATE(netif, linkfunc) sys_timeout(PCAPIF_LINKUP_DELAY, (sys_timeout_handler)linkfunc, netif)

constexpr auto ETH_MIN_FRAME_LEN = 60U;
constexpr auto ETH_MAX_FRAME_LEN = 1518U;
constexpr auto ADAPTER_NAME_LEN = 128;
constexpr auto ADAPTER_DESC_LEN = 128;
constexpr auto PCAPIF_LOOPBACKFILTER_NUM_TX_PACKETS = 128;

/* Packet Adapter informations */

/* Define PCAPIF_RX_LOCK_LWIP and PCAPIF_RX_UNLOCK_LWIP if you need to lock the lwIP core
   before/after pbuf_alloc() or netif->input() are called on RX. */

#define PCAPIF_RX_LOCK_LWIP()

#define PCAPIF_RX_UNLOCK_LWIP()


struct PcapIfPendingPacket
{
    // struct PcapIfPendingPacket* next;
    // size_t len;
    std::vector<uint8_t> data;
};

/* Packet Adapter informations */
struct PcapIfPrivate
{
    // void* input_fn_arg;
    pcap_t* adapter;
    std::string name;
    std::string description;
    bool shutdown_called;
    volatile int rx_run;
    volatile int rx_running;
    pcapifh_linkstate link_state;
    pcapifh_link_event last_link_event;
    std::vector<PcapIfPendingPacket> packets;
    std::vector<PcapIfPendingPacket> tx_packets;
    std::vector<PcapIfPendingPacket> free_packets;
};


bool
pcapif_recv(PcapInterface& pcap_if,
            NetworkInterface
            & netif,
            const struct pcap_pkthdr* pkt_header,
            const uint8_t* packet);


LwipStatus
pcapif_init(NetworkInterface* netif);

void
pcapif_shutdown(NetworkInterface* netif);

std::tuple<bool, uint32_t>
get_adapter_index_from_addr(LwipInAddrStruct& netaddr, std::vector<uint8_t>& guid);

bool
pcapif_add_tx_packet(PcapIfPrivate& priv, std::vector<uint8_t> buf);

bool
pcapif_compare_packets(PcapIfPendingPacket& pending_pkt,
                       std::vector<uint8_t>& target_pkt);

bool
pcaipf_is_tx_packet(NetworkInterface& netif,
                    std::vector<uint8_t>& packet,
                    PcapIfPrivate& priv);

//
// END OF FILE
//