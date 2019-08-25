#pragma once

#include "lwip_status.h"
#include "network_interface.h"
#include "pcapif_helper.h"
#include "pcap.h"

constexpr auto GUID_LEN = 128;
constexpr auto PCAPIF_LINKCHECK_INTERVAL_MS = 500;
constexpr auto ETH_MIN_FRAME_LEN = 60U;
constexpr auto ETH_MAX_FRAME_LEN = 1518U;
constexpr auto ADAPTER_NAME_LEN = 128;
constexpr auto ADAPTER_DESC_LEN = 128;
constexpr auto PCAPIF_LOOPBACKFILTER_NUM_TX_PACKETS = 128;


struct PcapIfPendingPacket
{
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
    PcapIfHlpLinkEvent last_link_event;
    std::vector<PcapIfPendingPacket> packets;
    std::vector<PcapIfPendingPacket> tx_packets;
    std::vector<PcapIfPendingPacket> free_packets;
};


std::tuple<bool, PacketBuffer>
pcapif_recv(NetworkInterface
            & netif,
            const struct pcap_pkthdr* pkt_header,
            const uint8_t* packet,
            PcapIfPrivate& pa);

std::tuple<bool, PcapIfPrivate>
pcapif_init(NetworkInterface& netif,
            std::string& name,
            std::vector<NetworkInterface>& interfaces,
            size_t ipv4_addr_index);

bool
pcapif_shutdown(NetworkInterface& netif, PcapIfPrivate& pa);

std::tuple<bool, uint32_t>

/**
 *
 */
get_adapter_index_from_addr(sockaddr_in& netaddr);

bool
pcapif_add_tx_packet(PcapIfPrivate& priv, std::vector<uint8_t> buf);

bool
pcapif_compare_packets(PcapIfPendingPacket& pending_pkt,
                       std::vector<uint8_t>& target_pkt);

bool
pcaipf_is_tx_packet(NetworkInterface& netif,
                    std::vector<uint8_t>& packet,
                    PcapIfPrivate& priv);

bool
pcapif_check_linkstate(NetworkInterface& netif, PcapIfPrivate& pa);


std::tuple<bool, PcapIfPrivate>
pcapif_low_level_init(NetworkInterface& netif,
                      MacAddress& my_mac_addr,
                      int adapter_num,
                      sockaddr_in& netaddr,
                      std::vector<NetworkInterface>& interfaces);



//
// END OF FILE
//