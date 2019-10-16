#pragma once
#include <vector>
#include <string>
#include <queue>
#include "pcap.h"
#include "packet.h"


struct PcapInterface
{
    void* input_fn_arg;
    pcap_t* adapter;
    std::string name;
    std::string description;
    bool shutdown_called;
    volatile int rx_run;
    volatile int rx_running;
    struct pcapifh_linkstate* link_state;
    enum PcapIfHlpLinkEvent last_link_event;
    // std::vector<PcapIfPendingPacket> packets;
    // struct PcapIfPendingPacket* tx_packets;
    // struct PcapIfPendingPacket* free_packets;

    std::queue<PacketContainer> tx_queue;
    std::queue<PacketContainer> rx_queue;
};


#pragma once

#include "netloom_status.h"
#include "network_interface.h"
#include "pcap_if.h"
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


std::tuple<bool, PacketContainer>
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


#ifndef WIN32
struct pcapifh_linkstate
{
    uint8_t empty;
};
#else

#include "Packet32.h"

struct pcapifh_linkstate
{
    LPADAPTER lpAdapter;
    PPACKET_OID_DATA ppacket_oid_data;
};
#endif


enum PcapIfHlpLinkEvent
{
    PCAPIF_LINKEVENT_UNKNOWN,
    PCAPIF_LINKEVENT_UP,
    PCAPIF_LINKEVENT_DOWN
};


std::tuple<bool, pcapifh_linkstate>
pcapifh_linkstate_init(std::string& adapter_name);

PcapIfHlpLinkEvent
pcapifh_linkstate_get(pcapifh_linkstate& state);

void
pcapifh_linkstate_close(pcapifh_linkstate& state);


//
// END OF FILE
//

// END OF FILE
