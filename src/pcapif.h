#pragma once

#include <lwip_status.h>
#include <network_interface.h>
#include <pcap.h>

// #include "pcap/pcap.h"
/* Define those to better describe your network interface.
   For now, we use 'e0', 'e1', 'e2' and so on */
#define IFNAME0                       'e'
#define IFNAME1                       '0'




constexpr auto PCAPIF_LINKCHECK_INTERVAL_MS = 500;

/* link state notification macro */

#define PCAPIF_NOTIFY_LINKSTATE(netif, linkfunc) sys_timeout(PCAPIF_LINKUP_DELAY, (sys_timeout_handler)linkfunc, netif)

constexpr auto ETH_MIN_FRAME_LEN = 60U;
constexpr auto ETH_MAX_FRAME_LEN = 1518U;
constexpr auto ADAPTER_NAME_LEN = 128;
constexpr auto ADAPTER_DESC_LEN = 128;
constexpr auto PCAPIF_LOOPBACKFILTER_NUM_TX_PACKETS = 128;

/* Packet Adapter informations */



struct PcapIfPbufCustom
{
   // struct pbuf_custom pc;
   struct PacketBuffer p;
};


bool pcapif_low_level_init(NetworkInterface& netif, std::vector<NetworkInterface>& interfaces);


bool
pcapif_init(NetworkInterface& netif, std::string& name, std::vector<NetworkInterface>& interfaces);
void  pcapif_shutdown(NetworkInterface*netif);

constexpr auto GUID_LEN = 128;


bool
pcapif_add_tx_packet(PcapInterface& priv, PacketBuffer& pkt_buf);


bool
pcapif_low_level_read(NetworkInterface& netif,
                      const uint8_t* packet,
                      size_t packet_len,
                      PacketBuffer& out_pbuf);


bool
pcapif_recv(PcapInterface& pcap_if,
            NetworkInterface
            & netif,
            const struct pcap_pkthdr* pkt_header,
            const uint8_t* packet);


pcap_t*
pcapif_open_adapter(const char* adapter_name, char* errbuf);


//
// END OF FILE
//