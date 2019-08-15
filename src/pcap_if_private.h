#pragma once
#include <vector>
#include <string>
#include <queue>
#include <pcap.h>


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

    std::queue<PacketBuffer> tx_queue;
    std::queue<PacketBuffer> rx_queue;
};

// END OF FILE
