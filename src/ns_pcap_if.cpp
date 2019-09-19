/**
 *
 * file: pcapif.cpp
 *
 */
#include "pcapif.h"
#include "ns_config.h"
#include "ns_etharp.h"
#include "ns_ip.h"
#include "ns_debug.h"
#include "ns_packet.h"
#include "ns_sys.h"
#include "ns_pcap_if.h"
#include "pcap.h"
#include <cstdio>
#include <cstring>
#include <utility>




/**
 *
 */
std::tuple<bool, pcapifh_linkstate>
pcapifh_linkstate_init(std::string& adapter_name)
{
    pcapifh_linkstate state{};
    state.ppacket_oid_data = PPACKET_OID_DATA(
        malloc(sizeof(PACKET_OID_DATA) + sizeof(NDIS_MEDIA_STATE)));
    if (state.ppacket_oid_data == nullptr)
    {
        return std::make_tuple(false, state);
    }
    state.lpAdapter = PacketOpenAdapter(PCHAR(adapter_name.c_str()));
    if ((state.lpAdapter == nullptr) || (state.lpAdapter->hFile == INVALID_HANDLE_VALUE))
    {
        /* failed to open adapter */
        return std::make_tuple(false, state);
    }
    return std::make_tuple(true, state);
}


/**
 *
 */
PcapIfHlpLinkEvent
pcapifh_linkstate_get(pcapifh_linkstate& state)
{
    auto ret = PCAPIF_LINKEVENT_UNKNOWN;
    state.ppacket_oid_data->Oid = OID_GEN_MEDIA_CONNECT_STATUS;
    state.ppacket_oid_data->Length = sizeof(NDIS_MEDIA_STATE);
    if (PacketRequest(state.lpAdapter, FALSE, state.ppacket_oid_data) != 0U)
    {
        const auto ndis_media_state = (*PNDIS_MEDIA_STATE(state.ppacket_oid_data->Data));
        if (ndis_media_state == NdisMediaStateConnected)
        {
            ret = PCAPIF_LINKEVENT_UP;
        }
        else
        {
            ret = PCAPIF_LINKEVENT_DOWN;
        }
    }
    return ret;
}


/**
 *
 */
void
pcapifh_linkstate_close(pcapifh_linkstate& state)
{
    if (state.lpAdapter != nullptr)
    {
        PacketCloseAdapter(state.lpAdapter);
    }
    if (state.ppacket_oid_data != nullptr)
    {
        free(state.ppacket_oid_data);
    }
}

#else /* WIN32 */

/* @todo: add linux/unix implementation? */


struct pcapifh_linkstate* pcapifh_linkstate_init(char *adapter_name)
{
  ;
  return NULL;
}

enum pcapifh_link_event pcapifh_linkstate_get(struct pcapifh_linkstate* state)
{
  ;
  return PCAPIF_LINKEVENT_UP;
}
void pcapifh_linkstate_close(struct pcapifh_linkstate* state)
{
  ;
}

#endif /* WIN32 */

/**
 *
 */
bool
pcapif_add_tx_packet(PcapIfPrivate& priv, std::vector<uint8_t> buf)
{
    PcapIfPendingPacket new_pkt{};
    new_pkt.data = std::move(buf);
    priv.tx_packets.push_back(new_pkt);
    return true;
}


/**
 *
 */
bool
pcapif_compare_packets(PcapIfPendingPacket& pending_pkt, std::vector<uint8_t>& target_pkt)
{
    if (pending_pkt.data.size() == target_pkt.size())
    {
        if (!memcmp(pending_pkt.data.data(),
                    target_pkt.data.bytes(),
                    pending_pkt.data.size()))
        {
            return true;
        }
    }
    return false;
}


bool
pcaipf_is_tx_packet(NetworkInterface& netif,
                    std::vector<uint8_t>& packet,
                    PcapIfPrivate& priv)
{
    PcapIfPendingPacket last = priv.tx_packets.at(priv.tx_packets.size() - 1);
    /* compare the first packet */
    if (pcapif_compare_packets(last, packet)) {
        return true;
    }
    for (auto& tx_pkt : priv.tx_packets) {
        if (pcapif_compare_packets(tx_pkt, packet)) {
            return true;
        }
    }
    return false;
}


/** Get the index of an adapter by its network address
*
* @param netaddr network address of the adapter (e.g. 192.168.1.0)
* @return index of the adapter or negative on error
*/
std::tuple<bool, uint32_t>
get_adapter_index_from_addr(sockaddr_in& netaddr)
{
    // todo: implement this function
    std::vector<uint8_t> guid;
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE + 1] = {};
    uint_fast32_t index = 0;

    /* Retrieve the interfaces list */
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        return std::make_tuple(false, 0);
    }

    /* Scan the list printing every entry */
    for (auto d = alldevs; d != nullptr; d = d->next, index++) {
        for (auto a = d->addresses; a != nullptr; a = a->next) {
            if (a->addr->sa_family == AF_INET) {
                const auto a_addr = reinterpret_cast<sockaddr_in*>(a->addr)->sin_addr.s_addr;
                const auto a_netmask = reinterpret_cast<sockaddr_in*>(a->netmask)->sin_addr.s_addr;
                const auto a_netaddr = a_addr & a_netmask;
                const auto addr = netaddr.sin_addr.s_addr;
                if (a_netaddr == addr) {
                    auto ret = -1;
                    // char name[128];
                    // size_t len = strlen(d->name);
                    // if (len > 127) {
                    //     len = 127;
                    // }
                    // memcpy(name, d->name, len);
                    // name[len] = 0;
                    // char* start = strstr(name, "{");
                    // if (start != nullptr) {
                    //     char* end = strstr(start, "}");
                    //     if (end != nullptr) {
                    //         size_t len = end - start + 1;
                    //         memcpy(guid, start, len);
                    //         ret = index;
                    //     }
                    // }
                    // pcap_freealldevs(alldevs);
                    ret = index;
                    return std::make_tuple(true, ret);
                }
            }
        }
    }
    printf("Network address not found.\n");
    pcap_freealldevs(alldevs); // return -1;
    return std::make_tuple(false, 0);
}








/// Get the index of an adapter by its GUID
///
/// @param adapter_guid GUID of the adapter
/// @return index of the adapter or negative on error
///
static int
get_adapter_index(const char* adapter_guid)
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    char errbuf[PCAP_ERRBUF_SIZE + 1];
    int idx = 0; /* Retrieve the interfaces list */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        printf("Error in pcap_findalldevs: %s\n", errbuf);
        return -1;
    } /* Scan the list and compare name vs. adapter_guid */
    for (d = alldevs; d != nullptr; d = d->next, idx++)
    {
        if (strstr(d->name, adapter_guid))
        {
            pcap_freealldevs(alldevs);
            return idx;
        }
    } /* not found, dump all adapters */
    printf("%d available adapters:\n", idx);
    for (d = alldevs, idx = 0; d != nullptr; d = d->next, idx++)
    {
        printf("- %d: %s\n", idx, d->name);
    }
    pcap_freealldevs(alldevs);
    return -1;
}

pcap_t*
pcapif_open_adapter(const char* adapter_name, char* errbuf)
{
    pcap_t* adapter = pcap_open_live(adapter_name,
                                     /* name of the device */
                                     65536,
                                     /* portion of the packet to capture */
                                     /* 65536 guarantees that the whole packet will be captured on all the link layers */
                                     PCAP_OPENFLAG_PROMISCUOUS,
                                     /* promiscuous mode */
                                     /*-*/
                                     1,
                                     /* don't wait at all for lower latency */
                                     errbuf); /* error buffer */
    return adapter;
}



/**
 * Open a network adapter and set it up for packet input
 *
 * @param adapter_num the index of the adapter to use
 * @return an adapter handle on success, NULL on failure
 */
static std::tuple<bool, PcapIfPrivate>
pcapif_init_adapter(uint32_t adapter_num)
{

    uint32_t number_of_adapters = 0;
    char errbuf[PCAP_ERRBUF_SIZE + 1]; // NOLINT(cppcoreguidelines-avoid-c-arrays)
    pcap_if_t* alldevs;
    pcap_if_t* d;
    pcap_if_t* used_adapter = nullptr;
    PcapIfPrivate pa{};
    // pcapif_init_tx_packets(pa);
    // pa->input_fn_arg = arg; /* Retrieve the interfaces list */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        return std::make_tuple(false ,pa);
    }
    /* get number of adapters and adapter pointer */
    for (d = alldevs, number_of_adapters = 0; d != nullptr; d = d->next,
         number_of_adapters++)
    {
        if (number_of_adapters == adapter_num)
        {
            char* desc = d->description;
            size_t len;
            len = strlen(d->name);
            ns_assert("len < ADAPTER_NAME_LEN", len < ADAPTER_NAME_LEN);
            pa.name = d->name;

            used_adapter = d; /* format vendor description */
            if (desc != nullptr)
            {
                len = strlen(desc);
                if (strstr(desc, " ' on local host") != nullptr)
                {
                    len -= 16;
                }
                else if (strstr(desc, "' on local host") != nullptr)
                {
                    len -= 15;
                }
                if (strstr(desc, "Network adapter '") == desc)
                {
                    len -= 17;
                    desc += 17;
                }
                len = std::min(len, size_t(ADAPTER_DESC_LEN - 1));
                while ((desc[len - 1] == ' ') || (desc[len - 1] == '\t'))
                {
                    /* don't copy trailing whitespace */
                    len--;
                }
                pa.description = desc;
            }
            else
            {
                pa.description = "<no description>";

            }
        }
    }

    /* Scan the list printing every entry */
    auto i = 0;
    for (d = alldevs, i = 0; d != nullptr; d = d->next, i++)
    {
        char* desc = d->description;
        char descBuf[128];
        size_t len;
        const char* devname = d->name;
        if (d->name == nullptr)
        {
            devname = "<unnamed>";
        }
        else
        {
            if (strstr(devname, "\\Device\\") == devname)
            {
                /* windows: strip the first part */
                devname += 8;
            }
        }
        printf("%2i: %s\n", i, devname);
        if (desc != nullptr)
        {
            /* format vendor description */
            len = strlen(desc);
            if (strstr(desc, " ' on local host") != nullptr)
            {
                len -= 16;
            }
            else if (strstr(desc, "' on local host") != nullptr)
            {
                len -= 15;
            }
            if (strstr(desc, "Network adapter '") == desc)
            {
                len -= 17;
                desc += 17;
            }
            len = std::min(len, size_t(127));
            while ((desc[len - 1] == ' ') || (desc[len - 1] == '\t'))
            {
                /* don't copy trailing whitespace */
                len--;
            }
            strncpy(descBuf, desc, len);
            descBuf[len] = 0;
            printf("     Desc: \"%s\"\n", descBuf);
        }
    }

    if (adapter_num >= number_of_adapters)
    {
        printf("Invalid adapter_num: %d\n", adapter_num);
        pcap_freealldevs(alldevs);
        return std::make_tuple(false, pa);
    }

    /* set up the selected adapter */
    ns_assert("used_adapter != NULL", used_adapter != nullptr); /* Open the device */
    pa.adapter = pcapif_open_adapter(used_adapter->name, errbuf);
    if (pa.adapter == nullptr)
    {
        printf("\nUnable to open the adapter. %s is not supported by pcap (\"%s\").\n",
               used_adapter->name,
               errbuf); /* Free the device list */
        pcap_freealldevs(alldevs);
        return std::make_tuple(false, pa);
    }
    pcap_freealldevs(alldevs);
    bool ok;
    std::tie(ok, pa.link_state) = pcapifh_linkstate_init(pa.name);
    if (!ok) {
        return std::make_tuple(false, pa);
    }
    pa.last_link_event = PCAPIF_LINKEVENT_UNKNOWN;
    return std::make_tuple(true, pa);
}


/**
 *
 */
bool
pcapif_check_linkstate(NetworkInterface& netif, PcapIfPrivate& pa)
{
    const auto le = pcapifh_linkstate_get(pa.link_state);
    if (pa.last_link_event != le)
    {
        pa.last_link_event = le;
        switch (le)
        {
        case PCAPIF_LINKEVENT_UP:
        {
            // PCAPIF_NOTIFY_LINKSTATE(netif, netif_set_link_up);
            break;
        }
        case PCAPIF_LINKEVENT_DOWN:
        {
            // PCAPIF_NOTIFY_LINKSTATE(netif, netif_set_link_down);
            break;
        }
        case PCAPIF_LINKEVENT_UNKNOWN: /* fall through */ default:
            break;
        }
    }
    // todo: pcap check link state asynchronous
    //sys_timeout_debug(500, pcapif_check_linkstate, netif, "pcapif_check_linkstate");
    return true;
}


/**
 * Close the adapter (no more packets can be sent or received)
 *
 * @param netif netif to shutdown
 * @param pa
 */
bool
pcapif_shutdown(NetworkInterface& netif, PcapIfPrivate& pa)
{
    pa.rx_run = 0;
    if (pa.adapter) {
        pcap_breakloop(pa.adapter);
        pcap_close(pa.adapter);
    }
    /* wait for rxthread to end */
    while (pa.rx_running);
    pcapifh_linkstate_close(pa.link_state);
    return true;
}


///
/// RX running in its own thread
///
static void
pcapif_input_thread(uint8_t* arg)
{
    // auto netif = reinterpret_cast<NetworkInterface*>(arg);
    // // struct pcapif_private* pa = (struct pcapif_private*)PCAPIF_GET_STATE_PTR(netif);
    // struct pcapif_private* pa = nullptr;
    // do
    // {
    //     struct pcap_pkthdr pkt_header;
    //     const uint8_t* packet = pcap_next(pa->adapter, &pkt_header);
    //     if (packet != nullptr)
    //     {
    //         pcapif_input((uint8_t*)pa, &pkt_header, packet);
    //     }
    // }
    // while (pa->rx_run);
    // pa->rx_running = 0;
}


/**
 * Low-level initialization: find the correct adapter and initialize it.
 */
std::tuple<bool, PcapIfPrivate>
pcapif_low_level_init(NetworkInterface& netif,
                      MacAddress& my_mac_addr,
                      int adapter_num,
                      sockaddr_in& netaddr,
                      std::vector<NetworkInterface>& interfaces)
{
    PcapIfPrivate pa{};
    char guid[GUID_LEN + 1] = {};
    /* If 'state' is != NULL at this point, we assume it is an 'int' giving
           the index of the adapter to use (+ 1 because 0==NULL is invalid).
           This can be used to instantiate multiple PCAP drivers. */
    // PACKET_LIB_GET_ADAPTER_NETADDRESS(&netaddr);

    bool ok;
    uint32_t adapter_index;

    std::tie(ok, adapter_index) = get_adapter_index_from_addr(netaddr);
    if (!ok) { return std::make_tuple(false, pa); }

    adapter_num = get_adapter_index(guid);
    if (adapter_num < 0) { return std::make_tuple(false, pa); }

    /* Do whatever else is needed to initialize interface. */
    std::tie(ok, pa) = pcapif_init_adapter(adapter_num);
    if (!ok) { return std::make_tuple(false, pa); }

    // netif.state = pa; /* change the MAC address to a unique value
    //  so that multiple ethernetifs are supported */
    /* @todo: this does NOT support multiple processes using this adapter! */
    my_mac_addr.bytes[MAC_ADDR_LEN - 1] += netif.number; /* Copy MAC addr */
    memcpy(&netif.mac_address, &my_mac_addr, MAC_ADDR_LEN);
    /* get the initial link state of the selected interface */
    pa.last_link_event = pcapifh_linkstate_get(pa.link_state);
    if (pa.last_link_event == PCAPIF_LINKEVENT_DOWN)
    {
        set_netif_link_down(netif, interfaces);
    }
    else
    {
        set_netif_link_up(netif, interfaces);
    }
    // sys_timeout_debug(500, pcapif_check_linkstate, netif, "pcapif_check_linkstate");
    pa.rx_run = 1;
    pa.rx_running = 1;
    // sys_thread_new("pcapif_rxthread", pcapif_input_thread, netif, 0, 0, );
    return std::make_tuple(true, pa);
}

/** low_level_output():
 * Transmit a packet. The packet is contained in the PacketBuffer that is passed to
 * the function. This PacketBuffer might be chained.
 */
bool
pcapif_low_level_output(NetworkInterface& netif, PacketContainer& pkt_buf)
{
    // char buffer[ETH_MAX_FRAME_LEN + ETH_PAD_SIZE];
    // uint8_t* buf = buffer;
    std::vector<uint8_t> buffer;
    uint16_t tot_len = pkt_buf.data.size() - ETH_PAD_SIZE;
    // struct pcapif_private* pa = (struct pcapif_private*)PCAPIF_GET_STATE_PTR(netif);
    PcapIfPrivate pa{};

    /* signal that packet should be sent */
    if (pcap_sendpacket(pa.adapter, pkt_buf.data.data(), tot_len) < 0)
    {
        return false;
    }

    if (is_netif_link_up(netif))
    {
        pcapif_add_tx_packet(pa, pkt_buf.data);
    }
    EthHdr* ethhdr = reinterpret_cast<EthHdr *>(pkt_buf.data.data());
    if ((ethhdr->dest.bytes[0] & 1) != 0)
    {
        /* broadcast or multicast packet*/
    }
    else
    {
        /* unicast packet */
    }
    return true;
}


/**
 * Allocate a PacketBuffer and transfer the bytes of the incoming packet from the
 * interface into the PacketBuffer.
 */
std::tuple<bool, PacketContainer>
pcapif_low_level_recv(NetworkInterface& netif,
                      const uint8_t* packet,
                      size_t packet_len,
                      PcapIfPrivate& pcap_if_priv)
{
    size_t length = packet_len;
    EthHdr* eth_hdr = (EthHdr*)packet;
    MacAddress dest = eth_hdr->dest;
    PacketContainer pkt_buf{};

    for (size_t i = 0; i < packet_len; i++) {
        pkt_buf.data.push_back(packet[i]);
    }

    const uint8_t bcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    const uint8_t ipv4mcast[] = {0x01, 0x00, 0x5e};
    const uint8_t ipv6mcast[] = {0x33, 0x33};
    if (pcaipf_is_tx_packet(netif, pkt_buf.data, pcap_if_priv))
    {
        /* don't update counters here! */
        return std::make_tuple(false, pkt_buf);
    }
    const auto unicast = ((dest.bytes[0] & 0x01) == 0);
    if (unicast) { } // todo: additional actions on unicast packet
    else { } // todo: additional actions on non-unicast packet
    return std::make_tuple(true, pkt_buf);
}


/**
 * This function is called when a packet is ready to be read from the interface. It
 * uses the function low_level_input() that should handle the actual reception of bytes
 * from the network interface.
 */
std::tuple<bool, PacketContainer>
pcapif_recv(NetworkInterface& netif,
            const struct pcap_pkthdr* pkt_header,
            const uint8_t* packet,
            PcapIfPrivate& pa)
{
    bool ok;
    PacketContainer pkt_buf{};
    std::tie(ok, pkt_buf) = pcapif_low_level_recv(netif, packet, pkt_header->caplen, pa);
    return std::make_tuple(ok, pkt_buf);
}


/**
 * pcapif_init(): initialization function, pass to netif_add().
 */
std::tuple<bool, PcapIfPrivate>
pcapif_init(NetworkInterface& netif,
            std::string& name,
            std::vector<NetworkInterface>& interfaces,
            size_t ipv4_addr_index)
{
    static int ethernetif_index;
    auto local_index = ethernetif_index++;
    netif.name = name;
    // netif.linkoutput = pcapif_low_level_output;
    // netif.output = etharp_output;
    // netif.output = nullptr; /* not used for PPPoE */
    // netif.output_ip6 = ethip6_output; /* Initialize interface hostname */
    // set_netif_hostname(netif, "ns");
    netif.hostname = "ns";
    netif.mtu = 1500;
    netif.flags.broadcast = true;
    netif.flags.eth_arp = true;
    netif.flags.ethernet = true;
    netif.flags.igmp = true;
    netif.flags.mld6 = true; /* sets link up or down based on current status */
    sockaddr_in net_addr{};
    net_addr.sin_addr.S_un.S_addr = netif.ip4_addresses[ipv4_addr_index].address.u32;
    bool ok;
    PcapIfPrivate pa{};
    std::tie(ok, pa) = pcapif_low_level_init(netif, netif.mac_address, local_index, net_addr, interfaces);
    return std::make_tuple(ok, pa);
}


bool
pcapif_poll(NetworkInterface& netif, PcapIfPrivate& pa)
{
    // todo: re-write
    // int ret;
    // do
    // {
    //     if (pa->adapter != nullptr)
    //     {
    //         ret = pcap_dispatch(pa->adapter, -1, pcapif_input, (uint8_t*)&pa);
    //     }
    //     else
    //     {
    //         ret = -1;
    //     }
    //     if (ret < 0)
    //     {
    //         /* error (e.g. adapter removed or resume from standby), try to reopen the adapter */
    //         // pcap_reopen_adapter(pa);
    //     }
    // }
    // while (ret > 0);
}


//
// END OF FILE
//
