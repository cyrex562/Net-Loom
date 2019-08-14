///
/// file: pcapif.cpp
///
#include <pcapif.h>
#include <opt.h>
#include <def.h>
#include <etharp.h>
#include <ethip6.h>
#include <ip.h>
#include <lwip_debug.h>
#include <packet_buffer.h>
#include <sys.h>
#include <tcpip.h>
#include <timeouts.h>
#include <pcapif_helper.h>
#include <pcap.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <utility>

// // #ifdef _MSC_VER
// // #pragma warning( push, 3 )
// // #include <pcap.h>
// // #pragma warning ( pop )
// // #else
// // /* e.g. mingw */
// // #define _MSC_VER 1500
// // #include <pcap.h>
// // #undef _MSC_VER
// // #endif
//
// // #include <opt.h>
//
// #if LWIP_ETHERNET
//
// #include <pcapif.h>
//
// #include <stdlib.h>
// #include <stdio.h>
//
//
// #include <debug.h>

bool
pcapif_add_tx_packet(PcapIfPrivate& priv, std::vector<uint8_t> buf)
{
    PcapIfPendingPacket new_pkt{};
    new_pkt.data = std::move(buf);
    priv.tx_packets.push_back(new_pkt);
    return true;
}


bool
pcapif_compare_packets(PcapIfPendingPacket& pending_pkt, std::vector<uint8_t>& target_pkt)
{
    if (pending_pkt.data.size() == target_pkt.size()) {
        if (!memcmp(pending_pkt.data.data(),
                    target_pkt.data.data(),
                    pending_pkt.data.size())) {
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
get_adapter_index_from_addr(LwipInAddrStruct& netaddr)
{
    // todo: implement this function
    std::vector<uint8_t> guid;
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE + 1];
    uint_fast32_t index = 0;

    /* Retrieve the interfaces list */
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        return std::make_tuple(false, 0);
    }

    /* Scan the list printing every entry */
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next, index++) {
        for (pcap_addr_t* a = d->addresses; a != nullptr; a = a->next) {
            if (a->addr->sa_family == AF_INET) {
                const ULONG a_addr = ((struct LwipSockaddrSockaddrIn *)a->addr)->sin_addr.s_addr;
                const ULONG a_netmask = ((struct LwipSockaddrSockaddrIn *)a->netmask->sin_addr.s_addr;
                const ULONG a_netaddr = a_addr & a_netmask;
                const ULONG addr = (*netaddr).s_addr;
                if (a_netaddr == addr) {
                    int ret = -1;
                    char name[128];
                    char *start, *end;
                    size_t len = strlen(d->name);
                    if (len > 127) {
                        len = 127;
                    }
                    memcpy(name, d->name, len);
                    name[len] = 0;
                    start = strstr(name, "{");
                    if (start != nullptr) {
                        end = strstr(start, "}");
                        if (end != nullptr) {
                            size_t len = end - start + 1;
                            memcpy(guid, start, len);
                            ret = index;
                        }
                    }
                    pcap_freealldevs(alldevs);
                    return ret;
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


#define PCAP_ERRBUF_SIZE 0xff

static int
get_adapter_index(const char* adapter_guid)
{
    // pcap_if_t* alldevs;
    // pcap_if_t* d;
    // char errbuf[PCAP_ERRBUF_SIZE + 1];
    // int idx = 0; /* Retrieve the interfaces list */
    // if (pcap_findalldevs(&alldevs, errbuf) == -1)
    // {
    //     printf("Error in pcap_findalldevs: %s\n", errbuf);
    //     return -1;
    // } /* Scan the list and compare name vs. adapter_guid */
    // for (d = alldevs; d != nullptr; d = d->next, idx++)
    // {
    //     if (strstr(d->name, adapter_guid))
    //     {
    //         pcap_freealldevs(alldevs);
    //         return idx;
    //     }
    // } /* not found, dump all adapters */
    // printf("%d available adapters:\n", idx);
    // for (d = alldevs, idx = 0; d != nullptr; d = d->next, idx++)
    // {
    //     printf("- %d: %s\n", idx, d->name);
    // }
    // pcap_freealldevs(alldevs);
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
static struct PcapIfPrivate*
pcapif_init_adapter(int adapter_num, uint8_t* arg)
{
    int i;
    int number_of_adapters;
    char errbuf[PCAP_ERRBUF_SIZE + 1];  // NOLINT(cppcoreguidelines-avoid-c-arrays)
    pcap_if_t* alldevs;
    pcap_if_t* d;
    pcap_if_t* used_adapter = nullptr;
    struct PcapIfPrivate* pa = (struct PcapIfPrivate *)malloc(
        sizeof(struct PcapIfPrivate));
    if (!pa)
    {
        printf("Unable to alloc the adapter!\n");
        return nullptr;
    }
    memset(pa, 0, sizeof(struct PcapIfPrivate));
    // pcapif_init_tx_packets(pa);
    // pa->input_fn_arg = arg; /* Retrieve the interfaces list */
    // if (pcap_findalldevs(&alldevs, errbuf) == -1)
    // {
    //     free(pa);
    //     return nullptr; /* no adapters found */
    // } /* get number of adapters and adapter pointer */
    // for (d = alldevs, number_of_adapters = 0; d != nullptr; d = d->next,
    //      number_of_adapters++)
    // {
    //     if (number_of_adapters == adapter_num)
    //     {
    //         // char* desc = d->description;
    //         // size_t len;
    //         // len = strlen(d->name);
    //         // lwip_assert("len < ADAPTER_NAME_LEN", len < ADAPTER_NAME_LEN);
    //         // strcpy(pa->name, d->name);
    //         // used_adapter = d; /* format vendor description */
    //         // if (desc != nullptr)
    //         // {
    //         //     len = strlen(desc);
    //         //     if (strstr(desc, " ' on local host") != nullptr)
    //         //     {
    //         //         len -= 16;
    //         //     }
    //         //     else if (strstr(desc, "' on local host") != nullptr)
    //         //     {
    //         //         len -= 15;
    //         //     }
    //         //     if (strstr(desc, "Network adapter '") == desc)
    //         //     {
    //         //         len -= 17;
    //         //         desc += 17;
    //         //     }
    //         //     len = std::min(len, ADAPTER_DESC_LEN-1);
    //         //     while ((desc[len - 1] == ' ') || (desc[len - 1] == '\t'))
    //         //     {
    //         //         /* don't copy trailing whitespace */
    //         //         len--;
    //         //     }
    //         //     strncpy(pa->description, desc, len);
    //         //     pa->description[len] = 0;
    //         // }
    //         // else
    //         // {
    //         //     strcpy(pa->description, "<no_desc>");
    //         // }
    //     }
    // } /* Scan the list printing every entry */
    // for (d = alldevs, i = 0; d != nullptr; d = d->next, i++)
    // {
    //     char* desc = d->description;
    //     char descBuf[128];
    //     size_t len;
    //     const char* devname = d->name;
    //     if (d->name == nullptr)
    //     {
    //         devname = "<unnamed>";
    //     }
    //     else
    //     {
    //         if (strstr(devname, "\\Device\\") == devname)
    //         {
    //             /* windows: strip the first part */
    //             devname += 8;
    //         }
    //     }
    //     printf("%2i: %s\n", i, devname);
    //     if (desc != nullptr)
    //     {
    //         /* format vendor description */
    //         len = strlen(desc);
    //         if (strstr(desc, " ' on local host") != nullptr)
    //         {
    //             len -= 16;
    //         }
    //         else if (strstr(desc, "' on local host") != nullptr)
    //         {
    //             len -= 15;
    //         }
    //         if (strstr(desc, "Network adapter '") == desc)
    //         {
    //             len -= 17;
    //             desc += 17;
    //         }
    //         len = std::min(len, 127);
    //         while ((desc[len - 1] == ' ') || (desc[len - 1] == '\t'))
    //         {
    //             /* don't copy trailing whitespace */
    //             len--;
    //         }
    //         strncpy(descBuf, desc, len);
    //         descBuf[len] = 0;
    //         printf("     Desc: \"%s\"\n", descBuf);
    //     }
    // } /* invalid adapter index -> check this after printing the adapters */
    // if (adapter_num < 0)
    // {
    //     printf("Invalid adapter_num: %d\n", adapter_num);
    //     free(pa);
    //     pcap_freealldevs(alldevs);
    //     return nullptr;
    // } /* adapter index out of range */
    // if (adapter_num >= number_of_adapters)
    // {
    //     printf("Invalid adapter_num: %d\n", adapter_num);
    //     free(pa);
    //     pcap_freealldevs(alldevs);
    //     return nullptr;
    // } /* set up the selected adapter */
    // lwip_assert("used_adapter != NULL", used_adapter != nullptr); /* Open the device */
    // pa->adapter = pcapif_open_adapter(used_adapter->name, errbuf);
    // if (pa->adapter == nullptr)
    // {
    //     printf("\nUnable to open the adapter. %s is not supported by pcap (\"%s\").\n",
    //            used_adapter->name,
    //            errbuf); /* Free the device list */
    //     pcap_freealldevs(alldevs);
    //     free(pa);
    //     return nullptr;
    // }
    // printf("Using adapter: \"%s\"\n", pa->description);
    // pcap_freealldevs(alldevs);
    // pa->link_state = pcapifh_linkstate_init(pa->name);
    // pa->last_link_event = PCAPIF_LINKEVENT_UNKNOWN;
    return pa;
}

static void
pcapif_check_linkstate(void* netif_ptr)
{
    auto netif = static_cast<NetworkInterface*>(netif_ptr);
    // struct pcapif_private* pa = (struct pcapif_private*)PCAPIF_GET_STATE_PTR(netif);
    struct PcapIfPrivate* pa = nullptr;
    const auto le = pcapifh_linkstate_get(pa->link_state);
    if (pa->last_link_event != le)
    {
        pa->last_link_event = le;
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
    sys_timeout_debug(500, pcapif_check_linkstate, netif, "pcapif_check_linkstate");
} /**
 * Close the adapter (no more packets can be sent or received)
 *
 * @param netif netif to shutdown
 */
void
pcapif_shutdown(NetworkInterface* netif)
{
    // auto pa = (struct pcapif_private*)PCAPIF_GET_STATE_PTR(netif);
    PcapIfPrivate* pa = nullptr;
    // if (pa)
    // {
    //     pa->rx_run = 0;
    //     if (pa->adapter)
    //     {
    //         pcap_breakloop(pa->adapter);
    //         pcap_close(pa->adapter);
    //     } /* wait for rxthread to end */
    //     while (pa->rx_running);
    //     pcapifh_linkstate_close(pa->link_state);
    //     free(pa);
    // }
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


///
/// Low-level initialization: find the correct adapter and initialize it.
///
static bool
pcapif_low_level_init(NetworkInterface& netif, MacAddress& my_mac_addr, int adapter_num)
{
    Ip4Addr netaddr{};
    char guid[GUID_LEN + 1] = {};
    /* If 'state' is != NULL at this point, we assume it is an 'int' giving
           the index of the adapter to use (+ 1 because 0==NULL is invalid).
           This can be used to instantiate multiple PCAP drivers. */
    // PACKET_LIB_GET_ADAPTER_NETADDRESS(&netaddr);
    if (get_adapter_index_from_addr((struct LwipInAddrStruct *)&netaddr, guid, GUID_LEN) <
        0)
    {
        return false;
    }
    adapter_num = get_adapter_index(guid);
    if (adapter_num < 0)
    {
        return false;
    } /* Do whatever else is needed to initialize interface. */
    struct PcapIfPrivate* pa = pcapif_init_adapter(adapter_num, (uint8_t*)netif);
    if (pa == nullptr)
    {
        return false;
    }
    netif.state = pa; /* change the MAC address to a unique value
     so that multiple ethernetifs are supported */
    /* @todo: this does NOT support multiple processes using this adapter! */
    my_mac_addr[ETH_ADDR_LEN - 1] += netif.if_num; /* Copy MAC addr */
    netif.mac_address =
    memcpy(&netif.mac_address, my_mac_addr, ETH_ADDR_LEN);
    /* get the initial link state of the selected interface */
    pcap_if_private.last_link_event = pcapifh_linkstate_get(pcap_if_private.link_state);
    if (pcap_if_private.last_link_event == PCAPIF_LINKEVENT_DOWN)
    {
        set_netif_link_down(netif, interfaces);
    }
    else
    {
        set_netif_link_up(netif, interfaces);
    }
    // sys_timeout_debug(500, pcapif_check_linkstate, netif, "pcapif_check_linkstate");
    pcap_if_private.rx_run = 1;
    pcap_if_private.rx_running = 1;
    // sys_thread_new("pcapif_rxthread", pcapif_input_thread, netif, 0, 0, );
    // Logf(true,
    //      ("pcapif: MacAddress %02X%02X%02X%02X%02X%02X\n", netif->hwaddr[0], netif->hwaddr[1]
    //          , netif->hwaddr[2], netif->hwaddr[3], netif->hwaddr[4], netif->hwaddr[5]));
}

/** low_level_output():
 * Transmit a packet. The packet is contained in the PacketBuffer that is passed to
 * the function. This PacketBuffer might be chained.
 */
static bool
pcapif_low_level_output(NetworkInterface& netif, PacketBuffer& pkt_buf)
{

    unsigned char buffer[ETH_MAX_FRAME_LEN + ETH_PAD_SIZE];
    unsigned char* buf = buffer;
    uint16_t tot_len = pkt_buf->tot_len - ETH_PAD_SIZE;
    // struct pcapif_private* pa = (struct pcapif_private*)PCAPIF_GET_STATE_PTR(netif);
    PcapIfPrivate* pa = nullptr;

    if ((pkt_buf->len == pkt_buf->tot_len) && (pkt_buf->len >= ETH_MIN_FRAME_LEN + ETH_PAD_SIZE))
    {
        /* no PacketBuffer chain, don't have to copy -> faster */
        buf = &((unsigned char*)pkt_buf->payload)[ETH_PAD_SIZE];
    }
    else
    {
        /* PacketBuffer chain, copy into contiguous buffer */
        if (pkt_buf->tot_len >= sizeof(buffer))
        {
            // LINK_STATS_INC(link.lenerr);
            // LINK_STATS_INC(link.drop);
            // MIB2_STATS_NETIF_INC(netif, ifoutdiscards);
            return ERR_BUF;
        }
        unsigned char* ptr = buffer;
        for (struct PacketBuffer* q = pkt_buf; q != nullptr; q = q->next)
        {
            /* Send the data from the PacketBuffer to the interface, one PacketBuffer at a
               time. The size of the data in each PacketBuffer is kept in the ->len
               variable. */ /* send data from(q->payload, q->len); */
            Logf(true,
                 "netif: send ptr %p q->payload %p q->len %i q->next %p\n",
                 ptr,
                 q->payload,
                 (int)q->len,
                 (void*)q->next);
            if (q == pkt_buf)
            {
                memcpy(ptr, &((char*)q->payload)[ETH_PAD_SIZE], q->len - ETH_PAD_SIZE);
                ptr += q->len - ETH_PAD_SIZE;
            }
            else
            {
                memcpy(ptr, q->payload, q->len);
                ptr += q->len;
            }
        }
    }
    if (tot_len < ETH_MIN_FRAME_LEN)
    {
        /* ensure minimal frame length */
        memset(&buf[tot_len], 0, ETH_MIN_FRAME_LEN - tot_len);
        tot_len = ETH_MIN_FRAME_LEN;
    } /* signal that packet should be sent */
    // if (pcap_sendpacket(pa->adapter, buf, tot_len) < 0)
    // {
    //     /* no PacketBuffer chain, don't have to copy -> faster */
    //     buf = &(pkt_buf.data)[ETH_PAD_SIZE];
    // }
    // else
    // {
    //     /* PacketBuffer chain, copy into contiguous buffer */
    //     if (pkt_buf.data.size() >= sizeof(buffer))
    //     {
    //         // LINK_STATS_INC(link.lenerr);
    //         // LINK_STATS_INC(link.drop);
    //         // MIB2_STATS_NETIF_INC(netif, ifoutdiscards);
    //         return ERR_BUF;
    //     }
    //     unsigned char* ptr = buffer;
    //     for (struct PacketBuffer* q = pkt_buf; q != nullptr; q = q->next)
    //     {
    //         /* Send the data from the PacketBuffer to the interface, one PacketBuffer at a
    //            time. The size of the data in each PacketBuffer is kept in the ->len
    //            variable. */ /* send data from(q->payload, q->len); */
    //         Logf(true,
    //              "netif: send ptr %p q->payload %p q->len %i q->next %p\n",
    //              ptr,
    //              q->payload,
    //              (int)q->len,
    //              (void*)q->next);
    //         if (q == pkt_buf)
    //         {
    //             memcpy(ptr, &((char*)q->payload)[ETH_PAD_SIZE], q->len - ETH_PAD_SIZE);
    //             ptr += q->len - ETH_PAD_SIZE;
    //         }
    //         else
    //         {
    //             memcpy(ptr, q->payload, q->len);
    //             ptr += q->len;
    //         }
    //     }
    // }
    // if (tot_len < ETH_MIN_FRAME_LEN)
    // {
    //     /* ensure minimal frame length */
    //     memset(&buf[tot_len], 0, ETH_MIN_FRAME_LEN - tot_len);
    //     tot_len = ETH_MIN_FRAME_LEN;
    // }

    /* signal that packet should be sent */
    if (pcap_sendpacket(pcap_if.adapter, pkt_buf.data.data(), tot_len) < 0)
    {
        return false;
    }

    if (is_netif_link_up(netif))
    {
        pcapif_add_tx_packet(pa, buf);
    }
    struct EthHdr* ethhdr = (struct EthHdr *)pkt_buf->payload;
    if ((ethhdr->dest.addr[0] & 1) != 0)
    {
        /* broadcast or multicast packet*/
    }
    else
    {
        /* unicast packet */
    }
    return true;
}


/** low_level_input(): Allocate a PacketBuffer and transfer the bytes of the incoming
 * packet from the interface into the PacketBuffer.
 */
bool
pcapif_low_level_read(NetworkInterface& netif,
                      const uint8_t* packet,
                      size_t packet_len,
                      PacketBuffer& out_pbuf)
{
    int length = packet_len;
    const struct MacAddress* dest = (const struct MacAddress*)packet;
    const uint8_t bcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    const uint8_t ipv4mcast[] = {0x01, 0x00, 0x5e};
    const uint8_t ipv6mcast[] = {0x33, 0x33};
    if (pcaipf_is_tx_packet(netif, packet,))
    {
        /* don't update counters here! */
        return nullptr;
    }
    int unicast = ((dest->addr[0] & 0x01) == 0);
    /* We allocate a PacketBuffer chain of pbufs from the pool. */
    // struct PacketBuffer* p = pbuf_alloc();
    PacketBuffer p{};
    Logf(true, "netif: recv length %i p->tot_len %i\n", length, (int)p->tot_len);
    if (p != nullptr)
    {
        /* We iterate over the PacketBuffer chain until we have read the entire
           packet into the PacketBuffer. */
        int start = 0;
        for (struct PacketBuffer* q = p; q != nullptr; q = q->next)
        {
            uint16_t copy_len = q->len;
            /* Read enough bytes to fill this PacketBuffer in the chain. The
                               available data in the PacketBuffer is given by the q->len
                               variable. */ /* read data into(q->payload, q->len); */
            Logf(true,
                 "netif: recv start %i length %i q->payload %p q->len %i q->next %p\n",
                 start,
                 length,
                 q->payload,
                 (int)q->len,
                 (void*)q->next);
            if (q == p)
            {
                memcpy(&((char*)q->payload)[ETH_PAD_SIZE],
                       &((const char*)packet)[start],
                       copy_len);
            }
            else
            {
                memcpy(q->payload, &((const char*)packet)[start], copy_len);
            }
            start += copy_len;
            length -= copy_len;
            if (length <= 0)
            {
                break;
            }
        }
        if (unicast)
        {
        }
        else
        {
        }
    }
    else
    {
        /* drop packet */
    }
    return p;
}

// static void
// pcapif_rx_pbuf_free_custom(struct PacketBuffer* p)
// {
//     lwip_assert("NULL pointer", p != nullptr);
//     struct PcapIfPbufCustom* ppc = (struct PcapIfPbufCustom*)p;
//
//     free_pkt_buf(ppc->p);
//     ppc->p = nullptr;
//     delete p;
// }

/**
 *
 */
// PacketBuffer
// pcapif_rx_ref(PacketBuffer& pbuf)
// {
//     // ppc = (struct pcapif_pbuf_custom*)mem_malloc(sizeof(struct pcapif_pbuf_custom));
//     struct PcapIfPbufCustom* ppc = new PcapIfPbufCustom;
//     lwip_assert("out of memory for RX", ppc != nullptr);
//     ppc->pc.custom_free_function = pcapif_rx_pbuf_free_custom;
//     ppc->p = pbuf;
//     // struct PacketBuffer* q = pbuf_alloced_custom(PBUF_RAW,
//     //                                              p->tot_len,
//     //                                              PBUF_REF,
//     //                                              &ppc->pc,
//     //                                              p->payload,
//     //                                              p->tot_len);
//     lwip_assert("pbuf_alloced_custom returned NULL", q != nullptr);
//     return q;
// }


/**
 * pcapif_input: This function is called when a packet is ready to be read
 * from the interface. It uses the function low_level_input() that should
 * handle the actual reception of bytes from the network interface.
 */
bool
pcapif_recv(PcapInterface& pcap_if,
            NetworkInterface& netif,
            const struct pcap_pkthdr* pkt_header,
            const uint8_t* packet)
{
    struct PcapIfPrivate* pa = (struct PcapIfPrivate*)user;
    // int packet_len = pkt_header->caplen;
    NetworkInterface* netif = (NetworkInterface*)pa->input_fn_arg;
    struct PacketBuffer* p;
    // PCAPIF_RX_LOCK_LWIP(); /* move received packet into a new PacketBuffer */
    // p = pcapif_low_level_input(netif, packet, packet_len);
    /* if no packet could be read, silently ignore this */
    if (p != nullptr)
    {
        return false;
    }
    // PCAPIF_RX_UNLOCK_LWIP();
} /**
 * pcapif_init(): initialization function, pass to netif_add().
 */
bool
pcapif_init(NetworkInterface& netif, std::string& name, std::vector<NetworkInterface>& interfaces)
{
    static int ethernetif_index;
    sys_prot_t lev;
    SYS_ARCH_PROTECT(lev);
    int local_index = ethernetif_index++;
    sys_arch_unprotect(lev);
    lwip_assert("pcapif needs an input callback", netif->input != nullptr);
    // netif->name[0] = IFNAME0;
    // netif->name[1] = (char)(IFNAME1 + local_index);
    // todo: set ifname properly
    netif->linkoutput = pcapif_low_level_output;
    netif->output = etharp_output;
    netif->output = nullptr; /* not used for PPPoE */
    netif->output_ip6 = ethip6_output; /* Initialize interface hostname */
    set_netif_hostname(netif, "lwip");
    netif->mtu = 1500;
    netif->flags = NETIF_FLAG_BCAST | NETIF_FLAG_ETH_ARP | NETIF_FLAG_ETH |
        NETIF_FLAG_IGMP;
    netif->flags |= NETIF_FLAG_MLD6;
    netif->hwaddr_len = ETH_ADDR_LEN;
    // NETIF_INIT_SNMP(netif, snmp_ifType_ethernet_csmacd, 100000000);
    /* sets link up or down based on current status */
    pcapif_low_level_init(netif,,);
    return STATUS_SUCCESS;
}

void
pcapif_poll(NetworkInterface* netif)
{
    // struct pcapif_private* pa = (struct pcapif_private*)PCAPIF_GET_STATE_PTR(netif);
    PcapIfPrivate* pa = nullptr;
    int ret;
    do
    {
        if (pa->adapter != nullptr)
        {
            // ret = pcap_dispatch(pa->adapter, -1, pcapif_input, (uint8_t*)pa);
        }
        else
        {
            ret = -1;
        }
        if (ret < 0)
        {
            /* error (e.g. adapter removed or resume from standby), try to reopen the adapter */
            // pcap_reopen_adapter(pa);
        }
    }
    while (ret > 0);
} //
// END OF FILE
//
