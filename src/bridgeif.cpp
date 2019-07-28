#include <bridgeif.h>
#include <etharp.h>
#include <lwip_debug.h>
#include <lwipopts.h>
#include <network_interface.h>
#include <cstring>
#include <ethip6.h>
#include <lwip_status.h>
#include <tcpip.h>
#include <packet_buffer.h>

constexpr char BRIDGE_IFC_NAME[] = { 'b', 'r' };

// struct bridgeif_private_s;


/* netif data index to get the bridge on input */
uint8_t bridgeif_netif_client_id = 0xff;

/**
 * @ingroup bridgeif
 * Add a static entry to the forwarding database.
 * A static entry marks where frames to a specific eth address (unicast or group address) are
 * forwarded.
 * bits [0..(BRIDGEIF_MAX_PORTS-1)]: hw ports
 * bit [BRIDGEIF_MAX_PORTS]: cpu port
 * 0: drop
 */
LwipStatus bridgeif_fdb_add(NetworkInterface* bridgeif,
                           const struct MacAddress* addr,
                           const BridgeIfcPortMask ports)
{
    lwip_assert("invalid netif", bridgeif != nullptr);
    const auto br = static_cast<BridgeIfcPrivate *>(bridgeif->state);
    lwip_assert("invalid state", br != nullptr);
    for (auto i = 0; i < br->max_fdbs_entries; i++)
    {
        if (!br->fdbs[i].used)
        {
            if (!br->fdbs[i].used)
            {
                br->fdbs[i].used = 1;
                br->fdbs[i].dst_ports = ports;
                memcpy(&br->fdbs[i].addr, addr, sizeof(struct MacAddress));
                return ERR_OK;
            }
        }
    }
    return ERR_MEM;
}


///
/// Remove a static entry from the forwarding database
///
LwipStatus remove_bridgeif_fdb(NetworkInterface* bridgeif, const struct MacAddress* addr)
{
    lwip_assert("invalid netif", bridgeif != nullptr);
    const auto br = static_cast<BridgeIfcPrivate *>(bridgeif->state);
    lwip_assert("invalid state", br != nullptr);
    for (auto i = 0; i < br->max_fdbs_entries; i++)
    {
        if (br->fdbs[i].used && !memcmp(&br->fdbs[i].addr, addr, sizeof(struct MacAddress)))
        {
            if (br->fdbs[i].used && !memcmp(&br->fdbs[i].addr,
                                            addr,
                                            sizeof(struct MacAddress)))
            {
                memset(&br->fdbs[i], 0, sizeof(BridgeIfcFdbStaticEntry));
                return ERR_OK;
            }
        }
    }
    return ERR_VAL;
}

/// Get the forwarding port(s) (as bit mask) for the specified destination mac address
static BridgeIfcPortMask bridgeif_find_dst_ports(BridgeIfcPrivate* br,
                                                 struct MacAddress* dst_addr)
{
    /* first check for static entries */
    for (auto i = 0; i < br->max_fdbs_entries; i++)
    {
        if (br->fdbs[i].used)
        {
            if (!memcmp(&br->fdbs[i].addr, dst_addr, sizeof(struct MacAddress)))
            {
                const auto ret = br->fdbs[i].dst_ports;
                return ret;
            }
        }
    }
    if (dst_addr->addr[0] & 1)
    {
        /* no match found: flood remaining group address */
        return BRIDGE_FLOOD;
    } /* no match found: check dynamic fdb for port or fall back to flooding */
    return bridgeif_fdb_get_dst_ports(br->fdbd, dst_addr);
}

/// 
/// Helper function to see if a destination mac belongs to the bridge
/// (bridge netif or one of the port netifs), in which case the frame
/// is sent to the cpu only.
///
static int bridgeif_is_local_mac(BridgeIfcPrivate* br, struct MacAddress* addr)
{
    if (!memcmp(br->netif->hwaddr, addr, sizeof(struct MacAddress)))
    {
        return 1;
    }
    for (auto i = 0; i < br->num_ports; i++)
    {
        auto portif = br->ports[i].port_netif;
        if (portif != nullptr)
        {
            if (!memcmp(portif->hwaddr, addr, sizeof(struct MacAddress)))
            {
                return 1;
            }
        }
    }
    return 0;
}

/* Output helper function */
static LwipStatus bridgeif_send_to_port(BridgeIfcPrivate* br,
                                       struct PacketBuffer* p,
                                       uint8_t dstport_idx)
{
    if (dstport_idx < kBridgeIfcMaxPorts)
    {
        /* possibly an external port */
        if (dstport_idx < br->max_ports)
        {
            auto portif = br->ports[dstport_idx].port_netif;
            if ((portif != nullptr) && (portif->linkoutput != nullptr))
            {
                /* prevent sending out to rx port */
                if (get_and_inc_netif_num(portif) != p->if_idx)
                {
                    if (is_netif_link_up(portif))
                    {
                        Logf(kBridgeIfcFwDebug,
                             "br -> flood(%p:%d) -> %d\n",
                             reinterpret_cast<uint8_t *>(p),
                             p->if_idx,
                             get_and_inc_netif_num(portif));
                        return portif->linkoutput(portif, p);
                    }
                }
            }
        }
    }
    else
    {
        lwip_assert("invalid port index", dstport_idx == kBridgeIfcMaxPorts);
    }
    return ERR_OK;
}

/** Helper function to pass a PacketBuffer to all ports marked in 'dstports'
 */
static LwipStatus bridgeif_send_to_ports(BridgeIfcPrivate* br,
                                        struct PacketBuffer* p,
                                        BridgeIfcPortMask dstports)
{
    LwipStatus ret_err = ERR_OK;
    BridgeIfcPortMask mask = 1;
    for (uint8_t i = 0; i < kBridgeIfcMaxPorts; i++, mask = static_cast<BridgeIfcPortMask>
         (mask << 1))
    {
        if (dstports & mask)
        {
            const auto err = bridgeif_send_to_port(br, p, i);
            if (err != ERR_OK)
            {
                ret_err = err;
            }
        }
        return ret_err;
    }
    return ret_err;
}

/** Output function of the application port of the bridge (the one with an ip address).
 * The forwarding port(s) where this PacketBuffer is sent on is/are automatically selected
 * from the FDB.
 */
LwipStatus bridgeif_output(NetworkInterface* netif, struct PacketBuffer* p)
{
    const auto br = static_cast<BridgeIfcPrivate *>(netif->state);
    const auto dst = reinterpret_cast<MacAddress *>(p->payload);
    const auto dstports = bridgeif_find_dst_ports(br, dst);
    const auto err = bridgeif_send_to_ports(br, p, dstports);
    if (p->payload[0] & 1)
    {
        /* broadcast or multicast packet*/
    }
    else
    {
        /* unicast packet */
    } /* increase ifoutdiscards or ifouterrors on error */
    return err;
}

/** The actual bridge input function. Port netif's input is changed to call
 * here. This function decides where the frame is forwarded.
 */
static LwipStatus bridgeif_input(struct PacketBuffer* p, NetworkInterface* netif)
{
    BridgeIfcPortMask dstports;
    if (p == nullptr || netif == nullptr)
    {
        return ERR_VAL;
    }
    const auto port = static_cast<BridgeIfcPort *>(netif_get_client_data(
        netif,
        bridgeif_netif_client_id));
    lwip_assert("port data not set", port != nullptr);
    if (port == nullptr || port->bridge == nullptr)
    {
        return ERR_VAL;
    }
    auto* br = reinterpret_cast<BridgeIfcPrivate *>(port->bridge);
    const auto rx_idx = get_and_inc_netif_num(netif); /* store receive index in pbuf */
    p->if_idx = rx_idx;
    auto dst = reinterpret_cast<struct MacAddress *>(p->payload);
    auto src = reinterpret_cast<struct MacAddress *>(static_cast<uint8_t *>(p->payload) +
        sizeof(struct MacAddress));
    if ((src->addr[0] & 1) == 0)
    {
        /* update src for all non-group addresses */
        bridgeif_fdb_update_src(br->fdbd, src, port->port_num);
    }
    if (dst->addr[0] & 1)
    {
        /* group address -> flood + cpu? */
        dstports = bridgeif_find_dst_ports(br, dst);
        bridgeif_send_to_ports(br, p, dstports);
        if (dstports & (1 << kBridgeIfcMaxPorts))
        {
            /* we pass the reference to ->input or have to free it */
            Logf(kBridgeIfcFwDebug, "br -> input(%p)\n", p);
            if (br->netif->input(p, br->netif) != ERR_OK)
            {
                free_pkt_buf(p);
            }
        }
        else
        {
            /* all references done */
            free_pkt_buf(p);
        } /* always return ERR_OK here to prevent the caller freeing the PacketBuffer */
        return ERR_OK;
    }
    else
    {
        /* is this for one of the local ports? */
        if (bridgeif_is_local_mac(br, dst))
        {
            /* yes, send to cpu port only */
            Logf(kBridgeIfcFwDebug, "br -> input(%p)\n", p);
            return br->netif->input(p, br->netif);
        } /* get dst port */
        dstports = bridgeif_find_dst_ports(br, dst);
        bridgeif_send_to_ports(br, p, dstports);
        /* no need to send to cpu, flooding is for external ports only */
        /* by  this, we consumed the PacketBuffer */
        free_pkt_buf(p);
        /* always return ERR_OK here to prevent the caller freeing the PacketBuffer */
        return ERR_OK;
    }
}

/** Input function for port netifs used to synchronize into tcpip_thread.
 */
static LwipStatus bridgeif_tcpip_input(struct PacketBuffer* p, NetworkInterface* netif)
{
    return tcpip_inpkt(p, netif, bridgeif_input);
}

/**
 * @ingroup bridgeif
 * Initialization function passed to netif_add().
 *
 * ATTENTION: A pointer to a @ref bridgeif_initdata_t must be passed as 'state'
 *            to @ref netif_add when adding the bridge. I supplies MAC address
 *            and controls memory allocation (number of ports, FDB size).
 *
 * @param netif the lwip network interface structure for this ethernetif
 * @return ERR_OK if the loopif is initialized
 *         ERR_MEM if private data couldn't be allocated
 *         any other LwipStatus on error
 */
LwipStatus bridgeif_init(NetworkInterface* netif)
{
    lwip_assert("netif != NULL", netif != nullptr);
    lwip_assert("bridgeif needs an input callback", netif->input != nullptr);
    if (netif->input == tcpip_input)
    {
        Logf(true,
             "bridgeif does not need tcpip_input, use netif_input/ethernet_input instead"
             );
    }
    if (bridgeif_netif_client_id == 0xFF)
    {
        bridgeif_netif_client_id = netif_alloc_client_data_id();
    }
    auto init_data = static_cast<BridgeIfcInitData *>(netif->state);
    lwip_assert("init_data != NULL", (init_data != nullptr));
    lwip_assert("init_data->max_ports <= BRIDGEIF_MAX_PORTS",
                init_data->max_ports <= kBridgeIfcMaxPorts);
    auto alloc_len_sizet = sizeof(BridgeIfcPrivate) + (init_data->max_ports * sizeof(
        BridgeIfcPort) + (init_data->max_fdb_static_entries * sizeof(
        BridgeIfcFdbStaticEntry)));
    auto br = new BridgeIfcPrivate;
    if (br == nullptr)
    {
        Logf(true, ("bridgeif_init: out of memory\n"));
        return ERR_MEM;
    }
    memcpy(&br->MacAddress, &init_data->MacAddress, sizeof(br->MacAddress));
    br->netif = netif;
    br->max_ports = init_data->max_ports;
    br->ports = reinterpret_cast<BridgeIfcPort *>(br + 1);
    br->max_fdbs_entries = init_data->max_fdb_static_entries;
    br->fdbs = reinterpret_cast<BridgeIfcFdbStaticEntry *>(reinterpret_cast<uint8_t *>(br + 1) + (init_data->
        max_ports * sizeof(BridgeIfcPort)));
    init_data = static_cast<BridgeIfcInitData *>(netif->state);
    lwip_assert("init_data != NULL", (init_data != nullptr));
    lwip_assert("init_data->max_ports <= BRIDGEIF_MAX_PORTS",
                init_data->max_ports <= kBridgeIfcMaxPorts);
    alloc_len_sizet = sizeof(BridgeIfcPrivate) + (init_data->max_ports * sizeof(
        BridgeIfcPort) + (init_data->max_fdb_static_entries * sizeof(
        BridgeIfcFdbStaticEntry)));
    br = new BridgeIfcPrivate;
    if (br == nullptr)
    {
        Logf(true, ("bridgeif_init: out of memory\n"));
        return ERR_MEM;
    }
    memcpy(&br->MacAddress, &init_data->MacAddress, sizeof(br->MacAddress));
    br->netif = netif;
    br->max_ports = init_data->max_ports;
    br->ports = reinterpret_cast<BridgeIfcPort *>(br + 1);
    br->max_fdbs_entries = init_data->max_fdb_static_entries;
    br->fdbs = reinterpret_cast<BridgeIfcFdbStaticEntry *>(reinterpret_cast<uint8_t *>(br
        + 1) + (init_data->max_ports * sizeof(BridgeIfcPort)));
    br->max_fdbd_entries = init_data->max_fdb_dynamic_entries;
    br->fdbd = bridgeif_fdb_init(init_data->max_fdb_dynamic_entries);
    if (br->fdbd == nullptr)
    {
        Logf(true, ("bridgeif_init: out of memory in fdb_init\n"));
        delete br;
        return ERR_MEM;
    } /* Initialize interface hostname */
    netif->hostname = "lwip"; /*
     * Initialize the snmp variables and counters inside the NetworkInterface*.
     * The last argument should be replaced with your link speed, in units
     * of bits per second.
     */ // MIB2_INIT_NETIF(netif, snmp_ifType_ethernet_csmacd, 0);
    netif->state = br;
    netif->name[0] = BRIDGE_IFC_NAME[0];
    netif->name[1] = BRIDGE_IFC_NAME[1];
    /* We directly use etharp_output() here to save a function call.
        * You can instead declare your own function an call etharp_output()
        * from it if you have to do some checks before sending (e.g. if link
        * is available...) */
    netif->output = etharp_output;
    netif->output_ip6 = ethip6_output;
    netif->linkoutput = bridgeif_output; /* set MAC hardware address length */
    netif->hwaddr_len = ETH_ADDR_LEN; /* set MAC hardware address */
    memcpy(netif->hwaddr, &br->MacAddress, ETH_ADDR_LEN); /* maximum transfer unit */
    netif->mtu = 1500; /* device capabilities */
    /* don't set NETIF_FLAG_ETHARP if this device is not an ethernet one */
    netif->flags = NETIF_FLAG_BCAST | NETIF_FLAG_ETH_ARP | NETIF_FLAG_ETH |
        NETIF_FLAG_IGMP | NETIF_FLAG_MLD6 | NETIF_FLAG_LINK_UP; /*
     * For hardware/netifs that implement MAC filtering.
     * All-nodes link-local is handled by default, so we must let the hardware know
     * to allow multicast packets in.
     * Should set mld_mac_filter previously. */
    if (netif->mld_mac_filter != nullptr)
    {
        Ip6Addr ip6_allnodes_ll{};
        set_ip6_addr_all_nodes_link_local(&ip6_allnodes_ll);
        netif->mld_mac_filter(netif, &ip6_allnodes_ll, NETIF_ADD_MAC_FILTER);
    }
    return ERR_OK;
}

/**
 * @ingroup bridgeif
 * Add a port to the bridge
 */
LwipStatus bridgeif_add_port(NetworkInterface* bridgeif, NetworkInterface* portif)
{
    lwip_assert("bridgeif != NULL", bridgeif != nullptr);
    lwip_assert("bridgeif->state != NULL", bridgeif->state != nullptr);
    lwip_assert("portif != NULL", portif != nullptr);
    if (!(portif->flags & NETIF_FLAG_ETH_ARP) || !(portif->flags & NETIF_FLAG_ETH))
    {
        /* can only add ETHERNET/ETHARP interfaces */
        return ERR_VAL;
    }
    const auto br = static_cast<BridgeIfcPrivate *>(bridgeif->state);
    if (br->num_ports >= br->max_ports)
    {
        return ERR_VAL;
    }
    const auto port = &br->ports[br->num_ports];
    port->port_netif = portif;
    port->port_num = br->num_ports;
    port->bridge = br;
    br->num_ports++; /* let the port call us on input */
    portif->input = bridgeif_input; /* store pointer to bridge in netif */
    netif_set_client_data(portif, bridgeif_netif_client_id, port);
    /* remove ETHARP flag to prevent sending report events on netif-up */
    netif_clear_flags(portif, NETIF_FLAG_ETH_ARP);
    return ERR_OK;
}

//
// END OF FILE
//