#include "bridgeif.h"
#include "bridgeif_opts.h"
#include "etharp.h"
#include "lwip_debug.h"
#include "lwipopts.h"
#include "mem.h"
#include "netif.h"
#include "opt.h"
#include <cstring>
#include "ethip6.h"
#include "lwip_error.h"
#include "tcpip.h"


// #if LWIP_NUM_NETIF_CLIENT_DATA

/* Define those to better describe your network interface. */
// #define IFNAME0 'b'
// #define IFNAME1 'r'

constexpr char kIfName[] = { 'b', 'r' };

// struct bridgeif_private_s;
struct bridgeif_private_t;

struct bridgeif_port_t
{
    struct bridgeif_private_t* bridge;
    struct netif* port_netif;
    uint8_t port_num;
};

struct bridgeif_fdb_static_entry_t
{
    uint8_t used;
    bridgeif_portmask_t dst_ports;
    struct EthAddr addr;
};

struct bridgeif_private_t
{
    struct netif* netif;
    struct EthAddr ethaddr;
    uint8_t max_ports;
    uint8_t num_ports;
    bridgeif_port_t* ports;
    uint16_t max_fdbs_entries;
    bridgeif_fdb_static_entry_t* fdbs;
    uint16_t max_fdbd_entries;
    void* fdbd;
};

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
err_t
bridgeif_fdb_add(struct netif* bridgeif, const struct EthAddr* addr, bridgeif_portmask_t ports)
{
    // BRIDGEIF_DECL_PROTECT(lev);
    LWIP_ASSERT("invalid netif", bridgeif != nullptr);
    auto br = static_cast<bridgeif_private_t *>(bridgeif->state);
    LWIP_ASSERT("invalid state", br != nullptr);

    // BRIDGEIF_READ_PROTECT(lev);
    for (auto i = 0; i < br->max_fdbs_entries; i++)
    {
        if (!br->fdbs[i].used)
        {
            // BRIDGEIF_WRITE_PROTECT(lev);
            if (!br->fdbs[i].used)
            {
                br->fdbs[i].used = 1;
                br->fdbs[i].dst_ports = ports;
                memcpy(&br->fdbs[i].addr, addr, sizeof(struct EthAddr));
                // BRIDGEIF_WRITE_UNPROTECT(lev);
                // BRIDGEIF_READ_UNPROTECT(lev);
                return ERR_OK;
            }
            // BRIDGEIF_WRITE_UNPROTECT(lev);
        }
    }
    // BRIDGEIF_READ_UNPROTECT(lev);
    return ERR_MEM;
}

/**
 * @ingroup bridgeif
 * Remove a static entry from the forwarding database
 */
err_t
bridgeif_fdb_remove(struct netif* bridgeif, const struct EthAddr* addr)
{
    // BRIDGEIF_DECL_PROTECT(lev);
    LWIP_ASSERT("invalid netif", bridgeif != nullptr);
    auto br = static_cast<bridgeif_private_t *>(bridgeif->state);
    LWIP_ASSERT("invalid state", br != nullptr);

    // BRIDGEIF_READ_PROTECT(lev);
    for (auto i = 0; i < br->max_fdbs_entries; i++)
    {
        if (br->fdbs[i].used && !memcmp(&br->fdbs[i].addr, addr, sizeof(struct EthAddr)))
        {
            BRIDGEIF_WRITE_PROTECT(lev);
            if (br->fdbs[i].used && !memcmp(&br->fdbs[i].addr, addr, sizeof(struct EthAddr)))
            {
                memset(&br->fdbs[i], 0, sizeof(bridgeif_fdb_static_entry_t));
                // BRIDGEIF_WRITE_UNPROTECT(lev);
                // BRIDGEIF_READ_UNPROTECT(lev);
                return ERR_OK;
            }
            // BRIDGEIF_WRITE_UNPROTECT(lev);
        }
    }
    // BRIDGEIF_READ_UNPROTECT(lev);
    return ERR_VAL;
}

/** Get the forwarding port(s) (as bit mask) for the specified destination mac address */
static bridgeif_portmask_t
bridgeif_find_dst_ports(bridgeif_private_t* br, struct EthAddr* dst_addr)
{
    // BRIDGEIF_DECL_PROTECT(lev);
    // BRIDGEIF_READ_PROTECT(lev);
    /* first check for static entries */
    for (auto i = 0; i < br->max_fdbs_entries; i++)
    {
        if (br->fdbs[i].used)
        {
            if (!memcmp(&br->fdbs[i].addr, dst_addr, sizeof(struct EthAddr)))
            {
                auto ret = br->fdbs[i].dst_ports;
                // BRIDGEIF_READ_UNPROTECT(lev);
                return ret;
            }
        }
    }
    if (dst_addr->addr[0] & 1)
    {
        /* no match found: flood remaining group address */
        // BRIDGEIF_READ_UNPROTECT(lev);
        return kBrFlood;
    }
    // BRIDGEIF_READ_UNPROTECT(lev);
    /* no match found: check dynamic fdb for port or fall back to flooding */
    return bridgeif_fdb_get_dst_ports(br->fdbd, dst_addr);
}

/** Helper function to see if a destination mac belongs to the bridge
 * (bridge netif or one of the port netifs), in which case the frame
 * is sent to the cpu only.
 */
static int
bridgeif_is_local_mac(bridgeif_private_t* br, struct EthAddr* addr)
{
    // BRIDGEIF_DECL_PROTECT(lev);
    if (!memcmp(br->netif->hwaddr, addr, sizeof(struct EthAddr)))
    {
        return 1;
    }
    // BRIDGEIF_READ_PROTECT(lev);
    for (auto i = 0; i < br->num_ports; i++)
    {
        auto portif = br->ports[i].port_netif;
        if (portif != nullptr)
        {
            if (!memcmp(portif->hwaddr, addr, sizeof(struct EthAddr)))
            {
                // BRIDGEIF_READ_UNPROTECT(lev);
                return 1;
            }
        }
    }
    // BRIDGEIF_READ_UNPROTECT(lev);
    return 0;
}

/* Output helper function */
static err_t
bridgeif_send_to_port(bridgeif_private_t* br, struct pbuf* p, uint8_t dstport_idx)
{
    if (dstport_idx < BRIDGEIF_MAX_PORTS)
    {
        /* possibly an external port */
        if (dstport_idx < br->max_ports)
        {
            auto portif = br->ports[dstport_idx].port_netif;
            if ((portif != nullptr) && (portif->linkoutput != nullptr))
            {
                /* prevent sending out to rx port */
                if (netif_get_index(portif) != p->if_idx)
                {
                    if (netif_is_link_up(portif))
                    {
                        LWIP_DEBUGF(BRIDGEIF_FW_DEBUG,
                                    ("br -> flood(%p:%d) -> %d\n", (void *)p, p->if_idx, netif_get_index(portif)));
                        return portif->linkoutput(portif, p);
                    }
                }
            }
        }
    }
    else
    {
        LWIP_ASSERT("invalid port index", dstport_idx == BRIDGEIF_MAX_PORTS);
    }
    return ERR_OK;
}

/** Helper function to pass a pbuf to all ports marked in 'dstports'
 */
static err_t
bridgeif_send_to_ports(bridgeif_private_t* br, struct pbuf* p, bridgeif_portmask_t dstports)
{
    err_t ret_err = ERR_OK;
    bridgeif_portmask_t mask = 1;
    // BRIDGEIF_DECL_PROTECT(lev);
    // BRIDGEIF_READ_PROTECT(lev);
    for (uint8_t i = 0; i < BRIDGEIF_MAX_PORTS; i++, mask = static_cast<bridgeif_portmask_t>(mask << 1))
    {
        if (dstports & mask)
        {
            auto err = bridgeif_send_to_port(br, p, i);
            if (err != ERR_OK)
            {
                ret_err = err;
            }
        }
    }
    // BRIDGEIF_READ_UNPROTECT(lev);
    return ret_err;
}

/** Output function of the application port of the bridge (the one with an ip address).
 * The forwarding port(s) where this pbuf is sent on is/are automatically selected
 * from the FDB.
 */
static err_t
bridgeif_output(struct netif* netif, struct pbuf* p)
{
    auto br = static_cast<bridgeif_private_t *>(netif->state);
    auto dst = static_cast<struct EthAddr *>(p->payload);

    auto dstports = bridgeif_find_dst_ports(br, dst);
    auto err = bridgeif_send_to_ports(br, p, dstports);

    // MIB2_STATS_NETIF_ADD(netif, ifoutoctets, p->tot_len);
    if (static_cast<uint8_t *>(p->payload)[0] & 1)
    {
        /* broadcast or multicast packet*/
        // MIB2_STATS_NETIF_INC(netif, ifoutnucastpkts);
    }
    else
    {
        /* unicast packet */
        // MIB2_STATS_NETIF_INC(netif, ifoutucastpkts);
    }
    /* increase ifoutdiscards or ifouterrors on error */

    // LINK_STATS_INC(link.xmit);

    return err;
}

/** The actual bridge input function. Port netif's input is changed to call
 * here. This function decides where the frame is forwarded.
 */
static err_t
bridgeif_input(struct pbuf* p, struct netif* netif)
{
    bridgeif_portmask_t dstports;
    if (p == nullptr || netif == nullptr)
    {
        return ERR_VAL;
    }
    auto port = static_cast<bridgeif_port_t *>(NETIF_GET_CLIENT_DATA(netif, bridgeif_netif_client_id));
    LWIP_ASSERT("port data not set", port != nullptr);
    if (port == nullptr || port->bridge == nullptr)
    {
        return ERR_VAL;
    }
    auto* br = reinterpret_cast<bridgeif_private_t *>(port->bridge);
    const auto rx_idx = netif_get_index(netif);
    /* store receive index in pbuf */
    p->if_idx = rx_idx;

    auto dst = static_cast<struct EthAddr *>(p->payload);
    auto src = reinterpret_cast<struct EthAddr *>(static_cast<uint8_t *>(p->payload) + sizeof(struct EthAddr));

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
        if (dstports & (1 << BRIDGEIF_MAX_PORTS))
        {
            /* we pass the reference to ->input or have to free it */
            LWIP_DEBUGF(BRIDGEIF_FW_DEBUG, ("br -> input(%p)\n", (void *)p));
            if (br->netif->input(p, br->netif) != ERR_OK)
            {
                pbuf_free(p);
            }
        }
        else
        {
            /* all references done */
            pbuf_free(p);
        }
        /* always return ERR_OK here to prevent the caller freeing the pbuf */
        return ERR_OK;
    }
    else
    {
        /* is this for one of the local ports? */
        if (bridgeif_is_local_mac(br, dst))
        {
            /* yes, send to cpu port only */
            LWIP_DEBUGF(BRIDGEIF_FW_DEBUG, ("br -> input(%p)\n", (void *)p));
            return br->netif->input(p, br->netif);
        }

        /* get dst port */
        dstports = bridgeif_find_dst_ports(br, dst);
        bridgeif_send_to_ports(br, p, dstports);
        /* no need to send to cpu, flooding is for external ports only */
        /* by  this, we consumed the pbuf */
        pbuf_free(p);
        /* always return ERR_OK here to prevent the caller freeing the pbuf */
        return ERR_OK;
    }
}

/** Input function for port netifs used to synchronize into tcpip_thread.
 */
static err_t
bridgeif_tcpip_input(struct pbuf* p, struct netif* netif)
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
 *         any other err_t on error
 */
err_t
bridgeif_init(struct netif* netif)
{
    bridgeif_initdata_t* init_data;
    bridgeif_private_t* br;
    size_t alloc_len_sizet;
    mem_size_t alloc_len;

    LWIP_ASSERT("netif != NULL", (netif != nullptr));
    LWIP_ASSERT("bridgeif needs an input callback", (netif->input != nullptr));
#if !BRIDGEIF_PORT_NETIFS_OUTPUT_DIRECT
    if (netif->input == tcpip_input)
    {
        LWIP_DEBUGF(BRIDGEIF_DEBUG | LWIP_DBG_ON,
                    ("bridgeif does not need tcpip_input, use netif_input/ethernet_input instead"));
    }
#endif

    if (bridgeif_netif_client_id == 0xFF)
    {
        bridgeif_netif_client_id = netif_alloc_client_data_id();
    }

    init_data = static_cast<bridgeif_initdata_t *>(netif->state);
    LWIP_ASSERT("init_data != NULL", (init_data != nullptr));
    LWIP_ASSERT("init_data->max_ports <= BRIDGEIF_MAX_PORTS",
                init_data->max_ports <= BRIDGEIF_MAX_PORTS);

    alloc_len_sizet = sizeof(bridgeif_private_t) + (init_data->max_ports * sizeof(bridgeif_port_t) + (init_data->
        max_fdb_static_entries * sizeof(bridgeif_fdb_static_entry_t)));
    alloc_len = static_cast<mem_size_t>(alloc_len_sizet);
    LWIP_ASSERT("alloc_len == alloc_len_sizet", alloc_len == alloc_len_sizet);
    LWIP_DEBUGF(BRIDGEIF_DEBUG, ("bridgeif_init: allocating %d bytes for private data\n", (int)alloc_len));
    br = static_cast<bridgeif_private_t *>(mem_calloc(1, alloc_len));
    if (br == nullptr)
    {
        LWIP_DEBUGF(NETIF_DEBUG, ("bridgeif_init: out of memory\n"));
        return ERR_MEM;
    }
    memcpy(&br->ethaddr, &init_data->ethaddr, sizeof(br->ethaddr));
    br->netif = netif;

    br->max_ports = init_data->max_ports;
    br->ports = reinterpret_cast<bridgeif_port_t *>(br + 1);

    br->max_fdbs_entries = init_data->max_fdb_static_entries;
    br->fdbs = reinterpret_cast<bridgeif_fdb_static_entry_t *>(reinterpret_cast<uint8_t *>(br + 1) + (init_data->
        max_ports * sizeof(
            bridgeif_port_t)));

    br->max_fdbd_entries = init_data->max_fdb_dynamic_entries;
    br->fdbd = bridgeif_fdb_init(init_data->max_fdb_dynamic_entries);
    if (br->fdbd == nullptr)
    {
        LWIP_DEBUGF(NETIF_DEBUG, ("bridgeif_init: out of memory in fdb_init\n"));
        mem_free(br);
        return ERR_MEM;
    }

    /* Initialize interface hostname */
    netif->hostname = "lwip";


    /*
     * Initialize the snmp variables and counters inside the struct netif.
     * The last argument should be replaced with your link speed, in units
     * of bits per second.
     */
    // MIB2_INIT_NETIF(netif, snmp_ifType_ethernet_csmacd, 0);

    netif->state = br;
    netif->name[0] = kIfName[0];
    netif->name[1] = kIfName[1];
    /* We directly use etharp_output() here to save a function call.
     * You can instead declare your own function an call etharp_output()
     * from it if you have to do some checks before sending (e.g. if link
     * is available...) */
    netif->output = etharp_output;
    netif->output_ip6 = ethip6_output;
    netif->linkoutput = bridgeif_output;
    /* set MAC hardware address length */
    netif->hwaddr_len = ETH_HWADDR_LEN;
    /* set MAC hardware address */
    memcpy(netif->hwaddr, &br->ethaddr, ETH_HWADDR_LEN);
    /* maximum transfer unit */
    netif->mtu = 1500;
    /* device capabilities */
    /* don't set NETIF_FLAG_ETHARP if this device is not an ethernet one */
    netif->flags = kNetifFlagBroadcast | kNetifFlagEtharp | kNetifFlagEthernet | kNetifFlagIgmp | kNetifFlagMld6 |
        NETIF_FLAG_LINK_UP;
    /*
     * For hardware/netifs that implement MAC filtering.
     * All-nodes link-local is handled by default, so we must let the hardware know
     * to allow multicast packets in.
     * Should set mld_mac_filter previously. */
    if (netif->mld_mac_filter != nullptr)
    {
        Ip6Addr ip6_allnodes_ll;
        ip6_addr_set_allnodes_linklocal(&ip6_allnodes_ll);
        netif->mld_mac_filter(netif, &ip6_allnodes_ll, NETIF_ADD_MAC_FILTER);
    }
    return ERR_OK;
}

/**
 * @ingroup bridgeif
 * Add a port to the bridge
 */
err_t
bridgeif_add_port(struct netif* bridgeif, struct netif* portif)
{
    LWIP_ASSERT("bridgeif != NULL", bridgeif != nullptr);
    LWIP_ASSERT("bridgeif->state != NULL", bridgeif->state != nullptr);
    LWIP_ASSERT("portif != NULL", portif != nullptr);

    if (!(portif->flags & kNetifFlagEtharp) || !(portif->flags & kNetifFlagEthernet))
    {
        /* can only add ETHERNET/ETHARP interfaces */
        return ERR_VAL;
    }

    const auto br = static_cast<bridgeif_private_t *>(bridgeif->state);

    if (br->num_ports >= br->max_ports)
    {
        return ERR_VAL;
    }
    const auto port = &br->ports[br->num_ports];
    port->port_netif = portif;
    port->port_num = br->num_ports;
    port->bridge = br;
    br->num_ports++;

    /* let the port call us on input */

    portif->input = bridgeif_input;
    /* store pointer to bridge in netif */
    NETIF_SET_CLIENT_DATA(portif, bridgeif_netif_client_id, port);
    /* remove ETHARP flag to prevent sending report events on netif-up */
    netif_clear_flags(portif, kNetifFlagEtharp);

    return ERR_OK;
}

