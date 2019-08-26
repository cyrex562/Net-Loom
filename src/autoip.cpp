#include "autoip.h"
#include "network_interface.h"
#include "etharp.h"
#include "lwip_debug.h"
#include <cstring>


/**
 * Restart AutoIP client and check the next address (conflict detected)
 *
 * @param netif The netif under AutoIP control
 * @param state
 *
 */
bool autoip_restart(NetworkInterface& netif,
                    AutoipState& state)
{
    // ReSharper disable once CppLocalVariableMayBeConst
    state.tried_llipaddr++;
    if (!autoip_start(netif, state)) { return false; }
    return true;
}


//
// Handle a IP address conflict after an ARP conflict detection
//
bool autoip_handle_arp_conflict(NetworkInterface& net_ifc, AutoipState& state)
{
    /* RFC3927, 2.5 "Conflict Detection and Defense" allows two options where
           a) means retreat on the first conflict and
           b) allows to keep an already configured address when having only one
              conflict in 10 seconds
           We use option b) since it helps to improve the chance that one of the two
           conflicting hosts may be able to retain its address. */
    if (state.lastconflict > 0)
    {
        /* retreat, there was a conflicting ARP in the last DEFEND_INTERVAL seconds */
        /* Active TCP sessions are aborted when removing the ip addresss */
        autoip_restart(net_ifc, state);
    }
    else
    {
        autoip_arp_announce(net_ifc, state.llipaddr);
        state.lastconflict = AUTO_IP_DEFEND_INTERVAL * AUTO_IP_TICKS_PER_SEC;
    }
    return true;
}

//
// Create an IP-Address out of range 169.254.1.0 to 169.254.254.255
//
// @param netif network interface on which create the IP-Address
// @param ipaddr ip address to initialize
//
bool autoip_create_addr(AutoipState& autoip, NetworkInterface& netif, Ip4Addr& ipaddr)
{

    /* Here we create an IP-Address out of range 169.254.1.0 to 169.254.254.255
      * compliant to RFC 3927 Section 2.1
      * We have 254 * 256 possibilities */
    auto addr = lwip_ntohl(autoip_gen_seed_addr(netif));
    addr += autoip.tried_llipaddr;
    addr = IP4_AUTO_IP_NET | (addr & 0xffff); /* Now, 169.254.0.0 <= addr <= 169.254.255.255 */
    if (addr < AUTOIP_RANGE_START)
    {
        addr += IP4_AUTO_IP_RANGE_END - AUTOIP_RANGE_START + 1;
    }
    if (addr > IP4_AUTO_IP_RANGE_END)
    {
        addr -= IP4_AUTO_IP_RANGE_END - AUTOIP_RANGE_START + 1;
    }
    lwip_assert("AUTOIP address not in range",
                (addr >= AUTOIP_RANGE_START) && (addr <= IP4_AUTO_IP_RANGE_END));
    set_ip4_addr_u32(ipaddr, lwip_htonl(addr));

    return true;
}

//
// Sends an ARP probe from a network interface
//
// @param netif network interface used to send the probe
//
bool
autoip_arp_probe(NetworkInterface& netif, AutoipState& autoip)
{

    /* this works because netif->ip_addr is ANY */
    return etharp_request(netif, autoip.llipaddr);
}

//
// Sends an ARP announce from a network interface
//
// @param netif network interface used to send the announce
//
bool
autoip_arp_announce(NetworkInterface& netif, Ip4Addr& announce_ip_addr)
{
  return etharp_gratuitous(netif, announce_ip_addr);
}

/**
 * Configure interface for use with current LL IP-Address
 * @param netif network interface to configure with current LL IP-Address
 * @param state
 */
bool
autoip_bind(NetworkInterface& netif, AutoipState& state)
{
    Ip4Addr sn_mask = ip4_addr_create_hbo(255, 255, 0, 0);
    Ip4Addr gw_addr = ip4_addr_create_hbo(0, 0, 0, 0);
    Ip4AddrInfo bind_addr_info{};
    bind_addr_info.netmask = sn_mask;
    bind_addr_info.gateway = gw_addr;
    bind_addr_info.address = state.llipaddr;
    return netif_upsert_ip4(netif, bind_addr_info);
}

/**
 * @ingroup autoip
 * Start AutoIP client
 *
 * @param netif network interface on which start the AutoIP client
 */
bool
autoip_start(NetworkInterface& netif, AutoipState& state)
{
    /* Set IP-Address, Netmask and Gateway to 0 to make sure that
         * ARP Packets are formed correctly
         */
    auto any_addr = ip4_addr_create_any();

    Ip4AddrInfo addr_info{};
    addr_info.address = any_addr;
    addr_info.netmask = any_addr;
    addr_info.gateway = any_addr;
    netif_upsert_ip4(netif, addr_info);
    // if (autoip == nullptr)
    // {
    //     /* no AutoIP client attached yet? */
    //     autoip = new AutoipState;
    //     if (autoip == nullptr)
    //     {
    //         return ERR_MEM;
    //     } /* store this AutoIP client in the netif */
    //     // netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_AUTOIP, autoip);
    //     netif->client_data[LWIP_NETIF_CLIENT_DATA_INDEX_AUTOIP] = autoip;
    // }
    // else
    // {
    //     autoip->state = AUTOIP_STATE_OFF;
    //     autoip->ttw = 0;
    //     autoip->sent_num = 0;
    //     zero_ip4_addr(&autoip->llipaddr);
    //     autoip->lastconflict = 0;
    // } // todo: check result

    state.state = AUTOIP_STATE_OFF;
    state.ttw = 0;
    state.sent_num = 0;
    ip4_addr_zero(state.llipaddr);
    state.lastconflict = 0;

    if (!autoip_create_addr(state, netif, state.llipaddr)) {return false;}
    return autoip_start_probing(netif, state);
}


bool
autoip_start_probing(NetworkInterface& netif, AutoipState& state)
{
    state.state = AUTOIP_STATE_PROBING;
    state.sent_num = 0;
    /* time to wait to first probe, this is randomly
   * chosen out of 0 to PROBE_WAIT seconds.
   * compliant to RFC 3927 Section 2.2.1
   */
    state.ttw = uint16_t(
        autoip_gen_rand(netif, state) % (AUTO_IP_PROBE_WAIT * AUTO_IP_TICKS_PER_SEC));

    // if we tried more then MAX_CONFLICTS we must limit our rate for acquiring and
    // probing address compliant to RFC 3927 Section 2.2.1
    if (state.tried_llipaddr > AUTO_IP_MAX_CONFLICTS)
    {
        state.ttw = AUTO_IP_RATE_LIMIT_INTERVAL * AUTO_IP_TICKS_PER_SEC;
    }
    return true;
}


uint32_t
autoip_gen_rand(NetworkInterface& netif, AutoipState& state)
{
    // todo: replace with system random function or real pseudo-random math function.
    auto x = (uint32_t(netif.mac_address.bytes[5] & 0xff) << 24 |
        uint32_t(netif.mac_address.bytes[3] & 0xff) << 16 |
        uint32_t(netif.mac_address.bytes[2] & 0xff) << 8 | uint32_t(
            netif.mac_address.bytes[4] & 0xff));
    return x + state.tried_llipaddr;
}


//
// Handle a possible change in the network configuration.
//
// If there is an AutoIP address configured, take the interface down
// and begin probing with the same address.
//
bool autoip_network_changed(NetworkInterface& netif, AutoipState& state)
{
    if ((state.state != AUTOIP_STATE_OFF))
    {
        autoip_start_probing(netif, state);
    }
    return true;
}

//
// @ingroup autoip
// Stop AutoIP client
//
// @param netif network interface on which stop the AutoIP client
//
bool
autoip_stop(NetworkInterface& netif, AutoipState& autoip)
{
    autoip.state = AUTOIP_STATE_OFF;
    // todo: determine which IP to modify
    int i = 0;
    if (ip4_addr_is_link_local(netif.ip4_addresses[i].address))
    {
        auto any_addr = ip4_addr_create_any();
        Ip4AddrInfo any_addr_info{};
        any_addr_info.address = any_addr;
        any_addr_info.netmask = any_addr;
        any_addr_info.gateway = any_addr;
        return netif_upsert_ip4(netif, any_addr_info);
    }
    return true;
}

//
// Has to be called in loop every AUTOIP_TMR_INTERVAL milliseconds
//
bool
autoip_timer_fn(std::vector<NetworkInterface>& interfaces,
                AutoipState& state)
{
    // loop through netif's
    for (auto& netif : interfaces)
    {
        /* only act on AutoIP configured interfaces */
        if (state.lastconflict > 0) { state.lastconflict--; }
        if (state.ttw > 0) { state.ttw--; }
        switch (state.state)
        {
        case AUTOIP_STATE_PROBING:
            if (state.ttw == 0)
            {
                if (state.sent_num >= AUTO_IP_PROBE_NUM)
                {
                    /* Switch to ANNOUNCING: now we can bind to an IP address and use it */
                    state.state = AUTOIP_STATE_ANNOUNCING;
                    autoip_bind(netif, state);
                    /* autoip_bind() calls netif_set_addr(): this triggers a gratuitous ARP
                     * which counts as an announcement */
                    state.sent_num = 1;
                    state.ttw = AUTO_IP_ANNOUNCE_WAIT * AUTO_IP_TICKS_PER_SEC;
                }
                else
                {
                    // todo: check the return
                    autoip_arp_probe(netif, state);
                    state.sent_num++;
                    if (state.sent_num == AUTO_IP_PROBE_NUM)
                    {
                        /* calculate time to wait to for announce */
                        state.ttw = AUTO_IP_ANNOUNCE_WAIT * AUTO_IP_TICKS_PER_SEC;
                    }
                    else
                    {
                        /* calculate time to wait to next probe */
                        state.ttw = uint16_t(
                            (autoip_gen_rand(netif, state) % ((AUTO_IP_PROBE_MAX -
                                AUTO_IP_PROBE_MIN) * AUTO_IP_TICKS_PER_SEC)) +
                            AUTO_IP_PROBE_MIN * AUTO_IP_TICKS_PER_SEC);
                    }
                }
            }
            break;
        case AUTOIP_STATE_ANNOUNCING:
            if (state.ttw == 0)
            {
                autoip_arp_announce(netif, state.llipaddr);
                state.ttw = AUTO_IP_ANNOUNCE_INTERVAL * AUTO_IP_TICKS_PER_SEC;
                state.sent_num++;
                if (state.sent_num >= AUTO_IP_ANNOUNCE_NUM)
                {
                    state.state = AUTOIP_STATE_BOUND;
                    state.sent_num = 0;
                    state.ttw = 0;
                }
            }
            break;
        default: /* nothing to do in other states */ break;
        }
    }

    return true;
}

//
// Handles every incoming ARP Packet, called by etharp_input().
//
// @param netif network interface to use for autoip processing
// @param hdr Incoming ARP packet
//
bool
autoip_arp_reply(NetworkInterface& netif, EtharpHdr& hdr, AutoipState& state)
{
    if (state.state != AUTOIP_STATE_OFF)
    {
        Ip4Addr sipaddr{};

        /* when ip.src == llipaddr && hw.src != netif->hwaddr
         *
         * when probing  ip.dst == llipaddr && hw.src != netif->hwaddr
         * we have a conflict and must solve it
         */
        Ip4Addr dipaddr{};
        MacAddress netifaddr{};
        memcpy(netifaddr.bytes, netif.mac_address.bytes, ETH_ADDR_LEN);

        /* Copy struct ip4_addr_wordaligned to aligned ip4_addr, to support compilers
         * without structure packing (not using structure copy which breaks
         * strict-aliasing rules).
         */
        hdr.sipaddr = sipaddr;
        hdr.dipaddr = dipaddr;
        if (state.state == AUTOIP_STATE_PROBING)
        {
            /* RFC 3927 Section 2.2.1:
             * from beginning to after ANNOUNCE_WAIT
             * seconds we have a conflict if
             * ip.src == llipaddr OR
             * ip.dst == llipaddr && hw.src != own hwaddr
             */
            if ((is_ip4_addr_equal(sipaddr, state.llipaddr)) || (
                is_ip4_addr_any(sipaddr) && is_ip4_addr_equal(dipaddr, state.llipaddr)
                && !eth_addr_cmp(netifaddr, hdr.shwaddr)))
            {
                return autoip_restart(netif, state);
            }
        }
        else
        {
            /* RFC 3927 Section 2.5:
             * in any state we have a conflict if
             * ip.src == llipaddr && hw.src != own hwaddr
             */
            if (is_ip4_addr_equal(sipaddr, state.llipaddr) && !eth_addr_cmp(
                netifaddr,
                hdr.shwaddr))
            {
                return autoip_handle_arp_conflict(netif, state);
            }
        }
    }

    return false;
}

// check if AutoIP supplied netif->ip_addr
//
// @param netif the netif to check
// @return 1 if AutoIP supplied netif->ip_addr (state BOUND or ANNOUNCING),
//         0 otherwise
//
bool
autoip_supplied_address(const NetworkInterface& netif, AutoipState& autoip)
{
    return (autoip.state == AUTOIP_STATE_BOUND) || (autoip.state ==
        AUTOIP_STATE_ANNOUNCING);
}


bool
autoip_accept_packet(AutoipState& state, const Ip4Addr& addr)
{
    return is_ip4_addr_equal(addr, state.llipaddr);
}

//
// END OF FILE
//
