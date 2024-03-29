#include <autoip.h>
#include <opt.h>
#include <ip_addr.h>
#include <network_interface.h>
#include <etharp.h>
#include <cstring>
#include <lwip_debug.h>


//
// Pseudo random macro based on netif informations.
// You could use "rand()" from the C Library if you define LWIP_AUTOIP_RAND in lwipopts.h
//
inline uint32_t autoip_gen_rand(NetworkInterface* netif)
{
    return (uint32_t(netif->hwaddr[5] & 0xff) << 24 | uint32_t(netif->hwaddr[3] & 0xff) <<
            16 | uint32_t(netif->hwaddr[2] & 0xff) << 8 | uint32_t(
                netif->hwaddr[4] & 0xff)) +
        (netif_autoip_data(netif) ? netif_autoip_data(netif)->tried_llipaddr : 0);
}


//
// Macro that generates the initial IP address to be tried by AUTOIP.
// If you want to override this, define it to something else in lwipopts.h.
//
inline uint32_t autoip_gen_seed_addr(NetworkInterface* netif)
{
    return lwip_htonl(kAutoipRangeStart + uint32_t(
        uint8_t(netif->hwaddr[4]) | uint32_t(uint8_t(netif->hwaddr[5])) << 8));
}

LwipStatus autoip_arp_announce(NetworkInterface* netif);
bool autoip_start_probing(NetworkInterface* netif);


//
// Set a statically allocated struct autoip to work with.
// Using this prevents autoip_start to allocate it using mem_malloc.
//
// netif: the netif for which to set the struct autoip
// autoip; (uninitialised) autoip struct allocated by the application
//
bool autoip_set_struct(NetworkInterface* netif, struct AutoipState* autoip)
{
    lwip_assert("netif != NULL", netif != nullptr);
    lwip_assert("autoip != NULL", autoip != nullptr);
    lwip_assert("netif already has a struct autoip set",
                netif_autoip_data(netif) == nullptr); /* clear data structure */
    memset(autoip, 0, sizeof(struct AutoipState)); /* autoip->state = AUTOIP_STATE_OFF; */
    netif->client_data[LWIP_NETIF_CLIENT_DATA_INDEX_AUTOIP] = static_cast<void*>(autoip);
    return true;
}

//
// Restart AutoIP client and check the next address (conflict detected)
//
// @param netif The netif under AutoIP control
//
bool autoip_restart(NetworkInterface* netif)
{
    // ReSharper disable once CppLocalVariableMayBeConst
    auto autoip = netif_autoip_data(netif);
    autoip->tried_llipaddr++; // TODO: check for error
    autoip_start(netif);
    return true;
}


//
// Handle a IP address conflict after an ARP conflict detection
//
bool autoip_handle_arp_conflict(NetworkInterface* netif)
{
    const auto autoip = netif_autoip_data(netif);
    /* RFC3927, 2.5 "Conflict Detection and Defense" allows two options where
           a) means retreat on the first conflict and
           b) allows to keep an already configured address when having only one
              conflict in 10 seconds
           We use option b) since it helps to improve the chance that one of the two
           conflicting hosts may be able to retain its address. */
    if (autoip->lastconflict > 0)
    {
        /* retreat, there was a conflicting ARP in the last DEFEND_INTERVAL seconds */
        /* Active TCP sessions are aborted when removing the ip addresss */
        autoip_restart(netif);
    }
    else
    {
        autoip_arp_announce(netif);
        autoip->lastconflict = kDefendInterval * kAutoipTicksPerSecond;
    }
    return true;
}

//
// Create an IP-Address out of range 169.254.1.0 to 169.254.254.255
//
// @param netif network interface on which create the IP-Address
// @param ipaddr ip address to initialize
//
bool autoip_create_addr(NetworkInterface* netif, Ip4Addr* ipaddr)
{
    const auto autoip = netif_autoip_data(netif);
    /* Here we create an IP-Address out of range 169.254.1.0 to 169.254.254.255
      * compliant to RFC 3927 Section 2.1
      * We have 254 * 256 possibilities */
    auto addr = lwip_ntohl(autoip_gen_seed_addr(netif));
    addr += autoip->tried_llipaddr;
    addr = kAutoipNet | (addr & 0xffff); /* Now, 169.254.0.0 <= addr <= 169.254.255.255 */
    if (addr < kAutoipRangeStart)
    {
        addr += kAutoipRangeEnd - kAutoipRangeStart + 1;
    }
    if (addr > kAutoipRangeEnd)
    {
        addr -= kAutoipRangeEnd - kAutoipRangeStart + 1;
    }
    lwip_assert("AUTOIP address not in range",
                (addr >= kAutoipRangeStart) && (addr <= kAutoipRangeEnd));
    set_ip4_addr_u32(ipaddr, lwip_htonl(addr));

    return true;
}

//
// Sends an ARP probe from a network interface
//
// @param netif network interface used to send the probe
//
LwipStatus autoip_arp_probe(NetworkInterface* netif)
{
    auto autoip = netif_autoip_data(netif);
    /* this works because netif->ip_addr is ANY */
    return etharp_request(netif, &autoip->llipaddr);
}

//
// Sends an ARP announce from a network interface
//
// @param netif network interface used to send the announce
//
LwipStatus
autoip_arp_announce(NetworkInterface* netif)
{
  return etharp_gratuitous(netif,,);
}

//
// Configure interface for use with current LL IP-Address
//
// @param netif network interface to configure with current LL IP-Address
//
 LwipStatus autoip_bind(NetworkInterface* netif)
{
    auto autoip = netif_autoip_data(netif);
    Ip4Addr sn_mask{};
    Ip4Addr gw_addr{};
    make_ip4_addr_host_from_bytes(&sn_mask, 255, 255, 0, 0);
    make_ip4_addr_host_from_bytes(&gw_addr, 0, 0, 0, 0);
    set_netif_addr(netif, &autoip->llipaddr, &sn_mask, &gw_addr);
    // interface is used by routing now that an address is set
    return STATUS_SUCCESS;
}

/**
 * @ingroup autoip
 * Start AutoIP client
 *
 * @param netif network interface on which start the AutoIP client
 */
LwipStatus autoip_start(NetworkInterface* netif)
{
    auto autoip = netif_autoip_data(netif);
    const LwipStatus result = STATUS_SUCCESS;
    /* Set IP-Address, Netmask and Gateway to 0 to make sure that
         * ARP Packets are formed correctly
         */
    auto any_addr = make_ip4_addr_any();

    set_netif_addr(netif, &any_addr, &any_addr, &any_addr);
    if (autoip == nullptr)
    {
        /* no AutoIP client attached yet? */
        autoip = new AutoipState;
        if (autoip == nullptr)
        {
            return ERR_MEM;
        } /* store this AutoIP client in the netif */
        // netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_AUTOIP, autoip);
        netif->client_data[LWIP_NETIF_CLIENT_DATA_INDEX_AUTOIP] = autoip;
    }
    else
    {
        autoip->state = AUTOIP_STATE_OFF;
        autoip->ttw = 0;
        autoip->sent_num = 0;
        zero_ip4_addr(&autoip->llipaddr);
        autoip->lastconflict = 0;
    } // todo: check result
    autoip_create_addr(netif, &(autoip->llipaddr)); // todo: check result
    autoip_start_probing(netif);
    return result;
}

static bool autoip_start_probing(NetworkInterface* netif)
{
    const auto autoip = netif_autoip_data(netif);
    autoip->state = AUTOIP_STATE_PROBING;
    autoip->sent_num = 0; /* time to wait to first probe, this is randomly
   * chosen out of 0 to PROBE_WAIT seconds.
   * compliant to RFC 3927 Section 2.2.1
   */
    autoip->ttw = uint16_t(autoip_gen_rand(netif) % (kProbeWait * kAutoipTicksPerSecond)); /*
   * if we tried more then MAX_CONFLICTS we must limit our rate for
   * acquiring and probing address
   * compliant to RFC 3927 Section 2.2.1
   */
    if (autoip->tried_llipaddr > kMaxConflicts)
    {
        autoip->ttw = kRateLimitInterval * kAutoipTicksPerSecond;
    }
    return true;
}

//
// Handle a possible change in the network configuration.
//
// If there is an AutoIP address configured, take the interface down
// and begin probing with the same address.
//
bool autoip_network_changed(NetworkInterface* netif)
{
    const auto autoip = netif_autoip_data(netif);
    if (autoip && (autoip->state != AUTOIP_STATE_OFF))
    {
        autoip_start_probing(netif);
    }
    return true;
}

//
// @ingroup autoip
// Stop AutoIP client
//
// @param netif network interface on which stop the AutoIP client
//
LwipStatus autoip_stop(NetworkInterface& netif)
{
    const auto autoip = netif_autoip_data(netif);
    if (autoip != nullptr)
    {
        autoip->state = AUTOIP_STATE_OFF;
        int i = 0;
        if (is_ip4_addr_link_local(netif.ip4_addresses[i].u_addr.ip4))
        {
            auto any_addr = make_ip4_addr_any();
            set_netif_addr(netif,
                           &any_addr,
                           &any_addr,
                           &any_addr);
        }
    }
    return STATUS_SUCCESS;
}

//
// Has to be called in loop every AUTOIP_TMR_INTERVAL milliseconds
//
void autoip_tmr(void)
{
    // loop through netif's
    for (auto netif = netif_list; (netif) != nullptr; netif = netif->next)
    {
        const auto autoip = netif_autoip_data(netif);
        /* only act on AutoIP configured interfaces */
        if (autoip != nullptr)
        {
            if (autoip->lastconflict > 0)
            {
                autoip->lastconflict--;
            }
            if (autoip->ttw > 0)
            {
                autoip->ttw--;
            }
            switch (autoip->state)
            {
            case AUTOIP_STATE_PROBING:
                if (autoip->ttw == 0)
                {
                    if (autoip->sent_num >= kProbeNum)
                    {
                        /* Switch to ANNOUNCING: now we can bind to an IP address and use it */
                        autoip->state = AUTOIP_STATE_ANNOUNCING;
                        autoip_bind(netif);
                        /* autoip_bind() calls netif_set_addr(): this triggers a gratuitous ARP
                                                                                      which counts as an announcement */
                        autoip->sent_num = 1;
                        autoip->ttw = kAnnounceWait * kAutoipTicksPerSecond;
                    }
                    else
                    {
                        // todo: check the return
                        autoip_arp_probe(netif);
                        autoip->sent_num++;
                        if (autoip->sent_num == kProbeNum)
                        {
                            /* calculate time to wait to for announce */
                            autoip->ttw = kAnnounceWait * kAutoipTicksPerSecond;
                        }
                        else
                        {
                            /* calculate time to wait to next probe */
                            autoip->ttw = uint16_t(
                                (autoip_gen_rand(netif) % ((kProbeMax - kProbeMin) *
                                    kAutoipTicksPerSecond)) + kProbeMin *
                                kAutoipTicksPerSecond);
                        }
                    }
                }
                break;
            case AUTOIP_STATE_ANNOUNCING:
                if (autoip->ttw == 0)
                {
                    autoip_arp_announce(netif);
                    autoip->ttw = kAnnounceInterval * kAutoipTicksPerSecond;
                    autoip->sent_num++;
                    if (autoip->sent_num >= kAnnounceNum)
                    {
                        autoip->state = AUTOIP_STATE_BOUND;
                        autoip->sent_num = 0;
                        autoip->ttw = 0;
                    }
                }
                break;
            default: /* nothing to do in other states */ break;
            }
        }
    }
}

//
// Handles every incoming ARP Packet, called by etharp_input().
//
// @param netif network interface to use for autoip processing
// @param hdr Incoming ARP packet
//
void autoip_arp_reply(NetworkInterface* netif, EtharpHdr* hdr)
{
    auto autoip = netif_autoip_data(netif);
    if ((autoip != nullptr) && (autoip->state != AUTOIP_STATE_OFF))
    {
        Ip4Addr sipaddr{}; /* when ip.src == llipaddr && hw.src != netif->hwaddr
         *
         * when probing  ip.dst == llipaddr && hw.src != netif->hwaddr
         * we have a conflict and must solve it
         */
        Ip4Addr dipaddr{};
        MacAddress netifaddr{};
        memcpy(netifaddr.bytes,netif->hwaddr,ETH_ADDR_LEN);
        /* Copy struct ip4_addr_wordaligned to aligned ip4_addr, to support compilers without
                   * structure packing (not using structure copy which breaks strict-aliasing rules).
                   */
        IpaddrWordalignedCopyToIp4AddrT(&hdr->sipaddr, &sipaddr);
        IpaddrWordalignedCopyToIp4AddrT(&hdr->dipaddr, &dipaddr);
        if (autoip->state == AUTOIP_STATE_PROBING)
        {
            /* RFC 3927 Section 2.2.1:
             * from beginning to after ANNOUNCE_WAIT
             * seconds we have a conflict if
             * ip.src == llipaddr OR
             * ip.dst == llipaddr && hw.src != own hwaddr
             */
            if ((is_ip4_addr_equal(&sipaddr, &autoip->llipaddr)) || (
                ip4_addr_isany_val(sipaddr) && is_ip4_addr_equal(&dipaddr, &autoip->llipaddr)
                && !cmp_eth_addr(&netifaddr, &hdr->shwaddr)))
            {
                autoip_restart(netif);
            }
        }
        else
        {
            /* RFC 3927 Section 2.5:
             * in any state we have a conflict if
             * ip.src == llipaddr && hw.src != own hwaddr
             */
            if (is_ip4_addr_equal(&sipaddr, &autoip->llipaddr) && !cmp_eth_addr(
                &netifaddr,
                &hdr->shwaddr))
            {
                autoip_handle_arp_conflict(netif);
            }
        }
    }
}

// check if AutoIP supplied netif->ip_addr
//
// @param netif the netif to check
// @return 1 if AutoIP supplied netif->ip_addr (state BOUND or ANNOUNCING),
//         0 otherwise
//
bool autoip_supplied_address(const NetworkInterface* netif)
{
    if ((netif != nullptr) && (netif_autoip_data(netif) != nullptr))
    {
        const auto autoip = netif_autoip_data(netif);
        return (autoip->state == AUTOIP_STATE_BOUND) || (autoip->state ==
            AUTOIP_STATE_ANNOUNCING);
    }
    return true;
}

bool autoip_accept_packet(NetworkInterface& netif, const Ip4Addr& addr)
{
    const auto autoip = netif_autoip_data(netif);
    return (autoip != nullptr) && is_ip4_addr_equal(addr, &(autoip->llipaddr));
}

//
// END OF FILE
//
