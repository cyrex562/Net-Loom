#include "opt.h"
#include "ip_addr.h"
#include "netif.h"
#include "autoip.h"
#include "etharp.h"
#include "autoip.h"
#include <cstring>
#include "lwip_debug.h"


/** Pseudo random macro based on netif informations.
 * You could use "rand()" from the C Library if you define LWIP_AUTOIP_RAND in lwipopts.h */

inline uint32_t LwipAutoipRand(NetIfc* netif){ return ( ((uint32_t((netif->hwaddr[5]) & 0xff) << 24) | 
                                   (uint32_t((netif->hwaddr[3]) & 0xff) << 16) | 
                                   (uint32_t((netif->hwaddr[2]) & 0xff) << 8) | 
                                   uint32_t((netif->hwaddr[4]) & 0xff)) + 
                                   (netif_autoip_data(netif) ? netif_autoip_data(netif)->tried_llipaddr
                                    : 0));
}


/**
 * Macro that generates the initial IP address to be tried by AUTOIP.
 * If you want to override this, define it to something else in lwipopts.h.
 */
inline uint32_t LwipAutoipCreateSeedAddr(NetIfc* netif)
{
    return lwip_htonl(AUTOIP_RANGE_START + uint32_t(
        uint8_t(netif->hwaddr[4]) | uint32_t(uint8_t(netif->hwaddr[5])) << 8));
}

/* static functions */
static LwipError autoip_arp_announce(NetIfc* netif);
static bool autoip_start_probing(NetIfc* netif);

/**
 * @ingroup autoip
 * Set a statically allocated struct autoip to work with.
 * Using this prevents autoip_start to allocate it using mem_malloc.
 *
 * @param netif the netif for which to set the struct autoip
 * @param autoip (uninitialised) autoip struct allocated by the application
 */
bool autoip_set_struct(NetIfc* netif, struct AutoipState* autoip)
{
    LWIP_ASSERT_CORE_LOCKED();
    LWIP_ASSERT("netif != NULL", netif != nullptr);
    LWIP_ASSERT("autoip != NULL", autoip != nullptr);
    LWIP_ASSERT("netif already has a struct autoip set",
                netif_autoip_data(netif) == nullptr); /* clear data structure */
    memset(autoip, 0, sizeof(struct AutoipState)); /* autoip->state = AUTOIP_STATE_OFF; */
    netif->client_data[LWIP_NETIF_CLIENT_DATA_INDEX_AUTOIP] = static_cast<void*>(autoip);
    return true;
}

/** Restart AutoIP client and check the next address (conflict detected)
 *
 * @param netif The netif under AutoIP control
 */
bool autoip_restart(NetIfc* netif)
{
    // ReSharper disable once CppLocalVariableMayBeConst
    auto autoip = netif_autoip_data(netif);
    autoip->tried_llipaddr++;
    // TODO: check for error
    autoip_start(netif);
    return true;
}


//
// Handle a IP address conflict after an ARP conflict detection
//
bool autoip_handle_arp_conflict(NetIfc* netif)
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
        autoip->lastconflict = DEFEND_INTERVAL * AUTOIP_TICKS_PER_SECOND;
    }
    return true;
}

//
// Create an IP-Address out of range 169.254.1.0 to 169.254.254.255
//
// @param netif network interface on which create the IP-Address
// @param ipaddr ip address to initialize
//
bool autoip_create_addr(NetIfc* netif, Ip4Addr* ipaddr)
{
    const auto autoip = netif_autoip_data(netif);
    /* Here we create an IP-Address out of range 169.254.1.0 to 169.254.254.255
      * compliant to RFC 3927 Section 2.1
      * We have 254 * 256 possibilities */
    auto addr = lwip_ntohl(LwipAutoipCreateSeedAddr(netif));
    addr += autoip->tried_llipaddr;
    addr = AUTOIP_NET | (addr & 0xffff); /* Now, 169.254.0.0 <= addr <= 169.254.255.255 */
    if (addr < AUTOIP_RANGE_START)
    {
        addr += AUTOIP_RANGE_END - AUTOIP_RANGE_START + 1;
    }
    if (addr > AUTOIP_RANGE_END)
    {
        addr -= AUTOIP_RANGE_END - AUTOIP_RANGE_START + 1;
    }
    LWIP_ASSERT("AUTOIP address not in range",
                (addr >= AUTOIP_RANGE_START) && (addr <= AUTOIP_RANGE_END));
    ip4_addr_set_u32(ipaddr, lwip_htonl(addr));

    return true;
}

//
// Sends an ARP probe from a network interface
//
// @param netif network interface used to send the probe
//
LwipError autoip_arp_probe(NetIfc* netif)
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
static LwipError
autoip_arp_announce(NetIfc* netif)
{
  return etharp_gratuitous(netif);
}

//
// Configure interface for use with current LL IP-Address
//
// @param netif network interface to configure with current LL IP-Address
//
static LwipError autoip_bind(NetIfc* netif)
{
    struct AutoipState* autoip = netif_autoip_data(netif);
    Ip4Addr sn_mask{};
    Ip4Addr gw_addr{};
    Ipv4AddrFromBytes(&sn_mask, 255, 255, 0, 0);
    Ipv4AddrFromBytes(&gw_addr, 0, 0, 0, 0);
    netif_set_addr(netif, &autoip->llipaddr, &sn_mask, &gw_addr);
    // interface is used by routing now that an address is set
    return ERR_OK;
}

/**
 * @ingroup autoip
 * Start AutoIP client
 *
 * @param netif network interface on which start the AutoIP client
 */
LwipError autoip_start(NetIfc* netif)
{
    struct AutoipState* autoip = netif_autoip_data(netif);
    LwipError result = ERR_OK;
    LWIP_ASSERT_CORE_LOCKED();
    /* Set IP-Address, Netmask and Gateway to 0 to make sure that
      * ARP Packets are formed correctly
      */
    netif_set_addr(netif, IP4_ADDR_ANY4, IP4_ADDR_ANY4, IP4_ADDR_ANY4);
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
        ip4_addr_set_zero(&autoip->llipaddr);
        autoip->lastconflict = 0;
    }
    // todo: check result
    autoip_create_addr(netif, &(autoip->llipaddr));
    // todo: check result
    autoip_start_probing(netif);
    return result;
}

static bool autoip_start_probing(NetIfc* netif)
{
    auto autoip = netif_autoip_data(netif);
    autoip->state = AUTOIP_STATE_PROBING;
    autoip->sent_num = 0; /* time to wait to first probe, this is randomly
   * chosen out of 0 to PROBE_WAIT seconds.
   * compliant to RFC 3927 Section 2.2.1
   */
    autoip->ttw = (uint16_t)(LwipAutoipRand(netif) % (PROBE_WAIT * AUTOIP_TICKS_PER_SECOND
    )); /*
   * if we tried more then MAX_CONFLICTS we must limit our rate for
   * acquiring and probing address
   * compliant to RFC 3927 Section 2.2.1
   */
    if (autoip->tried_llipaddr > MAX_CONFLICTS)
    {
        autoip->ttw = RATE_LIMIT_INTERVAL * AUTOIP_TICKS_PER_SECOND;
    }

    return true;
}

//
// Handle a possible change in the network configuration.
//
// If there is an AutoIP address configured, take the interface down
// and begin probing with the same address.
//
bool autoip_network_changed(NetIfc* netif)
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
LwipError autoip_stop(NetIfc* netif)
{
    struct AutoipState* autoip = netif_autoip_data(netif);
    LWIP_ASSERT_CORE_LOCKED();
    if (autoip != nullptr)
    {
        autoip->state = AUTOIP_STATE_OFF;
        if (ip4_addr_islinklocal(netif_ip4_addr(netif)))
        {
            netif_set_addr(netif, IP4_ADDR_ANY4, IP4_ADDR_ANY4, IP4_ADDR_ANY4);
        }
    }
    return ERR_OK;
}

//
// Has to be called in loop every AUTOIP_TMR_INTERVAL milliseconds
//
void autoip_tmr(void)
{
    // loop through netif's
    for (auto netif = netif_list; (netif) != nullptr; netif = netif->next)
    {
        auto autoip = netif_autoip_data(netif);
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
                    if (autoip->sent_num >= PROBE_NUM)
                    {
                        /* Switch to ANNOUNCING: now we can bind to an IP address and use it */
                        autoip->state = AUTOIP_STATE_ANNOUNCING;
                        autoip_bind(netif);
                        /* autoip_bind() calls netif_set_addr(): this triggers a gratuitous ARP
                                                               which counts as an announcement */
                        autoip->sent_num = 1;
                        autoip->ttw = ANNOUNCE_WAIT * AUTOIP_TICKS_PER_SECOND;
                    }
                    else
                    {
                        // todo: check the return
                        autoip_arp_probe(netif);
                        autoip->sent_num++;
                        if (autoip->sent_num == PROBE_NUM)
                        {
                            /* calculate time to wait to for announce */
                            autoip->ttw = ANNOUNCE_WAIT * AUTOIP_TICKS_PER_SECOND;
                        }
                        else
                        {
                            /* calculate time to wait to next probe */
                            autoip->ttw = uint16_t(
                                (LwipAutoipRand(netif) % ((PROBE_MAX - PROBE_MIN) * AUTOIP_TICKS_PER_SECOND)) +
                                PROBE_MIN * AUTOIP_TICKS_PER_SECOND);
                        }
                    }
                }
                break;
            case AUTOIP_STATE_ANNOUNCING:
                if (autoip->ttw == 0)
                {
                    autoip_arp_announce(netif);
                    autoip->ttw = ANNOUNCE_INTERVAL * AUTOIP_TICKS_PER_SECOND;
                    autoip->sent_num++;
                    if (autoip->sent_num >= ANNOUNCE_NUM)
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
void autoip_arp_reply(NetIfc* netif, EtharpHdr* hdr)
{
    auto autoip = netif_autoip_data(netif);
    if ((autoip != nullptr) && (autoip->state != AUTOIP_STATE_OFF))
    {
        Ip4Addr sipaddr{}; 
        /* when ip.src == llipaddr && hw.src != netif->hwaddr
         *
         * when probing  ip.dst == llipaddr && hw.src != netif->hwaddr
         * we have a conflict and must solve it
         */
        Ip4Addr dipaddr{};
        EthAddr netifaddr{};
        SMEMCPY(netifaddr.addr, netif->hwaddr, ETH_HWADDR_LEN);
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
            if ((ip4_addr_cmp(&sipaddr, &autoip->llipaddr)) || (
                ip4_addr_isany_val(sipaddr) && ip4_addr_cmp(&dipaddr, &autoip->llipaddr)
                && !eth_addr_cmp(&netifaddr, &hdr->shwaddr)))
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
            if (ip4_addr_cmp(&sipaddr, &autoip->llipaddr) && !eth_addr_cmp(
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
bool autoip_supplied_address(const NetIfc* netif)
{
    if ((netif != nullptr) && (netif_autoip_data(netif) != nullptr))
    {
        auto autoip = netif_autoip_data(netif);
        return (autoip->state == AUTOIP_STATE_BOUND) || (autoip->state ==
            AUTOIP_STATE_ANNOUNCING);
    }
    return true;
}

bool autoip_accept_packet(NetIfc* netif, const Ip4Addr* addr)
{
    const auto autoip = netif_autoip_data(netif);
    return (autoip != nullptr) && ip4_addr_cmp(addr, &(autoip->llipaddr));
}

//
// END OF FILE
//
