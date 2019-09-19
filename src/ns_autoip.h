#pragma once
#include "ns_etharp.h"
#include "ns_network_interface.h"
#include "ns_auto_ip_state.h"
#include "ns_ip4_addr.h"
#include "ns_mac_address.h"
#include "ns_def.h"
#include "ns_util.h"

/* 169.254.0.0 */
constexpr auto IP4_AUTO_IP_NET = 0xA9FE0000;
/* 169.254.1.0 */
constexpr auto AUTOIP_RANGE_START   =   (IP4_AUTO_IP_NET | 0x0100);
/* 169.254.254.255 */
constexpr auto IP4_AUTO_IP_RANGE_END   =     (IP4_AUTO_IP_NET | 0xFEFF);

/* RFC 3927 Constants */
constexpr auto AUTO_IP_PROBE_WAIT = 1   /* second   (initial random delay)                 */;
constexpr auto AUTO_IP_PROBE_MIN = 1   /* second   (minimum delay till repeated probe)    */;
constexpr auto AUTO_IP_PROBE_MAX = 2   /* seconds  (maximum delay till repeated probe)    */;
constexpr auto AUTO_IP_PROBE_NUM = 3   /*          (number of probe packets)              */;
constexpr auto AUTO_IP_ANNOUNCE_NUM = 2   /*          (number of announcement packets)       */;
constexpr auto AUTO_IP_ANNOUNCE_INTERVAL = 2   /* seconds  (time between announcement packets)    */;
constexpr auto AUTO_IP_ANNOUNCE_WAIT = 2   /* seconds  (delay before announcing)              */;
constexpr auto AUTO_IP_MAX_CONFLICTS = 10  /*          (max conflicts before rate limiting)   */;
constexpr auto AUTO_IP_RATE_LIMIT_INTERVAL = 60  /* seconds  (delay between successive attempts)    */;
constexpr auto AUTO_IP_DEFEND_INTERVAL = 10  /* seconds  (min. wait between defensive ARPs)     */;

/* AutoIP client states */
enum AutoIpStateEnum{
    AUTOIP_STATE_OFF = 0,
    AUTOIP_STATE_PROBING = 1,
    AUTOIP_STATE_ANNOUNCING = 2,
    AUTOIP_STATE_BOUND = 3
};

/** AutoIP Timing */
constexpr auto AUTO_IP_TIMER_INTERVAL = 100;
constexpr auto  AUTO_IP_TICKS_PER_SEC = (1000 / AUTO_IP_TIMER_INTERVAL);

/** Remove a struct autoip previously set to the netif using autoip_set_struct() */
bool
autoip_start(NetworkInterface& netif, AutoipState& state);


bool
autoip_stop(NetworkInterface& netif, AutoipState& autoip);


bool
autoip_arp_reply(NetworkInterface& netif, EtharpHdr& hdr, AutoipState& state);
void autoip_tmr(void);
bool autoip_network_changed(NetworkInterface& netif, AutoipState& state);
bool autoip_supplied_address(const NetworkInterface& netif, AutoipState& autoip);

/* for lwIP internal use by ip4.c */
bool autoip_accept_packet(NetworkInterface& netif, AutoipState& state, const Ip4Addr& addr);


bool
autoip_arp_announce(NetworkInterface& netif, Ip4Addr& announce_ip_addr);
bool autoip_start_probing(NetworkInterface& netif, AutoipState& state);


// inline AutoipState
// netif_autoip_data(const NetworkInterface& netif)
// {
//     return netif.auto_ip_state;
// }


/**
 * Pseudo random macro based on netif informations. You could use "rand()" from the C Library if you define LWIP_AUTOIP_RAND in lwipopts.h
 */
inline uint32_t
autoip_gen_rand(NetworkInterface& netif, AutoipState& state);

/**
 * Macro that generates the initial IP address to be tried by AUTOIP. If you want to
 * override this, define it to something else in lwipopts.h.
 */
inline uint32_t
autoip_gen_seed_addr(NetworkInterface& netif)
{
    return lwip_htonl(AUTOIP_RANGE_START + uint32_t(
        uint8_t(netif.mac_address.bytes[4]) | uint32_t(
            uint8_t(netif.mac_address.bytes[5])) << 8));
}

//
// END OF FILE
//
