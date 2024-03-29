#pragma once
#include <etharp.h>
#include <network_interface.h>


/* 169.254.0.0 */
constexpr auto kAutoipNet = 0xA9FE0000;
/* 169.254.1.0 */
constexpr auto kAutoipRangeStart   =   (kAutoipNet | 0x0100);
/* 169.254.254.255 */
constexpr auto kAutoipRangeEnd   =     (kAutoipNet | 0xFEFF);

/* RFC 3927 Constants */
constexpr auto kProbeWait = 1   /* second   (initial random delay)                 */;
constexpr auto kProbeMin = 1   /* second   (minimum delay till repeated probe)    */;
constexpr auto kProbeMax = 2   /* seconds  (maximum delay till repeated probe)    */;
constexpr auto kProbeNum = 3   /*          (number of probe packets)              */;
constexpr auto kAnnounceNum = 2   /*          (number of announcement packets)       */;
constexpr auto kAnnounceInterval = 2   /* seconds  (time between announcement packets)    */;
constexpr auto kAnnounceWait = 2   /* seconds  (delay before announcing)              */;
constexpr auto kMaxConflicts = 10  /*          (max conflicts before rate limiting)   */;
constexpr auto kRateLimitInterval = 60  /* seconds  (delay between successive attempts)    */;
constexpr auto kDefendInterval = 10  /* seconds  (min. wait between defensive ARPs)     */;

/* AutoIP client states */
enum AutoIpStateEnum{
    AUTOIP_STATE_OFF = 0,
    AUTOIP_STATE_PROBING = 1,
    AUTOIP_STATE_ANNOUNCING = 2,
    AUTOIP_STATE_BOUND = 3
};

/** AutoIP Timing */
constexpr auto kAutoipTmrInterval = 100;
constexpr auto  kAutoipTicksPerSecond = (1000 / kAutoipTmrInterval);



bool autoip_set_struct(NetworkInterface* netif, struct AutoipState *autoip);
/** Remove a struct autoip previously set to the netif using autoip_set_struct() */
LwipStatus autoip_start(NetworkInterface* netif);
LwipStatus autoip_stop(NetworkInterface& netif);
void autoip_arp_reply(NetworkInterface* netif, EtharpHdr* hdr);
void autoip_tmr(void);
bool autoip_network_changed(NetworkInterface* netif);
bool autoip_supplied_address(const NetworkInterface* netif);

/* for lwIP internal use by ip4.c */
bool autoip_accept_packet(NetworkInterface& netif, const Ip4Addr& addr);

inline AutoipState
netif_autoip_data(const NetworkInterface& netif)
{

    return netif.auto_ip_state;
}

//
// END OF FILE
//
