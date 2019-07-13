#pragma once
#include "netif.h"
#include "etharp.h"

 /* 169.254.0.0 */
constexpr auto AUTOIP_NET = 0xA9FE0000;
/* 169.254.1.0 */
constexpr auto AUTOIP_RANGE_START   =   (AUTOIP_NET | 0x0100);
/* 169.254.254.255 */
constexpr auto AUTOIP_RANGE_END   =     (AUTOIP_NET | 0xFEFF);

/* RFC 3927 Constants */
constexpr auto PROBE_WAIT = 1   /* second   (initial random delay)                 */;
constexpr auto PROBE_MIN = 1   /* second   (minimum delay till repeated probe)    */;
constexpr auto PROBE_MAX = 2   /* seconds  (maximum delay till repeated probe)    */;
constexpr auto PROBE_NUM = 3   /*          (number of probe packets)              */;
constexpr auto ANNOUNCE_NUM = 2   /*          (number of announcement packets)       */;
constexpr auto ANNOUNCE_INTERVAL = 2   /* seconds  (time between announcement packets)    */;
constexpr auto ANNOUNCE_WAIT = 2   /* seconds  (delay before announcing)              */;
constexpr auto MAX_CONFLICTS = 10  /*          (max conflicts before rate limiting)   */;
constexpr auto RATE_LIMIT_INTERVAL = 60  /* seconds  (delay between successive attempts)    */;
constexpr auto DEFEND_INTERVAL = 10  /* seconds  (min. wait between defensive ARPs)     */;

/* AutoIP client states */
typedef enum {
    AUTOIP_STATE_OFF = 0,
    AUTOIP_STATE_PROBING = 1,
    AUTOIP_STATE_ANNOUNCING = 2,
    AUTOIP_STATE_BOUND = 3
} autoip_state_enum_t;

/** AutoIP Timing */
constexpr auto AUTOIP_TMR_INTERVAL = 100;
constexpr auto  AUTOIP_TICKS_PER_SECOND = (1000 / AUTOIP_TMR_INTERVAL);

/** AutoIP state information per netif */
struct AutoipState
{
    /** the currently selected, probed, announced or used LL IP-Address */
    Ip4Addr llipaddr; /** current AutoIP state machine state */
    uint8_t state; /** sent number of probes or announces, dependent on state */
    uint8_t sent_num; /** ticks to wait, tick is AUTOIP_TMR_INTERVAL long */
    uint16_t ttw; /** ticks until a conflict can be solved by defending */
    uint8_t lastconflict; /** total number of probed/used Link Local IP-Addresses */
    uint8_t tried_llipaddr;
};

bool autoip_set_struct(NetIfc* netif, struct AutoipState *autoip);
/** Remove a struct autoip previously set to the netif using autoip_set_struct() */
LwipError autoip_start(NetIfc* netif);
LwipError autoip_stop(NetIfc* netif);
void autoip_arp_reply(NetIfc* netif, EtharpHdr* hdr);
void autoip_tmr(void);
bool autoip_network_changed(NetIfc* netif);
bool autoip_supplied_address(const NetIfc* netif);

/* for lwIP internal use by ip4.c */
bool autoip_accept_packet(NetIfc* netif, const Ip4Addr* addr);

inline AutoipState* netif_autoip_data(const NetIfc* netif)
{
    return static_cast<AutoipState*>(netif->client_data[
        LWIP_NETIF_CLIENT_DATA_INDEX_AUTOIP]);
}

//
// END OF FILE
//
