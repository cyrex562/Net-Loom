#pragma once
#include "ip4_addr.h"
#include <cstdint>

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

//
// END OF FILE
//