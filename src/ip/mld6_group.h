#pragma once
#include <cstdint>
#include "ip6_addr.h"

struct MldGroup;

/** MLD group */
struct MldGroup
{
    /** next link */
    struct MldGroup* next;
    /** multicast address */
    Ip6Addr group_address;
    /** signifies we were the last person to report */
    uint8_t last_reporter_flag;
    /** current state of the group */
    uint8_t group_state;
    /** timer for reporting */
    uint16_t timer;
    /** counter of simultaneous uses */
    uint8_t use;
};

//
// END OF FILE
//