#pragma once

#include "ip4_addr.h"

#include <cstdint>


//
// igmp group structure - there is
// a list of groups for each interface
// these should really be linked from the interface, but
// if we keep them separate we will not affect the ns original code
// too much
//
// There will be a group for the all systems group address but this
// will not run the state machine as it is used to kick off reports
// from all the other groups
//
struct IgmpGroup
{
    /** next link */
    // struct IgmpGroup* next;
    /** multicast address */
    Ip4Addr group_address;
    /** signifies we were the last person to report */
    uint8_t last_reporter_flag;
    /** current state of the group */
    uint8_t group_state;
    /** timer for reporting, negative is OFF */
    uint16_t timer;
    /** counter of simultaneous uses */
    uint8_t use;
};

//
// END OF FILE
//