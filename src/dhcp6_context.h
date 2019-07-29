#pragma once
#include <cstdint>


struct Dhcp6Context
{
    /** transaction identifier of last sent request */
    uint32_t xid; /** track PCB allocation state */
    uint8_t pcb_allocated; /** current DHCPv6 state machine state */
    uint8_t state; /** retries of current request */
    uint8_t tries;
    /** if request config is triggered while another action is active, this keeps track of it */
    uint8_t request_config_pending;
    /** #ticks with period DHCP6_TIMER_MSECS for request timeout */
    uint16_t request_timeout;
    /* @todo: add more members here to keep track of stateful DHCPv6 data, like lease times */
};

//
//
//