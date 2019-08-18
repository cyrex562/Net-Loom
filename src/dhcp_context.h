#pragma once
#include <cstdint>
#include "ip4_addr.h"


struct DhcpContext
{
    /** transaction identifier of last sent request */
    uint32_t xid; /** track PCB allocation state */
    uint8_t pcb_allocated; /** current DHCP state machine state */
    uint8_t state; /** retries of current request */
    uint8_t tries;

    uint8_t autoip_coop_state;

    uint8_t subnet_mask_given;

    uint16_t request_timeout;

    /* #ticks with period DHCP_FINE_TIMER_SECS for request timeout */
    uint16_t t1_timeout; /* #ticks with period DHCP_COARSE_TIMER_SECS for renewal time */
    uint16_t t2_timeout; /* #ticks with period DHCP_COARSE_TIMER_SECS for rebind time */
    uint16_t t1_renew_time;

    /* #ticks with period DHCP_COARSE_TIMER_SECS until next renew try */
    uint16_t t2_rebind_time;

    /* #ticks with period DHCP_COARSE_TIMER_SECS until next rebind try */
    uint16_t lease_used;

    /* #ticks with period DHCP_COARSE_TIMER_SECS since last received DHCP ack */
    uint16_t t0_timeout; /* #ticks with period DHCP_COARSE_TIMER_SECS for lease time */
    Ip4Addr server_ip_addr;

    /* dhcp server address that offered this lease (IpAddr because passed to UDP) */
    Ip4Addr offered_ip_addr;

    Ip4Addr offered_sn_mask;

    Ip4Addr offered_gw_addr;

    uint32_t offered_t0_lease; /* lease period (in seconds) */
    uint32_t offered_t1_renew; /* recommended renew time (usually 50% of lease period) */
    uint32_t offered_t2_rebind;

    /* recommended rebind time (usually 87.5 of lease period)  */
    Ip4Addr offered_si_addr;

    std::string boot_file_name;

    uint8_t dhcp_options[0xff];
};


//
//
//