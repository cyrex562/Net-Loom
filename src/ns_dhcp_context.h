#pragma once
#include "ns_ip4_addr.h"
#include <cstdint>
#include "uuid.h"


/* DHCP client states */
enum DhcpState
{
    DHCP_STATE_OFF = 0,
    DHCP_STATE_REQUESTING = 1,
    DHCP_STATE_INIT = 2,
    DHCP_STATE_REBOOTING = 3,
    DHCP_STATE_REBINDING = 4,
    DHCP_STATE_RENEWING = 5,
    DHCP_STATE_SELECTING = 6,
    DHCP_STATE_INFORMING = 7,
    DHCP_STATE_CHECKING = 8,
    DHCP_STATE_PERMANENT = 9,
    /* not yet implemented */
    DHCP_STATE_BOUND = 10,
    DHCP_STATE_RELEASING = 11,
    /* not yet implemented */
    DHCP_STATE_BACKING_OFF = 12
};


/* BootP options */
enum DhcpOptionType
{
    DHCP_OPTION_PAD = 0,
    DHCP_OPTION_SUBNET_MASK = 1, /* RFC 2132 3.3 */
    DHCP_OPTION_ROUTER = 3,
    DHCP_OPTION_DNS_SERVER = 6,
    DHCP_OPTION_HOSTNAME = 12,
    DHCP_OPTION_IP_TTL = 23,
    DHCP_OPTION_MTU = 26,
    DHCP_OPTION_BROADCAST = 28,
    DHCP_OPTION_TCP_TTL = 37,
    DHCP_OPTION_NTP = 42,
    DHCP_OPTION_END = 255,
    /* DHCP options */
    DHCP_OPTION_REQUESTED_IP = 50, /* RFC 2132 9.1, requested IP address */
    DHCP_OPTION_LEASE_TIME = 51, /* RFC 2132 9.2, time in seconds, in 4 bytes */
    DHCP_OPTION_OVERLOAD = 52, /* RFC2132 9.3, use file and/or sname field for options */
    DHCP_OPTION_MESSAGE_TYPE = 53, /* RFC 2132 9.6, important for DHCP */
    DHCP_OPTION_MESSAGE_TYPE_LEN = 1,
    DHCP_OPTION_SERVER_ID = 54, /* RFC 2132 9.7, server IP address */
    DHCP_OPTION_PARAMETER_REQUEST_LIST = 55, /* RFC 2132 9.8, requested option types */
    DHCP_OPTION_MAX_MSG_SIZE = 57, /* RFC 2132 9.10, message size accepted >= 576 */
    DHCP_OPTION_US = 60,
    DHCP_OPTION_CLIENT_ID = 61,
    DHCP_OPTION_TFTP_SERVERNAME = 66,
    DHCP_OPTION_BOOTFILE = 67,
    /* possible combinations of overloading the file and sname fields with options */
    DHCP_OVERLOAD_NONE = 0,
    DHCP_OVERLOAD_FILE = 1,
    DHCP_OVERLOAD_SNAME = 2,
    DHCP_OVERLOAD_SNAME_FILE = 3,
};


struct DhcpOption
{
    DhcpOptionType option_type;
    size_t len;
    std::vector<uint8_t> value;
};


/* AutoIP cooperation flags (struct dhcp.autoip_coop_state) */
enum DhcpAutoIpCoopState
{
    DHCP_AUTOIP_COOP_STATE_OFF = 0,
    DHCP_AUTOIP_COOP_STATE_ON = 1
};


struct DhcpContext
{
    /** transaction identifier of last sent request */
    uint32_t xid;
    /** track PCB allocation state */
    bool pcb_allocated;
    /** current DHCP state machine state */
    DhcpState state;
    /** retries of current request */
    uint32_t tries;
    DhcpAutoIpCoopState autoip_coop_state;
    bool subnet_mask_given;
    uint32_t ref_cnt;
    uint64_t request_timeout;
    /* #ticks with period DHCP_FINE_TIMER_SECS for request timeout */
    uint64_t t1_timeout;
    /* #ticks with period DHCP_COARSE_TIMER_SECS for renewal time */
    uint64_t t2_timeout;
    /* #ticks with period DHCP_COARSE_TIMER_SECS for rebind time */
    uint64_t t1_renew_time;
    /* #ticks with period DHCP_COARSE_TIMER_SECS until next renew try */
    uint64_t t2_rebind_time;
    /* #ticks with period DHCP_COARSE_TIMER_SECS until next rebind try */
    uint64_t lease_used;
    /* #ticks with period DHCP_COARSE_TIMER_SECS since last received DHCP ack */
    uint64_t t0_timeout;
    /* #ticks with period DHCP_COARSE_TIMER_SECS for lease time */
    /* dhcp server address that offered this lease (IpAddr because passed to UDP) */
    Ip4Addr server_ip_addr;
    Ip4Addr offered_ip_addr;
    Ip4Addr offered_sn_mask;
    Ip4Addr offered_gw_addr;
    /* lease period (in seconds) */
    uint64_t offered_t0_lease;
    /* recommended renew time (usually 50% of lease period) */
    uint64_t offered_t1_renew;
    /* recommended rebind time (usually 87.5 of lease period)  */
    uint64_t offered_t2_rebind;
    Ip4Addr offered_si_addr;
    std::string boot_file_name;
    std::vector<DhcpOptionType> options;
    uint8_t socket_options;
    uint8_t ttl;
    uint8_t mcast_ttl;
    uuids::uuid id;
};

//
// END OF FILE
//
