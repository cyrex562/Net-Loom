//
// file: dhcp.h
//

#pragma once
#include <ip4.h>
#include <opt.h>
#include <network_interface.h>


/* DHCP message item offsets and length */
constexpr unsigned int DHCP_CHADDR_LEN = 16U;
constexpr auto DHCP_SNAME_OFS = 44U;
constexpr auto DHCP_SNAME_LEN = 64U;
constexpr auto DHCP_FILE_OFS = 108U;
constexpr auto DHCP_FILE_LEN = 128U;
constexpr auto DHCP_MSG_LEN = 236U;
constexpr auto  DHCP_OPTIONS_OFS = (DHCP_MSG_LEN + 4U); /* 4 byte: cookie */
constexpr auto DHCP_MIN_OPTIONS_LEN = 68U;

/** set this to be sufficient for your options in outgoing DHCP msgs */
constexpr auto DHCP_OPTIONS_LEN = DHCP_MIN_OPTIONS_LEN;

/** minimum set of fields of any DHCP message */
struct DhcpMsg
{
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    Ip4Addr ciaddr;
    Ip4Addr yiaddr;
    Ip4Addr siaddr;
    Ip4Addr giaddr;
    uint8_t chaddr[DHCP_CHADDR_LEN];
    uint8_t sname[DHCP_SNAME_LEN];
    uint8_t file[DHCP_FILE_LEN];
    uint32_t cookie;
    uint8_t options[DHCP_OPTIONS_LEN];
};

/* DHCP client states */
enum DhcpStateEnum
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

/* DHCP op codes */
enum DhcpOpCodes
{
    DHCP_BOOTREQUEST = 1,
    DHCP_BOOTREPLY = 2,
};


/* DHCP message types */
enum DhcpMsgTypes
{
    DHCP_DISCOVER = 1,
    DHCP_OFFER = 2,
    DHCP_REQUEST = 3,
    DHCP_DECLINE = 4,
    DHCP_ACK = 5,
    DHCP_NAK = 6,
    DHCP_RELEASE = 7,
    DHCP_INFORM = 8
};


constexpr auto DHCP_MAGIC_COOKIE = 0x63825363UL;

/* This is a list of options for BOOTP and DHCP, see RFC 2132 for descriptions */

/* BootP options */
enum DhcpOptions
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

constexpr auto DHCP_OPTION_MAX_MSG_SIZE_LEN = 2;
constexpr auto DHCP_OPTION_T1 = 58; /* T1 renewal time */
constexpr auto DHCP_OPTION_T2 = 59; /* T2 rebinding time */

/** period (in seconds) of the application calling dhcp_coarse_tmr() */
constexpr auto DHCP_COARSE_TIMER_SECS = 60;
/** period (in milliseconds) of the application calling dhcp_coarse_tmr() */
constexpr auto DHCP_COARSE_TIMER_MSECS = (DHCP_COARSE_TIMER_SECS * 1000UL);
/** period (in milliseconds) of the application calling dhcp_fine_tmr() */
constexpr auto DHCP_FINE_TIMER_MSECS =  500;

constexpr auto DHCP_BOOT_FILE_LEN   =  128U;

/* AutoIP cooperation flags (struct dhcp.autoip_coop_state) */
enum DhcpAutoipCoopStateEnumT
{
    DHCP_AUTOIP_COOP_STATE_OFF = 0,
    DHCP_AUTOIP_COOP_STATE_ON = 1
};

struct DhcpContext
{
    /** transaction identifier of last sent request */
    uint32_t xid;
    /** track PCB allocation state */
    uint8_t pcb_allocated;
    /** current DHCP state machine state */
    uint8_t state;
    /** retries of current request */
    uint8_t tries;
    uint8_t autoip_coop_state;
    uint8_t subnet_mask_given;

    uint16_t request_timeout; /* #ticks with period DHCP_FINE_TIMER_SECS for request timeout */
    uint16_t t1_timeout; /* #ticks with period DHCP_COARSE_TIMER_SECS for renewal time */
    uint16_t t2_timeout; /* #ticks with period DHCP_COARSE_TIMER_SECS for rebind time */
    uint16_t t1_renew_time; /* #ticks with period DHCP_COARSE_TIMER_SECS until next renew try */
    uint16_t t2_rebind_time; /* #ticks with period DHCP_COARSE_TIMER_SECS until next rebind try */
    uint16_t lease_used; /* #ticks with period DHCP_COARSE_TIMER_SECS since last received DHCP ack */
    uint16_t t0_timeout; /* #ticks with period DHCP_COARSE_TIMER_SECS for lease time */
    IpAddr server_ip_addr; /* dhcp server address that offered this lease (IpAddr because passed to UDP) */
    Ip4Addr offered_ip_addr;
    Ip4Addr offered_sn_mask;
    Ip4Addr offered_gw_addr;

    uint32_t offered_t0_lease; /* lease period (in seconds) */
    uint32_t offered_t1_renew; /* recommended renew time (usually 50% of lease period) */
    uint32_t offered_t2_rebind; /* recommended rebind time (usually 87.5 of lease period)  */
    Ip4Addr offered_si_addr;
    char boot_file_name[DHCP_BOOT_FILE_LEN];

    uint8_t dhcp_options[0xff];
};


void dhcp_set_struct(struct NetworkInterface *netif, struct DhcpContext *dhcp);
/** Remove a struct dhcp previously set to the netif using dhcp_set_struct() */
// #define dhcp_remove_struct(netif) netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_DHCP, NULL)
// void dhcp_cleanup(NetworkInterface* netif);
LwipStatus dhcp_start(NetworkInterface* netif);
LwipStatus dhcp_renew(NetworkInterface* netif);
LwipStatus dhcp_release(NetworkInterface* netif);
void dhcp_stop(NetworkInterface* netif);
void dhcp_release_and_stop(NetworkInterface* netif);
void dhcp_inform(NetworkInterface* netif);
void dhcp_network_changed(NetworkInterface* netif);
void dhcp_arp_reply(NetworkInterface* netif, const Ip4Addr* addr);
uint8_t dhcp_supplied_address(const NetworkInterface* netif);
/* to be called every minute */
void dhcp_coarse_tmr();
/* to be called every half second */
void dhcp_fine_tmr();

/** This function must exist, in other to add offered NTP servers to
 * the NTP (or SNTP) engine.
 * See LWIP_DHCP_MAX_NTP_SERVERS */
extern void dhcp_set_ntp_servers(uint8_t num_ntp_servers, const Ip4Addr* ntp_server_addrs);


inline DhcpContext* get_netif_dhcp_ctx(const NetworkInterface* netif)
{
    // return static_cast<DhcpContext*>(netif->client_data[LWIP_NETIF_CLIENT_DATA_INDEX_DHCP]);
}

