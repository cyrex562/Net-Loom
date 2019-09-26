//
// file: dhcp.h
//
#pragma once
#include "ip4.h"
#include "netloom_config.h"
#include "network_interface.h"
#include "udp.h"
#include "eth_arp.h"
#include "uuid.h"

/* DHCP message item offsets and length */
constexpr unsigned int DHCP_CHADDR_LEN = 16U;
constexpr auto DHCP_SNAME_OFS = 44U;
constexpr auto DHCP_SNAME_LEN = 64U;
constexpr auto DHCP_FILE_OFS = 108U;
constexpr auto DHCP_FILE_LEN = 128U;
constexpr auto DHCP_MSG_LEN = 236U;
constexpr auto DHCP_OPTIONS_OFS = (DHCP_MSG_LEN + 4U); /* 4 byte: cookie */
constexpr auto DHCP_MIN_OPTIONS_LEN = 68U;
constexpr auto MAX_TRIES = 255;
constexpr auto MILLIS_PER_SEC = 1000;
constexpr auto K_DHCP_MAX_MSG_LEN_MIN_REQUIRED = 576;
/** Minimum length for reply before packet is parsed */
constexpr auto K_DHCP_MIN_REPLY_LEN = 44;
constexpr auto K_REBOOT_TRIES = 2;
/** set this to be sufficient for your options in outgoing DHCP msgs */
constexpr auto DHCP_OPTIONS_LEN = DHCP_MIN_OPTIONS_LEN;


/* DHCP op codes */
enum DhcpOpCode
{
    DHCP_BOOTREQUEST = 1,
    DHCP_BOOTREPLY = 2,
};


/* DHCP message types */
enum DhcpMessageType
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




/** Option handling: options are parsed in dhcp_parse_reply
 * and saved in an array where other functions can load them from.
 * This might be moved into the struct dhcp (not necessarily since
 * lwIP is single-threaded and the array is only used while in recv
 * callback). */
enum DhcpOptionIdx
{
    DHCP_OPTION_IDX_OVERLOAD = 0,
    DHCP_OPTION_IDX_MSG_TYPE,
    DHCP_OPTION_IDX_SERVER_ID,
    DHCP_OPTION_IDX_LEASE_TIME,
    DHCP_OPTION_IDX_T1,
    DHCP_OPTION_IDX_T2,
    DHCP_OPTION_IDX_SUBNET_MASK,
    DHCP_OPTION_IDX_ROUTER,
    DHCP_OPTION_IDX_DNS_SERVER,
    DHCP_OPTION_IDX_DNS_SERVER_LAST = DHCP_OPTION_IDX_DNS_SERVER - 1,
    DHCP_OPTION_IDX_NTP_SERVER,
    DHCP_OPTION_IDX_NTP_SERVER_LAST = DHCP_OPTION_IDX_NTP_SERVER +
    LWIP_DHCP_MAX_NTP_SERVERS - 1,
    DHCP_OPTION_IDX_MAX
};

/** Holds the decoded option values, only valid while in dhcp_recv.
    @todo: move this into struct dhcp? */
//uint32_t dhcp_rx_options_val[DHCP_OPTION_IDX_MAX];
/** Holds a flag which option was received and is contained in dhcp_rx_options_val,
   only valid while in dhcp_recv.
   @todo: move this into struct dhcp? */
//uint8_t dhcp_rx_options_given[DHCP_OPTION_IDX_MAX];
static uint8_t dhcp_discover_request_options[] = {
    DHCP_OPTION_SUBNET_MASK, DHCP_OPTION_ROUTER, DHCP_OPTION_BROADCAST,
    DHCP_OPTION_DNS_SERVER, DHCP_OPTION_NTP
};
constexpr auto DHCP_MAGIC_COOKIE = 0x63825363UL;

/* This is a list of options for BOOTP and DHCP, see RFC 2132 for descriptions */
constexpr auto DHCP_OPTION_MAX_MSG_SIZE_LEN = 2;
constexpr auto DHCP_OPTION_T1 = 58; /* T1 renewal time */
constexpr auto DHCP_OPTION_T2 = 59; /* T2 rebinding time */
/** period (in seconds) of the application calling dhcp_coarse_tmr() */
constexpr auto DHCP_COARSE_TIMER_SECS = 60;
/** period (in milliseconds) of the application calling dhcp_coarse_tmr() */
constexpr auto DHCP_COARSE_TIMER_MSECS = (DHCP_COARSE_TIMER_SECS * 1000UL);
/** period (in milliseconds) of the application calling dhcp_fine_tmr() */
constexpr auto DHCP_FINE_TIMER_MSECS = 500;
constexpr auto DHCP_BOOT_FILE_LEN = 128U;




/** minimum set of fields of any DHCP message */
struct DhcpMessage
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


void
dhcp_set_struct(struct NetworkInterface* netif, struct DhcpContext* dhcp);
/** Remove a struct dhcp previously set to the netif using dhcp_set_struct() */
// #define dhcp_remove_struct(netif) netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_DHCP, NULL)
// void dhcp_cleanup(NetworkInterface* netif);
bool
dhcp_start(NetworkInterface& netif, uint32_t dhcp_pcb_ref_cnt);

NsStatus
dhcp_renew(NetworkInterface* netif);

NsStatus
dhcp_release(NetworkInterface* netif);

void
dhcp_stop(NetworkInterface* netif);

void
dhcp_release_and_stop(NetworkInterface* netif);

bool
dhcp_inform(NetworkInterface& netif, uint32_t dhcp_pcb_ref_cnt);

void
dhcp_network_changed(NetworkInterface* netif);

bool
dhcp_arp_reply(NetworkInterface& netif, const Ip4Addr& addr, DhcpContext& ctx);

uint8_t
dhcp_supplied_address(const NetworkInterface* netif);
/* to be called every minute */
void
dhcp_coarse_timer(std::vector<NetworkInterface>& netifs, std::vector<DhcpContext>& dhcp_contexts);
/* to be called every half second */
void
dhcp_fine_tmr();

/** This function must exist, in other to add offered NTP servers to
 * the NTP (or SNTP) engine.
 * See LWIP_DHCP_MAX_NTP_SERVERS */
extern void
dhcp_set_ntp_servers(uint8_t num_ntp_servers, const Ip4Addr* ntp_server_addrs);




// static uint32_t xid;
// static uint8_t xid_initialised;
inline bool
dhcp_option_given(std::vector<DhcpOptionType> dhcp_options, DhcpOptionIdx idx)
{
    return dhcp_options[idx] != 0;
}


inline bool
dhcp_got_option(uint8_t* dhcp_options, size_t idx) { return dhcp_options[idx] == 1; }


inline void
dhcp_clear_option(uint8_t* dhcp_options, size_t idx) { dhcp_options[idx] = 0; }


inline void
dhcp_clear_all_options(uint8_t* dhcp_options, size_t element_count)
{
    memset(dhcp_options, 0, element_count);
}


inline uint8_t
dhcp_get_option_value(std::vector<DhcpOptionType>& dhcp_options, DhcpOptionIdx idx)
{
    return dhcp_options[idx];
}







inline void
dhcp_set_option_value(uint8_t* dhcp_options, size_t idx, uint8_t val)
{
    dhcp_options[idx] = val;
}

// static UdpPcb* dhcp_pcb;
// static uint8_t dhcp_pcb_refcount;
/* DHCP client state machine functions */
bool
dhcp_discover(NetworkInterface& netif, DhcpContext& ctx);

bool
dhcp_select(NetworkInterface& netif, DhcpContext& dhcp);

bool
dhcp_bind(NetworkInterface& netif, DhcpContext& dhcp);

NsStatus
dhcp_decline(NetworkInterface* netif);

NsStatus
dhcp_rebind(NetworkInterface* netif);

NsStatus
dhcp_reboot(NetworkInterface* netif);

void
dhcp_set_state(DhcpContext& dhcp, DhcpState new_state);

/* receive, unfold, parse and free incoming messages */
void
dhcp_recv(PacketContainer& p,
          const IpAddrInfo& addr,
          uint16_t port,
          NetworkInterface& netif,
          DhcpContext& dhcp);

/* set the DHCP timers */
bool
dhcp_timeout(NetworkInterface& netif,
             DhcpContext& dhcp,
             std::vector<EtharpEntry>& etharp_entries);

void
dhcp_t1_timeout(NetworkInterface* netif);

void
dhcp_t2_timeout(NetworkInterface* netif);

/* build outgoing messages */
/* create a DHCP message, fill in common headers */
std::tuple<DhcpMessage, size_t>
dhcp_create_msg(NetworkInterface& netif, DhcpContext& dhcp, DhcpMessageType message_type);


/* add a DHCP option (type, then length in bytes) */
void
dhcp_option(std::vector<DhcpOption>& options,
            DhcpOptionType option_type,
            uint8_t option_len);
/* add option values */
uint16_t
dhcp_option_byte(std::vector<DhcpOption>& options, uint8_t value);

uint16_t
dhcp_option_short(uint16_t options_out_len, uint8_t* options, uint16_t value);

uint16_t
dhcp_option_long(uint16_t options_out_len, uint8_t* options, uint32_t value);

uint16_t
dhcp_option_hostname(std::vector<DhcpOptionType>& options, NetworkInterface& netif);
/* always add the DHCP options trailer to end and pad */
void
dhcp_option_trailer(uint16_t options_out_len,
                    uint8_t* options,
                    struct PacketContainer* p_out);

bool
dhcp_inc_pcb_refcount(DhcpContext& ctx,
                      uint32_t dhcp_pcb_refcount,
                      NetworkInterface& netif);

NsStatus
dhcp_remove(DhcpContext& ctx, std::vector<DhcpContext>& dhcp_contexts);

//
// END OF FILE
//
