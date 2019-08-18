///
/// file: dhcp6.h
///
#pragma once
#include <lwip_status.h>
#include <network_interface.h>
#include <dhcp6_context.h>
#include <cstdint>

constexpr auto DHCP6_CLIENT_PORT = 546;
constexpr auto DHCP6_SERVER_PORT = 547;
constexpr auto DHCP6_TRANSACTION_ID_LEN = 3;



///
 enum Dhcp6States{
    DHCP6_STATE_OFF = 0,
    DHCP6_STATE_STATELESS_IDLE = 1,
    DHCP6_STATE_REQUESTING_CONFIG = 2
} ;

/** Option handling: options are parsed in dhcp6_parse_reply
 * and saved in an array where other functions can load them from.
 * This might be moved into the Dhcp6 (not necessarily since
 * lwIP is single-threaded and the array is only used while in recv
 * callback). */
enum Dhcp6OptionIdx {
  DHCP6_OPTION_IDX_CLI_ID = 0,
  DHCP6_OPTION_IDX_SERVER_ID,
  DHCP6_OPTION_IDX_DNS_SERVER,
  DHCP6_OPTION_IDX_DOMAIN_LIST,
  DHCP6_OPTION_IDX_NTP_SERVER,
  DHCP6_OPTION_IDX_MAX
};

/** DHCPv6 message types */
enum Dhcp6MessageType
{
    DHCP6_SOLICIT = 1,
    DHCP6_ADVERTISE = 2,
    DHCP6_REQUEST = 3,
    DHCP6_CONFIRM = 4,
    DHCP6_RENEW = 5,
    DHCP6_REBIND = 6,
    DHCP6_REPLY = 7,
    DHCP6_RELEASE = 8,
    DHCP6_DECLINE = 9,
    DHCP6_RECONFIGURE = 10,
    DHCP6_INFOREQUEST = 11,
    DHCP6_RELAYFORW = 12,
    DHCP6_RELAYREPL = 13,
};

/* More message types see https://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xhtml */

/** DHCPv6 status codes */
enum Dhcp6StatusCode
{
    DHCP6_STATUS_SUCCESS = 0,
    /* Success. */
    DHCP6_STATUS_UNSPECFAIL = 1,
    /* Failure, reason unspecified; this status code is sent by either a client or a server to indicate a failure not explicitly specified in this document. */
    DHCP6_STATUS_NOADDRSAVAIL = 2,
    /* Server has no addresses available to assign to the IA(s). */
    DHCP6_STATUS_NOBINDING = 3,
    /* Client record (binding) unavailable. */
    DHCP6_STATUS_NOTONLINK = 4,
    /* The prefix for the address is not appropriate for the link to which the client is attached. */
    DHCP6_STATUS_USEMULTICAST = 5,
    /* Sent by a server to a client to force the client to send messages to the server using the All_DHCP_Relay_Agents_and_Servers address. */
    /* More status codes see https://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xhtml */
};

/** DHCPv6 DUID types */
enum Dhcp6DuidType
{
    DHCP6_DUID_LLT = 1,
    /* LLT: Link-layer Address Plus Time */
    DHCP6_DUID_EN = 2,
    /* EN: Enterprise number */
    DHCP6_DUID_LL = 3,
    /* LL: Link-layer Address */
    DHCP6_DUID_UUID = 4,
    /* UUID (RFC 6355) */
};


/* DHCPv6 options */
enum Dhcp6Options
{
    DHCP6_OPTION_CLIENTID = 1,
    DHCP6_OPTION_SERVERID = 2,
    DHCP6_OPTION_IA_NA = 3,
    DHCP6_OPTION_IA_TA = 4,
    DHCP6_OPTION_IAADDR = 5,
    DHCP6_OPTION_ORO = 6,
    DHCP6_OPTION_PREFERENCE = 7,
    DHCP6_OPTION_ELAPSED_TIME = 8,
    DHCP6_OPTION_RELAY_MSG = 9,
    DHCP6_OPTION_AUTH = 11,
    DHCP6_OPTION_UNICAST = 12,
    DHCP6_OPTION_STATUS_CODE = 13,
    DHCP6_OPTION_RAPID_COMMIT = 14,
    DHCP6_OPTION_USER_CLASS = 15,
    DHCP6_OPTION_VENDOR_CLASS = 16,
    DHCP6_OPTION_VENDOR_OPTS = 17,
    DHCP6_OPTION_INTERFACE_ID = 18,
    DHCP6_OPTION_RECONF_MSG = 19,
    DHCP6_OPTION_RECONF_ACCEPT = 20,
    /* More options see https://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xhtml */
    DHCP6_OPTION_DNS_SERVERS = 23,
    /* RFC 3646 */
    DHCP6_OPTION_DOMAIN_LIST = 24,
    /* RFC 3646 */
    DHCP6_OPTION_SNTP_SERVERS = 31,
    /* RFC 4075 */
};

/** period (in milliseconds) of the application calling dhcp6_tmr() */
constexpr auto DHCP6_TIMER_MSECS = 500;

///
struct Dhcp6Msg
{
    uint8_t msgtype;
    uint8_t transaction_id[DHCP6_TRANSACTION_ID_LEN];
};





void dhcp6_set_struct(NetworkInterface*netif, struct Dhcp6Context *dhcp6);
/** Remove a Dhcp6 previously set to the netif using dhcp6_set_struct() */

// #define dhcp6_remove_struct(netif) netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_DHCP6, NULL)


/**
 *
 */
inline Dhcp6Context
get_netif_dhcp6_ctx(NetworkInterface& netif)
{
    return netif.dhcp6_ctx;
}


/**
 *
 */
inline bool
dhcp6_option_given(Dhcp6Context& dhcp6, const size_t idx)
{
    return dhcp6.dhcp6_rx_options[idx].option_given != 0;
}


/**
 *
 */
inline bool
dhcp6_got_option(Dhcp6Context& dhcp6, const size_t idx)
{
    return (dhcp6.dhcp6_rx_options[idx].option_given = 1);
}


/**
 *
 */
inline bool
dhcp6_clear_option(Dhcp6Context& dhcp6, const size_t idx)
{
    return (dhcp6.dhcp6_rx_options[idx].option_given = 0);
}


/**
 *
 */
inline size_t
dhcp6_get_option_start(Dhcp6Context& dhcp6, size_t idx)
{
    return (dhcp6.dhcp6_rx_options[idx].val_start);
}


/**
 *
 */
inline size_t
dhcp6_get_option_length(Dhcp6Context& dhcp6, size_t idx)
{
    return (dhcp6.dhcp6_rx_options[idx].val_length);
}


/**
 *
 */
inline void
dhcp6_set_option(Dhcp6Context& dhcp, const size_t idx, const size_t start, const size_t len)
{
    dhcp.dhcp6_rx_options[idx].val_start = (start);
    dhcp.dhcp6_rx_options[idx].val_length = (len);
}


void dhcp6_cleanup(NetworkInterface*netif);

LwipStatus dhcp6_enable_stateful(NetworkInterface*netif);
LwipStatus dhcp6_enable_stateless(NetworkInterface*netif);
void dhcp6_disable(NetworkInterface*netif);

void dhcp6_tmr();

void dhcp6_nd6_ra_trigger(NetworkInterface*netif, uint8_t managed_addr_config, uint8_t other_config);

/** This function must exist, in other to add offered NTP servers to
 * the NTP (or SNTP) engine.
 * See LWIP_DHCP6_MAX_NTP_SERVERS */
void dhcp6_set_ntp_servers(uint8_t num_ntp_servers, const IpAddrInfo* ntp_server_addrs);


/* receive, unfold, parse and free incoming messages */
void
dhcp6_recv(uint8_t* arg,
           struct UdpPcb* pcb,
           struct PacketBuffer* p,
           const IpAddrInfo* addr,
           uint16_t port,
           NetworkInterface* netif);

static LwipStatus dhcp6_inc_pcb_refcount();

static void
dhcp6_dec_pcb_refcount();



static struct Dhcp6Context* dhcp6_get_struct(NetworkInterface* netif, const char* dbg_requester);

static void
dhcp6_set_state(struct Dhcp6Context *dhcp6, uint8_t new_state, const char *dbg_caller);

static int
dhcp6_stateless_enabled(struct Dhcp6Context *dhcp6);





static struct PacketBuffer* dhcp6_create_msg(NetworkInterface* netif,
                                     struct Dhcp6Context* dhcp6,
                                     uint8_t message_type,
                                     uint16_t opt_len_alloc,
                                     uint16_t* options_out_len);

static uint16_t dhcp6_option_short(uint16_t options_out_len,
                                   uint8_t* options,
                                   uint16_t value);

static uint16_t dhcp6_option_optionrequest(size_t options_out_len,
                                           uint8_t* options,
                                           const uint16_t* req_options,
                                           uint32_t num_req_options,
                                           size_t max_len);

static void
dhcp6_msg_finalize(uint16_t options_out_len, struct PacketBuffer *p_out);

static void
dhcp6_information_request(NetworkInterface* netif, Dhcp6Context* dhcp6);

static LwipStatus
dhcp6_request_config(NetworkInterface*netif, Dhcp6Context *dhcp6);

static void
dhcp6_abort_config_request(Dhcp6Context *dhcp6);

static void
dhcp6_handle_config_reply(NetworkInterface* netif, struct PacketBuffer* p_msg_in);

static LwipStatus dhcp6_parse_reply(struct PacketBuffer* p, struct Dhcp6Context* dhcp6);

static void dhcp6_recv(void* arg,
                       struct UdpPcb* pcb,
                       struct PacketBuffer* p,
                       const IpAddrInfo* addr,
                       uint16_t port,
                       NetworkInterface* netif);


static void
dhcp6_timeout(NetworkInterface*netif, struct Dhcp6Context *dhcp6);


void
dhcp6_tmr();

//
// END OF FILE
//