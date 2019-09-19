#pragma once
#include <vector>
#include "ns_ip_addr.h"


constexpr auto DHCP6_CLIENT_PORT = 546;
constexpr auto DHCP6_SERVER_PORT = 547;
constexpr auto DHCP6_TRANSACTION_ID_LEN = 3;
/**  Period (in milliseconds) of the application calling dhcp6_tmr() */
constexpr auto DHCP6_TIMER_MSECS = 500;


/**
 *
 */
 enum Dhcp6State{
    DHCP6_STATE_OFF = 0,
    DHCP6_STATE_STATELESS_IDLE = 1,
    DHCP6_STATE_REQUESTING_CONFIG = 2
} ;


/**
 * Option handling: options are parsed in dhcp6_parse_reply and saved in an array where
 * other functions can load them from. This might be moved into the Dhcp6 (not
 * necessarily since lwIP is single-threaded and the array is only used while in recv
 * callback).
 */
enum Dhcp6OptionIdx {
  DHCP6_OPTION_IDX_CLI_ID = 0,
  DHCP6_OPTION_IDX_SERVER_ID,
  DHCP6_OPTION_IDX_DNS_SERVER,
  DHCP6_OPTION_IDX_DOMAIN_LIST,
  DHCP6_OPTION_IDX_NTP_SERVER,
  DHCP6_OPTION_IDX_MAX
};


/**
 * DHCPv6 message types
 * from: http://www.networksorcery.com/enp/protocol/dhcpv6.htm
 * More message types see https://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xhtml
 */
enum Dhcp6MessageType : uint8_t
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
    DHCP6_INFO_REQUEST = 11,
    DHCP6_RELAY_FORW = 12,
    DHCP6_RELAY_REPL = 13,
    DHCP6_LEASE_QUERY = 14,
    DHCP6_LEASE_QUERY_REPLY = 15,
    DHCP6_LEASE_QUERY_DONE = 16,
    DHCP6_LEASE_QUERY_DATA = 17,
};



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


/**
 * DHCPv6 options
 */
enum Dhcp6Option
{
    // Options 1-20 are from RFC 3315
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
    // Options 21-22 RFC 3319
    DHCP6_OPT_SIP_SRV_DOM_NAME_LIST = 21,
    DHCP6_OPT_SIP_SRV_IP6_ADDR_LIST = 22,
    // Options 23-24 RFC 3646
    DHCP6_OPTION_DNS_SERVERS = 23,
    DHCP6_OPTION_DOMAIN_LIST = 24,
    // Options 25-26 RFC 3633
    DHCP6_OPT_IA_PD = 25,
    DHCP6_OPT_IA_PREFIX = 26,
    // Options 27-30 RFC 3898
    DHCP6_OPT_NIS_SERVERS = 27,
    DHCP6_OPT_NISP_SERVERS = 28,
    DHCP6_OPT_NIS_DOM_NAME = 29,
    DHCP6_OPT_NISP_DOM_NAME = 30,
    // RFC 4075
    DHCP6_OPTION_SNTP_SERVERS = 31,
    // RFC 4242
    DHCP6_OPT_INFO_REFRESH_TIME = 32,
    // Opitons 33-34 RFC 4280
    DHCP6_BCMCS_CTRLR_DOM_NAME_LIST = 33,
    DHCP6_BCMCS_CTRLR_IP6_ADDR_LIST = 34,
    // RFC 4776
    DHCP6_OPT_GEOCONF_CIVIC = 36,
    // RFC 4649
    DHCP6_OPT_REMOTE_ID = 37,
    // RFC 4580
    DHCP6_OPT_RELAY_AGENT_SUBSCRIBER_ID = 38,
    // RFC 4704
    DHCP6_OPT_FQDN = 39,
    // RFC 5192
    DHCP6_OPT_PANA_AUTH_AGENT = 40,
    // OPtions 41-42 from RFC 4833
    DHCP6_OPT_NEW_POSIX_TIME_ZONE = 41,
    DHCP6_OPT_NEW_TZDB_TIME_ZONE = 42,
    // RFC 4994
    DHCP6_OPT_ECHO_REQ = 43,
    // Options 44-48 RFC 5007
    DHCP6_OPT_LQ_QUERY = 44,
    DHCP6_OPT_CLIENT_DATA = 45,
    DHCP6_OPT_CLT_TIME = 46,
    DHCP6_OPT_LQ_RELAY_DATA = 47,
    DHCP6_OPT_LQ_CLIENT_LINK = 48,
    // Options 49-50 RFC 6610
    DHCP6_OPT_MIP6_HOME_NET_ID_FQDN = 49,
    DHCP6_OPT_MIP6_VISITED_HOME_NET_INFO = 50,
    // RFC 5223
    DHCP6_OPT_LOST_SERVER = 51,
    // RFC 5417
    DHCP6_OPT_CAPWAP_ACCCESS_CTRLR_ADDR = 52,
    // RFC 5460
    DHCP6_OPT_RELAY_ID = 53,
    // Options 54-55 RFC 5678
    DHCP6_OPT_IPV6_ADDR_MOS = 54,
    DHCP6_OPT_IPV6_FQDN_MOS = 55,
    // RFC 5908
    DHCP6_OPT_NTP_SERVER = 56,
    // RFC 5986
    DHCP6_OPT_V6_ACCESS_DOMAIN = 57,
    // RFC 6011
    DHCP6_OPT_SIP_UA_CS_LIST = 58,
    // Options 59-62 RFC 5970
    DHCP6_OPT_BOOTFILE_URL = 59,
    DHCP6_OPT_BOOTFILE_PARAM = 60,
    DHCP6_OPT_CLIENT_ARCH_TYPE = 61,
    DHCP6_OPT_NII = 62,
    // RFC 6225
    DHCP6_OPT_GEOLOCATION = 63,
    // RFC 6334
    DHCP6_OPT_AFTR_NAME = 64,
    // RFC 6440
    DHCP6_OPT_ERP_LOCAL_DOM_NAME = 65,
    // RFC 6422
    DHCP6_OPT_RSOO = 66,
    // RFC 6603
    DHCP6_OPT_PD_EXCLUDE = 67,
    // RFC 6607
    DHCP6_OPT_VIRT_SUBNET_SEL = 68,
    // Optiosn 69-73 RFC 6610
    DHCP6_OPT_MIP6_ID_HOME_NET_INFO = 69,
    DHCP6_OPT_MIP6_UNRESTRICTED_HOME_NET_INFO = 70,
    DHCP6_OPT_MIP6_HOME_NET_PREFIX = 71,
    DHCP6_OPT_MIP6_HOME_AGENT_ADDR = 72,
    DHCP6_OPT_MIP6_HOME_AGENT_FQDN = 73
};


/**
 *
 */
struct Dhcp6ClientServerMessage
{
    Dhcp6MessageType msg_type{};
    uint8_t transaction_id[3];
    std::vector<uint8_t> data;
};


/**
 *
 */
struct Dhcp6OptionInfo
{
    bool option_given;
    size_t val_start;
    size_t val_length;
};


/**
 *
 */
struct Dhcp6Context
{
    /* transaction identifier of last sent request */
    uint32_t xid{};
    /* track PCB allocation state */
    bool pcb_allocated{};
    /* current DHCPv6 state machine state */
    uint8_t state{};
    /* retries of current request */
    uint8_t tries{};
    uint32_t ref_cnt;
    /* if request config is triggered while another action is active, this keeps track
     *of it */
    uint8_t request_config_pending{};
    /* #ticks with period DHCP6_TIMER_MSECS for request timeout */
    uint16_t request_timeout{};
    std::vector<Dhcp6OptionInfo> dhcp6_rx_options;
    IpAddrInfo local_ip{};
    IpAddrInfo remote_ip{};
    uint8_t netif_index{};
    uint8_t type_of_service{};
    uint8_t socket_options{};
    uint8_t time_to_live{};
    uint8_t flags{};
    uint16_t local_port{};
    uint16_t remote_port{};
    Ip4AddrInfo multicast_ip4{};
    uint8_t mcast_if_index{};
    uint8_t mcast_ttl{};
    uint16_t checksum_len_rx{};
    uint16_t checksum_len_tx{};
    /* @todo: add more members here to keep track of stateful DHCPv6 data, like lease times */
};
