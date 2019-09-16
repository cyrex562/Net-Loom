//
// file: dns.h
//

#pragma once

#include "ip_addr.h"
#include "ip4_addr.h"
#include "ip6_addr.h"
#include "lwip_status.h"
#include <vector>
#include "tcp_udp.h"

/** DNS server port address */
constexpr auto DNS_SERVER_PORT = 53;

/** UDP port for multicast DNS queries */
constexpr auto DNS_MQUERY_PORT = 5353;

// constexpr auto DNS_MQUERY_IPV4_GROUP_INIT = IpAddr4InitBytes(224,0,0,251);

/* IPv6 group for multicast DNS queries: FF02::FB */
// #define DNS_MQUERY_IPV6_GROUP_INIT  ip6(0xFF020000,0,0,0xFB)
inline Ip6AddrInfo dns_mquery_ipv6_group_init() { return set_ip6_addr2(0xFF020000,0,0,0xFB); }

/** DNS timer period */
constexpr auto DNS_TMR_INTERVAL = 1000;

/** DNS resource record max. TTL (one week as default) */
constexpr auto DNS_MAX_TTL = 604800;

/* The number of parallel requests (i.e. calls to dns_gethostbyname
 * that cannot be answered from the DNS table.
 * This is set to the table size by default.
 */
constexpr auto DNS_MAX_REQUESTS     =     DNS_TABLE_SIZE;

/* In this configuration, both arrays have to have the same size and are used
 * like one entry (used/free) */

/* The number of UDP source ports used in parallel */
constexpr auto DNS_MAX_SOURCE_PORTS  =    DNS_MAX_REQUESTS;

const Ip4Addr dns_mquery_group_v4 = {make_u32(224,0,0,251)};

const Ip6Addr dns_mquery_group_v6 = make_ip6_addr_host(0xf020000UL, 0, 0, 0x000000fbUL);

/* DNS field TYPE used for "Resource Records" */
enum DnsResRecFieldType
{
    /* a host address */
    DNS_RRTYPE_A = 1,
    /* an authoritative name server */
    DNS_RRTYPE_NS = 2,
    /* a mail destination (Obsolete - use MX) */
    DNS_RRTYPE_MD = 3,
    /* a mail forwarder (Obsolete - use MX) */
    DNS_RRTYPE_MF = 4,
    /* the canonical name for an alias */
    DNS_RRTYPE_CNAME = 5,
    /* marks the start of a zone of authority */
    DNS_RRTYPE_SOA = 6,
    /* a mailbox domain name (EXPERIMENTAL) */
    DNS_RRTYPE_MB = 7,
    /* a mail group member (EXPERIMENTAL) */
    DNS_RRTYPE_MG = 8,
    /* a mail rename domain name (EXPERIMENTAL) */
    DNS_RRTYPE_MR = 9,
    /* a null RR (EXPERIMENTAL) */
    DNS_RRTYPE_NULL = 10,
    /* a well known service description */
    DNS_RRTYPE_WKS = 11,
    /* a domain name pointer */
    DNS_RRTYPE_PTR = 12,
    /* host information */
    DNS_RRTYPE_HINFO = 13,
    /* mailbox or mail list information */
    DNS_RRTYPE_MINFO = 14,
    /* mail exchange */
    DNS_RRTYPE_MX = 15,
    /* text strings */
    DNS_RRTYPE_TXT = 16,
    /* IPv6 address */
    DNS_RRTYPE_AAAA = 28,
    /* service location */
    DNS_RRTYPE_SRV = 33,
    /* any type */
    DNS_RRTYPE_ANY = 255,
};


/* DNS field CLASS used for "Resource Records" */
enum DnsResRecFieldClass
{
    /* the Internet */
    DNS_RRCLASS_IN = 1,
    /* the CSNET class (Obsolete - used only for examples in some obsolete RFCs) */
    DNS_RRCLASS_CS = 2,
    /* the CHAOS class */
    DNS_RRCLASS_CH = 3,
    /* Hesiod [Dyer 87] */
    DNS_RRCLASS_HS = 4,
    /* any class */
    DNS_RRCLASS_ANY = 255,
    /* Flush bit */
    DNS_RRCLASS_FLUSH = 0x800,
};


/* DNS protocol flags */
enum DnsProtoFlag
{
    DNS_FLAG1_RESPONSE = 0x80,
DNS_FLAG1_OPCODE_STATUS = 0x10,
DNS_FLAG1_OPCODE_INVERSE = 0x08,
DNS_FLAG1_OPCODE_STANDARD = 0x00,
DNS_FLAG1_AUTHORATIVE = 0x04,
DNS_FLAG1_TRUNC = 0x02,
DNS_FLAG1_RD = 0x01,
DNS_FLAG2_RA = 0x80,
DNS_FLAG2_ERR_MASK = 0x0f,
DNS_FLAG2_ERR_NONE = 0x00,
DNS_FLAG2_ERR_NAME = 0x03,
};

/* DNS resolve types: */
enum DnsAddrType
{
    LWIP_DNS_ADDRTYPE_IPV4 = 0,
    LWIP_DNS_ADDRTYPE_IPV6 = 1,
    LWIP_DNS_ADDRTYPE_IPV4_IPV6 = 2,
    LWIP_DNS_ADDRTYPE_IPV6_IPV4 = 3,
    LWIP_DNS_ADDRTYPE_DEFAULT = LWIP_DNS_ADDRTYPE_IPV4_IPV6
};

/* DNS table entry states */
enum DnsTableEntryState
{
    DNS_STATE_UNUSED = 0,
    DNS_STATE_NEW = 1,
    DNS_STATE_ASKING = 2,
    DNS_STATE_DONE = 3
};

/** DNS message header */
struct DnsHdr
{
    uint16_t id;
    uint8_t flags1;
    uint8_t flags2;
    uint16_t numquestions;
    uint16_t numanswers;
    uint16_t numauthrr;
    uint16_t numextrarr;
};

constexpr auto DNS_HDR_LEN = 12;

/** DNS query message structure.
    No packing needed: only used locally on the stack. */
struct DnsQuery
{
    /* DNS query record starts with either a domain name or a pointer
       to a name already present somewhere in the packet. */
    uint16_t type;
    uint16_t cls;
};
constexpr auto DNS_QUERY_LEN = 4;

/** DNS answer message structure.
    No packing needed: only used locally on the stack. */
struct DnsAnswer
{
    /* DNS answer record starts with either a domain name or a pointer
       to a name already present somewhere in the packet. */
    uint16_t type;
    uint16_t cls;
    uint32_t ttl;
    uint16_t len;
};

constexpr auto SIZEOF_DNS_ANSWER = 10;
/* maximum allowed size for the struct due to non-packed */
constexpr auto SIZEOF_DNS_ANSWER_ASSERT = 12;

/** DNS table entry */
struct DnsTableEntry
{
    uint32_t ttl;
    IpAddrInfo address;
    uint16_t txid;
    uint8_t state;
    uint8_t server_idx;
    uint8_t tmr;
    uint8_t retries;
    uint8_t seqno;
    uint8_t pcb_idx;
    std::string hostname;
    uint8_t reqaddrtype;
    uint8_t is_mdns;
};

/** DNS request table entry: used when dns_gehostbyname cannot answer the
 * request from the DNS table */
struct DnsRequestEntry
{
    /* pointer to callback on DNS query done */
    // dns_found_callback found; /* argument passed to the callback function */
    // void* arg;
    uint8_t dns_table_idx;
    uint8_t reqaddrtype;
};

/** struct used for local host-list */
struct LocalHostListEntry
{
    /** static hostname */
    std::string name; /** static host address in network byteorder */
    IpAddrInfo addr;
};



/**
 *
 */
struct DnsPcb
{
    uint32_t id;
    IpAddrInfo local_ip;
    IpAddrInfo remote_ip;
    uint32_t netif_id;
    uint8_t sock_opts;
    uint8_t type_of_svc;
    uint8_t time_to_live;
    uint8_t flags;
    uint16_t local_port;
    uint16_t remote_port;
    Ip4AddrInfo mcast_ip;
    uint32_t mcast_netif_id;
    uint8_t mcast_ttl;
    uint16_t checksum_len_rx;
    uint16_t checksum_len_tx;
};

struct DnsTransaction
{

};

struct DnsBindingContext
{
    uint32_t id;

};


struct DnsServer
{
    IpAddrInfo address;
    uint32_t id;

};

/** Limits the source port to be >= 1024 by default */
inline bool dns_port_allowed(const uint16_t port){ return ((port) >= 1024); }

inline uint8_t dns_hdr_get_opcode(DnsHdr& hdr){return hdr.flags1 >> 3 & 0xF;}

inline void lwip_dns_set_addrtype(DnsAddrType& x, DnsAddrType& y){ x = y;}


inline void
dns_set_multicast_ttl(DnsPcb& pcb, const uint8_t value) { ((pcb).mcast_ttl = (value)); }

/**
 *
 */
inline DnsPcb dns_create_pcb()
{
    DnsPcb pcb{};
    pcb.time_to_live = UDP_TTL;
    pcb.mcast_ttl = UDP_TTL;
    return pcb;
}

/**
 *
 */
inline DnsPcb dns_new_ip_type(const IpAddrType addr_type)
{
    DnsPcb pcb = dns_create_pcb();
    (pcb.local_ip.type = addr_type);
    (pcb.remote_ip.type = addr_type);
    return pcb;
}

constexpr auto DNS_LOCAL_HOSTLIST_MAX_NAMELEN = DNS_MAX_NAME_LENGTH;

/** Callback which is invoked when a hostname is found.
 * A function of this type must be implemented by the application using the DNS resolver.
 * @param name pointer to the name that was looked up.
 * @param ipaddr pointer to an IpAddr containing the IP address of the hostname,
 *        or NULL if the name could not be found (or on any other error).
 * @param callback_arg a user-specified callback argument passed to dns_gethostbyname
*/
using dns_found_callback = void (*)(const char*, const IpAddrInfo*, uint8_t*);


std::vector<LocalHostListEntry>
dns_init_local(std::vector<LocalHostListEntry>& init_entries);

LwipStatus
dns_lookup_local(const char* hostname, IpAddrInfo* addr, uint8_t dns_addrtype);

void
dns_recv(uint8_t* s,
         DnsPcb* pcb,
         struct PacketBuffer* p,
         const IpAddrInfo* addr,
         uint16_t port,
         NetworkInterface* netif);

void
dns_check_entries();

void
dns_call_found(uint8_t idx, IpAddrInfo* addr);


std::tuple<bool, std::vector<DnsPcb>, std::vector<DnsServer>, std::vector<
LocalHostListEntry>>
dns_init(std::vector<NetworkInterface>& netifs,
         std::vector<NetworkPort>& ports,
         DnsServer& default_dns_server,
         std::vector<LocalHostListEntry>& initial_local_hosts);

void
dns_tmr();


bool
dns_setserver(DnsServer& dnsserver, std::vector<DnsServer>& servers);


std::tuple<bool, DnsServer>
dns_getserver(uint32_t server_id, std::vector<DnsServer>& servers);

LwipStatus
dns_gethostbyname(const char* hostname,
                  IpAddrInfo* addr,
                  dns_found_callback found,
                  uint8_t* callback_arg);

LwipStatus
dns_gethostbyname_addrtype(const char* hostname,
                           IpAddrInfo* addr,
                           dns_found_callback found,
                           uint8_t* callback_arg,
                           uint8_t dns_addrtype);

size_t
dns_local_iterate(dns_found_callback iterator_fn, uint8_t* iterator_arg);


std::tuple<bool, IpAddrInfo>
dns_local_lookup(const std::string& hostname, const std::vector<LocalHostListEntry>& entries);


uint32_t
dns_local_remove_host(std::string& hostname,
                      const IpAddrInfo& address,
                      std::vector<LocalHostListEntry>& local_host_list);


bool
dns_local_addhost(std::string& hostname, IpAddrInfo& address, std::vector<LocalHostListEntry>& local_hosts);

inline bool lwip_dns_addrtype_is_ipv6(DnsAddrType t)
{
    return (((t) == LWIP_DNS_ADDRTYPE_IPV6_IPV4) || ((t) == LWIP_DNS_ADDRTYPE_IPV6));
}

inline bool match_dns_addr_ip(DnsAddrType t, IpAddrInfo& ip)
{
    return ((ip.type == IP_ADDR_TYPE_V6) ? lwip_dns_addrtype_is_ipv6(t) : (!lwip_dns_addrtype_is_ipv6(t)));
}


bool
dns_bind(std::vector<NetworkInterface>& netifs,
         std::vector<NetworkPort>& ports,
         std::vector<DnsPcb>& dns_pcbs,
         DnsPcb& pcb,
         IpAddrInfo& ip_addr,
         uint16_t port);


//
// END OF FILE
//