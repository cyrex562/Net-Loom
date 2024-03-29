//
// file: dns.h
//

#pragma once

#include "ip_addr.h"
#include "ip4_addr.h"
#include "ip6_addr.h"
#include "lwip_status.h"

/** DNS server port address */

constexpr auto DNS_SERVER_PORT = 53;


/* DNS field TYPE used for "Resource Records" */
#define DNS_RRTYPE_A              1     /* a host address */
#define DNS_RRTYPE_NS             2     /* an authoritative name server */
#define DNS_RRTYPE_MD             3     /* a mail destination (Obsolete - use MX) */
#define DNS_RRTYPE_MF             4     /* a mail forwarder (Obsolete - use MX) */
#define DNS_RRTYPE_CNAME          5     /* the canonical name for an alias */
#define DNS_RRTYPE_SOA            6     /* marks the start of a zone of authority */
#define DNS_RRTYPE_MB             7     /* a mailbox domain name (EXPERIMENTAL) */
#define DNS_RRTYPE_MG             8     /* a mail group member (EXPERIMENTAL) */
#define DNS_RRTYPE_MR             9     /* a mail rename domain name (EXPERIMENTAL) */
#define DNS_RRTYPE_NULL           10    /* a null RR (EXPERIMENTAL) */
#define DNS_RRTYPE_WKS            11    /* a well known service description */
#define DNS_RRTYPE_PTR            12    /* a domain name pointer */
#define DNS_RRTYPE_HINFO          13    /* host information */
#define DNS_RRTYPE_MINFO          14    /* mailbox or mail list information */
#define DNS_RRTYPE_MX             15    /* mail exchange */
#define DNS_RRTYPE_TXT            16    /* text strings */
#define DNS_RRTYPE_AAAA           28    /* IPv6 address */
#define DNS_RRTYPE_SRV            33    /* service location */
#define DNS_RRTYPE_ANY            255   /* any type */

/* DNS field CLASS used for "Resource Records" */
#define DNS_RRCLASS_IN            1     /* the Internet */
#define DNS_RRCLASS_CS            2     /* the CSNET class (Obsolete - used only for examples in some obsolete RFCs) */
#define DNS_RRCLASS_CH            3     /* the CHAOS class */
#define DNS_RRCLASS_HS            4     /* Hesiod [Dyer 87] */
#define DNS_RRCLASS_ANY           255   /* any class */
#define DNS_RRCLASS_FLUSH         0x800 /* Flush bit */

/* DNS protocol flags */
#define DNS_FLAG1_RESPONSE        0x80
#define DNS_FLAG1_OPCODE_STATUS   0x10
#define DNS_FLAG1_OPCODE_INVERSE  0x08
#define DNS_FLAG1_OPCODE_STANDARD 0x00
#define DNS_FLAG1_AUTHORATIVE     0x04
#define DNS_FLAG1_TRUNC           0x02
#define DNS_FLAG1_RD              0x01
#define DNS_FLAG2_RA              0x80
#define DNS_FLAG2_ERR_MASK        0x0f
#define DNS_FLAG2_ERR_NONE        0x00
#define DNS_FLAG2_ERR_NAME        0x03

#define DNS_HDR_GET_OPCODE(hdr) ((((hdr)->flags1) >> 3) & 0xF)

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


/* Multicast DNS definitions */

/** UDP port for multicast DNS queries */
constexpr auto DNS_MQUERY_PORT = 5353;


/* IPv4 group for multicast DNS queries: 224.0.0.251 */

// constexpr auto DNS_MQUERY_IPV4_GROUP_INIT = IpAddr4InitBytes(224,0,0,251);


/* IPv6 group for multicast DNS queries: FF02::FB */

#define DNS_MQUERY_IPV6_GROUP_INIT  IPADDR6_INIT_HOST(0xFF020000,0,0,0xFB)

/** DNS timer period */
constexpr auto DNS_TMR_INTERVAL = 1000;

/* DNS resolve types: */
enum dns_addr_type
{
    LWIP_DNS_ADDRTYPE_IPV4 = 0,
    LWIP_DNS_ADDRTYPE_IPV6 = 1,
    LWIP_DNS_ADDRTYPE_IPV4_IPV6 = 2,
    LWIP_DNS_ADDRTYPE_IPV6_IPV4 = 3,
    LWIP_DNS_ADDRTYPE_DEFAULT = LWIP_DNS_ADDRTYPE_IPV4_IPV6
};





/** struct used for local host-list */
struct LocalHostListEntry
{
    /** static hostname */
    const char* name; /** static host address in network byteorder */
    IpAddrInfo addr;
    struct LocalHostListEntry* next;
};
#define DNS_LOCAL_HOSTLIST_ELEM(name, addr_init) {name, addr_init, NULL}
#define DNS_LOCAL_HOSTLIST_MAX_NAMELEN  DNS_MAX_NAME_LENGTH
#define LOCALHOSTLIST_ELEM_SIZE ((sizeof(struct LocalHostListEntry) + DNS_LOCAL_HOSTLIST_MAX_NAMELEN + 1))


extern const IpAddrInfo dns_mquery_v4group;

extern const IpAddrInfo dns_mquery_v6group;


/** Callback which is invoked when a hostname is found.
 * A function of this type must be implemented by the application using the DNS resolver.
 * @param name pointer to the name that was looked up.
 * @param ipaddr pointer to an IpAddr containing the IP address of the hostname,
 *        or NULL if the name could not be found (or on any other error).
 * @param callback_arg a user-specified callback argument passed to dns_gethostbyname
*/
typedef void (*dns_found_callback)(const char *name, const IpAddrInfo *ipaddr, uint8_t *callback_arg);

void             dns_init(void);
void             dns_tmr(void);
void             dns_setserver(uint8_t numdns, const IpAddrInfo *dnsserver);
IpAddrInfo dns_getserver(uint8_t numdns);
LwipStatus            dns_gethostbyname(const char *hostname, IpAddrInfo *addr,
                                   dns_found_callback found, uint8_t *callback_arg);
LwipStatus            dns_gethostbyname_addrtype(const char *hostname, IpAddrInfo *addr,
                                   dns_found_callback found, uint8_t *callback_arg,
                                   uint8_t dns_addrtype);

size_t         dns_local_iterate(dns_found_callback iterator_fn, uint8_t *iterator_arg);
LwipStatus          dns_local_lookup(const char *hostname, IpAddrInfo *addr, uint8_t dns_addrtype);

int            dns_local_removehost(const char *hostname, const IpAddrInfo *addr);
LwipStatus          dns_local_addhost(const char *hostname, const IpAddrInfo *addr);

inline bool lwip_dns_addrtype_is_ipv6(uint8_t t)
{
    return (((t) == LWIP_DNS_ADDRTYPE_IPV6_IPV4) || ((t) == LWIP_DNS_ADDRTYPE_IPV6));
}

inline bool match_dns_addr_ip(uint8_t t, IpAddrInfo& ip)
{
    return (is_ip_addr_v6(ip) ? lwip_dns_addrtype_is_ipv6(t) : (!lwip_dns_addrtype_is_ipv6(t)));
}


const Ip4Addr dns_mquery_group_v4 = {make_u32(224,0,0,251)};

const Ip6Addr dns_mquery_group_v6 = make_ip6_addr_host(0xf020000UL, 0, 0, 0x000000fbUL);