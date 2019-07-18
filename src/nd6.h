#pragma once

#include "ip6_addr.h"

#include "lwip_error.h"

#include "opt.h"

/** Neighbor solicitation message header. */

struct ns_header
{
    uint8_t type;
    uint8_t code;
    uint16_t chksum;
    uint32_t reserved;
    Ip6AddrPT target_address;
    /* Options follow. */
};

/** Neighbor advertisement message header. */


struct na_header
{
    uint8_t type;
    uint8_t code;
    uint16_t chksum;
    uint8_t flags;
    uint8_t reserved[3];
    Ip6AddrPT target_address;
    /* Options follow. */
};

#define ND6_FLAG_ROUTER      (0x80)
#define ND6_FLAG_SOLICITED   (0x40)
#define ND6_FLAG_OVERRIDE    (0x20)

/** Router solicitation message header. */


struct rs_header
{
    uint8_t type;
    uint8_t code;
    uint16_t chksum;
    uint32_t reserved;
    /* Options follow. */
};


/** Router advertisement message header. */
#define ND6_RA_FLAG_MANAGED_ADDR_CONFIG (0x80)
#define ND6_RA_FLAG_OTHER_CONFIG (0x40)
#define ND6_RA_FLAG_HOME_AGENT (0x20)
#define ND6_RA_PREFERENCE_MASK (0x18)
#define ND6_RA_PREFERENCE_HIGH (0x08)
#define ND6_RA_PREFERENCE_MEDIUM (0x00)
#define ND6_RA_PREFERENCE_LOW (0x18)
#define ND6_RA_PREFERENCE_DISABLED (0x10)

struct ra_header
{
    uint8_t type;
    uint8_t code;
    uint16_t chksum;
    uint8_t current_hop_limit;
    uint8_t flags;
    uint16_t router_lifetime;
    uint32_t reachable_time;
    uint32_t retrans_timer;
    /* Options follow. */
};


/** Redirect message header. */

struct redirect_header
{
    uint8_t type;
    uint8_t code;
    uint16_t chksum;
    uint32_t reserved;
    Ip6AddrPT target_address;
    Ip6AddrPT destination_address;
    /* Options follow. */
};


/** Link-layer address option. */
#define ND6_OPTION_TYPE_SOURCE_LLADDR (0x01)
#define ND6_OPTION_TYPE_TARGET_LLADDR (0x02)


struct lladdr_option
{
    uint8_t type;
    uint8_t length;
    uint8_t addr[kNetifMaxHwaddrLen];
};


/** Prefix information option. */
#define ND6_OPTION_TYPE_PREFIX_INFO (0x03)
#define ND6_PREFIX_FLAG_ON_LINK (0x80)
#define ND6_PREFIX_FLAG_AUTONOMOUS (0x40)
#define ND6_PREFIX_FLAG_ROUTER_ADDRESS (0x20)
#define ND6_PREFIX_FLAG_SITE_PREFIX (0x10)


struct prefix_option
{
    uint8_t type;
    uint8_t length;
    uint8_t prefix_length;
    uint8_t flags;
    uint32_t valid_lifetime;
    uint32_t preferred_lifetime;
    uint8_t reserved2[3];
    uint8_t site_prefix_length;
    Ip6AddrPT prefix;
};


/** Redirected header option. */
#define ND6_OPTION_TYPE_REDIR_HDR (0x04)


struct redirected_header_option
{
    uint8_t type;
    uint8_t length;
    uint8_t reserved[6];
    /* Portion of redirected packet follows. */
    /* (uint8_t redirected[8]); */
};


/** MTU option. */
#define ND6_OPTION_TYPE_MTU (0x05)


struct mtu_option
{
    uint8_t type;
    uint8_t length;
    uint16_t reserved;
    uint32_t mtu;
};

/** Route information option. */
#define ND6_OPTION_TYPE_ROUTE_INFO (24)


struct route_option
{
    uint8_t type;
    uint8_t length;
    uint8_t prefix_length;
    uint8_t preference;
    uint32_t route_lifetime;
    Ip6AddrPT prefix;
};


/** Recursive DNS Server Option. */
#define ND6_OPTION_TYPE_RDNSS (25)


struct rdnss_option
{
    uint8_t type;
    uint8_t length;
    uint16_t reserved;
    uint32_t lifetime;
    Ip6AddrPT rdnss_address[1];
};


#define SIZEOF_RDNSS_OPTION_BASE 8 /* size without addresses */


/** 1 second period */
#define ND6_TMR_INTERVAL 1000

/** Router solicitations are sent in 4 second intervals (see RFC 4861, ch. 6.3.7) */

#define ND6_RTR_SOLICITATION_INTERVAL  4000


struct PacketBuffer;

void nd6_tmr(void);
void nd6_input(struct PacketBuffer* p, NetIfc* inp);
void nd6_clear_destination_cache(void);
NetIfc* nd6_find_route(const Ip6Addr* ip6addr);


LwipError nd6_get_next_hop_addr_or_queue(NetIfc* netif, struct PacketBuffer* q, const Ip6Addr* ip6addr,
                                         const uint8_t** hwaddrp);
uint16_t nd6_get_destination_mtu(const Ip6Addr* ip6addr, NetIfc* netif);

void nd6_reachability_hint(const Ip6Addr* ip6addr);

void nd6_cleanup_netif(NetIfc* netif);

void nd6_adjust_mld_membership(NetIfc*netif, int8_t addr_idx, uint8_t new_state);

void nd6_restart_netif(NetIfc* netif);

//
// END OF FILE
//