/*
 * netif API (to be used from TCPIP thread)
 */

#pragma once

#include "lwip_error.h"
#include "packet_buffer.h"
#include "ip_addr.h"
#include "ip6_addr.h"
#include "def.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Throughout this file, IP addresses are expected to be in
 * the same byte order as in IP_PCB. */

/** Must be the maximum of all used hardware address lengths
    across all types of interfaces in use.
    This does not have to be changed, normally. */

/** The size of a fully constructed netif name which the
 * netif can be identified by in APIs. Composed of
 * 2 chars, 3 (max) digits, and 1 \0
 */
constexpr auto kNetifNamesize = 6;

/**
 * @defgroup netif_flags Flags
 * @ingroup netif
 * @{
 */

/** Whether the network interface is 'up'. This is
 * a software flag used to control whether this network
 * interface is enabled and processes traffic.
 * It must be set by the startup code before this netif can be used
 * (also for dhcp/autoip).
 */
constexpr auto NETIF_FLAG_UP = 0x01U;
/** If set, the netif has broadcast capability.
 * Set by the netif driver in its init function. */
constexpr auto kNetifFlagBroadcast = 0x02U;
/** If set, the interface has an active link
 *  (set by the network interface driver).
 * Either set by the netif driver in its init function (if the link
 * is up at that time) or at a later point once the link comes up
 * (if link detection is supported by the hardware). */
constexpr auto NETIF_FLAG_LINK_UP = 0x04U;
/** If set, the netif is an ethernet device using ARP.
 * Set by the netif driver in its init function.
 * Used to check input packet types and use of DHCP. */
constexpr auto kNetifFlagEtharp = 0x08U;
/** If set, the netif is an ethernet device. It might not use
 * ARP or TCP/IP if it is used for PPPoE only.
 */
constexpr auto kNetifFlagEthernet = 0x10U;
/** If set, the netif has IGMP capability.
 * Set by the netif driver in its init function. */
constexpr auto kNetifFlagIgmp = 0x20U;
/** If set, the netif has MLD6 capability.
 * Set by the netif driver in its init function. */
constexpr auto kNetifFlagMld6 = 0x40U;

/**
 * @}
 */

enum LwipInternalNetifClientDataIndex {
  LWIP_NETIF_CLIENT_DATA_INDEX_DHCP,
  LWIP_NETIF_CLIENT_DATA_INDEX_AUTOIP,
  LWIP_NETIF_CLIENT_DATA_INDEX_IGMP,
  LWIP_NETIF_CLIENT_DATA_INDEX_DHCP6,
  LWIP_NETIF_CLIENT_DATA_INDEX_MLD6,
  LWIP_NETIF_CLIENT_DATA_INDEX_MAX
};


constexpr auto NETIF_CHECKSUM_GEN_IP = 0x0001;
constexpr auto NETIF_CHECKSUM_GEN_UDP = 0x0002;
constexpr auto NETIF_CHECKSUM_GEN_TCP = 0x0004;
constexpr auto NETIF_CHECKSUM_GEN_ICMP = 0x0008;
constexpr auto NETIF_CHECKSUM_GEN_ICMP6 = 0x0010;
constexpr auto NETIF_CHECKSUM_CHECK_IP = 0x0100;
constexpr auto NETIF_CHECKSUM_CHECK_UDP = 0x0200;
constexpr auto NETIF_CHECKSUM_CHECK_TCP = 0x0400;
constexpr auto NETIF_CHECKSUM_CHECK_ICMP = 0x0800;
constexpr auto NETIF_CHECKSUM_CHECK_ICMP6 = 0x1000;
constexpr auto NETIF_CHECKSUM_ENABLE_ALL = 0xFFFF;
constexpr auto NETIF_CHECKSUM_DISABLE_ALL = 0x0000;


struct NetIfc;

/** MAC Filter Actions, these are passed to a netif's igmp_mac_filter or
 * mld_mac_filter callback function. */
enum NetifMacFilterAction {
  /** Delete a filter entry */
      NETIF_DEL_MAC_FILTER = 0,
  /** Add a filter entry */
      NETIF_ADD_MAC_FILTER = 1
};

/** Function prototype for netif init functions. Set up flags and output/linkoutput
 * callback functions in this function.
 *
 * @param netif The netif to initialize
 */
typedef LwipError (*netif_init_fn)(struct NetIfc *netif);
/** Function prototype for netif->input functions. This function is saved as 'input'
 * callback function in the netif struct. Call it when a packet has been received.
 *
 * @param p The received packet, copied into a PacketBuffer
 * @param inp The netif which received the packet
 * @return ERR_OK if the packet was handled
 *         != ERR_OK is the packet was NOT handled, in this case, the caller has
 *                   to free the PacketBuffer
 */
typedef LwipError (*netif_input_fn)(struct PacketBuffer *p, struct NetIfc *inp);


/** Function prototype for netif->output functions. Called by lwIP when a packet
 * shall be sent. For ethernet netif, set this to 'etharp_output' and set
 * 'linkoutput'.
 *
 * @param netif The netif which shall send a packet
 * @param p The packet to send (p->payload points to IP header)
 * @param ipaddr The IP address to which the packet shall be sent
 */
typedef LwipError (*netif_output_fn)(struct NetIfc* netif,
                                     struct PacketBuffer* p,
                                     const Ip4Addr* ipaddr);


/** Function prototype for netif->output_ip6 functions. Called by lwIP when a packet
 * shall be sent. For ethernet netif, set this to 'ethip6_output' and set
 * 'linkoutput'.
 *
 * @param netif The netif which shall send a packet
 * @param p The packet to send (p->payload points to IP header)
 * @param ipaddr The IPv6 address to which the packet shall be sent
 */
typedef LwipError (*netif_output_ip6_fn)(struct NetIfc *netif, struct PacketBuffer *p,
                                     const Ip6Addr*ipaddr);

/** Function prototype for netif->linkoutput functions. Only used for ethernet
 * netifs. This function is called by ARP when a packet shall be sent.
 *
 * @param netif The netif which shall send a packet
 * @param p The packet to send (raw ethernet packet)
 */
typedef LwipError (*netif_linkoutput_fn)(struct NetIfc *netif, struct PacketBuffer *p);
/** Function prototype for netif status- or link-callback functions. */
typedef void (*netif_status_callback_fn)(struct NetIfc *netif);

/** Function prototype for netif igmp_mac_filter functions */
typedef LwipError (*netif_igmp_mac_filter_fn)(struct NetIfc *netif,
       const Ip4Addr *group, enum NetifMacFilterAction action);

/** Function prototype for netif mld_mac_filter functions */
typedef LwipError (*netif_mld_mac_filter_fn)(struct NetIfc *netif,
       const Ip6Addr*group, enum NetifMacFilterAction action);

/** @ingroup netif_cd
 * Set client data. Obtain ID from netif_alloc_client_data_id().
 */

/** @ingroup netif_cd
 * Get client data. Obtain ID from netif_alloc_client_data_id().
 */


uint8_t netif_alloc_client_data_id(void);

#define NETIF_GET_CLIENT_DATA(netif, id) (netif)->client_data[(id)]

#define NETIF_SET_CLIENT_DATA(netif, id, data) \
  NETIF_GET_CLIENT_DATA(netif, id) = (data)

typedef uint16_t NetIfcAddrIdx;
constexpr auto kNetifAddrIdxMax = 0x7FFF;

#define LWIP_NETIF_USE_HINTS              1

struct NetIfcHint
{
    NetIfcAddrIdx addr_hint;
};


/** Generic data structure used for all lwIP network interfaces.
 *  The following fields should be filled in by the initialization
 *  function for the device driver: hwaddr_len, hwaddr[], mtu, flags */
struct NetIfc
{
    /** pointer to next in linked list */
    struct NetIfc* next; /** IP address configuration in network byte order */
    IpAddr ip_addr;
    IpAddr netmask;
    IpAddr gw; /** Array of IPv6 addresses for this netif. */
    IpAddr ip6_addr[LWIP_IPV6_NUM_ADDRESSES];
    /** The state of each IPv6 address (Tentative, Preferred, etc).
         * @see ip6_addr.h */
    uint8_t ip6_addr_state[LWIP_IPV6_NUM_ADDRESSES];
    /** Remaining valid and preferred lifetime of each IPv6 address, in seconds.
         * For valid lifetimes, the special value of IP6_ADDR_LIFE_STATIC (0)
         * indicates the address is static and has no lifetimes. */
    uint32_t ip6_addr_valid_life[LWIP_IPV6_NUM_ADDRESSES];
    uint32_t ip6_addr_pref_life[LWIP_IPV6_NUM_ADDRESSES];
    /** This function is called by the network device driver
         *  to pass a packet up the TCP/IP stack. */
    netif_input_fn input; /** This function is called by the IP module when it wants
   *  to send a packet on the interface. This function typically
   *  first resolves the hardware address, then sends the packet.
   *  For ethernet physical layer, this is usually etharp_output() */
    netif_output_fn output; /** This function is called by ethernet_output() when it wants
   *  to send a packet on the interface. This function outputs
   *  the PacketBuffer as-is on the link medium. */
    netif_linkoutput_fn linkoutput;
    /** This function is called by the IPv6 module when it wants
         *  to send a packet on the interface. This function typically
         *  first resolves the hardware address, then sends the packet.
         *  For ethernet physical layer, this is usually ethip6_output() */
    netif_output_ip6_fn output_ip6;
    /** This function is called when the netif state is set to up or down
         */
    netif_status_callback_fn status_callback;
    /** This function is called when the netif link is set to up or down
         */
    netif_status_callback_fn link_callback;
    /** This function is called when the netif has been removed */
    netif_status_callback_fn remove_callback;
    /** This field can be set by the device driver and could point
         *  to state information for the device. */
    void* state;
    void* client_data[LWIP_NETIF_CLIENT_DATA_INDEX_MAX + LWIP_NUM_NETIF_CLIENT_DATA];
    /* the hostname for this netif, NULL is a valid value */
    const char* hostname;
    uint16_t chksum_flags; /** maximum transfer unit (in bytes) */
    uint16_t mtu; /** maximum transfer unit (in bytes), updated by RA */
    uint16_t mtu6; /** link level hardware address of this interface */
    uint8_t hwaddr[kNetifMaxHwaddrLen]; /** number of bytes used in hwaddr */
    uint8_t hwaddr_len; /** flags (@see @ref netif_flags) */
    uint8_t flags; /** descriptive abbreviation */
    char name[2];
    /** number of this interface. Used for @ref if_api and @ref netifapi_netif, 
         * as well as for IPv6 zones */
    uint8_t num; /** is this netif enabled for IPv6 autoconfiguration */
    uint8_t ip6_autoconfig_enabled;
    /** Number of Router Solicitation messages that remain to be sent. */
    uint8_t rs_count; /** link type (from "snmp_ifType" enum from snmp_mib2.h) */
    uint8_t link_type; /** (estimate) link speed */
    uint32_t link_speed; /** timestamp at last change made (up/down) */
    uint32_t ts; /** counters */ //  struct stats_mib2_netif_ctrs mib2_counters;
    /** This function could be called to add or delete an entry in the multicast
        filter table of the ethernet MAC.*/
    netif_igmp_mac_filter_fn igmp_mac_filter;
    /** This function could be called to add or delete an entry in the IPv6 multicast
            filter table of the ethernet MAC. */
    netif_mld_mac_filter_fn mld_mac_filter;
    struct NetIfcHint* hints; /* List of packets to be queued for ourselves. */
    struct PacketBuffer* loop_first;
    struct PacketBuffer* loop_last;
    uint16_t loop_cnt_current;
};

#define NETIF_SET_CHECKSUM_CTRL(netif, chksumflags) do { \
  (netif)->chksum_flags = chksumflags; } while(0)
#define IF__NETIF_CHECKSUM_ENABLED(netif, chksumflag) if (((netif) == NULL) || (((netif)->chksum_flags & (chksumflag)) != 0))

/** The list of network interfaces. */
extern struct NetIfc *netif_list;
#define NETIF_FOREACH(netif) for ((netif) = netif_list; (netif) != NULL; (netif) = (netif)->next)

/** The default network interface. */
extern struct NetIfc *netif_default;

void netif_init(void);

struct NetIfc *netif_add_noaddr(struct NetIfc *netif,
                               void *state,
                               netif_init_fn init,
                               netif_input_fn input);


struct NetIfc *netif_add(struct NetIfc *netif,
                        const Ip4Addr *ipaddr,
                        const Ip4Addr *netmask,
                        const Ip4Addr *gw,
                        void *state,
                        netif_init_fn init,
                        netif_input_fn input);
bool netif_set_addr(struct NetIfc* netif,
                    const Ip4Addr* ipaddr,
                    const Ip4Addr* netmask,
                    const Ip4Addr* gw);

void netif_remove(struct NetIfc *netif);

/* Returns a network interface given its name. The name is of the form
   "et0", where the first two letters are the "name" field in the
   netif structure, and the digit is in the num field in the same
   structure. */
struct NetIfc *netif_find(const char *name);

void netif_set_default(struct NetIfc *netif);

void netif_set_ipaddr(struct NetIfc *netif, const Ip4Addr *ipaddr);
void netif_set_netmask(struct NetIfc *netif, const Ip4Addr *netmask);
void netif_set_gw(struct NetIfc *netif, const Ip4Addr *gw);
/** @ingroup netif_ip4 */
inline Ip4Addr *netif_ip4_addr(NetIfc *netif) {
  return (ip_2_ip4(&((netif)->ip_addr)));
}

/** @ingroup netif_ip4 */
#define netif_ip4_netmask(netif) ((const Ip4Addr*)ip_2_ip4(&((netif)->netmask)))
/** @ingroup netif_ip4 */
#define netif_ip4_gw(netif)      ((const Ip4Addr*)ip_2_ip4(&((netif)->gw)))
/** @ingroup netif_ip4 */
#define netif_ip_addr4(netif)    ((const IpAddr*)&((netif)->ip_addr))
/** @ingroup netif_ip4 */
#define netif_ip_netmask4(netif) ((const IpAddr*)&((netif)->netmask))
/** @ingroup netif_ip4 */
#define netif_ip_gw4(netif)      ((const IpAddr*)&((netif)->gw))


#define netif_set_flags(netif, set_flags)     do { (netif)->flags = (uint8_t)((netif)->flags |  (set_flags)); } while(0)
#define netif_clear_flags(netif, clr_flags)   do { (netif)->flags = (uint8_t)((netif)->flags & (uint8_t)(~(clr_flags) & 0xff)); } while(0)
#define netif_is_flag_set(nefif, flag)        (((netif)->flags & (flag)) != 0)

void netif_set_up(struct NetIfc *netif);
void netif_set_down(struct NetIfc *netif);
/** @ingroup netif
 * Ask if an interface is up
 */
#define netif_is_up(netif) (((netif)->flags & NETIF_FLAG_UP) ? (uint8_t)1 : (uint8_t)0)

void netif_set_status_callback(struct NetIfc *netif, netif_status_callback_fn status_callback);

void netif_set_remove_callback(struct NetIfc *netif, netif_status_callback_fn remove_callback);


void netif_set_link_up(struct NetIfc *netif);
void netif_set_link_down(struct NetIfc *netif);
/** Ask if a link is up */
#define netif_is_link_up(netif) (((netif)->flags & NETIF_FLAG_LINK_UP) ? (uint8_t)1 : (uint8_t)0)


void netif_set_link_callback(struct NetIfc *netif, netif_status_callback_fn link_callback);


/** @ingroup netif */
#define netif_set_hostname(netif, name) do { if((netif) != NULL) { (netif)->hostname = name; }}while(0)
/** @ingroup netif */
#define netif_get_hostname(netif) (((netif) != NULL) ? ((netif)->hostname) : NULL)

/** @ingroup netif */
#define netif_set_igmp_mac_filter(netif, function) do { if((netif) != NULL) { (netif)->igmp_mac_filter = function; }}while(0)
#define netif_get_igmp_mac_filter(netif) (((netif) != NULL) ? ((netif)->igmp_mac_filter) : NULL)

/** @ingroup netif */
#define netif_set_mld_mac_filter(netif, function) do { if((netif) != NULL) { (netif)->mld_mac_filter = function; }}while(0)
#define netif_get_mld_mac_filter(netif) (((netif) != NULL) ? ((netif)->mld_mac_filter) : NULL)
#define netif_mld_mac_filter(netif, addr, action) do { if((netif) && (netif)->mld_mac_filter) { (netif)->mld_mac_filter((netif), (addr), (action)); }}while(0)

LwipError netif_loop_output(struct NetIfc *netif, struct PacketBuffer *p);
void netif_poll(struct NetIfc *netif);

void netif_poll_all(void);


LwipError netif_input(struct PacketBuffer *p, struct NetIfc *inp);


/** @ingroup netif_ip6 */
#define netif_ip_addr6(netif, i)  ((const IpAddr*)(&((netif)->ip6_addr[i])))
/** @ingroup netif_ip6 */
#define netif_ip6_addr(netif, i)  ((const Ip6Addr*)ip_2_ip6(&((netif)->ip6_addr[i])))
void netif_ip6_addr_set(struct NetIfc *netif, int8_t addr_idx, const Ip6Addr*addr6);
void netif_ip6_addr_set_parts(struct NetIfc *netif, int8_t addr_idx, uint32_t i0, uint32_t i1, uint32_t i2, uint32_t i3);
#define netif_ip6_addr_state(netif, i)  ((netif)->ip6_addr_state[i])
void netif_ip6_addr_set_state(struct NetIfc* netif, int8_t addr_idx, uint8_t state);
int8_t netif_get_ip6_addr_match(struct NetIfc *netif, const Ip6Addr*ip6addr);
void netif_create_ip6_linklocal_address(struct NetIfc *netif, uint8_t from_mac_48bit);
LwipError netif_add_ip6_address(struct NetIfc *netif, const Ip6Addr*ip6addr, int8_t *chosen_idx);
#define netif_set_ip6_autoconfig_enabled(netif, action) do { if(netif) { (netif)->ip6_autoconfig_enabled = (action); }}while(0)

#define netif_ip6_addr_valid_life(netif, i)  \
    (((netif) != NULL) ? ((netif)->ip6_addr_valid_life[i]) : IP6_ADDR_LIFE_STATIC)
#define netif_ip6_addr_set_valid_life(netif, i, secs) \
    do { if (netif != NULL) { (netif)->ip6_addr_valid_life[i] = (secs); }} while (0)
#define netif_ip6_addr_pref_life(netif, i)  \
    (((netif) != NULL) ? ((netif)->ip6_addr_pref_life[i]) : IP6_ADDR_LIFE_STATIC)
#define netif_ip6_addr_set_pref_life(netif, i, secs) \
    do { if (netif != NULL) { (netif)->ip6_addr_pref_life[i] = (secs); }} while (0)
#define netif_ip6_addr_isstatic(netif, i)  \
    (netif_ip6_addr_valid_life((netif), (i)) == IP6_ADDR_LIFE_STATIC)

#define netif_mtu6(netif) ((netif)->mtu6)

#define NETIF_SET_HINTS(netif, netifhint)  (netif)->hints = (netifhint)
#define NETIF_RESET_HINTS(netif)      (netif)->hints = NULL


uint8_t netif_name_to_index(const char *name);
char * netif_index_to_name(uint8_t idx, char *name);
struct NetIfc* netif_get_by_index(uint8_t idx);

/* Interface indexes always start at 1 per RFC 3493, section 4, num starts at 0 (internal index is 0..254)*/
#define netif_get_index(netif)      ((uint8_t)((netif)->num + 1))
#define NETIF_NO_INDEX              (0)

/**
 * @ingroup netif
 * Extended netif status callback (NSC) reasons flags.
 * May be extended in the future!
 */
typedef uint16_t netif_nsc_reason_t;

/* used for initialization only */
constexpr auto LWIP_NSC_NONE = 0x0000;
/** netif was added. arg: NULL. Called AFTER netif was added. */
constexpr auto LWIP_NSC_NETIF_ADDED = 0x0001;
/** netif was removed. arg: NULL. Called BEFORE netif is removed. */
constexpr auto LWIP_NSC_NETIF_REMOVED = 0x0002;
/** link changed */
constexpr auto LWIP_NSC_LINK_CHANGED = 0x0004;
/** netif administrative status changed.\n
  * up is called AFTER netif is set up.\n
  * down is called BEFORE the netif is actually set down. */
constexpr auto LWIP_NSC_STATUS_CHANGED = 0x0008;
/** IPv4 address has changed */
constexpr auto LWIP_NSC_IPV4_ADDRESS_CHANGED = 0x0010;
/** IPv4 gateway has changed */
constexpr auto LWIP_NSC_IPV4_GATEWAY_CHANGED = 0x0020;
/** IPv4 netmask has changed */
constexpr auto LWIP_NSC_IPV4_NETMASK_CHANGED = 0x0040;
/** called AFTER IPv4 address/gateway/netmask changes have been applied */
constexpr auto LWIP_NSC_IPV4_SETTINGS_CHANGED = 0x0080;
/** IPv6 address was added */
constexpr auto LWIP_NSC_IPV6_SET = 0x0100;
/** IPv6 address state has changed */
constexpr auto LWIP_NSC_IPV6_ADDR_STATE_CHANGED = 0x0200;

/** @ingroup netif
 * Argument supplied to netif_ext_callback_fn.
 */
 union netif_ext_callback_args_t {
  /** Args to LWIP_NSC_LINK_CHANGED callback */
  struct link_changed {
    /** 1: up; 0: down */
    uint8_t state;
  } ;
  /** Args to LWIP_NSC_STATUS_CHANGED callback */
  struct status_changed {
    /** 1: up; 0: down */
    uint8_t state;
  } ;
  /** Args to LWIP_NSC_IPV4_ADDRESS_CHANGED|LWIP_NSC_IPV4_GATEWAY_CHANGED|LWIP_NSC_IPV4_NETMASK_CHANGED|LWIP_NSC_IPV4_SETTINGS_CHANGED callback */
  struct ipv4_changed {
    /** Old IPv4 address */
    const IpAddr *old_address;
    const IpAddr *old_netmask;
    const IpAddr *old_gw;
  } ;
  /** Args to LWIP_NSC_IPV6_SET callback */
  struct ipv6_set {
    /** Index of changed IPv6 address */
    int8_t addr_index;
    /** Old IPv6 address */
    const IpAddr *old_address;
  } ;
  /** Args to LWIP_NSC_IPV6_ADDR_STATE_CHANGED callback */
  struct ipv6_addr_state_changed_s {
    /** Index of affected IPv6 address */
    int8_t addr_index;
    /** Old IPv6 address state */
    uint8_t old_state;
    /** Affected IPv6 address */
    const IpAddr* address;
  } ipv6_addr_state_changed;
} ;

/**
 * @ingroup netif
 * Function used for extended netif status callbacks
 * Note: When parsing reason argument, keep in mind that more reasons may be added in the future!
 * @param netif netif that is affected by change
 * @param reason change reason
 * @param args depends on reason, see reason description
 */
typedef void(*netif_ext_callback_fn)(struct NetIfc *netif,
                                     netif_nsc_reason_t reason,
                                     const netif_ext_callback_args_t *args);

struct netif_ext_callback_t
{
  netif_ext_callback_fn callback_fn;
  struct netif_ext_callback_t* next;
} ;

#define NETIF_DECLARE_EXT_CALLBACK(name) static netif_ext_callback_t name;
void netif_add_ext_callback(netif_ext_callback_t* callback, netif_ext_callback_fn fn);
void netif_remove_ext_callback(netif_ext_callback_t* callback);
void netif_invoke_ext_callback(struct NetIfc* netif, netif_nsc_reason_t reason, const netif_ext_callback_args_t* args);

#ifdef __cplusplus
}
#endif
