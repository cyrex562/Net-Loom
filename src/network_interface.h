//
// netif API (to be used from TCPIP thread)
//

#pragma once

#include <lwip_status.h>
#include <packet_buffer.h>
#include <ip_addr.h>
#include <def.h>
#include <ip4_addr.h>
#include <ip6_addr.h>
#include <igmp_grp.h>
#include <array>

struct Ip6Addr;

/* Throughout this file, IP addresses are expected to be in
 * the same byte order as in IP_PCB. */

/** Must be the maximum of all used hardware address lengths
    across all types of interfaces in use.
    This does not have to be changed, normally. */

/** The size of a fully constructed netif name which the
 * netif can be identified by in APIs. Composed of
 * 2 chars, 3 (max) digits, and 1 \0
 */
constexpr auto NETIFC_NAME_SZ = 6;

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
enum NetIfcFlag : uint8_t
{
    NETIF_FLAG_UP = 0x01U,
    /** If set, the netif has broadcast capability.
    * Set by the netif driver in its init function. */
    NETIF_FLAG_BCAST = 0x02U,
    /** If set, the interface has an active link
    *  (set by the network interface driver).
    * Either set by the netif driver in its init function (if the link
    * is up at that time) or at a later point once the link comes up
    * (if link detection is supported by the hardware). */
    NETIF_FLAG_LINK_UP = 0x04U,
    /** If set, the netif is an ethernet device using ARP.
    * Set by the netif driver in its init function.
    * Used to check input packet types and use of DHCP. */
    NETIF_FLAG_ETH_ARP = 0x08U,
    /** If set, the netif is an ethernet device. It might not use
    * ARP or TCP/IP if it is used for PPPoE only.
    */
    NETIF_FLAG_ETH = 0x10U,
    /** If set, the netif has IGMP capability.
    * Set by the netif driver in its init function. */
    NETIF_FLAG_IGMP = 0x20U,
    /** If set, the netif has MLD6 capability.
    * Set by the netif driver in its init function. */
    NETIF_FLAG_MLD6 = 0x40U,
};


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


struct NetworkInterface;

/** MAC Filter Actions, these are passed to a netif's igmp_mac_filter or
 * mld_mac_filter callback function. */
enum NetifMacFilterAction {
  /** Delete a filter entry */
      NETIF_DEL_MAC_FILTER = 0,
  /** Add a filter entry */
      NETIF_ADD_MAC_FILTER = 1
};

//
// Function prototype for netif init functions. Set up flags and output/linkoutput
// callback functions in this function.
//
// netif: The netif to initialize
// returns LwipStatus
//
using NetifInitFn = LwipStatus (*)(NetworkInterface*);

/** Function prototype for netif->input functions. This function is saved as 'input'
 * callback function in the netif struct. Call it when a packet has been received.
 *
 * @param p The received packet, copied into a PacketBuffer
 * @param inp The netif which received the packet
 * @return ERR_OK if the packet was handled
 *         != ERR_OK is the packet was NOT handled, in this case, the caller has
 *                   to free the PacketBuffer
 */
using NetifInputFn = LwipStatus (*)(PacketBuffer*, NetworkInterface*);


// Function prototype for netif->output functions. Called by lwIP when a packet
// shall be sent. For ethernet netif, set this to 'etharp_output' and set
// 'linkoutput'.
//
// @param netif
// @param netif The netif which shall send a packet
// @param p The packet to send (p->payload points to IP header)
// @param ipaddr The IP address to which the packet shall be sent
//
using netif_output_fn = LwipStatus (*)(NetworkInterface*,
                                       PacketBuffer*,
                                       const Ip4Addr*);


/** Function prototype for netif->output_ip6 functions. Called by lwIP when a packet
 * shall be sent. For ethernet netif, set this to 'ethip6_output' and set
 * 'linkoutput'.
 *
 * @param netif The netif which shall send a packet
 * @param p The packet to send (p->payload points to IP header)
 * @param ipaddr The IPv6 address to which the packet shall be sent
 */
using netif_output_ip6_fn = LwipStatus (*)(NetworkInterface*,
                                           PacketBuffer*,
                                           const Ip6Addr*);

/** Function prototype for netif->linkoutput functions. Only used for ethernet
 * netifs. This function is called by ARP when a packet shall be sent.
 *
 * @param netif The netif which shall send a packet
 * @param p The packet to send (raw ethernet packet)
 */
using netif_linkoutput_fn = LwipStatus (*)(NetworkInterface*, PacketBuffer*);
/** Function prototype for netif status- or link-callback functions. */
using netif_status_callback_fn = void (*)(NetworkInterface*);

/** Function prototype for netif igmp_mac_filter functions */
using NetifIgmpMacFilterFn = LwipStatus (*)(NetworkInterface*,
                                                const Ip4Addr*,
                                                NetifMacFilterAction);

/** Function prototype for netif mld_mac_filter functions */
using netif_mld_mac_filter_fn = LwipStatus (*)( NetworkInterface*,
                                                const Ip6Addr*,
                                                NetifMacFilterAction);

/** @ingroup netif_cd
 * Set client data. Obtain ID from netif_alloc_client_data_id().
 */

/** @ingroup netif_cd
 * Get client data. Obtain ID from netif_alloc_client_data_id().
 */


uint8_t netif_alloc_client_data_id();

using NetIfcAddrIdx = uint16_t;

constexpr auto NETIF_ADDR_IDX_MAX = 0x7FFF;

struct NetIfcHint
{
    NetIfcAddrIdx addr_hint;
};


/** Generic data structure used for all lwIP network interfaces.
 *  The following fields should be filled in by the initialization
 *  function for the device driver: hwaddr_len, hwaddr[], mtu, flags */
struct NetworkInterface
{
    /** pointer to next in linked list */
    struct NetworkInterface* next; /** IP address configuration in network byte order */
    IpAddr ip_addr;
    IpAddr netmask;
    IpAddr gw; /** Array of IPv6 addresses for this netif. */
    // std::array<IpAddr, LWIP_IPV6_NUM_ADDRESSES> ip6_addr;
    IpAddr ip6_addr[LWIP_IPV6_NUM_ADDRESSES];
    /** The state of each IPv6 address (Tentative, Preferred, etc).
            * @see ip6_addr.h */
    Ip6AddrStates ip6_addr_state[LWIP_IPV6_NUM_ADDRESSES];
    /** Remaining valid and preferred lifetime of each IPv6 address, in seconds.
            * For valid lifetimes, the special value of IP6_ADDR_LIFE_STATIC (0)
            * indicates the address is static and has no lifetimes. */
    uint32_t ip6_addr_valid_life[LWIP_IPV6_NUM_ADDRESSES];
    uint32_t ip6_addr_pref_life[LWIP_IPV6_NUM_ADDRESSES];
    /** This function is called by the network device driver
            *  to pass a packet up the TCP/IP stack. */
    NetifInputFn input; /** This function is called by the IP module when it wants
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
    uint8_t hwaddr[NETIF_MAX_HWADDR_LEN]; /** number of bytes used in hwaddr */
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
    NetifIgmpMacFilterFn igmp_mac_filter;
    /** This function could be called to add or delete an entry in the IPv6 multicast
               filter table of the ethernet MAC. */
    netif_mld_mac_filter_fn mld_mac_filter;
    struct NetIfcHint* hints; /* List of packets to be queued for ourselves. */
    struct PacketBuffer* loop_first;
    struct PacketBuffer* loop_last;
    uint16_t loop_cnt_current;
};

//
//
//
inline void* netif_get_client_data(NetworkInterface* netif, const size_t id)
{
    return netif->client_data[id];
}

//
//
//
inline void netif_set_client_data(NetworkInterface* netif, const size_t id, void* data)
{
    netif->client_data[id] = data;
}

//
//
//
inline void NetifSetChecksumCtrl(NetworkInterface* netif, const uint16_t chksumflags)
{
    netif->chksum_flags = chksumflags;
}

//
//
//
inline bool is_netif_checksum_enabled(NetworkInterface* netif, uint16_t chksumflag)
{
    return netif == nullptr || (netif->chksum_flags & chksumflag) != 0;
}


// The list of network interfaces.
extern struct NetworkInterface *netif_list;

/** The default network interface. */
extern struct NetworkInterface *netif_default;

void netif_init(NetworkInterface* loop_netif);

struct NetworkInterface *netif_add_noaddr(struct NetworkInterface *netif,
                               uint8_t *state,
                               NetifInitFn init,
                               NetifInputFn input);


struct NetworkInterface *netif_add(NetworkInterface *netif,
                        const Ip4Addr *ipaddr,
                        const Ip4Addr *netmask,
                        const Ip4Addr *gw,
                        uint8_t *state,
                        NetifInitFn init,
                        NetifInputFn input);

bool netif_set_addr(struct NetworkInterface* netif,
                    const Ip4Addr* ipaddr,
                    const Ip4Addr* netmask,
                    const Ip4Addr* gw);

void netif_remove(struct NetworkInterface *netif);

/* Returns a network interface given its name. The name is of the form
   "et0", where the first two letters are the "name" field in the
   netif structure, and the digit is in the num field in the same
   structure. */
struct NetworkInterface *netif_find(const char *name);

void netif_set_default(struct NetworkInterface *netif);

void netif_set_ipaddr(struct NetworkInterface *netif, const Ip4Addr *ipaddr);
void netif_set_netmask(struct NetworkInterface *netif, const Ip4Addr *netmask);
void netif_set_gw(struct NetworkInterface *netif, const Ip4Addr *gw);



//
// Get Ip4 Address from the NetworkInterface
inline const Ip4Addr* get_net_ifc_ip4_addr(const NetworkInterface* netif)
{
    return &netif->ip_addr.u_addr.ip4;
}

//
//
//
inline const Ip4Addr* netif_ip4_netmask(const NetworkInterface* netif)
{
    return static_cast<const Ip4Addr*>(&netif->netmask.u_addr.ip4);
}


/** @ingroup netif_ip4 */
inline Ip4Addr *netif_ip4_gw(NetworkInterface *netif) {
  return static_cast<Ip4Addr *>(&netif->gw.u_addr.ip4);
}

struct IpAddr;

/** @ingroup netif_ip4 */
inline const IpAddr* netif_ip_addr4(const NetworkInterface* netif)
{
    return static_cast<const IpAddr *>(&((netif)->ip_addr));
}


/** @ingroup netif_ip4 */
inline IpAddr* netif_ip_netmask4(NetworkInterface* netif)
{
    return static_cast<IpAddr*>(&netif->netmask);
}

/** @ingroup netif_ip4 */
inline IpAddr* netif_ip_gw4(NetworkInterface* netif)
{
    return static_cast<IpAddr*>(&((netif)->gw));
}

inline void netif_set_flags(NetworkInterface* netif, const uint8_t set_flags)
{
    (netif)->flags = uint8_t((netif)->flags | (set_flags));
}

inline void netif_clear_flags(NetworkInterface* netif, const uint8_t clr_flags)
{
    (netif)->flags = uint8_t((netif)->flags & uint8_t(~(clr_flags) & 0xff));
}

inline void netif_is_flag_set(NetworkInterface* netif, uint8_t flag)
{
    (((netif)->flags & (flag)) != 0);
}

void netif_set_up(struct NetworkInterface *netif);
void netif_set_down(struct NetworkInterface *netif);
/** @ingroup netif
 * Ask if an interface is up
 */
inline bool netif_is_up(NetworkInterface* netif)
{
    return netif->flags & NETIF_FLAG_UP ? uint8_t(1) : uint8_t(0);
}

void netif_set_status_callback(struct NetworkInterface *netif, netif_status_callback_fn status_callback);

void netif_set_remove_callback(struct NetworkInterface *netif, netif_status_callback_fn remove_callback);


void netif_set_link_up(struct NetworkInterface *netif);
void netif_set_link_down(struct NetworkInterface *netif);
/** Ask if a link is up */
inline bool netif_is_link_up(NetworkInterface* netif)
{
    return (netif->flags & NETIF_FLAG_LINK_UP) != 0;
}

void netif_set_link_callback(struct NetworkInterface *netif, netif_status_callback_fn link_callback);


/** @ingroup netif */
inline void netif_set_hostname(NetworkInterface* netif, const char* name)
{
    if (netif != nullptr)
    {
        (netif)->hostname = name;
    }
}

/** @ingroup netif */
inline const char* netif_get_hostname(NetworkInterface* netif)
{
    if (netif != nullptr)
    {
        return netif->hostname;
    }
    return nullptr;
}

/** @ingroup netif */
// #define netif_set_mld_mac_filter(netif, function) do { if((netif) != NULL) { (netif)->mld_mac_filter = function; }}while(0)

// #define netif_get_mld_mac_filter(netif) (((netif) != NULL) ? ((netif)->mld_mac_filter) : NULL)


// #define netif_mld_mac_filter(netif, addr, action) do { if((netif) && (netif)->mld_mac_filter) { (netif)->mld_mac_filter((netif), (addr), (action)); }}while(0)

LwipStatus netif_loop_output(struct NetworkInterface *netif, struct PacketBuffer *p, NetworkInterface* loop_netif);
void netif_poll(struct NetworkInterface *netif);

void netif_poll_all(void);


LwipStatus netif_input(struct PacketBuffer *p, struct NetworkInterface *inp);


/** @ingroup netif_ip6 */
inline const IpAddr* netif_ip_addr6(const NetworkInterface* netif, const size_t i)
{
    return ((const IpAddr*)(&((netif)->ip6_addr[i])));
}


/** @ingroup netif_ip6 */
inline const Ip6Addr* netif_ip6_addr(const NetworkInterface* netif, const size_t index)
{
    return &netif->ip6_addr[index].u_addr.ip6;
}


void netif_ip6_addr_set(struct NetworkInterface *netif, int8_t addr_idx, const Ip6Addr*addr6);
void netif_ip6_addr_set_parts(struct NetworkInterface *netif, int8_t addr_idx, uint32_t i0, uint32_t i1, uint32_t i2, uint32_t i3);

inline Ip6AddrStates netif_ip6_addr_state(const NetworkInterface* netif, const size_t i)
{
    return ((netif)->ip6_addr_state[i]);
}


void netif_ip6_addr_set_state(struct NetworkInterface* netif, int8_t addr_idx, Ip6AddrStates state);
int8_t netif_get_ip6_addr_match(struct NetworkInterface *netif, const Ip6Addr*ip6addr);
void netif_create_ip6_linklocal_address(struct NetworkInterface *netif, uint8_t from_mac_48bit);
LwipStatus netif_add_ip6_address(struct NetworkInterface *netif, const Ip6Addr*ip6addr, int8_t *chosen_idx);

// #define netif_set_ip6_autoconfig_enabled(netif, action) do { if(netif) { (netif)->ip6_autoconfig_enabled = (action); }}while(0)

inline uint32_t netif_ip6_addr_valid_life(NetworkInterface* netif, size_t i)
{
    return (((netif) != nullptr) ? ((netif)->ip6_addr_valid_life[i]) : 0);
}

inline void netif_ip6_addr_set_valid_life(NetworkInterface* netif, const size_t i, const uint32_t secs)
{
    if (netif != nullptr)
    {
        (netif)->ip6_addr_valid_life[i] = (secs);
    }
}

inline uint32_t netif_ip6_addr_pref_life(NetworkInterface* netif, const size_t i)
{
    return (((netif) != nullptr) ? ((netif)->ip6_addr_pref_life[i]) : 0);
}

inline void netif_ip6_addr_set_pref_life(NetworkInterface* netif, size_t i, uint32_t secs)
{
    if (netif != nullptr)
    {
        (netif)->ip6_addr_pref_life[i] = (secs);
    }
}

inline bool netif_ip6_addr_isstatic(NetworkInterface* netif, size_t i)
{
    return (netif_ip6_addr_valid_life((netif), (i)) == 0);
}

inline uint32_t netif_mtu6(NetworkInterface* netif)
{
    return ((netif)->mtu6);
}

inline void NETIF_SET_HINTS(NetworkInterface* netif, NetIfcHint* netifhint)
{
    (netif)->hints = (netifhint);
}


inline void NETIF_RESET_HINTS(NetworkInterface* netif){      (netif)->hints = nullptr;}


uint8_t netif_name_to_index(const char *name);
char * netif_index_to_name(uint8_t idx, char *name);
struct NetworkInterface* netif_get_by_index(uint8_t idx);

/* Interface indexes always start at 1 per RFC 3493, section 4, num starts at 0 (internal index is 0..254)*/
inline uint8_t netif_get_index(const NetworkInterface* netif)
{
    return uint8_t(netif->num + 1);
}

constexpr auto NETIF_NO_INDEX = -1;

/**
 * @ingroup netif
 * Extended netif status callback (NSC) reasons flags.
 * May be extended in the future!
 */
using NetifNscReason = uint16_t;

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
union netif_ext_callback_args_t
{
    /** Args to LWIP_NSC_LINK_CHANGED callback */
    struct link_changed
    {
        /** 1: up; 0: down */
        uint8_t state;
    }; /** Args to LWIP_NSC_STATUS_CHANGED callback */
    struct status_changed
    {
        /** 1: up; 0: down */
        uint8_t state;
    }; /** Args to LWIP_NSC_IPV4_ADDRESS_CHANGED|LWIP_NSC_IPV4_GATEWAY_CHANGED|LWIP_NSC_IPV4_NETMASK_CHANGED|LWIP_NSC_IPV4_SETTINGS_CHANGED callback */
    struct ipv4_changed
    {
        /** Old IPv4 address */
        const IpAddr* old_address;
        const IpAddr* old_netmask;
        const IpAddr* old_gw;
    }; /** Args to LWIP_NSC_IPV6_SET callback */
    struct ipv6_set
    {
        /** Index of changed IPv6 address */
        int8_t addr_index; /** Old IPv6 address */
        const IpAddr* old_address;
    }; /** Args to LWIP_NSC_IPV6_ADDR_STATE_CHANGED callback */
    struct ipv6_addr_state_changed_s
    {
        /** Index of affected IPv6 address */
        int8_t addr_index; /** Old IPv6 address state */
        uint8_t old_state; /** Affected IPv6 address */
        const IpAddr* address;
    } ipv6_addr_state_changed;
};

/**
 * @ingroup netif
 * Function used for extended netif status callbacks
 * Note: When parsing reason argument, keep in mind that more reasons may be added in the future!
 * @param netif netif that is affected by change
 * @param reason change reason
 * @param args depends on reason, see reason description
 */
typedef void (*netif_ext_callback_fn)(struct NetworkInterface* netif,
                                      NetifNscReason reason,
                                      const netif_ext_callback_args_t* args);

struct netif_ext_callback_t
{
    netif_ext_callback_fn callback_fn;
    struct netif_ext_callback_t* next;
};

// #define NETIF_DECLARE_EXT_CALLBACK(name) static netif_ext_callback_t name;
void netif_add_ext_callback(netif_ext_callback_t* callback, netif_ext_callback_fn fn);
void netif_remove_ext_callback(netif_ext_callback_t* callback);
void netif_invoke_ext_callback(struct NetworkInterface* netif, NetifNscReason reason, const netif_ext_callback_args_t* args);

//
//
//
inline bool ip6_addr_est_zone(const Ip6Addr* ip6addr, const NetworkInterface* netif)
{
    return (ip6_addr_equals_zone((ip6addr), netif_get_index(netif)));
}

// Verify that the given IPv6 address is properly zoned for the given netif.
//
//
inline void IP6_ADDR_ZONECHECK_NETIF(const Ip6Addr* ip6addr, NetworkInterface* netif)
{
    lwip_assert("IPv6 netif zone check failed",
                ip6_addr_has_scope(ip6addr, IP6_UNKNOWN)
                    ? (ip6_addr_has_zone(ip6addr) && (((netif) == nullptr) ||
                        ip6_addr_est_zone((ip6addr), (netif))))
                    : !ip6_addr_has_zone(ip6addr));
}


/**
 * Assign a zone index to an IPv6 address, based on a network interface. If the
 * given address has a scope, the assigned zone index is that scope's zone of
 * the given netif; otherwise, the assigned zone index is "no zone".
 *
 * This default implementation follows the default model of RFC 4007, where
 * only interface-local and link-local scopes are defined, and the zone index
 * of both of those scopes always equals the index of the network interface.
 * As such, this default implementation need not distinguish between different
 * constrained scopes when assigning the zone.
 *
 * @param ip6addr the IPv6 address; its address part is examined, and its zone
 *                index is assigned.
 * @param type address type; see @ref lwip_ipv6_scope_type.
 * @param netif the network interface (const).
 */
inline void ip6_addr_assign_zone(Ip6Addr* ip6addr,
                                 const Ip6ScopeTypes type,
                                 const NetworkInterface* netif)
{
    if (ip6_addr_has_scope((ip6addr), (type)))
        (ip6_addr_set_zone((ip6addr), netif_get_index(netif)));
    else
        (ip6_addr_set_zone((ip6addr), 0));
}


const IpAddr* ip6_select_source_address(const NetworkInterface* netif, const Ip6Addr* dest);

inline const IpAddr* ip4_netif_get_local_ip(const NetworkInterface* netif)
{
    return netif != nullptr ? netif_ip_addr4(netif) : nullptr;
}

inline const IpAddr* ip6_netif_get_local_ip(const NetworkInterface* netif, const Ip6Addr* dest)
{
    return (((netif) != nullptr) ? ip6_select_source_address(netif, dest) : nullptr);
}





/** @ingroup igmp
 * Get list head of IGMP groups for netif.
 * Note: The allsystems group IP is contained in the list as first entry.
 * @see @ref netif_set_igmp_mac_filter()
 */
inline IgmpGroup* netif_igmp_data(NetworkInterface* netif)
{
    return static_cast<IgmpGroup *>(netif->client_data[LWIP_NETIF_CLIENT_DATA_INDEX_IGMP]
    );
}


/**
 * Search for a group in the netif's igmp group list
 *
 * @param ifp the network interface for which to look
 * @param addr the group ip address to search for
 * @return a struct igmp_group* if the group has been found,
 *         NULL if the group wasn't found.
 */
inline IgmpGroup*
igmp_lookfor_group(NetworkInterface* ifp, const Ip4Addr* addr)
{
    IgmpGroup* group = netif_igmp_data(ifp);
    while (group != nullptr) {
        if (ip4_addr_cmp(&(group->group_address), addr)) {
            return group;
        }
        group = group->next;
    } /* to be clearer, we return NULL here instead of
   * 'group' (which is also NULL at this point).
   */
    return nullptr;
}

#define IF_NAMESIZE NETIF_NAMESIZE

char * lwip_if_indextoname(unsigned int ifindex, char *ifname);
unsigned int lwip_if_nametoindex(const char *ifname);

#define if_indextoname(ifindex, ifname)  lwip_if_indextoname(ifindex,ifname)
#define if_nametoindex(ifname)           lwip_if_nametoindex(ifname)

//
// END OF FILE
//