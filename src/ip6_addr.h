#pragma once

#include "def.h"
#include "lwip_debug.h"
#include "netif.h"
#include "opt.h"

enum Ip6Zone : uint8_t {
  kIp6NoZone = 0,
};

/** This is the aligned version of Ip6Addr,
    used as local variable, on the stack, etc. */
struct Ip6Addr {
  uint32_t addr[4];
  Ip6Zone zone;
};

/** Symbolic constants for the 'type' parameters in some of the macros.
 * These exist for efficiency only, allowing the macros to avoid certain tests
 * when the address is known not to be of a certain type. Dead code elimination
 * will do the rest. IP6_MULTICAST is supported but currently not optimized.
 * @see ip6_addr_has_scope, ip6_addr_assign_zone, ip6_addr_lacks_zone.
 */
enum LwipIpv6ScopeType {
  /** Unknown */
  IP6_UNKNOWN = 0,
  /** Unicast */
  IP6_UNICAST = 1,
  /** Multicast */
  IP6_MULTICAST = 2
};

/** Identifier for "no zone". */

/** Return the zone index of the given IPv6 address; possibly "no zone". */
inline Ip6Zone ip6_addr_zone(const Ip6Addr* ip6addr) {
  return ((ip6addr)->zone);
}

/** Does the given IPv6 address have a zone set? (0/1) */
inline bool ip6_addr_has_zone(const Ip6Addr* ip6addr) {
  return (ip6_addr_zone(ip6addr) != kIp6NoZone);
}

/** Set the zone field of an IPv6 address to a particular value. */
inline void ip6_addr_set_zone(Ip6Addr* ip6addr, int zone_idx) {
  ((ip6addr)->zone = Ip6Zone(zone_idx));
}

/** Clear the zone field of an IPv6 address, setting it to "no zone". */
inline void ip6_addr_clear_zone(Ip6Addr* ip6_addr) {
  ((ip6_addr)->zone = kIp6NoZone);
}

/** Is the zone field of the given IPv6 address equal to the given zone index?
 * (0/1) */
#define ip6_addr_equals_zone(ip6addr, zone_idx) ((ip6addr)->zone == (zone_idx))

/** Are the zone fields of the given IPv6 addresses equal? (0/1)
 * This macro must only be used on IPv6 addresses of the same scope. */
inline bool ip6_addr_cmp_zone(const Ip6Addr* ip6addr1,
                              const Ip6Addr* ip6addr2) {
  return ((ip6addr1)->zone == (ip6addr2)->zone);
}

/** IPV6_CUSTOM_SCOPES: together, the following three macro definitions,
 * @ref ip6_addr_has_scope, @ref ip6_addr_assign_zone, and
 * @ref LwipIp6Addrest_zone, completely define the lwIP scoping policy.
 * The definitions below implement the default policy from RFC 4007 Sec. 6.
 * Should an implementation desire to implement a different policy, it can
 * define IPV6_CUSTOM_SCOPES to 1 and supply its own definitions for the three
 * macros instead.
 */

constexpr auto IPV6_CUSTOM_SCOPES = 0;

inline bool ip6_addr_islinklocal(const Ip6Addr* ip6_addr)
{
    return (ip6_addr->addr[0] & pp_htonl(0xffc00000UL)) == pp_htonl(0xfe800000UL);
}

#define ip6_addr_ismulticast_iflocal(ip6addr) \
  (((ip6addr)->addr[0] & PP_HTONL(0xff8f0000UL)) == PP_HTONL(0xff010000UL))

#define ip6_addr_ismulticast_linklocal(ip6addr) \
  (((ip6addr)->addr[0] & PP_HTONL(0xff8f0000UL)) == PP_HTONL(0xff020000UL))

/**
 * Determine whether an IPv6 address has a constrained scope, and as such is
 * meaningful only if accompanied by a zone index to identify the scope's zone.
 * The given address type may be used to eliminate at compile time certain
 * checks that will evaluate to false at run time anyway.
 *
 * This default implementation follows the default model of RFC 4007, where
 * only interface-local and link-local scopes are defined.
 *
 * Even though the unicast loopback address does have an implied link-local
 * scope, in this implementation it does not have an explicitly assigned zone
 * index. As such it should not be tested for in this macro.
 *
 * @param ip6addr the IPv6 address (const); only its address part is examined.
 * @param type address type; see @ref lwip_ipv6_scope_type.
 * @return 1 if the address has a constrained scope, 0 if it does not.
 */
inline bool ip6_addr_has_scope(const Ip6Addr* ip6addr,
                               const LwipIpv6ScopeType type) {
  return (
      ip6_addr_islinklocal(ip6addr) ||
      (((type) != IP6_UNICAST) && (ip6_addr_ismulticast_iflocal(ip6addr) ||
                                   ip6_addr_ismulticast_linklocal(ip6addr))));
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
#define ip6_addr_assign_zone(ip6addr, type, netif)                    \
  (ip6_addr_set_zone((ip6addr), ip6_addr_has_scope((ip6addr), (type)) \
                                    ? netif_get_index(netif)          \
                                    : 0))

/**
 * Test whether an IPv6 address is "zone-compatible" with a network interface.
 * That is, test whether the network interface is part of the zone associated
 * with the address. For efficiency, this macro is only ever called if the
 * given address is either scoped or zoned, and thus, it need not test this.
 * If an address is scoped but not zoned, or zoned and not scoped, it is
 * considered not zone-compatible with any netif.
 *
 * This default implementation follows the default model of RFC 4007, where
 * only interface-local and link-local scopes are defined, and the zone index
 * of both of those scopes always equals the index of the network interface.
 * As such, there is always only one matching netif for a specific zone index,
 * but all call sites of this macro currently support multiple matching netifs
 * as well (at no additional expense in the common case).
 *
 * @param ip6addr the IPv6 address (const).
 * @param netif the network interface (const).
 * @return 1 if the address is scope-compatible with the netif, 0 if not.
 */
#define LwipIp6Addrest_zone(ip6addr, netif) \
  (ip6_addr_equals_zone((ip6addr), netif_get_index(netif)))

/** Does the given IPv6 address have a scope, and as such should also have a
 * zone to be meaningful, but does not actually have a zone? (0/1) */
#define ip6_addr_lacks_zone(ip6addr, type) \
  (!ip6_addr_has_zone(ip6addr) && ip6_addr_has_scope((ip6addr), (type)))

/**
 * Try to select a zone for a scoped address that does not yet have a zone.
 * Called from PCB bind and connect routines, for two reasons: 1) to save on
 * this (relatively expensive) selection for every individual packet route
 * operation and 2) to allow the application to obtain the selected zone from
 * the PCB as is customary for e.g. getsockname/getpeername BSD socket calls.
 *
 * Ideally, callers would always supply a properly zoned address, in which case
 * this function would not be needed. It exists both for compatibility with the
 * BSD socket API (which accepts zoneless destination addresses) and for
 * backward compatibility with pre-scoping lwIP code.
 *
 * It may be impossible to select a zone, e.g. if there are no netifs.  In that
 * case, the address's zone field will be left as is.
 *
 * @param dest the IPv6 address for which to select and set a zone.
 * @param src source IPv6 address (const); may be equal to dest.
 */
#define ip6_addr_select_zone(dest, src)                          \
  do {                                                           \
    NetIfc* selected_netif;                                      \
    selected_netif = ip6_route((src), (dest));                   \
    if (selected_netif != NULL) {                                \
      ip6_addr_assign_zone((dest), IP6_UNKNOWN, selected_netif); \
    }                                                            \
  } while (0)

/** Verify that the given IPv6 address is properly zoned. */
inline void IP6_ADDR_ZONECHECK(const Ip6Addr* ip6addr) {
  lwip_assert(
      "IPv6 zone check failed",
      ip6_addr_has_scope(ip6addr, IP6_UNKNOWN) == ip6_addr_has_zone(ip6addr));
}

struct NetIfc;

/** Verify that the given IPv6 address is properly zoned for the given netif. */
inline void IP6_ADDR_ZONECHECK_NETIF(const Ip6Addr* ip6addr, NetIfc* netif)
{
    lwip_assert("IPv6 netif zone check failed",
                ip6_addr_has_scope(ip6addr, IP6_UNKNOWN)
                    ? (ip6_addr_has_zone(ip6addr) && (((netif) == nullptr) ||
                        LwipIp6Addrest_zone((ip6addr), (netif))))
                    : !ip6_addr_has_zone(ip6addr));
}

inline bool ip6_addr_cmp_zoneless(const Ip6Addr* addr1, const Ip6Addr* addr2) {
  return (((addr1)->addr[0] == (addr2)->addr[0]) &&
          ((addr1)->addr[1] == (addr2)->addr[1]) &&
          ((addr1)->addr[2] == (addr2)->addr[2]) &&
          ((addr1)->addr[3] == (addr2)->addr[3]));
}

inline bool ip6_addr_cmp(const Ip6Addr* addr1, const Ip6Addr* addr2) {
  return (ip6_addr_cmp_zoneless((addr1), (addr2)) &&
          ip6_addr_cmp_zone((addr1), (addr2)));
}

/** Set an IPv6 partial address given by byte-parts */
#define IP6_ADDR_PART(ip6addr, index, a, b, c, d) \
  (ip6addr)->addr[index] = PP_HTONL(LWIP_MAKEU32(a, b, c, d))

/** Set a full IPv6 address by passing the 4 uint32_t indices in network byte
   order (use PP_HTONL() for constants) */
inline void IP6_ADDR(Ip6Addr* ip6addr, uint32_t idx0, uint32_t idx1,
                     uint32_t idx2, uint32_t idx3) {
  (ip6addr)->addr[0] = idx0;
  (ip6addr)->addr[1] = idx1;
  (ip6addr)->addr[2] = idx2;
  (ip6addr)->addr[3] = idx3;
  ip6_addr_clear_zone(ip6addr);
}

/** Access address in 16-bit block */
#define IP6_ADDR_BLOCK1(ip6addr) \
  ((uint16_t)((lwip_htonl((ip6addr)->addr[0]) >> 16) & 0xffff))
/** Access address in 16-bit block */
#define IP6_ADDR_BLOCK2(ip6addr) \
  ((uint16_t)((lwip_htonl((ip6addr)->addr[0])) & 0xffff))
/** Access address in 16-bit block */
#define IP6_ADDR_BLOCK3(ip6addr) \
  ((uint16_t)((lwip_htonl((ip6addr)->addr[1]) >> 16) & 0xffff))
/** Access address in 16-bit block */
#define IP6_ADDR_BLOCK4(ip6addr) \
  ((uint16_t)((lwip_htonl((ip6addr)->addr[1])) & 0xffff))
/** Access address in 16-bit block */
#define IP6_ADDR_BLOCK5(ip6addr) \
  ((uint16_t)((lwip_htonl((ip6addr)->addr[2]) >> 16) & 0xffff))
/** Access address in 16-bit block */
#define IP6_ADDR_BLOCK6(ip6addr) \
  ((uint16_t)((lwip_htonl((ip6addr)->addr[2])) & 0xffff))
/** Access address in 16-bit block */
#define IP6_ADDR_BLOCK7(ip6addr) \
  ((uint16_t)((lwip_htonl((ip6addr)->addr[3]) >> 16) & 0xffff))
/** Access address in 16-bit block */
#define IP6_ADDR_BLOCK8(ip6addr) \
  ((uint16_t)((lwip_htonl((ip6addr)->addr[3])) & 0xffff))

/** Safely copy one IPv6 address to another (src may be NULL) */
inline void ip6_addr_set(Ip6Addr* dest, Ip6Addr* src) {
  (dest)->addr[0] = (src) == nullptr ? 0 : (src)->addr[0];
  (dest)->addr[1] = (src) == nullptr ? 0 : (src)->addr[1];
  (dest)->addr[2] = (src) == nullptr ? 0 : (src)->addr[2];
  (dest)->addr[3] = (src) == nullptr ? 0 : (src)->addr[3];
  ip6_addr_set_zone((dest), (src) == nullptr ? kIp6NoZone : ip6_addr_zone(src));
}

/** Copy packed IPv6 address to unpacked IPv6 address; zone is not set */
#define ip6_addr_copy_from_packed(dest, src) \
  do {                                       \
    (dest).addr[0] = (src).addr[0];          \
    (dest).addr[1] = (src).addr[1];          \
    (dest).addr[2] = (src).addr[2];          \
    (dest).addr[3] = (src).addr[3];          \
    ip6_addr_clear_zone(&dest);              \
  } while (0)

/** Copy unpacked IPv6 address to packed IPv6 address; zone is lost */
#define ip6_addr_copy_to_packed(dest, src) \
  do {                                     \
    (dest).addr[0] = (src).addr[0];        \
    (dest).addr[1] = (src).addr[1];        \
    (dest).addr[2] = (src).addr[2];        \
    (dest).addr[3] = (src).addr[3];        \
  } while (0)

/** Set complete address to zero */
inline void ip6_addr_set_zero(Ip6Addr* ip6addr) {
  (ip6addr)->addr[0] = 0;
  (ip6addr)->addr[1] = 0;
  (ip6addr)->addr[2] = 0;
  (ip6addr)->addr[3] = 0;
  ip6_addr_clear_zone(ip6addr);
}

/** Set address to ipv6 'any' (no need for lwip_htonl()) */
inline void ip6_addr_set_any(Ip6Addr* ip6addr) { ip6_addr_set_zero(ip6addr); }

/** Set address to ipv6 loopback address */
inline void ip6_addr_set_loopback(Ip6Addr* ip6addr) {
  (ip6addr)->addr[0] = 0;
  (ip6addr)->addr[1] = 0;
  (ip6addr)->addr[2] = 0;
  (ip6addr)->addr[3] = pp_htonl(0x00000001UL);
  ip6_addr_clear_zone(ip6addr);
}

/** Safely copy one IPv6 address to another and change byte order
 * from host- to network-order. */
inline void ip6_addr_set_hton(Ip6Addr* dest, Ip6Addr* src) {
  (dest)->addr[0] = (src) == nullptr ? 0 : lwip_htonl((src)->addr[0]);
  (dest)->addr[1] = (src) == nullptr ? 0 : lwip_htonl((src)->addr[1]);
  (dest)->addr[2] = (src) == nullptr ? 0 : lwip_htonl((src)->addr[2]);
  (dest)->addr[3] = (src) == nullptr ? 0 : lwip_htonl((src)->addr[3]);
  ip6_addr_set_zone((dest), (src) == nullptr ? kIp6NoZone : ip6_addr_zone(src));
}

/** Compare IPv6 networks, ignoring zone information. To be used sparingly! */
#define ip6_addr_netcmp_zoneless(addr1, addr2) \
  (((addr1)->addr[0] == (addr2)->addr[0]) &&   \
   ((addr1)->addr[1] == (addr2)->addr[1]))

/**
 * Determine if two IPv6 address are on the same network.
 *
 * @param addr1 IPv6 address 1
 * @param addr2 IPv6 address 2
 * @return 1 if the network identifiers of both address match, 0 if not
 */
#define ip6_addr_netcmp(addr1, addr2)            \
  (ip6_addr_netcmp_zoneless((addr1), (addr2)) && \
   ip6_addr_cmp_zone((addr1), (addr2)))

/* Exact-host comparison *after* ip6_addr_netcmp() succeeded, for efficiency. */
#define ip6_addr_nethostcmp(addr1, addr2)    \
  (((addr1)->addr[2] == (addr2)->addr[2]) && \
   ((addr1)->addr[3] == (addr2)->addr[3]))

/**
 * Determine if two IPv6 addresses are the same. In particular, the address
 * part of both must be the same, and the zone must be compatible.
 *
 * @param addr1 IPv6 address 1
 * @param addr2 IPv6 address 2
 * @return 1 if the addresses are considered equal, 0 if not
 */

/** Compare IPv6 address to packed address and zone */
#define ip6_addr_cmp_packed(ip6addr, paddr, zone_idx) \
  (((ip6addr)->addr[0] == (paddr)->addr[0]) &&        \
   ((ip6addr)->addr[1] == (paddr)->addr[1]) &&        \
   ((ip6addr)->addr[2] == (paddr)->addr[2]) &&        \
   ((ip6addr)->addr[3] == (paddr)->addr[3]) &&        \
   ip6_addr_equals_zone((ip6addr), (zone_idx)))

#define ip6_get_subnet_id(ip6addr) \
  (lwip_htonl((ip6addr)->addr[2]) & 0x0000ffffUL)

inline bool ip6_addr_isany_val(Ip6Addr ip6_addr) {
  return (((ip6_addr).addr[0] == 0) && ((ip6_addr).addr[1] == 0) &&
          ((ip6_addr).addr[2] == 0) && ((ip6_addr).addr[3] == 0));
}

inline bool ip6_addr_isany(Ip6Addr* ip6_addr) {
  return (((ip6_addr) == nullptr) || ip6_addr_isany_val(*(ip6_addr)));
}

inline bool ip6_addr_isloopback(Ip6Addr* ip6_addr) {
  return (((ip6_addr)->addr[0] == 0UL) && ((ip6_addr)->addr[1] == 0UL) &&
          ((ip6_addr)->addr[2] == 0UL) &&
          ((ip6_addr)->addr[3] == pp_htonl(0x00000001UL)));
}

#define ip6_addr_isglobal(ip6addr) \
  (((ip6addr)->addr[0] & PP_HTONL(0xe0000000UL)) == PP_HTONL(0x20000000UL))

#define ip6_addr_issitelocal(ip6addr) \
  (((ip6addr)->addr[0] & PP_HTONL(0xffc00000UL)) == PP_HTONL(0xfec00000UL))

#define ip6_addr_isuniquelocal(ip6addr) \
  (((ip6addr)->addr[0] & PP_HTONL(0xfe000000UL)) == PP_HTONL(0xfc000000UL))

#define ip6_addr_isipv4mappedipv6(ip6addr)                   \
  (((ip6addr)->addr[0] == 0) && ((ip6addr)->addr[1] == 0) && \
   (((ip6addr)->addr[2]) == PP_HTONL(0x0000FFFFUL)))

inline bool ip6_addr_ismulticast(Ip6Addr* ip6_addr) {
  return (ip6_addr->addr[0] & pp_htonl(0xff000000UL)) == pp_htonl(0xff000000UL);
}

#define ip6_addr_multicast_transient_flag(ip6addr) \
  ((ip6addr)->addr[0] & PP_HTONL(0x00100000UL))
#define ip6_addr_multicast_prefix_flag(ip6addr) \
  ((ip6addr)->addr[0] & PP_HTONL(0x00200000UL))
#define ip6_addr_multicast_rendezvous_flag(ip6addr) \
  ((ip6addr)->addr[0] & PP_HTONL(0x00400000UL))
#define ip6_addr_multicast_scope(ip6addr) \
  ((lwip_htonl((ip6addr)->addr[0]) >> 16) & 0xf)
#define IP6_MULTICAST_SCOPE_RESERVED 0x0
#define IP6_MULTICAST_SCOPE_RESERVED0 0x0
#define IP6_MULTICAST_SCOPE_INTERFACE_LOCAL 0x1
#define IP6_MULTICAST_SCOPE_LINK_LOCAL 0x2
#define IP6_MULTICAST_SCOPE_RESERVED3 0x3
#define IP6_MULTICAST_SCOPE_ADMIN_LOCAL 0x4
#define IP6_MULTICAST_SCOPE_SITE_LOCAL 0x5
#define IP6_MULTICAST_SCOPE_ORGANIZATION_LOCAL 0x8
#define IP6_MULTICAST_SCOPE_GLOBAL 0xe
#define IP6_MULTICAST_SCOPE_RESERVEDF 0xf

#define ip6_addr_ismulticast_adminlocal(ip6addr) \
  (((ip6addr)->addr[0] & PP_HTONL(0xff8f0000UL)) == PP_HTONL(0xff040000UL))
#define ip6_addr_ismulticast_sitelocal(ip6addr) \
  (((ip6addr)->addr[0] & PP_HTONL(0xff8f0000UL)) == PP_HTONL(0xff050000UL))
#define ip6_addr_ismulticast_orglocal(ip6addr) \
  (((ip6addr)->addr[0] & PP_HTONL(0xff8f0000UL)) == PP_HTONL(0xff080000UL))
#define ip6_addr_ismulticast_global(ip6addr) \
  (((ip6addr)->addr[0] & PP_HTONL(0xff8f0000UL)) == PP_HTONL(0xff0e0000UL))

/* Scoping note: while interface-local and link-local multicast addresses do
 * have a scope (i.e., they are meaningful only in the context of a particular
 * interface), the following functions are not assigning or comparing zone
 * indices. The reason for this is backward compatibility. Any call site that
 * produces a non-global multicast address must assign a multicast address as
 * appropriate itself. */

#define ip6_addr_isallnodes_iflocal(ip6addr)                     \
  (((ip6addr)->addr[0] == PP_HTONL(0xff010000UL)) &&             \
   ((ip6addr)->addr[1] == 0UL) && ((ip6addr)->addr[2] == 0UL) && \
   ((ip6addr)->addr[3] == PP_HTONL(0x00000001UL)))

#define ip6_addr_isallnodes_linklocal(ip6addr)                   \
  (((ip6addr)->addr[0] == PP_HTONL(0xff020000UL)) &&             \
   ((ip6addr)->addr[1] == 0UL) && ((ip6addr)->addr[2] == 0UL) && \
   ((ip6addr)->addr[3] == PP_HTONL(0x00000001UL)))

inline void ip6_addr_set_allnodes_linklocal(Ip6Addr* ip6addr)
{
    (ip6addr)->addr[0] = pp_htonl(0xff020000UL);
    (ip6addr)->addr[1] = 0;
    (ip6addr)->addr[2] = 0;
    (ip6addr)->addr[3] = pp_htonl(0x00000001UL);
    ip6_addr_clear_zone(ip6addr);
}

#define ip6_addr_isallrouters_linklocal(ip6addr)                 \
  (((ip6addr)->addr[0] == PP_HTONL(0xff020000UL)) &&             \
   ((ip6addr)->addr[1] == 0UL) && ((ip6addr)->addr[2] == 0UL) && \
   ((ip6addr)->addr[3] == PP_HTONL(0x00000002UL)))
#define ip6_addr_set_allrouters_linklocal(ip6addr) \
  do {                                             \
    (ip6addr)->addr[0] = PP_HTONL(0xff020000UL);   \
    (ip6addr)->addr[1] = 0;                        \
    (ip6addr)->addr[2] = 0;                        \
    (ip6addr)->addr[3] = PP_HTONL(0x00000002UL);   \
    ip6_addr_clear_zone(ip6addr);                  \
  } while (0)

#define ip6_addr_issolicitednode(ip6addr)            \
  (((ip6addr)->addr[0] == PP_HTONL(0xff020000UL)) && \
   ((ip6addr)->addr[2] == PP_HTONL(0x00000001UL)) && \
   (((ip6addr)->addr[3] & PP_HTONL(0xff000000UL)) == PP_HTONL(0xff000000UL)))

#define ip6_addr_set_solicitednode(ip6addr, if_id)           \
  do {                                                       \
    (ip6addr)->addr[0] = PP_HTONL(0xff020000UL);             \
    (ip6addr)->addr[1] = 0;                                  \
    (ip6addr)->addr[2] = PP_HTONL(0x00000001UL);             \
    (ip6addr)->addr[3] = (PP_HTONL(0xff000000UL) | (if_id)); \
    ip6_addr_clear_zone(ip6addr);                            \
  } while (0)

#define ip6_addr_cmp_solicitednode(ip6addr, sn_addr) \
  (((ip6addr)->addr[0] == PP_HTONL(0xff020000UL)) && \
   ((ip6addr)->addr[1] == 0) &&                      \
   ((ip6addr)->addr[2] == PP_HTONL(0x00000001UL)) && \
   ((ip6addr)->addr[3] == (PP_HTONL(0xff000000UL) | (sn_addr)->addr[3])))

/* IPv6 address states. */
#define IP6_ADDR_INVALID 0x00
#define IP6_ADDR_TENTATIVE 0x08
#define IP6_ADDR_TENTATIVE_1 0x09 /* 1 probe sent */
#define IP6_ADDR_TENTATIVE_2 0x0a /* 2 probes sent */
#define IP6_ADDR_TENTATIVE_3 0x0b /* 3 probes sent */
#define IP6_ADDR_TENTATIVE_4 0x0c /* 4 probes sent */
#define IP6_ADDR_TENTATIVE_5 0x0d /* 5 probes sent */
#define IP6_ADDR_TENTATIVE_6 0x0e /* 6 probes sent */
#define IP6_ADDR_TENTATIVE_7 0x0f /* 7 probes sent */
#define IP6_ADDR_VALID \
  0x10 /* This bit marks an address as valid (preferred or deprecated) */
#define IP6_ADDR_PREFERRED 0x30
#define IP6_ADDR_DEPRECATED 0x10 /* Same as VALID (valid but not preferred) */
#define IP6_ADDR_DUPLICATED 0x40 /* Failed DAD test, not valid */

#define IP6_ADDR_TENTATIVE_COUNT_MASK 0x07 /* 1-7 probes sent */

#define ip6_addr_isinvalid(addr_state) (addr_state == IP6_ADDR_INVALID)
#define ip6_addr_istentative(addr_state) (addr_state & IP6_ADDR_TENTATIVE)
#define ip6_addr_isvalid(addr_state)                                         \
  (addr_state & IP6_ADDR_VALID) /* Include valid, preferred, and deprecated. \
                                 */
#define ip6_addr_ispreferred(addr_state) (addr_state == IP6_ADDR_PREFERRED)
#define ip6_addr_isdeprecated(addr_state) (addr_state == IP6_ADDR_DEPRECATED)
#define ip6_addr_isduplicated(addr_state) (addr_state == IP6_ADDR_DUPLICATED)

#define IP6_ADDR_LIFE_STATIC (0)
#define IP6_ADDR_LIFE_INFINITE (0xffffffffUL)
#define ip6_addr_life_isstatic(addr_life) ((addr_life) == IP6_ADDR_LIFE_STATIC)
#define ip6_addr_life_isinfinite(addr_life) \
  ((addr_life) == IP6_ADDR_LIFE_INFINITE)

#define ip6_addr_debug_print_parts(debug, a, b, c, d, e, f, g, h)    \
  Logf(debug, ("%" X16_F ":%" X16_F ":%" X16_F ":%" X16_F ":%" X16_F \
               ":%" X16_F ":%" X16_F ":%" X16_F,                     \
               a, b, c, d, e, f, g, h))
#define ip6_addr_debug_print(debug, ipaddr)                              \
  ip6_addr_debug_print_parts(                                            \
      debug, (uint16_t)((ipaddr) != NULL ? IP6_ADDR_BLOCK1(ipaddr) : 0), \
      (uint16_t)((ipaddr) != NULL ? IP6_ADDR_BLOCK2(ipaddr) : 0),        \
      (uint16_t)((ipaddr) != NULL ? IP6_ADDR_BLOCK3(ipaddr) : 0),        \
      (uint16_t)((ipaddr) != NULL ? IP6_ADDR_BLOCK4(ipaddr) : 0),        \
      (uint16_t)((ipaddr) != NULL ? IP6_ADDR_BLOCK5(ipaddr) : 0),        \
      (uint16_t)((ipaddr) != NULL ? IP6_ADDR_BLOCK6(ipaddr) : 0),        \
      (uint16_t)((ipaddr) != NULL ? IP6_ADDR_BLOCK7(ipaddr) : 0),        \
      (uint16_t)((ipaddr) != NULL ? IP6_ADDR_BLOCK8(ipaddr) : 0))
#define ip6_addr_debug_print_val(debug, ipaddr)                      \
  ip6_addr_debug_print_parts(                                        \
      debug, IP6_ADDR_BLOCK1(&(ipaddr)), IP6_ADDR_BLOCK2(&(ipaddr)), \
      IP6_ADDR_BLOCK3(&(ipaddr)), IP6_ADDR_BLOCK4(&(ipaddr)),        \
      IP6_ADDR_BLOCK5(&(ipaddr)), IP6_ADDR_BLOCK6(&(ipaddr)),        \
      IP6_ADDR_BLOCK7(&(ipaddr)), IP6_ADDR_BLOCK8(&(ipaddr)))

#define IP6ADDR_STRLEN_MAX 46

int ip6addr_aton(const char* cp, const Ip6Addr* addr);
/** returns ptr to static buffer; not reentrant! */
char* ip6addr_ntoa(const Ip6Addr* addr);
char* ip6addr_ntoa_r(const Ip6Addr* addr, char* buf, int buflen);
