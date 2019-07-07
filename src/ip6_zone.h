#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup ip6_zones IPv6 Zones
 * @ingroup ip6
 * @{
 */

/** Identifier for "no zone". */
constexpr auto IP6_NO_ZONE = 0;

/** Zone initializer for static IPv6 address initialization, including comma. */
#define IPADDR6_ZONE_INIT , IP6_NO_ZONE

/** Return the zone index of the given IPv6 address; possibly "no zone". */
#define ip6_addr_zone(ip6addr) ((ip6addr)->zone)

/** Does the given IPv6 address have a zone set? (0/1) */
#define ip6_addr_has_zone(ip6addr) (ip6_addr_zone(ip6addr) != IP6_NO_ZONE)

/** Set the zone field of an IPv6 address to a particular value. */
#define ip6_addr_set_zone(ip6addr, zone_idx) ((ip6addr)->zone = (zone_idx))

/** Clear the zone field of an IPv6 address, setting it to "no zone". */
#define ip6_addr_clear_zone(ip6addr) ((ip6addr)->zone = IP6_NO_ZONE)

/** Copy the zone field from the second IPv6 address to the first one. */
#define ip6_addr_copy_zone(ip6addr1, ip6addr2) ((ip6addr1).zone = (ip6addr2).zone)

/** Is the zone field of the given IPv6 address equal to the given zone index? (0/1) */
#define ip6_addr_equals_zone(ip6addr, zone_idx) ((ip6addr)->zone == (zone_idx))

/** Are the zone fields of the given IPv6 addresses equal? (0/1)
 * This macro must only be used on IPv6 addresses of the same scope. */
#define ip6_addr_cmp_zone(ip6addr1, ip6addr2) ((ip6addr1)->zone == (ip6addr2)->zone)

/** Symbolic constants for the 'type' parameters in some of the macros.
 * These exist for efficiency only, allowing the macros to avoid certain tests
 * when the address is known not to be of a certain type. Dead code elimination
 * will do the rest. IP6_MULTICAST is supported but currently not optimized.
 * @see ip6_addr_has_scope, ip6_addr_assign_zone, ip6_addr_lacks_zone.
 */
enum lwip_ipv6_scope_type
{
  /** Unknown */
  IP6_UNKNOWN   = 0,
  /** Unicast */
  IP6_UNICAST   = 1,
  /** Multicast */
  IP6_MULTICAST = 2
};

/** IPV6_CUSTOM_SCOPES: together, the following three macro definitions,
 * @ref ip6_addr_has_scope, @ref ip6_addr_assign_zone, and
 * @ref LwipIp6Addrest_zone, completely define the lwIP scoping policy.
 * The definitions below implement the default policy from RFC 4007 Sec. 6.
 * Should an implementation desire to implement a different policy, it can
 * define IPV6_CUSTOM_SCOPES to 1 and supply its own definitions for the three
 * macros instead.
 */

#define IPV6_CUSTOM_SCOPES 0



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
#define ip6_addr_has_scope(ip6addr, type) \
  (ip6_addr_islinklocal(ip6addr) || (((type) != IP6_UNICAST) && \
   (ip6_addr_ismulticast_iflocal(ip6addr) || \
    ip6_addr_ismulticast_linklocal(ip6addr))))

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
#define ip6_addr_assign_zone(ip6addr, type, netif) \
    (ip6_addr_set_zone((ip6addr), \
      ip6_addr_has_scope((ip6addr), (type)) ? netif_get_index(netif) : 0))

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
#define ip6_addr_select_zone(dest, src) do { struct netif *selected_netif; \
  selected_netif = ip6_route((src), (dest)); \
  if (selected_netif != NULL) { \
    ip6_addr_assign_zone((dest), IP6_UNKNOWN, selected_netif); \
  } } while (0)


/** Verify that the given IPv6 address is properly zoned. */
#define IP6_ADDR_ZONECHECK(ip6addr) LWIP_ASSERT("IPv6 zone check failed", \
    ip6_addr_has_scope(ip6addr, IP6_UNKNOWN) == ip6_addr_has_zone(ip6addr))

/** Verify that the given IPv6 address is properly zoned for the given netif. */
#define IP6_ADDR_ZONECHECK_NETIF(ip6addr, netif) LWIP_ASSERT("IPv6 netif zone check failed", \
    ip6_addr_has_scope(ip6addr, IP6_UNKNOWN) ? \
    (ip6_addr_has_zone(ip6addr) && \
     (((netif) == NULL) || LwipIp6Addrest_zone((ip6addr), (netif)))) : \
    !ip6_addr_has_zone(ip6addr))


#ifdef __cplusplus
}
#endif

