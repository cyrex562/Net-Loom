///
/// file: ip.cpp
/// 

#include <ip_addr.h>
#include <ip.h>

/// Global data for both IPv4 and IPv6 */
/// todo: get rid of this garbage
// struct IpGlobals ip_data;

// const IpAddr IP_ADDR_ANY_TYPE = kIpAddrAnyType();

/**
 * @ingroup ipaddr
 * Convert numeric IP address (both versions) into ASCII representation.
 * returns ptr to static buffer; not reentrant!
 *
 * @param addr ip address in network order to convert
 * @return pointer to a global static (!) buffer that holds the ASCII
 *         representation of addr
 */
char *ipaddr_ntoa(const IpAddr *addr)
{
  if (addr == nullptr) {
    return nullptr;
  }
  if (is_ip_addr_v6(addr)) {
    return ip6addr_ntoa(&addr->u_addr.ip6);
  } else {
    return lwip_ip4addr_ntoa(convert_ip_addr_to_ip4_addr(addr));
  }
}

/**
 * @ingroup ipaddr
 * Same as ipaddr_ntoa, but reentrant since a user-supplied buffer is used.
 *
 * @param addr ip address in network order to convert
 * @param buf target buffer where the string is stored
 * @param buflen length of buf
 * @return either pointer to buf which now holds the ASCII
 *         representation of addr or NULL if buf was too small
 */
char *ipaddr_ntoa_r(const IpAddr *addr, char *buf, int buflen)
{
  if (addr == nullptr) {
    return nullptr;
  }
  if (is_ip_addr_v6(addr)) {
    return ip6addr_ntoa_r(&addr->u_addr.ip6, buf);
  } else {
    return lwip_ip4addr_ntoa_r(convert_ip_addr_to_ip4_addr(addr), buf);
  }
}

/**
 * @ingroup ipaddr
 * Convert IP address string (both versions) to numeric.
 * The version is auto-detected from the string.
 *
 * @param cp IP address string to convert
 * @param addr conversion result is stored here
 * @return 1 on success, 0 on error
 */
int
ipaddr_aton(const char *cp, IpAddr *addr)
{
  if (cp != nullptr) {
      for (const char* c = cp; *c != 0; c++) {
      if (*c == ':') {
        /* contains a colon: IPv6 address */
        if (addr) {
          set_ip_addr_type_val(*addr, IPADDR_TYPE_V6);
        }
        return ip6addr_aton(cp, &addr->u_addr.ip6);
      } else if (*c == '.') {
        /* contains a dot: IPv4 address */
        break;
      }
    }
    /* call ip4addr_aton as fallback or if IPv4 was found */
    if (addr) {
      set_ip_addr_type_val(*addr, IPADDR_TYPE_V4);
    }
    return lwip_ip4addr_aton(cp, &addr->u_addr.ip4);
  }
  return 0;
}

/**
 * @ingroup lwip_nosys
 * If both IP versions are enabled, this function can dispatch packets to the correct one.
 * Don't call directly, pass to netif_add() and call netif->input().
 */
LwipStatus
ip_input(struct PacketBuffer *p, NetworkInterface*inp)
{
  if (p != nullptr) {
    if (get_ip_hdr_version(p->payload) == 6) {
      return ip6_input(p, inp);
    }
    return ip4_input(p, inp);
  }
  return ERR_VAL;
}
