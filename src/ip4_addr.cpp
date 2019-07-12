#include "opt.h"
#include "lwip_debug.h"
#include "ip_addr.h"
#include "netif.h"

#include <cctype>

/* used by IP4_ADDR_ANY and IP_ADDR_BROADCAST in ip_addr.h */
const IpAddr kIpAddrAny = {{{{kIp4AddrAny4}}}};
const IpAddr kIpAddrBroadcast = {{{{IPADDR_BROADCAST}}}};

/**
 * Determine if an address is a broadcast address on a network interface
 *
 * @param addr address to be checked
 * @param netif the network interface against which the address is checked
 * @return returns non-zero if the address is a broadcast address
 */
uint8_t
ip4_addr_isbroadcast_u32(const uint32_t addr, const struct NetIfc *netif)
{
  Ip4Addr ipaddr;
  ip4_addr_set_u32(&ipaddr, addr);

  /* all ones (broadcast) or all zeroes (old skool broadcast) */
  if ((~addr == kIp4AddrAny4) ||
      (addr == kIp4AddrAny4)) {
    return 1;
    /* no broadcast support on this network interface? */
  }
  if ((netif->flags & kNetifFlagBroadcast) == 0) {
      /* the given address cannot be a broadcast address
     * nor can we check against any broadcast addresses */
      return 0;
      /* address matches network interface address exactly? => no broadcast */
  }
  if (addr == ip4_addr_get_u32(netif_ip4_addr(netif))) {
      return 0;
      /*  on the same (sub) network... */
  }
  if (ip4_addr_netcmp(&ipaddr, netif_ip4_addr(netif), netif_ip4_netmask(netif))
      /* ...and host identifier bits are all ones? =>... */
      && ((addr & ~ip4_addr_get_u32(netif_ip4_netmask(netif))) ==
          (IPADDR_BROADCAST & ~ip4_addr_get_u32(netif_ip4_netmask(netif))))) {
      /* => network broadcast address */
      return 1;
  }
  return 0;
}

// Checks if a netmask is valid (starting with ones, then only zeros)
//
// @param netmask the IPv4 netmask to check (in network byte order!)
// @return 1 if the netmask is valid, 0 if it is not
//
uint8_t ip4_addr_netmask_valid(const uint32_t netmask)
{
    uint32_t mask;
    const auto nm_hostorder = lwip_htonl(netmask); /* first, check for the first zero */
    for (mask = 1UL << 31; mask != 0; mask >>= 1)
    {
        if ((nm_hostorder & mask) == 0)
        {
            break;
        }
    } 
    
    /* then check that there is no one */
    for (; mask != 0; mask >>= 1)
    {
        if ((nm_hostorder & mask) != 0)
        {
            /* there is a one after the first zero -> invalid */
            return 0;
        }
    } 
    
    /* no one after the first zero -> valid */
    return 1;
}

/**
 * Ascii internet address interpretation routine.
 * The value returned is in network order.
 *
 * @param cp IP address in ascii representation (e.g. "127.0.0.1")
 * @return ip address in network order
 */
uint32_t ipaddr_addr(const char* cp)
{
    Ip4Addr val;
    if (ip4addr_aton(cp, &val))
    {
        return ip4_addr_get_u32(&val);
    }
    return (kIpaddrNone);
}

/**
 * Check whether "cp" is a valid ascii representation
 * of an Internet address and convert to a binary address.
 * Returns 1 if the address is valid, 0 if not.
 * This replaces inet_addr, the return value from which
 * cannot distinguish between failure and a local broadcast address.
 *
 * @param cp IP address in ascii representation (e.g. "127.0.0.1")
 * @param addr pointer to which to save the ip address in network order
 * @return 1 if cp could be converted to addr, 0 on failure
 */
int ip4addr_aton(const char* cp, Ip4Addr* addr)
{
    uint32_t val;
    uint32_t parts[4];
    auto pp = parts;
    auto c = *cp;
    for (;;)
    {
        /*
         * Collect number up to ``.''.
         * Values are specified as for C:
         * 0x=hex, 0=octal, 1-9=decimal.
         */
        if (!isdigit(c))
        {
            return 0;
        }
        val = 0;
        uint8_t base = 10;
        if (c == '0')
        {
            c = *++cp;
            if (c == 'x' || c == 'X')
            {
                base = 16;
                c = *++cp;
            }
            else
            {
                base = 8;
            }
        }
        for (;;)
        {
            if (isdigit(c))
            {
                val = (val * base) + uint32_t(c - '0');
                c = *++cp;
            }
            else if (base == 16 && isxdigit(c))
            {
                val = (val << 4) | uint32_t(c + 10 - (islower(c) ? 'a' : 'A'));
                c = *++cp;
            }
            else
            {
                break;
            }
        }
        if (c == '.')
        {
            /*
             * Internet format:
             *  a.b.c.d
             *  a.b.c   (with c treated as 16 bits)
             *  a.b (with b treated as 24 bits)
             */
            if (pp >= parts + 3)
            {
                return 0;
            }
            *pp++ = val;
            c = *++cp;
        }
        else
        {
            break;
        }
    } /*
   * Check for trailing characters.
   */
    if (c != '\0' && !isspace(c))
    {
        return 0;
    } /*
   * Concoct the address according to
   * the number of parts specified.
   */
    switch (pp - parts + 1)
    {
    case 0:
        return 0; /* initial nondigit */
    case 1: /* a -- 32 bits */ break;
    case 2: /* a.b -- 8.24 bits */ if (val > 0xffffffUL)
        {
            return 0;
        }
        if (parts[0] > 0xff)
        {
            return 0;
        }
        val |= parts[0] << 24;
        break;
    case 3: /* a.b.c -- 8.8.16 bits */ if (val > 0xffff)
        {
            return 0;
        }
        if ((parts[0] > 0xff) || (parts[1] > 0xff))
        {
            return 0;
        }
        val |= (parts[0] << 24) | (parts[1] << 16);
        break;
    case 4: /* a.b.c.d -- 8.8.8.8 bits */ if (val > 0xff)
        {
            return 0;
        }
        if ((parts[0] > 0xff) || (parts[1] > 0xff) || (parts[2] > 0xff))
        {
            return 0;
        }
        val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
        break;
    default: LWIP_ASSERT("unhandled", 0);
    }
    if (addr)
    {
        ip4_addr_set_u32(addr, lwip_htonl(val));
    }
    return 1;
}

/**
 * Convert numeric IP address into decimal dotted ASCII representation.
 * returns ptr to static buffer; not reentrant!
 *
 * @param addr ip address in network order to convert
 * @return pointer to a global static (!) buffer that holds the ASCII
 *         representation of addr
 */
char *
ip4addr_ntoa(const Ip4Addr *addr)
{
  static char str[IP4ADDR_STRLEN_MAX];
  return ip4addr_ntoa_r(addr, str, IP4ADDR_STRLEN_MAX);
}

/**
 * Same as ip4addr_ntoa, but reentrant since a user-supplied buffer is used.
 *
 * @param addr ip address in network order to convert
 * @param buf target buffer where the string is stored
 * @param buflen length of buf
 * @return either pointer to buf which now holds the ASCII
 *         representation of addr or NULL if buf was too small
 */
char* ip4addr_ntoa_r(const Ip4Addr* addr, char* buf, const int buflen)
{
    uint32_t s_addr;
    char inv[3];
    auto len = 0;
    s_addr = ip4_addr_get_u32(addr);
    auto rp = buf;
    auto ap = reinterpret_cast<uint8_t *>(&s_addr);
    for (uint8_t n = 0; n < 4; n++)
    {
        uint8_t i = 0;
        do
        {
            const uint8_t rem = *ap % uint8_t(10);
            *ap /= uint8_t(10);
            inv[i++] = char('0' + rem);
        }
        while (*ap);
        while (i--)
        {
            if (len++ >= buflen)
            {
                return nullptr;
            }
            *rp++ = inv[i];
        }
        if (len++ >= buflen)
        {
            return nullptr;
        }
        *rp++ = '.';
        ap++;
    }
    *--rp = 0;
    return buf;
}
