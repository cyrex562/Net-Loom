#include <ip4_addr.h>
#include <lwip_debug.h>
#include <network_interface.h>
#include <cctype>


// Checks if a netmask is valid (starting with ones, then only zeros)
//
// @param netmask the IPv4 netmask to check (in network byte order!)
// @return 1 if the netmask is valid, 0 if it is not
//
bool ip4_addr_netmask_valid(const uint32_t netmask)
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
            return false;
        }
    } 
    
    /* no one after the first zero -> valid */
    return true;
}

/**
 * Ascii internet address interpretation routine.
 * The value returned is in network order.
 *
 * @param cp IP address in ascii representation (e.g. "127.0.0.1")
 * @return ip address in network order
 */
uint32_t ipaddr_addr(std::string& cp)
{
    Ip4Addr val;
    if (lwip_ip4addr_aton(cp, val))
    {
        return get_ip4_addr(val);
    }
    const Ip4Addr addr_none = ip4_addr_none();
    return addr_none.addr;
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
bool lwip_ip4addr_aton(std::string& cp, Ip4Addr& addr)
{
    uint32_t val;
    uint32_t parts[4];
    auto pp = parts;
    // auto c = *cp;

    uint8_t base = 10;
    if (cp.find('x') != std::string::npos || cp.find('X' != std::string::npos))
    {
        base = 16;
    }

    // todo: implement regex;

    return true;

    // for (auto c : cp)
    // {
    //     /*
    //      * Collect number up to ``.''.
    //      * Values are specified as for C:
    //      * 0x=hex, 0=octal, 1-9=decimal.
    //      */
    //     if (isdigit(c) == 0)
    //     {
    //         return false;
    //     }
    //
    //     
    //
    //     
    //     for (;;)
    //     {
    //         if (isdigit(c))
    //         {
    //             val = (val * base) + uint32_t(c - '0');
    //             c = *++cp;
    //         }
    //         else if (base == 16 && isxdigit(c))
    //         {
    //             val = (val << 4) | uint32_t(c + 10 - (islower(c) ? 'a' : 'A'));
    //             c = *++cp;
    //         }
    //         else
    //         {
    //             break;
    //         }
    //     }
    //     if (c == '.')
    //     {
    //         /*
    //          * Internet format:
    //          *  a.b.c.d
    //          *  a.b.c   (with c treated as 16 bits)
    //          *  a.b (with b treated as 24 bits)
    //          */
    //         if (pp >= parts + 3)
    //         {
    //             return false;
    //         }
    //         *pp++ = val;
    //         c = *++cp;
    //     }
    //     else
    //     {
    //         break;
    //     }
    // } /*
   // *//  Check for trailing characters.
   // *// /
   //  // if (c != '\0' && !isspace(c))
   //  // {
   //  //     return false;
   //  // } /*
   // *//  Concoct the address according to
   // *//  the number of parts specified.
   // *// /
    // switch (pp - parts + 1)
    // {
    // case 0:
    //     return false; /* initial nondigit */
    // case 1: /* a -- 32 bits */ break;
    // case 2: /* a.b -- 8.24 bits */ if (val > 0xffffffUL)
    //     {
    //         return false;
    //     }
    //     if (parts[0] > 0xff)
    //     {
    //         return false;
    //     }
    //     val |= parts[0] << 24;
    //     break;
    // case 3: /* a.b.c -- 8.8.16 bits */ if (val > 0xffff)
    //     {
    //         return false;
    //     }
    //     if ((parts[0] > 0xff) || (parts[1] > 0xff))
    //     {
    //         return false;
    //     }
    //     val |= (parts[0] << 24) | (parts[1] << 16);
    //     break;
    // case 4: /* a.b.c.d -- 8.8.8.8 bits */ if (val > 0xff)
    //     {
    //         return false;
    //     }
    //     if ((parts[0] > 0xff) || (parts[1] > 0xff) || (parts[2] > 0xff))
    //     {
    //         return false;
    //     }
    //     val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
    //     break;
    // default: lwip_assert("unhandled", false);
    // }
    // if (addr)
    // {
    //     set_ip4_addr_u32(addr, lwip_htonl(val));
    // }
    // return true;
}

/**
 * Convert numeric IP address into decimal dotted ASCII representation.
 * returns ptr to static buffer; not reentrant!
 *
 * @param addr ip address in network order to convert
 * @return pointer to a global static (!) buffer that holds the ASCII
 *         representation of addr
 */
std::string lwip_ip4addr_ntoa(const Ip4Addr& addr)
{
  std::string str;
  return lwip_ip4addr_ntoa_r(addr, str);
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
std::string lwip_ip4addr_ntoa_r(const Ip4Addr& addr, std::string& buf)
{
    // todo: refactor
    // uint32_t s_addr;
    // char inv[3];
    // auto len = 0;
    // s_addr = get_ip4_addr(addr);
    // auto rp = buf;
    // auto ap = reinterpret_cast<uint8_t *>(&s_addr);
    // for (uint8_t n = 0; n < 4; n++)
    // {
    //     uint8_t i = 0;
    //     do
    //     {
    //         const uint8_t rem = *ap % uint8_t(10);
    //         *ap /= uint8_t(10);
    //         inv[i++] = char('0' + rem);
    //     }
    //     while (*ap);
    //     while (i--)
    //     {
    //         if (len++ >= buflen)
    //         {
    //             return nullptr;
    //         }
    //         *rp++ = inv[i];
    //     }
    //     if (len++ >= buflen)
    //     {
    //         return nullptr;
    //     }
    //     *rp++ = '.';
    //     ap++;
    // }
    // *--rp = 0;
    return buf;
}
