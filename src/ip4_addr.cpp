#include <ip4_addr.h>
#include <lwip_debug.h>
#include <network_interface.h>
#include <cctype>


// Checks if a netmask is valid (starting with ones, then only zeros)
//
// @param netmask the IPv4 netmask to check (in network byte order!)
// @return 1 if the netmask is valid, 0 if it is not
//
bool
is_ip4_netmask_valid(const uint32_t netmask)
{
    uint32_t mask;
    const auto nm_hostorder = lwip_htonl(netmask); /* first, check for the first zero */
    for (mask = 1UL << 31; mask != 0; mask >>= 1)
    {
        if ((nm_hostorder & mask) == 0)
        {
            break;
        }
    } /* then check that there is no one */
    for (; mask != 0; mask >>= 1)
    {
        if ((nm_hostorder & mask) != 0)
        {
            /* there is a one after the first zero -> invalid */
            return false;
        }
    } /* no one after the first zero -> valid */
    return true;
} 

/**
 * Ascii internet address interpretation routine.
 * The value returned is in network order.
 *
 * @param cp IP address in ascii representation (e.g. "127.0.0.1")
 * @return ip address in network order
 */
uint32_t
ipaddr_addr(std::string& cp)
{
    Ip4Addr val;
    if (ip4_addr_aton(cp, val))
    {
        return get_ip4_addr_u32(val);
    }
    const auto addr_none = make_ip4_addr_none();
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
bool
ip4_addr_aton(std::string& cp, Ip4Addr& addr)
{
    uint32_t val;
    uint32_t parts[4];
    auto pp = parts; // auto c = *cp;
    uint8_t base = 10;
    if (cp.find('x') != std::string::npos || cp.find('X' != std::string::npos))
    {
        base = 16;
    } // todo: implement regex;
    return true;
} 

/**
 * Convert numeric IP address into decimal dotted ASCII representation.
 * returns ptr to static buffer; not reentrant!
 *
 * @param addr ip address in network order to convert
 * @return pointer to a global static (!) buffer that holds the ASCII
 *         representation of addr
 */
std::string
ip4_addr_ntoa(const Ip4Addr& addr)
{
    std::string str;
    return ip4_addr_ntoa_r(addr);
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
std::string
ip4_addr_ntoa_r(const Ip4Addr& addr)
{
    std::string buf;
    return buf;
    // todo: write this function
}

//
//
//
