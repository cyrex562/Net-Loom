#pragma once
#include <cstdint>


//
// END OF FILE
//

struct IpcpOptions
{
    bool neg_addr; /* Negotiate IP Address? */
    bool old_addrs ; /* Use old (IP-Addresses) option? */
    bool req_addr ; /* Ask peer to send IP address? */
    bool neg_vj; /* Van Jacobson Compression? */
    bool old_vj; /* use old (short) form of VJ option? */
    bool cflag;
    bool accept_local; /* accept peer's value for ouraddr */
    bool accept_remote; /* accept peer's value for hisaddr */
    bool req_dns1; /* Ask peer to send primary DNS address? */
    bool req_dns2; /* Ask peer to send secondary DNS address? */
    uint32_t ouraddr, hisaddr; /* Addresses in NETWORK BYTE ORDER */
    uint32_t dnsaddr[2]; /* Primary and secondary MS DNS entries */
    uint16_t vj_protocol; /* protocol value to use in VJ option */
    uint8_t maxslotindex; /* values for RFC1332 VJ compression neg. */
};