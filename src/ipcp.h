#pragma once

/*
 * Options.
 */
    // IP Addresses

constexpr auto CI_ADDRS = 1;	
constexpr auto CI_COMPRESSTYPE = 2;	/* Compression Type */;
constexpr auto CI_ADDR = 3;
constexpr auto CI_MS_DNS1 = 129	/* Primary DNS value */;
constexpr auto CI_MS_DNS2 = 131     /* Secondary DNS value */;
constexpr auto MAX_STATES = 16		/* from slcompress.h */;
constexpr auto IPCP_VJMODE_OLD = 1	/* "old" mode (option # = 0x0037) */;
constexpr auto IPCP_VJMODE_RFC1172 = 2	/* "old-rfc"mode (option # = 0x002d) */;
constexpr auto IPCP_VJMODE_RFC1332 = 3	/* "new-rfc"mode (option # = 0x002d, */;
                                /*  maxslot and slot number compression) */
constexpr auto IPCP_VJ_COMP = 0x002d	/* current value for VJ compression option*/;
constexpr auto IPCP_VJ_COMP_OLD = 0x0037	/* "old" (i.e, broken) value for VJ */;
				/* compression option*/ 
struct IpcpOptions
{
    unsigned int neg_addr :1; /* Negotiate IP Address? */
    unsigned int old_addrs :1; /* Use old (IP-Addresses) option? */
    unsigned int req_addr :1; /* Ask peer to send IP address? */
    unsigned int neg_vj :1; /* Van Jacobson Compression? */
    unsigned int old_vj :1; /* use old (short) form of VJ option? */
    unsigned int cflag :1;
    unsigned int accept_local :1; /* accept peer's value for ouraddr */
    unsigned int accept_remote :1; /* accept peer's value for hisaddr */
    unsigned int req_dns1 :1; /* Ask peer to send primary DNS address? */
    unsigned int req_dns2 :1; /* Ask peer to send secondary DNS address? */
    uint32_t ouraddr, hisaddr; /* Addresses in NETWORK BYTE ORDER */
    uint32_t dnsaddr[2]; /* Primary and secondary MS DNS entries */
    uint16_t vj_protocol; /* protocol value to use in VJ option */
    uint8_t maxslotindex; /* values for RFC1332 VJ compression neg. */
};
