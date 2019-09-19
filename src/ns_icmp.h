
#pragma once
#include "ns_packet.h"
#include "icmp6.h"
#include "ns_network_interface.h"

enum IcmpType
{
    ICMP_ER = 0,
    /* echo reply */
    ICMP_DUR = 3,
    /* destination unreachable */
    ICMP_SQ = 4,
    /* source quench */
    ICMP_RD = 5,
    /* redirect */
    ICMP_ECHO =8,
    /* echo */
    ICMP_TE = 11,
    /* time exceeded */
    ICMP_PP = 12,
    /* parameter problem */
    ICMP_TS = 13,
    /* timestamp */
    ICMP_TSR= 14,
    /* timestamp reply */
    ICMP_IRQ =15,
    /* information request */
    ICMP_IR = 16,
    /* information reply */
    ICMP_AM = 17,
    /* address mask request */
    ICMP_AMR =18,
    /* address mask reply */
};



 /** This is the standard ICMP header only that the uint32_t data
  *  is split to two uint16_t like ICMP echo needs it.
  *  This header is also used for other ICMP types that do not
  *  use the data part.
  */

struct IcmpEchoHdr {
    uint8_t type;
    uint8_t code;
    uint16_t chksum;
    uint16_t id;
    uint16_t seqno;
} ;


/* Compatibility defines, old versions used to combine type and code to an uint16_t */
inline uint8_t
get_icmp_hdr_type(IcmpEchoHdr& hdr)
{
    return ((hdr).type);
}


/**
 *
 */
inline uint8_t
get_icmp_hdr_code(IcmpEchoHdr& hdr)
{
    return ((hdr).code);
}


/**
 *
 */
inline void set_icmp_hdr_type(IcmpEchoHdr& hdr, const IcmpType icmp_type)
{
    ((hdr).type = (icmp_type));
}


/**
 *
 */
inline void
set_icmp_hdr_code(IcmpEchoHdr& hdr, const uint8_t code)
{
    ((hdr).code = (code));
}


/** ICMP destination unreachable codes */
enum IcmpDestUnreachCode {
  /** net unreachable */
  ICMP_DUR_NET   = 0,
  /** host unreachable */
  ICMP_DUR_HOST  = 1,
  /** protocol unreachable */
  ICMP_DUR_PROTO = 2,
  /** port unreachable */
  ICMP_DUR_PORT  = 3,
  /** fragmentation needed and DF set */
  ICMP_DUR_FRAG  = 4,
  /** source route failed */
  ICMP_DUR_SR    = 5
};

/// ICMP time exceeded codes */
enum IcmpTimeExceededCode {
  /** time to live exceeded in transit */
  ICMP_TE_TTL  = 0,
  /** fragment reassembly time exceeded */
  ICMP_TE_FRAG = 1
};

void icmp_input(PacketContainer& p, NetworkInterface& inp);
void icmp_dest_unreach(PacketContainer& pkt_buf, enum IcmpDestUnreachCode dur_type);
void icmp_time_exceeded(PacketContainer& pkt_buf, enum IcmpTimeExceededCode te_type);
void send_icmp_response(PacketContainer& p, uint8_t type, uint8_t code);

inline void icmp_port_unreach(const bool is_ipv6, PacketContainer& pkt_buf)
{
    is_ipv6
        ? icmp6_dest_unreach(pkt_buf, ICMP6_DUR_PORT)
        : icmp_dest_unreach(pkt_buf, ICMP_DUR_PORT);
}

