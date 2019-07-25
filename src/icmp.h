
#pragma once
#include <packet_buffer.h>
#include <icmp6.h>
#include <netif.h>

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
inline uint8_t IcmphType(IcmpEchoHdr* hdr)
{
    return ((hdr)->type);
}

inline uint8_t IcmphCode(IcmpEchoHdr* hdr)
{
    return ((hdr)->code);
}

inline void IcmphTypeSet(IcmpEchoHdr* hdr, const IcmpType t)
{
    ((hdr)->type = (t));
}

inline void ICMPH_CODE_SET(IcmpEchoHdr* hdr, const uint8_t c){ ((hdr)->code = (c));}


/** ICMP destination unreachable codes */
enum icmp_dur_type {
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
enum icmp_te_type {
  /** time to live exceeded in transit */
  ICMP_TE_TTL  = 0,
  /** fragment reassembly time exceeded */
  ICMP_TE_FRAG = 1
};

void icmp_input(struct PacketBuffer *p, NetworkInterface*inp);
void icmp_dest_unreach(struct PacketBuffer *p, enum icmp_dur_type t);
void icmp_time_exceeded(struct PacketBuffer *p, enum icmp_te_type t);
void icmp_send_response(struct PacketBuffer *p, uint8_t type, uint8_t code);

inline void icmp_port_unreach(const bool isipv6, PacketBuffer* pbuf)
{
    isipv6
        ? icmp6_dest_unreach(pbuf, ICMP6_DUR_PORT)
        : icmp_dest_unreach(pbuf, ICMP_DUR_PORT);
}

