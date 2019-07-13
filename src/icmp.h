
#pragma once
#include "packet_buffer.h"
#include "ip_addr.h"
constexpr auto ICMP_ER = 0    /* echo reply */;
constexpr auto ICMP_DUR = 3    /* destination unreachable */;
constexpr auto ICMP_SQ = 4    /* source quench */;
constexpr auto ICMP_RD = 5    /* redirect */;
#define ICMP_ECHO 8    /* echo */
#define ICMP_TE  11    /* time exceeded */
#define ICMP_PP  12    /* parameter problem */
#define ICMP_TS  13    /* timestamp */
#define ICMP_TSR 14    /* timestamp reply */
#define ICMP_IRQ 15    /* information request */
#define ICMP_IR  16    /* information reply */
#define ICMP_AM  17    /* address mask request */
#define ICMP_AMR 18    /* address mask reply */

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


#define ICMPH_TYPE_SET(hdr, t) ((hdr)->type = (t))
#define ICMPH_CODE_SET(hdr, c) ((hdr)->code = (c))
#ifdef __cplusplus
extern "C" {
#endif

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

/** ICMP time exceeded codes */
enum icmp_te_type {
  /** time to live exceeded in transit */
  ICMP_TE_TTL  = 0,
  /** fragment reassembly time exceeded */
  ICMP_TE_FRAG = 1
};

void icmp_input(struct PacketBuffer *p, NetIfc*inp);
void icmp_dest_unreach(struct PacketBuffer *p, enum icmp_dur_type t);
void icmp_time_exceeded(struct PacketBuffer *p, enum icmp_te_type t);

inline void icmp_port_unreach(bool isipv6, PacketBuffer* pbuf)
{
    isipv6
        ? icmp6_dest_unreach(pbuf, ICMP6_DUR_PORT)
        : icmp_dest_unreach(pbuf, ICMP_DUR_PORT);
}


#ifdef __cplusplus
}
#endif
