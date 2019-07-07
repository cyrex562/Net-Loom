/**
 * @file
 * UDP API (to be used from TCPIP thread)\n
 * See also @ref udp_raw
 */

/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */
#ifndef LWIP_HDR_UDP_H
#define LWIP_HDR_UDP_H

#include "opt.h"
#include "arch.h"


#define UDP_HLEN 8

 /* Fields are (of course) in network byte order. */
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct udp_hdr {
    PACK_STRUCT_FIELD(uint16_t src);
    PACK_STRUCT_FIELD(uint16_t dest);  /* src/dest UDP ports */
    PACK_STRUCT_FIELD(uint16_t len);
    PACK_STRUCT_FIELD(uint16_t chksum);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "epstruct.h"
#endif


#if LWIP_UDP /* don't build if not configured for use in lwipopts.h */

#include "PacketBuffer.h"
#include "netif.h"
#include "ip_addr.h"
#include "ip.h"
#include "ip6_addr.h"
#include "udp.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UDP_FLAGS_NOCHKSUM       0x01U
#define UDP_FLAGS_UDPLITE        0x02U
#define UDP_FLAGS_CONNECTED      0x04U
#define UDP_FLAGS_MULTICAST_LOOP 0x08U

struct udp_pcb;

/** Function prototype for udp pcb receive callback functions
 * addr and port are in same byte order as in the pcb
 * The callback is responsible for freeing the PacketBuffer
 * if it's not used any more.
 *
 * ATTENTION: Be aware that 'addr' might point into the PacketBuffer 'p' so freeing this PacketBuffer
 *            can make 'addr' invalid, too.
 *
 * @param arg user supplied argument (udp_pcb.recv_arg)
 * @param pcb the udp_pcb which received data
 * @param p the packet buffer that was received
 * @param addr the remote IP address from which the packet was received
 * @param port the remote port from which the packet was received
 */
typedef void (*udp_recv_fn)(void *arg, struct udp_pcb *pcb, struct PacketBuffer *p,
    const LwipIpAddr *addr, uint16_t port);

/** the UDP protocol control block */
struct udp_pcb {
/** Common members of all PCB types */
    ip_addr_t local_ip;
    /* Bound netif index */
    uint8_t netif_idx;
    /* Socket options */
    uint8_t so_options;
    /* Type Of Service */
    uint8_t tos;
    /* Time To Live */
    uint8_t ttl;
    struct netif_hint netif_hints;

/* Protocol specific PCB members */

  struct udp_pcb *next;

  uint8_t flags;
  /** ports are in host byte order */
  uint16_t local_port, remote_port;

#if LWIP_MULTICAST_TX_OPTIONS
#if LWIP_IPV4
  /** outgoing network interface for multicast packets, by IPv4 address (if not 'any') */
  ip4_addr_t mcast_ip4;
#endif /* LWIP_IPV4 */
  /** outgoing network interface for multicast packets, by interface index (if nonzero) */
  uint8_t mcast_ifindex;
  /** TTL for outgoing multicast packets */
  uint8_t mcast_ttl;
#endif /* LWIP_MULTICAST_TX_OPTIONS */

#if LWIP_UDPLITE
  /** used for UDP_LITE only */
  uint16_t chksum_len_rx, chksum_len_tx;
#endif /* LWIP_UDPLITE */

  /** receive callback function */
  udp_recv_fn recv;
  /** user-supplied argument for the recv callback */
  void *recv_arg;
};
/* udp_pcbs export for external reference (e.g. SNMP agent) */
extern struct udp_pcb *udp_pcbs;

/* The following functions is the application layer interface to the
   UDP code. */
struct udp_pcb * udp_new        (void);
struct udp_pcb * udp_new_ip_type(uint8_t type);
void             udp_remove     (struct udp_pcb *pcb);
LwipError            udp_bind       (struct udp_pcb *pcb, const LwipIpAddr *ipaddr,
                                 uint16_t port);
void             udp_bind_netif (struct udp_pcb *pcb, const struct netif* netif);
LwipError            udp_connect    (struct udp_pcb *pcb, const LwipIpAddr *ipaddr,
                                 uint16_t port);
void             udp_disconnect (struct udp_pcb *pcb);
void             udp_recv       (struct udp_pcb *pcb, udp_recv_fn recv,
                                 void *recv_arg);
LwipError            udp_sendto_if  (struct udp_pcb *pcb, struct PacketBuffer *p,
                                 const LwipIpAddr *dst_ip, uint16_t dst_port,
                                 struct netif *netif);
LwipError            udp_sendto_if_src(struct udp_pcb *pcb, struct PacketBuffer *p,
                                 const LwipIpAddr *dst_ip, uint16_t dst_port,
                                 struct netif *netif, const LwipIpAddr *src_ip);
LwipError            udp_sendto     (struct udp_pcb *pcb, struct PacketBuffer *p,
                                 const LwipIpAddr *dst_ip, uint16_t dst_port);
LwipError            udp_send       (struct udp_pcb *pcb, struct PacketBuffer *p);

#if LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP
LwipError            udp_sendto_if_chksum(struct udp_pcb *pcb, struct PacketBuffer *p,
                                 const ip_addr_t *dst_ip, uint16_t dst_port,
                                 struct netif *netif, uint8_t have_chksum,
                                 uint16_t chksum);
LwipError            udp_sendto_chksum(struct udp_pcb *pcb, struct PacketBuffer *p,
                                 const ip_addr_t *dst_ip, uint16_t dst_port,
                                 uint8_t have_chksum, uint16_t chksum);
LwipError            udp_send_chksum(struct udp_pcb *pcb, struct PacketBuffer *p,
                                 uint8_t have_chksum, uint16_t chksum);
LwipError            udp_sendto_if_src_chksum(struct udp_pcb *pcb, struct PacketBuffer *p,
                                 const ip_addr_t *dst_ip, uint16_t dst_port, struct netif *netif,
                                 uint8_t have_chksum, uint16_t chksum, const ip_addr_t *src_ip);
#endif /* LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP */

#define          udp_flags(pcb) ((pcb)->flags)
#define          udp_setflags(pcb, f)  ((pcb)->flags = (f))

#define          udp_set_flags(pcb, set_flags)     do { (pcb)->flags = (uint8_t)((pcb)->flags |  (set_flags)); } while(0)
#define          udp_clear_flags(pcb, clr_flags)   do { (pcb)->flags = (uint8_t)((pcb)->flags & (uint8_t)(~(clr_flags) & 0xff)); } while(0)
#define          udp_is_flag_set(pcb, flag)        (((pcb)->flags & (flag)) != 0)

/* The following functions are the lower layer interface to UDP. */
void             udp_input      (struct PacketBuffer *p, struct netif *inp);

void             udp_init       (void);

/* for compatibility with older implementation */
#define udp_new_ip6() udp_new_ip_type(IPADDR_TYPE_V6)

#if LWIP_MULTICAST_TX_OPTIONS
#if LWIP_IPV4
#define udp_set_multicast_netif_addr(pcb, ip4addr) ip4_addr_copy((pcb)->mcast_ip4, *(ip4addr))
#define udp_get_multicast_netif_addr(pcb)          (&(pcb)->mcast_ip4)
#endif /* LWIP_IPV4 */
#define udp_set_multicast_netif_index(pcb, idx)    ((pcb)->mcast_ifindex = (idx))
#define udp_get_multicast_netif_index(pcb)         ((pcb)->mcast_ifindex)
#define udp_set_multicast_ttl(pcb, value)          ((pcb)->mcast_ttl = (value))
#define udp_get_multicast_ttl(pcb)                 ((pcb)->mcast_ttl)
#endif /* LWIP_MULTICAST_TX_OPTIONS */

#if UDP_DEBUG
void udp_debug_print(struct udp_hdr *udphdr);
#else
#define udp_debug_print(udphdr)
#endif

void udp_netif_ip_addr_changed(const LwipIpAddr* old_addr, const LwipIpAddr* new_addr);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_UDP */

#endif /* LWIP_HDR_UDP_H */
