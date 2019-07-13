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
#pragma once

#include "opt.h"
#include "arch.h"
#include "packet_buffer.h"
#include "netif.h"
#include "ip_addr.h"
#include "ip.h"
#include "ip6_addr.h"
#include "udp.h"

constexpr auto kUdpHdrLen = 8;

struct UdpHdr
{
    uint16_t src;
    uint16_t dest; /* src/dest UDP ports */
    uint16_t len;
    uint16_t chksum;
};

enum UdpFlags
{
    UDP_FLAGS_NOCHKSUM = 0x01U,
    UDP_FLAGS_UDPLITE = 0x02U,
    UDP_FLAGS_CONNECTED = 0x04U,
    UDP_FLAGS_MULTICAST_LOOP= 0x08U
};

struct UdpPcb;

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
typedef void (*udp_recv_fn)(void *arg, struct UdpPcb *pcb, struct PacketBuffer *p,
    const IpAddr *addr, uint16_t port);

/** the UDP protocol control block */
struct UdpPcb
{
    /** Common members of all PCB types */
    IpAddr local_ip; /* Bound netif index */
    uint8_t netif_idx; /* Socket options */
    uint8_t so_options; /* Type Of Service */
    uint8_t tos; /* Time To Live */
    uint8_t ttl;
    NetIfc*cHint netif_hints; /* Protocol specific PCB members */
    struct UdpPcb* next;
    uint8_t flags; /** ports are in host byte order */
    uint16_t local_port, remote_port;
    /** outgoing network interface for multicast packets, by IPv4 address (if not 'any') */
    Ip4Addr mcast_ip4;
    /** outgoing network interface for multicast packets, by interface index (if nonzero) */
    uint8_t mcast_ifindex; /** TTL for outgoing multicast packets */
    uint8_t mcast_ttl; /** used for UDP_LITE only */
    uint16_t chksum_len_rx, chksum_len_tx; /** receive callback function */
    udp_recv_fn recv; /** user-supplied argument for the recv callback */
    void* recv_arg;
};


/* udp_pcbs export for external reference (e.g. SNMP agent) */
extern struct UdpPcb *udp_pcbs;

/* The following functions is the application layer interface to the
   UDP code. */
struct UdpPcb * udp_new        (void);
struct UdpPcb * udp_new_ip_type(uint8_t type);
void             udp_remove     (struct UdpPcb *pcb);
LwipError            udp_bind       (struct UdpPcb *pcb, const IpAddr *ipaddr,
                                 uint16_t port);
void             udp_bind_netif (struct UdpPcb *pcb, const NetIfc** netif);
LwipError            udp_connect    (struct UdpPcb *pcb, const IpAddr *ipaddr,
                                 uint16_t port);
void             udp_disconnect (struct UdpPcb *pcb);
void             udp_recv       (struct UdpPcb *pcb, udp_recv_fn recv,
                                 void *recv_arg);
LwipError            udp_sendto_if  (struct UdpPcb *pcb, struct PacketBuffer *p,
                                 const IpAddr *dst_ip, uint16_t dst_port,
                                 NetIfc*netif);
LwipError            udp_sendto_if_src(struct UdpPcb *pcb, struct PacketBuffer *p,
                                 const IpAddr *dst_ip, uint16_t dst_port,
                                 NetIfc*netif, const IpAddr *src_ip);
LwipError            udp_sendto     (struct UdpPcb *pcb, struct PacketBuffer *p,
                                 const IpAddr *dst_ip, uint16_t dst_port);
LwipError            udp_send       (struct UdpPcb *pcb, struct PacketBuffer *p);

LwipError            udp_sendto_if_chksum(UdpPcb *pcb, struct PacketBuffer *p,
                                 const IpAddr *dst_ip, uint16_t dst_port,
                                 NetIfc*netif, uint8_t have_chksum,
                                 uint16_t chksum);
LwipError            udp_sendto_chksum(UdpPcb *pcb, struct PacketBuffer *p,
                                 const IpAddr *dst_ip, uint16_t dst_port,
                                 uint8_t have_chksum, uint16_t chksum);
LwipError            udp_send_chksum(UdpPcb *pcb, struct PacketBuffer *p,
                                 uint8_t have_chksum, uint16_t chksum);
LwipError            udp_sendto_if_src_chksum(UdpPcb *pcb, struct PacketBuffer *p,
                                 const IpAddr *dst_ip, uint16_t dst_port, NetIfc*netif,
                                 uint8_t have_chksum, uint16_t chksum, const IpAddr *src_ip);

#define          udp_flags(pcb) ((pcb)->flags)
#define          udp_setflags(pcb, f)  ((pcb)->flags = (f))

#define          udp_set_flags(pcb, set_flags)     do { (pcb)->flags = (uint8_t)((pcb)->flags |  (set_flags)); } while(0)
#define          udp_clear_flags(pcb, clr_flags)   do { (pcb)->flags = (uint8_t)((pcb)->flags & (uint8_t)(~(clr_flags) & 0xff)); } while(0)
#define          udp_is_flag_set(pcb, flag)        (((pcb)->flags & (flag)) != 0)

/* The following functions are the lower layer interface to UDP. */
void             udp_input      (struct PacketBuffer *p, NetIfc*inp);

void             udp_init       (void);

/* for compatibility with older implementation */
#define udp_new_ip6() udp_new_ip_type(IPADDR_TYPE_V6)

#define udp_set_multicast_netif_addr(pcb, ip4addr) ip4_addr_copy((pcb)->mcast_ip4, *(ip4addr))
#define udp_get_multicast_netif_addr(pcb)          (&(pcb)->mcast_ip4)
#define udp_set_multicast_netif_index(pcb, idx)    ((pcb)->mcast_ifindex = (idx))
#define udp_get_multicast_netif_index(pcb)         ((pcb)->mcast_ifindex)
#define udp_set_multicast_ttl(pcb, value)          ((pcb)->mcast_ttl = (value))
#define udp_get_multicast_ttl(pcb)                 ((pcb)->mcast_ttl)


void udp_debug_print(struct udp_hdr *udphdr);

void udp_netif_ip_addr_changed(const IpAddr* old_addr, const IpAddr* new_addr);
