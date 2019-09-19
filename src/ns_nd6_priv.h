/**
 * @file
 *
 * Neighbor discovery and stateless address autoconfiguration for IPv6.
 * Aims to be compliant with RFC 4861 (Neighbor discovery) and RFC 4862
 * (Address autoconfiguration).
 */

/*
 * Copyright (c) 2010 Inico Technologies Ltd.
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
 * Author: Ivan Delamer <delamer@inicotech.com>
 *
 *
 * Please coordinate changes and requests with Ivan Delamer
 * <delamer@inicotech.com>
 */
#pragma once
#include "ns_config.h"
#include "ns_packet.h"
#include "ns_ip6_addr.h"
#include "ns_network_interface.h"

/** struct for queueing outgoing packets for unknown address
  * defined here to be accessed by memp.h
  */
struct nd6_q_entry {
  struct nd6_q_entry *next;
  struct PacketContainer *p;
};


/** Struct for tables. */
struct nd6_neighbor_cache_entry {
  Ip6Addr next_hop_address;
  NetworkInterface*netif;
  uint8_t lladdr[NETIF_MAX_HWADDR_LEN];
  /*uint32_t pmtu;*/

  /** Pointer to queue of pending outgoing packets on this entry. */
  struct nd6_q_entry *q;

  uint8_t state;
  uint8_t isrouter;
  union {
    uint32_t reachable_time; /* in seconds */
    uint32_t delay_time;     /* ticks (ND6_TMR_INTERVAL) */
    uint32_t probes_sent;
    uint32_t stale_time;     /* ticks (ND6_TMR_INTERVAL) */
  } counter;
};

struct nd6_destination_cache_entry {
  Ip6Addr destination_addr;
  Ip6Addr next_hop_addr;
  uint16_t pmtu;
  uint32_t age;
};

struct nd6_prefix_list_entry {
  Ip6Addr prefix;
  NetworkInterface*netif;
  uint32_t invalidation_timer; /* in seconds */
};

struct nd6_router_list_entry {
  struct nd6_neighbor_cache_entry *neighbor_entry;
  uint32_t invalidation_timer; /* in seconds */
  uint8_t flags;
};

enum nd6_neighbor_cache_entry_state {
  ND6_NO_ENTRY = 0,
  ND6_INCOMPLETE,
  ND6_REACHABLE,
  ND6_STALE,
  ND6_DELAY,
  ND6_PROBE
};

#define ND6_HOPLIM 255 /* maximum hop limit, required in all ND packets */

#define ND6_2HRS 7200 /* two hours, expressed in number of seconds */

/* Router tables. */
/* @todo make these static? and entries accessible through API? */
extern struct nd6_neighbor_cache_entry neighbor_cache[];
extern struct nd6_destination_cache_entry destination_cache[];
extern struct nd6_prefix_list_entry prefix_list[];
extern struct nd6_router_list_entry default_router_list[];

/* Default values, can be updated by a RA message. */
extern uint32_t reachable_time;
extern uint32_t retrans_timer;

