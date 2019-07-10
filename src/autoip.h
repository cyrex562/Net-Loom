/**
 * @file
 *
 * AutoIP Automatic LinkLocal IP Configuration
 */

/*
 *
 * Copyright (c) 2007 Dominik Spies <kontakt@dspies.de>
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
 * Author: Dominik Spies <kontakt@dspies.de>
 *
 * This is a AutoIP implementation for the lwIP TCP/IP stack. It aims to conform
 * with RFC 3927.
 *
 */

#ifndef LWIP_HDR_AUTOIP_H
#define LWIP_HDR_AUTOIP_H

#include "opt.h"


 /* 169.254.0.0 */
#define AUTOIP_NET              0xA9FE0000
/* 169.254.1.0 */
#define AUTOIP_RANGE_START      (AUTOIP_NET | 0x0100)
/* 169.254.254.255 */
#define AUTOIP_RANGE_END        (AUTOIP_NET | 0xFEFF)

/* RFC 3927 Constants */
#define PROBE_WAIT              1   /* second   (initial random delay)                 */
#define PROBE_MIN               1   /* second   (minimum delay till repeated probe)    */
#define PROBE_MAX               2   /* seconds  (maximum delay till repeated probe)    */
#define PROBE_NUM               3   /*          (number of probe packets)              */
#define ANNOUNCE_NUM            2   /*          (number of announcement packets)       */
#define ANNOUNCE_INTERVAL       2   /* seconds  (time between announcement packets)    */
#define ANNOUNCE_WAIT           2   /* seconds  (delay before announcing)              */
#define MAX_CONFLICTS           10  /*          (max conflicts before rate limiting)   */
#define RATE_LIMIT_INTERVAL     60  /* seconds  (delay between successive attempts)    */
#define DEFEND_INTERVAL         10  /* seconds  (min. wait between defensive ARPs)     */

/* AutoIP client states */
typedef enum {
    AUTOIP_STATE_OFF = 0,
    AUTOIP_STATE_PROBING = 1,
    AUTOIP_STATE_ANNOUNCING = 2,
    AUTOIP_STATE_BOUND = 3
} autoip_state_enum_t;


#if LWIP_IPV4 && LWIP_AUTOIP /* don't build if not configured for use in lwipopts.h */

#include "netif.h"
/* #include "udp.h" */
#include "etharp.h"

#ifdef __cplusplus
extern "C" {
#endif

/** AutoIP Timing */
#define AUTOIP_TMR_INTERVAL      100
#define AUTOIP_TICKS_PER_SECOND (1000 / AUTOIP_TMR_INTERVAL)

/** AutoIP state information per netif */
struct autoip
{
  /** the currently selected, probed, announced or used LL IP-Address */
  Ip4Addr llipaddr;
  /** current AutoIP state machine state */
  uint8_t state;
  /** sent number of probes or announces, dependent on state */
  uint8_t sent_num;
  /** ticks to wait, tick is AUTOIP_TMR_INTERVAL long */
  uint16_t ttw;
  /** ticks until a conflict can be solved by defending */
  uint8_t lastconflict;
  /** total number of probed/used Link Local IP-Addresses */
  uint8_t tried_llipaddr;
};


void autoip_set_struct(struct netif *netif, struct autoip *autoip);
/** Remove a struct autoip previously set to the netif using autoip_set_struct() */
#define autoip_remove_struct(netif) do { (netif)->autoip = NULL; } while (0)
LwipError autoip_start(struct netif *netif);
LwipError autoip_stop(struct netif *netif);
void autoip_arp_reply(struct netif *netif, struct etharp_hdr *hdr);
void autoip_tmr(void);
void autoip_network_changed(struct netif *netif);
uint8_t autoip_supplied_address(const struct netif *netif);

/* for lwIP internal use by ip4.c */
uint8_t autoip_accept_packet(struct netif *netif, const Ip4Addr *addr);

#define netif_autoip_data(netif) ((struct autoip*)netif_get_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_AUTOIP))

#ifdef __cplusplus
}
#endif

#endif /* LWIP_IPV4 && LWIP_AUTOIP */

#endif /* LWIP_HDR_AUTOIP_H */
