/**
 * @file
 * IGMP API
 */

/*
 * Copyright (c) 2002 CITEL Technologies Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of CITEL Technologies Ltd nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY CITEL TECHNOLOGIES AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL CITEL TECHNOLOGIES OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is a contribution to the lwIP TCP/IP stack.
 * The Swedish Institute of Computer Science and Adam Dunkels
 * are specifically granted permission to redistribute this
 * source code.
*/

#pragma once
#include "netif.h"
#include "packet_buffer.h"
#include "ip4.h"


/*
 * IGMP constants
 */
#define IGMP_TTL                       1
#define IGMP_MINLEN                    8
#define ROUTER_ALERT                   0x9404U
#define ROUTER_ALERTLEN                4

 /*
  * IGMP message types, including version number.
  */
#define IGMP_MEMB_QUERY                0x11 /* Membership query         */
#define IGMP_V1_MEMB_REPORT            0x12 /* Ver. 1 membership report */
#define IGMP_V2_MEMB_REPORT            0x16 /* Ver. 2 membership report */
#define IGMP_LEAVE_GROUP               0x17 /* Leave-group message      */

  /* Group  membership states */
#define IGMP_GROUP_NON_MEMBER          0
#define IGMP_GROUP_DELAYING_MEMBER     1
#define IGMP_GROUP_IDLE_MEMBER         2

/**
 * IGMP packet format.
 */
struct IgmpMsg
{
    uint8_t igmp_msgtype;
    uint8_t igmp_maxresp;
    uint16_t igmp_checksum;
    Ip4AddrPT igmp_group_address;
};

/* IGMP timer */
#define IGMP_TMR_INTERVAL              100 /* Milliseconds */
#define IGMP_V1_DELAYING_MEMBER_TMR   (1000/IGMP_TMR_INTERVAL)
#define IGMP_JOIN_DELAYING_MEMBER_TMR (500 /IGMP_TMR_INTERVAL)

/* Compatibility defines (don't use for new code) */
#define IGMP_DEL_MAC_FILTER            NETIF_DEL_MAC_FILTER
#define IGMP_ADD_MAC_FILTER            NETIF_ADD_MAC_FILTER

/**
 * igmp group structure - there is
 * a list of groups for each interface
 * these should really be linked from the interface, but
 * if we keep them separate we will not affect the lwip original code
 * too much
 *
 * There will be a group for the all systems group address but this
 * will not run the state machine as it is used to kick off reports
 * from all the other groups
 */
struct IgmpGroup {
  /** next link */
  struct IgmpGroup *next;
  /** multicast address */
  Ip4Addr         group_address;
  /** signifies we were the last person to report */
  uint8_t               last_reporter_flag;
  /** current state of the group */
  uint8_t               group_state;
  /** timer for reporting, negative is OFF */
  uint16_t              timer;
  /** counter of simultaneous uses */
  uint8_t               use;
};

/*  Prototypes */
void   igmp_init(void);
LwipError  igmp_start(NetIfc*netif);
LwipError  igmp_stop(NetIfc*netif);
void   igmp_report_groups(NetIfc*netif);
struct IgmpGroup *igmp_lookfor_group(NetIfc*ifp, const Ip4Addr *addr);
void   igmp_input(struct PacketBuffer *p, NetIfc*inp, const Ip4Addr *dest);
LwipError  igmp_joingroup(const Ip4Addr *ifaddr, const Ip4Addr *groupaddr);
LwipError  igmp_joingroup_netif(NetIfc*netif, const Ip4Addr *groupaddr);
LwipError  igmp_leavegroup(const Ip4Addr *ifaddr, const Ip4Addr *groupaddr);
LwipError  igmp_leavegroup_netif(NetIfc*netif, const Ip4Addr *groupaddr);
void   igmp_tmr(void);

/** @ingroup igmp 
 * Get list head of IGMP groups for netif.
 * Note: The allsystems group IP is contained in the list as first entry.
 * @see @ref netif_set_igmp_mac_filter()
 */
inline IgmpGroup* netif_igmp_data(NetIfc* netif)
{
    return static_cast<IgmpGroup *>(netif->client_data[LWIP_NETIF_CLIENT_DATA_INDEX_IGMP]
    );
}

//
// END OF FILE
//