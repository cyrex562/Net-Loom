/**
 * @file
 * TCP internal implementations (do not use in application code)
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
#include "icmp.h"

#include "ip.h"

#include "ip6.h"

#include "ip6_addr.h"

#include "opt.h"

#include "packet_buffer.h"

#include "tcp.h"

#include "tcp.h"

/* Functions for interfacing with TCP: */

/* Lower layer interface to TCP: */
void             tcp_init    (void);  /* Initialize this module. */
void             tcp_tmr     (void);  /* Must be called every
                                         TCP_TMR_INTERVAL
                                         ms. (Typically 250 ms). */
/* It is also possible to call these two functions at the right
   intervals (instead of calling tcp_tmr()). */
void             tcp_slowtmr (void);
void             tcp_fasttmr (void);

/* Call this from a netif driver (watch out for threading issues!) that has
   returned a memory error on transmit and now has free buffers to send more.
   This iterates all active pcbs that had an error and tries to call
   tcp_output, so use this with care as it might slow down the system. */
void             tcp_txnow   (void);

/* Only used by IP to pass a TCP segment to TCP: */
void             tcp_input   (struct PacketBuffer *p, NetIfc*inp);
/* Used within the TCP code only: */
struct TcpPcb * tcp_alloc   (uint8_t prio);
void             tcp_free    (struct TcpPcb *pcb);
void             tcp_abandon (struct TcpPcb *pcb, int reset);
LwipStatus            tcp_send_empty_ack(struct TcpPcb *pcb);
LwipStatus            tcp_rexmit  (struct TcpPcb *pcb);
LwipStatus            tcp_rexmit_rto_prepare(struct TcpPcb *pcb);
void             tcp_rexmit_rto_commit(struct TcpPcb *pcb);
void             tcp_rexmit_rto  (struct TcpPcb *pcb);
void             tcp_rexmit_fast (struct TcpPcb *pcb);
uint32_t            tcp_update_rcv_ann_wnd(struct TcpPcb *pcb);
LwipStatus            tcp_process_refused_data(struct TcpPcb *pcb);

/**
 * This is the Nagle algorithm: try to combine user data to send as few TCP
 * segments as possible. Only send if
 * - no previously transmitted data on the connection remains unacknowledged or
 * - the TF_NODELAY flag is set (nagle algorithm turned off for this pcb) or
 * - the only unsent segment is at least pcb->mss bytes long (or there is more
 *   than one unsent segment - with lwIP, this can happen although unsent->len < mss)
 * - or if we are in fast-retransmit (TF_INFR)
 */
#define tcp_do_output_nagle(tpcb) ((((tpcb)->unacked == NULL) || \
                            ((tpcb)->flags & (TF_NODELAY | TF_INFR)) || \
                            (((tpcb)->unsent != NULL) && (((tpcb)->unsent->next != NULL) || \
                              ((tpcb)->unsent->len >= (tpcb)->mss))) || \
                            ((tcp_sndbuf(tpcb) == 0) || (tcp_sndqueuelen(tpcb) >= TCP_SND_QUEUELEN)) \
                            ) ? 1 : 0)
#define tcp_output_nagle(tpcb) (tcp_do_output_nagle(tpcb) ? tcp_output(tpcb) : ERR_OK)


#define TCP_SEQ_LT(a,b)     ((s32_t)((uint32_t)(a) - (uint32_t)(b)) < 0)
#define TCP_SEQ_LEQ(a,b)    ((s32_t)((uint32_t)(a) - (uint32_t)(b)) <= 0)
#define TCP_SEQ_GT(a,b)     ((s32_t)((uint32_t)(a) - (uint32_t)(b)) > 0)
#define TCP_SEQ_GEQ(a,b)    ((s32_t)((uint32_t)(a) - (uint32_t)(b)) >= 0)
/* is b<=a<=c? */

#define TCP_SEQ_BETWEEN(a,b,c) (TCP_SEQ_GEQ(a,b) && TCP_SEQ_LEQ(a,c))

#define TCP_TMR_INTERVAL       250  /* The TCP timer interval in milliseconds. */



#define TCP_FAST_INTERVAL      TCP_TMR_INTERVAL /* the fine grained timeout in milliseconds */



#define TCP_SLOW_INTERVAL      (2*TCP_TMR_INTERVAL)  /* the coarse grained timeout in milliseconds */


#define TCP_FIN_WAIT_TIMEOUT 20000 /* milliseconds */
#define TCP_SYN_RCVD_TIMEOUT 20000 /* milliseconds */

#define TCP_OOSEQ_TIMEOUT        6U /* x RTO */


#define TCP_MSL 60000UL /* The maximum segment lifetime in milliseconds */


/* Keepalive values, compliant with RFC 1122. Don't change this unless you know what you're doing */

#define  TCP_KEEPIDLE_DEFAULT     7200000UL /* Default KEEPALIVE timer in milliseconds */



#define  TCP_KEEPINTVL_DEFAULT    75000UL   /* Default Time between KEEPALIVE probes in milliseconds */



#define  TCP_KEEPCNT_DEFAULT      9U        /* Default Counter for KEEPALIVE probes */


#define  TCP_MAXIDLE              TCP_KEEPCNT_DEFAULT * TCP_KEEPINTVL_DEFAULT  /* Maximum KEEPALIVE probe time */

#define TCP_TCPLEN(seg) ((seg)->len + (((TCPH_FLAGS((seg)->tcphdr) & (TCP_FIN | TCP_SYN)) != 0) ? 1U : 0U))

/** Flags used on input processing, not on pcb->flags
*/
#define TF_RESET     (uint8_t)0x08U   /* Connection was reset. */
#define TF_CLOSED    (uint8_t)0x10U   /* Connection was successfully closed. */
#define TF_GOT_FIN   (uint8_t)0x20U   /* Connection was closed by the remote end. */


#define TCP_EVENT_ACCEPT(lpcb,pcb,arg,err,ret)                 \
  do {                                                         \
    if((lpcb)->accept_fn != NULL)                                 \
      (ret) = (lpcb)->accept_fn((arg),(pcb),(err));               \
    else (ret) = ERR_ARG;                                      \
  } while (0)

#define TCP_EVENT_SENT(pcb,space,ret)                          \
  do {                                                         \
    if((pcb)->sent != NULL)                                    \
      (ret) = (pcb)->sent((pcb)->callback_arg,(pcb),(space));  \
    else (ret) = ERR_OK;                                       \
  } while (0)

#define TCP_EVENT_RECV(pcb,p,err,ret)                          \
  do {                                                         \
    if((pcb)->recv != NULL) {                                  \
      (ret) = (pcb)->recv((pcb)->callback_arg,(pcb),(p),(err));\
    } else {                                                   \
      (ret) = tcp_recv_null(NULL, (pcb), (p), (err));          \
    }                                                          \
  } while (0)

#define TCP_EVENT_CLOSED(pcb,ret)                                \
  do {                                                           \
    if(((pcb)->recv != NULL)) {                                  \
      (ret) = (pcb)->recv((pcb)->callback_arg,(pcb),NULL,ERR_OK);\
    } else {                                                     \
      (ret) = ERR_OK;                                            \
    }                                                            \
  } while (0)

#define TCP_EVENT_CONNECTED(pcb,err,ret)                         \
  do {                                                           \
    if((pcb)->connected != NULL)                                 \
      (ret) = (pcb)->connected((pcb)->callback_arg,(pcb),(err)); \
    else (ret) = ERR_OK;                                         \
  } while (0)

#define TCP_EVENT_POLL(pcb,ret)                                \
  do {                                                         \
    if((pcb)->poll != NULL)                                    \
      (ret) = (pcb)->poll((pcb)->callback_arg,(pcb));          \
    else (ret) = ERR_OK;                                       \
  } while (0)

#define TCP_EVENT_ERR(last_state,errf,arg,err)                 \
  do {                                                         \
    ;                               \
    if((errf) != NULL)                                         \
      (errf)((arg),(err));                                     \
  } while (0)



/** Enabled extra-check for TCP_OVERSIZE if LWIP_DEBUG is enabled */


/** Don't generate checksum on copy if CHECKSUM_GEN_TCP is disabled */
#define TCP_CHECKSUM_ON_COPY  (LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_TCP)

/* This structure represents a TCP segment on the unsent, unacked and ooseq queues */
struct tcp_seg {
  struct tcp_seg *next;    /* used when putting segments on a queue */
  struct PacketBuffer *p;          /* buffer containing data + TCP header */
  uint16_t len;               /* the TCP length of this segment */

  uint16_t chksum;
  uint8_t  chksum_swapped;

  uint8_t  flags;
#define TF_SEG_OPTS_MSS         (uint8_t)0x01U /* Include MSS option (only used in SYN segments) */
#define TF_SEG_OPTS_TS          (uint8_t)0x02U /* Include timestamp option. */
#define TF_SEG_DATA_CHECKSUMMED (uint8_t)0x04U /* ALL data (not the header) is
                                               checksummed into 'chksum' */
#define TF_SEG_OPTS_WND_SCALE   (uint8_t)0x08U /* Include WND SCALE option (only used in SYN segments) */
#define TF_SEG_OPTS_SACK_PERM   (uint8_t)0x10U /* Include SACK Permitted option (only used in SYN segments) */
  struct TcpHdr *tcphdr;  /* the TCP header */
};

#define LWIP_TCP_OPT_EOL        0
#define LWIP_TCP_OPT_NOP        1
#define LWIP_TCP_OPT_MSS        2
#define LWIP_TCP_OPT_WS         3
#define LWIP_TCP_OPT_SACK_PERM  4
#define LWIP_TCP_OPT_TS         8

#define LWIP_TCP_OPT_LEN_MSS    4

#define LWIP_TCP_OPT_LEN_TS     10
#define LWIP_TCP_OPT_LEN_TS_OUT 12 /* aligned for output (includes NOP padding) */

#define LWIP_TCP_OPT_LEN_WS     3
#define LWIP_TCP_OPT_LEN_WS_OUT 4 /* aligned for output (includes NOP padding) */

#define LWIP_TCP_OPT_LEN_SACK_PERM     2
constexpr auto LWIP_TCP_OPT_LEN_SACK_PERM_OUT = 4 /* aligned for output (includes NOP padding) */;
// #define LWIP_TCP_OPT_LEN_SACK_PERM_OUT 0


#define LWIP_TCP_OPT_LENGTH(flags) \
  ((flags) & TF_SEG_OPTS_MSS       ? LWIP_TCP_OPT_LEN_MSS           : 0) + \
  ((flags) & TF_SEG_OPTS_TS        ? LWIP_TCP_OPT_LEN_TS_OUT        : 0) + \
  ((flags) & TF_SEG_OPTS_WND_SCALE ? LWIP_TCP_OPT_LEN_WS_OUT        : 0) + \
  ((flags) & TF_SEG_OPTS_SACK_PERM ? LWIP_TCP_OPT_LEN_SACK_PERM_OUT : 0)

/** This returns a TCP header option for MSS in an uint32_t */
#define TCP_BUILD_MSS_OPTION(mss) lwip_htonl(0x02040000 | ((mss) & 0xFFFF))


#define TCPWNDSIZE_F       U32_F
#define TCPWND_MAX         0xFFFFFFFFU
#define TCPWND_CHECK16(x)  lwip_assert("window size > 0xFFFF", (x) <= 0xFFFF)
#define TCPWND_MIN16(x)    ((uint16_t)LWIP_MIN((x), 0xFFFF))


/* Global variables: */
extern struct TcpPcb *tcp_input_pcb;
extern uint32_t tcp_ticks;
extern uint8_t tcp_active_pcbs_changed;

/* The TCP PCB lists. */
union tcp_listen_pcbs_t { /* List of all TCP PCBs in LISTEN state. */
  struct TcpPcbListen *listen_pcbs;
  struct TcpPcb *pcbs;
};
extern struct TcpPcb *tcp_bound_pcbs;
extern union tcp_listen_pcbs_t tcp_listen_pcbs;
extern struct TcpPcb *tcp_active_pcbs;  /* List of all TCP PCBs that are in a
              state in which they accept or send
              data. */
extern struct TcpPcb *tcp_tw_pcbs;      /* List of all TCP PCBs in TIME-WAIT. */

#define NUM_TCP_PCB_LISTS_NO_TIME_WAIT  3
#define NUM_TCP_PCB_LISTS               4
extern struct TcpPcb ** const tcp_pcb_lists[NUM_TCP_PCB_LISTS];

/* Axioms about the above lists:
   1) Every TCP PCB that is not CLOSED is in one of the lists.
   2) A PCB is only in one of the lists.
   3) All PCBs in the tcp_listen_pcbs list is in LISTEN state.
   4) All PCBs in the tcp_tw_pcbs list is in TIME-WAIT state.
*/
/* Define two macros, TCP_REG and TCP_RMV that registers a TCP PCB
   with a PCB list or removes a PCB from a list, respectively. */

/** External function (implemented in timers.c), called when TCP detects
 * that a timer is needed (i.e. active- or time-wait-pcb found). */
void tcp_timer_needed(void);


//
//
//
inline void remove_tcp_pcb_from_list(TcpPcb** pcbs, TcpPcb* npcb)
{
    if (*(pcbs) == (npcb))
    {
        (*(pcbs)) = (*pcbs)->next;
    }
    else
    {
        for (auto tcp_tmp_pcb = *pcbs;
             tcp_tmp_pcb != nullptr;
             tcp_tmp_pcb = tcp_tmp_pcb->next)
        {
            if (tcp_tmp_pcb->next == (npcb))
            {
                tcp_tmp_pcb->next = (npcb)->next;
                break;
            }
        }
    }
    (npcb)->next = nullptr;
}

inline void reg_tcp_pcb(TcpPcb** pcbs, TcpPcb* npcb)
{
    (npcb)->next = *pcbs;
    *(pcbs) = (npcb);
    tcp_timer_needed();
}

inline unsigned int reg_active_tcp_pcb(TcpPcb* npcb)
{
    auto tcp_active_pcbs_changed = 0;
    reg_tcp_pcb(&tcp_active_pcbs, npcb);
    tcp_active_pcbs_changed = 1;
    return tcp_active_pcbs_changed;
}

inline unsigned int remove_active_tcp_pcb(TcpPcb* npcb)
{
    auto tcp_active_pcbs_changed = 0;
    remove_tcp_pcb_from_list(&tcp_active_pcbs, npcb);
    tcp_active_pcbs_changed = 1;
    return tcp_active_pcbs_changed;
}

#define TCP_PCB_REMOVE_ACTIVE(pcb)                 \
  do {                                             \
    tcp_pcb_remove(&tcp_active_pcbs, pcb);         \
    tcp_active_pcbs_changed = 1;                   \
  } while (0)


/* Internal functions: */
struct TcpPcb *tcp_pcb_copy(struct TcpPcb *pcb);
void tcp_pcb_purge(struct TcpPcb *pcb);
void tcp_pcb_remove(struct TcpPcb **pcblist, struct TcpPcb *pcb);

void tcp_segs_free(struct tcp_seg *seg);
void tcp_seg_free(struct tcp_seg *seg);
struct tcp_seg *tcp_seg_copy(struct tcp_seg *seg);

#define tcp_ack(pcb)                               \
  do {                                             \
    if((pcb)->flags & TF_ACK_DELAY) {              \
      tcp_clear_flags(pcb, TF_ACK_DELAY);          \
      tcp_ack_now(pcb);                            \
    }                                              \
    else {                                         \
      tcp_set_flags(pcb, TF_ACK_DELAY);            \
    }                                              \
  } while (0)

#define tcp_ack_now(pcb)                           \
  tcp_set_flags(pcb, TF_ACK_NOW)

LwipStatus tcp_send_fin(struct TcpPcb *pcb);
LwipStatus tcp_enqueue_flags(struct TcpPcb *pcb, uint8_t flags);

void tcp_rexmit_seg(struct TcpPcb *pcb, struct tcp_seg *seg);

void tcp_rst(const struct TcpPcb* pcb, uint32_t seqno, uint32_t ackno,
       const IpAddr *local_ip, const IpAddr *remote_ip,
       uint16_t local_port, uint16_t remote_port);

uint32_t tcp_next_iss(struct TcpPcb *pcb);

LwipStatus tcp_keepalive(struct TcpPcb *pcb);
LwipStatus tcp_split_unsent_seg(struct TcpPcb *pcb, uint16_t split);
LwipStatus tcp_zero_window_probe(struct TcpPcb *pcb);
void  tcp_trigger_input_pcb_close(void);

uint16_t tcp_eff_send_mss_netif(uint16_t sendmss, NetIfc*outif,
                             const IpAddr *dest);
#define tcp_eff_send_mss(sendmss, src, dest) \
    tcp_eff_send_mss_netif(sendmss, ip_route(src, dest), dest)

LwipStatus tcp_recv_null(void *arg, struct TcpPcb *pcb, struct PacketBuffer *p, LwipStatus err);

#  define tcp_debug_print(tcphdr)
#  define tcp_debug_print_flags(flags)
#  define tcp_debug_print_state(s)
#  define tcp_debug_print_pcbs()
#  define tcp_pcbs_sane() 1




void tcp_netif_ip_addr_changed(const IpAddr* old_addr, const IpAddr* new_addr);

void tcp_free_ooseq(struct TcpPcb *pcb);


LwipStatus tcp_ext_arg_invoke_callbacks_passive_open(struct TcpPcbListen *lpcb, struct TcpPcb *cpcb);

