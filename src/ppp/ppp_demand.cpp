/*
 * demand.c - Support routines for demand-dialling.
 *
 * Copyright (c) 1996-2002 Paul Mackerras. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. The name(s) of the authors of this software must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 3. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Paul Mackerras
 *     <paulus@samba.org>".
 *
 * THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define NOMINMAX
#include "ppp_demand.h"
#include "ppp_config.h"
#include "fsm.h"
#include "ipcp.h"
#include "ppp_lcp.h"

#include <cstdlib>
#include <cstring>
#include "pppos.h"
#ifdef _MSC_VER

#else
#include "unistd.h"
#include "syslog.h"
#include <sys/param.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap-bpf.h>
#endif

char *frame;
int framelen;
int framemax;
int escape_flag;
int flush_flag;
int fcs;
struct Packet *pend_q;
struct Packet *pend_qtail;

/*
 * demand_conf - configure the interface for doing dial-on-demand.
 */
void demand_conf()
{
    // int i;
    // const struct protent* protp; /*    framemax = lcp_allowoptions[0].mru;
    // if (framemax < PPP_MRU) */
    framemax = PPP_MRU;
    framemax += PPP_HDRLEN + PPP_FCSLEN;
    frame = static_cast<char*>(malloc(framemax));
    if (frame == nullptr)
    {
        // novm("demand frame");
        framelen = 0;
    }
    pend_q = nullptr;
    escape_flag = 0;
    flush_flag = 0;
    fcs = PPP_INITFCS;
    //    netif_set_mtu(pcb, std::min(lcp_allowoptions[0].mru, PPP_MRU));
    //    if (ppp_send_config(pcb, PPP_MRU, uint32_t(0), 0, 0) < 0
    // || ppp_recv_config(pcb, PPP_MRU, uint32_t(0), 0, 0) < 0)
    //     fatal("Couldn't set up demand-dialled PPP interface: %m");
    //
    //    set_filters(&pass_filter, &active_filter);
    /*
     * Call the demand_conf procedure for each protocol that's got one.
     */ //    for (i = 0; (protp = protocols[i]) != NULL; ++i)
    // if (protp->demand_conf != NULL)
    //     ((*protp->demand_conf)(pcb));
    /* FIXME: find a way to die() here */
}


/*
 * demand_block - set each network protocol to block further packets.
 */
void demand_block()
{
    int i;
    const struct protent* protp; //    for (i = 0; (protp = protocols[i]) != NULL; ++i)
    // if (protp->demand_conf != NULL)
    //     sifnpmode(pcb, protp->protocol & ~0x8000, NPMODE_QUEUE);
    //    get_loop_output();
}

/*
 * demand_discard - set each network protocol to discard packets
 * with an error.
 */
void demand_discard()
{
    struct Packet*nextpkt;
    int i;
    const struct protent* protp; // for (i = 0; (protp = protocols[i]) != NULL; ++i)
    // if (protp->demand_conf != NULL)
    //     sifnpmode(pcb, protp->protocol & ~0x8000, PppNetworkProtoMode);
    //    get_loop_output();
    /* discard all saved packets */
    for (auto pkt = pend_q; pkt != nullptr; pkt = nextpkt)
    {
        nextpkt = pkt->next;
        free(pkt);
    }
    pend_q = nullptr;
    framelen = 0;
    flush_flag = 0;
    escape_flag = 0;
    fcs = PPP_INITFCS;
}

/*
 * demand_unblock - set each enabled network protocol to pass packets.
 */
void demand_unblock()
{
    int i;
    const struct protent* protp; //    for (i = 0; (protp = protocols[i]) != NULL; ++i)
    // if (protp->demand_conf != NULL)
    //     sifnpmode(pcb, protp->protocol & ~0x8000, NPMODE_PASS);
}


/*
 * loop_chars - process characters received from the loopback.
 * Calls loop_frame when a complete frame has been accumulated.
 * Return value is 1 if we need to bring up the link, 0 otherwise.
 */
// int
// loop_chars(p, n)
//     unsigned char *p;
//     int n;
// {
//     int c, rv;
//
//     rv = 0;
//
// /* check for synchronous connection... */
//
//     if ( (p[0] == 0xFF) && (p[1] == 0x03) ) {
//         rv = loop_frame(p,n);
//         return rv;
//     }
//
//     for (; n > 0; --n) {
// 	c = *p++;
// 	if (c == PPP_FLAG) {
// 	    if (!escape_flag && !flush_flag
// 		&& framelen > 2 && fcs == PPP_GOODFCS) {
// 		framelen -= 2;
// 		if (loop_frame((unsigned char *)frame, framelen))
// 		    rv = 1;
// 	    }
// 	    framelen = 0;
// 	    flush_flag = 0;
// 	    escape_flag = 0;
// 	    fcs = PPP_INITFCS;
// 	    continue;
// 	}
// 	if (flush_flag)
// 	    continue;
// 	if (escape_flag) {
// 	    c ^= PPP_TRANS;
// 	    escape_flag = 0;
// 	} else if (c == PPP_ESCAPE) {
// 	    escape_flag = 1;
// 	    continue;
// 	}
// 	if (framelen >= framemax) {
// 	    flush_flag = 1;
// 	    continue;
// 	}
// 	frame[framelen++] = c;
// 	fcs = PPP_FCS(fcs, c);
//     }
//     return rv;
// }

/*
 * loop_frame - given a frame obtained from the loopback,
 * decide whether to bring up the link or not, and, if we want
 * to transmit this frame later, put it on the pending queue.
 * Return value is 1 if we need to bring up the link, 0 otherwise.
 * We assume that the kernel driver has already applied the
 * pass_filter, so we won't get packets it rejected.
 * We apply the active_filter to see if we want this packet to
 * bring up the link.
 */
// int
// loop_frame(frame, len)
//     unsigned char *frame;
//     int len;
// {
//     struct Packet *pkt;
//
//     /* dbglog("from loop: %P", frame, len); */
//     if (len < PPP_HDRLEN)
// 	return 0;
//     if ((PPP_PROTOCOL(frame) & 0x8000) != 0)
// 	return 0;		/* shouldn't get any of these anyway */
//     if (!active_packet(frame, len))
// 	return 0;
//
//     pkt = (struct Packet *) malloc(sizeof(struct Packet) + len);
//     if (pkt != NULL) {
// 	pkt->length = len;
// 	pkt->next = NULL;
// 	memcpy(pkt->data, frame, len);
// 	if (pend_q == NULL)
// 	    pend_q = pkt;
// 	else
// 	    pend_qtail->next = pkt;
// 	pend_qtail = pkt;
//     }
//     return 1;
// }

/*
 * demand_rexmit - Resend all those frames which we got via the
 * loopback, now that the real serial link is up.
 */
// void
// demand_rexmit(proto, newip)
//     int proto;
//     uint32_t newip;
// {
//     struct Packet *pkt, *prev, *nextpkt;
//     unsigned short checksum;
//     unsigned short pkt_checksum = 0;
//     unsigned iphdr;
//     struct timeval tv;
//     char cv = 0;
//     char ipstr[16];
//
//     prev = NULL;
//     pkt = pend_q;
//     pend_q = NULL;
//     tv.tv_sec = 1;
//     tv.tv_usec = 0;
//     select(0,NULL,NULL,NULL,&tv);	/* Sleep for 1 Seconds */
//     for (; pkt != NULL; pkt = nextpkt) {
// 	nextpkt = pkt->next;
// 	if (PPP_PROTOCOL(pkt->data) == proto) {
//             if ( (proto == PPP_IP) && newip ) {
// 		/* Get old checksum */
//
// 		iphdr = (pkt->data[4] & 15) << 2;
// 		checksum = *((unsigned short *) (pkt->data+14));
//                 if (checksum == 0xFFFF) {
//                     checksum = 0;
//                 }
//
//  
//                 if (pkt->data[13] == 17) {
//                     pkt_checksum =  *((unsigned short *) (pkt->data+10+iphdr));
// 		    if (pkt_checksum) {
//                         cv = 1;
//                         if (pkt_checksum == 0xFFFF) {
//                             pkt_checksum = 0;
//                         }
//                     }
//                     else {
//                        cv = 0;
//                     }
//                 }
//
// 		if (pkt->data[13] == 6) {
// 		    pkt_checksum = *((unsigned short *) (pkt->data+20+iphdr));
// 		    cv = 1;
//                     if (pkt_checksum == 0xFFFF) {
//                         pkt_checksum = 0;
//                     }
// 		}
//
// 		/* Delete old Source-IP-Address */
//                 checksum -= *((unsigned short *) (pkt->data+16)) ^ 0xFFFF;
//                 checksum -= *((unsigned short *) (pkt->data+18)) ^ 0xFFFF;
//
// 		pkt_checksum -= *((unsigned short *) (pkt->data+16)) ^ 0xFFFF;
// 		pkt_checksum -= *((unsigned short *) (pkt->data+18)) ^ 0xFFFF;
//
// 		/* Change Source-IP-Address */
//                 * ((uint32_t *) (pkt->data + 16)) = newip;
//
// 		/* Add new Source-IP-Address */
//                 checksum += *((unsigned short *) (pkt->data+16)) ^ 0xFFFF;
//                 checksum += *((unsigned short *) (pkt->data+18)) ^ 0xFFFF;
//
//                 pkt_checksum += *((unsigned short *) (pkt->data+16)) ^ 0xFFFF;
//                 pkt_checksum += *((unsigned short *) (pkt->data+18)) ^ 0xFFFF;
//
// 		/* Write new checksum */
//                 if (!checksum) {
//                     checksum = 0xFFFF;
//                 }
//                 *((unsigned short *) (pkt->data+14)) = checksum;
// 		if (pkt->data[13] == 6) {
// 		    *((unsigned short *) (pkt->data+20+iphdr)) = pkt_checksum;
// 		}
// 		if (cv && (pkt->data[13] == 17) ) {
// 		    *((unsigned short *) (pkt->data+10+iphdr)) = pkt_checksum;
// 		}
//
// 		/* Log Packet */
// 		strcpy(ipstr,inet_ntoa(*( (struct LwipInAddrStruct *) (pkt->data+16))));
// 		if (pkt->data[13] == 1) {
// 		    syslog(LOG_INFO,"Open ICMP %s -> %s\n",
// 			ipstr,
// 			inet_ntoa(*( (struct LwipInAddrStruct *) (pkt->data+20))));
// 		} else {
// 		    syslog(LOG_INFO,"Open %s %s:%d -> %s:%d\n",
// 			pkt->data[13] == 6 ? "TCP" : "UDP",
// 			ipstr,
// 			ntohs(*( (short *) (pkt->data+iphdr+4))),
// 			inet_ntoa(*( (struct LwipInAddrStruct *) (pkt->data+20))),
// 			ntohs(*( (short *) (pkt->data+iphdr+6))));
//                 }
//             }
// 	    output(pcb, pkt->data, pkt->length);
// 	    free(pkt);
// 	} else {
// 	    if (prev == NULL)
// 		pend_q = pkt;
// 	    else
// 		prev->next = pkt;
// 	    prev = pkt;
// 	}
//     }
//     pend_qtail = prev;
//     if (prev != NULL)
// 	prev->next = NULL;
// }

/*
 * Scan a packet to decide whether it is an "active" packet,
 * that is, whether it is worth bringing up the link for.
 */
// static int
// active_packet(p, len)
//     unsigned char *p;
//     int len;
// {
//     int proto, i;
//     const struct protent *protp;
//
//     if (len < PPP_HDRLEN)
// 	return 0;
//     proto = PPP_PROTOCOL(p);
// #ifdef PPP_FILTER
//     p[0] = 1;		/* outbound packet indicator */
//     if ((pass_filter.bf_len != 0
// 	 && bpf_filter(pass_filter.bf_insns, p, len, len) == 0)
// 	|| (active_filter.bf_len != 0
// 	    && bpf_filter(active_filter.bf_insns, p, len, len) == 0)) {
// 	p[0] = 0xff;
// 	return 0;
//     }
//     p[0] = 0xff;
// #endif
//     for (i = 0; (protp = protocols[i]) != NULL; ++i) {
// 	if (protp->protocol < 0xC000 && (protp->protocol & ~0x8000) == proto) {
// 	    if (protp->active_pkt == NULL)
// 		return 1;
// 	    return (*protp->active_pkt)(p, len);
// 	}
//     }
//     return 0;			/* not a supported protocol !!?? */
// }
