/*
 * ipcp.c - PPP IP Control Protocol.
 *
 * Copyright (c) 1984-2000 Carnegie Mellon University. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "ppp_opts.h"

/*
 * @todo:
 */


#include "ppp_impl.h"

#include "fsm.h"
#include "ipcp.h"










/* Notifiers for when IPCP goes up and down */
struct notifier *ip_up_notifier = nullptr;
struct notifier *ip_down_notifier = nullptr;


/* local vars */


/*
 * Callbacks for fsm code.  (CI = Configuration Information)
 */
static void ipcp_resetci(fsm *f);	/* Reset our CI */
static int  ipcp_cilen(fsm *f);	        /* Return length of our CI */
static void ipcp_addci(fsm *f, uint8_t *ucp, int *lenp); /* Add our CI */
static int  ipcp_ackci(fsm *f, uint8_t *p, int len);	/* Peer ack'd our CI */
static int  ipcp_nakci(fsm *f, uint8_t *p, int len, int treat_as_reject);/* Peer nak'd our CI */
static int  ipcp_rejci(fsm *f, uint8_t *p, int len);	/* Peer rej'd our CI */
static int  ipcp_reqci(fsm *f, uint8_t *inp, int *len, int reject_if_disagree); /* Rcv CI */
static void ipcp_up(fsm *f);		/* We're UP */
static void ipcp_down(fsm *f);		/* We're DOWN */
static void ipcp_finished(fsm *f);	/* Don't need lower layer */

static const fsm_callbacks ipcp_callbacks = { /* IPCP callback routines */
    ipcp_resetci,		/* Reset our Configuration Information */
    ipcp_cilen,			/* Length of our Configuration Information */
    ipcp_addci,			/* Add our Configuration Information */
    ipcp_ackci,			/* ACK our Configuration Information */
    ipcp_nakci,			/* NAK our Configuration Information */
    ipcp_rejci,			/* Reject our Configuration Information */
    ipcp_reqci,			/* Request peer's Configuration Information */
    ipcp_up,			/* Called when fsm reaches OPENED state */
    ipcp_down,			/* Called when fsm leaves OPENED state */
    NULL,			/* Called when we want the lower layer up */
    ipcp_finished,		/* Called when we want the lower layer down */
    NULL,			/* Called when Protocol-Reject received */
    NULL,			/* Retransmission is necessary */
    NULL,			/* Called to handle protocol-specific codes */
    "IPCP"			/* String name of protocol */
};

/*
 * Protocol entry points from main code.
 */
static void ipcp_init(PppPcb *pcb);
static void ipcp_open(PppPcb *pcb);
static void ipcp_close(PppPcb *pcb, const char *reason);
static void ipcp_lowerup(PppPcb *pcb);
static void ipcp_lowerdown(PppPcb *pcb);
static void ipcp_input(PppPcb *pcb, uint8_t *p, int len);
static void ipcp_protrej(PppPcb *pcb);

static int  ip_demand_conf (int);
static int  ip_active_pkt (uint8_t *, int);



const struct protent ipcp_protent = {
    PPP_IPCP,
    ipcp_init,
    ipcp_input,
    ipcp_protrej,
    ipcp_lowerup,
    ipcp_lowerdown,
    ipcp_open,
    ipcp_close,
    NULL,
    ip_demand_conf,
    ip_active_pkt

};

static void ipcp_clear_addrs(PppPcb *pcb, uint32_t ouraddr, uint32_t hisaddr, uint8_t replacedefaultroute);

/*
 * Lengths of configuration options.
 */
#define CILEN_VOID	2
#define CILEN_COMPRESS	4	/* min length for compression protocol opt. */
#define CILEN_VJ	6	/* length for RFC1332 Van-Jacobson opt. */
#define CILEN_ADDR	6	/* new-style single address option */
#define CILEN_ADDRS	10	/* old-style dual address option */


#define CODENAME(x)	((x) == CONFACK ? "ACK" : \
			 (x) == CONFNAK ? "NAK" : "REJ")



/*
 * ipcp_init - Initialize IPCP.
 */
static void ipcp_init(PppPcb *pcb) {
    fsm *f = &pcb->ipcp_fsm;

    ipcp_options *wo = &pcb->ipcp_wantoptions;
    ipcp_options *ao = &pcb->ipcp_allowoptions;

    f->pcb = pcb;
    f->protocol = PPP_IPCP;
    f->callbacks = &ipcp_callbacks;
    fsm_init(f);

    /*
     * Some 3G modems use repeated IPCP NAKs as a way of stalling
     * until they can contact a server on the network, so we increase
     * the default number of NAKs we accept before we start treating
     * them as rejects.
     */
    f->maxnakloops = 100;



    wo->neg_addr = wo->old_addrs = 1;

    wo->neg_vj = 1;
    wo->vj_protocol = IPCP_VJ_COMP;
    wo->maxslotindex = MAX_STATES - 1; /* really max index */
    wo->cflag = 1;




    ao->neg_addr = ao->old_addrs = 1;

    /* max slots and slot-id compression are currently hardwired in */
    /* ppp_if.c to 16 and 1, this needs to be changed (among other */
    /* things) gmc */

    ao->neg_vj = 1;
    ao->maxslotindex = MAX_STATES - 1;
    ao->cflag = 1;



    /*
     * XXX These control whether the user may use the proxyarp
     * and defaultroute options.
     */
    ao->proxy_arp = 1;
    ao->default_route = 1;

}


/*
 * ipcp_open - IPCP is allowed to come up.
 */
static void ipcp_open(PppPcb *pcb) {
    fsm *f = &pcb->ipcp_fsm;
    fsm_open(f);
    pcb->ipcp_is_open = 1;
}


/*
 * ipcp_close - Take IPCP down.
 */
static void ipcp_close(PppPcb *pcb, const char *reason) {
    fsm *f = &pcb->ipcp_fsm;
    fsm_close(f, reason);
}


/*
 * ipcp_lowerup - The lower layer is up.
 */
static void ipcp_lowerup(PppPcb *pcb) {
    fsm *f = &pcb->ipcp_fsm;
    fsm_lowerup(f);
}


/*
 * ipcp_lowerdown - The lower layer is down.
 */
static void ipcp_lowerdown(PppPcb *pcb) {
    fsm *f = &pcb->ipcp_fsm;
    fsm_lowerdown(f);
}


/*
 * ipcp_input - Input IPCP packet.
 */
static void ipcp_input(PppPcb *pcb, uint8_t *p, int len) {
    fsm *f = &pcb->ipcp_fsm;
    fsm_input(f, p, len);
}


/*
 * ipcp_protrej - A Protocol-Reject was received for IPCP.
 *
 * Pretend the lower layer went down, so we shut up.
 */
static void ipcp_protrej(PppPcb *pcb) {
    fsm *f = &pcb->ipcp_fsm;
    fsm_lowerdown(f);
}


/*
 * ipcp_resetci - Reset our CI.
 * Called by fsm_sconfreq, Send Configure Request.
 */
static void ipcp_resetci(fsm *f) {
    PppPcb *pcb = f->pcb;
    ipcp_options *wo = &pcb->ipcp_wantoptions;
    ipcp_options *go = &pcb->ipcp_gotoptions;
    ipcp_options *ao = &pcb->ipcp_allowoptions;

    wo->req_addr = (wo->neg_addr || wo->old_addrs) &&
	(ao->neg_addr || ao->old_addrs);
    if (wo->ouraddr == 0)
	wo->accept_local = 1;
    if (wo->hisaddr == 0)
	wo->accept_remote = 1;

    wo->req_dns1 = wo->req_dns2 = pcb->settings.usepeerdns;	/* Request DNS addresses from the peer */

    *go = *wo;
    if (!pcb->ask_for_local)
	go->ouraddr = 0;

    BZERO(&pcb->ipcp_hisoptions, sizeof(ipcp_options));
}


/*
 * ipcp_cilen - Return length of our CI.
 * Called by fsm_sconfreq, Send Configure Request.
 */
static int ipcp_cilen(fsm *f) {
    PppPcb *pcb = f->pcb;
    ipcp_options *go = &pcb->ipcp_gotoptions;

    ipcp_options *wo = &pcb->ipcp_wantoptions;

    ipcp_options *ho = &pcb->ipcp_hisoptions;

#define LENCIADDRS(neg)		(neg ? CILEN_ADDRS : 0)

#define LENCIVJ(neg, old)	(neg ? (old? CILEN_COMPRESS : CILEN_VJ) : 0)

#define LENCIADDR(neg)		(neg ? CILEN_ADDR : 0)

#define LENCIDNS(neg)		LENCIADDR(neg)



    /*
     * First see if we want to change our options to the old
     * forms because we have received old forms from the peer.
     */
    if (go->neg_addr && go->old_addrs && !ho->neg_addr && ho->old_addrs)
	go->neg_addr = 0;


    if (wo->neg_vj && !go->neg_vj && !go->old_vj) {
	/* try an older style of VJ negotiation */
	/* use the old style only if the peer did */
	if (ho->neg_vj && ho->old_vj) {
	    go->neg_vj = 1;
	    go->old_vj = 1;
	    go->vj_protocol = ho->vj_protocol;
	}
    }


    return (LENCIADDRS(!go->neg_addr && go->old_addrs) +

	    LENCIVJ(go->neg_vj, go->old_vj) +

	    LENCIADDR(go->neg_addr) +

	    LENCIDNS(go->req_dns1) +
	    LENCIDNS(go->req_dns2) +


	    0);
}


/*
 * ipcp_addci - Add our desired CIs to a packet.
 * Called by fsm_sconfreq, Send Configure Request.
 */
static void ipcp_addci(fsm *f, uint8_t *ucp, int *lenp) {
    PppPcb *pcb = f->pcb;
    ipcp_options *go = &pcb->ipcp_gotoptions;
    int len = *lenp;

#define ADDCIADDRS(opt, neg, val1, val2) \
    if (neg) { \
	if (len >= CILEN_ADDRS) { \
	    uint32_t l; \
	    PUTCHAR(opt, ucp); \
	    PUTCHAR(CILEN_ADDRS, ucp); \
	    l = lwip_ntohl(val1); \
	    PUTLONG(l, ucp); \
	    l = lwip_ntohl(val2); \
	    PUTLONG(l, ucp); \
	    len -= CILEN_ADDRS; \
	} else \
	    go->old_addrs = 0; \
    }

#define ADDCIVJ(opt, neg, val, old, maxslotindex, cflag) \
    if (neg) { \
	int vjlen = old? CILEN_COMPRESS : CILEN_VJ; \
	if (len >= vjlen) { \
	    PUTCHAR(opt, ucp); \
	    PUTCHAR(vjlen, ucp); \
	    PUTSHORT(val, ucp); \
	    if (!old) { \
		PUTCHAR(maxslotindex, ucp); \
		PUTCHAR(cflag, ucp); \
	    } \
	    len -= vjlen; \
	} else \
	    neg = 0; \
    }


#define ADDCIADDR(opt, neg, val) \
    if (neg) { \
	if (len >= CILEN_ADDR) { \
	    uint32_t l; \
	    PUTCHAR(opt, ucp); \
	    PUTCHAR(CILEN_ADDR, ucp); \
	    l = lwip_ntohl(val); \
	    PUTLONG(l, ucp); \
	    len -= CILEN_ADDR; \
	} else \
	    neg = 0; \
    }

#define ADDCIDNS(opt, neg, addr) \
    if (neg) { \
	if (len >= CILEN_ADDR) { \
	    uint32_t l; \
	    PUTCHAR(opt, ucp); \
	    PUTCHAR(CILEN_ADDR, ucp); \
	    l = lwip_ntohl(addr); \
	    PUTLONG(l, ucp); \
	    len -= CILEN_ADDR; \
	} else \
	    neg = 0; \
    }


    ADDCIADDRS(CI_ADDRS, !go->neg_addr && go->old_addrs, go->ouraddr,
	       go->hisaddr);


    ADDCIVJ(CI_COMPRESSTYPE, go->neg_vj, go->vj_protocol, go->old_vj,
	    go->maxslotindex, go->cflag);


    ADDCIADDR(CI_ADDR, go->neg_addr, go->ouraddr);


    ADDCIDNS(CI_MS_DNS1, go->req_dns1, go->dnsaddr[0]);

    ADDCIDNS(CI_MS_DNS2, go->req_dns2, go->dnsaddr[1]);



    
    *lenp -= len;
}


/*
 * ipcp_ackci - Ack our CIs.
 * Called by fsm_rconfack, Receive Configure ACK.
 *
 * Returns:
 *	0 - Ack was bad.
 *	1 - Ack was good.
 */
static int ipcp_ackci(fsm *f, uint8_t *p, int len) {
    PppPcb *pcb = f->pcb;
    ipcp_options *go = &pcb->ipcp_gotoptions;
    u_short cilen, citype;
    uint32_t cilong;

    u_short cishort;
    uint8_t cimaxslotindex, cicflag;


    /*
     * CIs must be in exactly the same order that we sent...
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */

#define ACKCIADDRS(opt, neg, val1, val2) \
    if (neg) { \
	uint32_t l; \
	if ((len -= CILEN_ADDRS) < 0) \
	    goto bad; \
	GETCHAR(citype, p); \
	GETCHAR(cilen, p); \
	if (cilen != CILEN_ADDRS || \
	    citype != opt) \
	    goto bad; \
	GETLONG(l, p); \
	cilong = lwip_htonl(l); \
	if (val1 != cilong) \
	    goto bad; \
	GETLONG(l, p); \
	cilong = lwip_htonl(l); \
	if (val2 != cilong) \
	    goto bad; \
    }

#define ACKCIVJ(opt, neg, val, old, maxslotindex, cflag) \
    if (neg) { \
	int vjlen = old? CILEN_COMPRESS : CILEN_VJ; \
	if ((len -= vjlen) < 0) \
	    goto bad; \
	GETCHAR(citype, p); \
	GETCHAR(cilen, p); \
	if (cilen != vjlen || \
	    citype != opt)  \
	    goto bad; \
	GETSHORT(cishort, p); \
	if (cishort != val) \
	    goto bad; \
	if (!old) { \
	    GETCHAR(cimaxslotindex, p); \
	    if (cimaxslotindex != maxslotindex) \
		goto bad; \
	    GETCHAR(cicflag, p); \
	    if (cicflag != cflag) \
		goto bad; \
	} \
    }


#define ACKCIADDR(opt, neg, val) \
    if (neg) { \
	uint32_t l; \
	if ((len -= CILEN_ADDR) < 0) \
	    goto bad; \
	GETCHAR(citype, p); \
	GETCHAR(cilen, p); \
	if (cilen != CILEN_ADDR || \
	    citype != opt) \
	    goto bad; \
	GETLONG(l, p); \
	cilong = lwip_htonl(l); \
	if (val != cilong) \
	    goto bad; \
    }

#define ACKCIDNS(opt, neg, addr) \
    if (neg) { \
	uint32_t l; \
	if ((len -= CILEN_ADDR) < 0) \
	    goto bad; \
	GETCHAR(citype, p); \
	GETCHAR(cilen, p); \
	if (cilen != CILEN_ADDR || citype != opt) \
	    goto bad; \
	GETLONG(l, p); \
	cilong = lwip_htonl(l); \
	if (addr != cilong) \
	    goto bad; \
    }


    ACKCIADDRS(CI_ADDRS, !go->neg_addr && go->old_addrs, go->ouraddr,
	       go->hisaddr);


    ACKCIVJ(CI_COMPRESSTYPE, go->neg_vj, go->vj_protocol, go->old_vj,
	    go->maxslotindex, go->cflag);


    ACKCIADDR(CI_ADDR, go->neg_addr, go->ouraddr);


    ACKCIDNS(CI_MS_DNS1, go->req_dns1, go->dnsaddr[0]);

    ACKCIDNS(CI_MS_DNS2, go->req_dns2, go->dnsaddr[1]);



    /*
     * If there are any remaining CIs, then this packet is bad.
     */
    if (len != 0)
	goto bad;
    return (1);

bad:
    IPCPDEBUG(("ipcp_ackci: received bad Ack!"));
    return (0);
}

/*
 * ipcp_nakci - Peer has sent a NAK for some of our CIs.
 * This should not modify any state if the Nak is bad
 * or if IPCP is in the OPENED state.
 * Calback from fsm_rconfnakrej - Receive Configure-Nak or Configure-Reject.
 *
 * Returns:
 *	0 - Nak was bad.
 *	1 - Nak was good.
 */
static int ipcp_nakci(fsm *f, uint8_t *p, int len, int treat_as_reject) {
    PppPcb *pcb = f->pcb;
    ipcp_options *go = &pcb->ipcp_gotoptions;

    uint8_t cimaxslotindex, cicflag;
    u_short cishort;

    uint32_t ciaddr1, ciaddr2, l;

    uint32_t cidnsaddr;

    ipcp_options no;		/* options we've seen Naks for */
    ipcp_options try_;		/* options to request next time */

    BZERO(&no, sizeof(no));
    try_ = *go;

    /*
     * Any Nak'd CIs must be in exactly the same order that we sent.
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */
#define NAKCIADDRS(opt, neg, code) \
    if ((neg) && \
	(cilen = p[1]) == CILEN_ADDRS && \
	len >= cilen && \
	p[0] == opt) { \
	len -= cilen; \
	INCPTR(2, p); \
	GETLONG(l, p); \
	ciaddr1 = lwip_htonl(l); \
	GETLONG(l, p); \
	ciaddr2 = lwip_htonl(l); \
	no.old_addrs = 1; \
	code \
    }

#define NAKCIVJ(opt, neg, code) \
    if (go->neg && \
	((cilen = p[1]) == CILEN_COMPRESS || cilen == CILEN_VJ) && \
	len >= cilen && \
	p[0] == opt) { \
	len -= cilen; \
	INCPTR(2, p); \
	GETSHORT(cishort, p); \
	no.neg = 1; \
        code \
    }


#define NAKCIADDR(opt, neg, code) \
    if (go->neg && \
	(cilen = p[1]) == CILEN_ADDR && \
	len >= cilen && \
	p[0] == opt) { \
	len -= cilen; \
	INCPTR(2, p); \
	GETLONG(l, p); \
	ciaddr1 = lwip_htonl(l); \
	no.neg = 1; \
	code \
    }

#define NAKCIDNS(opt, neg, code) \
    if (go->neg && \
	((cilen = p[1]) == CILEN_ADDR) && \
	len >= cilen && \
	p[0] == opt) { \
	len -= cilen; \
	INCPTR(2, p); \
	GETLONG(l, p); \
	cidnsaddr = lwip_htonl(l); \
	no.neg = 1; \
	code \
    }


    /*
     * Accept the peer's idea of {our,his} address, if different
     * from our idea, only if the accept_{local,remote} flag is set.
     */
    NAKCIADDRS(CI_ADDRS, !go->neg_addr && go->old_addrs,
	       if (treat_as_reject) {
		   try_.old_addrs = 0;
	       } else {
		   if (go->accept_local && ciaddr1) {
		       /* take his idea of our address */
		       try_.ouraddr = ciaddr1;
		   }
		   if (go->accept_remote && ciaddr2) {
		       /* take his idea of his address */
		       try_.hisaddr = ciaddr2;
		   }
	       }
	);

    /*
     * Accept the peer's value of maxslotindex provided that it
     * is less than what we asked for.  Turn off slot-ID compression
     * if the peer wants.  Send old-style compress-type option if
     * the peer wants.
     */
    NAKCIVJ(CI_COMPRESSTYPE, neg_vj,
	    if (treat_as_reject) {
		try_.neg_vj = 0;
	    } else if (cilen == CILEN_VJ) {
		GETCHAR(cimaxslotindex, p);
		GETCHAR(cicflag, p);
		if (cishort == IPCP_VJ_COMP) {
		    try_.old_vj = 0;
		    if (cimaxslotindex < go->maxslotindex)
			try_.maxslotindex = cimaxslotindex;
		    if (!cicflag)
			try_.cflag = 0;
		} else {
		    try_.neg_vj = 0;
		}
	    } else {
		if (cishort == IPCP_VJ_COMP || cishort == IPCP_VJ_COMP_OLD) {
		    try_.old_vj = 1;
		    try_.vj_protocol = cishort;
		} else {
		    try_.neg_vj = 0;
		}
	    }
	    );


    NAKCIADDR(CI_ADDR, neg_addr,
	      if (treat_as_reject) {
		  try_.neg_addr = 0;
		  try_.old_addrs = 0;
	      } else if (go->accept_local && ciaddr1) {
		  /* take his idea of our address */
		  try_.ouraddr = ciaddr1;
	      }
	      );

    NAKCIDNS(CI_MS_DNS1, req_dns1,
	     if (treat_as_reject) {
		 try_.req_dns1 = 0;
	     } else {
		 try_.dnsaddr[0] = cidnsaddr;
	     }
	     );

    NAKCIDNS(CI_MS_DNS2, req_dns2,
	     if (treat_as_reject) {
		 try_.req_dns2 = 0;
	     } else {
		 try_.dnsaddr[1] = cidnsaddr;
	     }
	     );


    /*
     * There may be remaining CIs, if the peer is requesting negotiation
     * on an option that we didn't include in our request packet.
     * If they want to negotiate about IP addresses, we comply.
     * If they want us to ask for compression, we refuse.
     * If they want us to ask for ms-dns, we do that, since some
     * peers get huffy if we don't.
     */
    while (len >= CILEN_VOID) {
	GETCHAR(citype, p);
	GETCHAR(cilen, p);
	if ( cilen < CILEN_VOID || (len -= cilen) < 0 )
	    goto bad;
	next = p + cilen - 2;

	switch (citype) {

	case CI_COMPRESSTYPE:
	    if (go->neg_vj || no.neg_vj ||
		(cilen != CILEN_VJ && cilen != CILEN_COMPRESS))
		goto bad;
	    no.neg_vj = 1;
	    break;

	case CI_ADDRS:
	    if ((!go->neg_addr && go->old_addrs) || no.old_addrs
		|| cilen != CILEN_ADDRS)
		goto bad;
	    try_.neg_addr = 0;
	    GETLONG(l, p);
	    ciaddr1 = lwip_htonl(l);
	    if (ciaddr1 && go->accept_local)
		try_.ouraddr = ciaddr1;
	    GETLONG(l, p);
	    ciaddr2 = lwip_htonl(l);
	    if (ciaddr2 && go->accept_remote)
		try_.hisaddr = ciaddr2;
	    no.old_addrs = 1;
	    break;
	case CI_ADDR:
	    if (go->neg_addr || no.neg_addr || cilen != CILEN_ADDR)
		goto bad;
	    try_.old_addrs = 0;
	    GETLONG(l, p);
	    ciaddr1 = lwip_htonl(l);
	    if (ciaddr1 && go->accept_local)
		try_.ouraddr = ciaddr1;
	    if (try_.ouraddr != 0)
		try_.neg_addr = 1;
	    no.neg_addr = 1;
	    break;

	case CI_MS_DNS1:
	    if (go->req_dns1 || no.req_dns1 || cilen != CILEN_ADDR)
		goto bad;
	    GETLONG(l, p);
	    try_.dnsaddr[0] = lwip_htonl(l);
	    try_.req_dns1 = 1;
	    no.req_dns1 = 1;
	    break;
	case CI_MS_DNS2:
	    if (go->req_dns2 || no.req_dns2 || cilen != CILEN_ADDR)
		goto bad;
	    GETLONG(l, p);
	    try_.dnsaddr[1] = lwip_htonl(l);
	    try_.req_dns2 = 1;
	    no.req_dns2 = 1;
	    break;

	default:
	    break;
	}
	p = next;
    }

    /*
     * OK, the Nak is good.  Now we can update state.
     * If there are any remaining options, we ignore them.
     */
    if (f->state != PPP_FSM_OPENED)
	*go = try_;

    return 1;

bad:
    IPCPDEBUG(("ipcp_nakci: received bad Nak!"));
    return 0;
}


/*
 * ipcp_rejci - Reject some of our CIs.
 * Callback from fsm_rconfnakrej.
 */
static int ipcp_rejci(fsm *f, uint8_t *p, int len) {
    PppPcb *pcb = f->pcb;
    ipcp_options *go = &pcb->ipcp_gotoptions;
    uint8_t cilen;
    uint8_t cimaxslotindex, ciflag;
    u_short cishort;
    uint32_t cilong;
    ipcp_options try_;		/* options to request next time */

    try_ = *go;
    /*
     * Any Rejected CIs must be in exactly the same order that we sent.
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */
#define REJCIADDRS(opt, neg, val1, val2) \
    if ((neg) && \
	(cilen = p[1]) == CILEN_ADDRS && \
	len >= cilen && \
	p[0] == opt) { \
	uint32_t l; \
	len -= cilen; \
	INCPTR(2, p); \
	GETLONG(l, p); \
	cilong = lwip_htonl(l); \
	/* Check rejected value. */ \
	if (cilong != val1) \
	    goto bad; \
	GETLONG(l, p); \
	cilong = lwip_htonl(l); \
	/* Check rejected value. */ \
	if (cilong != val2) \
	    goto bad; \
	try_.old_addrs = 0; \
    }

#define REJCIVJ(opt, neg, val, old, maxslot, cflag) \
    if (go->neg && \
	p[1] == (old? CILEN_COMPRESS : CILEN_VJ) && \
	len >= p[1] && \
	p[0] == opt) { \
	len -= p[1]; \
	INCPTR(2, p); \
	GETSHORT(cishort, p); \
	/* Check rejected value. */  \
	if (cishort != val) \
	    goto bad; \
	if (!old) { \
	   GETCHAR(cimaxslotindex, p); \
	   if (cimaxslotindex != maxslot) \
	     goto bad; \
	   GETCHAR(ciflag, p); \
	   if (ciflag != cflag) \
	     goto bad; \
        } \
	try_.neg = 0; \
     }


#define REJCIADDR(opt, neg, val) \
    if (go->neg && \
	(cilen = p[1]) == CILEN_ADDR && \
	len >= cilen && \
	p[0] == opt) { \
	uint32_t l; \
	len -= cilen; \
	INCPTR(2, p); \
	GETLONG(l, p); \
	cilong = lwip_htonl(l); \
	/* Check rejected value. */ \
	if (cilong != val) \
	    goto bad; \
	try_.neg = 0; \
    }

#define REJCIDNS(opt, neg, dnsaddr) \
    if (go->neg && \
	((cilen = p[1]) == CILEN_ADDR) && \
	len >= cilen && \
	p[0] == opt) { \
	uint32_t l; \
	len -= cilen; \
	INCPTR(2, p); \
	GETLONG(l, p); \
	cilong = lwip_htonl(l); \
	/* Check rejected value. */ \
	if (cilong != dnsaddr) \
	    goto bad; \
	try_.neg = 0; \
    }



    REJCIADDRS(CI_ADDRS, !go->neg_addr && go->old_addrs,
	       go->ouraddr, go->hisaddr);


    REJCIVJ(CI_COMPRESSTYPE, neg_vj, go->vj_protocol, go->old_vj,
	    go->maxslotindex, go->cflag);


    REJCIADDR(CI_ADDR, neg_addr, go->ouraddr);


    REJCIDNS(CI_MS_DNS1, req_dns1, go->dnsaddr[0]);

    REJCIDNS(CI_MS_DNS2, req_dns2, go->dnsaddr[1]);




    /*
     * If there are any remaining CIs, then this packet is bad.
     */
    if (len != 0)
	goto bad;
    /*
     * Now we can update state.
     */
    if (f->state != PPP_FSM_OPENED)
	*go = try_;
    return 1;

bad:
    IPCPDEBUG(("ipcp_rejci: received bad Reject!"));
    return 0;
}


/*
 * ipcp_reqci - Check the peer's requested CIs and send appropriate response.
 * Callback from fsm_rconfreq, Receive Configure Request
 *
 * Returns: CONFACK, CONFNAK or CONFREJ and input packet modified
 * appropriately.  If reject_if_disagree is non-zero, doesn't return
 * CONFNAK; returns CONFREJ if it can't return CONFACK.
 *
 * inp = Requested CIs
 * len = Length of requested CIs
 */
static int ipcp_reqci(fsm *f, uint8_t *inp, int *len, int reject_if_disagree) {
    PppPcb *pcb = f->pcb;
    ipcp_options *wo = &pcb->ipcp_wantoptions;
    ipcp_options *ho = &pcb->ipcp_hisoptions;
    ipcp_options *ao = &pcb->ipcp_allowoptions;
    uint8_t *cip, *next;		/* Pointer to current and next CIs */
    u_short cilen, citype;	/* Parsed len, type */

    u_short cishort;		/* Parsed short value */

    uint32_t tl, ciaddr1, ciaddr2;/* Parsed address values */
    int rc = CONFACK;		/* Final packet return code */
    int orc;			/* Individual option return code */
    uint8_t *p;			/* Pointer to next char to parse */
    uint8_t *ucp = inp;		/* Pointer to current output char */
    int l = *len;		/* Length left */

    uint8_t maxslotindex, cflag;


    int d;


    /*
     * Reset all his options.
     */
    BZERO(ho, sizeof(*ho));
    
    /*
     * Process all his options.
     */
    next = inp;
    while (l) {
	orc = CONFACK;			/* Assume success */
	cip = p = next;			/* Remember begining of CI */
	if (l < 2 ||			/* Not enough data for CI header or */
	    p[1] < 2 ||			/*  CI length too small or */
	    p[1] > l) {			/*  CI length too big? */
	    IPCPDEBUG(("ipcp_reqci: bad CI length!"));
	    orc = CONFREJ;		/* Reject bad CI */
	    cilen = l;			/* Reject till end of packet */
	    l = 0;			/* Don't loop again */
	    goto endswitch;
	}
	GETCHAR(citype, p);		/* Parse CI type */
	GETCHAR(cilen, p);		/* Parse CI length */
	l -= cilen;			/* Adjust remaining length */
	next += cilen;			/* Step to next CI */

	switch (citype) {		/* Check CI type */
	case CI_ADDRS:
	    if (!ao->old_addrs || ho->neg_addr ||
		cilen != CILEN_ADDRS) {	/* Check CI length */
		orc = CONFREJ;		/* Reject CI */
		break;
	    }

	    /*
	     * If he has no address, or if we both have his address but
	     * disagree about it, then NAK it with our idea.
	     * In particular, if we don't know his address, but he does,
	     * then accept it.
	     */
	    GETLONG(tl, p);		/* Parse source address (his) */
	    ciaddr1 = lwip_htonl(tl);
	    if (ciaddr1 != wo->hisaddr
		&& (ciaddr1 == 0 || !wo->accept_remote)) {
		orc = CONFNAK;
		if (!reject_if_disagree) {
		    DECPTR(sizeof(uint32_t), p);
		    tl = lwip_ntohl(wo->hisaddr);
		    PUTLONG(tl, p);
		}
	    } else if (ciaddr1 == 0 && wo->hisaddr == 0) {
		/*
		 * If neither we nor he knows his address, reject the option.
		 */
		orc = CONFREJ;
		wo->req_addr = 0;	/* don't NAK with 0.0.0.0 later */
		break;
	    }

	    /*
	     * If he doesn't know our address, or if we both have our address
	     * but disagree about it, then NAK it with our idea.
	     */
	    GETLONG(tl, p);		/* Parse desination address (ours) */
	    ciaddr2 = lwip_htonl(tl);
	    if (ciaddr2 != wo->ouraddr) {
		if (ciaddr2 == 0 || !wo->accept_local) {
		    orc = CONFNAK;
		    if (!reject_if_disagree) {
			DECPTR(sizeof(uint32_t), p);
			tl = lwip_ntohl(wo->ouraddr);
			PUTLONG(tl, p);
		    }
		} else {
		    wo->ouraddr = ciaddr2;	/* accept peer's idea */
		}
	    }

	    ho->old_addrs = 1;
	    ho->hisaddr = ciaddr1;
	    ho->ouraddr = ciaddr2;
	    break;

	case CI_ADDR:
	    if (!ao->neg_addr || ho->old_addrs ||
		cilen != CILEN_ADDR) {	/* Check CI length */
		orc = CONFREJ;		/* Reject CI */
		break;
	    }

	    /*
	     * If he has no address, or if we both have his address but
	     * disagree about it, then NAK it with our idea.
	     * In particular, if we don't know his address, but he does,
	     * then accept it.
	     */
	    GETLONG(tl, p);	/* Parse source address (his) */
	    ciaddr1 = lwip_htonl(tl);
	    if (ciaddr1 != wo->hisaddr
		&& (ciaddr1 == 0 || !wo->accept_remote)) {
		orc = CONFNAK;
		if (!reject_if_disagree) {
		    DECPTR(sizeof(uint32_t), p);
		    tl = lwip_ntohl(wo->hisaddr);
		    PUTLONG(tl, p);
		}
	    } else if (ciaddr1 == 0 && wo->hisaddr == 0) {
		/*
		 * Don't ACK an address of 0.0.0.0 - reject it instead.
		 */
		orc = CONFREJ;
		wo->req_addr = 0;	/* don't NAK with 0.0.0.0 later */
		break;
	    }
	
	    ho->neg_addr = 1;
	    ho->hisaddr = ciaddr1;
	    break;


	case CI_MS_DNS1:
	case CI_MS_DNS2:
	    /* Microsoft primary or secondary DNS request */
	    d = citype == CI_MS_DNS2;

	    /* If we do not have a DNS address then we cannot send it */
	    if (ao->dnsaddr[d] == 0 ||
		cilen != CILEN_ADDR) {	/* Check CI length */
		orc = CONFREJ;		/* Reject CI */
		break;
	    }
	    GETLONG(tl, p);
	    if (lwip_htonl(tl) != ao->dnsaddr[d]) {
                DECPTR(sizeof(uint32_t), p);
		tl = lwip_ntohl(ao->dnsaddr[d]);
		PUTLONG(tl, p);
		orc = CONFNAK;
            }
            break;


	case CI_COMPRESSTYPE:
	    if (!ao->neg_vj ||
		(cilen != CILEN_VJ && cilen != CILEN_COMPRESS)) {
		orc = CONFREJ;
		break;
	    }
	    GETSHORT(cishort, p);

	    if (!(cishort == IPCP_VJ_COMP ||
		  (cishort == IPCP_VJ_COMP_OLD && cilen == CILEN_COMPRESS))) {
		orc = CONFREJ;
		break;
	    }

	    ho->neg_vj = 1;
	    ho->vj_protocol = cishort;
	    if (cilen == CILEN_VJ) {
		GETCHAR(maxslotindex, p);
		if (maxslotindex > ao->maxslotindex) { 
		    orc = CONFNAK;
		    if (!reject_if_disagree){
			DECPTR(1, p);
			PUTCHAR(ao->maxslotindex, p);
		    }
		}
		GETCHAR(cflag, p);
		if (cflag && !ao->cflag) {
		    orc = CONFNAK;
		    if (!reject_if_disagree){
			DECPTR(1, p);
			PUTCHAR(wo->cflag, p);
		    }
		}
		ho->maxslotindex = maxslotindex;
		ho->cflag = cflag;
	    } else {
		ho->old_vj = 1;
		ho->maxslotindex = MAX_STATES - 1;
		ho->cflag = 1;
	    }
	    break;


	default:
	    orc = CONFREJ;
	    break;
	}
endswitch:
	if (orc == CONFACK &&		/* Good CI */
	    rc != CONFACK)		/*  but prior CI wasnt? */
	    continue;			/* Don't send this one */

	if (orc == CONFNAK) {		/* Nak this CI? */
	    if (reject_if_disagree)	/* Getting fed up with sending NAKs? */
		orc = CONFREJ;		/* Get tough if so */
	    else {
		if (rc == CONFREJ)	/* Rejecting prior CI? */
		    continue;		/* Don't send this one */
		if (rc == CONFACK) {	/* Ack'd all prior CIs? */
		    rc = CONFNAK;	/* Not anymore... */
		    ucp = inp;		/* Backup */
		}
	    }
	}

	if (orc == CONFREJ &&		/* Reject this CI */
	    rc != CONFREJ) {		/*  but no prior ones? */
	    rc = CONFREJ;
	    ucp = inp;			/* Backup */
	}

	/* Need to move CI? */
	if (ucp != cip)
	    MEMCPY(ucp, cip, cilen);	/* Move it */

	/* Update output pointer */
	INCPTR(cilen, ucp);
    }

    /*
     * If we aren't rejecting this packet, and we want to negotiate
     * their address, and they didn't send their address, then we
     * send a NAK with a CI_ADDR option appended.  We assume the
     * input buffer is long enough that we can append the extra
     * option safely.
     */
    if (rc != CONFREJ && !ho->neg_addr && !ho->old_addrs &&
	wo->req_addr && !reject_if_disagree && !pcb->settings.noremoteip) {
	if (rc == CONFACK) {
	    rc = CONFNAK;
	    ucp = inp;			/* reset pointer */
	    wo->req_addr = 0;		/* don't ask again */
	}
	PUTCHAR(CI_ADDR, ucp);
	PUTCHAR(CILEN_ADDR, ucp);
	tl = lwip_ntohl(wo->hisaddr);
	PUTLONG(tl, ucp);
    }

    *len = ucp - inp;			/* Compute output length */
    IPCPDEBUG(("ipcp: returning Configure-%s", CODENAME(rc)));
    return (rc);			/* Return final code */
}



/*
 * ip_demand_conf - configure the interface as though
 * IPCP were up, for use with dial-on-demand.
 */
static int
ip_demand_conf(u)
    int u;
{
    PppPcb *pcb = &PppPcb_list[u];
    ipcp_options *wo = &ipcp_wantoptions[u];

    if (wo->hisaddr == 0 && !pcb->settings.noremoteip) {
	/* make up an arbitrary address for the peer */
	wo->hisaddr = lwip_htonl(0x0a707070 + ifunit);
	wo->accept_remote = 1;
    }
    if (wo->ouraddr == 0) {
	/* make up an arbitrary address for us */
	wo->ouraddr = lwip_htonl(0x0a404040 + ifunit);
	wo->accept_local = 1;
	ask_for_local = 0;	/* don't tell the peer this address */
    }
    if (!sifaddr(pcb, wo->ouraddr, wo->hisaddr, get_mask(wo->ouraddr)))
	return 0;
    if (!sifup(pcb))
	return 0;
    if (!sifnpmode(pcb, PPP_IP, NPMODE_QUEUE))
	return 0;
#if 0 /* UNUSED */
    if (wo->default_route)
	if (sifdefaultroute(pcb, wo->ouraddr, wo->hisaddr,
		wo->replace_default_route))
	    default_route_set[u] = 1;
#endif /* UNUSED */
#if 0 /* UNUSED - PROXY ARP */
    if (wo->proxy_arp)
	if (sifproxyarp(pcb, wo->hisaddr))
	    proxy_arp_set[u] = 1;
#endif /* UNUSED - PROXY ARP */

    ppp_notice("local  IP address %I", wo->ouraddr);
    if (wo->hisaddr)
	ppp_notice("remote IP address %I", wo->hisaddr);

    return 1;
}


/*
 * ipcp_up - IPCP has come UP.
 *
 * Configure the IP network interface appropriately and bring it up.
 */
static void ipcp_up(fsm *f) {
    PppPcb *pcb = f->pcb;
    uint32_t mask;
    ipcp_options *ho = &pcb->ipcp_hisoptions;
    ipcp_options *go = &pcb->ipcp_gotoptions;
    ipcp_options *wo = &pcb->ipcp_wantoptions;

    IPCPDEBUG(("ipcp: up"));

    /*
     * We must have a non-zero IP address for both ends of the link.
     */
    if (!ho->neg_addr && !ho->old_addrs)
	ho->hisaddr = wo->hisaddr;

    if (!(go->neg_addr || go->old_addrs) && (wo->neg_addr || wo->old_addrs)
	&& wo->ouraddr != 0) {
	ppp_error("Peer refused to agree to our IP address");
	ipcp_close(f->pcb, "Refused our IP address");
	return;
    }
    if (go->ouraddr == 0) {
	ppp_error("Could not determine local IP address");
	ipcp_close(f->pcb, "Could not determine local IP address");
	return;
    }
    if (ho->hisaddr == 0 && !pcb->settings.noremoteip) {
	ho->hisaddr = lwip_htonl(0x0a404040);
	ppp_warn("Could not determine remote IP address: defaulting to %I",
	     ho->hisaddr);
    }

    if (!go->req_dns1)
	    go->dnsaddr[0] = 0;
    if (!go->req_dns2)
	    go->dnsaddr[1] = 0;

    if (pcb->settings.usepeerdns && (go->dnsaddr[0] || go->dnsaddr[1])) {
	sdns(pcb, go->dnsaddr[0], go->dnsaddr[1]);

    }


    /*
     * Check that the peer is allowed to use the IP address it wants.
     */
    if (ho->hisaddr != 0) {
	uint32_t addr = lwip_ntohl(ho->hisaddr);
	if ((addr >> IP_CLASSA_NSHIFT) == IP_LOOPBACKNET
	    || IP_MULTICAST(addr) || IP_BADCLASS(addr)
	    /*
	     * For now, consider that PPP in server mode with peer required
	     * to authenticate must provide the peer IP address, reject any
	     * IP address wanted by peer different than the one we wanted.
	     */

	    || (pcb->settings.auth_required && wo->hisaddr != ho->hisaddr)

	    ) {
		ppp_error("Peer is not authorized to use remote address %I", ho->hisaddr);
		ipcp_close(pcb, "Unauthorized remote IP address");
		return;
	}
    }



    /* set tcp compression */
    sifvjcomp(pcb, ho->neg_vj, ho->cflag, ho->maxslotindex);

    /*
     * If we are doing dial-on-demand, the interface is already
     * configured, so we put out any saved-up packets, then set the
     * interface to pass IP packets.
     */
    if (demand) {
	if (go->ouraddr != wo->ouraddr || ho->hisaddr != wo->hisaddr) {
	    ipcp_clear_addrs(f->unit, wo->ouraddr, wo->hisaddr,
				      wo->replace_default_route);
	    if (go->ouraddr != wo->ouraddr) {
		ppp_warn("Local IP address changed to %I", go->ouraddr);
		script_setenv("OLDIPLOCAL", ip_ntoa(wo->ouraddr), 0);
		wo->ouraddr = go->ouraddr;
	    } else
		script_unsetenv("OLDIPLOCAL");
	    if (ho->hisaddr != wo->hisaddr && wo->hisaddr != 0) {
		ppp_warn("Remote IP address changed to %I", ho->hisaddr);
		script_setenv("OLDIPREMOTE", ip_ntoa(wo->hisaddr), 0);
		wo->hisaddr = ho->hisaddr;
	    } else
		script_unsetenv("OLDIPREMOTE");

	    /* Set the interface to the new addresses */
	    mask = get_mask(go->ouraddr);
	    if (!sifaddr(pcb, go->ouraddr, ho->hisaddr, mask)) {

		ipcp_close(f->unit, "Interface configuration failed");
		return;
	    }

	    /* assign a default route through the interface if required */
	    if (ipcp_wantoptions[f->unit].default_route) 
		if (sifdefaultroute(pcb, go->ouraddr, ho->hisaddr,
			wo->replace_default_route))
		    default_route_set[f->unit] = 1;



	}
	demand_rexmit(PPP_IP,go->ouraddr);
	sifnpmode(pcb, PPP_IP, NPMODE_PASS);

    } else

    {
	/*
	 * Set IP addresses and (if specified) netmask.
	 */
	mask = get_mask(go->ouraddr);


	if (!sifaddr(pcb, go->ouraddr, ho->hisaddr, mask)) {

	    ipcp_close(f->pcb, "Interface configuration failed");
	    return;
	}


	/* bring the interface up for IP */
	if (!sifup(pcb)) {

	    ipcp_close(f->pcb, "Interface configuration failed");
	    return;
	}


	if (!sifaddr(pcb, go->ouraddr, ho->hisaddr, mask)) {

	    ipcp_close(f->unit, "Interface configuration failed");
	    return;
	}


	sifnpmode(pcb, PPP_IP, NPMODE_PASS);






	wo->ouraddr = go->ouraddr;

	ppp_notice("local  IP address %I", go->ouraddr);
	if (ho->hisaddr != 0)
	    ppp_notice("remote IP address %I", ho->hisaddr);

	if (go->dnsaddr[0])
	    ppp_notice("primary   DNS address %I", go->dnsaddr[0]);
	if (go->dnsaddr[1])
	    ppp_notice("secondary DNS address %I", go->dnsaddr[1]);

    }



    np_up(pcb, PPP_IP);
    pcb->ipcp_is_up = 1;


    notify(ip_up_notifier, 0);

}


/*
 * ipcp_down - IPCP has gone DOWN.
 *
 * Take the IP network interface down, clear its addresses
 * and delete routes through it.
 */
static void ipcp_down(fsm *f) {
    PppPcb *pcb = f->pcb;
    ipcp_options *ho = &pcb->ipcp_hisoptions;
    ipcp_options *go = &pcb->ipcp_gotoptions;

    IPCPDEBUG(("ipcp: down"));

    notify(ip_down_notifier, 0);


    if (pcb->ipcp_is_up) {
	pcb->ipcp_is_up = 0;
	np_down(pcb, PPP_IP);
    }

    sifvjcomp(pcb, 0, 0, 0);

    /*
     * If we are doing dial-on-demand, set the interface
     * to queue up outgoing packets (for now).
     */
    if (demand) {
	sifnpmode(pcb, PPP_IP, NPMODE_QUEUE);
    } else

    {

	sifnpmode(pcb, PPP_IP, NPMODE_DROP);

	sifdown(pcb);
	ipcp_clear_addrs(pcb, go->ouraddr,
			 ho->hisaddr, 0);

	cdns(pcb, go->dnsaddr[0], go->dnsaddr[1]);

    }
}


/*
 * ipcp_clear_addrs() - clear the interface addresses, routes,
 * proxy arp entries, etc.
 */
static void ipcp_clear_addrs(PppPcb *pcb, uint32_t ouraddr, uint32_t hisaddr, uint8_t replacedefaultroute) {
    ;



    cifaddr(pcb, ouraddr, hisaddr);
}


/*
 * ipcp_finished - possibly shut down the lower layers.
 */
static void ipcp_finished(fsm *f) {
	PppPcb *pcb = f->pcb;
	if (pcb->ipcp_is_open) {
		pcb->ipcp_is_open = 0;
		np_finished(pcb, PPP_IP);
	}
}





/*
 * ip_active_pkt - see if this IP packet is worth bringing the link up for.
 * We don't bring the link up for IP fragments or for TCP FIN packets
 * with no data.
 */
#define IP_HDRLEN	20	/* bytes */
#define IP_OFFMASK	0x1fff
#ifndef IPPROTO_TCP
#define IPPROTO_TCP	6
#endif
#define TCP_HDRLEN	20
#define TH_FIN		0x01

/*
 * We use these macros because the IP header may be at an odd address,
 * and some compilers might use word loads to get th_off or ip_hl.
 */

#define net_short(x)	(((x)[0] << 8) + (x)[1])
#define get_iphl(x)	(((unsigned char *)(x))[0] & 0xF)
#define get_ipoff(x)	net_short((unsigned char *)(x) + 6)
#define get_ipproto(x)	(((unsigned char *)(x))[9])
#define get_tcpoff(x)	(((unsigned char *)(x))[12] >> 4)
#define get_tcpflags(x)	(((unsigned char *)(x))[13])

static int
ip_active_pkt(pkt, len)
    uint8_t *pkt;
    int len;
{
    uint8_t *tcp;
    int hlen;

    len -= PPP_HDRLEN;
    pkt += PPP_HDRLEN;
    if (len < IP_HDRLEN)
	return 0;
    if ((get_ipoff(pkt) & IP_OFFMASK) != 0)
	return 0;
    if (get_ipproto(pkt) != IPPROTO_TCP)
	return 1;
    hlen = get_iphl(pkt) * 4;
    if (len < hlen + TCP_HDRLEN)
	return 0;
    tcp = pkt + hlen;
    if ((get_tcpflags(tcp) & TH_FIN) != 0 && len == hlen + get_tcpoff(tcp) * 4)
	return 0;
    return 1;
}

