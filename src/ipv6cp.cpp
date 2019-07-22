/*
 * ipv6cp.c - PPP IPV6 Control Protocol.
 *
 * Copyright (c) 1999 Tommi Komulainen.  All rights reserved.
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
 * 3. The name(s) of the authors of this software must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Tommi Komulainen
 *     <Tommi.Komulainen@iki.fi>".
 *
 * THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

/*  Original version, based on RFC2023 :

    Copyright (c) 1995, 1996, 1997 Francis.Dupont@inria.fr, INRIA Rocquencourt,
    Alain.Durand@imag.fr, IMAG,
    Jean-Luc.Richier@imag.fr, IMAG-LSR.

    Copyright (c) 1998, 1999 Francis.Dupont@inria.fr, GIE DYADE,
    Alain.Durand@imag.fr, IMAG,
    Jean-Luc.Richier@imag.fr, IMAG-LSR.

    Ce travail a été fait au sein du GIE DYADE (Groupement d'Intérêt
    Économique ayant pour membres BULL S.A. et l'INRIA).

    Ce logiciel informatique est disponible aux conditions
    usuelles dans la recherche, c'est-à-dire qu'il peut
    être utilisé, copié, modifié, distribué à l'unique
    condition que ce texte soit conservé afin que
    l'origine de ce logiciel soit reconnue.

    Le nom de l'Institut National de Recherche en Informatique
    et en Automatique (INRIA), de l'IMAG, ou d'une personne morale
    ou physique ayant participé à l'élaboration de ce logiciel ne peut
    être utilisé sans son accord préalable explicite.

    Ce logiciel est fourni tel quel sans aucune garantie,
    support ou responsabilité d'aucune sorte.
    Ce logiciel est dérivé de sources d'origine
    "University of California at Berkeley" et
    "Digital Equipment Corporation" couvertes par des copyrights.

    L'Institut d'Informatique et de Mathématiques Appliquées de Grenoble (IMAG)
    est une fédération d'unités mixtes de recherche du CNRS, de l'Institut National
    Polytechnique de Grenoble et de l'Université Joseph Fourier regroupant
    sept laboratoires dont le laboratoire Logiciels, Systèmes, Réseaux (LSR).

    This work has been done in the context of GIE DYADE (joint R & D venture
    between BULL S.A. and INRIA).

    This software is available with usual "research" terms
    with the aim of retain credits of the software. 
    Permission to use, copy, modify and distribute this software for any
    purpose and without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies,
    and the name of INRIA, IMAG, or any contributor not be used in advertising
    or publicity pertaining to this material without the prior explicit
    permission. The software is provided "as is" without any
    warranties, support or liabilities of any kind.
    This software is derived from source code from
    "University of California at Berkeley" and
    "Digital Equipment Corporation" protected by copyrights.

    Grenoble's Institute of Computer Science and Applied Mathematics (IMAG)
    is a federation of seven research units funded by the CNRS, National
    Polytechnic Institute of Grenoble and University Joseph Fourier.
    The research unit in Software, Systems, Networks (LSR) is member of IMAG.
*/

/*
 * Derived from :
 *
 *
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
 *
 * $Id: ipv6cp.c,v 1.21 2005/08/25 23:59:34 paulus Exp $ 
 */

/*
 * @todo: 
 *
 * Proxy Neighbour Discovery.
 *
 * Better defines for selecting the ordering of
 *   interface up / set address.
 */

#include <ppp_opts.h>
#include <ppp_impl.h>
#include <fsm.h>
#include <ipcp.h>
#include <ipv6cp.h>
#include <magic.h>

/* global vars */


/*
 * Callbacks for fsm code.  (CI = Configuration Information)
 */
static void ipv6cp_resetci(fsm *f); /* Reset our CI */
static int  ipv6cp_cilen(fsm *f); /* Return length of our CI */
static void ipv6cp_addci(fsm *f, uint8_t *ucp, int *lenp); /* Add our CI */
static int  ipv6cp_ackci(fsm *f, uint8_t *p, int len); /* Peer ack'd our CI */
static int  ipv6cp_nakci(fsm *f, uint8_t *p, int len, int treat_as_reject); /* Peer nak'd our CI */
static int  ipv6cp_rejci(fsm *f, uint8_t *p, int len); /* Peer rej'd our CI */
static int  ipv6cp_reqci(fsm *f, uint8_t *inp, int *len, int reject_if_disagree); /* Rcv CI */
static void ipv6cp_up(fsm *f); /* We're UP */
static void ipv6cp_down(fsm *f); /* We're DOWN */
static void ipv6cp_finished(fsm *f); /* Don't need lower layer */

static const FsmCallbacks ipv6cp_callbacks = { /* IPV6CP callback routines */
    ipv6cp_resetci,		/* Reset our Configuration Information */
    ipv6cp_cilen,		/* Length of our Configuration Information */
    ipv6cp_addci,		/* Add our Configuration Information */
    ipv6cp_ackci,		/* ACK our Configuration Information */
    ipv6cp_nakci,		/* NAK our Configuration Information */
    ipv6cp_rejci,		/* Reject our Configuration Information */
    ipv6cp_reqci,		/* Request peer's Configuration Information */
    ipv6cp_up,			/* Called when fsm reaches OPENED state */
    ipv6cp_down,		/* Called when fsm leaves OPENED state */
    NULL,			/* Called when we want the lower layer up */
    ipv6cp_finished,		/* Called when we want the lower layer down */
    NULL,			/* Called when Protocol-Reject received */
    NULL,			/* Retransmission is necessary */
    NULL,			/* Called to handle protocol-specific codes */
    "IPV6CP"			/* String name of protocol */
};

/*
 * Protocol entry points from main code.
 */
static void ipv6cp_init(PppPcb *pcb);
static void ipv6cp_open(PppPcb *pcb);
static void ipv6cp_close(PppPcb *pcb, const char *reason);
static void ipv6cp_lowerup(PppPcb *pcb);
static void ipv6cp_lowerdown(PppPcb *pcb);
static void ipv6cp_input(PppPcb *pcb, uint8_t *p, int len);
static void ipv6cp_protrej(PppPcb *pcb);


static int  ipv6_demand_conf(int u);


static int ipv6_active_pkt(uint8_t *pkt, int len);


const struct protent ipv6cp_protent = {
    PPP_IPV6CP,
    ipv6cp_init,
    ipv6cp_input,
    ipv6cp_protrej,
    ipv6cp_lowerup,
    ipv6cp_lowerdown,
    ipv6cp_open,
    ipv6cp_close,

    NULL,




    ipv6_demand_conf,
    ipv6_active_pkt

};

static void ipv6cp_clear_addrs(PppPcb *pcb, eui64_t ourid, eui64_t hisid);


/*
 * Lengths of configuration options.
 */
#define CILEN_VOID	2
#define CILEN_COMPRESS	4	/* length for RFC2023 compress opt. */
#define CILEN_IFACEID   10	/* RFC2472, interface identifier    */

#define CODENAME(x)	((x) == CONFACK ? "ACK" : \
			 (x) == CONFNAK ? "NAK" : "REJ")


static char *llv6_ntoa(eui64_t ifaceid);

/*
 * Make a string representation of a network address.
 */
static char *
llv6_ntoa(eui64_t ifaceid)
{
    static char b[26];

    sprintf(b, "fe80::%02x%02x:%02x%02x:%02x%02x:%02x%02x",
      ifaceid.e8[0], ifaceid.e8[1], ifaceid.e8[2], ifaceid.e8[3],
      ifaceid.e8[4], ifaceid.e8[5], ifaceid.e8[6], ifaceid.e8[7]);

    return b;
}


/*
 * ipv6cp_init - Initialize IPV6CP.
 */
static void ipv6cp_init(PppPcb *pcb) {
    fsm *f = &pcb->ipv6cp_fsm;
    ipv6cp_options *wo = &pcb->ipv6cp_wantoptions;
    ipv6cp_options *ao = &pcb->ipv6cp_allowoptions;

    f->pcb = pcb;
    f->protocol = PPP_IPV6CP;
    f->callbacks = &ipv6cp_callbacks;
    fsm_init(f);


    wo->accept_local = 1;
    wo->neg_ifaceid = 1;
    ao->neg_ifaceid = 1;

    wo->neg_vj = 1;
    ao->neg_vj = 1;
    wo->vj_protocol = IPV6CP_COMP;


}


/*
 * ipv6cp_open - IPV6CP is allowed to come up.
 */
static void ipv6cp_open(PppPcb *pcb) {
    fsm_open(&pcb->ipv6cp_fsm);
}


/*
 * ipv6cp_close - Take IPV6CP down.
 */
static void ipv6cp_close(PppPcb *pcb, const char *reason) {
    fsm_close(&pcb->ipv6cp_fsm, reason);
}


/*
 * ipv6cp_lowerup - The lower layer is up.
 */
static void ipv6cp_lowerup(PppPcb *pcb) {
    fsm_lowerup(&pcb->ipv6cp_fsm);
}


/*
 * ipv6cp_lowerdown - The lower layer is down.
 */
static void ipv6cp_lowerdown(PppPcb *pcb) {
    fsm_lowerdown(&pcb->ipv6cp_fsm);
}


/*
 * ipv6cp_input - Input IPV6CP packet.
 */
static void ipv6cp_input(PppPcb *pcb, uint8_t *p, int len) {
    fsm_input(&pcb->ipv6cp_fsm, p, len);
}


/*
 * ipv6cp_protrej - A Protocol-Reject was received for IPV6CP.
 *
 * Pretend the lower layer went down, so we shut up.
 */
static void ipv6cp_protrej(PppPcb *pcb) {
    fsm_lowerdown(&pcb->ipv6cp_fsm);
}


/*
 * ipv6cp_resetci - Reset our CI.
 */
static void ipv6cp_resetci(fsm *f) {
    PppPcb *pcb = f->pcb;
    ipv6cp_options *wo = &pcb->ipv6cp_wantoptions;
    ipv6cp_options *go = &pcb->ipv6cp_gotoptions;
    ipv6cp_options *ao = &pcb->ipv6cp_allowoptions;

    wo->req_ifaceid = wo->neg_ifaceid && ao->neg_ifaceid;
    
    if (!wo->opt_local) {
	eui64_magic_nz(wo->ourid);
    }
    
    *go = *wo;
    eui64_zero(go->hisid);	/* last proposed interface identifier */
}


/*
 * ipv6cp_cilen - Return length of our CI.
 */
static int ipv6cp_cilen(fsm *f) {
    PppPcb *pcb = f->pcb;
    ipv6cp_options *go = &pcb->ipv6cp_gotoptions;


#define LENCIVJ(neg)		(neg ? CILEN_COMPRESS : 0)

#define LENCIIFACEID(neg)	(neg ? CILEN_IFACEID : 0)

    return (LENCIIFACEID(go->neg_ifaceid) +

	    LENCIVJ(go->neg_vj) +

	    0);
}


/*
 * ipv6cp_addci - Add our desired CIs to a packet.
 */
static void ipv6cp_addci(fsm *f, uint8_t *ucp, int *lenp) {
    PppPcb *pcb = f->pcb;
    ipv6cp_options *go = &pcb->ipv6cp_gotoptions;
    int len = *lenp;


#define ADDCIVJ(opt, neg, val) \
    if (neg) { \
	int vjlen = CILEN_COMPRESS; \
	if (len >= vjlen) { \
	    PUTCHAR(opt, ucp); \
	    PUTCHAR(vjlen, ucp); \
	    PUTSHORT(val, ucp); \
	    len -= vjlen; \
	} else \
	    neg = 0; \
    }


#define ADDCIIFACEID(opt, neg, val1) \
    if (neg) { \
	int idlen = CILEN_IFACEID; \
	if (len >= idlen) { \
	    PUTCHAR(opt, ucp); \
	    PUTCHAR(idlen, ucp); \
	    eui64_put(val1, ucp); \
	    len -= idlen; \
	} else \
	    neg = 0; \
    }

    ADDCIIFACEID(CI_IFACEID, go->neg_ifaceid, go->ourid);


    ADDCIVJ(CI_COMPRESSTYPE, go->neg_vj, go->vj_protocol);


    *lenp -= len;
}


/*
 * ipv6cp_ackci - Ack our CIs.
 *
 * Returns:
 *	0 - Ack was bad.
 *	1 - Ack was good.
 */
static int ipv6cp_ackci(fsm *f, uint8_t *p, int len) {
    PppPcb *pcb = f->pcb;
    ipv6cp_options *go = &pcb->ipv6cp_gotoptions;
    u_short cilen, citype;

    u_short cishort;

    eui64_t ifaceid;

    /*
     * CIs must be in exactly the same order that we sent...
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */


#define ACKCIVJ(opt, neg, val) \
    if (neg) { \
	int vjlen = CILEN_COMPRESS; \
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
    }


#define ACKCIIFACEID(opt, neg, val1) \
    if (neg) { \
	int idlen = CILEN_IFACEID; \
	if ((len -= idlen) < 0) \
	    goto bad; \
	GETCHAR(citype, p); \
	GETCHAR(cilen, p); \
	if (cilen != idlen || \
	    citype != opt) \
	    goto bad; \
	eui64_get(ifaceid, p); \
	if (! eui64_equals(val1, ifaceid)) \
	    goto bad; \
    }

    ACKCIIFACEID(CI_IFACEID, go->neg_ifaceid, go->ourid);


    ACKCIVJ(CI_COMPRESSTYPE, go->neg_vj, go->vj_protocol);


    /*
     * If there are any remaining CIs, then this packet is bad.
     */
    if (len != 0)
	goto bad;
    return (1);

bad:
    IPV6CPDEBUG(("ipv6cp_ackci: received bad Ack!"));
    return (0);
}

/*
 * ipv6cp_nakci - Peer has sent a NAK for some of our CIs.
 * This should not modify any state if the Nak is bad
 * or if IPV6CP is in the OPENED state.
 *
 * Returns:
 *	0 - Nak was bad.
 *	1 - Nak was good.
 */
static int ipv6cp_nakci(fsm *f, uint8_t *p, int len, int treat_as_reject) {
    PppPcb *pcb = f->pcb;
    ipv6cp_options *go = &pcb->ipv6cp_gotoptions;
    uint8_t citype, cilen, *next;

    u_short cishort;

    eui64_t ifaceid;
    ipv6cp_options no;		/* options we've seen Naks for */
    ipv6cp_options try_;	/* options to request next time */

    BZERO(&no, sizeof(no));
    try_ = *go;

    /*
     * Any Nak'd CIs must be in exactly the same order that we sent.
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */
#define NAKCIIFACEID(opt, neg, code) \
    if (go->neg && \
	len >= (cilen = CILEN_IFACEID) && \
	p[1] == cilen && \
	p[0] == opt) { \
	len -= cilen; \
	INCPTR(2, p); \
	eui64_get(ifaceid, p); \
	no.neg = 1; \
	code \
    }


#define NAKCIVJ(opt, neg, code) \
    if (go->neg && \
	((cilen = p[1]) == CILEN_COMPRESS) && \
	len >= cilen && \
	p[0] == opt) { \
	len -= cilen; \
	INCPTR(2, p); \
	GETSHORT(cishort, p); \
	no.neg = 1; \
        code \
    }


    /*
     * Accept the peer's idea of {our,his} interface identifier, if different
     * from our idea, only if the accept_{local,remote} flag is set.
     */
    NAKCIIFACEID(CI_IFACEID, neg_ifaceid,
		 if (treat_as_reject) {
		     try_.neg_ifaceid = 0;
		 } else if (go->accept_local) {
		     while (eui64_iszero(ifaceid) || 
			    eui64_equals(ifaceid, go->hisid)) /* bad luck */
			 eui64_magic(ifaceid);
		     try_.ourid = ifaceid;
		     IPV6CPDEBUG(("local LL address %s", llv6_ntoa(ifaceid)));
		 }
		 );


    NAKCIVJ(CI_COMPRESSTYPE, neg_vj,
	    {
		if (cishort == IPV6CP_COMP && !treat_as_reject) {
		    try_.vj_protocol = cishort;
		} else {
		    try_.neg_vj = 0;
		}
	    }
	    );


    /*
     * There may be remaining CIs, if the peer is requesting negotiation
     * on an option that we didn't include in our request packet.
     * If they want to negotiate about interface identifier, we comply.
     * If they want us to ask for compression, we refuse.
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
		(cilen != CILEN_COMPRESS))
		goto bad;
	    no.neg_vj = 1;
	    break;

	case CI_IFACEID:
	    if (go->neg_ifaceid || no.neg_ifaceid || cilen != CILEN_IFACEID)
		goto bad;
	    try_.neg_ifaceid = 1;
	    eui64_get(ifaceid, p);
	    if (go->accept_local) {
		while (eui64_iszero(ifaceid) || 
		       eui64_equals(ifaceid, go->hisid)) /* bad luck */
		    eui64_magic(ifaceid);
		try_.ourid = ifaceid;
	    }
	    no.neg_ifaceid = 1;
	    break;
	default:
	    break;
	}
	p = next;
    }

    /* If there is still anything left, this packet is bad. */
    if (len != 0)
	goto bad;

    /*
     * OK, the Nak is good.  Now we can update state.
     */
    if (f->state != PPP_FSM_OPENED)
	*go = try_;

    return 1;

bad:
    IPV6CPDEBUG(("ipv6cp_nakci: received bad Nak!"));
    return 0;
}


/*
 * ipv6cp_rejci - Reject some of our CIs.
 */
static int ipv6cp_rejci(fsm *f, uint8_t *p, int len) {
    PppPcb *pcb = f->pcb;
    ipv6cp_options *go = &pcb->ipv6cp_gotoptions;
    uint8_t cilen;

    u_short cishort;

    eui64_t ifaceid;
    ipv6cp_options try_;		/* options to request next time */

    try_ = *go;
    /*
     * Any Rejected CIs must be in exactly the same order that we sent.
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */
#define REJCIIFACEID(opt, neg, val1) \
    if (go->neg && \
	len >= (cilen = CILEN_IFACEID) && \
	p[1] == cilen && \
	p[0] == opt) { \
	len -= cilen; \
	INCPTR(2, p); \
	eui64_get(ifaceid, p); \
	/* Check rejected value. */ \
	if (! eui64_equals(ifaceid, val1)) \
	    goto bad; \
	try_.neg = 0; \
    }

#define REJCIVJ(opt, neg, val) \
    if (go->neg && \
	p[1] == CILEN_COMPRESS && \
	len >= p[1] && \
	p[0] == opt) { \
	len -= p[1]; \
	INCPTR(2, p); \
	GETSHORT(cishort, p); \
	/* Check rejected value. */  \
	if (cishort != val) \
	    goto bad; \
	try_.neg = 0; \
     }


    REJCIIFACEID(CI_IFACEID, neg_ifaceid, go->ourid);

    REJCIVJ(CI_COMPRESSTYPE, neg_vj, go->vj_protocol);


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
    IPV6CPDEBUG(("ipv6cp_rejci: received bad Reject!"));
    return 0;
}


/*
 * ipv6cp_reqci - Check the peer's requested CIs and send appropriate response.
 *
 * Returns: CONFACK, CONFNAK or CONFREJ and input packet modified
 * appropriately.  If reject_if_disagree is non-zero, doesn't return
 * CONFNAK; returns CONFREJ if it can't return CONFACK.
 *
 * inp = Requested CIs
 * len = Length of requested CIs
 *
 */
static int ipv6cp_reqci(fsm *f, uint8_t *inp, int *len, int reject_if_disagree) {
    PppPcb *pcb = f->pcb;
    ipv6cp_options *wo = &pcb->ipv6cp_wantoptions;
    ipv6cp_options *ho = &pcb->ipv6cp_hisoptions;
    ipv6cp_options *ao = &pcb->ipv6cp_allowoptions;
    ipv6cp_options *go = &pcb->ipv6cp_gotoptions;
    uint8_t *cip, *next;		/* Pointer to current and next CIs */
    u_short cilen, citype;	/* Parsed len, type */

    u_short cishort;		/* Parsed short value */

    eui64_t ifaceid;		/* Parsed interface identifier */
    int rc = CONFACK;		/* Final packet return code */
    int orc;			/* Individual option return code */
    uint8_t *p;			/* Pointer to next char to parse */
    uint8_t *ucp = inp;		/* Pointer to current output char */
    int l = *len;		/* Length left */

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
	    IPV6CPDEBUG(("ipv6cp_reqci: bad CI length!"));
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
	case CI_IFACEID:
	    IPV6CPDEBUG(("ipv6cp: received interface identifier "));

	    if (!ao->neg_ifaceid ||
		cilen != CILEN_IFACEID) {	/* Check CI length */
		orc = CONFREJ;		/* Reject CI */
		break;
	    }

	    /*
	     * If he has no interface identifier, or if we both have same 
	     * identifier then NAK it with new idea.
	     * In particular, if we don't know his identifier, but he does,
	     * then accept it.
	     */
	    eui64_get(ifaceid, p);
	    IPV6CPDEBUG(("(%s)", llv6_ntoa(ifaceid)));
	    if (eui64_iszero(ifaceid) && eui64_iszero(go->ourid)) {
		orc = CONFREJ;		/* Reject CI */
		break;
	    }
	    if (!eui64_iszero(wo->hisid) && 
		!eui64_equals(ifaceid, wo->hisid) && 
		eui64_iszero(go->hisid)) {
		    
		orc = CONFNAK;
		ifaceid = wo->hisid;
		go->hisid = ifaceid;
		DECPTR(sizeof(ifaceid), p);
		eui64_put(ifaceid, p);
	    } else
	    if (eui64_iszero(ifaceid) || eui64_equals(ifaceid, go->ourid)) {
		orc = CONFNAK;
		if (eui64_iszero(go->hisid))	/* first time, try option */
		    ifaceid = wo->hisid;
		while (eui64_iszero(ifaceid) || 
		       eui64_equals(ifaceid, go->ourid)) /* bad luck */
		    eui64_magic(ifaceid);
		go->hisid = ifaceid;
		DECPTR(sizeof(ifaceid), p);
		eui64_put(ifaceid, p);
	    }

	    ho->neg_ifaceid = 1;
	    ho->hisid = ifaceid;
	    break;


	case CI_COMPRESSTYPE:
	    IPV6CPDEBUG(("ipv6cp: received COMPRESSTYPE "));
	    if (!ao->neg_vj ||
		(cilen != CILEN_COMPRESS)) {
		orc = CONFREJ;
		break;
	    }
	    GETSHORT(cishort, p);
	    IPV6CPDEBUG(("(%d)", cishort));

	    if (!(cishort == IPV6CP_COMP)) {
		orc = CONFREJ;
		break;
	    }

	    ho->neg_vj = 1;
	    ho->vj_protocol = cishort;
	    break;


	default:
	    orc = CONFREJ;
	    break;
	}

endswitch:
	IPV6CPDEBUG((" (%s)\n", CODENAME(orc)));

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
     * their identifier and they didn't send their identifier, then we
     * send a NAK with a CI_IFACEID option appended.  We assume the
     * input buffer is long enough that we can append the extra
     * option safely.
     */
    if (rc != CONFREJ && !ho->neg_ifaceid &&
	wo->req_ifaceid && !reject_if_disagree) {
	if (rc == CONFACK) {
	    rc = CONFNAK;
	    ucp = inp;				/* reset pointer */
	    wo->req_ifaceid = 0;		/* don't ask again */
	}
	PUTCHAR(CI_IFACEID, ucp);
	PUTCHAR(CILEN_IFACEID, ucp);
	eui64_put(wo->hisid, ucp);
    }

    *len = ucp - inp;			/* Compute output length */
    IPV6CPDEBUG(("ipv6cp: returning Configure-%s", CODENAME(rc)));
    return (rc);			/* Return final code */
}


/*
 * ipv6_demand_conf - configure the interface as though
 * IPV6CP were up, for use with dial-on-demand.
 */
static int ipv6_demand_conf(int u) {
    ipv6cp_options *wo = &ipv6cp_wantoptions[u];

    if (!sif6up(u))
	return 0;

    if (!sif6addr(u, wo->ourid, wo->hisid))
	return 0;

    if (!sifnpmode(u, PPP_IPV6, NPMODE_QUEUE))
	return 0;

    ppp_notice("ipv6_demand_conf");
    ppp_notice("local  LL address %s", llv6_ntoa(wo->ourid));
    ppp_notice("remote LL address %s", llv6_ntoa(wo->hisid));

    return 1;
}


/*
 * ipv6cp_up - IPV6CP has come UP.
 *
 * Configure the IPv6 network interface appropriately and bring it up.
 */
static void ipv6cp_up(fsm *f) {
    PppPcb *pcb = f->pcb;
    ipv6cp_options *wo = &pcb->ipv6cp_wantoptions;
    ipv6cp_options *ho = &pcb->ipv6cp_hisoptions;
    ipv6cp_options *go = &pcb->ipv6cp_gotoptions;

    IPV6CPDEBUG(("ipv6cp: up"));

    /*
     * We must have a non-zero LL address for both ends of the link.
     */
    if (!ho->neg_ifaceid)
	ho->hisid = wo->hisid;


	if (eui64_iszero(ho->hisid)) {
	    ppp_error("Could not determine remote LL address");
	    ipv6cp_close(f->pcb, "Could not determine remote LL address");
	    return;
	}
	if (eui64_iszero(go->ourid)) {
	    ppp_error("Could not determine local LL address");
	    ipv6cp_close(f->pcb, "Could not determine local LL address");
	    return;
	}
	if (eui64_equals(go->ourid, ho->hisid)) {
	    ppp_error("local and remote LL addresses are equal");
	    ipv6cp_close(f->pcb, "local and remote LL addresses are equal");
	    return;
	}

    script_setenv("LLLOCAL", llv6_ntoa(go->ourid), 0);
    script_setenv("LLREMOTE", llv6_ntoa(ho->hisid), 0);



    /* set tcp compression */
    sif6comp(f->unit, ho->neg_vj);



    /*
     * If we are doing dial-on-demand, the interface is already
     * configured, so we put out any saved-up packets, then set the
     * interface to pass IPv6 packets.
     */
    if (demand) {
	if (! eui64_equals(go->ourid, wo->ourid) || 
	    ! eui64_equals(ho->hisid, wo->hisid)) {
	    if (! eui64_equals(go->ourid, wo->ourid))
		warn("Local LL address changed to %s", 
		     llv6_ntoa(go->ourid));
	    if (! eui64_equals(ho->hisid, wo->hisid))
		warn("Remote LL address changed to %s", 
		     llv6_ntoa(ho->hisid));
	    ipv6cp_clear_addrs(f->pcb, go->ourid, ho->hisid);

	    /* Set the interface to the new addresses */
	    if (!sif6addr(f->pcb, go->ourid, ho->hisid)) {
		if (debug)
		    warn("sif6addr failed");
		ipv6cp_close(f->unit, "Interface configuration failed");
		return;
	    }

	}
	demand_rexmit(PPP_IPV6);
	sifnpmode(f->unit, PPP_IPV6, NPMODE_PASS);

    } else

    {
	/*
	 * Set LL addresses
	 */
	if (!sif6addr(f->pcb, go->ourid, ho->hisid)) {
	    PPPDEBUG(LOG_DEBUG, ("sif6addr failed"));
	    ipv6cp_close(f->pcb, "Interface configuration failed");
	    return;
	}

	/* bring the interface up for IPv6 */
	if (!sif6up(f->pcb)) {
	    PPPDEBUG(LOG_DEBUG, ("sif6up failed (IPV6)"));
	    ipv6cp_close(f->pcb, "Interface configuration failed");
	    return;
	}

	sifnpmode(f->pcb, PPP_IPV6, NPMODE_PASS);


	ppp_notice("local  LL address %s", llv6_ntoa(go->ourid));
	ppp_notice("remote LL address %s", llv6_ntoa(ho->hisid));
    }

    np_up(f->pcb, PPP_IPV6);
    pcb->ipv6cp_is_up = 1;

}


/*
 * ipv6cp_down - IPV6CP has gone DOWN.
 *
 * Take the IPv6 network interface down, clear its addresses
 * and delete routes through it.
 */
static void ipv6cp_down(fsm *f) {
    PppPcb *pcb = f->pcb;
    ipv6cp_options *go = &pcb->ipv6cp_gotoptions;
    ipv6cp_options *ho = &pcb->ipv6cp_hisoptions;

    IPV6CPDEBUG(("ipv6cp: down"));
    if (pcb->ipv6cp_is_up) {
	pcb->ipv6cp_is_up = 0;
	np_down(f->pcb, PPP_IPV6);
    }

    sif6comp(f->unit, 0);

    /*
     * If we are doing dial-on-demand, set the interface
     * to queue up outgoing packets (for now).
     */
    if (demand) {
	sifnpmode(f->pcb, PPP_IPV6, NPMODE_QUEUE);
    } else

    {

	sifnpmode(f->pcb, PPP_IPV6, NPMODE_DROP);

	ipv6cp_clear_addrs(f->pcb,
			   go->ourid,
			   ho->hisid);
	sif6down(f->pcb);
    }

}


/*
 * ipv6cp_clear_addrs() - clear the interface addresses, routes,
 * proxy neighbour discovery entries, etc.
 */
static void ipv6cp_clear_addrs(PppPcb *pcb, eui64_t ourid, eui64_t hisid) {
    cif6addr(pcb, ourid, hisid);
}


/*
 * ipv6cp_finished - possibly shut down the lower layers.
 */
static void ipv6cp_finished(fsm *f) {
    np_finished(f->pcb, PPP_IPV6);
}





/*
 * ipv6_active_pkt - see if this IP packet is worth bringing the link up for.
 * We don't bring the link up for IP fragments or for TCP FIN packets
 * with no data.
 */
#define IP6_HDRLEN	40	/* bytes */
#define IP6_NHDR_FRAG	44	/* fragment IPv6 header */
#define TCP_HDRLEN	20
#define TH_FIN		0x01

/*
 * We use these macros because the IP header may be at an odd address,
 * and some compilers might use word loads to get th_off or ip_hl.
 */

#define get_ip6nh(x)	(((unsigned char *)(x))[6])
#define get_tcpoff(x)	(((unsigned char *)(x))[12] >> 4)
#define get_tcpflags(x)	(((unsigned char *)(x))[13])

static int ipv6_active_pkt(uint8_t *pkt, int len) {
    uint8_t *tcp;

    len -= PPP_HDRLEN;
    pkt += PPP_HDRLEN;
    if (len < IP6_HDRLEN)
	return 0;
    if (get_ip6nh(pkt) == IP6_NHDR_FRAG)
	return 0;
    if (get_ip6nh(pkt) != IPPROTO_TCP)
	return 1;
    if (len < IP6_HDRLEN + TCP_HDRLEN)
	return 0;
    tcp = pkt + IP6_HDRLEN;
    if ((get_tcpflags(tcp) & TH_FIN) != 0 && len == IP6_HDRLEN + get_tcpoff(tcp) * 4)
	return 0;
    return 1;
}



