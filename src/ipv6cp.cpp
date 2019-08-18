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

#include <ipv6cp.h>

#include <fsm.h>
#include <ipcp.h>
#include <magic.h>

/* global vars */


/*
 * Callbacks for fsm code.  (CI = Configuration Information)
 */


// const FsmCallbacks ipv6cp_callbacks = { /* IPV6CP callback routines */
//     ipv6cp_resetci,		/* Reset our Configuration Information */
//     ipv6cp_cilen,		/* Length of our Configuration Information */
//     ipv6cp_addci,		/* Add our Configuration Information */
//     ipv6cp_ackci,		/* ACK our Configuration Information */
//     ipv6cp_nakci,		/* NAK our Configuration Information */
//     ipv6cp_rejci,		/* Reject our Configuration Information */
//     ipv6cp_reqci,		/* Request peer's Configuration Information */
//     ipv6cp_up,			/* Called when fsm reaches OPENED state */
//     ipv6cp_down,		/* Called when fsm leaves OPENED state */
//     NULL,			/* Called when we want the lower layer up */
//     ipv6cp_finished,		/* Called when we want the lower layer down */
//     NULL,			/* Called when Protocol-Reject received */
//     NULL,			/* Retransmission is necessary */
//     NULL,			/* Called to handle protocol-specific codes */
//     "IPV6CP"			/* String name of protocol */
// };

/*
 * Protocol entry points from main code.
 */



// const struct protent ipv6cp_protent = {
//     PPP_IPV6CP,
//     ipv6cp_init,
//     ipv6cp_input,
//     ipv6cp_protrej,
//     ipv6cp_lowerup,
//     ipv6cp_lowerdown,
//     ipv6cp_open,
//     ipv6cp_close,
//
//     NULL,
//
//
//
//
//     ipv6_demand_conf,
//     ipv6_active_pkt
//
// };






// #define CODENAME(x)	((x) == CONFACK ? "ACK" : \
// 			 (x) == CONFNAK ? "NAK" : "REJ")




/*
 * Make a string representation of a network address.
 */
char *
llv6_ntoa(Eui64 ifaceid)
{
    char b[26];

    sprintf(b, "fe80::%02x%02x:%02x%02x:%02x%02x:%02x%02x",
      ifaceid.e8[0], ifaceid.e8[1], ifaceid.e8[2], ifaceid.e8[3],
      ifaceid.e8[4], ifaceid.e8[5], ifaceid.e8[6], ifaceid.e8[7]);

    return b;
}


/*
 * ipv6cp_init - Initialize IPV6CP.
 */
void ipv6cp_init(PppPcb *pcb) {
    Fsm *f = &pcb->ipv6cp_fsm;
    Ipv6CpOptions *wo = &pcb->ipv6cp_wantoptions;
    Ipv6CpOptions *ao = &pcb->ipv6cp_allowoptions;

    f->pcb = pcb;
    f->protocol = PPP_IPV6CP;
    // f->callbacks = &ipv6cp_callbacks;
    fsm_init(f);


    wo->accept_local = true;
    wo->neg_ifaceid = true;
    ao->neg_ifaceid = true;

    wo->neg_vj = true;
    ao->neg_vj = true;
    wo->vj_protocol = IPV6CP_COMP;


}


/*
 * ipv6cp_open - IPV6CP is allowed to come up.
 */
void ipv6cp_open(PppPcb *pcb) {
    fsm_open(&pcb->ipv6cp_fsm);
}


/*
 * ipv6cp_close - Take IPV6CP down.
 */
void ipv6cp_close(PppPcb *pcb, const char *reason) {
    fsm_close(&pcb->ipv6cp_fsm, reason);
}


/*
 * ipv6cp_lowerup - The lower layer is up.
 */
void ipv6cp_lowerup(PppPcb *pcb) {
    fsm_lowerup(&pcb->ipv6cp_fsm);
}


/*
 * ipv6cp_lowerdown - The lower layer is down.
 */
void ipv6cp_lowerdown(PppPcb *pcb) {
    fsm_lowerdown(&pcb->ipv6cp_fsm);
}


/*
 * ipv6cp_input - Input IPV6CP packet.
 */
void ipv6cp_input(PppPcb *pcb, uint8_t *p, int len) {
    fsm_input(&pcb->ipv6cp_fsm, p);
}


/*
 * ipv6cp_protrej - A Protocol-Reject was received for IPV6CP.
 *
 * Pretend the lower layer went down, so we shut up.
 */
void ipv6cp_protrej(PppPcb *pcb) {
    fsm_lowerdown(&pcb->ipv6cp_fsm);
}


/*
 * ipv6cp_resetci - Reset our CI.
 */
void ipv6cp_resetci(Fsm *f) {
    PppPcb *pcb = f->pcb;
    Ipv6CpOptions *wo = &pcb->ipv6cp_wantoptions;
    Ipv6CpOptions *go = &pcb->ipv6cp_gotoptions;
    Ipv6CpOptions *ao = &pcb->ipv6cp_allowoptions;

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
int ipv6cp_cilen(Fsm *f) {
    PppPcb *pcb = f->pcb;
    Ipv6CpOptions *go = &pcb->ipv6cp_gotoptions;

    return ((go->neg_ifaceid ? CILEN_IFACEID : 0) +

	    (go->neg_vj ? CILEN_COMPRESS : 0) +

	    0);
}


/*
 * ipv6cp_addci - Add our desired CIs to a packet.
 */
void
ipv6cp_addci(Fsm* f, uint8_t* ucp, int* lenp)
{
    PppPcb* pcb = f->pcb;
    Ipv6CpOptions* go = &pcb->ipv6cp_gotoptions;
    int len = *lenp;

    if (go->neg_ifaceid) {
        int idlen = CILEN_IFACEID;
        if (len >= idlen) {
            PUTCHAR(1, ucp);
            PUTCHAR(idlen, ucp);
            eui64_put(&go->ourid, (Eui64*)ucp);
            len -= idlen;
        }
        else
        {
            go->neg_ifaceid = false;
        }
    }
    if (go->neg_vj) {
        int vjlen = CILEN_COMPRESS;
        if (len >= vjlen) {
            PUTCHAR(CI_COMPRESSTYPE, ucp);
            PUTCHAR(vjlen, ucp);
            PUTSHORT(go->vj_protocol, ucp);
            len -= vjlen;
        }
        else
        {
            go->neg_vj = false;
        }
    }
    *lenp -= len;
}


/*
 * ipv6cp_ackci - Ack our CIs.
 *
 * Returns:
 *	0 - Ack was bad.
 *	1 - Ack was good.
 */
int
ipv6cp_ackci(Fsm* f, uint8_t* p, int len)
{
    PppPcb* pcb = f->pcb;
    Ipv6CpOptions* go = &pcb->ipv6cp_gotoptions;
    u_short cilen, citype;

    u_short cishort;

    Eui64 ifaceid;

    /*
     * CIs must be in exactly the same order that we sent...
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */


    if (go->neg_ifaceid) {
        const int idlen = CILEN_IFACEID;
        if ((len -= idlen) < 0)
        {
            goto bad;
        }
        GETCHAR(citype, p);
        GETCHAR(cilen, p);
        if (cilen != idlen || citype != 1)
        {
            goto bad;
        }
        eui64_get(&ifaceid, (Eui64*)p);
        if (! eui64_equals(go->ourid, ifaceid))
        {
            goto bad;
        }
    }
    if (go->neg_vj) {
        int vjlen = CILEN_COMPRESS;
        if ((len -= vjlen) < 0)
        {
            goto bad;
        }
        GETCHAR(citype, p);
        GETCHAR(cilen, p);
        if (cilen != vjlen || citype != CI_COMPRESSTYPE) goto bad;
        GETSHORT(cishort, p);
        if (cishort != go->vj_protocol)
        {
            goto bad;
        }
    } /*
     * If there are any remaining CIs, then this packet is bad.
     */
    if (len != 0)
    {
        goto bad;
    }
    return (1);

bad:

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
int
ipv6cp_nakci(Fsm* f, uint8_t* p, int len, int treat_as_reject)
{
    PppPcb* pcb = f->pcb;
    Ipv6CpOptions* go = &pcb->ipv6cp_gotoptions;
    uint8_t citype, cilen;

    u_short cishort;

    Eui64 ifaceid;
    Ipv6CpOptions no; /* options we've seen Naks for */
    BZERO(&no, sizeof(no));
    Ipv6CpOptions try_ = *go;

    /*
     * Any Nak'd CIs must be in exactly the same order that we sent.
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */


    /*
     * Accept the peer's idea of {our,his} interface identifier, if different
     * from our idea, only if the accept_{local,remote} flag is set.
     */
    if (go->neg_ifaceid && len >= (cilen = CILEN_IFACEID) && p[1] == cilen && p[0] == 1) {
        len -= cilen;
        INCPTR(2, p);
        eui64_get(&ifaceid, (Eui64*)p);
        no.neg_ifaceid = true;
        if (treat_as_reject) {
            try_.neg_ifaceid = false;
        }
        else if (go->accept_local) {
            while (eui64_iszero(ifaceid) || eui64_equals(ifaceid, go->hisid))
            {
                eui64_magic(ifaceid);
            }
            try_.ourid = ifaceid;
        }
    }
    if (go->neg_vj && ((cilen = p[1]) == CILEN_COMPRESS) && len >= cilen && p[0] == CI_COMPRESSTYPE) {
        len -= cilen;
        INCPTR(2, p);
        GETSHORT(cishort, p);
        no.neg_vj = true;
        {
            if (cishort == 0x004f && !treat_as_reject) {
                try_.vj_protocol = cishort;
            }
            else {
                try_.neg_vj = false;
            }
        }
    } /*
     * There may be remaining CIs, if the peer is requesting negotiation
     * on an option that we didn't include in our request packet.
     * If they want to negotiate about interface identifier, we comply.
     * If they want us to ask for compression, we refuse.
     */
    while (len >= CILEN_VOID) {
        GETCHAR(citype, p);
        GETCHAR(cilen, p);
        if (cilen < CILEN_VOID || (len -= cilen) < 0)
        {
            goto bad;
        }
        uint8_t* next = p + cilen - 2;

        switch (citype) {

        case CI_COMPRESSTYPE:
            if (go->neg_vj || no.neg_vj ||
                (cilen != CILEN_COMPRESS))
            {
                goto bad;
            }
            no.neg_vj = true;
            break;

        case CI_IFACEID:
            if (go->neg_ifaceid || no.neg_ifaceid || cilen != CILEN_IFACEID)
            {
                goto bad;
            }
            try_.neg_ifaceid = true;
            eui64_get(&ifaceid, (Eui64*)p);
            if (go->accept_local) {
                while (eui64_iszero(ifaceid) ||
                    eui64_equals(ifaceid, go->hisid))
                {
                    /* bad luck */
                    eui64_magic(ifaceid);
                }
                try_.ourid = ifaceid;
            }
            no.neg_ifaceid = true;
            break;
        default:
            break;
        }
        p = next;
    }

    /* If there is still anything left, this packet is bad. */
    if (len != 0)
    {
        goto bad;
    } /*
     * OK, the Nak is good.  Now we can update state.
     */
    if (f->state != PPP_FSM_OPENED)
        *go = try_;

    return 1;

bad:
    // IPV6CPDEBUG(("ipv6cp_nakci: received bad Nak!"));
    return 0;
}


/*
 * ipv6cp_rejci - Reject some of our CIs.
 */
int
ipv6cp_rejci(Fsm* f, uint8_t* p, int len)
{
    PppPcb* pcb = f->pcb;
    Ipv6CpOptions* go = &pcb->ipv6cp_gotoptions;
    uint8_t cilen;

    u_short cishort;

    Eui64 ifaceid;
    Ipv6CpOptions try_ = *go;
    /*
     * Any Rejected CIs must be in exactly the same order that we sent.
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */


    if (go->neg_ifaceid && len >= (cilen = CILEN_IFACEID) && p[1] == cilen && p[0] == 1) {
        len -= cilen;
        INCPTR(2, p);
        eui64_get(&ifaceid, (Eui64*)p);
        if (! eui64_equals(ifaceid, go->ourid))
        {
            goto bad;
        }
        try_.neg_ifaceid = false;
    }
    if (go->neg_vj && p[1] == CILEN_COMPRESS && len >= p[1] && p[0] == CI_COMPRESSTYPE) {
        len -= p[1];
        INCPTR(2, p);
        GETSHORT(cishort, p);
        if (cishort != go->vj_protocol)
        {
            goto bad;
        }
        try_.neg_vj = false;
    } /*
     * If there are any remaining CIs, then this packet is bad.
     */
    if (len != 0)
    {
        goto bad;
    } /*
     * Now we can update state.
     */
    if (f->state != PPP_FSM_OPENED)
    {
        *go = try_;
    }
    return 1;

bad:

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
int ipv6cp_reqci(Fsm *f, uint8_t *inp, int *len, int reject_if_disagree) {
    PppPcb *pcb = f->pcb;
    Ipv6CpOptions *wo = &pcb->ipv6cp_wantoptions;
    Ipv6CpOptions *ho = &pcb->ipv6cp_hisoptions;
    Ipv6CpOptions *ao = &pcb->ipv6cp_allowoptions;
    Ipv6CpOptions *go = &pcb->ipv6cp_gotoptions;
    u_short cilen, citype;	/* Parsed len, type */

    u_short cishort;		/* Parsed short value */

    Eui64 ifaceid;		/* Parsed interface identifier */
    int rc = CONFACK;		/* Final packet return code */
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
    uint8_t* next = inp;
    while (l) {
	int orc = CONFACK;			/* Assume success */
	uint8_t* cip = p = next;			/* Remember begining of CI */
	if (l < 2 ||			/* Not enough data for CI header or */
	    p[1] < 2 ||			/*  CI length too small or */
	    p[1] > l) {			/*  CI length too big? */

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
	    eui64_get(&ifaceid, (Eui64*)p);

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
		eui64_put(&ifaceid, (Eui64*)p);
	    } else
	    if (eui64_iszero(ifaceid) || eui64_equals(ifaceid, go->ourid)) {
		orc = CONFNAK;
		if (eui64_iszero(go->hisid))
        {
            /* first time, try option */
		    ifaceid = wo->hisid;
        }
        while (eui64_iszero(ifaceid) || 
		       eui64_equals(ifaceid, go->ourid))
        {
            /* bad luck */
		    eui64_magic(ifaceid);
        }
        go->hisid = ifaceid;
		DECPTR(sizeof(ifaceid), p);
		eui64_put(&ifaceid, (Eui64*)p);
	    }

	    ho->neg_ifaceid = true;
	    ho->hisid = ifaceid;
	    break;


	case CI_COMPRESSTYPE:
	    // IPV6CPDEBUG(("ipv6cp: received COMPRESSTYPE "));
	    if (!ao->neg_vj ||
		(cilen != CILEN_COMPRESS)) {
		orc = CONFREJ;
		break;
	    }
	    GETSHORT(cishort, p);
	    // IPV6CPDEBUG(("(%d)", cishort));

	    if (!(cishort == IPV6CP_COMP)) {
		orc = CONFREJ;
		break;
	    }

	    ho->neg_vj = true;
	    ho->vj_protocol = cishort;
	    break;


	default:
	    orc = CONFREJ;
	    break;
	}

endswitch:


	if (orc == CONFACK &&		/* Good CI */
	    rc != CONFACK)
    {
        /*  but prior CI wasnt? */
	    continue;			/* Don't send this one */
    }
    if (orc == CONFNAK) {		/* Nak this CI? */
	    if (reject_if_disagree)
        {
            /* Getting fed up with sending NAKs? */
		orc = CONFREJ;		/* Get tough if so */
        }
        else {
		if (rc == CONFREJ)
        {
            /* Rejecting prior CI? */
		    continue;		/* Don't send this one */
        }
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
    {
        memcpy(ucp, cip, cilen);	/* Move it */
    } /* Update output pointer */
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
	    wo->req_ifaceid = false;		/* don't ask again */
	}
	{ *(ucp)++ = (uint8_t) (1); }
    { *(ucp)++ = (uint8_t) (10); }
    eui64_put(&wo->hisid, (Eui64*)ucp);
    }

    *len = ucp - inp;			/* Compute output length */

    return (rc);			/* Return final code */
}


/*
 * ipv6_demand_conf - configure the interface as though
 * IPV6CP were up, for use with dial-on-demand.
 */
bool
ipv6_demand_conf(PppPcb* u) {
    // Ipv6CpOptions *wo = &ipv6cp_wantoptions[u];
    Ipv6CpOptions *wo = nullptr;
    
    if (!sif6up(u))
    {
        return false;
    }
    if (!sif6addr(u, wo->ourid, wo->hisid))
    {
        return false;
    }
    if (!sifnpmode(u, PPP_IPV6, NPMODE_QUEUE))
    {
        return false;
    }
    ppp_notice("ipv6_demand_conf");
    ppp_notice("local  LL address %s", llv6_ntoa(wo->ourid));
    ppp_notice("remote LL address %s", llv6_ntoa(wo->hisid));

    return true;
}


/*
 * ipv6cp_up - IPV6CP has come UP.
 *
 * Configure the IPv6 network interface appropriately and bring it up.
 */
void ipv6cp_up(Fsm *f) {
    PppPcb *pcb = f->pcb;
    Ipv6CpOptions *wo = &pcb->ipv6cp_wantoptions;
    Ipv6CpOptions *ho = &pcb->ipv6cp_hisoptions;
    Ipv6CpOptions *go = &pcb->ipv6cp_gotoptions;

    // IPV6CPDEBUG(("ipv6cp: up"));

    /*
     * We must have a non-zero LL address for both ends of the link.
     */
    if (!ho->neg_ifaceid)
    {
        ho->hisid = wo->hisid;
    }
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

    // script_setenv("LLLOCAL", llv6_ntoa(go->ourid), 0);
    // script_setenv("LLREMOTE", llv6_ntoa(ho->hisid), 0);



    /* set tcp compression */
    // sif6comp(f->unit, ho->neg_vj);



    /*
     * If we are doing dial-on-demand, the interface is already
     * configured, so we put out any saved-up packets, then set the
     * interface to pass IPv6 packets.
     */
    bool demand = false;
    if (demand) {
	if (! eui64_equals(go->ourid, wo->ourid) || 
	    ! eui64_equals(ho->hisid, wo->hisid)) {
	    if (! eui64_equals(go->ourid, wo->ourid))
        {
            // warn("Local LL address changed to %s", 
		//      llv6_ntoa(go->ourid));
	    if (! eui64_equals(ho->hisid, wo->hisid))
        {
            // warn("Remote LL address changed to %s", 
		//      llv6_ntoa(ho->hisid));
	    ipv6cp_clear_addrs(f->pcb, go->ourid, ho->hisid);
            }
        } /* Set the interface to the new addresses */
	    if (!sif6addr(f->pcb, go->ourid, ho->hisid)) {
		// if (debug)
		//     warn("sif6addr failed");
		ipv6cp_close(f->unit, "Interface configuration failed");
		return;
	    }

	}
	// demand_rexmit(PPP_IPV6);
	sifnpmode(f->unit, PPP_IPV6, NPMODE_PASS);

    } else

    {
	/*
	 * Set LL addresses
	 */
	if (!sif6addr(f->pcb, go->ourid, ho->hisid)) {
	    // PPPDEBUG(LOG_DEBUG, ("sif6addr failed"));
	    ipv6cp_close(f->pcb, "Interface configuration failed");
	    return;
	}

	/* bring the interface up for IPv6 */
	if (!sif6up(f->pcb)) {
	    // PPPDEBUG(LOG_DEBUG, ("sif6up failed (IPV6)"));
	    ipv6cp_close(f->pcb, "Interface configuration failed");
	    return;
	}

	sifnpmode(f->pcb, PPP_IPV6, NPMODE_PASS);


	ppp_notice("local  LL address %s", llv6_ntoa(go->ourid));
	ppp_notice("remote LL address %s", llv6_ntoa(ho->hisid));
    }

    np_up(f->pcb, PPP_IPV6);
    pcb->ipv6_cp_is_up = true;

}


/*
 * ipv6cp_down - IPV6CP has gone DOWN.
 *
 * Take the IPv6 network interface down, clear its addresses
 * and delete routes through it.
 */
void ipv6cp_down(Fsm *f) {
    PppPcb *pcb = f->pcb;
    Ipv6CpOptions *go = &pcb->ipv6cp_gotoptions;
    Ipv6CpOptions *ho = &pcb->ipv6cp_hisoptions;

    // IPV6CPDEBUG(("ipv6cp: down"));
    if (pcb->ipv6_cp_is_up) {
	pcb->ipv6_cp_is_up = false;
	np_down(f->pcb, PPP_IPV6);
    }

    // sif6comp(f->unit, 0);

    /*
     * If we are doing dial-on-demand, set the interface
     * to queue up outgoing packets (for now).
     */
    bool demand = false;
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
void ipv6cp_clear_addrs(PppPcb *pcb, Eui64 ourid, Eui64 hisid) {
    // cif6addr(pcb, ourid, hisid);
}


/*
 * ipv6cp_finished - possibly shut down the lower layers.
 */
void ipv6cp_finished(Fsm *f) {
    np_finished(f->pcb, PPP_IPV6);
}







/*
 * We use these macros because the IP header may be at an odd address,
 * and some compilers might use word loads to get th_off or ip_hl.
 */

// #define get_ip6nh(x)	(((unsigned char *)(x))[6])
// #define get_tcpoff(x)	(((unsigned char *)(x))[12] >> 4)
// #define get_tcpflags(x)	(((unsigned char *)(x))[13])

int ipv6_active_pkt(uint8_t *pkt, int len) {
    len -= PPP_HDRLEN;
    pkt += PPP_HDRLEN;
    if (len < IP6_HDRLEN)
    {
        return 0;
    }
    if ((((unsigned char *)(pkt))[6]) == IP6_NHDR_FRAG)
    {
        return 0;
    }
    if ((((unsigned char *)(pkt))[6]) != IPPROTO_TCP)
    {
        return 1;
    }
    if (len < IP6_HDRLEN + TCP_HDRLEN)
    {
        return 0;
    }
    uint8_t* tcp = pkt + IP6_HDRLEN;
    if (((((unsigned char *)(tcp))[13]) & TH_FIN) != 0 && len == IP6_HDRLEN + (((unsigned char *)(tcp))[12] >> 4) * 4)
    {
        return 0;
    }
    return 1;
}



