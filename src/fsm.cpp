/*
 * fsm.c - {Link, IP} Control Protocol Finite State Machine.
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

/*
 * @todo:
 * Randomize fsm id on link/init.
 * Deal with variable outgoing MTU.
 */

#define NOMINMAX
#include <fsm.h>
#include <ppp_impl.h>

/*
 * fsm_init - Initialize fsm.
 *
 * Initialize fsm state.
 */
void fsm_init(Fsm* f)
{
    PppPcb* pcb = f->pcb;
    f->state = PPP_FSM_INITIAL;
    f->flags = 0;
    f->id = 0; /* XXX Start with random id? */
    f->maxnakloops = pcb->settings.fsm_max_nak_loops;
    f->term_reason_len = 0;
}


/*
 * fsm_lowerup - The lower layer is up.
 */
void fsm_lowerup(Fsm *f) {
    switch( f->state ){
    case PPP_FSM_INITIAL:
    f->state = PPP_FSM_CLOSED;
    break;

    case PPP_FSM_STARTING:
    if( f->flags & OPT_SILENT )
        f->state = PPP_FSM_STOPPED;
    else {
        /* Send an initial configure-request */
        fsm_sconfreq(f, 0);
        f->state = PPP_FSM_REQSENT;
    }
    break;

    // FSMDEBUG(("%s: Up event in state %d!", PROTO_NAME(f), f->state));
    /* no break */
    }
}


/*
 * fsm_lowerdown - The lower layer is down.
 *
 * Cancel all timeouts and inform upper layers.
 */
void fsm_lowerdown(Fsm *f) {
    switch( f->state ){
    case PPP_FSM_CLOSED:
    f->state = PPP_FSM_INITIAL;
    break;

    case PPP_FSM_STOPPED:
    f->state = PPP_FSM_STARTING;
    if( f->callbacks->starting )
        (*f->callbacks->starting)(f);
    break;

    case PPP_FSM_CLOSING:
    f->state = PPP_FSM_INITIAL;
    Untimeout(fsm_timeout, f);	/* Cancel timeout */
    break;

    case PPP_FSM_STOPPING:
    case PPP_FSM_REQSENT:
    case PPP_FSM_ACKRCVD:
    case PPP_FSM_ACKSENT:
    f->state = PPP_FSM_STARTING;
    Untimeout(fsm_timeout, f);	/* Cancel timeout */
    break;

    case PPP_FSM_OPENED:
    if( f->callbacks->down )
        (*f->callbacks->down)(f, f, f->pcb);
    f->state = PPP_FSM_STARTING;
    break;
    // FSMDEBUG(("%s: Down event in state %d!", PROTO_NAME(f), f->state));
    /* no break */
    }
}


/*
 * fsm_open - Link is allowed to come up.
 */
bool fsm_open(Fsm* f)
{
    switch (f->state)
    {
    case PPP_FSM_INITIAL:
        f->state = PPP_FSM_STARTING;
        if (f->callbacks->starting)
            (*f->callbacks->starting)(f);
        break;
    case PPP_FSM_CLOSED:
        if (f->flags & OPT_SILENT)
            f->state = PPP_FSM_STOPPED;
        else
        {
            /* Send an initial configure-request */
            fsm_sconfreq(f, 0);
            f->state = PPP_FSM_REQSENT;
        }
        break;
    case PPP_FSM_CLOSING:
        f->state = PPP_FSM_STOPPING; /* fall through */ /* no break */
    case PPP_FSM_STOPPED: case PPP_FSM_OPENED:
        if (f->flags & OPT_RESTART)
        {
            fsm_lowerdown(f);
            fsm_lowerup(f);
        }
        break;
    default:
        break;
    }

    return true;
}

/*
 * terminate_layer - Start process of shutting down the FSM
 *
 * Cancel any timeout running, notify upper layers we're done, and
 * send a terminate-request message as configured.
 */
void terminate_layer(Fsm *f, int nextstate) {
    PppPcb *pcb = f->pcb;

    if( f->state != PPP_FSM_OPENED )
    Untimeout(fsm_timeout, f);	/* Cancel timeout */
    else if( f->callbacks->down )
    (*f->callbacks->down)(f, f, pcb);	/* Inform upper layers we're down */

    /* Init restart counter and send Terminate-Request */
    f->retransmits = pcb->settings.fsm_max_term_transmits;
    fsm_sdata(f, TERMREQ, f->reqid = ++f->id,
          reinterpret_cast<const uint8_t *>(f->term_reason), f->term_reason_len);

    if (f->retransmits == 0) {
    /*
     * User asked for no terminate requests at all; just close it.
     * We've already fired off one Terminate-Request just to be nice
     * to the peer, but we're not going to wait for a reply.
     */
    f->state = nextstate == PPP_FSM_CLOSING ? PPP_FSM_CLOSED : PPP_FSM_STOPPED;
    if( f->callbacks->finished )
        (*f->callbacks->finished)(f);
    return;
    }

    Timeout(fsm_timeout, f, pcb->settings.fsm_timeout_time);
    --f->retransmits;

    f->state = nextstate;
}

/*
 * fsm_close - Start closing connection.
 *
 * Cancel timeouts and either initiate close or possibly go directly to
 * the PPP_FSM_CLOSED state.
 */
void fsm_close(Fsm *f, const char *reason) {
    f->term_reason = reason;
    f->term_reason_len = (reason == nullptr? 0: (uint8_t)std::min(strlen(reason), (size_t)0xFF) );
    switch( f->state ){
    case PPP_FSM_STARTING:
    f->state = PPP_FSM_INITIAL;
    break;
    case PPP_FSM_STOPPED:
    f->state = PPP_FSM_CLOSED;
    break;
    case PPP_FSM_STOPPING:
    f->state = PPP_FSM_CLOSING;
    break;

    case PPP_FSM_REQSENT:
    case PPP_FSM_ACKRCVD:
    case PPP_FSM_ACKSENT:
    case PPP_FSM_OPENED:
    terminate_layer(f, PPP_FSM_CLOSING);
    break;
    default:
    break;
    }
}


/*
 * fsm_timeout - Timeout expired.
 */
void fsm_timeout(void* arg) {
    Fsm *f = (Fsm *) arg;
    PppPcb *pcb = f->pcb;

    switch (f->state) {
    case PPP_FSM_CLOSING:
    case PPP_FSM_STOPPING:
    if( f->retransmits <= 0 ){
        /*
         * We've waited for an ack long enough.  Peer probably heard us.
         */
        f->state = (f->state == PPP_FSM_CLOSING)? PPP_FSM_CLOSED: PPP_FSM_STOPPED;
        if( f->callbacks->finished )
        (*f->callbacks->finished)(f);
    } else {
        /* Send Terminate-Request */
        fsm_sdata(f, TERMREQ, f->reqid = ++f->id,
              (const uint8_t *) f->term_reason, f->term_reason_len);
        Timeout(fsm_timeout, f, pcb->settings.fsm_timeout_time);
        --f->retransmits;
    }
    break;

    case PPP_FSM_REQSENT:
    case PPP_FSM_ACKRCVD:
    case PPP_FSM_ACKSENT:
    if (f->retransmits <= 0) {
        ppp_warn("%s: timeout sending Config-Requests", ((f)->callbacks->proto_name));
        f->state = PPP_FSM_STOPPED;
        if( (f->flags & OPT_PASSIVE) == 0 && f->callbacks->finished )
        (*f->callbacks->finished)(f);

    } else {
        /* Retransmit the configure-request */
        if (f->callbacks->retransmit)
        (*f->callbacks->retransmit)(f);
        fsm_sconfreq(f, 1);		/* Re-send Configure-Request */
        if( f->state == PPP_FSM_ACKRCVD )
        f->state = PPP_FSM_REQSENT;
    }
    break;
    // FSMDEBUG(("%s: Timeout event in state %d!", PROTO_NAME(f), f->state));
    /* no break */
    }
}


/*
 * fsm_input - Input packet.
 */
void fsm_input(Fsm *f, uint8_t *inpacket, int l) {
    uint8_t code, id;
    int len;

    /*
     * Parse header (code, id and length).
     * If packet too short, drop it.
     */
    uint8_t* inp = inpacket;
    if (l < FSM_PKT_HDR_LEN) {
    // FSMDEBUG(("fsm_input(%x): Rcvd short header.", f->protocol));
    return;
    }
    GETCHAR(code, inp);
    GETCHAR(id, inp);
    GETSHORT(len, inp);
    if (len < FSM_PKT_HDR_LEN) {
    // FSMDEBUG(("fsm_input(%x): Rcvd illegal length.", f->protocol));
    return;
    }
    if (len > l) {
    // FSMDEBUG(("fsm_input(%x): Rcvd short packet.", f->protocol));
    return;
    }
    len -= FSM_PKT_HDR_LEN;		/* subtract header length */

    if( f->state == PPP_FSM_INITIAL || f->state == PPP_FSM_STARTING ){
    // FSMDEBUG(("fsm_input(%x): Rcvd packet in state %d.",
          // f->protocol, f->state));
    return;
    }

    /*
     * Action depends on code.
     */
    switch (code) {
    case CONFREQ:
    fsm_rconfreq(f, id, inp, len);
    break;

    case CONFACK:
    fsm_rconfack(f, id, inp, len);
    break;

    case CONFNAK:
    case CONFREJ:
    fsm_rconfnakrej(f, code, id, inp, len);
    break;

    case TERMREQ:
    fsm_rtermreq(f, id, inp, len);
    break;

    case TERMACK:
    fsm_rtermack(f);
    break;

    case CODEREJ:
    fsm_rcoderej(f, inp, len);
    break;

    default:
    if( !f->callbacks->extcode
       || !(*f->callbacks->extcode)(f, code, id, inp, len, f->pcb) )
        fsm_sdata(f, CODEREJ, ++f->id, inpacket, len + FSM_PKT_HDR_LEN);
    break;
    }
}


/*
 * fsm_rconfreq - Receive Configure-Request.
 */
void fsm_rconfreq(Fsm* f, uint8_t id, uint8_t *inp, size_t len) {
    int code;

    switch( f->state ){
    case PPP_FSM_CLOSED:
    /* Go away, we're closed */
    fsm_sdata(f, TERMACK, id, nullptr, 0);
    return;
    case PPP_FSM_CLOSING:
    case PPP_FSM_STOPPING:
    return;

    case PPP_FSM_OPENED:
    /* Go down and restart negotiation */
    if( f->callbacks->down )
        (*f->callbacks->down)(f, f, f->pcb);	/* Inform upper layers */
    fsm_sconfreq(f, 0);		/* Send initial Configure-Request */
    f->state = PPP_FSM_REQSENT;
    break;

    case PPP_FSM_STOPPED:
    /* Negotiation started by our peer */
    fsm_sconfreq(f, 0);		/* Send initial Configure-Request */
    f->state = PPP_FSM_REQSENT;
    break;
    default:
    break;
    }

    /*
     * Pass the requested configuration options
     * to protocol-specific code for checking.
     */
    if (f->callbacks->reqci)
    {
        /* Check CI */
    int reject_if_disagree = (f->nakloops >= f->maxnakloops);
    code = (*f->callbacks->reqci)(f, inp, &len, reject_if_disagree, f->pcb);
    } else if (len)
    code = CONFREJ;			/* Reject all CI */
    else
    code = CONFACK;

    /* send the Ack, Nak or Rej to the peer */
    fsm_sdata(f, code, id, inp, len);

    if (code == CONFACK) {
    if (f->state == PPP_FSM_ACKRCVD) {
        Untimeout(fsm_timeout, f);	/* Cancel timeout */
        f->state = PPP_FSM_OPENED;
        if (f->callbacks->up)
        (*f->callbacks->up)(f, f->pcb);	/* Inform upper layers */
    } else
        f->state = PPP_FSM_ACKSENT;
    f->nakloops = 0;

    } else {
    /* we sent CONFACK or CONFREJ */
    if (f->state != PPP_FSM_ACKRCVD)
        f->state = PPP_FSM_REQSENT;
    if( code == CONFNAK )
        ++f->nakloops;
    }
}


/*
 * fsm_rconfack - Receive Configure-Ack.
 */
void fsm_rconfack(Fsm* f, int id, uint8_t *inp, size_t len) {
    PppPcb *pcb = f->pcb;

    if (id != f->reqid || f->seen_ack)		/* Expected id? */
    return;					/* Nope, toss... */
    if( !(f->callbacks->ackci? (*f->callbacks->ackci)(f, inp, len, f->pcb):
      (len == 0)) ){
    /* Ack is bad - ignore it */
    ppp_error("Received bad configure-ack: %P", inp, len);
    return;
    }
    f->seen_ack = 1;
    f->rnakloops = 0;

    switch (f->state) {
    case PPP_FSM_CLOSED:
    case PPP_FSM_STOPPED:
    fsm_sdata(f, TERMACK, id, nullptr, 0);
    break;

    case PPP_FSM_REQSENT:
    f->state = PPP_FSM_ACKRCVD;
    f->retransmits = pcb->settings.fsm_max_conf_req_transmits;
    break;

    case PPP_FSM_ACKRCVD:
    /* Huh? an extra valid Ack? oh well... */
    Untimeout(fsm_timeout, f);	/* Cancel timeout */
    fsm_sconfreq(f, 0);
    f->state = PPP_FSM_REQSENT;
    break;

    case PPP_FSM_ACKSENT:
    Untimeout(fsm_timeout, f);	/* Cancel timeout */
    f->state = PPP_FSM_OPENED;
    f->retransmits = pcb->settings.fsm_max_conf_req_transmits;
    if (f->callbacks->up)
        (*f->callbacks->up)(f, f->pcb);	/* Inform upper layers */
    break;

    case PPP_FSM_OPENED:
    /* Go down and restart negotiation */
    if (f->callbacks->down)
        (*f->callbacks->down)(f, f, f->pcb);	/* Inform upper layers */
    fsm_sconfreq(f, 0);		/* Send initial Configure-Request */
    f->state = PPP_FSM_REQSENT;
    break;
    default:
    break;
    }
}


/*
 * fsm_rconfnakrej - Receive Configure-Nak or Configure-Reject.
 */
void fsm_rconfnakrej(Fsm* f, int code, int id, uint8_t *inp, size_t len) {
    int ret;
    if (id != f->reqid || f->seen_ack)	/* Expected id? */
    return;				/* Nope, toss... */

    if (code == CONFNAK) {
    ++f->rnakloops;
    int treat_as_reject = (f->rnakloops >= f->maxnakloops);
    if (f->callbacks->nakci == nullptr
        || !(ret = f->callbacks->nakci(f, inp, len, treat_as_reject, f->pcb))) {
        ppp_error("Received bad configure-nak: %P", inp, len);
        return;
    }
    } else {
    f->rnakloops = 0;
    if (f->callbacks->rejci == nullptr
        || !(ret = f->callbacks->rejci(f, inp, len, f->pcb))) {
        ppp_error("Received bad configure-rej: %P", inp, len);
        return;
    }
    }

    f->seen_ack = 1;

    switch (f->state) {
    case PPP_FSM_CLOSED:
    case PPP_FSM_STOPPED:
    fsm_sdata(f, TERMACK, id, nullptr, 0);
    break;

    case PPP_FSM_REQSENT:
    case PPP_FSM_ACKSENT:
    /* They didn't agree to what we wanted - try another request */
    Untimeout(fsm_timeout, f);	/* Cancel timeout */
    if (ret < 0)
        f->state = PPP_FSM_STOPPED;		/* kludge for stopping CCP */
    else
        fsm_sconfreq(f, 0);		/* Send Configure-Request */
    break;

    case PPP_FSM_ACKRCVD:
    /* Got a Nak/reject when we had already had an Ack?? oh well... */
    Untimeout(fsm_timeout, f);	/* Cancel timeout */
    fsm_sconfreq(f, 0);
    f->state = PPP_FSM_REQSENT;
    break;

    case PPP_FSM_OPENED:
    /* Go down and restart negotiation */
    if (f->callbacks->down)
        (*f->callbacks->down)(f, f, f->pcb);	/* Inform upper layers */
    fsm_sconfreq(f, 0);		/* Send initial Configure-Request */
    f->state = PPP_FSM_REQSENT;
    break;
    default:
    break;
    }
}


/*
 * fsm_rtermreq - Receive Terminate-Req.
 */
void fsm_rtermreq(Fsm* f, int id, uint8_t *p, size_t len) {
    PppPcb *pcb = f->pcb;

    switch (f->state) {
    case PPP_FSM_ACKRCVD:
    case PPP_FSM_ACKSENT:
    f->state = PPP_FSM_REQSENT;		/* Start over but keep trying */
    break;

    case PPP_FSM_OPENED:
    if (len > 0) {
        ppp_info("%s terminated by peer (%0.*v)", ((f)->callbacks->proto_name), len, p);
    } else
        ppp_info("%s terminated by peer", ((f)->callbacks->proto_name));
    f->retransmits = 0;
    f->state = PPP_FSM_STOPPING;
    if (f->callbacks->down)
        (*f->callbacks->down)(f,f, f->pcb);	/* Inform upper layers */
    Timeout(fsm_timeout, f, pcb->settings.fsm_timeout_time);
    break;
    default:
    break;
    }

    fsm_sdata(f, TERMACK, id, nullptr, 0);
}


/*
 * fsm_rtermack - Receive Terminate-Ack.
 */
void fsm_rtermack(Fsm* f) {
    switch (f->state) {
    case PPP_FSM_CLOSING:
    Untimeout(fsm_timeout, f);
    f->state = PPP_FSM_CLOSED;
    if( f->callbacks->finished )
        (*f->callbacks->finished)(f);
    break;
    case PPP_FSM_STOPPING:
    Untimeout(fsm_timeout, f);
    f->state = PPP_FSM_STOPPED;
    if( f->callbacks->finished )
        (*f->callbacks->finished)(f);
    break;

    case PPP_FSM_ACKRCVD:
    f->state = PPP_FSM_REQSENT;
    break;

    case PPP_FSM_OPENED:
    if (f->callbacks->down)
        (*f->callbacks->down)(f,f,f->pcb);	/* Inform upper layers */
    fsm_sconfreq(f, 0);
    f->state = PPP_FSM_REQSENT;
    break;
    default:
    break;
    }
}


/*
 * fsm_rcoderej - Receive an Code-Reject.
 */
void fsm_rcoderej(Fsm* f, uint8_t *inp, size_t len) {
    uint8_t code, id;

    if (len < FSM_PKT_HDR_LEN) {
    // FSMDEBUG(("fsm_rcoderej: Rcvd short Code-Reject packet!"));
    return;
    }
    GETCHAR(code, inp);
    GETCHAR(id, inp);
    ppp_warn("%s: Rcvd Code-Reject for code %d, id %d", ((f)->callbacks->proto_name), code, id);

    if( f->state == PPP_FSM_ACKRCVD )
    f->state = PPP_FSM_REQSENT;
}


/*
 * fsm_protreject - Peer doesn't speak this protocol.
 *
 * Treat this as a catastrophic error (RXJ-).
 */
void fsm_protreject(Fsm* f) {
    switch( f->state ){
    case PPP_FSM_CLOSING:
    Untimeout(fsm_timeout, f);	/* Cancel timeout */
    /* fall through */
    /* no break */
    case PPP_FSM_CLOSED:
    f->state = PPP_FSM_CLOSED;
    if( f->callbacks->finished )
        (*f->callbacks->finished)(f);
    break;

    case PPP_FSM_STOPPING:
    case PPP_FSM_REQSENT:
    case PPP_FSM_ACKRCVD:
    case PPP_FSM_ACKSENT:
    Untimeout(fsm_timeout, f);	/* Cancel timeout */
    /* fall through */
    /* no break */
    case PPP_FSM_STOPPED:
    f->state = PPP_FSM_STOPPED;
    if( f->callbacks->finished )
        (*f->callbacks->finished)(f);
    break;

    case PPP_FSM_OPENED:
    terminate_layer(f, PPP_FSM_STOPPING);
    break;

    default:
        auto a = true;
    // FSMDEBUG(("%s: Protocol-reject event in state %d!",
    // 	  PROTO_NAME(f), f->state));
    /* no break */
    }
}


/*
 * fsm_sconfreq - Send a Configure-Request.
 */
void fsm_sconfreq(Fsm* f, int retransmit) {
    PppPcb *pcb = f->pcb;
    int cilen;

    if( f->state != PPP_FSM_REQSENT && f->state != PPP_FSM_ACKRCVD && f->state != PPP_FSM_ACKSENT ){
    /* Not currently negotiating - reset options */
    if( f->callbacks->resetci )
        (*f->callbacks->resetci)(f, f->pcb);
    f->nakloops = 0;
    f->rnakloops = 0;
    }

    if( !retransmit ){
    /* New request - reset retransmission counter, use new ID */
    f->retransmits = pcb->settings.fsm_max_conf_req_transmits;
    f->reqid = ++f->id;
    }

    f->seen_ack = 0;

    /*
     * Make up the request packet
     */
    if( f->callbacks->cilen && f->callbacks->addci ){
    cilen = (*f->callbacks->cilen)(f->pcb);
    if( cilen > pcb->peer_mru - FSM_PKT_HDR_LEN )
        cilen = pcb->peer_mru - FSM_PKT_HDR_LEN;
    } else
    cilen = 0;

    // p = pbuf_alloc(PBUF_RAW, (uint16_t)(cilen + kHeaderlen + PPP_HDRLEN), PPP_CTRL_PBUF_TYPE);
    PacketBuffer* p = new PacketBuffer;
    if(nullptr == p)
        return;
    if(p->tot_len != p->len) {
        free_pkt_buf(p);
        return;
    }

    /* send the request to our peer */
    uint8_t* outp = static_cast<uint8_t*>(p->payload);
    PUTCHAR(PPP_ALLSTATIONS, outp);
    PUTCHAR(PPP_UI, outp);
    PUTSHORT(f->protocol, outp);
    PUTCHAR(CONFREQ, outp);
    PUTCHAR(f->reqid, outp);
    PUTSHORT(cilen + FSM_PKT_HDR_LEN, outp);
    if (cilen != 0) {
    (*f->callbacks->addci)(f, outp, &cilen, f->pcb);
    lwip_assert("cilen == p->len - kHeaderlen - PPP_HDRLEN", cilen == p->len - FSM_PKT_HDR_LEN - PPP_HDRLEN);
    }

    ppp_write(pcb, p);

    /* start the retransmit timer */
    --f->retransmits;
    Timeout(fsm_timeout, f, pcb->settings.fsm_timeout_time);
}


/*
 * fsm_sdata - Send some data.
 *
 * Used for all packets sent to our peer by this module.
 */
void fsm_sdata(Fsm *f, uint8_t code, uint8_t id, const uint8_t *data, int datalen) {
    PppPcb *pcb = f->pcb; /* Adjust length to be smaller than MTU */
    if (datalen > pcb->peer_mru - FSM_PKT_HDR_LEN)
    datalen = pcb->peer_mru - FSM_PKT_HDR_LEN;
    int outlen = datalen + FSM_PKT_HDR_LEN;

    // p = pbuf_alloc(PBUF_RAW, (uint16_t)(outlen + PPP_HDRLEN), PPP_CTRL_PBUF_TYPE);
    PacketBuffer* p = new PacketBuffer;
    if(nullptr == p)
        return;
    if(p->tot_len != p->len) {
        free_pkt_buf(p);
        return;
    }

    uint8_t* outp = (uint8_t*)p->payload;
    if (datalen) /* && data != outp + PPP_HDRLEN + kHeaderlen)  -- was only for fsm_sconfreq() */
    memcpy(outp + PPP_HDRLEN + FSM_PKT_HDR_LEN, data, datalen);
    MAKEHEADER(outp, f->protocol);
    PUTCHAR(code, outp);
    PUTCHAR(id, outp);
    PUTSHORT(outlen, outp);
    ppp_write(pcb, p);
}

//
// END OF FILE
//
