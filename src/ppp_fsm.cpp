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
#include "fsm.h"
#include "fsm_def.h"
#include "ppp.h"
#include <vector>
#include <string>

/**
 * Initialize fsm state.
 */
bool
fsm_init(Fsm& fsm, PppPcb& pcb)
{
    fsm.state = PPP_FSM_INITIAL;
    fsm.id = 0; /* XXX Start with random id? */
    fsm.maxnakloops = pcb.settings.fsm_max_nak_loops;
}


/**
 * The lower layer is up.
 */
bool
fsm_lowerup(PppPcb& pcb, Fsm& f) {

    if (f.state == PPP_FSM_INITIAL) {
        f.state = PPP_FSM_CLOSED;
    }
    else if (f.state == PPP_FSM_STARTING) {
        if (f.options.silent) {
            f.state = PPP_FSM_STOPPED;
        } else {
            if (!fsm_senc_conf_req(pcb, f, false)) {return false;}
        }
    }
    return true;
}


/**
 * The lower layer is down. Cancel all timeouts and inform upper layers.
 */
bool
fsm_lowerdown(Fsm& f) {

    if (f.state == PPP_FSM_CLOSED) {
        f.state = PPP_FSM_INITIAL;
    }
    else if (f.state == PPP_FSM_STOPPED) {
        f.state = PPP_FSM_STARTING;
        // todo: send starting notification
    }
    else if (f.state == PPP_FSM_CLOSING) {
        f.state = PPP_FSM_INITIAL;
        // todo: cancel fsm_timeout function
    }
    else if (f.state == PPP_FSM_STOPPING || f.state == PPP_FSM_REQSENT || f.state == PPP_FSM_ACKRCVD || f.state == PPP_FSM_ACKSENT) {
        f.state = PPP_FSM_STARTING;
        // todo: cancel fsm_timeout function
    }
    else if (f.state == PPP_FSM_OPENED) {
        // todo: send down callback
        f.state = PPP_FSM_STARTING;
    }
    return true;
}


/*
 * fsm_open - Link is allowed to come up.
 */
bool fsm_open(PppPcb& pcb, Fsm& f)
{
    if (f.state == PPP_FSM_INITIAL) {
        f.state = PPP_FSM_STARTING;
        // todo: publish starting notification;
    }
    else if (f.state == PPP_FSM_CLOSED) {
        if (f.options.silent) { f.state = PPP_FSM_STOPPED;}
        else {
            if (!fsm_senc_conf_req(pcb, f, false)) {
                return false;
            }
            f.state = PPP_FSM_REQSENT;
        }
    }
    else if (f.state == PPP_FSM_CLOSING) {
        f.state = PPP_FSM_STOPPING;
    }
    else if (f.state == PPP_FSM_STOPPED || f.state == PPP_FSM_OPENED) {
        if (f.options.restart) {
            if (!fsm_lowerdown(f)) {return false; }
            if (!fsm_lowerup(pcb, f)) {return false;}
        }
    }

    return true;
}

/**
 * Start process of shutting down the FSM. Cancel any timeout running, notify upper
 * layers we're done, and send a terminate-request message as configured.
 */
bool
terminate_layer(PppPcb& pcb, Fsm& f, PppFsmLinkState next_state) {
    // PppPcb *pcb = f.pcb;

    if( f.state != PPP_FSM_OPENED )
    {
        // todo: cancel fsm_timeout function
        // fsm_timeout(pcb, f);
        // Untimeout(fsm_timeout, f);	/* Cancel timeout */
    }
    // todo: publish down notification
    // else if( f.callbacks->down )
    // {
    //     (*f.callbacks->down)(f, f, pcb);	/* Inform upper layers we're down */
    // }

    /* Init restart counter and send Terminate-Request */
    f.retransmits = pcb.settings.fsm_max_term_transmits;
    std::vector<uint8_t> data;
    data.reserve(f.term_reason.length());
    std::copy(f.term_reason.begin(), f.term_reason.end(), data.begin());
    fsm_send_data2(pcb, f, TERM_REQ, f.reqid = ++f.id, data);
    if (f.retransmits == 0) {
        /*
            * User asked for no terminate requests at all; just close it.
            * We've already fired off one Terminate-Request just to be nice
            * to the peer, but we're not going to wait for a reply.
            */
        f.state = next_state == PPP_FSM_CLOSING ? PPP_FSM_CLOSED : PPP_FSM_STOPPED;
        // if( f.callbacks->finished )
        // {
        //     (*f.callbacks->finished)(f);
        // }
        // todo: call finished callback
        return true;
    }

    // Timeout(fsm_timeout, f, pcb->settings.fsm_timeout_time);
    // todo: schedule fsm_timeout function
    --f.retransmits;
    f.state = next_state;
    return true;
}

/**
 * Start closing connection. Cancel timeouts and either initiate close or possibly go
 * directly to the PPP_FSM_CLOSED state.
 */
bool
fsm_close(PppPcb& pcb, Fsm& fsm, std::string& reason) {
    fsm.term_reason = reason;

    if (fsm.state == PPP_FSM_STARTING) {
        fsm.state = PPP_FSM_INITIAL;
    }
    else if (fsm.state == PPP_FSM_STOPPED) {
        fsm.state = PPP_FSM_CLOSED;
    }
    else if (fsm.state == PPP_FSM_STOPPING) {
        fsm.state = PPP_FSM_CLOSING;
    }
    else if (fsm.state == PPP_FSM_REQSENT || fsm.state == PPP_FSM_ACKRCVD
             || fsm.state == PPP_FSM_ACKSENT || fsm.state == PPP_FSM_OPENED) {
        return terminate_layer(pcb, fsm, PPP_FSM_CLOSING);
    }

    return true;
}


/*
 * fsm_timeout - Timeout expired.
 */
bool
fsm_timeout(PppPcb& pcb, Fsm& fsm) {
    if (fsm.state == PPP_FSM_CLOSING || fsm.state == PPP_FSM_STOPPING) {
        if (fsm.retransmits <= 0) {
            if (fsm.state == PPP_FSM_CLOSING) {
                fsm.state = PPP_FSM_CLOSED;
            } else {
                fsm.state = PPP_FSM_STOPPED;
            }
            // todo: send finished callback notification
        } else {
            /* send terminate request */
            std::vector<uint8_t> data;
            data.reserve(fsm.term_reason.length());
            std::copy(fsm.term_reason.begin(), fsm.term_reason.end(), data.begin());
            fsm_send_data2(pcb, fsm, TERM_REQ, fsm.reqid = ++fsm.id, data);
            // todo: schedule timeout for fsm_timeout_time
            --fsm.retransmits;
        }
    }
    else if (fsm.state == PPP_FSM_REQSENT || fsm.state == PPP_FSM_ACKRCVD || fsm.state == PPP_FSM_ACKSENT) {
        if (fsm.retransmits <= 0) {
            fsm.state = PPP_FSM_STOPPED;
            if (fsm.options.passive) {
                // todo: call finished callback
            }
        } else {
            // todo: call retransmit callback
            if (!fsm_senc_conf_req(pcb, fsm, true)) {return false;}
            if (fsm.state == PPP_FSM_ACKRCVD) { fsm.state = PPP_FSM_REQSENT;}
        }
    }

    return true;
}


/*
 * fsm_input - Input packet.
 */
bool
fsm_input(PppPcb& pcb, Fsm& fsm, std::vector<uint8_t>& packet) {
    if (packet.size() < FSM_PKT_HDR_LEN) {
        return false;
    }

    /*
     * Parse header (code, id and length).
     * If packet too short, drop it.
     */
    bool ok = true;
    uint8_t code;
    uint8_t id;
    uint16_t len;
    size_t index = 0;
    std::tie(ok, code) = GETCHAR(packet, index);
    if (!ok) {
        return false;
    }

    std::tie(ok, id) = GETCHAR(packet, index);
    if (!ok) {return false;}

    std::tie(ok, len) = GETSHORT(packet, index);
    if (!ok) { return false;}

    if (len < FSM_PKT_HDR_LEN) {
        return false;
    }

    if (len > packet.size()) {
        return false;
    }

    len -= FSM_PKT_HDR_LEN;
    if (fsm.state == PPP_FSM_INITIAL || fsm.state == PPP_FSM_STARTING) { return false; }

    /*
     * Action depends on code.
     */
    switch (code) {
    case CONF_REQ: fsm_recv_conf_req(pcb, fsm, id, packet);
        break;
    case CONF_ACK: fsm_recv_conf_ack(pcb, fsm, id, packet);
        break;
    case CONF_NAK: case CONF_REJECT: fsm_recv_conf_nak_rej(pcb, fsm, code, id, packet);
        break;
    case TERM_REQ: fsm_recv_term_req(pcb, fsm, id, packet);
        break;
    case TERM_ACK: fsm_recv_term_ack(pcb, fsm);
        break;
    case CODE_REJECT: fsm_recv_code_rej(pcb, fsm, packet);
        break;
    default:
        // if (!fsm.callbacks->extcode || !(*fsm.callbacks->extcode
        // )(fsm, code, id, inp, len, fsm.pcb)) fsm_send_data2(
        //     ,
        //     fsm,
        //     CODEREJ,
        //     ++fsm.id,
        //     packet);
        //     todo: deal with extcode fsm callback
        break;
    }
    // todo: handle bool return values of  functions called above
    return true;
}


/**
 * Receive Configure-Request.
 */
bool
fsm_recv_conf_req(PppPcb& pcb, Fsm& f, uint8_t id, std::vector<uint8_t>& packet) {
    int code;

    std::vector<uint8_t> data;
    if (f.state == PPP_FSM_CLOSED) {
        fsm_send_data2(pcb, f, TERM_ACK, id, data);
        return true;
    } // todo: call appropriate reqci func
    if (f.state == PPP_FSM_CLOSING || f.state == PPP_FSM_STOPPING) {
        return true;
    }
    if (f.state == PPP_FSM_OPENED) {
        // todo: call down callback
        if (!fsm_senc_conf_req(pcb, f, false)) { return false;}
    }
    else if (f.state == PPP_FSM_STOPPED) {
        if (!fsm_senc_conf_req(pcb, f ,false)) { return false;}
        f.state = PPP_FSM_REQSENT;
    }

    // if (f->callbacks->reqci) {
    //     /* Check CI */
    //     int reject_if_disagree = (f->nakloops >= f->maxnakloops);
    //     code = (*f->callbacks->reqci)(f, packet, &len, reject_if_disagree, f->pcb);
    // }
    /*
     * Pass the requested configuration options
     * to protocol-specific code for checking.
     */
    if (packet.size()) {
        code = CONF_REJECT;
    }
    else {
        code = CONF_ACK;
    }
    fsm_send_data2(pcb, f, code, id, packet);
    if (code == CONF_ACK) {
        if (f.state == PPP_FSM_ACKRCVD) {
            // Untimeout(fsm_timeout, f); /* Cancel timeout */
            // todo: cancel fsm timeout
            f.state = PPP_FSM_OPENED;
            // if (f.callbacks->up) {
            //     (*f.callbacks->up)(f, f.pcb); /* Inform upper layers */
            // }
            // todo: call fsm up callback
        }
        else { f.state = PPP_FSM_ACKSENT; }
        f.nakloops = 0;
    }
    else {
        /* we sent CONFACK or CONFREJ */
        if (f.state != PPP_FSM_ACKRCVD) { f.state = PPP_FSM_REQSENT; }
        if (code == CONF_NAK) { ++f.nakloops; }
    }

    return true;
}


/*
 * fsm_rconfack - Receive Configure-Ack.
 */
bool
fsm_recv_conf_ack(PppPcb& pcb, Fsm& f, int id, std::vector<uint8_t> packet)
{
    if (id != f.reqid || f.seen_ack) {
        /* Expected id? */
        return false; /* Nope, toss... */
    }
    // if (!(f->callbacks->ackci
    //           ? (*f->callbacks->ackci)(f, packet, len, f->pcb)
    //           : (len == 0))) {
    //     /* Ack is bad - ignore it */
    //     ppp_error("Received bad configure-ack: %P", packet, len);
    //     return;
    // }
    // todo: call fsm ackci callback
    f.seen_ack = 1;
    f.rnakloops = 0;
    std::vector<uint8_t> data;
    switch (f.state) {
    case PPP_FSM_CLOSED: case PPP_FSM_STOPPED: fsm_send_data2(pcb, f, TERM_ACK, id, data);
        break;
    case PPP_FSM_REQSENT: f.state = PPP_FSM_ACKRCVD;
        f.retransmits = pcb.settings.fsm_max_conf_req_transmits;
        break;
    case PPP_FSM_ACKRCVD: /* Huh? an extra valid Ack? oh well... */
        // Untimeout(
        //     fsm_timeout,
        //     f); /* Cancel timeout */
        //     todo: cancel timeout
        if (!fsm_senc_conf_req(pcb, f, false)) { return false;}
        f.state = PPP_FSM_REQSENT;
        break;
    case PPP_FSM_ACKSENT:
        // Untimeout(fsm_timeout, f); /* Cancel timeout */
        // todo: cancel timeout
        f.state = PPP_FSM_OPENED;
        f.retransmits = pcb.settings.fsm_max_conf_req_transmits;
        // if (f.callbacks->up) {
        //     (*f.callbacks->up)(f, f.pcb); /* Inform upper layers */
        // }
        // todo: call up fsm callback
        break;
    case PPP_FSM_OPENED: /* Go down and restart negotiation */
        // if (f.callbacks->down) (*f.callbacks->down)(f, f, f.pcb); /* Inform upper layers */
        // todo: call fsm down callback
        if (!fsm_senc_conf_req(pcb, f, false)) {return false;} /* Send initial Configure-Request */
        f.state = PPP_FSM_REQSENT;
        break;
    default: break;
    }
    return true;
}


/*
 * fsm_rconfnakrej - Receive Configure-Nak or Configure-Reject.
 */
bool
fsm_recv_conf_nak_rej(PppPcb& pcb, Fsm& f, int code, int id, std::vector<uint8_t>& packet) {
    int ret;
    if (id != f.reqid || f.seen_ack) {
        /* Expected id? */
        return; /* Nope, toss... */
    }
    if (code == CONF_NAK) {
        ++f.rnakloops;
        int treat_as_reject = (f.rnakloops >= f.maxnakloops);
        // if (f.callbacks->nakci == nullptr || !(ret = f
        //                                               .callbacks->nakci(
        //                                                   f,
        //                                                   packet,
        //                                                   len,
        //                                                   treat_as_reject,
        //                                                   f.pcb))) {
        //     ppp_error("Received bad configure-nak: %P", packet, len);
        //     return;
        // }
        // todo: call nakci fsm callback
    }
    else {
        f.rnakloops = 0;
        // if (f.callbacks->rejci == nullptr || !(ret = f
        //                                               .callbacks->rejci(
        //                                                   f,
        //                                                   packet,
        //                                                   len,
        //                                                   f.pcb))) {
        //     ppp_error("Received bad configure-rej: %P", packet, len);
        //     return;
        // }
        // todo: call rejci fsm callback
    }

    f.seen_ack = 1;
    std::vector<uint8_t> data;
    switch (f.state) {

    case PPP_FSM_CLOSED: case PPP_FSM_STOPPED: fsm_send_data2(pcb, f, TERM_ACK, id, data);
        break;
    case PPP_FSM_REQSENT: case PPP_FSM_ACKSENT:
        // /* They didn't agree to what we wanted - try another request */ Untimeout(
        //     fsm_timeout,
        //     f); /* Cancel timeout */
        //     todo: cancel timeout
        if (ret < 0) {
            f.state = PPP_FSM_STOPPED; /* kludge for stopping CCP */
        }
        else {
            /* Send Configure-Request */
            if (!fsm_senc_conf_req(pcb, f, false)) { return false; }

        }
        break;
    case PPP_FSM_ACKRCVD:
        // /* Got a Nak/reject when we had already had an Ack?? oh well... */ Untimeout(
        //     fsm_timeout,
        //     f); /* Cancel timeout */
        //     todo: cancel fsm timeout
        if (!fsm_senc_conf_req(pcb, f, 0)) { return false;}
        f.state = PPP_FSM_REQSENT;
        break;
    case PPP_FSM_OPENED: /* Go down and restart negotiation */
        // if (f.callbacks->down) {
        //     (*f.callbacks->down)(f, f, f.pcb); /* Inform upper layers */
        // }
        // todo: call down fsm callback
        fsm_senc_conf_req(pcb, f, false); /* Send initial Configure-Request */
        f.state = PPP_FSM_REQSENT;
        break;
    default: break;
    }

    return true;
}


/**
 * Receive Terminate-Req.
 */
bool
fsm_recv_term_req(PppPcb& pcb, Fsm& f, int id, std::vector<uint8_t>& packet)
{
    switch (f.state) {
    case PPP_FSM_ACKRCVD: case PPP_FSM_ACKSENT: f.state = PPP_FSM_REQSENT;
        /* Start over but keep trying */
        break;
    case PPP_FSM_OPENED: if (packet.size() > 0) {
            // ppp_info("%s terminated by peer (%0.*v)",
            //          ((f).callbacks->proto_name),
            //          len,
            //          packet);
        }
        // else { ppp_info("%s terminated by peer", ((f).callbacks->proto_name)); }
        f.retransmits = 0;
        f.state = PPP_FSM_STOPPING;
        // if (f.callbacks->down) {
        //     (*f.callbacks->down)(f, f, f.pcb); /* Inform upper layers */
        // }
        // todo: call down fsm callback
        // Timeout(fsm_timeout, f, pcb->settings.fsm_timeout_time);
        // todo: set timeout
        break;
    default: break;
    }
    std::vector<uint8_t> data;
    fsm_send_data2(pcb, f, TERM_ACK, id, data);
    return true;
}


/*
 * fsm_rtermack - Receive Terminate-Ack.
 */
bool
fsm_recv_term_ack(PppPcb& pcb, Fsm& f) {
    switch (f.state) {
    case PPP_FSM_CLOSING:
        // Untimeout(fsm_timeout, f);
        // todo: un-register fsm timeout
        f.state = PPP_FSM_CLOSED;
        // if (f.callbacks->finished) (*f.callbacks->finished)(f);
        // todo: call fsm finished callback
        break;
    case PPP_FSM_STOPPING:
        // Untimeout(fsm_timeout, f);
        // todo: un-register timeout
        f.state = PPP_FSM_STOPPED;
        // if (f.callbacks->finished) { (*f.callbacks->finished)(f); }
        // todo: call fsm finished callback
        break;
    case PPP_FSM_ACKRCVD: f.state = PPP_FSM_REQSENT;
        break;
    case PPP_FSM_OPENED:
        // if (f.callbacks->down) {
        //     (*f.callbacks->down)(f, f, f.pcb); /* Inform upper layers */
        // }
        // todo: call fsm down callback
        fsm_senc_conf_req(pcb, f, false);
        f.state = PPP_FSM_REQSENT;
        break;
    default: break;
    }

    return true;
}


/*
 * fsm_rcoderej - Receive an Code-Reject.
 */
bool
fsm_recv_code_rej(PppPcb& pcb, Fsm& f, std::vector<uint8_t> packet)
{
    uint8_t code;
    uint8_t id;
    bool ok = true;
    size_t index = 0;
    if (packet.size() < FSM_PKT_HDR_LEN) {
        // FSMDEBUG(("fsm_rcoderej: Rcvd short Code-Reject packet!"));
        return false;
    }
    std::tie(ok, code) = GETCHAR(packet, index);
    if (!ok) { return false;}
    std::tie(ok, id) = GETCHAR(packet, index);
    if (!ok) { return false;}
    // ppp_warn("%s: Rcvd Code-Reject for code %d, id %d",
    //          ((f)->callbacks->proto_name),
    //          code,
    //          id);
    if (f.state == PPP_FSM_ACKRCVD) { f.state = PPP_FSM_REQSENT; }
    return true;
}


/*
 * fsm_protreject - Peer doesn't speak this protocol.
 *
 * Treat this as a catastrophic error (RXJ-).
 */
bool
fsm_proto_rej(PppPcb& pcb, Fsm& f)
{
    switch (f.state) {
    case PPP_FSM_CLOSING:
        // Untimeout(fsm_timeout, f); /* Cancel timeout */
        // todo: cancel timeout
        /* fall through */ /* no break */
    case PPP_FSM_CLOSED: f.state = PPP_FSM_CLOSED;
        // if (f.callbacks->finished) { (*f.callbacks->finished)(f); }
        // todo: call finished callback
        break;
    case PPP_FSM_STOPPING: case PPP_FSM_REQSENT: case PPP_FSM_ACKRCVD:
    case PPP_FSM_ACKSENT:
        // Untimeout(fsm_timeout, f); /* Cancel timeout */
        // todo: cancel timeout
        /* fall through */ /* no break */
    case PPP_FSM_STOPPED: f.state = PPP_FSM_STOPPED;
        // if (f.callbacks->finished) { (*f.callbacks->finished)(f); }
        // todo: call finished callback
        break;
    case PPP_FSM_OPENED:
        if (!terminate_layer(pcb, f, PPP_FSM_STOPPING)) { return false; }
        break;
    default: ; // default:
        // auto a = true; // FSMDEBUG(("%s: Protocol-reject event in state %d!",
        // 	  PROTO_NAME(f), f->state));
        /* no break */
    }
    return true;
}


/*
 * fsm_sconfreq - Send a Configure-Request.
 */
bool
fsm_senc_conf_req(PppPcb& pcb, Fsm& f, bool retransmit) {
    size_t cilen;
    if (f.state != PPP_FSM_REQSENT && f.state != PPP_FSM_ACKRCVD && f.state !=
        PPP_FSM_ACKSENT) {
        /* Not currently negotiating - reset options */ // if( f.callbacks->resetci )
        //     (*f.callbacks->resetci)(f, f.pcb);
        //     todo: call appropriate resetci function
        f.nakloops = 0;
        f.rnakloops = 0;
    }
    if (!retransmit) {
        /* New request - reset retransmission counter, use new ID */
        f.retransmits = pcb.settings.fsm_max_conf_req_transmits;
        f.reqid = ++f.id;
    }

    f.seen_ack = 0;

    /*
     * Make up the request packet
     */
    // if( f.callbacks->cilen && f.callbacks->addci ){
    // cilen = (*f.callbacks->cilen)(f.pcb);
    // if( cilen > pcb.peer_mru - FSM_PKT_HDR_LEN )
    //     cilen = pcb.peer_mru - FSM_PKT_HDR_LEN;
    // } else
    // todo: perform same function as callbacks->cilen and callbacks->addci
    cilen = 0;

    // p = pbuf_alloc(PBUF_RAW, (uint16_t)(cilen + kHeaderlen + PPP_HDRLEN), PPP_CTRL_PBUF_TYPE);
    PacketContainer p = init_pkt_buf()
    p.data.reserve(cilen + 40 + 60 + PPP_HDRLEN + 1500);

    /* send the request to our peer */
    // uint8_t* outp = static_cast<uint8_t*>(p->payload.data());
    size_t index = 0;
    ppp_put_char(PPP_ALLSTATIONS, p.data, index);
    ppp_put_char(PPP_UI, p.data, index);
    ppp_put_short(f.protocol, p.data, index);
    ppp_put_char(CONF_REQ, p.data, index);
    ppp_put_char(f.reqid, p.data, index);
    ppp_put_short(cilen + FSM_PKT_HDR_LEN, p.data, index);
    // if (cilen != 0) {
    // (*f.callbacks->addci)(f, outp, &cilen, f.pcb);
    // lwip_assert("cilen == p->len - kHeaderlen - PPP_HDRLEN", cilen == p->len - FSM_PKT_HDR_LEN - PPP_HDRLEN);
    // }
    // todo: call f.callbacks->addci

    if (! ppp_write(pcb, p)) {
        return false;
    }

    /* start the retransmit timer */
    --f.retransmits;
    // Timeout(fsm_timeout, f, pcb.settings.fsm_timeout_time);
    // todo: call fsm timeout function to check for timeout
}


/*
 * fsm_sdata - Send some data.
 *
 * Used for all packets sent to our peer by this module.
 */
bool
fsm_send_data2(PppPcb& pcb, Fsm& f, uint8_t code, uint8_t id, std::vector<uint8_t>& data)
{

    if (data.size() > pcb.peer_mru - FSM_PKT_HDR_LEN) {
        // datalen = pcb.peer_mru - FSM_PKT_HDR_LEN;
    }
    size_t outlen = data.size() + FSM_PKT_HDR_LEN;
    // p = pbuf_alloc(PBUF_RAW, (uint16_t)(outlen + PPP_HDRLEN), PPP_CTRL_PBUF_TYPE);
    PacketContainer p = init_pkt_buf()
    p.data.reserve(data.size() + FSM_PKT_HDR_LEN);
    // todo: reserve size for packet
    size_t index = 0;
    ppp_make_header(p.data, f.protocol);
    ppp_put_char(code, p.data, index);
    ppp_put_char(id, p.data, index);
    ppp_put_short(outlen, p.data, index);
    // if (datalen) {
    //     /* && data != outp + PPP_HDRLEN + kHeaderlen)  -- was only for fsm_sconfreq() */
    //     memcpy(outp + PPP_HDRLEN + FSM_PKT_HDR_LEN, data, datalen);
    // }
    ppp_write(pcb, p);
}

//
// END OF FILE
//
