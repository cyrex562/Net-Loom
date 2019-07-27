/*
 * upap.c - User/Password Authentication Protocol.
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

#include <ppp_opts.h>

/*
 * @todo:
 */


#include <ppp_impl.h>

#include <upap.h>

/*
 * Protocol entry points.
 */
static void upap_init(PppPcb *pcb);
static void upap_lowerup(PppPcb *pcb);
static void upap_lowerdown(PppPcb *pcb);
static void upap_input(PppPcb *pcb, uint8_t *inpacket, int l);
static void upap_protrej(PppPcb *pcb);

// const struct protent pap_protent = {
//     PPP_PAP,
//     upap_init,
//     upap_input,
//     upap_protrej,
//     upap_lowerup,
//     upap_lowerdown,
//     NULL,
//     NULL,
//
//
//
//
// };

static void upap_timeout(void* arg);

static void upap_reqtimeout(void* arg);
static void upap_rauthreq(PppPcb *pcb, uint8_t *inp, int id, int len);

static void upap_rauthack(PppPcb *pcb, uint8_t *inp, int id, int len);
static void upap_rauthnak(PppPcb *pcb, uint8_t *inp, int id, int len);
static void upap_sauthreq(PppPcb *pcb);





/*
 * upap_init - Initialize a UPAP unit.
 */
static void upap_init(PppPcb *pcb) {
    pcb->upap.us_user = nullptr;
    // pcb->upap.us_userlen = 0;
    pcb->upap.us_passwd = nullptr;
    // pcb->upap.us_passwdlen = 0;
    pcb->upap.us_clientstate = UPAPCS_INITIAL;

    pcb->upap.us_serverstate = UPAPSS_INITIAL;

    pcb->upap.us_id = 0;
}


/*
 * upap_authwithpeer - Authenticate us with our peer (start client).
 *
 * Set new state and send authenticate's.
 */
void upap_authwithpeer(PppPcb *pcb, std::string& user, std::string& password) {
    if (user.empty() || password.empty())
    {
        return;
    }

    /* Save the username and password we're given */
    pcb->upap.us_user = user;
    // pcb->upap.us_userlen = (uint8_t)std::min(strlen(user), 0xff);
    pcb->upap.us_passwd = password;
    // pcb->upap.us_passwdlen = (uint8_t)std::min(strlen(password), 0xff);
    pcb->upap.us_transmits = 0;

    /* Lower layer up yet? */
    if (pcb->upap.us_clientstate == UPAPCS_INITIAL ||
    pcb->upap.us_clientstate == UPAPCS_PENDING) {
    pcb->upap.us_clientstate = UPAPCS_PENDING;
    return;
    }

    upap_sauthreq(pcb);		/* Start protocol */
}


/*
 * upap_authpeer - Authenticate our peer (start server).
 *
 * Set new state.
 */
void upap_authpeer(PppPcb *pcb) {

    /* Lower layer up yet? */
    if (pcb->upap.us_serverstate == UPAPSS_INITIAL ||
    pcb->upap.us_serverstate == UPAPSS_PENDING) {
    pcb->upap.us_serverstate = UPAPSS_PENDING;
    return;
    }

    pcb->upap.us_serverstate = UPAPSS_LISTEN;
    if (pcb->settings.pap_req_timeout > 0)
    {
        Timeout(upap_reqtimeout, pcb, pcb->settings.pap_req_timeout);
    }
}


/*
 * upap_timeout - Retransmission timer for sending auth-reqs expired.
 */
static void upap_timeout(void* arg) {
    auto pcb = static_cast<PppPcb*>(arg);

    if (pcb->upap.us_clientstate != UPAPCS_AUTHREQ)
    return;

    if (pcb->upap.us_transmits >= pcb->settings.pap_max_transmits) {
    /* give up in disgust */
    ppp_error("No response to PAP authenticate-requests");
    pcb->upap.us_clientstate = UPAPCS_BADAUTH;
    auth_withpeer_fail(pcb, PPP_PAP);
    return;
    }

    upap_sauthreq(pcb);		/* Send Authenticate-Request */
}



/*
 * upap_reqtimeout - Give up waiting for the peer to send an auth-req.
 */
static void upap_reqtimeout(void* arg) {
    auto pcb = (PppPcb*)arg;

    if (pcb->upap.us_serverstate != UPAPSS_LISTEN)
    {
        return;			/* huh?? */
    }
    auth_peer_fail(pcb, PPP_PAP);
    pcb->upap.us_serverstate = UPAPSS_BADAUTH;
}



/*
 * upap_lowerup - The lower layer is up.
 *
 * Start authenticating if pending.
 */
static void upap_lowerup(PppPcb *pcb) {

    if (pcb->upap.us_clientstate == UPAPCS_INITIAL)
    {
        pcb->upap.us_clientstate = UPAPCS_CLOSED;
    }
    else if (pcb->upap.us_clientstate == UPAPCS_PENDING) {
    upap_sauthreq(pcb);	/* send an auth-request */
    }


    if (pcb->upap.us_serverstate == UPAPSS_INITIAL)
    pcb->upap.us_serverstate = UPAPSS_CLOSED;
    else if (pcb->upap.us_serverstate == UPAPSS_PENDING) {
    pcb->upap.us_serverstate = UPAPSS_LISTEN;
    if (pcb->settings.pap_req_timeout > 0)
    {
        Timeout(upap_reqtimeout, pcb, pcb->settings.pap_req_timeout);
    }
    }

}


/*
 * upap_lowerdown - The lower layer is down.
 *
 * Cancel all timeouts.
 */
static void upap_lowerdown(PppPcb *pcb) {

    if (pcb->upap.us_clientstate == UPAPCS_AUTHREQ)	/* Timeout pending? */
    Untimeout(upap_timeout, pcb);		/* Cancel timeout */

    if (pcb->upap.us_serverstate == UPAPSS_LISTEN && pcb->settings.pap_req_timeout > 0)
    {
        Untimeout(upap_reqtimeout, pcb);
    }
    pcb->upap.us_clientstate = UPAPCS_INITIAL;

    pcb->upap.us_serverstate = UPAPSS_INITIAL;

}


/*
 * upap_protrej - Peer doesn't speak this protocol.
 *
 * This shouldn't happen.  In any case, pretend lower layer went down.
 */
static void upap_protrej(PppPcb *pcb) {

    if (pcb->upap.us_clientstate == UPAPCS_AUTHREQ) {
    ppp_error("PAP authentication failed due to protocol-reject");
    auth_withpeer_fail(pcb, PPP_PAP);
    }

    if (pcb->upap.us_serverstate == UPAPSS_LISTEN) {
    ppp_error("PAP authentication of peer failed (protocol-reject)");
    auth_peer_fail(pcb, PPP_PAP);
    }

    upap_lowerdown(pcb);
}


/*
 * upap_input - Input UPAP packet.
 */
static void upap_input(PppPcb *pcb, uint8_t *inpacket, int l) {
    uint8_t code, id;
    int len;

    /*
     * Parse header (code, id and length).
     * If packet too short, drop it.
     */
    uint8_t* inp = inpacket;
    if (l < UPAP_HEADERLEN) {
    // UPAPDEBUG(("pap_input: rcvd short header."));
    return;
    }
    GETCHAR(code, inp);
    GETCHAR(id, inp);
    GETSHORT(len, inp);
    if (len < UPAP_HEADERLEN) {
    // UPAPDEBUG(("pap_input: rcvd illegal length."));
    return;
    }
    if (len > l) {
    // UPAPDEBUG(("pap_input: rcvd short packet."));
    return;
    }
    len -= UPAP_HEADERLEN;

    /*
     * Action depends on code.
     */
    switch (code) {
    case UPAP_AUTHREQ:

    upap_rauthreq(pcb, inp, id, len);

    break;

    case UPAP_AUTHACK:
    upap_rauthack(pcb, inp, id, len);
    break;

    case UPAP_AUTHNAK:
    upap_rauthnak(pcb, inp, id, len);
    break;

    default:				/* XXX Need code reject */
    break;
    }
}


/*
 * upap_rauth - Receive Authenticate.
 */
static void upap_rauthreq(PppPcb *pcb, uint8_t *inp, int id, int len) {
    uint8_t ruserlen, rpasswdlen;
    std::string rhostname;
    std::string msg;
    int msglen;

    if (pcb->upap.us_serverstate < UPAPSS_LISTEN)
    {
        return;
    } /*
     * If we receive a duplicate authenticate-request, we are
     * supposed to return the same status as for the first request.
     */
    std::string empty_str = "";
    if (pcb->upap.us_serverstate == UPAPSS_OPEN)
    {
        upap_sresp(pcb, UPAP_AUTHACK, id, empty_str); /* return auth-ack */
        return;
    }
    if (pcb->upap.us_serverstate == UPAPSS_BADAUTH)
    {
        upap_sresp(pcb, UPAP_AUTHNAK, id, empty_str); /* return auth-nak */
        return;
    }

    /*
     * Parse user/passwd.
     */
    if (len < 1) {
    // UPAPDEBUG(("pap_rauth: rcvd short packet."));
    return;
    }
    GETCHAR(ruserlen, inp);
    len -= sizeof (uint8_t) + ruserlen + sizeof (uint8_t);
    if (len < 0) {
    // UPAPDEBUG(("pap_rauth: rcvd short packet."));
    return;
    }
    std::string ruser = (char *)inp;
    INCPTR(ruserlen, inp);
    GETCHAR(rpasswdlen, inp);
    if (len < rpasswdlen) {
    // UPAPDEBUG(("pap_rauth: rcvd short packet."));
    return;
    }

    std::string rpasswd = (char *)inp;

    /*
     * Check the username and password given.
     */
    int retcode = UPAP_AUTHNAK;
    if (auth_check_passwd(pcb, ruser, rpasswd, msg)) {
      retcode = UPAP_AUTHACK;
    }
    // BZERO(rpasswd, rpasswdlen);

    upap_sresp(pcb, retcode, id, msg);

    /* Null terminate and clean remote name. */
    // ppp_slprintf(rhostname, sizeof(rhostname), "%.*v", ruserlen, ruser);
    rhostname = ruser;


    if (retcode == UPAP_AUTHACK) {
    pcb->upap.us_serverstate = UPAPSS_OPEN;
    ppp_notice("PAP peer authentication succeeded for %q", rhostname);
    auth_peer_success(pcb, PPP_PAP, 0, ruser);
    } else {
    pcb->upap.us_serverstate = UPAPSS_BADAUTH;
    ppp_warn("PAP peer authentication failed for %q", rhostname);
    auth_peer_fail(pcb, PPP_PAP);
    }

    if (pcb->settings.pap_req_timeout > 0)
    {
        Untimeout(upap_reqtimeout, pcb);
    }
}


/*
 * upap_rauthack - Receive Authenticate-Ack.
 */
static void upap_rauthack(PppPcb *pcb, uint8_t *inp, int id, int len) {
    uint8_t msglen;
    if (pcb->upap.us_clientstate != UPAPCS_AUTHREQ)
    {
        /* XXX */
    return;
    } /*
     * Parse message.
     */
    if (len < 1) {
    // UPAPDEBUG(("pap_rauthack: ignoring missing msg-length."));
    } else {
    GETCHAR(msglen, inp);
    if (msglen > 0) {
        len -= sizeof (uint8_t);
        if (len < msglen) {
        // UPAPDEBUG(("pap_rauthack: rcvd short packet."));
        return;
        }
        char* msg = (char *)inp;
        PRINTMSG(msg, msglen);
    }
    }

    pcb->upap.us_clientstate = UPAPCS_OPEN;

    auth_withpeer_success(pcb, PPP_PAP, 0);
}


/*
 * upap_rauthnak - Receive Authenticate-Nak.
 */
static void upap_rauthnak(PppPcb *pcb, uint8_t *inp, int id, int len) {
    uint8_t msglen;
    if (pcb->upap.us_clientstate != UPAPCS_AUTHREQ)
    {
        /* XXX */
    return;
    } /*
     * Parse message.
     */
    if (len < 1) {
    // UPAPDEBUG(("pap_rauthnak: ignoring missing msg-length."));
    } else {
    GETCHAR(msglen, inp);
    if (msglen > 0) {
        len -= sizeof (uint8_t);
        if (len < msglen) {
        // UPAPDEBUG(("pap_rauthnak: rcvd short packet."));
        return;
        }
        char* msg = (char *)inp;
        PRINTMSG(msg, msglen);
    }
    }

    pcb->upap.us_clientstate = UPAPCS_BADAUTH;

    ppp_error("PAP authentication failed");
    auth_withpeer_fail(pcb, PPP_PAP);
}


/*
 * upap_sauthreq - Send an Authenticate-Request.
 */
static void upap_sauthreq(PppPcb *pcb) {
    int outlen = UPAP_HEADERLEN + 2 * sizeof(uint8_t) + pcb->upap.us_user.length() + pcb->upap.
                                                                                    us_passwd.length();
    PacketBuffer* p = pbuf_alloc(PBUF_RAW, (uint16_t)(PPP_HDRLEN + outlen));
    if(nullptr == p)
    {
        return;
    }
    if(p->tot_len != p->len) {
        free_pkt_buf(p);
        return;
    }

    uint8_t* outp = (uint8_t*)p->payload;
    MAKEHEADER(outp, PPP_PAP);

    PUTCHAR(UPAP_AUTHREQ, outp);
    PUTCHAR(++pcb->upap.us_id, outp);
    PUTSHORT(outlen, outp);
    PUTCHAR(pcb->upap.us_user.length(), outp);
    memcpy(outp, pcb->upap.us_user.c_str(), pcb->upap.us_user.length());
    // INCPTR(pcb->upap.us_userlen, outp);
    // PUTCHAR(pcb->upap.us_passwdlen, outp);
    memcpy(outp, pcb->upap.us_passwd.c_str(), pcb->upap.us_passwd.length());

    ppp_write(pcb, p);

    Timeout(upap_timeout, pcb, pcb->settings.pap_timeout_time);
    ++pcb->upap.us_transmits;
    pcb->upap.us_clientstate = UPAPCS_AUTHREQ;
}
/*
 * upap_sresp - Send a response (ack or nak).
 */
static void upap_sresp(PppPcb *pcb, uint8_t code, uint8_t id, std::string& msg) {
    int outlen = UPAP_HEADERLEN + sizeof(uint8_t) + msg.length();
    PacketBuffer* p = pbuf_alloc(PBUF_RAW, (uint16_t)(PPP_HDRLEN + outlen));
    if(nullptr == p)
    {
        return;
    }
    if(p->tot_len != p->len) {
        free_pkt_buf(p);
        return;
    }

    uint8_t* outp = (uint8_t*)p->payload;
    MAKEHEADER(outp, PPP_PAP);

    PUTCHAR(code, outp);
    PUTCHAR(id, outp);
    PUTSHORT(outlen, outp);
    PUTCHAR(msg.length(), outp);
    memcpy(outp, msg.c_str(), msg.length());
    ppp_write(pcb, p);
}

//
//
//