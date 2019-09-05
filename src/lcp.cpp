/**
 * lcp.cpp
 */


#define NOMINMAX
#include "lcp.h"
#include "ppp_opts.h"
#include "fsm.h"
#include "chap_new.h"
#include "magic.h"
#include "auth.h"
#include <algorithm>
#include "util.h"
#include "ppp.h"
#include "lcp_options.h"


/*
 * lcp_init - Initialize LCP.
 */
void lcp_init(PppPcb& pcb) {
    Fsm f = pcb.lcp_fsm;
    LcpOptions wo = pcb.lcp_wantoptions;
    LcpOptions ao = pcb.lcp_allowoptions;

    // f->pcb = pcb;
    f.protocol = PPP_LCP;
    // f->callbacks = &lcp_callbacks;

    fsm_init(f, pcb);

    zero_mem(&wo, sizeof(LcpOptions));
    wo.neg_mru = true;
    wo.mru = PPP_DEFMRU;
    wo.neg_asyncmap = true;
    wo.neg_magicnumber = true;
    wo.neg_pcompression = true;
    wo.neg_accompression = true;

    zero_mem(&ao, sizeof(LcpOptions));
    ao.neg_mru = true;
    ao.mru = PPP_MAXMRU;
    ao.neg_asyncmap = true;

    ao.neg_chap = true;
    ao.chap_mdtype = MDTYPE_NONE;

    ao.neg_upap = true;

    ao.neg_eap = true;

    ao.neg_magicnumber = true;
    ao.neg_pcompression = true;
    ao.neg_accompression = true;
    ao.neg_endpoint = true;
}


/**
 * LCP is allowed to come up.
 */
bool
lcp_open(PppPcb& pcb) {
    pcb.lcp_fsm.options.passive = false;
    pcb.lcp_fsm.options.silent = false;
    if(pcb.lcp_wantoptions.passive)
    {
        pcb.lcp_fsm.options.passive = true;
    }

    if (pcb.lcp_wantoptions.silent)
    {
        pcb.lcp_fsm.options.silent = true;
    }
    return fsm_open(pcb, pcb.lcp_fsm);
}


/*
 *  Take LCP down.
 */
bool
lcp_close(PppPcb& pcb, std::string& reason) {
    Fsm f = pcb.lcp_fsm;
    if (pcb.phase != PPP_PHASE_DEAD && pcb.phase != PPP_PHASE_MASTER)
    {
        new_phase(pcb, PPP_PHASE_TERMINATE);
    }
    if (f.options.delayed_up)
    {
        // Untimeout(lcp_delayed_up, f);
        // todo: remove lcp_delayed_up timer
        f.state = PPP_FSM_STOPPED;
    }
    PppFsmLinkState oldstate = f.state;

    if(!fsm_close(pcb, pcb.lcp_fsm, reason))
    {
        return false;
    }

    if (oldstate == PPP_FSM_STOPPED && (f.options.passive || f.options.silent || f.options.delayed_up)) {
    /*
     * This action is not strictly according to the FSM in RFC1548,
     * but it does mean that the program terminates if you do a
     * lcp_close() when a connection hasn't been established
     * because we are in passive/silent mode or because we have
     * delayed the fsm_lowerup() call and it hasn't happened yet.
     */
    f.options.delayed_up = false;
    lcp_finished(f,);
    }
}


/**
 * The lower layer is up.
 */
bool
lcp_lowerup(PppPcb& pcb)
{
    LcpOptions wo = pcb.lcp_wantoptions;
    Fsm f = pcb.lcp_fsm; /*
     * Don't use A/C or protocol compression on transmission,
     * but accept A/C and protocol compressed packets
     * if we are going to ask for A/C and protocol compression.
     */
    if (ppp_send_config(pcb, PPP_MRU, 0xffffffff, 0, 0) < 0 || ppp_recv_config(
        pcb,
        PPP_MRU,
        (pcb.settings.lax_recv ? 0 : 0xffffffff),
        wo.neg_pcompression,
        wo.neg_accompression) < 0) { return; }
    pcb.peer_mru = PPP_MRU;
    if (pcb.settings.listen_time != 0)
    {
        f.options.delayed_up = true;
        // timeout_ms(lcp_delayed_up, f, pcb.settings.listen_time);
    }
    else
    {
        return fsm_lowerup(pcb, f);
    }
    return true;
}


/**
 * The lower layer is down.
 */
bool
lcp_lowerdown(PppPcb& pcb)
{
    Fsm f = pcb.lcp_fsm;
    if (f.options.delayed_up)
    {
        f.options.delayed_up = false; // Untimeout(lcp_delayed_up, f);
    }
    else
    {
        return fsm_lowerdown(f);
    }
    return true;
}


/**
 * Bring the lower layer up now.
 */
bool
lcp_delayed_up(PppPcb& pcb)
{
    Fsm f = pcb.lcp_fsm;
    if (f.options.delayed_up)
    {
        f.options.delayed_up = false;
        return fsm_lowerup(pcb, pcb.lcp_fsm);
    }
    return true;
}


/**
 * Input LCP packet.
 */
bool
lcp_input(PppPcb& pcb,
          std::vector<uint8_t>& pkt)
{
    Fsm f = pcb.lcp_fsm;
    if (f.options.delayed_up)
    {
        f.options.delayed_up = false; // Untimeout(lcp_delayed_up, f);
        if (!fsm_lowerup(pcb, f)) { return false; }
    }
    return fsm_input(pcb, f, pkt);
}


/**
 * Handle a LCP-specific code.
 */
bool
lcp_extcode(PppPcb& pcb, Fsm& f, int code, int id, std::vector<uint8_t>& pkt)
{
    // PppPcb pcb = f.pcb;
    LcpOptions go = pcb.lcp_gotoptions;
    std::vector<uint8_t> magp;
    size_t index = 0;
    switch (code)
    {
    case PROTREJ:
        lcp_rprotrej(f, pkt, len);
        break;
    case ECHOREQ:
        if (f.state != PPP_FSM_OPENED)
            break;
        magp = pkt;
        PUTLONG(go.magicnumber, magp, index);
        if (!fsm_send_data2(pcb, f, ECHOREP, id, pkt))
        {
            return false;
        }
        break;
    case ECHOREP:
        lcp_received_echo_reply(f, id, pkt, len);
        break;
    case DISCREQ: case IDENTIF: case TIMEREM:
        break;
    default:
        return false;
    }
    return true;
}


/*
 * lcp_rprotrej - Receive an Protocol-Reject.
 *
 * Figure out which protocol is rejected and inform it.
 */
void lcp_rprotrej(Fsm *f, uint8_t *inp, int len) {
    int i;
    // const struct protent *protp;
    u_short prot;
    if (len < 2) {
    return;
    }

    GETSHORT(prot, inp);

    /*
     * Protocol-Reject packets received in any state other than the LCP
     * OPENED state SHOULD be silently discarded.
     */
    if( f->state != PPP_FSM_OPENED ){
    return;
    }


    const char* pname = protocol_name(prot);


    /*
     * Upcall the proper Protocol-Reject routine.
     */
    // for (i = 0; (protp = protocols[i]) != NULL; ++i)
    // if (protp->protocol == prot) {
    //
    //     if (pname != nullptr)
    // 	ppp_dbglog("Protocol-Reject for '%s' (0x%x) received", pname,
    // 	       prot);
    //     else
    //
    // 	ppp_dbglog("Protocol-Reject for 0x%x received", prot);
    //     (*protp->protrej)(f->pcb);
    //     return;
    // }


    if (pname != nullptr)
    ppp_warn("Protocol-Reject for unsupported protocol '%s' (0x%x)", pname,
         prot);
    else
    {
        ppp_warn("Protocol-Reject for unsupported protocol 0x%x", prot);
    }
}


/*
 * lcp_protrej - A Protocol-Reject was received.
 */
/*ARGSUSED*/
void lcp_protrej(PppPcb *pcb) {
    /*
     * Can't reject LCP!
     */
    ppp_error("Received Protocol-Reject for LCP!");
    fsm_proto_rej(, &pcb->lcp_fsm);
}


/*
 * lcp_sprotrej - Send a Protocol-Reject for some protocol.
 */
void lcp_sprotrej(PppPcb *pcb, uint8_t *p, int len) {
    Fsm *f = &pcb->lcp_fsm;
    /*
     * Send back the protocol and the information field of the
     * rejected packet.  We only get here if LCP is in the OPENED state.
     */


    fsm_send_data(, f, PROTREJ,
                ++f->id, p);
}


/*
 * lcp_resetci - Reset our CI.
 */
void lcp_resetci(Fsm *f) {
    PppPcb *pcb = f->pcb;
    LcpOptions *wo = &pcb->lcp_wantoptions;
    LcpOptions *go = &pcb->lcp_gotoptions;
    LcpOptions *ao = &pcb->lcp_allowoptions;



    /* note: default value is true for allow options */
    if (!pcb->settings.user.empty() && !pcb->settings.passwd.empty()) {

      if (pcb->settings.refuse_pap) {
        ao->neg_upap = false;
      }

      if (pcb->settings.refuse_chap) {
        // ao->chap_mdtype &= ~MDTYPE_MD5;
      }

      if (pcb->settings.refuse_mschap) {
        // ao->chap_mdtype &= ~MDTYPE_MICROSOFT;
      }
      if (pcb->settings.refuse_mschap_v2) {
        // ao->chap_mdtype &= ~MDTYPE_MICROSOFT_V2;
      }

      ao->neg_chap = (ao->chap_mdtype != MDTYPE_NONE);

      if (pcb->settings.refuse_eap) {
        ao->neg_eap = false;
      }

      /* note: default value is false for wanted options */
      if (pcb->settings.auth_required) {

        if (!pcb->settings.refuse_pap) {
          wo->neg_upap = true;
        }

        if (!pcb->settings.refuse_chap) {
          wo->chap_mdtype = MDTYPE_MD5;
        }

        if (!pcb->settings.refuse_mschap) {
          wo->chap_mdtype = MDTYPE_MICROSOFT;
        }
        if (!pcb->settings.refuse_mschap_v2) {
          wo->chap_mdtype = MDTYPE_MICROSOFT_V2;
        }

        wo->neg_chap = (wo->chap_mdtype != MDTYPE_NONE);

        if (!pcb->settings.refuse_eap) {
          wo->neg_eap = true;
        }

      }


    } else {

      ao->neg_upap = false;

      ao->neg_chap = false;
      ao->chap_mdtype = MDTYPE_NONE;


      ao->neg_eap = false;

    }

    // PPPDEBUG(LOG_DEBUG, ("ppp: auth protocols:"));
    //
    // PPPDEBUG(LOG_DEBUG, (" PAP=%d", ao->neg_upap));
    //
    // PPPDEBUG(LOG_DEBUG, (" CHAP=%d CHAP_MD5=%d", ao->neg_chap, !!(ao->chap_mdtype&MDTYPE_MD5)));
    //
    // PPPDEBUG(LOG_DEBUG, (" CHAP_MS=%d CHAP_MS2=%d", !!(ao->chap_mdtype&MDTYPE_MICROSOFT), !!(ao->chap_mdtype&MDTYPE_MICROSOFT_V2)));
    //
    // PPPDEBUG(LOG_DEBUG, (" EAP=%d", ao->neg_eap));
    //
    // PPPDEBUG(LOG_DEBUG, ("\n"));



    wo->magicnumber = magic();
    wo->numloops = 0;
    *go = *wo;

    if (!multilink) {
    go->neg_mrru = false;

    go->neg_ssnhf = false;
    go->neg_endpoint = false;

    }

    if (pcb->settings.noendpoint)
    {
        ao->neg_endpoint = false;
    }
    pcb->peer_mru = PPP_MRU;

}


/*
 * lcp_cilen - Return length of our CI.
 */
static int lcp_cilen(Fsm *f) {
    PppPcb *pcb = f->pcb;
    LcpOptions *go = &pcb->lcp_gotoptions;

#define LENCIVOID(neg)	((neg) ? CILEN_VOID : 0)

#define LENCICHAP(neg)	((neg) ? CILEN_CHAP : 0)

#define LENCISHORT(neg)	((neg) ? CILEN_SHORT : 0)
#define LENCILONG(neg)	((neg) ? CILEN_LONG : 0)

#define LENCILQR(neg)	((neg) ? CILEN_LQR: 0)

#define LENCICBCP(neg)	((neg) ? CILEN_CBCP: 0)
    /*
     * NB: we only ask for one of CHAP, UPAP, or EAP, even if we will
     * accept more than one.  We prefer EAP first, then CHAP, then
     * PAP.
     */
    return (LENCISHORT(go->neg_mru && go->mru != PPP_DEFMRU) +
        LENCILONG(go->neg_asyncmap && go->asyncmap != 0xFFFFFFFF) +

        LENCISHORT(go->neg_eap) +

        LENCICHAP(!go->neg_eap && go->neg_chap) +

        LENCISHORT(!go->neg_eap && !go->neg_chap && go->neg_upap) +

        LENCILQR(go->neg_lqr) +

        LENCICBCP(go->neg_cbcp) +
        LENCILONG(go->neg_magicnumber) +
        LENCIVOID(go->neg_pcompression) +
        LENCIVOID(go->neg_accompression) +

        LENCISHORT(go->neg_mrru) +

        LENCIVOID(go->neg_ssnhf) +
        (go->neg_endpoint? CILEN_CHAR + go->endpoint.length: 0));
}


/*
 * lcp_addci - Add our desired CIs to a packet.
 */
void lcp_addci(Fsm *f, uint8_t *ucp, int *lenp) {
    PppPcb *pcb = f->pcb;
    LcpOptions *go = &pcb->lcp_gotoptions;
    uint8_t *start_ucp = ucp;

#define ADDCIVOID(opt, neg) \
    if (neg) { \
    PUTCHAR(opt, ucp); \
    PUTCHAR(CILEN_VOID, ucp); \
    }
#define ADDCISHORT(opt, neg, val) \
    if (neg) { \
    PUTCHAR(opt, ucp); \
    PUTCHAR(CILEN_SHORT, ucp); \
    PUTSHORT(val, ucp); \
    }
#if CHAP_SUPPORT
#define ADDCICHAP(opt, neg, val) \
    if (neg) { \
    PUTCHAR((opt), ucp); \
    PUTCHAR(CILEN_CHAP, ucp); \
    PUTSHORT(PPP_CHAP, ucp); \
    PUTCHAR((CHAP_DIGEST(val)), ucp); \
    }
#endif /* CHAP_SUPPORT */
#define ADDCILONG(opt, neg, val) \
    if (neg) { \
    PUTCHAR(opt, ucp); \
    PUTCHAR(CILEN_LONG, ucp); \
    PUTLONG(val, ucp); \
    }
#if LQR_SUPPORT
#define ADDCILQR(opt, neg, val) \
    if (neg) { \
    PUTCHAR(opt, ucp); \
    PUTCHAR(CILEN_LQR, ucp); \
    PUTSHORT(PPP_LQR, ucp); \
    PUTLONG(val, ucp); \
    }
#endif /* LQR_SUPPORT */
#define ADDCICHAR(opt, neg, val) \
    if (neg) { \
    PUTCHAR(opt, ucp); \
    PUTCHAR(CILEN_CHAR, ucp); \
    PUTCHAR(val, ucp); \
    }
#define ADDCIENDP(opt, neg, class, val, len) \
    if (neg) { \
    int i; \
    PUTCHAR(opt, ucp); \
    PUTCHAR(CILEN_CHAR + len, ucp); \
    PUTCHAR(class, ucp); \
    for (i = 0; i < len; ++i) \
        PUTCHAR(val[i], ucp); \
    }

    ADDCISHORT(CI_MRU, go->neg_mru && go->mru != PPP_DEFMRU, go->mru);
    ADDCILONG(CI_ASYNCMAP, go->neg_asyncmap && go->asyncmap != 0xFFFFFFFF,
          go->asyncmap);

    ADDCISHORT(CI_AUTHTYPE, go->neg_eap, PPP_EAP);

    ADDCICHAP(CI_AUTHTYPE, !go->neg_eap && go->neg_chap, go->chap_mdtype);

    ADDCISHORT(CI_AUTHTYPE, !go->neg_eap && !go->neg_chap && go->neg_upap, PPP_PAP);



    ADDCILQR(CI_QUALITY, go->neg_lqr, go->lqr_period);

    ADDCICHAR(CI_CALLBACK, go->neg_cbcp, CBCP_OPT);
    ADDCILONG(CI_MAGICNUMBER, go->neg_magicnumber, go->magicnumber);
    ADDCIVOID(CI_PCOMPRESSION, go->neg_pcompression);
    ADDCIVOID(CI_ACCOMPRESSION, go->neg_accompression);

    ADDCISHORT(CI_MRRU, go->neg_mrru, go->mrru);

    ADDCIVOID(CI_SSNHF, go->neg_ssnhf);
    ADDCIENDP(CI_EPDISC, go->neg_endpoint, go->endpoint.class_,
          go->endpoint.value, go->endpoint.length);

    if (ucp - start_ucp != *lenp) {
    /* this should never happen, because peer_mtu should be 1500 */
    ppp_error("Bug in lcp_addci: wrong length");
    }
}


/*
 * lcp_ackci - Ack our CIs.
 * This should not modify any state if the Ack is bad.
 *
 * Returns:
 *	0 - Ack was bad.
 *	1 - Ack was good.
 */
static int lcp_ackci(Fsm *f, uint8_t *p, int len) {
    PppPcb *pcb = f->pcb;
    LcpOptions *go = &pcb->lcp_gotoptions;
    uint8_t cilen, citype, cichar;
    u_short cishort;
    uint32_t cilong;

    /*
     * CIs must be in exactly the same order that we sent.
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */
#define ACKCIVOID(opt, neg) \
    if (neg) { \
    if ((len -= CILEN_VOID) < 0) \
        goto bad; \
    GETCHAR(citype, p); \
    GETCHAR(cilen, p); \
    if (cilen != CILEN_VOID || \
        citype != opt) \
        goto bad; \
    }
#define ACKCISHORT(opt, neg, val) \
    if (neg) { \
    if ((len -= CILEN_SHORT) < 0) \
        goto bad; \
    GETCHAR(citype, p); \
    GETCHAR(cilen, p); \
    if (cilen != CILEN_SHORT || \
        citype != opt) \
        goto bad; \
    GETSHORT(cishort, p); \
    if (cishort != val) \
        goto bad; \
    }
#define ACKCICHAR(opt, neg, val) \
    if (neg) { \
    if ((len -= CILEN_CHAR) < 0) \
        goto bad; \
    GETCHAR(citype, p); \
    GETCHAR(cilen, p); \
    if (cilen != CILEN_CHAR || \
        citype != opt) \
        goto bad; \
    GETCHAR(cichar, p); \
    if (cichar != val) \
        goto bad; \
    }
#if CHAP_SUPPORT
#define ACKCICHAP(opt, neg, val) \
    if (neg) { \
    if ((len -= CILEN_CHAP) < 0) \
        goto bad; \
    GETCHAR(citype, p); \
    GETCHAR(cilen, p); \
    if (cilen != CILEN_CHAP || \
        citype != (opt)) \
        goto bad; \
    GETSHORT(cishort, p); \
    if (cishort != PPP_CHAP) \
        goto bad; \
    GETCHAR(cichar, p); \
    if (cichar != (CHAP_DIGEST(val))) \
      goto bad; \
    }
#endif /* CHAP_SUPPORT */
#define ACKCILONG(opt, neg, val) \
    if (neg) { \
    if ((len -= CILEN_LONG) < 0) \
        goto bad; \
    GETCHAR(citype, p); \
    GETCHAR(cilen, p); \
    if (cilen != CILEN_LONG || \
        citype != opt) \
        goto bad; \
    GETLONG(cilong, p); \
    if (cilong != val) \
        goto bad; \
    }
#if LQR_SUPPORT
#define ACKCILQR(opt, neg, val) \
    if (neg) { \
    if ((len -= CILEN_LQR) < 0) \
        goto bad; \
    GETCHAR(citype, p); \
    GETCHAR(cilen, p); \
    if (cilen != CILEN_LQR || \
        citype != opt) \
        goto bad; \
    GETSHORT(cishort, p); \
    if (cishort != PPP_LQR) \
        goto bad; \
    GETLONG(cilong, p); \
    if (cilong != val) \
      goto bad; \
    }
#endif /* LQR_SUPPORT */
#define ACKCIENDP(opt, neg, class, val, vlen) \
    if (neg) { \
    int i; \
    if ((len -= CILEN_CHAR + vlen) < 0) \
        goto bad; \
    GETCHAR(citype, p); \
    GETCHAR(cilen, p); \
    if (cilen != CILEN_CHAR + vlen || \
        citype != opt) \
        goto bad; \
    GETCHAR(cichar, p); \
    if (cichar != class) \
        goto bad; \
    for (i = 0; i < vlen; ++i) { \
        GETCHAR(cichar, p); \
        if (cichar != val[i]) \
        goto bad; \
    } \
    }

    ACKCISHORT(CI_MRU, go->neg_mru && go->mru != PPP_DEFMRU, go->mru);
    ACKCILONG(CI_ASYNCMAP, go->neg_asyncmap && go->asyncmap != 0xFFFFFFFF,
          go->asyncmap);

    ACKCISHORT(CI_AUTHTYPE, go->neg_eap, PPP_EAP);

    ACKCICHAP(CI_AUTHTYPE, !go->neg_eap && go->neg_chap, go->chap_mdtype);

    ACKCISHORT(CI_AUTHTYPE, !go->neg_eap && !go->neg_chap && go->neg_upap, PPP_PAP);


    ACKCILQR(CI_QUALITY, go->neg_lqr, go->lqr_period);

    ACKCICHAR(CI_CALLBACK, go->neg_cbcp, CBCP_OPT);
    ACKCILONG(CI_MAGICNUMBER, go->neg_magicnumber, go->magicnumber);
    ACKCIVOID(CI_PCOMPRESSION, go->neg_pcompression);
    ACKCIVOID(CI_ACCOMPRESSION, go->neg_accompression);

    ACKCISHORT(CI_MRRU, go->neg_mrru, go->mrru);

    ACKCIVOID(CI_SSNHF, go->neg_ssnhf);
    ACKCIENDP(CI_EPDISC, go->neg_endpoint, go->endpoint.class_,
          go->endpoint.value, go->endpoint.length);

    /*
     * If there are any remaining CIs, then this packet is bad.
     */
    if (len != 0)
    goto bad;
    return (1);
bad:
    // LCPDEBUG(("lcp_acki: received bad Ack!"));
    return (0);
}


/*
 * lcp_nakci - Peer has sent a NAK for some of our CIs.
 * This should not modify any state if the Nak is bad
 * or if LCP is in the OPENED state.
 *
 * Returns:
 *	0 - Nak was bad.
 *	1 - Nak was good.
 */
static int lcp_nakci(Fsm *f, uint8_t *p, int len, int treat_as_reject) {
    PppPcb *pcb = f->pcb;
    LcpOptions *go = &pcb->lcp_gotoptions;
    LcpOptions *wo = &pcb->lcp_wantoptions;
    uint8_t citype;
    ChapDigestCodes cichar;
    uint8_t* next;
    u_short cishort;
    uint32_t cilong;
    LcpOptions no;		/* options we've seen Naks for */
    LcpOptions try_;		/* options to request next time */
    int looped_back = 0;
    int cilen;

    zero_mem(&no, sizeof(no));
    try_ = *go;

    /*
     * Any Nak'd CIs must be in exactly the same order that we sent.
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */
#define NAKCIVOID(opt, neg) \
    if (go->neg && \
    len >= CILEN_VOID && \
    p[1] == CILEN_VOID && \
    p[0] == opt) { \
    len -= CILEN_VOID; \
    INCPTR(CILEN_VOID, p); \
    no.neg = 1; \
    try_.neg = 0; \
    }

#define NAKCICHAP(opt, neg, code) \
    if (go->neg && \
    len >= CILEN_CHAP && \
    p[1] == CILEN_CHAP && \
    p[0] == opt) { \
    len -= CILEN_CHAP; \
    INCPTR(2, p); \
    GETSHORT(cishort, p); \
    GETCHAR(cichar, p); \
    no.neg = 1; \
    code \
    }

#define NAKCICHAR(opt, neg, code) \
    if (go->neg && \
    len >= CILEN_CHAR && \
    p[1] == CILEN_CHAR && \
    p[0] == opt) { \
    len -= CILEN_CHAR; \
    INCPTR(2, p); \
    GETCHAR(cichar, p); \
    no.neg = 1; \
    code \
    }
#define NAKCISHORT(opt, neg, code) \
    if (go->neg && \
    len >= CILEN_SHORT && \
    p[1] == CILEN_SHORT && \
    p[0] == opt) { \
    len -= CILEN_SHORT; \
    INCPTR(2, p); \
    GETSHORT(cishort, p); \
    no.neg = 1; \
    code \
    }
#define NAKCILONG(opt, neg, code) \
    if (go->neg && \
    len >= CILEN_LONG && \
    p[1] == CILEN_LONG && \
    p[0] == opt) { \
    len -= CILEN_LONG; \
    INCPTR(2, p); \
    GETLONG(cilong, p); \
    no.neg = 1; \
    code \
    }

#define NAKCILQR(opt, neg, code) \
    if (go->neg && \
    len >= CILEN_LQR && \
    p[1] == CILEN_LQR && \
    p[0] == opt) { \
    len -= CILEN_LQR; \
    INCPTR(2, p); \
    GETSHORT(cishort, p); \
    GETLONG(cilong, p); \
    no.neg = 1; \
    code \
    }

#define NAKCIENDP(opt, neg) \
    if (go->neg && \
    len >= CILEN_CHAR && \
    p[0] == opt && \
    p[1] >= CILEN_CHAR && \
    p[1] <= len) { \
    len -= p[1]; \
    INCPTR(p[1], p); \
    no.neg = 1; \
    try_.neg = 0; \
    }

    /*
     * NOTE!  There must be no assignments to individual fields of *go in
     * the code below.  Any such assignment is a BUG!
     */
    /*
     * We don't care if they want to send us smaller packets than
     * we want.  Therefore, accept any MRU less than what we asked for,
     * but then ignore the new value when setting the MRU in the kernel.
     * If they send us a bigger MRU than what we asked, accept it, up to
     * the limit of the default MRU we'd get if we didn't negotiate.
     */
    if (go->neg_mru && go->mru != PPP_DEFMRU) {
    NAKCISHORT(CI_MRU, neg_mru,
           if (cishort <= wo->mru || cishort <= PPP_DEFMRU)
               try_.mru = cishort;
           );
    }

    /*
     * Add any characters they want to our (receive-side) asyncmap.
     */
    if (go->neg_asyncmap && go->asyncmap != 0xFFFFFFFF) {
    NAKCILONG(CI_ASYNCMAP, neg_asyncmap,
          try_.asyncmap = go->asyncmap | cilong;
          );
    }

    /*
     * If they've nak'd our authentication-protocol, check whether
     * they are proposing a different protocol, or a different
     * hash algorithm for CHAP.
     */
    if ((false

        || go->neg_chap

        || go->neg_upap

        || go->neg_eap

        )
    && len >= CILEN_SHORT
    && p[0] == CI_AUTHTYPE && p[1] >= CILEN_SHORT && p[1] <= len) {
    cilen = p[1];
    len -= cilen;

    no.neg_chap = go->neg_chap;
    no.neg_upap = go->neg_upap;
    no.neg_eap = go->neg_eap;
    INCPTR(2, p);
    GETSHORT(cishort, p);
    if (cishort == PPP_PAP && cilen == 4) {
        /* If we were asking for EAP, then we need to stop that. */
        if (go->neg_eap)
        {
            try_.neg_eap = false;
        }
        else
        /* If we were asking for CHAP, then we need to stop that. */
        if (go->neg_chap)
        {
            try_.neg_chap = false;
        }
        else
        {
            /*
             * If we weren't asking for CHAP or EAP, then we were asking for
             * PAP, in which case this Nak is bad.
             */
        goto bad;
        }
    } else
    if (cishort == PPP_CHAP && cilen == 5) {
        { (cichar) = (ChapDigestCodes)*(p)++; };
        /* Stop asking for EAP, if we were. */
        if (go->neg_eap) {
        try_.neg_eap = false;
        /* Try to set up to use their suggestion, if possible */
        if (chap_candigest(go->chap_mdtype, cichar))
        {
            try_.chap_mdtype = chap_mdtype_d(cichar);
        }
        } else
        if (go->neg_chap) {
        /*
         * We were asking for our preferred algorithm, they must
         * want something different.
         */
        if (cichar != CHAP_DIGEST(go->chap_mdtype)) {
            if (chap_candigest(go->chap_mdtype, cichar)) {
            /* Use their suggestion if we support it ... */
            try_.chap_mdtype = chap_mdtype_d(cichar);
            } else {
            /* ... otherwise, try our next-preferred algorithm. */
            try_.chap_mdtype = (ChapMdTypes)(try_.chap_mdtype & ~(CHAP_MDTYPE(try_.chap_mdtype)));
            if (try_.chap_mdtype == MDTYPE_NONE)
            {
                /* out of algos */
                try_.neg_chap = false;
            }
            }
        } else {
            /*
             * Whoops, they Nak'd our algorithm of choice
             * but then suggested it back to us.
             */
            goto bad;
        }
        } else {
        /*
         * Stop asking for PAP if we were asking for it.
         */
        try_.neg_upap = false;
        }
    } else
    {
        /*
         * If we were asking for EAP, and they're Conf-Naking EAP,
         * well, that's just strange.  Nobody should do that.
         */
        if (cishort == PPP_EAP && cilen == CILEN_SHORT && go->neg_eap)
        {
            ppp_dbglog("Unexpected Conf-Nak for EAP");
        } /*
         * We don't recognize what they're suggesting.
         * Stop asking for what we were asking for.
         */
        if (go->neg_eap)
        {
            try_.neg_eap = false;
        }
        else
        if (go->neg_chap)
        {
            try_.neg_chap = false;
        }
        else
        if(true)
        try_.neg_upap = false;
        else
        {}

        p += cilen - CILEN_SHORT;
    }
    }

    /*
     * If they can't cope with our link quality protocol, we'll have
     * to stop asking for LQR.  We haven't got any other protocol.
     * If they Nak the reporting period, take their value XXX ?
     */
    if (go->neg_lqr && len >= CILEN_LQR && p[1] == CILEN_LQR && p[0] == CI_QUALITY) { len -= CILEN_LQR; INCPTR(2, p); GETSHORT(cishort, p); GETLONG(cilong, p); no.neg_lqr = 1; if (cishort != PPP_LQR) try_.neg_lqr = 0; else try_.lqr_period = cilong; };

    /*
     * Only implementing CBCP...not the rest of the callback options
     */
    if (go->neg_cbcp && len >= CILEN_CHAR && p[1] == CILEN_CHAR && p[0] == CI_CALLBACK) { len -= CILEN_CHAR; INCPTR(2, p); { (cichar) = (ChapDigestCodes)*(p)++; }; no.neg_cbcp = 1; try_.neg_cbcp = 0; (void)cichar; };

    /*
     * Check for a looped-back line.
     */
    if (go->neg_magicnumber && len >= CILEN_LONG && p[1] == CILEN_LONG && p[0] == CI_MAGICNUMBER) { len -= CILEN_LONG; INCPTR(2, p); GETLONG(cilong, p); no.neg_magicnumber = 1; try_.magicnumber = magic(); looped_back = 1; };

    /*
     * Peer shouldn't send Nak for protocol compression or
     * address/control compression requests; they should send
     * a Reject instead.  If they send a Nak, treat it as a Reject.
     */
    if (go->neg_pcompression && len >= CILEN_VOID && p[1] == CILEN_VOID && p[0] == CI_PCOMPRESSION) { len -= CILEN_VOID; INCPTR(CILEN_VOID, p); no.neg_pcompression = 1; try_.neg_pcompression = 0; };
    if (go->neg_accompression && len >= CILEN_VOID && p[1] == CILEN_VOID && p[0] == CI_ACCOMPRESSION) { len -= CILEN_VOID; INCPTR(CILEN_VOID, p); no.neg_accompression = 1; try_.neg_accompression = 0; };


    /*
     * Nak for MRRU option - accept their value if it is smaller
     * than the one we want.
     */
    if (go->neg_mrru) {
    if (go->neg_mrru && len >= CILEN_SHORT && p[1] == CILEN_SHORT && p[0] == CI_MRRU) { len -= CILEN_SHORT; INCPTR(2, p); GETSHORT(cishort, p); no.neg_mrru = 1; if (treat_as_reject) try_.neg_mrru = 0; else if (cishort <= wo->mrru) try_.mrru = cishort; };
    }


    /*
     * Nak for short sequence numbers shouldn't be sent, treat it
     * like a reject.
     */
    if (go->neg_ssnhf && len >= CILEN_VOID && p[1] == CILEN_VOID && p[0] == CI_SSNHF) { len -= CILEN_VOID; INCPTR(CILEN_VOID, p); no.neg_ssnhf = 1; try_.neg_ssnhf = 0; };

    /*
     * Nak of the endpoint discriminator option is not permitted,
     * treat it like a reject.
     */
    NAKCIENDP(CI_EPDISC, neg_endpoint);

    /*
     * There may be remaining CIs, if the peer is requesting negotiation
     * on an option that we didn't include in our request packet.
     * If we see an option that we requested, or one we've already seen
     * in this packet, then this packet is bad.
     * If we wanted to respond by starting to negotiate on the requested
     * option(s), we could, but we don't, because except for the
     * authentication type and quality protocol, if we are not negotiating
     * an option, it is because we were told not to.
     * For the authentication type, the Nak from the peer means
     * `let me authenticate myself with you' which is a bit pointless.
     * For the quality protocol, the Nak means `ask me to send you quality
     * reports', but if we didn't ask for them, we don't want them.
     * An option we don't recognize represents the peer asking to
     * negotiate some option we don't support, so ignore it.
     */
    while (len >= CILEN_VOID) {
    GETCHAR(citype, p);
    GETCHAR(cilen, p);
    if (cilen < CILEN_VOID || (len -= cilen) < 0)
        goto bad;
    next = p + cilen - 2;

    switch (citype) {
    case CI_MRU:
        if ((go->neg_mru && go->mru != PPP_DEFMRU)
        || no.neg_mru || cilen != CILEN_SHORT)
        {
            goto bad;
        }
        GETSHORT(cishort, p);
        if (cishort < PPP_DEFMRU) {
        try_.neg_mru = true;
        try_.mru = cishort;
        }
        break;
    case CI_ASYNCMAP:
        if ((go->neg_asyncmap && go->asyncmap != 0xFFFFFFFF)
        || no.neg_asyncmap || cilen != CILEN_LONG)
        goto bad;
        break;
    case CI_AUTHTYPE:
        if (false

                || go->neg_chap || no.neg_chap

                || go->neg_upap || no.neg_upap

        || go->neg_eap || no.neg_eap

        )
        goto bad;
        break;
    case CI_MAGICNUMBER:
        if (go->neg_magicnumber || no.neg_magicnumber ||
        cilen != CILEN_LONG)
        goto bad;
        break;
    case CI_PCOMPRESSION:
        if (go->neg_pcompression || no.neg_pcompression
        || cilen != CILEN_VOID)
        {
            goto bad;
        }
        break;
    case CI_ACCOMPRESSION:
        if (go->neg_accompression || no.neg_accompression
        || cilen != CILEN_VOID)
        {
            goto bad;
        }
        break;

    case CI_QUALITY:
        if (go->neg_lqr || no.neg_lqr || cilen != CILEN_LQR)
        goto bad;
        break;


    case CI_MRRU:
        if (go->neg_mrru || no.neg_mrru || cilen != CILEN_SHORT)
        goto bad;
        break;

    case CI_SSNHF:
        if (go->neg_ssnhf || no.neg_ssnhf || cilen != CILEN_VOID)
        goto bad;
        try_.neg_ssnhf = true;
        break;
    case CI_EPDISC:
        if (go->neg_endpoint || no.neg_endpoint || cilen < CILEN_CHAR)
        goto bad;
        break;
    default:
        break;
    }
    p = next;
    }

    /*
     * OK, the Nak is good.  Now we can update state.
     * If there are any options left we ignore them.
     */
    if (f->state != PPP_FSM_OPENED) {
    if (looped_back) {
        if (++try_.numloops >= pcb->settings.lcp_loopbackfail) {
        ppp_notice("Serial line is looped back.");
        pcb->err_code = PPPERR_LOOPBACK;
        lcp_close(f->pcb, "Loopback detected");
        }
    } else
    {
        try_.numloops = 0;
    }
    *go = try_;
    }

    return 1;

bad:
    // LCPDEBUG(("lcp_nakci: received bad Nak!"));
    return 0;
}


/*
 * lcp_rejci - Peer has Rejected some of our CIs.
 * This should not modify any state if the Reject is bad
 * or if LCP is in the OPENED state.
 *
 * Returns:
 *	0 - Reject was bad.
 *	1 - Reject was good.
 */
static int lcp_rejci(Fsm *f, uint8_t *p, int len) {
    PppPcb *pcb = f->pcb;
    LcpOptions *go = &pcb->lcp_gotoptions;
    uint8_t cichar;
    u_short cishort;
    uint32_t cilong;
    LcpOptions try_;		/* options to request next time */

    try_ = *go;

    /*
     * Any Rejected CIs must be in exactly the same order that we sent.
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */
#define REJCIVOID(opt, neg) \
    if (go->neg && \
    len >= CILEN_VOID && \
    p[1] == CILEN_VOID && \
    p[0] == opt) { \
    len -= CILEN_VOID; \
    INCPTR(CILEN_VOID, p); \
    try_.neg = 0; \
    }
#define REJCISHORT(opt, neg, val) \
    if (go->neg && \
    len >= CILEN_SHORT && \
    p[1] == CILEN_SHORT && \
    p[0] == opt) { \
    len -= CILEN_SHORT; \
    INCPTR(2, p); \
    GETSHORT(cishort, p); \
    /* Check rejected value. */ \
    if (cishort != val) \
        goto bad; \
    try_.neg = 0; \
    }

#define REJCICHAP(opt, neg, val) \
    if (go->neg && \
    len >= CILEN_CHAP && \
    p[1] == CILEN_CHAP && \
    p[0] == opt) { \
    len -= CILEN_CHAP; \
    INCPTR(2, p); \
    GETSHORT(cishort, p); \
    GETCHAR(cichar, p); \
    /* Check rejected value. */ \
    if ((cishort != PPP_CHAP) || (cichar != (CHAP_DIGEST(val)))) \
        goto bad; \
    try_.neg = 0; \
    try_.neg_eap = try_.neg_upap = 0; \
    }

#define REJCICHAP(opt, neg, val) \
    if (go->neg && \
    len >= CILEN_CHAP && \
    p[1] == CILEN_CHAP && \
    p[0] == opt) { \
    len -= CILEN_CHAP; \
    INCPTR(2, p); \
    GETSHORT(cishort, p); \
    GETCHAR(cichar, p); \
    /* Check rejected value. */ \
    if ((cishort != PPP_CHAP) || (cichar != (CHAP_DIGEST(val)))) \
        goto bad; \
    try_.neg = 0; \
    try_.neg_upap = 0; \
    }

#define REJCILONG(opt, neg, val) \
    if (go->neg && \
    len >= CILEN_LONG && \
    p[1] == CILEN_LONG && \
    p[0] == opt) { \
    len -= CILEN_LONG; \
    INCPTR(2, p); \
    GETLONG(cilong, p); \
    /* Check rejected value. */ \
    if (cilong != val) \
        goto bad; \
    try_.neg = 0; \
    }

#define REJCILQR(opt, neg, val) \
    if (go->neg && \
    len >= CILEN_LQR && \
    p[1] == CILEN_LQR && \
    p[0] == opt) { \
    len -= CILEN_LQR; \
    INCPTR(2, p); \
    GETSHORT(cishort, p); \
    GETLONG(cilong, p); \
    /* Check rejected value. */ \
    if (cishort != PPP_LQR || cilong != val) \
        goto bad; \
    try_.neg = 0; \
    }
#define REJCICBCP(opt, neg, val) \
    if (go->neg && \
    len >= CILEN_CBCP && \
    p[1] == CILEN_CBCP && \
    p[0] == opt) { \
    len -= CILEN_CBCP; \
    INCPTR(2, p); \
    GETCHAR(cichar, p); \
    /* Check rejected value. */ \
    if (cichar != val) \
        goto bad; \
    try_.neg = 0; \
    }
#define REJCIENDP(opt, neg, class, val, vlen) \
    if (go->neg && \
    len >= CILEN_CHAR + vlen && \
    p[0] == opt && \
    p[1] == CILEN_CHAR + vlen) { \
    int i; \
    len -= CILEN_CHAR + vlen; \
    INCPTR(2, p); \
    GETCHAR(cichar, p); \
    if (cichar != class) \
        goto bad; \
    for (i = 0; i < vlen; ++i) { \
        GETCHAR(cichar, p); \
        if (cichar != val[i]) \
        goto bad; \
    } \
    try_.neg = 0; \
    }

    REJCISHORT(CI_MRU, neg_mru, go->mru);
    REJCILONG(CI_ASYNCMAP, neg_asyncmap, go->asyncmap);
    REJCISHORT(CI_AUTHTYPE, neg_eap, PPP_EAP);
    if (!go->neg_eap) {
    REJCICHAP(CI_AUTHTYPE, neg_chap, go->chap_mdtype);
    if (!go->neg_chap) {
        REJCISHORT(CI_AUTHTYPE, neg_upap, PPP_PAP);
    }
    }
    REJCILQR(CI_QUALITY, neg_lqr, go->lqr_period);
    REJCICBCP(CI_CALLBACK, neg_cbcp, CBCP_OPT);
    REJCILONG(CI_MAGICNUMBER, neg_magicnumber, go->magicnumber);
    REJCIVOID(CI_PCOMPRESSION, neg_pcompression);
    REJCIVOID(CI_ACCOMPRESSION, neg_accompression);

    REJCISHORT(CI_MRRU, neg_mrru, go->mrru);

    REJCIVOID(CI_SSNHF, neg_ssnhf);
    REJCIENDP(CI_EPDISC, neg_endpoint, go->endpoint.class_,
          go->endpoint.value, go->endpoint.length);

    /*
     * If there are any remaining CIs, then this packet is bad.
     */
    if (len != 0)
    {
        goto bad;
    } /*
     * Now we can update state.
     */
    if (f->state != PPP_FSM_OPENED)
    *go = try_;
    return 1;

bad:
    // LCPDEBUG(("lcp_rejci: received bad Reject!"));
    return 0;
}


/*
 * lcp_reqci - Check the peer's requested CIs and send appropriate response.
 *
 * Returns: CONFACK, CONFNAK or CONFREJ and input packet modified
 * appropriately.  If reject_if_disagree is non-zero, doesn't return
 * CONFNAK; returns CONFREJ if it can't return CONFACK.
 *
 * inp = Requested CIs
 * lenp = Length of requested CIs
 */
bool
lcp_req_conf_info(PppPcb& pcb, Fsm& f, std::vector<uint8_t>& inp, bool reject_if_disagree) {
    uint8_t cilen;
    uint8_t citype;
    ChapDigestCodes cichar;
    u_short cishort;		/* Parsed short value */
    uint32_t cilong;		/* Parse long value */
    int rc = CONF_ACK;		/* Final packet return code */
    // uint8_t *p;			/* Pointer to next char to parse */ // struct PacketBuffer nakp{};          /* Nak buffer */ // auto l = *lenp;		/* Length left */
    size_t in_index = 0;
    bool ok;
    /*
     * Reset all his options.
     */
    reset_lcp_options(pcb.lcp_hisoptions);

    /*
     * Process all his options.
     */
    size_t rem_len = inp.size();
    uint8_t* next = inp.data();
    // nakp = pbuf_alloc(PBUF_RAW, (uint16_t)(PPP_CTRL_PBUF_MAX_SIZE));
    PacketBuffer nakp = init_pkt_buf();
    uint8_t* nakoutp = nakp.bytes.data();
    uint8_t* rejp = inp.data();
    while (rem_len != 0u)
    {
        int opt_rc = CONF_ACK; /* Assume success */
        // uint8_t* cip = p = next; /* Remember begining of CI */
        /* Not enough data for CI header or */ /*  CI length too small or */
        if (rem_len < 2 || inp[in_index + 1] < 2 || inp[in_index + 1] > rem_len)
        {
            /*  CI length too big? */ // LCPDEBUG(("lcp_reqci: bad CI length!"));
            opt_rc = CONF_REJECT; /* Reject bad CI */
            cilen = rem_len; /* Reject till end of packet */
            rem_len = 0; /* Don't loop again */
            citype = 0;
            // todo: call some sort of end method and return or set ok to false
            // goto endswitch;
            ok = false;
        }

        /* Parse CI type */
        if (ok) { std::tie(ok, citype) = GETCHAR(inp, in_index); }

        /* Parse CI length */
        if (ok) { std::tie(ok, cilen) = GETCHAR(inp, in_index); }
        if (ok) {
            if (citype == CI_MRU) {
                if (!pcb.lcp_allowoptions.neg_mru || cilen != CILEN_SHORT) {
                    /* Check CI length */
                    opt_rc = CONF_REJECT; /* Reject CI */
                }
                else {
                    GETSHORT(cishort, in_index); /* Parse MRU */
                    /* He must be able to receive at least our minimum.
                                                              * No need to check a maximum.  If he sends a large number,
                                                              * we'll just ignore it.
                                                              */
                    if (cishort < PPP_MINMRU) {
                        opt_rc = CONF_NAK; /* Nak CI */
                        PUTCHAR(CI_MRU, nakoutp);
                        PUTCHAR(CILEN_SHORT, nakoutp);
                        PUTSHORT(PPP_MINMRU, nakoutp); /* Give him a hint */
                        break;
                    }
                    pcb.lcp_hisoptions.neg_mru = true; /* Remember he sent MRU */
                    pcb.lcp_hisoptions.mru = cishort; /* And remember value */
                }
            }
        }

        switch (citype)
        {
            /* Check CI type */
            /* Allow option? */
        case CI_MRU:


            break;
        case CI_ASYNCMAP:
            if (!ao->neg_asyncmap || cilen != CILEN_LONG)
            {
                opt_rc = CONF_REJECT;
                break;
            }
            GETLONG(cilong, p); /*
         * Asyncmap must have set at least the bits
         * which are set in lcp_allowoptions[unit].asyncmap.
         */
            if ((ao->asyncmap & ~cilong) != 0)
            {
                opt_rc = CONF_NAK;
                PUTCHAR(CI_ASYNCMAP, nakoutp);
                PUTCHAR(CILEN_LONG, nakoutp);
                PUTLONG(ao->asyncmap | cilong, nakoutp);
                break;
            }
            ho->neg_asyncmap = true;
            ho->asyncmap = cilong;
            break;
        case CI_AUTHTYPE:
            if (cilen < CILEN_SHORT || !(false || ao->neg_upap || ao->neg_chap || ao->
                neg_eap))
            {
                /*
                        * Reject the option if we're not willing to authenticate.
                        */
                ppp_dbglog("No auth is possible");
                opt_rc = CONF_REJECT;
                break;
            }
            GETSHORT(cishort, p); /*
         * Authtype must be PAP, CHAP, or EAP.
         *
         * Note: if more than one of ao->neg_upap, ao->neg_chap, and
         * ao->neg_eap are set, and the peer sends a Configure-Request
         * with two or more authenticate-protocol requests, then we will
         * reject the second request.
         * Whether we end up doing CHAP, UPAP, or EAP depends then on
         * the ordering of the CIs in the peer's Configure-Request.
             */
            if (cishort == PPP_PAP)
            {
                /* we've already accepted CHAP or EAP */
                if (false || ho->neg_chap || ho->neg_eap || cilen != CILEN_SHORT)
                {
                    // LCPDEBUG(("lcp_reqci: rcvd AUTHTYPE PAP, rejecting..."));
                    opt_rc = CONF_REJECT;
                    break;
                }
                if (!ao->neg_upap)
                {
                    /* we don't want to do PAP */
                    opt_rc = CONF_NAK; /* NAK it and suggest CHAP or EAP */
                    PUTCHAR(CI_AUTHTYPE, nakoutp);
                    if (ao->neg_eap)
                    {
                        PUTCHAR(CILEN_SHORT, nakoutp);
                        PUTSHORT(PPP_EAP, nakoutp);
                    }
                    else
                    {
                        PUTCHAR(CILEN_CHAP, nakoutp);
                        PUTSHORT(PPP_CHAP, nakoutp);
                        PUTCHAR(CHAP_DIGEST(ao->chap_mdtype), nakoutp);
                    }
                    break;
                }
                ho->neg_upap = true;
                break;
            }
            if (cishort == PPP_CHAP)
            {
                /* we've already accepted PAP or EAP */
                if (ho->neg_upap || ho->neg_eap || cilen != CILEN_CHAP)
                {
                    // LCPDEBUG(("lcp_reqci: rcvd AUTHTYPE CHAP, rejecting..."));
                    opt_rc = CONF_REJECT;
                    break;
                }
                if (!ao->neg_chap)
                {
                    /* we don't want to do CHAP */
                    opt_rc = CONF_NAK; /* NAK it and suggest EAP or PAP */
                    PUTCHAR(CI_AUTHTYPE, nakoutp);
                    PUTCHAR(CILEN_SHORT, nakoutp);
                    if (ao->neg_eap) { PUTSHORT(PPP_EAP, nakoutp); }
                    else if (true) { PUTSHORT(PPP_PAP, nakoutp); }
                    else {}
                    break;
                }
                {
                    (cichar) = (ChapDigestCodes)*(p)++;
                }; /* get digest type */
                if (!(chap_candigest(ao->chap_mdtype, cichar)))
                {
                    /*
                                * We can't/won't do the requested type,
                                * suggest something else.
                                */
                    opt_rc = CONF_NAK;
                    PUTCHAR(CI_AUTHTYPE, nakoutp);
                    PUTCHAR(CILEN_CHAP, nakoutp);
                    PUTSHORT(PPP_CHAP, nakoutp);
                    PUTCHAR(CHAP_DIGEST(ao->chap_mdtype), nakoutp);
                    break;
                }
                ho->chap_mdtype = chap_mdtype_d(cichar); /* save md type */
                ho->neg_chap = true;
                break;
            }
            if (cishort == PPP_EAP)
            {
                /* we've already accepted CHAP or PAP */
                if (ho->neg_chap || ho->neg_upap || cilen != CILEN_SHORT)
                {
                    // LCPDEBUG(("lcp_reqci: rcvd AUTHTYPE EAP, rejecting..."));
                    opt_rc = CONF_REJECT;
                    break;
                }
                if (!ao->neg_eap)
                {
                    /* we don't want to do EAP */
                    opt_rc = CONF_NAK; /* NAK it and suggest CHAP or PAP */
                    PUTCHAR(CI_AUTHTYPE, nakoutp);
                    if (ao->neg_chap)
                    {
                        PUTCHAR(CILEN_CHAP, nakoutp);
                        PUTSHORT(PPP_CHAP, nakoutp);
                        PUTCHAR(CHAP_DIGEST(ao->chap_mdtype), nakoutp);
                    }
                    else if (true)
                    {
                        PUTCHAR(CILEN_SHORT, nakoutp);
                        PUTSHORT(PPP_PAP, nakoutp);
                    }
                    else {}
                    break;
                }
                ho->neg_eap = true;
                break;
            } /*
         * We don't recognize the protocol they're asking for.
         * Nak it with something we're willing to do.
         * (At this point we know ao->neg_upap || ao->neg_chap ||
         * ao->neg_eap.)
         */
            opt_rc = CONF_NAK;
            PUTCHAR(CI_AUTHTYPE, nakoutp);
            if (ao->neg_eap)
            {
                PUTCHAR(CILEN_SHORT, nakoutp);
                PUTSHORT(PPP_EAP, nakoutp);
            }
            else if (ao->neg_chap)
            {
                PUTCHAR(CILEN_CHAP, nakoutp);
                PUTSHORT(PPP_CHAP, nakoutp);
                PUTCHAR(CHAP_DIGEST(ao->chap_mdtype), nakoutp);
            }
            else if (true)
            {
                PUTCHAR(CILEN_SHORT, nakoutp);
                PUTSHORT(PPP_PAP, nakoutp);
            }
            else {}
            break;
        case CI_QUALITY:
            if (!ao->neg_lqr || cilen != CILEN_LQR)
            {
                opt_rc = CONF_REJECT;
                break;
            }
            GETSHORT(cishort, p);
            GETLONG(cilong, p); /*
         * Check the protocol and the reporting period.
         * XXX When should we Nak this, and what with?
         */
            if (cishort != PPP_LQR)
            {
                opt_rc = CONF_NAK;
                PUTCHAR(CI_QUALITY, nakoutp);
                PUTCHAR(CILEN_LQR, nakoutp);
                PUTSHORT(PPP_LQR, nakoutp);
                PUTLONG(ao->lqr_period, nakoutp);
                break;
            }
            break;
        case CI_MAGICNUMBER:
            if (!(ao->neg_magicnumber || go->neg_magicnumber) || cilen != CILEN_LONG)
            {
                opt_rc = CONF_REJECT;
                break;
            }
            GETLONG(cilong, p); /*
         * He must have a different magic number.
         */
            if (go->neg_magicnumber && cilong == go->magicnumber)
            {
                cilong = magic(); /* Don't put magic() inside macro! */
                opt_rc = CONF_NAK;
                PUTCHAR(CI_MAGICNUMBER, nakoutp);
                PUTCHAR(CILEN_LONG, nakoutp);
                PUTLONG(cilong, nakoutp);
                break;
            }
            ho->neg_magicnumber = true;
            ho->magicnumber = cilong;
            break;
        case CI_PCOMPRESSION:
            if (!ao->neg_pcompression || cilen != CILEN_VOID)
            {
                opt_rc = CONF_REJECT;
                break;
            }
            ho->neg_pcompression = true;
            break;
        case CI_ACCOMPRESSION:
            if (!ao->neg_accompression || cilen != CILEN_VOID)
            {
                opt_rc = CONF_REJECT;
                break;
            }
            ho->neg_accompression = true;
            break;
        case CI_MRRU:
            if (!ao->neg_mrru || !multilink || cilen != CILEN_SHORT)
            {
                opt_rc = CONF_REJECT;
                break;
            }
            GETSHORT(cishort, p);
            /* possibly should insist on a minimum/maximum MRRU here */
            ho->neg_mrru = true;
            ho->mrru = cishort;
            break;
        case CI_SSNHF:
            if (!ao->neg_ssnhf || !multilink || cilen != CILEN_VOID)
            {
                opt_rc = CONF_REJECT;
                break;
            }
            ho->neg_ssnhf = true;
            break;
        case CI_EPDISC:
            if (!ao->neg_endpoint || cilen < CILEN_CHAR || cilen > CILEN_CHAR +
                MAX_ENDP_LEN)
            {
                opt_rc = CONF_REJECT;
                break;
            }
            {
                (cichar) = (ChapDigestCodes)*(p)++;
            };
            cilen -= CILEN_CHAR;
            ho->neg_endpoint = true;
            ho->endpoint.class_ = cichar;
            ho->endpoint.length = cilen;
            memcpy(ho->endpoint.value, p, cilen);
            INCPTR(cilen, p);
            break;
        default: // LCPDEBUG(("lcp_reqci: rcvd unknown option %d", citype));
            opt_rc = CONF_REJECT;
            break;
        }
    endswitch: if (opt_rc == CONF_ACK && /* Good CI */ rc != CONF_ACK)
        {
            /*  but prior CI wasnt? */
            continue; /* Don't send this one */
        }
        if (opt_rc == CONF_NAK)
        {
            /* Nak this CI? */
            if (reject_if_disagree /* Getting fed up with sending NAKs? */ && citype !=
                CI_MAGICNUMBER) { opt_rc = CONF_REJECT; /* Get tough if so */ }
            else
            {
                if (rc == CONF_REJECT) /* Rejecting prior CI? */
                    continue; /* Don't send this one */
                rc = CONF_NAK;
            }
        }
        if (opt_rc == CONF_REJECT)
        {
            /* Reject this CI */
            rc = CONF_REJECT;
            if (cip != rejp)
            {
                /* Need to move rejected CI? */
                memcpy(rejp, cip, cilen); /* Move it */
            }
            INCPTR(cilen, rejp); /* Update output pointer */
        }

        rem_len -= cilen; /* Adjust remaining length */
        in_index += cilen; /* Step to next CI */
    }

    /*
     * If we wanted to send additional NAKs (for unsent CIs), the
     * code would go here.  The extra NAKs would go at *nakoutp.
     * At present there are no cases where we want to ask the
     * peer to negotiate an option.
     */

    switch (rc) {
    case CONF_ACK:
    *lenp = next - inp;
    break;
    case CONF_NAK:
    /*
     * Copy the Nak'd options from the nak buffer to the caller's buffer.
     */
    *lenp = nakoutp - (uint8_t*)nakp->payload;
    memcpy(inp, nakp->payload, *lenp);
    break;
    case CONF_REJECT:
    *lenp = rejp - inp;
    break;
    default:
    break;
    }

    free_pkt_buf(nakp);

    return (rc);			/* Return final code */
}


/**
 * LCP has come UP.
 */
bool
lcp_up(Fsm& f, PppPcb& pcb, bool multilink)
{
    if (!pcb.lcp_gotoptions.neg_magicnumber) { pcb.lcp_gotoptions.magicnumber = 0; }
    if (!pcb.lcp_hisoptions.neg_magicnumber) { pcb.lcp_hisoptions.magicnumber = 0; }

    /*
     * Set our MTU to the smaller of the MTU we wanted and
     * the MRU our peer wanted.  If we negotiated an MRU,
     * set our MRU to the larger of value we wanted and
     * the value we got in the negotiation.
     * Note on the MTU: the link MTU can be the MRU the peer wanted,
     * the interface MTU is set to the lowest of that, the
     * MTU we want to use, and our link MRU.
     */
    int mtu = pcb.lcp_hisoptions.neg_mru ? pcb.lcp_hisoptions.mru : PPP_MRU;
    int mru = pcb.lcp_gotoptions.neg_mru
                  ? std::max(pcb.lcp_wantoptions.mru, pcb.lcp_gotoptions.mru)
                  : PPP_MRU;
    if (!(multilink && pcb.lcp_gotoptions.neg_mrru && pcb.lcp_hisoptions.neg_mrru))
    {
        netif_set_mtu(pcb,
                      std::min(uint16_t(std::min(mtu, mru)), pcb.lcp_allowoptions.mru));
    }
    ppp_send_config(pcb,
                    mtu,
                    (pcb.lcp_hisoptions.neg_asyncmap
                         ? pcb.lcp_hisoptions.asyncmap
                         : 0xffffffff),
                    pcb.lcp_hisoptions.neg_pcompression,
                    pcb.lcp_hisoptions.neg_accompression);
    ppp_recv_config(pcb,
                    mru,
                    (pcb.settings.lax_recv
                         ? 0
                         : pcb.lcp_gotoptions.neg_asyncmap
                         ? pcb.lcp_gotoptions.asyncmap
                         : 0xffffffff),
                    pcb.lcp_gotoptions.neg_pcompression,
                    pcb.lcp_gotoptions.neg_accompression);
    if (pcb.lcp_hisoptions.neg_mru)
        pcb.peer_mru = pcb.lcp_hisoptions.mru;
    lcp_echo_lowerup(pcb); /* Enable echo messages */
    UpapState upap_state{};
    return link_established(pcb, upap_state, true);
}


/**
 * LCP has gone DOWN. Alert other protocols.
 */
bool
lcp_down(PppPcb& pcb, Fsm& f, bool multilink)
{
    lcp_echo_lower_down(pcb, f);
    if (!link_down(pcb, multilink)) { return false; }
    ppp_send_config(pcb, PPP_MRU, 0xffffffff, 0, 0);
    ppp_recv_config(pcb,
                    PPP_MRU,
                    (pcb.lcp_gotoptions.neg_asyncmap
                         ? pcb.lcp_gotoptions.asyncmap
                         : 0xffffffff),
                    pcb.lcp_gotoptions.neg_pcompression,
                    pcb.lcp_gotoptions.neg_accompression);
    pcb.peer_mru = PPP_MRU;
    return true;
}


/*
 * lcp_starting - LCP needs the lower layer up.
 */
void lcp_starting(Fsm *f) {
    PppPcb *pcb = f->pcb;
    link_required(pcb);
}


/**
 * LCP has finished with the lower layer.
 */
bool
lcp_finished(Fsm& f, PppPcb& pcb) { return link_terminated(pcb, false); }


/**
 * Time to shut down the link because there is nothing out there.
 */
bool
lcp_link_failure(Fsm& f, PppPcb& pcb)
{
    if (f.state == PPP_FSM_OPENED)
    {
        ppp_info("No response to %d echo-requests", pcb.lcp_echos_pending);
        ppp_notice("Serial link appears to be disconnected.");
        pcb.err_code = PPPERR_PEERDEAD;
        std::string msg = "Peer not responding";
        return lcp_close(pcb, msg);
    }
    return true;
}


/**
 * Timer expired for the LCP echo requests from this process.
 */

void lcp_echo_check(Fsm *f) {
    PppPcb *pcb = f->pcb;

    lcp_send_echo_request (f);
    if (f->state != PPP_FSM_OPENED)
    {
        return;
    } /*
     * Start the timer for the next interval.
     */
    if (pcb->lcp_echo_timer_running)
    {
        ppp_warn("assertion lcp_echo_timer_running==0 failed");
    }
    Timeout (lcp_echo_timeout, f, pcb->settings.lcp_echo_interval);
    pcb->lcp_echo_timer_running = true;
}

/*
 * LcpEchoTimeout - Timer expired on the LCP echo
 */

void lcp_echo_timeout(void* arg) {
    Fsm *f = (Fsm*)arg;
    PppPcb *pcb = f->pcb;
    if (pcb->lcp_echo_timer_running != 0) {
        pcb->lcp_echo_timer_running = false;
        lcp_echo_check ((Fsm *) arg);
    }
}

/*
 * LcpEchoReply - LCP has received a reply to the echo
 */

void lcp_received_echo_reply(Fsm *f, int id, uint8_t *inp, int len) {
    PppPcb *pcb = f->pcb;
    LcpOptions *go = &pcb->lcp_gotoptions;
    uint32_t magic_val; /* Check the magic number - don't count replies from ourselves. */
    if (len < 4) {
    ppp_dbglog("lcp: received short Echo-Reply, length %d", len);
    return;
    }
    GETLONG(magic_val, inp);
    if (go->neg_magicnumber
    && magic_val == go->magicnumber) {
    ppp_warn("appear to have received our own echo-reply!");
    return;
    }

    /* Reset the number of outstanding echo frames */
    pcb->lcp_echos_pending = 0;
}

/*
 * LcpSendEchoRequest - Send an echo request frame to the peer
 */

void lcp_send_echo_request(Fsm *f) {
    PppPcb *pcb = f->pcb;
    LcpOptions *go = &pcb->lcp_gotoptions;
    uint8_t pkt[4];

    /*
     * Detect the failure of the peer at this point.
     */
    if (pcb->settings.lcp_echo_fails != 0) {
        if (pcb->lcp_echos_pending >= pcb->settings.lcp_echo_fails) {
            lcp_link_failure(f,);
            pcb->lcp_echos_pending = 0;
    }
    }

    /*
     * If adaptive echos have been enabled, only send the echo request if
     * no traffic was received since the last one.
     */
    if (pcb->settings.lcp_echo_adaptive) {
    static unsigned int last_pkts_in = 0;

    }


    /*
     * Make and send the echo request frame.
     */
    if (f->state == PPP_FSM_OPENED) {
        uint32_t lcp_magic = go->magicnumber;
    uint8_t* pktp = pkt;
    PUTLONG(lcp_magic, pktp);
        fsm_send_data(, f, ECHOREQ, pcb->lcp_echo_number++, pkt);
    ++pcb->lcp_echos_pending;
    }
}

/*
 * lcp_echo_lowerup - Start the timer for the LCP frame
 */

void lcp_echo_lowerup(PppPcb *pcb) {
    Fsm *f = &pcb->lcp_fsm;

    /* Clear the parameters for generating echo frames */
    pcb->lcp_echos_pending      = 0;
    pcb->lcp_echo_number        = 0;
    pcb->lcp_echo_timer_running = false;

    /* If a timeout interval is specified then start the timer */
    if (pcb->settings.lcp_echo_interval != 0)
    {
        lcp_echo_check (f);
    }
}

/*
 * lcp_echo_lowerdown - Stop the timer for the LCP frame
 */

void lcp_echo_lower_down(PppPcb *pcb, Fsm* f) {
    if (pcb->lcp_echo_timer_running != 0) {
        Untimeout(lcp_echo_timeout, f);
        pcb->lcp_echo_timer_running = false;
    }
}