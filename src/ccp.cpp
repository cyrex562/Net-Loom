

#include "ppp_opts.h"
#include "protent.h"
#include "lcp.h"	
#include "mppe.h"	
#include "ppp_impl.h"
#include "fsm.h"
#include "ccp.h"
#include <cstring>

constexpr auto kDeflateMinWorks = 9;

/*
 * Protocol entry points from main code.
 */
static void ccp_init(PppPcb* ppp_pcb);
static void ccp_open(PppPcb* pcb);
static void ccp_close(PppPcb* pcb, const char* reason);
static void ccp_lowerup(PppPcb* pcb);
static void ccp_lowerdown(PppPcb* pcb);
static void ccp_input(PppPcb* pcb, uint8_t* pkt, int len, Protent** protocols);
static void ccp_protrej(PppPcb* pcb);
static void ccp_datainput(PppPcb *pcb, uint8_t *pkt, int len);


const struct Protent kCcpProtent = {
    PPP_CCP,
    ccp_init,
    ccp_input,
    ccp_protrej,
    ccp_lowerup,
    ccp_lowerdown,
    ccp_open,
    ccp_close,
    ccp_datainput,
};

/*
 * Callbacks for fsm code.
 */
static void ccp_resetci(fsm*, PppPcb* pcb);
static size_t ccp_cilen(PppPcb* ppp_pcb);
static void ccp_addci(fsm*, uint8_t*, int*, PppPcb* pcb);
static int ccp_ackci(fsm*, uint8_t*, int, PppPcb* pcb);
static int ccp_nakci(fsm*, const uint8_t*, int, int, PppPcb* pcb);
static int ccp_rejci(fsm*, const uint8_t*, int, PppPcb* pcb);
static int ccp_reqci(fsm*, uint8_t*, size_t*, int, PppPcb* pcb);
static void ccp_up(fsm*, PppPcb* pcb, Protent** protocols);
static void ccp_down(fsm*, fsm* lcp_fsm, PppPcb* pcb);
static int ccp_extcode(fsm*, int, int, uint8_t*, int, PppPcb* ppp_pcb);
static void ccp_rack_timeout(void*);
static const char* method_name(struct CcpOptions*, struct CcpOptions*);

static const struct FsmCallbacks kCcpCallbacks = {
    ccp_resetci,
    ccp_cilen,
    ccp_addci,
    ccp_ackci,
    ccp_nakci,
    ccp_rejci,
    ccp_reqci,
    ccp_up,
    ccp_down,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    ccp_extcode,
    "CCP"
};

/*
 * Do we want / did we get any compression?
 */
static int ccp_anycompress(CcpOptions* opt)
{
    return ((opt)->deflate || (opt)->bsd_compress || (opt)->predictor_1 || (opt)->
        predictor_2 || (opt)->mppe);
}

/*
 * Local state (mainly for handling reset-reqs and reset-acks).
 */
constexpr auto kRackPending = 1	/* waiting for reset-ack */;
constexpr auto kRreqRepeat = 2	/* send another reset-req if no reset-ack */;
constexpr auto kRacktimeout = 1	/* second */;

/*
 * ccp_init - initialize CCP.
 */
static void ccp_init(PppPcb* ppp_pcb)
{
    ppp_pcb->ccp_fsm.protocol = PPP_CCP;
    ppp_pcb->ccp_fsm.callbacks = &kCcpCallbacks;
    fsm_init(&ppp_pcb->ccp_fsm);
    const auto wo = &ppp_pcb->ccp_wantoptions;
    const auto ao = &ppp_pcb->ccp_allowoptions;
    wo->deflate = 1;
    wo->deflate_size = DEFLATE_MAX_SIZE;
    wo->deflate_correct = 1;
    wo->deflate_draft = 1;
    ao->deflate = 1;
    ao->deflate_size = DEFLATE_MAX_SIZE;
    ao->deflate_correct = 1;
    ao->deflate_draft = 1;
    wo->bsd_compress = 1;
    wo->bsd_bits = BSD_MAX_BITS;
    ao->bsd_compress = 1;
    ao->bsd_bits = BSD_MAX_BITS;
    ao->predictor_1 = 1;
}

void ccp_reset_comp(PppPcb* pcb)
{
    switch (pcb->ccp_transmit_method)
    {
    case CI_MPPE:
        mppe_comp_reset(pcb, &pcb->mppe_comp);
        break;
    default:
        break;
    }
}

void ccp_reset_decomp(PppPcb* pcb)
{
    switch (pcb->ccp_receive_method)
    {
    case CI_MPPE:
        mppe_decomp_reset(pcb, &pcb->mppe_decomp);
        break;
    default:
        break;
    }
}


/*
 * ccp_set - inform about the current state of CCP.
 */
void ccp_set(PppPcb* pcb,
             uint8_t isopen,
             uint8_t isup,
             const uint8_t receive_method,
             const uint8_t transmit_method)
{
    pcb->ccp_receive_method = receive_method;
    pcb->ccp_transmit_method = transmit_method;
}

/*
 * ccp_open - CCP is allowed to come up.
 */
static void ccp_open(PppPcb* pcb)
{
    auto f = &pcb->ccp_fsm;
    const auto go = &pcb->ccp_gotoptions;
    if (f->state != PPP_FSM_OPENED)
        ccp_set(pcb, 1, 0, 0, 0); /*
     * Find out which compressors the kernel supports before
     * deciding whether to open in silent mode.
     */
    ccp_resetci(f, pcb);
    if (!ccp_anycompress(go))
        f->flags |= OPT_SILENT;
    fsm_open(f);
}

/*
 * ccp_close - Terminate CCP.
 */
static void ccp_close(PppPcb* pcb, const char* reason)
{
    const auto f = &pcb->ccp_fsm;
    ccp_set(pcb, 0, 0, 0, 0);
    fsm_close(f, reason);
}

/*
 * ccp_lowerup - we may now transmit CCP packets.
 */
static void ccp_lowerup(PppPcb* pcb)
{
    const auto f = &pcb->ccp_fsm;
    fsm_lowerup(f);
}

/*
 * ccp_lowerdown - we may not transmit CCP packets.
 */
static void ccp_lowerdown(PppPcb* pcb)
{
    fsm_lowerdown(&pcb->ccp_fsm);
}

/*
 * ccp_input - process a received CCP packet.
 */
static void ccp_input(PppPcb* pcb, uint8_t* pkt, int len, Protent** protocols)
{
    const auto f = &pcb->ccp_fsm;
    const auto go = &pcb->ccp_gotoptions;

    /*
     * Check for a terminate-request so we can print a message.
     */
    const auto oldstate = f->state;
    fsm_input(f, pkt, len);
    if (oldstate == PPP_FSM_OPENED && pkt[0] == TERMREQ && f->state != PPP_FSM_OPENED)
    {
        ppp_notice("Compression disabled by peer.");
	if (go->mppe) {
	    ppp_error("MPPE disabled, closing LCP");
	    lcp_close(pcb, "MPPE disabled by peer");
	}
    }

    /*
     * If we get a terminate-ack and we're not asking for compression,
     * close CCP.
     */
    if (oldstate == PPP_FSM_REQSENT && pkt[0] == TERMACK
        && !ccp_anycompress(go))
        ccp_close(pcb, "No compression negotiated");
}

/*
 * Handle a CCP-specific code.
 */
static int ccp_extcode(fsm* f,
                       const int code,
                       const int id,
                       uint8_t* p,
                       int len,
                       PppPcb* ppp_pcb)
{
    switch (code)
    {
    case CCP_RESETREQ:
        if (f->state != PPP_FSM_OPENED)
            break;
        ccp_reset_comp(ppp_pcb);
        /* send a reset-ack, which the transmitter will see and
           reset its compression state. */
        fsm_sdata(f, CCP_RESETACK, id, nullptr, 0);
        break;

    case CCP_RESETACK:
        if ((ppp_pcb->ccp_localstate & kRackPending) && id == f->reqid)
        {
            ppp_pcb->ccp_localstate &= ~(kRackPending | kRreqRepeat);
            Untimeout(ccp_rack_timeout, f);
            ccp_reset_decomp(ppp_pcb);
        }
        break;

    default:
        return 0;
    }

    return 1;
}

/*
 * ccp_protrej - peer doesn't talk CCP.
 */
static void ccp_protrej(PppPcb* pcb)
{
    const auto f = &pcb->ccp_fsm;
    const auto go = &pcb->ccp_gotoptions;

    ccp_set(pcb, 0, 0, 0, 0);
    fsm_lowerdown(f);

    if (go->mppe) {
	ppp_error("MPPE required but peer negotiation failed");
	lcp_close(pcb, "MPPE required but peer negotiation failed");
    }
}

/*
 * ccp_resetci - initialize at start of negotiation.
 */
static void ccp_resetci(fsm* f, PppPcb* pcb)
{
    // PppPcb* pcb = f->pcb;
    auto go = &pcb->ccp_gotoptions;
    auto wo = &pcb->ccp_wantoptions;
    const auto ao = &pcb->ccp_allowoptions;
    uint8_t opt_buf[CCP_MAX_OPTION_LENGTH];
    int res;

    if (pcb->settings.require_mppe)
    {
        wo->mppe = ao->mppe =
            (pcb->settings.refuse_mppe_40 ? 0 : MPPE_OPT_40)
            | (pcb->settings.refuse_mppe_128 ? 0 : MPPE_OPT_128);
    }


    *go = *wo;
    pcb->ccp_all_rejected = 0;

    if (go->mppe)
    {
        int auth_mschap_bits = pcb->auth_done; /*
         * Start with a basic sanity check: mschap[v2] auth must be in
         * exactly one direction.  RFC 3079 says that the keys are
         * 'derived from the credentials of the peer that initiated the call',
         * however the PPP protocol doesn't have such a concept, and pppd
         * cannot get this info externally.  Instead we do the best we can.
         * NB: If MPPE is required, all other compression opts are invalid.
         *     So, we return right away if we can't do it.
         */

        /* Leave only the mschap auth bits set */
        auth_mschap_bits &= (CHAP_MS_WITHPEER | CHAP_MS_PEER |
            CHAP_MS2_WITHPEER | CHAP_MS2_PEER);
        /* Count the mschap auths */
        auth_mschap_bits >>= CHAP_MS_SHIFT;
        auto numbits = 0;
        do
        {
            numbits += auth_mschap_bits & 1;
            auth_mschap_bits >>= 1;
        }
        while (auth_mschap_bits);
        if (numbits > 1)
        {
            ppp_error("MPPE required, but auth done in both directions.");
            lcp_close(pcb, "MPPE required but not available");
            return;
        }
        if (!numbits)
        {
            ppp_error("MPPE required, but MS-CHAP[v2] auth not performed.");
            lcp_close(pcb, "MPPE required but not available");
            return;
        }

        /* A plugin (eg radius) may not have obtained key material. */
        if (!pcb->mppe_keys_set)
        {
            ppp_error("MPPE required, but keys are not available.  "
                "Possible plugin problem?");
            lcp_close(pcb, "MPPE required but not available");
            return;
        }

        /* LM auth not supported for MPPE */
        if (pcb->auth_done & (CHAP_MS_WITHPEER | CHAP_MS_PEER))
        {
            /* This might be noise */
            if (go->mppe & MPPE_OPT_40)
            {
                ppp_notice("Disabling 40-bit MPPE; MS-CHAP LM not supported");
                go->mppe &= ~MPPE_OPT_40;
                wo->mppe &= ~MPPE_OPT_40;
            }
        }

        /* Last check: can we actually negotiate something? */
        if (!(go->mppe & (MPPE_OPT_40 | MPPE_OPT_128)))
        {
            /* Could be misconfig, could be 40-bit disabled above. */
            ppp_error("MPPE required, but both 40-bit and 128-bit disabled.");
            lcp_close(pcb, "MPPE required but not available");
            return;
        }

        /* sync options */
        ao->mppe = go->mppe;
        /* MPPE is not compatible with other compression types */
        ao->bsd_compress = go->bsd_compress = 0;
        ao->predictor_1 = go->predictor_1 = 0;
        ao->predictor_2 = go->predictor_2 = 0;
        ao->deflate = go->deflate = 0;
    }

    /*
     * Check whether the kernel knows about the various
     * compression methods we might request.
     */
    /* FIXME: we don't need to test if BSD compress is available
     * if BSDCOMPRESS_SUPPORT is set, it is.
     */
    if (go->bsd_compress)
    {
        opt_buf[0] = CI_BSD_COMPRESS;
        opt_buf[1] = CILEN_BSD_COMPRESS;
        for (;;)
        {
            if (go->bsd_bits < BSD_MIN_BITS)
            {
                go->bsd_compress = 0;
                break;
            }
            opt_buf[2] = BSD_MAKE_OPT(BSD_CURRENT_VERSION, go->bsd_bits);
            res = ccp_test(pcb, opt_buf, CILEN_BSD_COMPRESS, 0);
            if (res > 0)
            {
                break;
            }
            else if (res < 0)
            {
                go->bsd_compress = 0;
                break;
            }
            go->bsd_bits--;
        }
    }
    /* FIXME: we don't need to test if deflate is available
     * if DEFLATE_SUPPORT is set, it is.
     */
    if (go->deflate)
    {
        if (go->deflate_correct)
        {
            opt_buf[0] = CI_DEFLATE;
            opt_buf[1] = CILEN_DEFLATE;
            opt_buf[3] = DEFLATE_CHK_SEQUENCE;
            for (;;)
            {
                if (go->deflate_size < kDeflateMinWorks)
                {
                    go->deflate_correct = 0;
                    break;
                }
                opt_buf[2] = DEFLATE_MAKE_OPT(go->deflate_size);
                res = ccp_test(pcb, opt_buf, CILEN_DEFLATE, 0);
                if (res > 0)
                {
                    break;
                }
                else if (res < 0)
                {
                    go->deflate_correct = 0;
                    break;
                }
                go->deflate_size--;
            }
        }
        if (go->deflate_draft)
        {
            opt_buf[0] = CI_DEFLATE_DRAFT;
            opt_buf[1] = CILEN_DEFLATE;
            opt_buf[3] = DEFLATE_CHK_SEQUENCE;
            for (;;)
            {
                if (go->deflate_size < kDeflateMinWorks)
                {
                    go->deflate_draft = 0;
                    break;
                }
                opt_buf[2] = DEFLATE_MAKE_OPT(go->deflate_size);
                res = ccp_test(pcb, opt_buf, CILEN_DEFLATE, 0);
                if (res > 0)
                {
                    break;
                }
                else if (res < 0)
                {
                    go->deflate_draft = 0;
                    break;
                }
                go->deflate_size--;
            }
        }
        if (!go->deflate_correct && !go->deflate_draft)
            go->deflate = 0;
    }

    /* FIXME: we don't need to test if predictor is available,
     * if PREDICTOR_SUPPORT is set, it is.
     */
    if (go->predictor_1)
    {
        opt_buf[0] = CI_PREDICTOR_1;
        opt_buf[1] = CILEN_PREDICTOR_1;
        if (ccp_test(pcb, opt_buf, CILEN_PREDICTOR_1, 0) <= 0)
            go->predictor_1 = 0;
    }
    if (go->predictor_2)
    {
        opt_buf[0] = CI_PREDICTOR_2;
        opt_buf[1] = CILEN_PREDICTOR_2;
        if (ccp_test(pcb, opt_buf, CILEN_PREDICTOR_2, 0) <= 0)
            go->predictor_2 = 0;
    }
}

/*
 * ccp_cilen - Return total length of our configuration info.
 */
static size_t ccp_cilen(PppPcb* ppp_pcb)
{
    auto go = &ppp_pcb->ccp_gotoptions;

    return 0
        + (go->bsd_compress ? CILEN_BSD_COMPRESS : 0)
        + (go->deflate && go->deflate_correct ? CILEN_DEFLATE : 0)
        + (go->deflate && go->deflate_draft ? CILEN_DEFLATE : 0)
        + (go->predictor_1 ? CILEN_PREDICTOR_1 : 0)
        + (go->predictor_2 ? CILEN_PREDICTOR_2 : 0)
        + (go->mppe ? CILEN_MPPE : 0);
}

/*
 * ccp_addci - put our requests in a packet.
 */
static void ccp_addci(fsm* f, uint8_t* p, int* lenp, PppPcb* pcb)
{
    // PppPcb* pcb = f->pcb;
    const auto go = &pcb->ccp_gotoptions;
    const auto p0 = p;

    /*
     * Add the compression types that we can receive, in decreasing
     * preference order.
     */
    if (go->mppe)
    {
        p[0] = CI_MPPE;
        p[1] = CILEN_MPPE;
        MPPE_OPTS_TO_CI(go->mppe, &p[2]);
        mppe_init(pcb, &pcb->mppe_decomp, go->mppe);
        p += CILEN_MPPE;
    }
    if (go->deflate)
    {
        if (go->deflate_correct)
        {
            p[0] = CI_DEFLATE;
            p[1] = CILEN_DEFLATE;
            p[2] = DEFLATE_MAKE_OPT(go->deflate_size);
            p[3] = DEFLATE_CHK_SEQUENCE;
            p += CILEN_DEFLATE;
        }
        if (go->deflate_draft)
        {
            p[0] = CI_DEFLATE_DRAFT;
            p[1] = CILEN_DEFLATE;
            p[2] = p[2 - CILEN_DEFLATE];
            p[3] = DEFLATE_CHK_SEQUENCE;
            p += CILEN_DEFLATE;
        }
    }
    if (go->bsd_compress)
    {
        p[0] = CI_BSD_COMPRESS;
        p[1] = CILEN_BSD_COMPRESS;
        p[2] = BSD_MAKE_OPT(BSD_CURRENT_VERSION, go->bsd_bits);
        p += CILEN_BSD_COMPRESS;
    }

    /* XXX Should Predictor 2 be preferable to Predictor 1? */
    if (go->predictor_1)
    {
        p[0] = CI_PREDICTOR_1;
        p[1] = CILEN_PREDICTOR_1;
        p += CILEN_PREDICTOR_1;
    }
    if (go->predictor_2)
    {
        p[0] = CI_PREDICTOR_2;
        p[1] = CILEN_PREDICTOR_2;
        p += CILEN_PREDICTOR_2;
    }


    go->method = (p > p0) ? p0[0] : 0;

    *lenp = p - p0;
}

/*
 * ccp_ackci - process a received configure-ack, and return
 * 1 iff the packet was OK.
 */
static int ccp_ackci(fsm* f, uint8_t* p, int len, PppPcb* pcb)
{
    // PppPcb* pcb = f->pcb;
    const auto go = &pcb->ccp_gotoptions;
    const auto p0 = p;

    if (go->mppe)
    {
        uint8_t opt_buf[CILEN_MPPE];

        opt_buf[0] = CI_MPPE;
        opt_buf[1] = CILEN_MPPE;
        MPPE_OPTS_TO_CI(go->mppe, &opt_buf[2]);
        if (len < CILEN_MPPE || memcmp(opt_buf, p, CILEN_MPPE))
            return 0;
        p += CILEN_MPPE;
        len -= CILEN_MPPE;
        /* XXX Cope with first/fast ack */
        if (len == 0)
            return 1;
    }

    if (go->deflate)
    {
        if (len < CILEN_DEFLATE
            || p[0] != (go->deflate_correct ? CI_DEFLATE : CI_DEFLATE_DRAFT)
            || p[1] != CILEN_DEFLATE
            || p[2] != DEFLATE_MAKE_OPT(go->deflate_size)
            || p[3] != DEFLATE_CHK_SEQUENCE)
            return 0;
        p += CILEN_DEFLATE;
        len -= CILEN_DEFLATE;
        /* XXX Cope with first/fast ack */
        if (len == 0)
            return 1;
        if (go->deflate_correct && go->deflate_draft)
        {
            if (len < CILEN_DEFLATE
                || p[0] != CI_DEFLATE_DRAFT
                || p[1] != CILEN_DEFLATE
                || p[2] != DEFLATE_MAKE_OPT(go->deflate_size)
                || p[3] != DEFLATE_CHK_SEQUENCE)
                return 0;
            p += CILEN_DEFLATE;
            len -= CILEN_DEFLATE;
        }
    }

    if (go->bsd_compress)
    {
        if (len < CILEN_BSD_COMPRESS
            || p[0] != CI_BSD_COMPRESS || p[1] != CILEN_BSD_COMPRESS
            || p[2] != BSD_MAKE_OPT(BSD_CURRENT_VERSION, go->bsd_bits))
            return 0;
        p += CILEN_BSD_COMPRESS;
        len -= CILEN_BSD_COMPRESS;
        /* XXX Cope with first/fast ack */
        if (p == p0 && len == 0)
            return 1;
    }

    if (go->predictor_1)
    {
        if (len < CILEN_PREDICTOR_1
            || p[0] != CI_PREDICTOR_1 || p[1] != CILEN_PREDICTOR_1)
            return 0;
        p += CILEN_PREDICTOR_1;
        len -= CILEN_PREDICTOR_1;
        /* XXX Cope with first/fast ack */
        if (p == p0 && len == 0)
            return 1;
    }
    if (go->predictor_2)
    {
        if (len < CILEN_PREDICTOR_2
            || p[0] != CI_PREDICTOR_2 || p[1] != CILEN_PREDICTOR_2)
            return 0;
        p += CILEN_PREDICTOR_2;
        len -= CILEN_PREDICTOR_2;
        /* XXX Cope with first/fast ack */
        if (p == p0 && len == 0)
            return 1;
    }


    if (len != 0)
        return 0;
    return 1;
}

/*
 * ccp_nakci - process received configure-nak.
 * Returns 1 iff the nak was OK.
 */
static int ccp_nakci(fsm* f, const uint8_t* p, int len, int treat_as_reject, PppPcb* pcb)
{
    // PppPcb* pcb = f->pcb;
    auto go = &pcb->ccp_gotoptions;
    ccp_options no; /* options we've seen already */
    memset(&no, 0, sizeof(no));
    auto try_ = *go;

    if (go->mppe && len >= CILEN_MPPE
        && p[0] == CI_MPPE && p[1] == CILEN_MPPE)
    {
        no.mppe = 1;
        /*
         * Peer wants us to use a different strength or other setting.
         * Fail if we aren't willing to use his suggestion.
         */
        MPPE_CI_TO_OPTS(&p[2], try_.mppe);
        if ((try_.mppe & MPPE_OPT_STATEFUL) && pcb->settings.refuse_mppe_stateful)
        {
            ppp_error("Refusing MPPE stateful mode offered by peer");
            try_.mppe = 0;
        }
        else if (((go->mppe | MPPE_OPT_STATEFUL) & try_.mppe) != try_.mppe)
        {
            /* Peer must have set options we didn't request (suggest) */
            try_.mppe = 0;
        }

        if (!try_.mppe)
        {
            ppp_error("MPPE required but peer negotiation failed");
            lcp_close(pcb, "MPPE required but peer negotiation failed");
        }
    }

    if (go->deflate && len >= CILEN_DEFLATE
        && p[0] == (go->deflate_correct ? CI_DEFLATE : CI_DEFLATE_DRAFT)
        && p[1] == CILEN_DEFLATE)
    {
        no.deflate = 1;
        /*
         * Peer wants us to use a different code size or something.
         * Stop asking for Deflate if we don't understand his suggestion.
         */
        if (DEFLATE_METHOD(p[2]) != DEFLATE_METHOD_VAL
            || DEFLATE_SIZE(p[2]) < kDeflateMinWorks
            || p[3] != DEFLATE_CHK_SEQUENCE)
            try_.deflate = 0;
        else if (DEFLATE_SIZE(p[2]) < go->deflate_size)
            try_.deflate_size = DEFLATE_SIZE(p[2]);
        p += CILEN_DEFLATE;
        len -= CILEN_DEFLATE;
        if (go->deflate_correct && go->deflate_draft
            && len >= CILEN_DEFLATE && p[0] == CI_DEFLATE_DRAFT
            && p[1] == CILEN_DEFLATE)
        {
            p += CILEN_DEFLATE;
            len -= CILEN_DEFLATE;
        }
    }

    if (go->bsd_compress && len >= CILEN_BSD_COMPRESS
        && p[0] == CI_BSD_COMPRESS && p[1] == CILEN_BSD_COMPRESS)
    {
        no.bsd_compress = 1;
        /*
         * Peer wants us to use a different number of bits
         * or a different version.
         */
        if (BSD_VERSION(p[2]) != BSD_CURRENT_VERSION)
            try_.bsd_compress = 0;
        else if (BSD_NBITS(p[2]) < go->bsd_bits)
            try_.bsd_bits = BSD_NBITS(p[2]);
        p += CILEN_BSD_COMPRESS;
        len -= CILEN_BSD_COMPRESS;
    }


    /*
     * Predictor-1 and 2 have no options, so they can't be Naked.
     *
     * There may be remaining options but we ignore them.
     */

    if (f->state != PPP_FSM_OPENED)
        *go = try_;
    return 1;
} 

//
// ccp_rejci - reject some of our suggested compression methods.
//
static int ccp_rejci(fsm* f, const uint8_t* p, int len, PppPcb* pcb)
{
    // PppPcb* pcb = f->pcb;
    const auto go = &pcb->ccp_gotoptions;
    auto try_ = *go; /*
     * Cope with empty configure-rejects by ceasing to send
     * configure-requests.
     */
    if (len == 0 && pcb->ccp_all_rejected)
        return -1;
    if (go->mppe && len >= CILEN_MPPE && p[0] == CI_MPPE && p[1] == CILEN_MPPE)
    {
        ppp_error("MPPE required but peer refused");
        lcp_close(pcb, "MPPE required but peer refused");
        p += CILEN_MPPE;
        len -= CILEN_MPPE;
    }
    if (go->deflate_correct && len >= CILEN_DEFLATE && p[0] == CI_DEFLATE && p[1] ==
        CILEN_DEFLATE)
    {
        if (p[2] != DEFLATE_MAKE_OPT(go->deflate_size) || p[3] != DEFLATE_CHK_SEQUENCE)
            return 0; /* Rej is bad */
        try_.deflate_correct = 0;
        p += CILEN_DEFLATE;
        len -= CILEN_DEFLATE;
    }
    if (go->deflate_draft && len >= CILEN_DEFLATE && p[0] == CI_DEFLATE_DRAFT && p[1] ==
        CILEN_DEFLATE)
    {
        if (p[2] != DEFLATE_MAKE_OPT(go->deflate_size) || p[3] != DEFLATE_CHK_SEQUENCE)
            return 0; /* Rej is bad */
        try_.deflate_draft = 0;
        p += CILEN_DEFLATE;
        len -= CILEN_DEFLATE;
    }
    if (!try_.deflate_correct && !try_.deflate_draft)
        try_.deflate = 0;
    if (go->bsd_compress && len >= CILEN_BSD_COMPRESS && p[0] == CI_BSD_COMPRESS && p[1]
        == CILEN_BSD_COMPRESS)
    {
        if (p[2] != BSD_MAKE_OPT(BSD_CURRENT_VERSION, go->bsd_bits))
            return 0;
        try_.bsd_compress = 0;
        p += CILEN_BSD_COMPRESS;
        len -= CILEN_BSD_COMPRESS;
    }
    if (go->predictor_1 && len >= CILEN_PREDICTOR_1 && p[0] == CI_PREDICTOR_1 && p[1] ==
        CILEN_PREDICTOR_1)
    {
        try_.predictor_1 = 0;
        p += CILEN_PREDICTOR_1;
        len -= CILEN_PREDICTOR_1;
    }
    if (go->predictor_2 && len >= CILEN_PREDICTOR_2 && p[0] == CI_PREDICTOR_2 && p[1] ==
        CILEN_PREDICTOR_2)
    {
        try_.predictor_2 = 0;
        p += CILEN_PREDICTOR_2;
        len -= CILEN_PREDICTOR_2;
    }
    if (len != 0)
        return 0;
    if (f->state != PPP_FSM_OPENED)
        *go = try_;
    return 1;
}

/*
 * ccp_reqci - processed a received configure-request.
 * Returns CONFACK, CONFNAK or CONFREJ and the packet modified
 * appropriately.
 */
static int ccp_reqci(fsm* f, uint8_t* p, size_t* lenp, const int dont_nak, PppPcb* pcb)
{
    // PppPcb* pcb = f->pcb;
    CcpOptions* ho = &pcb->ccp_hisoptions;
    CcpOptions* ao = &pcb->ccp_allowoptions;
    int res;
    int nb;
#endif /* DEFLATE_SUPPORT || BSDCOMPRESS_SUPPORT */
    uint8_t *p0, *retp;
    int len, clen, type;
#if MPPE_SUPPORT
    uint8_t rej_for_ci_mppe = 1;	/* Are we rejecting based on a bad/missing */
				/* CI_MPPE, or due to other options?       */
#endif /* MPPE_SUPPORT */

    int ret = CONFACK;
    uint8_t* retp = p0 = p;
    size_t len = *lenp;

    memset(ho, 0, sizeof(CcpOptions));
    ho->method = (len > 0) ? p[0] : 0;

    while (len > 0)
    {
        int newret = CONFACK;
        if (len < 2 || p[1] < 2 || p[1] > len)
        {
            /* length is bad */
            clen = len;
            newret = CONFREJ;
        }
        else
        {
            int type = p[0];
            clen = p[1];

            switch (type)
            {
            case CI_MPPE:
                if (!ao->mppe || clen != CILEN_MPPE)
                {
                    newret = CONFREJ;
                    break;
                }
                MPPE_CI_TO_OPTS(&p[2], ho->mppe);

                /* Nak if anything unsupported or unknown are set. */
                if (ho->mppe & MPPE_OPT_UNSUPPORTED)
                {
                    newret = CONFNAK;
                    ho->mppe &= ~MPPE_OPT_UNSUPPORTED;
                }
                if (ho->mppe & MPPE_OPT_UNKNOWN)
                {
                    newret = CONFNAK;
                    ho->mppe &= ~MPPE_OPT_UNKNOWN;
                }

                /* Check state opt */
                if (ho->mppe & MPPE_OPT_STATEFUL)
                {
                    /*
                     * We can Nak and request stateless, but it's a
                     * lot easier to just assume the peer will request
                     * it if he can do it; stateful mode is bad over
                     * the Internet -- which is where we expect MPPE.
                     */
                    if (pcb->settings.refuse_mppe_stateful)
                    {
                        ppp_error("Refusing MPPE stateful mode offered by peer");
                        newret = CONFREJ;
                        break;
                    }
                }

                /* Find out which of {S,L} are set. */
                if ((ho->mppe & MPPE_OPT_128)
                    && (ho->mppe & MPPE_OPT_40))
                {
                    /* Both are set, negotiate the strongest. */
                    newret = CONFNAK;
                    if (ao->mppe & MPPE_OPT_128)
                        ho->mppe &= ~MPPE_OPT_40;
                    else if (ao->mppe & MPPE_OPT_40)
                        ho->mppe &= ~MPPE_OPT_128;
                    else
                    {
                        newret = CONFREJ;
                        break;
                    }
                }
                else if (ho->mppe & MPPE_OPT_128)
                {
                    if (!(ao->mppe & MPPE_OPT_128))
                    {
                        newret = CONFREJ;
                        break;
                    }
                }
                else if (ho->mppe & MPPE_OPT_40)
                {
                    if (!(ao->mppe & MPPE_OPT_40))
                    {
                        newret = CONFREJ;
                        break;
                    }
                }
                else
                {
                    /* Neither are set. */
                    /* We cannot accept this.  */
                    newret = CONFNAK;
                    /* Give the peer our idea of what can be used,
                       so it can choose and confirm */
                    ho->mppe = ao->mppe;
                }

                /* rebuild the opts */
                MPPE_OPTS_TO_CI(ho->mppe, &p[2]);
                if (newret == CONFACK)
                {
                    mppe_init(pcb, &pcb->mppe_comp, ho->mppe);
                    /*
                     * We need to decrease the interface MTU by MPPE_PAD
                     * because MPPE frames **grow**.  The kernel [must]
                     * allocate MPPE_PAD extra bytes in xmit buffers.
                     */
                    auto mtu = netif_get_mtu(pcb);
                    if (mtu)
                        netif_set_mtu(pcb, mtu - MPPE_PAD);
                    else
                        newret = CONFREJ;
                }

                /*
                 * We have accepted MPPE or are willing to negotiate
                 * MPPE parameters.  A CONFREJ is due to subsequent
                 * (non-MPPE) processing.
                 */
                rej_for_ci_mppe = 0;
                break;
            case CI_DEFLATE:
            case CI_DEFLATE_DRAFT:
                if (!ao->deflate || clen != CILEN_DEFLATE
                    || (!ao->deflate_correct && type == CI_DEFLATE)
                    || (!ao->deflate_draft && type == CI_DEFLATE_DRAFT))
                {
                    newret = CONFREJ;
                    break;
                }

                ho->deflate = 1;
                ho->deflate_size = nb = DEFLATE_SIZE(p[2]);
                if (DEFLATE_METHOD(p[2]) != DEFLATE_METHOD_VAL
                    || p[3] != DEFLATE_CHK_SEQUENCE
                    || nb > ao->deflate_size || nb < kDeflateMinWorks)
                {
                    newret = CONFNAK;
                    if (!dont_nak)
                    {
                        p[2] = DEFLATE_MAKE_OPT(ao->deflate_size);
                        p[3] = DEFLATE_CHK_SEQUENCE;
                        /* fall through to test this #bits below */
                    }
                    else
                        break;
                }

                /*
                 * Check whether we can do Deflate with the window
                 * size they want.  If the window is too big, reduce
                 * it until the kernel can cope and nak with that.
                 * We only check this for the first option.
                 */
                if (p == p0)
                {
                    for (;;)
                    {
                        res = ccp_test(pcb, p, CILEN_DEFLATE, 1);
                        if (res > 0)
                            break; /* it's OK now */
                        if (res < 0 || nb == kDeflateMinWorks || dont_nak)
                        {
                            newret = CONFREJ;
                            p[2] = DEFLATE_MAKE_OPT(ho->deflate_size);
                            break;
                        }
                        newret = CONFNAK;
                        --nb;
                        p[2] = DEFLATE_MAKE_OPT(nb);
                    }
                }
                break;
            case CI_BSD_COMPRESS:
                if (!ao->bsd_compress || clen != CILEN_BSD_COMPRESS)
                {
                    newret = CONFREJ;
                    break;
                }

                ho->bsd_compress = 1;
                ho->bsd_bits = nb = BSD_NBITS(p[2]);
                if (BSD_VERSION(p[2]) != BSD_CURRENT_VERSION
                    || nb > ao->bsd_bits || nb < BSD_MIN_BITS)
                {
                    newret = CONFNAK;
                    if (!dont_nak)
                    {
                        p[2] = BSD_MAKE_OPT(BSD_CURRENT_VERSION, ao->bsd_bits);
                        /* fall through to test this #bits below */
                    }
                    else
                        break;
                }

                /*
                 * Check whether we can do BSD-Compress with the code
                 * size they want.  If the code size is too big, reduce
                 * it until the kernel can cope and nak with that.
                 * We only check this for the first option.
                 */
                if (p == p0)
                {
                    for (;;)
                    {
                        res = ccp_test(pcb, p, CILEN_BSD_COMPRESS, 1);
                        if (res > 0)
                            break;
                        if (res < 0 || nb == BSD_MIN_BITS || dont_nak)
                        {
                            newret = CONFREJ;
                            p[2] = BSD_MAKE_OPT(BSD_CURRENT_VERSION,
                                                ho->bsd_bits);
                            break;
                        }
                        newret = CONFNAK;
                        --nb;
                        p[2] = BSD_MAKE_OPT(BSD_CURRENT_VERSION, nb);
                    }
                }
                break;
            case CI_PREDICTOR_1:
                if (!ao->predictor_1 || clen != CILEN_PREDICTOR_1)
                {
                    newret = CONFREJ;
                    break;
                }

                ho->predictor_1 = 1;
                if (p == p0
                    && ccp_test(pcb, p, CILEN_PREDICTOR_1, 1) <= 0)
                {
                    newret = CONFREJ;
                }
                break;

            case CI_PREDICTOR_2:
                if (!ao->predictor_2 || clen != CILEN_PREDICTOR_2)
                {
                    newret = CONFREJ;
                    break;
                }

                ho->predictor_2 = 1;
                if (p == p0
                    && ccp_test(pcb, p, CILEN_PREDICTOR_2, 1) <= 0)
                {
                    newret = CONFREJ;
                }
                break;
            default:
                newret = CONFREJ;
            }
        }

        if (newret == CONFNAK && dont_nak)
            newret = CONFREJ;
        if (!(newret == CONFACK || (newret == CONFNAK && ret == CONFREJ)))
        {
            /* we're returning this option */
            if (newret == CONFREJ && ret == CONFNAK)
                retp = p0;
            ret = newret;
            if (p != retp)
                MEMCPY(retp, p, clen);
            retp += clen;
        }

        p += clen;
        len -= clen;
    }

    if (ret != CONFACK)
    {
        if (ret == CONFREJ && *lenp == retp - p0)
            pcb->ccp_all_rejected = 1;
        else
            *lenp = retp - p0;
    }
    if (ret == CONFREJ && ao->mppe && rej_for_ci_mppe)
    {
        ppp_error("MPPE required but peer negotiation failed");
        lcp_close(pcb, "MPPE required but peer negotiation failed");
    }
    return ret;
}

/*
 * Make a string name for a compression method (or 2).
 */
static const char* method_name(CcpOptions* opt, CcpOptions* opt2)
{
    static char result[64];

    if (!ccp_anycompress(opt))
        return "(none)";
    switch (opt->method)
    {
    case CI_MPPE:
    {
        auto p = result;
        auto q = result + sizeof(result); /* 1 past result */

	ppp_slprintf(p, q - p, "MPPE ");
	p += 5;
	if (opt->mppe & MPPE_OPT_128) {
	    ppp_slprintf(p, q - p, "128-bit ");
	    p += 8;
	}
	if (opt->mppe & MPPE_OPT_40) {
	    ppp_slprintf(p, q - p, "40-bit ");
	    p += 7;
	}
	if (opt->mppe & MPPE_OPT_STATEFUL)
	    ppp_slprintf(p, q - p, "stateful");
	else
	    ppp_slprintf(p, q - p, "stateless");

	break;
    }


    case CI_DEFLATE:
    case CI_DEFLATE_DRAFT:
	if (opt2 != nullptr && opt2->deflate_size != opt->deflate_size)
	    ppp_slprintf(result, sizeof(result), "Deflate%s (%d/%d)",
		     (opt->method == CI_DEFLATE_DRAFT? "(old#)": ""),
		     opt->deflate_size, opt2->deflate_size);
	else
	    ppp_slprintf(result, sizeof(result), "Deflate%s (%d)",
		     (opt->method == CI_DEFLATE_DRAFT? "(old#)": ""),
		     opt->deflate_size);
	break;

    case CI_BSD_COMPRESS:
	if (opt2 != nullptr && opt2->bsd_bits != opt->bsd_bits)
	    ppp_slprintf(result, sizeof(result), "BSD-Compress (%d/%d)",
		     opt->bsd_bits, opt2->bsd_bits);
	else
	    ppp_slprintf(result, sizeof(result), "BSD-Compress (%d)",
		     opt->bsd_bits);
	break;


    case CI_PREDICTOR_1:
	return "Predictor 1";
    case CI_PREDICTOR_2:
	return "Predictor 2";

    default:
        ppp_slprintf(result, sizeof(result), "Method %d", opt->method);
    }
    return result;
}

/*
 * CCP has come up - inform the kernel driver and log a message.
 */
static void ccp_up(fsm* f, PppPcb* pcb, Protent** protocols)
{
    const auto go = &pcb->ccp_gotoptions;
    const auto ho = &pcb->ccp_hisoptions;
    char method1[64];

    ccp_set(pcb, 1, 1, go->method, ho->method);
    if (ccp_anycompress(go))
    {
        if (ccp_anycompress(ho))
        {
            if (go->method == ho->method)
            {
                ppp_notice("%s compression enabled", method_name(go, ho));
            }
            else
            {
                ppp_strlcpy(method1, method_name(go, nullptr), sizeof(method1));
                ppp_notice("%s / %s compression enabled",
                           method1, method_name(ho, nullptr));
            }
        }
        else
            ppp_notice("%s receive compression enabled", method_name(go, nullptr));
    }
    else if (ccp_anycompress(ho))
        ppp_notice("%s transmit compression enabled", method_name(ho, nullptr));
    if (go->mppe)
    {
        continue_networks(pcb, protocols); /* Bring up IP et al */
    }
}

/*
 * CCP has gone down - inform the kernel driver.
 */
static void ccp_down(fsm* f, fsm* lcp_fsm, PppPcb* pcb)
{
    // PppPcb* pcb = f->pcb;
    const auto go = &pcb->ccp_gotoptions;

    if (pcb->ccp_localstate & kRackPending)
        Untimeout(ccp_rack_timeout, f);
    pcb->ccp_localstate = 0;
    ccp_set(pcb, 1, 0, 0, 0);
    if (go->mppe)
    {
        go->mppe = 0;
        if (lcp_fsm->state == PPP_FSM_OPENED)
        {
            /* If LCP is not already going down, make sure it does. */
            ppp_error("MPPE disabled");
            lcp_close(pcb, "MPPE disabled");
        }
    }
}

/*
 * We have received a packet that the decompressor failed to
 * decompress.  Here we would expect to issue a reset-request, but
 * Motorola has a patent on resetting the compressor as a result of
 * detecting an error in the decompressed data after decompression.
 * (See US patent 5,130,993; international patent publication number
 * WO 91/10289; Australian patent 73296/91.)
 *
 * So we ask the kernel whether the error was detected after
 * decompression; if it was, we take CCP down, thus disabling
 * compression :-(, otherwise we issue the reset-request.
 */
static void ccp_datainput(PppPcb* pcb, uint8_t* pkt, int len)
{
    auto go = &pcb->ccp_gotoptions;
    const auto f = &pcb->ccp_fsm;
    if (f->state == PPP_FSM_OPENED) {
// 	if (ccp_fatal_error(pcb)) {
// 	    /*
// 	     * Disable compression by taking CCP down.
// 	     */
// 	    ppp_error("Lost compression sync: disabling compression");
// 	    ccp_close(pcb, "Lost compression sync");
// #if MPPE_SUPPORT
// 	    /*
// 	     * If we were doing MPPE, we must also take the link down.
// 	     */
// 	    if (go->mppe) {
// 		ppp_error("Too many MPPE errors, closing LCP");
// 		lcp_close(pcb, "Too many MPPE errors");
// 	    }
// #endif /* MPPE_SUPPORT */
// 	} else {
// 	    /*
// 	     * Send a reset-request to reset the peer's compressor.
// 	     * We don't do that if we are still waiting for an
// 	     * acknowledgement to a previous reset-request.
// 	     */
// 	    if (!(pcb->ccp_localstate & RACK_PENDING)) {
// 		fsm_sdata(f, CCP_RESETREQ, f->reqid = ++f->id, NULL, 0);
// 		TIMEOUT(ccp_rack_timeout, f, RACKTIMEOUT);
// 		pcb->ccp_localstate |= RACK_PENDING;
// 	    } else
// 		pcb->ccp_localstate |= RREQ_REPEAT;
// 	}
    }
}

/*
 * We have received a packet that the decompressor failed to
 * decompress. Issue a reset-request.
 */
void ccp_resetrequest(uint8_t* ppp_pcb_ccp_local_state, fsm* f)
{
    if (f->state != PPP_FSM_OPENED)
        return;

    /*
     * Send a reset-request to reset the peer's compressor.
     * We don't do that if we are still waiting for an
     * acknowledgement to a previous reset-request.
     */
    if (!(*ppp_pcb_ccp_local_state & kRackPending))
    {
        fsm_sdata(f, CCP_RESETREQ, f->reqid = ++f->id, nullptr, 0);
        TIMEOUT(ccp_rack_timeout, f, kRacktimeout);
        *ppp_pcb_ccp_local_state |= kRackPending;
    }
    else
        *ppp_pcb_ccp_local_state |= kRreqRepeat;
}


/*
 * Timeout waiting for reset-ack.
 */
static void ccp_rack_timeout(void* arg)
{
    auto args = static_cast<CcpRackTimeoutArgs*>(arg);

    if (args->f->state == PPP_FSM_OPENED && (args->pcb->ccp_localstate & kRreqRepeat))
    {
        fsm_sdata(args->f, CCP_RESETREQ, args->f->reqid, nullptr, 0);
        TIMEOUT(ccp_rack_timeout, args, kRacktimeout);
        args->pcb->ccp_localstate &= ~kRreqRepeat;
    }
    else
        args->pcb->ccp_localstate &= ~kRackPending;
}
