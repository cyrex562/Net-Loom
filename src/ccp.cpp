
#define NOMINMAX
#include "auth.h"
#include "ccp.h"
#include <cstring>
#include "auth.h"
#include "ppp.h"
#include <spdlog/spdlog.h>


/*
 * Do we want / did we get any compression?
 */
bool
ccp_anycompress(CcpOptions& options)
{
    return ((options).deflate || (options).bsd_compress || (options).predictor_1 || (options).
        predictor_2 || (options).mppe);
}



/*
 * ccp_init - initialize CCP.
 */
bool
ccp_init(PppPcb& pcb)
{
    pcb.ccp_fsm.protocol = PPP_CCP;
    if (!fsm_init(pcb.ccp_fsm, pcb)) { return false; }
    const auto wo = &pcb.ccp_wantoptions;
    const auto ao = &pcb.ccp_allowoptions;
    pcb.ccp_wantoptions.deflate = true;
    pcb.ccp_wantoptions.deflate_size = DEFLATE_MAX_SIZE;
    pcb.ccp_wantoptions.deflate_correct = true;
    pcb.ccp_wantoptions.deflate_draft = true;
    pcb.ccp_allowoptions.deflate = true;
    pcb.ccp_allowoptions.deflate_size = DEFLATE_MAX_SIZE;
    pcb.ccp_allowoptions.deflate_correct = true;
    pcb.ccp_allowoptions.deflate_draft = true;
    pcb.ccp_wantoptions.bsd_compress = true;
    pcb.ccp_wantoptions.bsd_bits = BSD_MAX_BITS;
    pcb.ccp_allowoptions.bsd_compress = true;
    pcb.ccp_allowoptions.bsd_bits = BSD_MAX_BITS;
    pcb.ccp_allowoptions.predictor_1 = true;
    return true;
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
bool
ccp_set(PppPcb& pcb,
        bool isopen,
        bool isup,
        const uint8_t receive_method,
        const uint8_t transmit_method)
{
    pcb.ccp_receive_method = receive_method;
    pcb.ccp_transmit_method = transmit_method;
    return true;
}

/*
 * ccp_open - CCP is allowed to come up.
 */
bool ccp_open(PppPcb& pcb)
{
    // auto f = &pcb->ccp_fsm;
    // const auto go = &pcb->ccp_gotoptions;
    if (pcb.ccp_fsm.state != PPP_FSM_OPENED)
        ccp_set(pcb, 1, 0, 0, 0); /*
     * Find out which compressors the kernel supports before
     * deciding whether to open in silent mode.
     */
    ccp_resetci(pcb.ccp_fsm ,pcb);
    if (!ccp_anycompress(pcb.ccp_gotoptions))
        pcb.ccp_fsm.options.silent = true;
    fsm_open(, pcb.ccp_fsm);
}

/*
 * ccp_close - Terminate CCP.
 */
static bool
ccp_close(PppPcb& pcb, std::string& reason)
{
    ccp_set(pcb, false, false, 0, 0);
    fsm_close(, pcb.ccp_fsm, reason);
}

/*
 * ccp_lowerup - we may now transmit CCP packets.
 */
static void ccp_lowerup(PppPcb* pcb)
{
    const auto f = &pcb->ccp_fsm;
    fsm_lowerup(, f);
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
void ccp_input(PppPcb& pcb, std::vector<uint8_t>& pkt)
{
    auto f = pcb.ccp_fsm;
    auto go = pcb.ccp_gotoptions; /*
     * Check for a terminate-request so we can print a message.
     */
    const auto oldstate = f.state;
    fsm_input(, pcb.ccp_fsm, pkt);
    if (oldstate == PPP_FSM_OPENED && pkt[0] == TERMREQ && pcb.ccp_fsm.state != PPP_FSM_OPENED)
    {
        spdlog::info("Compression disabled by peer.");
        if (go.mppe)
        {
            spdlog::error("MPPE disabled, closing LCP");
            std::string msg = "MPPE disabled by peer";
            lcp_close(pcb, msg);
        }
    } /*
     * If we get a terminate-ack and we're not asking for compression,
     * close CCP.
     */
    if (oldstate == PPP_FSM_REQSENT && pkt[0] == TERMACK && !ccp_anycompress(go))
    {
        std::string msg = "No compression negotiated";
        ccp_close(pcb, msg);
    }

}

/*
 * Handle a CCP-specific code.
 */
static int ccp_extcode(Fsm* f,
                       const int code,
                       const int id,
                       uint8_t* p,
                       int len,
                       PppPcb* PppPcb)
{
    switch (code)
    {
    case CCP_RESETREQ:
        if (f->state != PPP_FSM_OPENED)
        {
            break;
        }
        ccp_reset_comp(PppPcb); /* send a reset-ack, which the transmitter will see and
           reset its compression state. */
        fsm_send_data(, f, CCP_RESETACK, id, nullptr);
        break;
    case CCP_RESETACK:
        if ((PppPcb->ccp_localstate & RESET_ACK_PENDING) && id == f->reqid)
        {
            PppPcb->ccp_localstate &= ~(RESET_ACK_PENDING | REPEAT_RESET_REQ);
            Untimeout(ccp_rack_timeout, f);
            ccp_reset_decomp(PppPcb);
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
    if (go->mppe)
    {
        ppp_error("MPPE required but peer negotiation failed");
        lcp_close(pcb, "MPPE required but peer negotiation failed");
    }
}

/*
 * ccp_resetci - initialize at start of negotiation.
 */
bool
ccp_resetci(Fsm& f, PppPcb& pcb)
{
    // PppPcb* pcb = f->pcb;
    auto go = &pcb->ccp_gotoptions;
    auto wo = &pcb->ccp_wantoptions;
    const auto ao = &pcb->ccp_allowoptions;
    uint8_t opt_buf[CCP_MAX_OPTION_LENGTH];
    int res;
    if (pcb->settings.require_mppe)
    {
        wo->mppe = ao->mppe = MppeOptions((pcb->settings.refuse_mppe_40 ? MPPE_OPT_NONE : MPPE_OPT_40) | (
            pcb->settings.refuse_mppe_128 ? MPPE_OPT_NONE : MPPE_OPT_128));
    }
    *go = *wo;
    pcb->ccp_all_rejected = false;
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
         */ /* Leave only the mschap auth bits set */
        auth_mschap_bits &= (CHAP_MS_WITHPEER | CHAP_MS_PEER | CHAP_MS2_WITHPEER |
            CHAP_MS2_PEER); /* Count the mschap auths */
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
        } /* A plugin (eg radius) may not have obtained key material. */
        if (!pcb->mppe_keys_set)
        {
            ppp_error(
                "MPPE required, but keys are not available.  "
                "Possible plugin problem?");
            lcp_close(pcb, "MPPE required but not available");
            return;
        } /* LM auth not supported for MPPE */
        if (pcb->auth_done & (CHAP_MS_WITHPEER | CHAP_MS_PEER))
        {
            /* This might be noise */
            if (go->mppe & MPPE_OPT_40)
            {
                ppp_notice("Disabling 40-bit MPPE; MS-CHAP LM not supported");
                go->mppe = MppeOptions(go->mppe & ~MPPE_OPT_40);
                wo->mppe = MppeOptions(wo->mppe & ~MPPE_OPT_40);
            }
        } /* Last check: can we actually negotiate something? */
        if (!(go->mppe & (MPPE_OPT_40 | MPPE_OPT_128)))
        {
            /* Could be misconfig, could be 40-bit disabled above. */
            ppp_error("MPPE required, but both 40-bit and 128-bit disabled.");
            lcp_close(pcb, "MPPE required but not available");
            return;
        } /* sync options */
        ao->mppe = go->mppe; /* MPPE is not compatible with other compression types */
        ao->bsd_compress = go->bsd_compress = false;
        ao->predictor_1 = go->predictor_1 = false;
        ao->predictor_2 = go->predictor_2 = false;
        ao->deflate = go->deflate = false;
    } /*
     * Check whether the kernel knows about the various
     * compression methods we might request.
     */ /* FIXME: we don't need to test if BSD compress is available
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
                go->bsd_compress = false;
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
                go->bsd_compress = false;
                break;
            }
            go->bsd_bits--;
        }
    } /* FIXME: we don't need to test if deflate is available
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
                    go->deflate_correct = false;
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
                    go->deflate_correct = false;
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
                    go->deflate_draft = false;
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
                    go->deflate_draft = false;
                    break;
                }
                go->deflate_size--;
            }
        }
        if (!go->deflate_correct && !go->deflate_draft)
        {
            go->deflate = false;
        }
    } /* FIXME: we don't need to test if predictor is available,
     * if PREDICTOR_SUPPORT is set, it is.
     */
    if (go->predictor_1)
    {
        opt_buf[0] = CI_PREDICTOR_1;
        opt_buf[1] = CILEN_PREDICTOR_1;
        if (ccp_test(pcb, opt_buf, CILEN_PREDICTOR_1, 0) <= 0)
        {
            go->predictor_1 = false;
        }
    }
    if (go->predictor_2)
    {
        opt_buf[0] = CI_PREDICTOR_2;
        opt_buf[1] = CILEN_PREDICTOR_2;
        if (ccp_test(pcb, opt_buf, CILEN_PREDICTOR_2, 0) <= 0)
        {
            go->predictor_2 = false;
        }
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
static void ccp_addci(Fsm* f, uint8_t* p, int* lenp, PppPcb* pcb)
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
        mppe_opts_to_ci(go->mppe, &p[2]);
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
static int ccp_ackci(Fsm* f, uint8_t* p, int len, PppPcb* pcb)
{
    // PppPcb* pcb = f->pcb;
    const auto go = &pcb->ccp_gotoptions;
    const auto p0 = p;

    if (go->mppe)
    {
        uint8_t opt_buf[CILEN_MPPE];

        opt_buf[0] = CI_MPPE;
        opt_buf[1] = CILEN_MPPE;
        mppe_opts_to_ci(go->mppe, &opt_buf[2]);
        if (len < CILEN_MPPE || memcmp(opt_buf, p, CILEN_MPPE))
        {
            return 0;
        }
        p += CILEN_MPPE;
        len -= CILEN_MPPE;
        /* XXX Cope with first/fast ack */
        if (len == 0)
        {
            return 1;
        }
    }

    if (go->deflate)
    {
        if (len < CILEN_DEFLATE
            || p[0] != (go->deflate_correct ? CI_DEFLATE : CI_DEFLATE_DRAFT)
            || p[1] != CILEN_DEFLATE
            || p[2] != DEFLATE_MAKE_OPT(go->deflate_size)
            || p[3] != DEFLATE_CHK_SEQUENCE)
        {
            return 0;
        }
        p += CILEN_DEFLATE;
        len -= CILEN_DEFLATE;
        /* XXX Cope with first/fast ack */
        if (len == 0)
        {
            return 1;
        }
        if (go->deflate_correct && go->deflate_draft)
        {
            if (len < CILEN_DEFLATE
                || p[0] != CI_DEFLATE_DRAFT
                || p[1] != CILEN_DEFLATE
                || p[2] != DEFLATE_MAKE_OPT(go->deflate_size)
                || p[3] != DEFLATE_CHK_SEQUENCE)
            {
                return 0;
            }
            p += CILEN_DEFLATE;
            len -= CILEN_DEFLATE;
        }
    }

    if (go->bsd_compress)
    {
        if (len < CILEN_BSD_COMPRESS
            || p[0] != CI_BSD_COMPRESS || p[1] != CILEN_BSD_COMPRESS
            || p[2] != BSD_MAKE_OPT(BSD_CURRENT_VERSION, go->bsd_bits))
        {
            return 0;
        }
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
        {
            return 0;
        }
        p += CILEN_PREDICTOR_1;
        len -= CILEN_PREDICTOR_1;
        /* XXX Cope with first/fast ack */
        if (p == p0 && len == 0)
        {
            return 1;
        }
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
    {
        return 0;
    }
    return 1;
}

/*
 * ccp_nakci - process received configure-nak.
 * Returns 1 iff the nak was OK.
 */
static int ccp_nakci(Fsm* f, const uint8_t* p, int len, int treat_as_reject, PppPcb* pcb)
{
    // PppPcb* pcb = f->pcb;
    auto go = &pcb->ccp_gotoptions;
    CcpOptions no{}; /* options we've seen already */
    memset(&no, 0, sizeof(no));
    auto try_ = *go;

    if (go->mppe && len >= CILEN_MPPE
        && p[0] == CI_MPPE && p[1] == CILEN_MPPE)
    {
        no.mppe = MPPE_OPT_40;
        /*
         * Peer wants us to use a different strength or other setting.
         * Fail if we aren't willing to use his suggestion.
         */
        MPPE_CI_TO_OPTS(&p[2], try_.mppe);
        if ((try_.mppe & MPPE_OPT_STATEFUL) && pcb->settings.refuse_mppe_stateful)
        {
            ppp_error("Refusing MPPE stateful mode offered by peer");
            try_.mppe = MPPE_OPT_NONE;
        }
        else if (((go->mppe | MPPE_OPT_STATEFUL) & try_.mppe) != try_.mppe)
        {
            /* Peer must have set options we didn't request (suggest) */
            try_.mppe = MPPE_OPT_NONE;
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
        no.deflate = true;
        /*
         * Peer wants us to use a different code size or something.
         * Stop asking for Deflate if we don't understand his suggestion.
         */
        if (DEFLATE_METHOD(p[2]) != DEFLATE_METHOD_VAL
            || DEFLATE_SIZE(p[2]) < kDeflateMinWorks
            || p[3] != DEFLATE_CHK_SEQUENCE)
            try_.deflate = false;
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
        no.bsd_compress = true;
        /*
         * Peer wants us to use a different number of bits
         * or a different version.
         */
        if (BSD_VERSION(p[2]) != BSD_CURRENT_VERSION)
            try_.bsd_compress = false;
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
static int ccp_rejci(Fsm* f, const uint8_t* p, int len, PppPcb* pcb)
{
    // PppPcb* pcb = f->pcb;
    const auto go = &pcb->ccp_gotoptions;
    auto try_ = *go; /*
     * Cope with empty configure-rejects by ceasing to send
     * configure-requests.
     */
    if (len == 0 && pcb->ccp_all_rejected)
    {
        return -1;
    }
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
        {
            return 0; /* Rej is bad */
        }
        try_.deflate_correct = false;
        p += CILEN_DEFLATE;
        len -= CILEN_DEFLATE;
    }
    if (go->deflate_draft && len >= CILEN_DEFLATE && p[0] == CI_DEFLATE_DRAFT && p[1] ==
        CILEN_DEFLATE)
    {
        if (p[2] != DEFLATE_MAKE_OPT(go->deflate_size) || p[3] != DEFLATE_CHK_SEQUENCE)
        {
            return 0; /* Rej is bad */
        }
        try_.deflate_draft = false;
        p += CILEN_DEFLATE;
        len -= CILEN_DEFLATE;
    }
    if (!try_.deflate_correct && !try_.deflate_draft)
    {
        try_.deflate = false;
    }
    if (go->bsd_compress && len >= CILEN_BSD_COMPRESS && p[0] == CI_BSD_COMPRESS && p[1]
        == CILEN_BSD_COMPRESS)
    {
        if (p[2] != BSD_MAKE_OPT(BSD_CURRENT_VERSION, go->bsd_bits))
        {
            return 0;
        }
        try_.bsd_compress = false;
        p += CILEN_BSD_COMPRESS;
        len -= CILEN_BSD_COMPRESS;
    }
    if (go->predictor_1 && len >= CILEN_PREDICTOR_1 && p[0] == CI_PREDICTOR_1 && p[1] ==
        CILEN_PREDICTOR_1)
    {
        try_.predictor_1 = false;
        p += CILEN_PREDICTOR_1;
        len -= CILEN_PREDICTOR_1;
    }
    if (go->predictor_2 && len >= CILEN_PREDICTOR_2 && p[0] == CI_PREDICTOR_2 && p[1] ==
        CILEN_PREDICTOR_2)
    {
        try_.predictor_2 = false;
        p += CILEN_PREDICTOR_2;
        len -= CILEN_PREDICTOR_2;
    }
    if (len != 0)
    {
        return 0;
    }
    if (f->state != PPP_FSM_OPENED)
        *go = try_;
    return 1;
}

/*
 * ccp_reqci - processed a received configure-request.
 * Returns CONFACK, CONFNAK or CONFREJ and the packet modified
 * appropriately.
 */
static int ccp_reqci(Fsm* f, uint8_t* p, size_t* lenp, const int dont_nak, PppPcb* pcb)
{
    // PppPcb* pcb = f->pcb;
    auto ho = &pcb->ccp_hisoptions;
    auto ao = &pcb->ccp_allowoptions;
    int res;
    int nb;
    uint8_t *p0;
    int clen;
    int type;
    uint8_t rej_for_ci_mppe = 1; /* Are we rejecting based on a bad/missing */
    /* CI_MPPE, or due to other options?       */
    auto ret = CONFACK;
    auto retp = p0 = p;
    int len = *lenp;
    memset(ho, 0, sizeof(CcpOptions));
    ho->method = (len > 0) ? p[0] : 0;
    while (len > 0)
    {
        CpCodes newret = CONFACK;
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
                    ho->mppe = MppeOptions(ho->mppe & ~MPPE_OPT_UNSUPPORTED);
                }
                if (ho->mppe & MPPE_OPT_UNKNOWN)
                {
                    newret = CONFNAK;
                    ho->mppe = MppeOptions(ho->mppe & ~MPPE_OPT_UNKNOWN);
                } /* Check state opt */
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
                } /* Find out which of {S,L} are set. */
                if ((ho->mppe & MPPE_OPT_128) && (ho->mppe & MPPE_OPT_40))
                {
                    /* Both are set, negotiate the strongest. */
                    newret = CONFNAK;
                    if (ao->mppe & MPPE_OPT_128)
                    {
                        ho->mppe = MppeOptions(ho->mppe & ~MPPE_OPT_40);
                    }
                    else if (ao->mppe & MPPE_OPT_40)
                    {
                        ho->mppe = MppeOptions(ho->mppe & ~MPPE_OPT_128);
                    }
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
                    /* Neither are set. */ /* We cannot accept this.  */
                    newret = CONFNAK; /* Give the peer our idea of what can be used,
                       so it can choose and confirm */
                    ho->mppe = ao->mppe;
                } /* rebuild the opts */
                mppe_opts_to_ci(ho->mppe, &p[2]);
                if (newret == CONFACK)
                {
                    mppe_init(pcb, &pcb->mppe_comp, ho->mppe); /*
                     * We need to decrease the interface MTU by MPPE_PAD
                     * because MPPE frames **grow**.  The kernel [must]
                     * allocate MPPE_PAD extra bytes in xmit buffers.
                     */
                    auto mtu = netif_get_mtu(pcb);
                    if (mtu)
                        netif_set_mtu(pcb, mtu - MPPE_PAD);
                    else
                    {
                        newret = CONFREJ;
                    }
                } /*
                 * We have accepted MPPE or are willing to negotiate
                 * MPPE parameters.  A CONFREJ is due to subsequent
                 * (non-MPPE) processing.
                 */
                rej_for_ci_mppe = 0;
                break;
            case CI_DEFLATE: case CI_DEFLATE_DRAFT:
                if (!ao->deflate || clen != CILEN_DEFLATE || (!ao->deflate_correct && type
                    == CI_DEFLATE) || (!ao->deflate_draft && type == CI_DEFLATE_DRAFT))
                {
                    newret = CONFREJ;
                    break;
                }
                ho->deflate = true;
                ho->deflate_size = nb = DEFLATE_SIZE(p[2]);
                if (DEFLATE_METHOD(p[2]) != DEFLATE_METHOD_VAL || p[3] !=
                    DEFLATE_CHK_SEQUENCE || nb > ao->deflate_size || nb < kDeflateMinWorks
                )
                {
                    newret = CONFNAK;
                    if (!dont_nak)
                    {
                        p[2] = DEFLATE_MAKE_OPT(ao->deflate_size);
                        p[3] = DEFLATE_CHK_SEQUENCE;
                        /* fall through to test this #bits below */
                    }
                    else
                    {
                        break;
                    }
                } /*
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
                ho->bsd_compress = true;
                ho->bsd_bits = nb = BSD_NBITS(p[2]);
                if (BSD_VERSION(p[2]) != BSD_CURRENT_VERSION || nb > ao->bsd_bits || nb <
                    BSD_MIN_BITS)
                {
                    newret = CONFNAK;
                    if (!dont_nak)
                    {
                        p[2] = BSD_MAKE_OPT(BSD_CURRENT_VERSION, ao->bsd_bits);
                        /* fall through to test this #bits below */
                    }
                    else
                    {
                        break;
                    }
                } /*
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
                        {
                            break;
                        }
                        if (res < 0 || nb == BSD_MIN_BITS || dont_nak)
                        {
                            newret = CONFREJ;
                            p[2] = BSD_MAKE_OPT(BSD_CURRENT_VERSION, ho->bsd_bits);
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
                ho->predictor_1 = true;
                if (p == p0 && ccp_test(pcb, p, CILEN_PREDICTOR_1, 1) <= 0)
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
                ho->predictor_2 = true;
                if (p == p0 && ccp_test(pcb, p, CILEN_PREDICTOR_2, 1) <= 0)
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
            {
                retp = p0;
            }
            ret = newret;
            if (p != retp)
            {
                memcpy(retp, p, clen);
            }
            retp += clen;
        }
        p += clen;
        len -= clen;
    }
    if (ret != CONFACK)
    {
        if (ret == CONFREJ && *lenp == retp - p0)
        {
            pcb->ccp_all_rejected = true;
        }
        else
        {
            *lenp = retp - p0;
        }
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
    {
        return "(none)";
    }
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
    {
        ppp_slprintf(p, q - p, "stateful");
    }
    else
    {
        ppp_slprintf(p, q - p, "stateless");
        }
        break;
    }


    case CI_DEFLATE:
    case CI_DEFLATE_DRAFT:
    if (opt2 != nullptr && opt2->deflate_size != opt->deflate_size)
    {
        ppp_slprintf(result, sizeof(result), "Deflate%s (%d/%d)",
             (opt->method == CI_DEFLATE_DRAFT? "(old#)": ""),
             opt->deflate_size, opt2->deflate_size);
    }
    else
    {
        ppp_slprintf(result, sizeof(result), "Deflate%s (%d)",
             (opt->method == CI_DEFLATE_DRAFT? "(old#)": ""),
             opt->deflate_size);
    }
    break;

    case CI_BSD_COMPRESS:
    if (opt2 != nullptr && opt2->bsd_bits != opt->bsd_bits)
        ppp_slprintf(result, sizeof(result), "BSD-Compress (%d/%d)",
             opt->bsd_bits, opt2->bsd_bits);
    else
    {
        ppp_slprintf(result, sizeof(result), "BSD-Compress (%d)",
             opt->bsd_bits);
    }
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
static void ccp_up(Fsm* f, PppPcb* pcb, Protent** protocols)
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
        {
            ppp_notice("%s receive compression enabled", method_name(go, nullptr));
        }
    }
    else if (ccp_anycompress(ho))
    {
        ppp_notice("%s transmit compression enabled", method_name(ho, nullptr));
    }
    if (go->mppe)
    {
        continue_networks(pcb); /* Bring up IP et al */
    }
}

/*
 * CCP has gone down - inform the kernel driver.
 */
static void ccp_down(Fsm* f, Fsm* lcp_fsm, PppPcb* pcb)
{
    // PppPcb* pcb = f->pcb;
    const auto go = &pcb->ccp_gotoptions;

    if (pcb->ccp_localstate & RESET_ACK_PENDING)
    {
        Untimeout(ccp_rack_timeout, f);
    }
    pcb->ccp_localstate = 0;
    ccp_set(pcb, 1, 0, 0, 0);
    if (go->mppe)
    {
        go->mppe = MPPE_OPT_NONE;
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
// 		Timeout(ccp_rack_timeout, f, RACKTIMEOUT);
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
bool
ccp_reset_request(uint8_t ppp_pcb_ccp_local_state, Fsm& f)
{
    if (f.state != PPP_FSM_OPENED)
    {
        return false;
    } /*
     * Send a reset-request to reset the peer's compressor.
     * We don't do that if we are still waiting for an
     * acknowledgement to a previous reset-request.
     */
    if (!(ppp_pcb_ccp_local_state & RESET_ACK_PENDING))
    {
        fsm_send_data(, f, CCP_RESETREQ, f.reqid = ++f.id, nullptr);
        // timeout(ccp_rack_timeout, f, kRacktimeout);
        ppp_pcb_ccp_local_state |= RESET_ACK_PENDING;
    }
    else
    {
        ppp_pcb_ccp_local_state |= REPEAT_RESET_REQ;
    }
}


/*
 * Timeout waiting for reset-ack.
 */
static void ccp_rack_timeout(void* arg)
{
    auto args = static_cast<CcpRackTimeoutArgs*>(arg);

    if (args->f->state == PPP_FSM_OPENED && (args->pcb->ccp_localstate & REPEAT_RESET_REQ))
    {
        fsm_send_data(, args->f, CCP_RESETREQ, args->f->reqid, nullptr);
        Timeout(ccp_rack_timeout, args, RESET_ACK_TIMEOUT);
        args->pcb->ccp_localstate &= ~REPEAT_RESET_REQ;
    }
    else
    {
        args->pcb->ccp_localstate &= ~RESET_ACK_PENDING;
    }
}

//
// END OF FILE
//