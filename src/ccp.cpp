
#define NOMINMAX
#include "auth.h"
#include "ccp.h"
#include <cstring>
#include "auth.h"
#include "ppp.h"
#include <spdlog/spdlog.h>
#include "mppe.h"


/*
 * Do we want / did we get any compression?
 */
bool
ccp_anycompress(CcpOptions& options)
{
    return ((options).deflate || (options).bsd_compress || (options).predictor_1 || (options).
        predictor_2 || mppe_has_options((options).mppe));
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


bool
ccp_reset_comp(PppPcb& pcb)
{
    if (pcb.ccp_transmit_method == CI_MPPE) {
        return mppe_comp_reset(pcb, pcb.mppe_comp);
    }
    else {
        // unsupported transmit method
        return false;
    }
}


bool
ccp_reset_decomp(PppPcb& pcb)
{
    if (pcb.ccp_receive_method == CI_MPPE)
    {
        return mppe_decomp_reset(pcb, pcb.mppe_decomp);
    }
    // unsupported receive method
    return true;
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
bool
ccp_open(PppPcb& pcb)
{
    // auto f = &pcb->ccp_fsm;
    // const auto go = &pcb->ccp_gotoptions;
    if (pcb.ccp_fsm.state != PPP_FSM_OPENED)
        ccp_set(pcb, 1, 0, 0, 0); /*
     * Find out which compressors the kernel supports before
     * deciding whether to open in silent mode.
     */
    ccp_resetci(pcb);
    if (!ccp_anycompress(pcb.ccp_gotoptions))
        pcb.ccp_fsm.options.silent = true;
    return fsm_open(pcb, pcb.ccp_fsm);
}

/*
 * ccp_close - Terminate CCP.
 */
static bool
ccp_close(PppPcb& pcb, std::string& reason)
{
    ccp_set(pcb, false, false, 0, 0);
    return fsm_close(pcb, pcb.ccp_fsm, reason);
}

/*
 * ccp_lowerup - we may now transmit CCP packets.
 */
bool
ccp_lowerup(PppPcb& pcb)
{
    return fsm_lowerup(pcb, pcb.ccp_fsm);
}

/*
 * ccp_lowerdown - we may not transmit CCP packets.
 */
bool
ccp_lowerdown(PppPcb& pcb)
{
    return fsm_lowerdown(pcb.ccp_fsm);
}

/*
 * ccp_input - process a received CCP packet.
 */
bool ccp_input(PppPcb& pcb, std::vector<uint8_t>& pkt)
{
    auto f = pcb.ccp_fsm;
    auto go = pcb.ccp_gotoptions; /*
     * Check for a terminate-request so we can print a message.
     */
    const auto oldstate = f.state;
    fsm_input(pcb, pcb.ccp_fsm, pkt);
    if (oldstate == PPP_FSM_OPENED && pkt[0] == TERMREQ && pcb.ccp_fsm.state != PPP_FSM_OPENED)
    {
        spdlog::info("Compression disabled by peer.");
        if (mppe_has_options(go.mppe))
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

    return true;
}

/**
 * Handle a CCP-specific code.
 */
bool
ccp_extcode(PppPcb& pcb, Fsm& f, const int code, const int id, std::vector<uint8_t>& data)
{
    switch (code)
    {
    case CCP_RESETREQ:
        if (f.state != PPP_FSM_OPENED) { break; }
        ccp_reset_comp(pcb); /* send a reset-ack, which the transmitter will see and
           reset its compression state. */
        fsm_send_data2(pcb, f, CCP_RESETACK, id, data);
        break;
    case CCP_RESETACK:
        if ((pcb.ccp_localstate & RESET_ACK_PENDING) && id == f.reqid)
        {
            pcb.ccp_localstate &= ~(RESET_ACK_PENDING | REPEAT_RESET_REQ);
            //Untimeout(ccp_rack_timeout, f);
            // todo: replace removal of timeout
            ccp_reset_decomp(pcb);
        }
        break;
    default:
        return false;
    }
    return true;
}

/**
 * Peer doesn't talk CCP.
 */
bool
ccp_proto_rejected(PppPcb& pcb)
{
    const auto f = pcb.ccp_fsm;
    const auto go = pcb.ccp_gotoptions;
    if (!ccp_set(pcb, false, false, 0, 0)) { return false; }
    if (!fsm_lowerdown(pcb.ccp_fsm)) { return false; }
    if (mppe_has_options(pcb.ccp_gotoptions.mppe)) {
        spdlog::error("MPPE required but peer negotiation failed");
        std::string msg = "MPPE required but peer negotiation failed";
        return lcp_close(pcb, msg);
    }
    return true;
}

/**
 * Initialize at start of negotiation.
 */
bool
ccp_resetci(PppPcb& pcb)
{
    // PppPcb* pcb = f->pcb;
    // auto go = &pcb->ccp_gotoptions;
    // auto wo = &pcb->ccp_wantoptions;
    // const auto ao = &pcb->ccp_allowoptions;
    // uint8_t opt_buf[CCP_MAX_OPTION_LENGTH];
    std::vector<uint8_t> opt_buf;
    int res;
    if (pcb.settings.require_mppe)
    {
        if (pcb.settings.refuse_mppe_40 == false) {
            pcb.ccp_wantoptions.mppe.opt_40 = true;
        }
        if (pcb.settings.refuse_mppe_128 == false) {
            pcb.ccp_wantoptions.mppe.opt_128 = true;
        }
    }
    pcb.ccp_gotoptions = pcb.ccp_wantoptions;
    pcb.ccp_all_rejected = false;
    if (mppe_has_options(pcb.ccp_gotoptions.mppe))
    {
        int auth_mschap_bits = pcb.auth_done;
        /*
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

        do {
            numbits += auth_mschap_bits & 1;
            auth_mschap_bits >>= 1;
        }
        while (auth_mschap_bits);

        if (numbits > 1) {
            std::string msg = "MPPE required but not available";
            spdlog::error(msg);
            if (!lcp_close(pcb, msg)) { return false; }
            return true;
        }
        if (numbits == 0) {
            std::string msg = "MPPE required, but MS-CHAP[v2] auth not performed.";
            spdlog::error(msg);
            lcp_close(pcb, msg);
            return false;
        }

        /* A plugin (eg radius) may not have obtained key material. */
        if (!pcb.mppe_keys_set)
        {
            spdlog::error(
                "MPPE required, but keys are not available.  "
                "Possible plugin problem?");
            std::string msg = "MPPE required but not available";
            lcp_close(pcb, msg);
            return false;
        }
        /* LM auth not supported for MPPE */
        if (pcb.auth_done & (CHAP_MS_WITHPEER | CHAP_MS_PEER))
        {
            /* This might be noise */
            if (pcb.ccp_gotoptions.mppe.opt_40) {
                spdlog::info("Disabling 40-bit MPPE; MS-CHAP LM not supported");
                pcb.ccp_gotoptions.mppe.opt_40 = false;
                pcb.ccp_wantoptions.mppe.opt_40 = false;
            }
        }
        /* Last check: can we actually negotiate something? */
        if (!(pcb.ccp_gotoptions.mppe.opt_40 || pcb.ccp_gotoptions.mppe.opt_128))
        {
            /* Could be misconfig, could be 40-bit disabled above. */
            std::string msg = "MPPE required, but both 40-bit and 128-bit disabled.";
            spdlog::error(msg);
            lcp_close(pcb, msg);
            return false;
        }

        // sync options
        // MPPE is not compatible with other compression types
        pcb.ccp_allowoptions.bsd_compress = pcb.ccp_gotoptions.bsd_compress = false;
        pcb.ccp_allowoptions.predictor_1 = pcb.ccp_gotoptions.predictor_1 = false;
        pcb.ccp_allowoptions.predictor_2 = pcb.ccp_gotoptions.predictor_2 = false;
        pcb.ccp_allowoptions.deflate = pcb.ccp_gotoptions.deflate = false;
        pcb.ccp_allowoptions.mppe = pcb.ccp_gotoptions.mppe;

    }

    /*
     * Check whether the kernel knows about the various
     * compression methods we might request.
     */ /* FIXME: we don't need to test if BSD compress is available
     * if BSDCOMPRESS_SUPPORT is set, it is.
     */
    if (pcb.ccp_gotoptions.bsd_compress)
    {
        opt_buf[0] = CI_BSD_COMPRESS;
        opt_buf[1] = CILEN_BSD_COMPRESS;
        for (;;)
        {
            if (pcb.ccp_gotoptions.bsd_bits < BSD_MIN_BITS)
            {
                pcb.ccp_gotoptions.bsd_compress = false;
                break;
            }
            opt_buf[2] = (((1) << 5) | (pcb.ccp_gotoptions.bsd_bits));
            res = ccp_test(pcb, opt_buf, 3, 0);
            if (res > 0)
            {
                break;
            }
            if (res < 0)
            {
                pcb.ccp_gotoptions.bsd_compress = false;
                break;
            }
            pcb.ccp_gotoptions.bsd_bits--;
        }
    }

    /* FIXME: we don't need to test if deflate is available
     * if DEFLATE_SUPPORT is set, it is.
     */
    if (pcb.ccp_gotoptions.deflate)
    {
        if (pcb.ccp_gotoptions.deflate_correct)
        {
            opt_buf[0] = CI_DEFLATE;
            opt_buf[1] = CILEN_DEFLATE;
            opt_buf[3] = DEFLATE_CHK_SEQUENCE;
            for (;;)
            {
                if (pcb.ccp_gotoptions.deflate_size < DEFLATE_MIN_WORKS)
                {
                    pcb.ccp_gotoptions.deflate_correct = false;
                    break;
                }
                opt_buf[2] = DEFLATE_MAKE_OPT(pcb.ccp_gotoptions.deflate_size);
                res = ccp_test(pcb, opt_buf, CILEN_DEFLATE, 0);
                if (res > 0)
                {
                    break;
                }
                if (res < 0)
                {
                    pcb.ccp_gotoptions.deflate_correct = false;
                    break;
                }
                pcb.ccp_gotoptions.deflate_size--;
            }
        }
        if (pcb.ccp_gotoptions.deflate_draft)
        {
            opt_buf[0] = CI_DEFLATE_DRAFT;
            opt_buf[1] = CILEN_DEFLATE;
            opt_buf[3] = DEFLATE_CHK_SEQUENCE;
            for (;;)
            {
                if (pcb.ccp_gotoptions.deflate_size < DEFLATE_MIN_WORKS)
                {
                    pcb.ccp_gotoptions.deflate_draft = false;
                    break;
                }
                opt_buf[2] = DEFLATE_MAKE_OPT(pcb.ccp_gotoptions.deflate_size);
                res = ccp_test(pcb, opt_buf, CILEN_DEFLATE, 0);
                if (res > 0)
                {
                    break;
                }
                if (res < 0)
                {
                    pcb.ccp_gotoptions.deflate_draft = false;
                    break;
                }
                pcb.ccp_gotoptions.deflate_size--;
            }
        }
        if (!pcb.ccp_gotoptions.deflate_correct && !pcb.ccp_gotoptions.deflate_draft)
        {
            pcb.ccp_gotoptions.deflate = false;
        }
    } /* FIXME: we don't need to test if predictor is available,
     * if PREDICTOR_SUPPORT is set, it is.
     */
    if (pcb.ccp_gotoptions.predictor_1)
    {
        opt_buf[0] = CI_PREDICTOR_1;
        opt_buf[1] = CILEN_PREDICTOR_1;
        if (ccp_test(pcb, opt_buf, CILEN_PREDICTOR_1, 0) <= 0)
        {
            pcb.ccp_gotoptions.predictor_1 = false;
        }
    }
    if (pcb.ccp_gotoptions.predictor_2)
    {
        opt_buf[0] = CI_PREDICTOR_2;
        opt_buf[1] = CILEN_PREDICTOR_2;
        if (ccp_test(pcb, opt_buf, CILEN_PREDICTOR_2, 0) <= 0)
        {
            pcb.ccp_gotoptions.predictor_2 = false;
        }
    }

    return true;
}

/*
 * ccp_cilen - Return total length of our configuration info.
 */
size_t ccp_cilen(PppPcb& ppp_pcb)
{
    // auto go = &ppp_pcb->ccp_gotoptions;

    if (ppp_pcb.ccp_gotoptions.bsd_compress) {
        if (ppp_pcb.ccp_gotoptions.deflate && ppp_pcb.ccp_gotoptions.deflate_correct) {
            if (ppp_pcb.ccp_gotoptions.deflate && ppp_pcb.ccp_gotoptions.deflate_draft) {
                if (ppp_pcb.ccp_gotoptions.predictor_1) {
                    if (ppp_pcb.ccp_gotoptions.predictor_2) {
                        if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe)) {
                            return 0 + CILEN_BSD_COMPRESS + CILEN_DEFLATE + CILEN_DEFLATE + CILEN_PREDICTOR_1
                                + CILEN_PREDICTOR_2 + CILEN_MPPE;
                        }
                        return 0 + CILEN_BSD_COMPRESS + CILEN_DEFLATE + CILEN_DEFLATE + CILEN_PREDICTOR_1
                            + CILEN_PREDICTOR_2 + 0;
                    }
                    if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe)) {
                        return 0 + CILEN_BSD_COMPRESS + CILEN_DEFLATE + CILEN_DEFLATE + CILEN_PREDICTOR_1
                            + 0 + CILEN_MPPE;
                    }
                    return 0 + CILEN_BSD_COMPRESS + CILEN_DEFLATE + CILEN_DEFLATE + CILEN_PREDICTOR_1
                        + 0 + 0;
                }
                if (ppp_pcb.ccp_gotoptions.predictor_2) {
                    if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe)) {
                        return 0 + CILEN_BSD_COMPRESS + CILEN_DEFLATE + CILEN_DEFLATE + 0 +
                            CILEN_PREDICTOR_2 + CILEN_MPPE;
                    }
                    return 0 + CILEN_BSD_COMPRESS + CILEN_DEFLATE + CILEN_DEFLATE + 0 +
                        CILEN_PREDICTOR_2 + 0;
                }
                if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe)) {
                    return 0 + CILEN_BSD_COMPRESS + CILEN_DEFLATE + CILEN_DEFLATE + 0 + 0 +
                        CILEN_MPPE;
                }
                return 0 + CILEN_BSD_COMPRESS + CILEN_DEFLATE + CILEN_DEFLATE + 0 + 0 + 0;
            }
            if (ppp_pcb.ccp_gotoptions.predictor_1) {
                if (ppp_pcb.ccp_gotoptions.predictor_2) {
                    if (0 + CILEN_BSD_COMPRESS + CILEN_DEFLATE + 0 + CILEN_PREDICTOR_1 + CILEN_PREDICTOR_2
                        + mppe_has_options(ppp_pcb.ccp_gotoptions.mppe)) { return CILEN_MPPE;
                    }
                    return 0;
                }

                if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe))
                    return 0 + CILEN_BSD_COMPRESS + CILEN_DEFLATE + 0 + CILEN_PREDICTOR_1 + 0 +
                        CILEN_MPPE;
                return 0 + CILEN_BSD_COMPRESS + CILEN_DEFLATE + 0 + CILEN_PREDICTOR_1 + 0 + 0;
            }
            if (ppp_pcb.ccp_gotoptions.predictor_2) {
                if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe)) {
                    return 0 + CILEN_BSD_COMPRESS + CILEN_DEFLATE + 0 + 0 + CILEN_PREDICTOR_2 +
                        CILEN_MPPE;
                }
                return 0 + CILEN_BSD_COMPRESS + CILEN_DEFLATE + 0 + 0 + CILEN_PREDICTOR_2 + 0;
            }
            if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe)) { return 0 + CILEN_BSD_COMPRESS + CILEN_DEFLATE + 0 + 0 + 0 + CILEN_MPPE;
            }
            return 0 + CILEN_BSD_COMPRESS + CILEN_DEFLATE + 0 + 0 + 0 + 0;
        }
        if (ppp_pcb.ccp_gotoptions.deflate && ppp_pcb.ccp_gotoptions.deflate_draft) {
            if (ppp_pcb.ccp_gotoptions.predictor_1) {
                if (ppp_pcb.ccp_gotoptions.predictor_2) {
                    if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe)) {
                        return 0 + CILEN_BSD_COMPRESS + 0 + CILEN_DEFLATE + CILEN_PREDICTOR_1 +
                            CILEN_PREDICTOR_2 + CILEN_MPPE;
                    }
                    return 0 + CILEN_BSD_COMPRESS + 0 + CILEN_DEFLATE + CILEN_PREDICTOR_1 +
                        CILEN_PREDICTOR_2 + 0;
                }
                if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe)) {
                    return 0 + CILEN_BSD_COMPRESS + 0 + CILEN_DEFLATE + CILEN_PREDICTOR_1 + 0 +
                        CILEN_MPPE;
                }
                return 0 + CILEN_BSD_COMPRESS + 0 + CILEN_DEFLATE + CILEN_PREDICTOR_1 + 0 + 0;
            }
            if (ppp_pcb.ccp_gotoptions.predictor_2) {
                if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe)) {
                    return 0 + CILEN_BSD_COMPRESS + 0 + CILEN_DEFLATE + 0 + CILEN_PREDICTOR_2 +
                        CILEN_MPPE;
                }
                return 0 + CILEN_BSD_COMPRESS + 0 + CILEN_DEFLATE + 0 + CILEN_PREDICTOR_2 + 0;
            }
            if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe)) { return 0 + CILEN_BSD_COMPRESS + 0 + CILEN_DEFLATE + 0 + 0 + CILEN_MPPE;
            }
            return 0 + CILEN_BSD_COMPRESS + 0 + CILEN_DEFLATE + 0 + 0 + 0;
        }
        if (ppp_pcb.ccp_gotoptions.predictor_1) {
            if (ppp_pcb.ccp_gotoptions.predictor_2) {
                if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe)) {
                    return 0 + CILEN_BSD_COMPRESS + 0 + 0 + CILEN_PREDICTOR_1 + CILEN_PREDICTOR_2 +
                        CILEN_MPPE;
                }
                return 0 + CILEN_BSD_COMPRESS + 0 + 0 + CILEN_PREDICTOR_1 + CILEN_PREDICTOR_2 + 0;
            }
            if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe)) { return 0 + CILEN_BSD_COMPRESS + 0 + 0 + CILEN_PREDICTOR_1 + 0 + CILEN_MPPE;
            }
            return 0 + CILEN_BSD_COMPRESS + 0 + 0 + CILEN_PREDICTOR_1 + 0 + 0;
        }
        if (ppp_pcb.ccp_gotoptions.predictor_2) {
            if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe))
                return 0 + CILEN_BSD_COMPRESS + 0 + 0 + 0 + CILEN_PREDICTOR_2 + CILEN_MPPE;
            return 0 + CILEN_BSD_COMPRESS + 0 + 0 + 0 + CILEN_PREDICTOR_2 + 0;
        }
        if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe))
            return 0 + CILEN_BSD_COMPRESS + 0 + 0 + 0 + 0 + CILEN_MPPE;
        return 0 + CILEN_BSD_COMPRESS + 0 + 0 + 0 + 0 + 0;
    }
    if (ppp_pcb.ccp_gotoptions.deflate && ppp_pcb.ccp_gotoptions.deflate_correct) {
        if (ppp_pcb.ccp_gotoptions.deflate && ppp_pcb.ccp_gotoptions.deflate_draft) {
            if (ppp_pcb.ccp_gotoptions.predictor_1) {
                if (ppp_pcb.ccp_gotoptions.predictor_2) {
                    if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe)) {
                        return 0 + 0 + CILEN_DEFLATE + CILEN_DEFLATE + CILEN_PREDICTOR_1 +
                            CILEN_PREDICTOR_2 + CILEN_MPPE;
                    }
                    return 0 + 0 + CILEN_DEFLATE + CILEN_DEFLATE + CILEN_PREDICTOR_1 +
                        CILEN_PREDICTOR_2 + 0;
                }
                return 0 + 0 + CILEN_DEFLATE + CILEN_DEFLATE + CILEN_PREDICTOR_1 + 0 + (
                    ppp_pcb.ccp_gotoptions.mppe ? CILEN_MPPE : 0);
            }
            if (ppp_pcb.ccp_gotoptions.predictor_2) {
                if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe)) { return 0 + 0 + CILEN_DEFLATE + CILEN_DEFLATE + 0 + CILEN_PREDICTOR_2 + CILEN_MPPE;
                }
                return 0 + 0 + CILEN_DEFLATE + CILEN_DEFLATE + 0 + CILEN_PREDICTOR_2 + 0;
            }
            if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe)) { return 0 + 0 + CILEN_DEFLATE + CILEN_DEFLATE + 0 + 0 + CILEN_MPPE;
            }
            return 0 + 0 + CILEN_DEFLATE + CILEN_DEFLATE + 0 + 0 + 0;
        }
        if (ppp_pcb.ccp_gotoptions.predictor_1) {
            if (ppp_pcb.ccp_gotoptions.predictor_2) {
                if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe)) {
                    return 0 + 0 + CILEN_DEFLATE + 0 + CILEN_PREDICTOR_1 + CILEN_PREDICTOR_2 +
                        CILEN_MPPE;
                }
                return 0 + 0 + CILEN_DEFLATE + 0 + CILEN_PREDICTOR_1 + CILEN_PREDICTOR_2 + 0;
            }
            if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe)) { return 0 + 0 + CILEN_DEFLATE + 0 + CILEN_PREDICTOR_1 + 0 + CILEN_MPPE;
            }
            return 0 + 0 + CILEN_DEFLATE + 0 + CILEN_PREDICTOR_1 + 0 + 0;
        }
        if (ppp_pcb.ccp_gotoptions.predictor_2) {
            if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe)) { return 0 + 0 + CILEN_DEFLATE + 0 + 0 + CILEN_PREDICTOR_2 + CILEN_MPPE;
            }
            return 0 + 0 + CILEN_DEFLATE + 0 + 0 + CILEN_PREDICTOR_2 + 0;
        }
        if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe))
            return 0 + 0 + CILEN_DEFLATE + 0 + 0 + 0 + CILEN_MPPE;
        return 0 + 0 + CILEN_DEFLATE + 0 + 0 + 0 + 0;
    }
    if (ppp_pcb.ccp_gotoptions.deflate && ppp_pcb.ccp_gotoptions.deflate_draft) {
        if (ppp_pcb.ccp_gotoptions.predictor_1) {
            if (ppp_pcb.ccp_gotoptions.predictor_2) {
                if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe)) {
                    return 0 + 0 + 0 + CILEN_DEFLATE + CILEN_PREDICTOR_1 + CILEN_PREDICTOR_2 +
                        CILEN_MPPE;
                }
                return 0 + 0 + 0 + CILEN_DEFLATE + CILEN_PREDICTOR_1 + CILEN_PREDICTOR_2 + 0;
            }
            if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe)) { return 0 + 0 + 0 + CILEN_DEFLATE + CILEN_PREDICTOR_1 + 0 + CILEN_MPPE;
            }
            return 0 + 0 + 0 + CILEN_DEFLATE + CILEN_PREDICTOR_1 + 0 + 0;
        }
        if (ppp_pcb.ccp_gotoptions.predictor_2) {
            if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe))
                return 0 + 0 + 0 + CILEN_DEFLATE + 0 + CILEN_PREDICTOR_2 + CILEN_MPPE;
            return 0 + 0 + 0 + CILEN_DEFLATE + 0 + CILEN_PREDICTOR_2 + 0;
        }
        if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe)) { return 0 + 0 + 0 + CILEN_DEFLATE + 0 + 0 + CILEN_MPPE;
        }
        return 0 + 0 + 0 + CILEN_DEFLATE + 0 + 0 + 0;
    }
    if (ppp_pcb.ccp_gotoptions.predictor_1) {
        if (ppp_pcb.ccp_gotoptions.predictor_2) {
            if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe))
                return 0 + 0 + 0 + 0 + CILEN_PREDICTOR_1 + CILEN_PREDICTOR_2 + CILEN_MPPE;
            return 0 + 0 + 0 + 0 + CILEN_PREDICTOR_1 + CILEN_PREDICTOR_2 + 0;
        }
        if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe))
            return 0 + 0 + 0 + 0 + CILEN_PREDICTOR_1 + 0 + CILEN_MPPE;
        return 0 + 0 + 0 + 0 + CILEN_PREDICTOR_1 + 0 + 0;
    }
    if (ppp_pcb.ccp_gotoptions.predictor_2) {
        if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe))
            return 0 + 0 + 0 + 0 + 0 + CILEN_PREDICTOR_2 + CILEN_MPPE;
        return 0 + 0 + 0 + 0 + 0 + CILEN_PREDICTOR_2 + 0;
    }
    if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe)) { return 0 + 0 + 0 + 0 + 0 + 0 + CILEN_MPPE;
    }
    return 0 + 0 + 0 + 0 + 0 + 0 + 0;
}



/**
 * Put our requests in a packet.
 */
bool
ccp_addci(Fsm& f, std::vector<uint8_t>& pkt, PppPcb& pcb)
{
    // PppPcb* pcb = f->pcb;
    // const auto go = &pcb->ccp_gotoptions;
    // const auto p0 = pkt;

    /*
     * Add the compression types that we can receive, in decreasing
     * preference order.
     */
    if (mppe_has_options(pcb.ccp_gotoptions.mppe))
    {
        pkt[0] = CI_MPPE;
        pkt[1] = CILEN_MPPE;
        mppe_opts_to_ci(pcb.ccp_gotoptions.mppe, &pkt[2]);
        if (!mppe_init(pcb, pcb.mppe_decomp, pcb.ccp_gotoptions.mppe)) {
            return false;
        }
        pkt += CILEN_MPPE;
    }
    if (go->deflate)
    {
        if (go->deflate_correct)
        {
            pkt[0] = CI_DEFLATE;
            pkt[1] = CILEN_DEFLATE;
            pkt[2] = DEFLATE_MAKE_OPT(go->deflate_size);
            pkt[3] = DEFLATE_CHK_SEQUENCE;
            pkt += CILEN_DEFLATE;
        }
        if (go->deflate_draft)
        {
            pkt[0] = CI_DEFLATE_DRAFT;
            pkt[1] = CILEN_DEFLATE;
            pkt[2] = pkt[2 - CILEN_DEFLATE];
            pkt[3] = DEFLATE_CHK_SEQUENCE;
            pkt += CILEN_DEFLATE;
        }
    }
    if (go->bsd_compress)
    {
        pkt[0] = CI_BSD_COMPRESS;
        pkt[1] = CILEN_BSD_COMPRESS;
        pkt[2] = BSD_MAKE_OPT(BSD_CURRENT_VERSION, go->bsd_bits);
        pkt += CILEN_BSD_COMPRESS;
    }

    /* XXX Should Predictor 2 be preferable to Predictor 1? */
    if (go->predictor_1)
    {
        pkt[0] = CI_PREDICTOR_1;
        pkt[1] = CILEN_PREDICTOR_1;
        pkt += CILEN_PREDICTOR_1;
    }
    if (go->predictor_2)
    {
        pkt[0] = CI_PREDICTOR_2;
        pkt[1] = CILEN_PREDICTOR_2;
        pkt += CILEN_PREDICTOR_2;
    }


    go->method = (pkt > p0) ? p0[0] : 0;

    *lenp = pkt - p0;
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
 * Process received configure-nak.
 * Returns 1 iff the nak was OK.
 */
bool
ccp_nak_cfg_received(Fsm& f,
                     std::vector<uint8_t>& pkt_data,
                     bool treat_as_reject,
                     PppPcb& pcb)
{
    // PppPcb* pcb = f->pcb;
    // auto go = &pcb->ccp_gotoptions;
    CcpOptions no{}; /* options we've seen already */
    memset(&no, 0, sizeof(no));
    // auto try_ = *go;

    if (mppe_has_options(pcb.ccp_gotoptions.mppe) && pkt_data.size() >= CILEN_MPPE
        && pkt_data[0] == CI_MPPE && pkt_data[1] == CILEN_MPPE)
    {
        no.mppe.opt_40 = true;
        /*
         * Peer wants us to use a different strength or other setting.
         * Fail if we aren't willing to use his suggestion.
         */
        pcb.ccp_gotoptions.mppe = MPPE_CI_TO_OPTS(pkt_data.data() + 2);
        if ((pcb.ccp_gotoptions.mppe.stateful) && pcb.settings.refuse_mppe_stateful)
        {
            spdlog::error("Refusing MPPE stateful mode offered by peer");
            mppe_clear_options(pcb.ccp_gotoptions.mppe);
        }
        // else if (((pcb.ccp_gotoptions.mppe.stateful) & pcb.ccp_gotoptions.mppe) != pcb.ccp_gotoptions.mppe)
        // {
        //     /* Peer must have set options we didn't request (suggest) */
        //     mppe_clear_options(pcb.ccp_gotoptions.mppe);
        // }

        if (!mppe_has_options(pcb.ccp_gotoptions.mppe))
        {
            std::string msg = "MPPE required but peer negotiation failed";
            spdlog::error(msg);
            lcp_close(pcb, msg);
        }
    }

    if (pcb.ccp_gotoptions.deflate && pkt_data.size() >= CILEN_DEFLATE
        && pkt_data[0] == (pcb.ccp_gotoptions.deflate_correct ? CI_DEFLATE : CI_DEFLATE_DRAFT)
        && pkt_data[1] == CILEN_DEFLATE)
    {
        no.deflate = true;
        /*
         * Peer wants us to use a different code size or something.
         * Stop asking for Deflate if we don't understand his suggestion.
         */
        if (DEFLATE_METHOD(pkt_data[2]) != DEFLATE_METHOD_VAL
            || DEFLATE_SIZE(pkt_data[2]) < DEFLATE_MIN_WORKS
            || pkt_data[3] != DEFLATE_CHK_SEQUENCE)
            pcb.ccp_gotoptions.deflate = false;
        else if (DEFLATE_SIZE(pkt_data[2]) < pcb.ccp_gotoptions.deflate_size)
            pcb.ccp_gotoptions.deflate_size = DEFLATE_SIZE(pkt_data[2]);
        pkt_data += CILEN_DEFLATE;
        len -= CILEN_DEFLATE;
        if (pcb.ccp_gotoptions.deflate_correct && pcb.ccp_gotoptions.deflate_draft
            && len >= CILEN_DEFLATE && pkt_data[0] == CI_DEFLATE_DRAFT
            && pkt_data[1] == CILEN_DEFLATE)
        {
            pkt_data += CILEN_DEFLATE;
            len -= CILEN_DEFLATE;
        }
    }

    if (pcb.ccp_gotoptions.bsd_compress && len >= CILEN_BSD_COMPRESS
        && pkt_data[0] == CI_BSD_COMPRESS && pkt_data[1] == CILEN_BSD_COMPRESS)
    {
        no.bsd_compress = true;
        /*
         * Peer wants us to use a different number of bits
         * or a different version.
         */
        if (BSD_VERSION(pkt_data[2]) != BSD_CURRENT_VERSION) {
            pcb.ccp_gotoptions.bsd_compress = false;
        }
        else if (BSD_NBITS(pkt_data[2]) < pcb.ccp_gotoptions.bsd_bits) { pcb.ccp_gotoptions.bsd_bits = BSD_NBITS(pkt_data[2]); }
        pkt_data += CILEN_BSD_COMPRESS;
        len -= CILEN_BSD_COMPRESS;
    }


    /*
     * Predictor-1 and 2 have no options, so they can't be Naked.
     *
     * There may be remaining options but we ignore them.
     */

    // if (f.state != PPP_FSM_OPENED)
    //     *go = try_;
    return true;
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
        spdlog::error("MPPE required but peer refused");
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
                        spdlog::error("Refusing MPPE stateful mode offered by peer");
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
                    DEFLATE_CHK_SEQUENCE || nb > ao->deflate_size || nb < DEFLATE_MIN_WORKS
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
                        if (res > 0) { break; /* it's OK now */ }
                        if (res < 0 || nb == DEFLATE_MIN_WORKS || dont_nak)
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
        if (newret == CONFNAK && dont_nak) { newret = CONFREJ; }
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
        spdlog::error("MPPE required but peer negotiation failed");
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
                spdlog::info("%s compression enabled", method_name(go, ho));
            }
            else
            {
                ppp_strlcpy(method1, method_name(go, nullptr), sizeof(method1));
                spdlog::info("%s / %s compression enabled",
                           method1, method_name(ho, nullptr));
            }
        }
        else
        {
            spdlog::info("%s receive compression enabled", method_name(go, nullptr));
        }
    }
    else if (ccp_anycompress(ho))
    {
        spdlog::info("%s transmit compression enabled", method_name(ho, nullptr));
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
            spdlog::error("MPPE disabled");
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
// 	    spdlog::error("Lost compression sync: disabling compression");
// 	    ccp_close(pcb, "Lost compression sync");
// #if MPPE_SUPPORT
// 	    /*
// 	     * If we were doing MPPE, we must also take the link down.
// 	     */
// 	    if (go->mppe) {
// 		spdlog::error("Too many MPPE errors, closing LCP");
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
ccp_reset_request(uint8_t& ppp_pcb_ccp_local_state, Fsm& f, PppPcb& pcb)
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
        std::vector<uint8_t> empty;
        if (!fsm_send_data2(pcb, f, CCP_RESETREQ, f.reqid = ++f.id, empty))
        {
            return false;
        }

        // timeout(ccp_rack_timeout, f, kRacktimeout);
        ppp_pcb_ccp_local_state |= RESET_ACK_PENDING;
    }
    else
    {
        ppp_pcb_ccp_local_state |= REPEAT_RESET_REQ;
    }

    return true;
}


/**
 * Timeout waiting for reset-ack.
 */
bool
ccp_rack_timeout(Fsm& f, PppPcb& pcb)
{
    if (f.state == PPP_FSM_OPENED && (pcb.ccp_localstate & REPEAT_RESET_REQ)) {
        std::vector<uint8_t> empty;
        fsm_send_data2(pcb, f, CCP_RESETREQ, f.reqid, empty);
        // Timeout(ccp_rack_timeout, args, RESET_ACK_TIMEOUT);
        // todo: schedule timeout
        pcb.ccp_localstate &= ~REPEAT_RESET_REQ;
    }
    else { pcb.ccp_localstate &= ~RESET_ACK_PENDING; }
}

//
// END OF FILE
//