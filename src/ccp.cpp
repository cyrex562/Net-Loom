
#define NOMINMAX
#include "ccp.h"
#include "auth.h"
#include "mppe.h"
#include "ppp.h"
#include <cstring>
#include <fmt/format.h>
#include <spdlog/spdlog.h>


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
        ccp_set(pcb, true, false, 0, 0); /*
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
bool
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
    if (oldstate == PPP_FSM_OPENED && pkt[0] == TERM_REQ && pcb.ccp_fsm.state != PPP_FSM_OPENED)
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
    if (oldstate == PPP_FSM_REQSENT && pkt[0] == TERM_ACK && !ccp_anycompress(go))
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
        if ((pcb.ccp_localstate.reset_ack_pending) && id == f.reqid)
        {
            pcb.ccp_localstate.reset_ack_pending = false;
            pcb.ccp_localstate.repeat_reset_req = false;
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
                if (mppe_has_options(ppp_pcb.ccp_gotoptions.mppe)) return 0 + 0 + CILEN_DEFLATE + CILEN_DEFLATE +
                    CILEN_PREDICTOR_1 + 0 + CILEN_MPPE;
                return 0 + 0 + CILEN_DEFLATE + CILEN_DEFLATE + CILEN_PREDICTOR_1 + 0 + 0;
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
    size_t ptr = 0;

    /*
     * Add the compression types that we can receive, in decreasing
     * preference order.
     */
    if (mppe_has_options(pcb.ccp_gotoptions.mppe)) {

        pkt[ptr] = CI_MPPE;
        pkt[ptr+1] = CILEN_MPPE;
        mppe_opts_to_ci(pcb.ccp_gotoptions.mppe, pkt.data() + 2);
        if (!mppe_init(pcb, pcb.mppe_decomp, pcb.ccp_gotoptions.mppe)) { return false; }
        ptr += CILEN_MPPE;
    }
    if (pcb.ccp_gotoptions.deflate) {
        if (pcb.ccp_gotoptions.deflate_correct) {
            pkt[ptr] = CI_DEFLATE;
            pkt[ptr + 1] = CILEN_DEFLATE;
            pkt[ptr + 2] = DEFLATE_MAKE_OPT(pcb.ccp_gotoptions.deflate_size);
            pkt[ptr + 3] = DEFLATE_CHK_SEQUENCE;
            ptr += CILEN_DEFLATE;
        }
        if (pcb.ccp_gotoptions.deflate_draft) {
            pkt[ptr] = CI_DEFLATE_DRAFT;
            pkt[ptr + 1] = CILEN_DEFLATE;
            pkt[ptr + 2] = pkt[ptr + 2 - CILEN_DEFLATE];
            pkt[ptr + 3] = DEFLATE_CHK_SEQUENCE;
            ptr += CILEN_DEFLATE;
        }
    }
    if (pcb.ccp_gotoptions.bsd_compress) {
        pkt[ptr + 0] = CI_BSD_COMPRESS;
        pkt[ptr + 1] = CILEN_BSD_COMPRESS;
        pkt[ptr + 2] = BSD_MAKE_OPT(BSD_CURRENT_VERSION, pcb.ccp_gotoptions.bsd_bits);
        ptr += CILEN_BSD_COMPRESS;
    }

    /* XXX Should Predictor 2 be preferable to Predictor 1? */
    if (pcb.ccp_gotoptions.predictor_1) {
        pkt[0] = CI_PREDICTOR_1;
        pkt[ptr + 1] = CILEN_PREDICTOR_1;
        ptr += CILEN_PREDICTOR_1;
    }
    if (pcb.ccp_gotoptions.predictor_2) {
        pkt[0] = CI_PREDICTOR_2;
        pkt[ptr + 1] = CILEN_PREDICTOR_2;
        ptr += CILEN_PREDICTOR_2;
    }

    if ((pkt[ptr] > pkt[0])) pcb.ccp_gotoptions.method = pkt[0];
    else pcb.ccp_gotoptions.method = 0;

    // *lenp = pkt - p0;
    return true;
}

/**
 * process a received configure-ack, and return 1 iff the packet was OK.
 */
bool
ccp_proc_config_ack(Fsm& f, std::vector<uint8_t>& pkt, PppPcb& pcb)
{
    // PppPcb* pcb = f->pcb;
    // const auto go = &pcb->ccp_gotoptions;
    // const auto p0 = p;
    size_t ptr = 0;
    if (mppe_has_options(pcb.ccp_gotoptions.mppe)) {
        uint8_t opt_buf[CILEN_MPPE];
        opt_buf[0] = CI_MPPE;
        opt_buf[1] = CILEN_MPPE;
        mppe_opts_to_ci(pcb.ccp_gotoptions.mppe, &opt_buf[2]);
        if (pkt.size() < CILEN_MPPE || memcmp(opt_buf, pkt.data(), CILEN_MPPE)) {
            return false;
        }
        ptr += CILEN_MPPE;
        // todo: Cope with first/fast ack
        if (ptr == pkt.size()) { return true; }
    }
    if (pcb.ccp_gotoptions.deflate) {
        if (pkt.size() - ptr < CILEN_DEFLATE
            || pkt[ptr + 0] != (pcb.ccp_gotoptions.deflate_correct ? CI_DEFLATE
              : CI_DEFLATE_DRAFT)
            || pkt[ptr + 1] != CILEN_DEFLATE
            || pkt[ptr + 2] != DEFLATE_MAKE_OPT(pcb.ccp_gotoptions.deflate_size)
            || pkt[ptr + 3] != DEFLATE_CHK_SEQUENCE) { return false; }
        ptr += CILEN_DEFLATE;
        // todo: Cope with first/fast ack
        if (ptr == pkt.size()) { return true; }
        if (pcb.ccp_gotoptions.deflate_correct && pcb.ccp_gotoptions.deflate_draft) {
            if (ptr + pkt.size() < CILEN_DEFLATE || pkt[ptr + 0] != CI_DEFLATE_DRAFT ||
                pkt[ptr + 1] != CILEN_DEFLATE || pkt[ptr + 2] !=
                DEFLATE_MAKE_OPT(pcb.ccp_gotoptions.deflate_size) || pkt[ptr + 3] !=
                DEFLATE_CHK_SEQUENCE) { return false; }
            ptr += CILEN_DEFLATE;
        }
    }

    if (pcb.ccp_gotoptions.bsd_compress) {
        if (pkt.size() - ptr < CILEN_BSD_COMPRESS || pkt[ptr + 0] != CI_BSD_COMPRESS ||
            pkt[ptr + 1] != CILEN_BSD_COMPRESS || pkt[2] != BSD_MAKE_OPT(
                BSD_CURRENT_VERSION,
                pcb.ccp_gotoptions.bsd_bits)) { return false; }
        ptr += CILEN_BSD_COMPRESS;
        // todo: Cope with first/fast ack
        if (pkt[ptr] == pkt[0] && pkt.size() - ptr == 0) return true;
    }

    if (pcb.ccp_gotoptions.predictor_1) {
        if (pkt.size() - ptr < CILEN_PREDICTOR_1 || pkt[ptr + 0] != CI_PREDICTOR_1 || pkt[
            ptr + 1] != CILEN_PREDICTOR_1) { return false; }
        ptr += CILEN_PREDICTOR_1;
        // todo: Cope with first/fast ack
        if (pkt[ptr] == pkt[0] && pkt.size() - ptr == 0) { return true; }
    }

    if (pcb.ccp_gotoptions.predictor_2) {
        if (pkt.size() - ptr < CILEN_PREDICTOR_2 || pkt[ptr + 0] != CI_PREDICTOR_2 || pkt[
            ptr + 1] != CILEN_PREDICTOR_2) return false;
        ptr += CILEN_PREDICTOR_2;
        // todo: Cope with first/fast ack
        if (pkt[ptr] == pkt[0] && pkt.size() - ptr == 0) return true;
    }


    if (pkt.size() - ptr != 0)
    {
        return false;
    }
    return true;
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
    size_t ptr = 0;
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
        && pkt_data[ptr + 0] == (pcb.ccp_gotoptions.deflate_correct ? CI_DEFLATE : CI_DEFLATE_DRAFT)
        && pkt_data[ptr + 1] == CILEN_DEFLATE)
    {
        no.deflate = true;
        /*
         * Peer wants us to use a different code size or something.
         * Stop asking for Deflate if we don't understand his suggestion.
         */
        if (DEFLATE_METHOD(pkt_data[ptr + 2]) != DEFLATE_METHOD_VAL
            || DEFLATE_SIZE(pkt_data[ptr + 2]) < DEFLATE_MIN_WORKS
            || pkt_data[ptr + 3] != DEFLATE_CHK_SEQUENCE)
            pcb.ccp_gotoptions.deflate = false;
        else if (DEFLATE_SIZE(pkt_data[ptr + 2]) < pcb.ccp_gotoptions.deflate_size)
            pcb.ccp_gotoptions.deflate_size = DEFLATE_SIZE(pkt_data[ptr + 2]);
        ptr += CILEN_DEFLATE;
        if (pcb.ccp_gotoptions.deflate_correct && pcb.ccp_gotoptions.deflate_draft
            && pkt_data.size() - ptr >= CILEN_DEFLATE && pkt_data[ptr + 0] == CI_DEFLATE_DRAFT
            && pkt_data[ptr + 1] == CILEN_DEFLATE)
        {
            ptr += CILEN_DEFLATE;
        }
    }

    if (pcb.ccp_gotoptions.bsd_compress && pkt_data.size() - ptr >= CILEN_BSD_COMPRESS
        && pkt_data[ptr + 0] == CI_BSD_COMPRESS && pkt_data[ptr + 1] == CILEN_BSD_COMPRESS)
    {
        no.bsd_compress = true;
        /*
         * Peer wants us to use a different number of bits
         * or a different version.
         */
        if (BSD_VERSION(pkt_data[ptr + 2]) != BSD_CURRENT_VERSION) {
            pcb.ccp_gotoptions.bsd_compress = false;
        }
        else if (BSD_NBITS(pkt_data[ptr + 2]) < pcb.ccp_gotoptions.bsd_bits) { pcb.ccp_gotoptions.bsd_bits = BSD_NBITS(pkt_data[ptr + 2]); }
        ptr += CILEN_BSD_COMPRESS;
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
bool
ccp_rejci(Fsm& f, std::vector<uint8_t>& pkt, PppPcb& pcb)
{
    // PppPcb* pcb = f->pcb;
    // const auto go = &pcb->ccp_gotoptions;
    // auto try_ = *go;
    // /*
    //  * Cope with empty configure-rejects by ceasing to send
    //  * configure-requests.
    //  */
    size_t ptr = 0;
    if (pkt.empty() && pcb.ccp_all_rejected)
    {
        return false;
    }
    if (mppe_has_options(pcb.ccp_gotoptions.mppe) && pkt.size() - ptr >= CILEN_MPPE && pkt[ptr + 0] == CI_MPPE && pkt[ptr + 1] == CILEN_MPPE)
    {
        std::string msg = "MPPE required but peer refused";
        spdlog::error(msg);
        lcp_close(pcb, msg);
        ptr += CILEN_MPPE;
    }
    if (pcb.ccp_gotoptions.deflate_correct && pkt.size() - ptr >= CILEN_DEFLATE && pkt[ptr + 0] == CI_DEFLATE && pkt[ptr + 1] ==
        CILEN_DEFLATE)
    {
        if (pkt[2] != DEFLATE_MAKE_OPT(pcb.ccp_gotoptions.deflate_size) || pkt[3] != DEFLATE_CHK_SEQUENCE)
        {
            return false; /* Rej is bad */
        }
        pcb.ccp_gotoptions.deflate_correct = false;
        ptr += CILEN_DEFLATE;
    }
    if (pcb.ccp_gotoptions.deflate_draft && pkt.size() - ptr >= CILEN_DEFLATE && pkt[ptr + 0] == CI_DEFLATE_DRAFT && pkt[ptr + 1] ==
        CILEN_DEFLATE)
    {
        if (pkt[2] != DEFLATE_MAKE_OPT(pcb.ccp_gotoptions.deflate_size) || pkt[ptr + 3] != DEFLATE_CHK_SEQUENCE)
        {
            return false; /* Rej is bad */
        }
        pcb.ccp_gotoptions.deflate_draft = false;
        ptr += CILEN_DEFLATE;

    }
    if (!pcb.ccp_gotoptions.deflate_correct && !pcb.ccp_gotoptions.deflate_draft)
    {
        pcb.ccp_gotoptions.deflate = false;
    }
    if (pcb.ccp_gotoptions.bsd_compress && pkt.size() - ptr >= CILEN_BSD_COMPRESS && pkt[ptr + 0] == CI_BSD_COMPRESS && pkt[ptr + 1]
        == CILEN_BSD_COMPRESS)
    {
        if (pkt[ptr + 2] != BSD_MAKE_OPT(BSD_CURRENT_VERSION, pcb.ccp_gotoptions.bsd_bits))
        {
            return false;
        }
        pcb.ccp_gotoptions.bsd_compress = false;
        ptr += CILEN_BSD_COMPRESS;
    }
    if (pcb.ccp_gotoptions.predictor_1 && pkt.size() - ptr >= CILEN_PREDICTOR_1 && pkt[ptr + 0] == CI_PREDICTOR_1 && pkt[ptr + 1] ==
        CILEN_PREDICTOR_1)
    {
        pcb.ccp_gotoptions.predictor_1 = false;
        ptr += CILEN_PREDICTOR_1;
    }
    if (pcb.ccp_gotoptions.predictor_2 && pkt.size() - ptr >= CILEN_PREDICTOR_2 && pkt[ptr + 0] == CI_PREDICTOR_2 && pkt[ptr + 1] ==
        CILEN_PREDICTOR_2)
    {
        pcb.ccp_gotoptions.predictor_2 = false;
        ptr += CILEN_PREDICTOR_2;
    }
    if (pkt.size() - ptr != 0)
    {
        return false;
    }
    // if (f->state != PPP_FSM_OPENED)
    //     *go = try_;
    return true;
}

/*
 * ccp_reqci - processed a received configure-request.
 * Returns CONFACK, CONFNAK or CONFREJ and the packet modified
 * appropriately.
 */
std::tuple<bool, int>
ccp_proc_config_req(Fsm& f, std::vector<uint8_t>& pkt, bool dont_nak, PppPcb& pcb)
{
    // PppPcb* pcb = f->pcb;
    // auto ho = &pcb->ccp_hisoptions;
    // auto ao = &pcb->ccp_allowoptions;
    int res;
    int nb;
    // uint8_t *p0;
    int clen;
    int type;
    bool rej_for_ci_mppe = true;
    /* Are we rejecting based on a bad/missing CI_MPPE, or due to other options? */
    auto ret = CONF_ACK;
    // auto retp = p0 = pkt;
    size_t ptr = 0;
    CpCodes newret = CONF_NOT_SET;
    // int len = *lenp;
    // todo: refactor to clear fields of CcpOptions
    memset(&pcb.ccp_hisoptions, 0, sizeof(CcpOptions));
    pcb.ccp_hisoptions.method = (!pkt.empty()) ? pkt[ptr + 0] : 0;
    while (!pkt.empty())
    {
        CpCodes newret = CONF_ACK;
        if (pkt.size() < 2 || pkt[ptr + 1] < 2 || pkt[ptr + 1] > pkt.size())
        {
            /* length is bad */
            clen = pkt.size();
            newret = CONF_REJECT;
        }
        else
        {
            type = pkt[ptr + 0];
            clen = pkt[ptr + 1];
            switch (type)
            {
            case CI_MPPE:
                if (!mppe_has_options(pcb.ccp_allowoptions.mppe) || clen != CILEN_MPPE) {
                    newret = CONF_REJECT;
                    break;
                }
                pcb.ccp_hisoptions.mppe = MPPE_CI_TO_OPTS(pkt.data() + ptr + 2);
                /* Nak if anything unsupported or unknown are set. */
                if (pcb.ccp_hisoptions.mppe.opt_56 || pcb.ccp_hisoptions.mppe.opt_mppc ||
                    pcb.ccp_hisoptions.mppe.opt_d) {
                    newret = CONF_NAK;
                    pcb.ccp_hisoptions.mppe.opt_56 = false;
                    pcb.ccp_hisoptions.mppe.opt_mppc = false;
                    pcb.ccp_hisoptions.mppe.opt_d = false;
                }
                if (pcb.ccp_hisoptions.mppe.unknown) {
                    newret = CONF_NAK;
                    pcb.ccp_hisoptions.mppe.unknown = false;
                }

                /* Check state opt */
                if (pcb.ccp_hisoptions.mppe.stateful) {
                    /*
                     * We can Nak and request stateless, but it's a
                     * lot easier to just assume the peer will request
                     * it if he can do it; stateful mode is bad over
                     * the Internet -- which is where we expect MPPE.
                     */
                    if (pcb.settings.refuse_mppe_stateful) {
                        spdlog::error("Refusing MPPE stateful mode offered by peer");
                        newret = CONF_REJECT;
                        break;
                    }
                }

                /* Find out which of {S,L} are set. */
                if ((pcb.ccp_hisoptions.mppe.opt_128) && (pcb.ccp_hisoptions.mppe.opt_40))
                {
                    /* Both are set, negotiate the strongest. */
                    newret = CONF_NAK;
                    if (pcb.ccp_allowoptions.mppe.opt_128)
                    {
                        pcb.ccp_hisoptions.mppe.opt_40 = false;
                    }
                    else if (pcb.ccp_allowoptions.mppe.opt_40)
                    {
                        pcb.ccp_hisoptions.mppe.opt_128 = false;
                    }
                    else
                    {
                        newret = CONF_REJECT;
                        break;
                    }
                }
                else if (pcb.ccp_hisoptions.mppe.opt_128)
                {
                    if (!(pcb.ccp_allowoptions.mppe.opt_128))
                    {
                        newret = CONF_REJECT;
                        break;
                    }
                }
                else if (pcb.ccp_hisoptions.mppe.opt_40) {
                    if (!(pcb.ccp_allowoptions.mppe.opt_40)) {
                        newret = CONF_REJECT;
                        break;
                    }
                }
                else {
                    /* Neither are set. */
                    /* We cannot accept this.  */
                    newret = CONF_NAK;
                    /* Give the peer our idea of what can be used,
                       so it can choose and confirm */
                    pcb.ccp_hisoptions.mppe = pcb.ccp_allowoptions.mppe;
                }

                /* rebuild the opts */
                mppe_opts_to_ci(pcb.ccp_hisoptions.mppe, pkt.data() + 2);
                if (newret == CONF_ACK) {
                    mppe_init(pcb, pcb.mppe_comp, pcb.ccp_hisoptions.mppe);
                    /*
                     * We need to decrease the interface MTU by MPPE_PAD
                     * because MPPE frames **grow**.  The kernel [must]
                     * allocate MPPE_PAD extra bytes in xmit buffers.
                     */
                    const auto mtu = ppp_netif_get_mtu(pcb);
                    if (mtu) netif_set_mtu(pcb, mtu - MPPE_PAD);
                    else {
                        newret = CONF_REJECT;
                    }
                }

                /*
                 * We have accepted MPPE or are willing to negotiate
                 * MPPE parameters.  A CONFREJ is due to subsequent
                 * (non-MPPE) processing.
                 */
                rej_for_ci_mppe = false;
                break;
            case CI_DEFLATE: case CI_DEFLATE_DRAFT: if (!pcb.ccp_allowoptions.deflate ||
                    clen != CILEN_DEFLATE || (!pcb.ccp_allowoptions.deflate_correct &&
                        type == CI_DEFLATE) || (!pcb.ccp_allowoptions.deflate_draft &&
                        type == CI_DEFLATE_DRAFT)) {
                    newret = CONF_REJECT;
                    break;
                }
                pcb.ccp_hisoptions.deflate = true;
                pcb.ccp_hisoptions.deflate_size = nb = DEFLATE_SIZE(pkt[2]);
                if (DEFLATE_METHOD(pkt[2]) != DEFLATE_METHOD_VAL || pkt[3] !=
                    DEFLATE_CHK_SEQUENCE || nb > pcb.ccp_allowoptions.deflate_size || nb <
                    DEFLATE_MIN_WORKS) {
                    newret = CONF_NAK;
                    if (!dont_nak) {
                        pkt[2] = DEFLATE_MAKE_OPT(pcb.ccp_allowoptions.deflate_size);
                        pkt[3] = DEFLATE_CHK_SEQUENCE;
                        /* fall through to test this #bits below */
                    }
                    else { break; }
                }

                /*
                 * Check whether we can do Deflate with the window
                 * size they want.  If the window is too big, reduce
                 * it until the kernel can cope and nak with that.
                 * We only check this for the first option.
                 */
                if (pkt[ptr] == pkt[0])
                {
                    for (;;)
                    {
                        res = ccp_test(pcb, pkt, CILEN_DEFLATE, 1);
                        if (res > 0) { break; /* it's OK now */ }
                        if (res < 0 || nb == DEFLATE_MIN_WORKS || dont_nak)
                        {
                            newret = CONF_REJECT;
                            pkt[2] = DEFLATE_MAKE_OPT(pcb.ccp_hisoptions.deflate_size);
                            break;
                        }
                        newret = CONF_NAK;
                        --nb;
                        pkt[2] = DEFLATE_MAKE_OPT(nb);
                    }
                }
                break;
            case CI_BSD_COMPRESS:
                if (!pcb.ccp_allowoptions.bsd_compress || clen != CILEN_BSD_COMPRESS) {
                    newret = CONF_REJECT;
                    break;
                }
                pcb.ccp_hisoptions.bsd_compress = true;
                pcb.ccp_hisoptions.bsd_bits = nb = BSD_NBITS(pkt[2]);
                if (BSD_VERSION(pkt[2]) != BSD_CURRENT_VERSION
                    || nb > pcb.ccp_allowoptions.bsd_bits
                    || nb < BSD_MIN_BITS) {
                    newret = CONF_NAK;
                    if (!dont_nak) {
                        pkt[2] = BSD_MAKE_OPT(BSD_CURRENT_VERSION, pcb.ccp_allowoptions.bsd_bits);
                        /* fall through to test this #bits below */
                    }
                    else { break; }
                }

                /*
                 * Check whether we can do BSD-Compress with the code
                 * size they want.  If the code size is too big, reduce
                 * it until the kernel can cope and nak with that.
                 * We only check this for the first option.
                 */
                if (pkt[ptr] == pkt[0]) {
                    for (;;) {
                        res = ccp_test(pcb, pkt, CILEN_BSD_COMPRESS, 1);
                        if (res > 0) { break; }
                        if (res < 0 || nb == BSD_MIN_BITS || dont_nak) {
                            newret = CONF_REJECT;
                            pkt[2] = BSD_MAKE_OPT(BSD_CURRENT_VERSION,  pcb.ccp_hisoptions.bsd_bits);
                            break;
                        }
                        newret = CONF_NAK;
                        --nb;
                        pkt[2] = BSD_MAKE_OPT(BSD_CURRENT_VERSION, nb);
                    }
                }
                break;
            case CI_PREDICTOR_1:
                if (!pcb.ccp_allowoptions.predictor_1 || clen != CILEN_PREDICTOR_1) {
                    newret = CONF_REJECT;
                    break;
                }
                pcb.ccp_hisoptions.predictor_1 = true;
                if (pkt[ptr] == pkt[0] && ccp_test(pcb, pkt, CILEN_PREDICTOR_1, 1) <= 0) {
                    newret = CONF_REJECT;
                }
                break;
            case CI_PREDICTOR_2:
                if (!pcb.ccp_allowoptions.predictor_2 || clen != CILEN_PREDICTOR_2) {
                    newret = CONF_REJECT;
                    break;
                }
                pcb.ccp_hisoptions.predictor_2 = true;
                if (pkt[ptr] == pkt[0] && ccp_test(pcb, pkt, CILEN_PREDICTOR_2, 1) <= 0) {
                    newret = CONF_REJECT;
                }
                break;
            default:
                newret = CONF_REJECT;
            }
        }
        if (newret == CONF_NAK && dont_nak) { newret = CONF_REJECT; }
        if (!(newret == CONF_ACK || (newret == CONF_NAK && ret == CONF_REJECT)))
        {
            /* we're returning this option */
            if (newret == CONF_REJECT && ret == CONF_NAK)
            {
                // todo: figure out what the desired behavior here is.
                //retp = pkt[0];
            }
            ret = newret;
            // todo: figure out what the desire behavior here is.
            // if (pkt != retp)
            // {
            //     memcpy(retp, pkt.data(), clen);
            // }
            // retp += clen;
        }
        ptr += clen;
    }
    if (ret != CONF_ACK)
    {
        if (ret == CONF_REJECT && pkt.size() == pkt[ptr] - pkt[0])
        {
            pcb.ccp_all_rejected = true;
        }
        // else
        // {
        //     *lenp = retp - p0;
        // }
    }
    if (ret == CONF_REJECT && mppe_has_options(pcb.ccp_allowoptions.mppe) && rej_for_ci_mppe)
    {
        std::string msg = "MPPE required but peer negotiation failed";
        spdlog::error(msg);
        lcp_close(pcb, msg);
    }
    return std::make_tuple(true, newret);
}

/**
 * Make a string name for a compression method (or 2).
 */
std::string
method_name(CcpOptions& opt1, CcpOptions& opt2)
{
    std::string result;
    if (!ccp_anycompress(opt1)) { return "(none)"; }
    switch (opt1.method) {
    case CI_MPPE: {
        result = "MPPE ";
        if (opt1.mppe.opt_128) {
            result = result + "128-bit ";
        }
        if (opt1.mppe.opt_40) {
            result = result + "40-bit ";
        }
        if (opt1.mppe.stateful) { result = result + "stateful";}
        else {result += "stateless"; }
        break;
    }
    case CI_DEFLATE: case CI_DEFLATE_DRAFT:
        if (opt2.deflate_size != opt1.deflate_size) {
            result += fmt::format("Deflate {} ({}/{})",
                                  opt1.method == CI_DEFLATE_DRAFT ? "(old#)" : "",
                                  opt1.deflate_size,
                                  opt2.deflate_size);
        }
        else {
            result += fmt::format("Deflate {} {}",
                                  opt1.method == CI_DEFLATE_DRAFT ? "(old#)" : "",
                                  opt1.deflate_size);
        }
        break;
    case CI_BSD_COMPRESS:
        if (opt2.bsd_bits != opt1.bsd_bits) result += fmt::format(
            "BSD-Compress ({}/{})",
            opt1.bsd_bits,
            opt2.bsd_bits);
        else { result += fmt::format("BSD-Compress ({})", opt1.bsd_bits); }
        break;
    case CI_PREDICTOR_1:
        return "Predictor 1";
    case CI_PREDICTOR_2:
        return "Predictor 2";
    default:
        result += fmt::format("Method {}", opt1.method);
    }
    return result;
}

/**
 * CCP has come up - inform the kernel driver and log a message.
 */
bool
ccp_up(Fsm&, PppPcb& pcb)
{
    auto empty_opts = CcpOptions();
    ccp_set(pcb, true, true, pcb.ccp_gotoptions.method, pcb.ccp_hisoptions.method);
    if (ccp_anycompress(pcb.ccp_gotoptions)) {
        if (ccp_anycompress(pcb.ccp_hisoptions)) {
            if (pcb.ccp_gotoptions.method == pcb.ccp_hisoptions.method) {
                spdlog::info("%s compression enabled",
                             method_name(pcb.ccp_gotoptions, pcb.ccp_hisoptions));
            }
            else {
                const std::string method1 = method_name(pcb.ccp_gotoptions, empty_opts);
                spdlog::info("%s / %s compression enabled",
                             method1,
                             method_name(pcb.ccp_hisoptions, empty_opts));
            }
        }
        else {
            spdlog::info("%s receive compression enabled",
                         method_name(pcb.ccp_gotoptions, empty_opts));
        }
    }
    else if (ccp_anycompress(pcb.ccp_hisoptions)) {
        spdlog::info("%s transmit compression enabled",
                     method_name(pcb.ccp_hisoptions, empty_opts));
    }
    if (mppe_has_options(pcb.ccp_gotoptions.mppe)) {
        /* Bring up IP et al */
        continue_networks(pcb);
    }
    return true;
}

/**
 * Inform the kernel driver.
 */
bool
ccp_down(Fsm& f, Fsm& lcp_fsm, PppPcb& pcb)
{
    if (pcb.ccp_localstate.reset_ack_pending) {
        // todo: un-register timeout
        // Untimeout(ccp_rack_timeout, f);
    }
    clear_ccp_local_state(pcb.ccp_localstate);
    ccp_set(pcb, true, false, 0, 0);
    if (mppe_has_options(pcb.ccp_gotoptions.mppe)) {
        mppe_clear_options(pcb.ccp_gotoptions.mppe);
        if (lcp_fsm.state == PPP_FSM_OPENED) {
            /* If LCP is not already going down, make sure it does. */
            std::string msg = "MPPE disabled";
            spdlog::error(msg);
            lcp_close(pcb, msg);
        }
    }

    return true;
}


/**
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
bool
ccp_datainput(PppPcb& pcb, std::vector<uint8_t>& pkt)
{
    // todo: re-write method
    // auto go = &pcb->ccp_gotoptions;
    // const auto f = &pcb->ccp_fsm;
    if (pcb.ccp_fsm.state == PPP_FSM_OPENED) {
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
    return true;
}

/*
 * We have received a packet that the decompressor failed to
 * decompress. Issue a reset-request.
 */
bool
ccp_reset_request(CcpLocalState& local_state, Fsm& f, PppPcb& pcb)
{
    if (f.state != PPP_FSM_OPENED) { return false; }
    /*
     * Send a reset-request to reset the peer's compressor.
     * We don't do that if we are still waiting for an
     * acknowledgement to a previous reset-request.
     */
    if (!(local_state.reset_ack_pending)) {
        std::vector<uint8_t> empty;
        if (!fsm_send_data2(pcb, f, CCP_RESETREQ, f.reqid = ++f.id, empty)) {
            return false;
        }

        // todo: schedule timeout
        // timeout(ccp_rack_timeout, f, kRacktimeout);
        local_state.reset_ack_pending = true;
    }
    else { local_state.repeat_reset_req = true; }
    return true;
}


/**
 * Timeout waiting for reset-ack.
 */
bool
ccp_reset_ack_timeout(Fsm& f, PppPcb& pcb)
{
    if (f.state == PPP_FSM_OPENED && (pcb.ccp_localstate.repeat_reset_req)) {
        std::vector<uint8_t> empty;
        fsm_send_data2(pcb, f, CCP_RESETREQ, f.reqid, empty);
        // Timeout(ccp_rack_timeout, args, RESET_ACK_TIMEOUT);
        // todo: schedule timeout
        pcb.ccp_localstate.repeat_reset_req = false;
    }
    else { pcb.ccp_localstate.reset_ack_pending = false; }
    return true;
}

//
// END OF FILE
//