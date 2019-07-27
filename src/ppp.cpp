#include <auth.h>
#include <ccp.h>
#include <dns.h>
#include <fsm.h>
#include <ip4.h> /* for ip4_input() */
#include <ip6.h> /* for ip6_input() */
#include <ipv6cp.h>
#include <lcp.h>
#include <magic.h>
#include <mppe.h>
#include <packet_buffer.h>
#include <ppp_impl.h>
#include <ppp_opts.h>
#include <pppos.h>
#include <timeouts.h>
#include <vj.h>
#ifdef _MSC_VER
#endif
/*************************/ /*** LOCAL DEFINITIONS ***/ /*************************/
/* FIXME: add stats per PPP session */
// static struct timeval; /* Time when link was started. */
// static struct pppd_stats old_link_stats;
// struct pppd_stats link_stats;
// unsigned link_connect_time;
// int link_stats_valid; /*
 // * PPP Data Link Layer "protocol" table.
 // * One entry per supported protocol.
 // * The last entry must be NULL.
 // */ // const struct Protent* const kProtocols[] = {
//     &kLcpProtent,
//     &pap_protent,
//     &kChapProtent,
//     nullptr,
//     &ipcp_protent,
//     &ipv6cp_protent,
//     &kCcpProtent,
//     &kEcpProtent,
//     nullptr,
//     &eap_protent,
// };
/* Prototypes for procedures local to this file. */ /***********************************/
/*** PUBLIC FUNCTION DEFINITIONS ***/ /***********************************/
void
ppp_set_auth(PppPcb* pcb,
             const PppAuthTypes authtype,
             std::string& user,
             std::string& password)
{
    pcb->settings.refuse_pap = !(authtype == PPPAUTHTYPE_PAP);
    pcb->settings.refuse_chap = !(authtype == PPPAUTHTYPE_CHAP);
    pcb->settings.refuse_mschap = !(authtype == PPPAUTHTYPE_MSCHAP);
    pcb->settings.refuse_mschap_v2 = !(authtype == PPPAUTHTYPE_MSCHAP_V2);
    pcb->settings.refuse_eap = !(authtype == PPPAUTHTYPE_EAP);
    pcb->settings.user = user;
    pcb->settings.passwd = password;
}

/* Set MPPE configuration */
void
ppp_set_mppe(PppPcb* pcb, uint8_t flags)
{
    if (flags == kPppMppeDisable)
    {
        pcb->settings.require_mppe = false;
        return;
    }
    pcb->settings.require_mppe = true;
    pcb->settings.refuse_mppe_stateful = !(flags & PPP_MPPE_ALLOW_STATEFUL);
    pcb->settings.refuse_mppe_40 = !!(flags & PPP_MPPE_REFUSE_40);
    pcb->settings.refuse_mppe_128 = !!(flags & PPP_MPPE_REFUSE_128);
} //
//
//
void
ppp_set_notify_phase_callback(PppPcb* pcb, ppp_notify_phase_cb_fn notify_phase_cb)
{
    // pcb->notify_phase_cb = notify_phase_cb;
    // notify_phase_cb(pcb, pcb->phase, pcb->ctx_cb);
} /*
 * Initiate a PPP connection.
 *
 * This can only be called if PPP is in the dead phase.
 *
 * Holdoff is the time to wait (in seconds) before initiating
 * the connection.
 *
 * If this port connects to a modem, the modem connection must be
 * established before calling this.
 */
LwipStatus
ppp_connect(PppPcb* pcb, uint16_t holdoff)
{
    if (pcb->phase != PPP_PHASE_DEAD)
    {
        return ERR_ALREADY;
    } // PPPDEBUG(LOG_DEBUG, ("ppp_connect[%d]: holdoff=%d\n", pcb->netif->num, holdoff));
    magic_randomize();
    if (holdoff == 0)
    {
        ppp_do_connect(pcb);
        return ERR_OK;
    }
    new_phase(pcb, PPP_PHASE_HOLDOFF);
    sys_timeout_debug((uint32_t)(holdoff * 1000), ppp_do_connect, pcb, "ppp_do_connect");
    return ERR_OK;
} /*
 * Listen for an incoming PPP connection.
 *
 * This can only be called if PPP is in the dead phase.
 *
 * If this port connects to a modem, the modem connection must be
 * established before calling this.
 */
LwipStatus
ppp_listen(PppPcb* pcb)
{
    if (pcb->phase != PPP_PHASE_DEAD)
    {
        return ERR_ALREADY;
    } // PPPDEBUG(LOG_DEBUG, ("ppp_listen[%d]\n", pcb->netif->num));
    magic_randomize();
    if (pcb->link_cb->listen)
    {
        new_phase(pcb, PPP_PHASE_INITIALIZE);
        pcb->link_cb->listen(pcb, (uint8_t*)pcb->link_ctx_cb);
        return ERR_OK;
    }
    return ERR_IF;
} /*
 * Initiate the end of a PPP connection.
 * Any outstanding packets in the queues are dropped.
 *
 * Setting nocarrier to 1 close the PPP connection without initiating the
 * shutdown procedure. Always using nocarrier = 0 is still recommended,
 * this is going to take a little longer time if your link is down, but
 * is a safer choice for the PPP state machine.
 *
 * Return 0 on success, an error code on failure.
 */
LwipStatus
ppp_close(PppPcb* pcb, uint8_t nocarrier)
{
    pcb->err_code = PPPERR_USER; /* holdoff phase, cancel the reconnection */
    if (pcb->phase == PPP_PHASE_HOLDOFF)
    {
        sys_untimeout(ppp_do_connect, pcb);
        new_phase(pcb, PPP_PHASE_DEAD);
    } /* dead phase, nothing to do, call the status callback to be consistent */
    if (pcb->phase == PPP_PHASE_DEAD)
    {
        pcb->link_status_cb(pcb, pcb->err_code, pcb->ctx_cb);
        return ERR_OK;
    } /* Already terminating, nothing to do */
    if (pcb->phase >= PPP_PHASE_TERMINATE)
    {
        return ERR_INPROGRESS;
    } /* LCP not open, close link protocol */
    if (pcb->phase < PPP_PHASE_ESTABLISH)
    {
        new_phase(pcb, PPP_PHASE_DISCONNECT);
        ppp_link_terminated(pcb);
        return ERR_OK;
    } /*
     * Only accept carrier lost signal on the stable running phase in order
     * to prevent changing the PPP phase FSM in transition phases.
     *
     * Always using nocarrier = 0 is still recommended, this is going to
     * take a little longer time, but is a safer choice from FSM point of view.
     */
    if (nocarrier && pcb->phase == PPP_PHASE_RUNNING)
    {
        // PPPDEBUG(LOG_DEBUG, ("ppp_close[%d]: carrier lost -> lcp_lowerdown\n", pcb->netif->num));
        lcp_lowerdown(pcb);
        /* forced link termination, this will force link protocol to disconnect. */
        link_terminated(pcb);
        return ERR_OK;
    } /* Disconnect */
    // PPPDEBUG(LOG_DEBUG, ("ppp_close[%d]: kill_link -> lcp_close\n", pcb->netif->num));
    /* LCP soft close request. */
    lcp_close(pcb, "User request");
    return ERR_OK;
} /*
 * Release the control block.
 *
 * This can only be called if PPP is in the dead phase.
 *
 * You must use ppp_close() before if you wish to terminate
 * an established PPP session.
 *
 * Return 0 on success, an error code on failure.
 */
LwipStatus
ppp_free(PppPcb* pcb)
{
    if (pcb->phase != PPP_PHASE_DEAD)
    {
        return ERR_CONN;
    } // PPPDEBUG(LOG_DEBUG, ("ppp_free[%d]\n", pcb->netif->num));
    netif_remove(pcb->netif);
    LwipStatus err = pcb->link_cb->free(pcb, (uint8_t*)pcb->link_ctx_cb);
    delete pcb; // LWIP_MEMPOOL_FREE(PppPcb, pcb);
    return err;
} /* Get and set parameters for the given connection.
 * Return 0 on success, an error code on failure. */
LwipStatus
ppp_ioctl(PppPcb* pcb, uint8_t cmd, uint8_t* arg)
{
    if (pcb == nullptr)
    {
        return ERR_VAL;
    }
    switch (cmd)
    {
    case PPPCTLG_UPSTATUS: /* Get the PPP up status. */ if (!arg)
        {
            goto fail;
        }
        *(int *)arg = (int)(false || pcb->if4_up || pcb->if6_up);
        return ERR_OK;
    case kPppctlgErrcode: /* Get the PPP error code. */ if (!arg)
        {
            goto fail;
        }
        *(int *)arg = (int)(pcb->err_code);
        return ERR_OK;
    default:
        goto fail;
    }
fail: return ERR_VAL;
} /**********************************/ /*** LOCAL FUNCTION DEFINITIONS ***/
/**********************************/
static void
ppp_do_connect(void* arg)
{
    PppPcb* pcb = (PppPcb*)arg;
    // lwip_assert("pcb->phase == PPP_PHASE_DEAD || pcb->phase == PPP_PHASE_HOLDOFF",
    //             pcb->phase == PPP_PHASE_DEAD || pcb->phase == PPP_PHASE_HOLDOFF);
    new_phase(pcb, PPP_PHASE_INITIALIZE);
    pcb->link_cb->connect(pcb, (uint8_t*)pcb->link_ctx_cb);
} /*
 * ppp_netif_init_cb - netif init callback
 */
static LwipStatus
ppp_netif_init_cb(NetworkInterface* netif)
{
    netif->name[0] = 'p';
    netif->name[1] = 'p';
    netif->output = ppp_netif_output_ip4;
    netif->output_ip6 = ppp_netif_output_ip6;
    netif->flags = NETIF_FLAG_UP; /* @todo: Initialize interface hostname */
    /* netif_set_hostname(netif, "lwip"); */
    return ERR_OK;
} /*
 * Send an IPv4 packet on the given connection.
 */
static LwipStatus
ppp_netif_output_ip4(NetworkInterface* netif,
                     struct PacketBuffer* pb,
                     const Ip4Addr* ipaddr)
{
    return ppp_netif_output(netif, pb, PPP_IP);
} /*
 * Send an IPv6 packet on the given connection.
 */
static LwipStatus
ppp_netif_output_ip6(NetworkInterface* netif,
                     struct PacketBuffer* pb,
                     const Ip6Addr* ipaddr)
{
    return ppp_netif_output(netif, pb, PPP_IPV6);
}

static LwipStatus
ppp_netif_output(NetworkInterface* netif, struct PacketBuffer* pb, uint16_t protocol)
{
    PppPcb* pcb = (PppPcb*)netif->state;
    LwipStatus err;
    struct PacketBuffer* fpb = nullptr; /* Check that the link is up. */
    if (false || (protocol == PPP_IP && !pcb->if4_up) || (protocol == PPP_IPV6 && !pcb->if6_up
    ))
    {
        // PPPDEBUG(LOG_ERR, ("ppp_netif_output[%d]: link not up\n", pcb->netif->num));
        goto err_rte_drop;
    } /* If MPPE is required, refuse any IP packet until we are able to crypt them. */
    if (pcb->settings.require_mppe && pcb->ccp_transmit_method != CI_MPPE)
    {
        // PPPDEBUG(LOG_ERR, ("ppp_netif_output[%d]: MPPE required, not up\n", pcb->netif->num));
        goto err_rte_drop;
    } /*
     * Attempt Van Jacobson header compression if VJ is configured and
     * this is an IP packet.
     */
    if (protocol == PPP_IP && pcb->vj_enabled)
    {
        switch (vj_compress_tcp(&pcb->vj_comp, &pb))
        {
        case TYPE_IP: /* No change...
               protocol = PPP_IP; */ break;
        case TYPE_COMPRESSED_TCP:
            /* vj_compress_tcp() returns a new allocated PacketBuffer, indicate we should free
                                   * our duplicated PacketBuffer later */ fpb = pb;
            protocol = PPP_VJC_COMP;
            break;
        case TYPE_UNCOMPRESSED_TCP:
            /* vj_compress_tcp() returns a new allocated PacketBuffer, indicate we should free
                                   * our duplicated PacketBuffer later */ fpb = pb;
            protocol = PPP_VJC_UNCOMP;
            break;
        default:
            // PPPDEBUG(LOG_WARNING, ("ppp_netif_output[%d]: bad IP packet\n", pcb->netif->num));
            // LINK_STATS_INC(link.proterr);
            // LINK_STATS_INC(link.drop);
            // MIB2_STATS_NETIF_INC(pcb->netif, ifoutdiscards);
            return ERR_VAL;
        }
    }
    switch (pcb->ccp_transmit_method)
    {
    case 0:
        break; /* Don't compress */
    case CI_MPPE:
        if ((err = mppe_compress(pcb, &pcb->mppe_comp, &pb, protocol)) != ERR_OK)
        {
            // LINK_STATS_INC(link.memerr);
            // LINK_STATS_INC(link.drop);
            // MIB2_STATS_NETIF_INC(netif, ifoutdiscards);
            goto err;
        } /* if VJ compressor returned a new allocated PacketBuffer, free it */
        if (fpb)
        {
            free_pkt_buf(fpb);
        } /* mppe_compress() returns a new allocated PacketBuffer, indicate we should free
         * our duplicated PacketBuffer later */
        fpb = pb;
        protocol = PPP_COMP;
        break;
    default:
        // PPPDEBUG(LOG_ERR, ("ppp_netif_output[%d]: bad CCP transmit method\n", pcb->netif->num));
        goto err_rte_drop;
        /* Cannot really happen, we only negotiate what we are able to do */
    }
    err = pcb->link_cb->netif_output(pcb, (uint8_t*)pcb->link_ctx_cb, pb, protocol);
    goto err;
err_rte_drop: err = ERR_RTE; // LINK_STATS_INC(link.rterr);
    // LINK_STATS_INC(link.drop);
    // MIB2_STATS_NETIF_INC(netif, ifoutdiscards);
err: if (fpb)
    {
        free_pkt_buf(fpb);
    }
    return err;
} /************************************/ /*** PRIVATE FUNCTION DEFINITIONS ***/
/************************************/ /* Initialize the PPP subsystem. */
int
init_ppp_subsys()
{
    // LWIP_MEMPOOL_INIT(PppPcb);
    /*
     * Initialize magic number generator now so that protocols may
     * use magic numbers in initialization.
     */
    magic_init();
    return 0;
} //
// Create a new PPP control block.
//
// This initializes the PPP control block but does not
// attempt to negotiate the LCP session.
//
// Return a new PPP connection control block pointer
// on success or a null pointer on failure.
//
PppPcb*
init_ppp_pcb(NetworkInterface* pppif,
             void* link_ctx_cb,
             const ppp_link_status_cb_fn link_status_cb,
             void* ctx_cb)
{
    const struct Protent* protp; /* PPP is single-threaded: without a callback,
     * there is no way to know when the link is up. */
    if (link_status_cb == nullptr)
    {
        return nullptr;
    } // pcb = (PppPcb*)LWIP_MEMPOOL_ALLOC(PppPcb);
    const auto pcb = new PppPcb;
    if (pcb == nullptr)
    {
        return nullptr;
    }
    memset(pcb, 0, sizeof(PppPcb)); /* default configuration */
    pcb->settings.pap_timeout_time = UPAP_DEFTIMEOUT;
    pcb->settings.pap_max_transmits = UPAP_DEFTRANSMITS;
    pcb->settings.pap_req_timeout = UPAP_DEFREQTIME;
    pcb->settings.chap_timeout_time = CHAP_DEFTIMEOUT;
    pcb->settings.chap_max_transmits = CHAP_DEFTRANSMITS;
    pcb->settings.chap_rechallenge_time = CHAP_DEFRECHALLENGETIME;
    pcb->settings.eap_req_time = EAP_DEFREQTIME;
    pcb->settings.eap_allow_req = EAP_DEFALLOWREQ;
    pcb->settings.eap_timeout_time = EAP_DEFTIMEOUT;
    pcb->settings.eap_max_transmits = EAP_DEFTRANSMITS;
    pcb->settings.lcp_loopbackfail = LCP_DEFLOOPBACKFAIL;
    pcb->settings.lcp_echo_interval = LCP_ECHOINTERVAL;
    pcb->settings.lcp_echo_fails = LCP_MAXECHOFAILS;
    pcb->settings.fsm_timeout_time = FSM_DEFTIMEOUT;
    pcb->settings.fsm_max_conf_req_transmits = FSM_DEFMAXCONFREQS;
    pcb->settings.fsm_max_term_transmits = FSM_DEFMAXTERMREQS;
    pcb->settings.fsm_max_nak_loops = FSM_DEFMAXNAKLOOPS;
    pcb->netif = pppif;
    Ip4Addr ip4_any = create_ip4_addr_any();
    Ip4Addr ip4_bcast = ip4_addr_bcast();
    if (!netif_add(pcb->netif,
                   &ip4_any,
                   &ip4_bcast,
                   &ip4_any,
                   reinterpret_cast<uint8_t *>(pcb),
                   ppp_netif_init_cb,
                   nullptr))
    {
        delete pcb;
        return nullptr;
    } //pcb->link_cb = callbacks;
    // TODO: consider implementing "copy callbacks" fn
    // pcb->link_cb->connect = callbacks->connect;
    // pcb->link_cb->listen = callbacks->listen;
    // pcb->link_cb->disconnect = callbacks->listen;
    // pcb->link_cb->free = callbacks->free;
    // pcb->link_cb->write = callbacks->write;
    // pcb->link_cb->netif_output = callbacks->netif_output;
    // pcb->link_cb->send_config = callbacks->send_config;
    // pcb->link_cb->recv_config = callbacks->recv_config;
    // pcb->link_ctx_cb = link_ctx_cb;
    // pcb->link_status_cb = link_status_cb;
    pcb->ctx_cb = ctx_cb; //
    // Initialize each protocol.
    // TODO: call init for protocols
    // for (auto i = 0; (protp = kProtocols[i]) != nullptr; ++i)
    // {
    //     (*protp->init)(pcb);
    // }
    new_phase(pcb, PPP_PHASE_DEAD);
    return pcb;
} /** Initiate LCP open request */
void
ppp_start(PppPcb* pcb)
{
    // PPPDEBUG(LOG_DEBUG, ("ppp_start[%d]\n", pcb->netif->num));
    /* Clean data not taken care by anything else, mostly shared data. */
    // link_stats_valid = 0;
    pcb->mppe_keys_set = false;
    memset(&pcb->mppe_comp, 0, sizeof(pcb->mppe_comp));
    memset(&pcb->mppe_decomp, 0, sizeof(pcb->mppe_decomp));
    vj_compress_init(&pcb->vj_comp); /* Start protocol */
    new_phase(pcb, PPP_PHASE_ESTABLISH);
    lcp_open(pcb);
    lcp_lowerup(pcb);
    // PPPDEBUG(LOG_DEBUG, ("ppp_start[%d]: finished\n", pcb->netif->num));
} /** Called when link failed to setup */
void
ppp_link_failed(PppPcb* pcb)
{
    // PPPDEBUG(LOG_DEBUG, ("ppp_link_failed[%d]\n", pcb->netif->num));
    new_phase(pcb, PPP_PHASE_DEAD);
    pcb->err_code = PPPERR_OPEN;
    pcb->link_status_cb(pcb, pcb->err_code, pcb->ctx_cb);
} /** Called when link is normally down (i.e. it was asked to end) */
void
ppp_link_end(PppPcb* pcb)
{
    // PPPDEBUG(LOG_DEBUG, ("ppp_link_end[%d]\n", pcb->netif->num));
    new_phase(pcb, PPP_PHASE_DEAD);
    if (pcb->err_code == PPPERR_NONE)
    {
        pcb->err_code = PPPERR_CONNECT;
    }
    pcb->link_status_cb(pcb, pcb->err_code, pcb->ctx_cb);
} /*
 * Pass the processed input packet to the appropriate handler.
 * This function and all handlers run in the context of the tcpip_thread
 */
bool
ppp_input(PppPcb* pcb, struct PacketBuffer* pb, Fsm* lcp_fsm)
{
    magic_randomize();
    if (pb->len < 2)
    {
        free_pkt_buf(pb);
        return false;
    }
    const auto pb_payload_0 = uint8_t(static_cast<uint8_t*>(pb->payload)[0]);
    const auto pb_payload_1 = uint8_t(static_cast<uint8_t*>(pb->payload)[1]);
    uint16_t protocol = uint16_t(pb_payload_0) << 8 | uint16_t(pb_payload_1);
    const size_t proto_size = 2; // sizeof(protocol)
    pbuf_remove_header(pb, proto_size);
    if (pb->len < 2)
    {
        free_pkt_buf(pb);
        return false;
    } // protocol = (static_cast<uint8_t *>(pb->payload)[0] << 8) | static_cast<uint8_t*>(pb->payload)[1];
    pbuf_remove_header(pb, proto_size);
    if (protocol == PPP_COMP)
    {
        if (protocol != PPP_LCP && lcp_fsm->state != PPP_FSM_OPENED)
        {
            ppp_dbglog("Discarded non-LCP packet when LCP not open");
            free_pkt_buf(pb);
            return false;
        } /// Until we get past the authentication phase, toss all packets except LCP, LQR and authentication packets.
        if (pcb->phase <= PPP_PHASE_AUTHENTICATE && !(protocol == PPP_LCP || protocol ==
                PPP_LQR || protocol == PPP_PAP || protocol == PPP_CHAP || protocol ==
                PPP_EAP)
        )
        {
            ppp_dbglog("discarding proto 0x%x in phase %d", protocol, pcb->phase);
            free_pkt_buf(pb);
            return false;
        } /// Extract and hide protocol (do PFC decompression if necessary)
        uint8_t* pl = static_cast<uint8_t*>(pb->payload);
        if (pl[0] & 0x01)
        {
            protocol = pl[0];
            pbuf_remove_header(pb, 1);
        }
        else
        {
            protocol = (pl[0] << 8) | pl[1];
            pbuf_remove_header(pb, 2);
        }
        if (protocol == PPP_COMP)
        {
            if (pcb->ccp_receive_method == CI_MPPE)
            {
                if (mppe_decompress(pcb, &pcb->mppe_decomp, &pb) != ERR_OK)
                {
                    free_pkt_buf(pb);
                    return false;
                }
            }
            else
            {
                // PPPDEBUG(LOG_ERR, ("ppp_input[%d]: bad CCP receive method\n", pcb->netif->num));
                free_pkt_buf(pb);
                return false;
                /// Cannot really happen, we only negotiate what we are able to do
            }
            /// Assume no PFC
            if (pb->len < 2)
            {
                free_pkt_buf(pb);
                return false;
            }
            /// Extract and hide protocol (do PFC decompression if necessary)
            pl = static_cast<uint8_t*>(pb->payload);
            if (pl[0] & 0x01)
            {
                protocol = pl[0];
                pbuf_remove_header(pb, 1);
            }
            else
            {
                protocol = (pl[0] << 8) | pl[1];
                pbuf_remove_header(pb, 2);
            }
        }
        if (protocol == PPP_IP)
        {
            ip4_input(pb, pcb->netif);
            free_pkt_buf(pb);
            return false;
        }
        if (protocol == PPP_IPV6)
        {
            ip6_input(pb, pcb->netif);
            free_pkt_buf(pb);
            return false;
        }
        if (protocol == PPP_VJC_UNCOMP)
        {
            if (pcb->vj_enabled && vj_uncompress_uncomp(pb, &pcb->vj_comp) >= 0)
            {
                ip4_input(pb, pcb->netif);
                return false;
            }
            const char* pname = protocol_name(protocol);
            if (pname != nullptr)
            {
                ppp_warn("Unsupported protocol '%s' (0x%x) received", pname, protocol);
            }
            else
            {
                ppp_warn("Unsupported protocol 0x%x received", protocol);
            }
            if (pbuf_add_header(pb, sizeof(protocol)))
            {
                // PPPDEBUG(LOG_WARNING, ("ppp_input[%d]: Dropping (pbuf_add_header failed)\n", pcb->netif->num));
                free_pkt_buf(pb);
                return false;
            }
            lcp_sprotrej(pcb, static_cast<uint8_t*>(pb->payload), pb->len);
        }
    }
    free_pkt_buf(pb);
    return true;
}


/*
 * Write a PacketBuffer to a ppp link, only used from PPP functions
 * to send PPP packets.
 *
 * IPv4 and IPv6 packets from lwIP are sent, respectively,
 * with ppp_netif_output_ip4() and ppp_netif_output_ip6()
 * functions (which are callbacks of the netif PPP interface).
 */
LwipStatus
ppp_write(PppPcb* pcb, struct PacketBuffer* p)
{
    return pcb->link_cb->write(pcb, pcb->link_ctx_cb, p);
}

void
ppp_link_terminated(PppPcb* pcb)
{
    // PPPDEBUG(LOG_DEBUG, ("ppp_link_terminated[%d]\n", pcb->netif->num));
    pcb->link_cb->disconnect(pcb, pcb->link_ctx_cb);
    // PPPDEBUG(LOG_DEBUG, ("ppp_link_terminated[%d]: finished.\n", pcb->netif->num));
} /************************************************************************
 * Functions called by various PPP subsystems to configure
 * the PPP interface or change the PPP phase.
 */ /*
 * new_phase - signal the start of a new phase of pppd's operation.
 */
void
new_phase(PppPcb* pcb, int p)
{
    pcb->phase = p;
    // PPPDEBUG(LOG_DEBUG, ("ppp phase changed[%d]: phase=%d\n", pcb->netif->num, pcb->phase));
    if (pcb->notify_phase_cb != nullptr)
    {
        pcb->notify_phase_cb(pcb, p, pcb->ctx_cb);
    }
} /*
 * ppp_send_config - configure the transmit-side characteristics of
 * the ppp interface.
 */
int
ppp_send_config(PppPcb* pcb, int mtu, uint32_t accm, int pcomp, int accomp)
{
    if (pcb->link_cb->send_config)
    {
        pcb->link_cb->send_config(pcb, pcb->link_ctx_cb, accm, pcomp, accomp);
    } // PPPDEBUG(LOG_INFO, ("ppp_send_config[%d]\n", pcb->netif->num) );
    return 0;
} /*
 * ppp_recv_config - configure the receive-side characteristics of
 * the ppp interface.
 */
int
ppp_recv_config(PppPcb* pcb, int mru, uint32_t accm, int pcomp, int accomp)
{
    if (pcb->link_cb->recv_config)
    {
        pcb->link_cb->recv_config(pcb, pcb->link_ctx_cb, accm, pcomp, accomp);
    } // PPPDEBUG(LOG_INFO, ("ppp_recv_config[%d]\n", pcb->netif->num));
    return 0;
} /*
 * sifaddr - Config the interface IP addresses and netmask.
 */
int
sifaddr(PppPcb* pcb, const uint32_t our_adr, const uint32_t his_adr, const uint32_t netmask)
{
    Ip4Addr ip{};
    Ip4Addr nm{};
    Ip4Addr gw{};
    set_ip4_addr_u32(&ip, our_adr);
    set_ip4_addr_u32(&nm, netmask);
    set_ip4_addr_u32(&gw, his_adr);
    netif_set_addr(pcb->netif, &ip, &nm, &gw);
    return 1;
}




/********************************************************************
 *
 * cifaddr - Clear the interface IP addresses, and delete routes
 * through the interface if possible.
 */
int
cifaddr(PppPcb* pcb, uint32_t our_adr, uint32_t his_adr)
{
    auto bcast_addr = create_ip_addr_ip4_bcast();
    auto ip_addr = create_ip_addr_ip4_any();
    auto gw = create_ip_addr_ip4_any();
    netif_set_addr(pcb->netif, &ip_addr.u_addr.ip4, &bcast_addr.u_addr.ip4, &gw.u_addr.ip4);
    return 1;
} /*
 * sdns - Config the DNS servers
 */
int
sdns(PppPcb* pcb, uint32_t ns1, uint32_t ns2)
{
    IpAddr ns{};
    set_ip_addr_ip4_u32_val(ns, ns1);
    dns_setserver(0, &ns);
    set_ip_addr_ip4_u32_val(ns, ns2);
    dns_setserver(1, &ns);
    return 1;
} /********************************************************************
 *
 * cdns - Clear the DNS servers
 */
int
cdns(PppPcb* pcb, uint32_t ns1, uint32_t ns2)
{
    IpAddr nsa;
    IpAddr nsb;
    auto any_addr = make_ip_addr_any();
    nsa = dns_getserver(0);
    set_ip_addr_ip4_u32_val(nsb, ns1);
    if (compare_ip_addr(&nsa, &nsb))
    {
        dns_setserver(0, &any_addr);
    }
    nsa = dns_getserver(1);
    set_ip_addr_ip4_u32_val(nsb, ns2);
    if (compare_ip_addr(&nsa, &nsb))
    {
        dns_setserver(1, &any_addr);
    }
    return 1;
} /********************************************************************
 *
 * sifvjcomp - config tcp header compression
 */
int
sifvjcomp(PppPcb* pcb, int vjcomp, int cidcomp, int maxcid)
{
    pcb->vj_enabled = vjcomp;
    pcb->vj_comp.compress_slot = cidcomp;
    pcb->vj_comp.max_slot_index = maxcid; // PPPDEBUG(LOG_INFO,
    //          ("sifvjcomp[%d]: VJ compress enable=%d slot=%d max slot=%d\n",
    //              pcb->netif->num, vjcomp, cidcomp, maxcid));
    return 0;
} /*
 * sifup - Config the interface up and enable IP packets to pass.
 */
int
sifup(PppPcb* pcb)
{
    pcb->if4_up = true;
    pcb->err_code = PPPERR_NONE;
    netif_set_link_up(pcb->netif);
    // PPPDEBUG(LOG_DEBUG, ("sifup[%d]: err_code=%d\n", pcb->netif->num, pcb->err_code));
    pcb->link_status_cb(pcb, pcb->err_code, pcb->ctx_cb);
    return 1;
} /********************************************************************
 *
 * sifdown - Disable the indicated protocol and config the interface
 *           down if there are no remaining protocols.
 */
int
sifdown(PppPcb* pcb)
{
    pcb->if4_up = false;
    if (true /* set the interface down if IPv6 is down as well */ && !pcb->if6_up)
    {
        /* make sure the netif link callback is called */
        netif_set_link_down(pcb->netif);
    } // PPPDEBUG(LOG_DEBUG, ("sifdown[%d]: err_code=%d\n", pcb->netif->num, pcb->err_code));
    return 1;
} /********************************************************************
 *
 * Return user specified netmask, modified by any mask we might determine
 * for address `addr' (in network byte order).
 * Here we scan through the system's list of interfaces, looking for
 * any non-point-to-point interfaces which might appear to be on the same
 * network as `addr'.  If we find any, we OR in their netmask to the
 * user-specified netmask.
 */
uint32_t
get_mask(uint32_t addr)
{
    return IP4_ADDR_BCAST;
}

inline void
IN6_LLADDR_FROM_EUI64(Ip6Addr* ip6, Eui64* eui64)
{
    ip6->addr[0] = pp_htonl(0xfe800000);
    ip6->addr[1] = 0;
    eui64_copy(eui64, (Eui64*)&ip6->addr[2]);
} /********************************************************************
 *
 * sif6addr - Config the interface with an IPv6 link-local address
 */
int
sif6addr(PppPcb* pcb, Eui64 our_eui64, Eui64 his_eui64)
{
    Ip6Addr ip6{};
    IN6_LLADDR_FROM_EUI64(&ip6, &our_eui64);
    netif_ip6_addr_set(pcb->netif, 0, &ip6);
    netif_ip6_addr_set_state(pcb->netif, 0, IP6_ADDR_PREFERRED);
    /* FIXME: should we add an IPv6 static neighbor using his_eui64 ? */
    return 1;
} /********************************************************************
 *
 * cif6addr - Remove IPv6 address from interface
 */
int
cif6addr(PppPcb* pcb, Eui64 our_eui64, Eui64 his_eui64)
{
    auto any_addr = make_ip_addr_ip6_any();
    netif_ip6_addr_set_state(pcb->netif, 0, IP6_ADDR_INVALID);
    netif_ip6_addr_set(pcb->netif, 0, &any_addr.u_addr.ip6);
    return 1;
} /*
 * sif6up - Config the interface up and enable IPv6 packets to pass.
 */
int
sif6up(PppPcb* pcb)
{
    pcb->if6_up = true;
    pcb->err_code = PPPERR_NONE;
    netif_set_link_up(pcb->netif);
    // PPPDEBUG(LOG_DEBUG, ("sif6up[%d]: err_code=%d\n", pcb->netif->num, pcb->err_code));
    pcb->link_status_cb(pcb, pcb->err_code, pcb->ctx_cb);
    return 1;
} /********************************************************************
 *
 * sif6down - Disable the indicated protocol and config the interface
 *            down if there are no remaining protocols.
 */
int
sif6down(PppPcb* pcb)
{
    pcb->if6_up = false;
    if (true /* set the interface down if IPv4 is down as well */ && !pcb->if4_up)
    {
        /* make sure the netif link callback is called */
        netif_set_link_down(pcb->netif);
    } // PPPDEBUG(LOG_DEBUG, ("sif6down[%d]: err_code=%d\n", pcb->netif->num, pcb->err_code));
    return 1;
} /*
 * sifnpmode - Set the mode for handling packets for a given NP.
 */
int
sifnpmode(PppPcb* pcb, int proto, enum PppNetworkProtoMode mode)
{
    return 0;
} /*
 * netif_set_mtu - set the MTU on the PPP network interface.
 */
void
netif_set_mtu(PppPcb* pcb, int mtu)
{
    pcb->netif->mtu = mtu;
    // PPPDEBUG(LOG_INFO, ("netif_set_mtu[%d]: mtu=%d\n", pcb->netif->num, mtu));
} /*
 * netif_get_mtu - get PPP interface MTU
 */
int
netif_get_mtu(PppPcb* pcb)
{
    return pcb->netif->mtu;
} /*
 * ccp_set - inform about the current state of CCP.
 */
void
ccp_set(PppPcb* pcb,
        uint8_t isopen,
        uint8_t isup,
        uint8_t receive_method,
        uint8_t transmit_method)
{
    pcb->ccp_receive_method = receive_method;
    pcb->ccp_transmit_method = transmit_method; // PPPDEBUG(LOG_DEBUG,
    //          ("ccp_set[%d]: is_open=%d, is_up=%d, receive_method=%u, transmit_method=%u\n",
    //              pcb->netif->num, isopen, isup, receive_method, transmit_method));
} /********************************************************************
 *
 * get_idle_time - return how long the link has been idle.
 */
int
get_idle_time(PppPcb* pcb, struct ppp_idle* ip)
{
    return 1;
} /********************************************************************
 *
 * get_loop_output - get outgoing packets from the ppp device,
 * and detect when we want to bring the real link up.
 * Return value is 1 if we need to bring up the link, 0 otherwise.
 */
int
get_loop_output(void)
{
    return 0;
} /* List of protocol names, to make our messages a little more informative. */
struct protocol_list
{
    u_short proto;
    const char* name;
} const protocol_list[] = {
    {0x21, "IP"}, {0x23, "OSI Network Layer"}, {0x25, "Xerox NS IDP"},
    {0x27, "DECnet Phase IV"}, {0x29, "Appletalk"}, {0x2b, "Novell IPX"},
    {0x2d, "VJ compressed TCP/IP"}, {0x2f, "VJ uncompressed TCP/IP"},
    {0x31, "Bridging PDU"}, {0x33, "Stream Protocol ST-II"}, {0x35, "Banyan Vines"},
    {0x39, "AppleTalk EDDP"}, {0x3b, "AppleTalk SmartBuffered"}, {0x3d, "Multi-Link"},
    {0x3f, "NETBIOS Framing"}, {0x41, "Cisco Systems"}, {0x43, "Ascom Timeplex"},
    {0x45, "Fujitsu Link Backup and Load Balancing (LBLB)"}, {0x47, "DCA Remote Lan"},
    {0x49, "Serial Data Transport Protocol (PPP-SDTP)"}, {0x4b, "SNA over 802.2"},
    {0x4d, "SNA"}, {0x4f, "IP6 Header Compression"}, {0x51, "KNX Bridging Data"},
    {0x53, "Encryption"}, {0x55, "Individual Link Encryption"}, {0x57, "IPv6"},
    {0x59, "PPP Muxing"}, {0x5b, "Vendor-Specific Network Protocol"},
    {0x61, "RTP IPHC Full Header"}, {0x63, "RTP IPHC Compressed TCP"},
    {0x65, "RTP IPHC Compressed non-TCP"}, {0x67, "RTP IPHC Compressed UDP 8"},
    {0x69, "RTP IPHC Compressed RTP 8"}, {0x6f, "Stampede Bridging"}, {0x73, "MP+"},
    {0xc1, "NTCITS IPI"}, {0xfb, "single-link compression"},
    {0xfd, "Compressed Datagram"}, {0x0201, "802.1d Hello Packets"},
    {0x0203, "IBM Source Routing BPDU"}, {0x0205, "DEC LANBridge100 Spanning Tree"},
    {0x0207, "Cisco Discovery Protocol"}, {0x0209, "Netcs Twin Routing"},
    {0x020b, "STP - Scheduled Transfer Protocol"},
    {0x020d, "EDP - Extreme Discovery Protocol"},
    {0x0211, "Optical Supervisory Channel Protocol"},
    {0x0213, "Optical Supervisory Channel Protocol"}, {0x0231, "Luxcom"},
    {0x0233, "Sigma Network Systems"}, {0x0235, "Apple Client Server Protocol"},
    {0x0281, "MPLS Unicast"}, {0x0283, "MPLS Multicast"},
    {0x0285, "IEEE p1284.4 standard - data packets"},
    {0x0287, "ETSI TETRA Network Protocol Type 1"},
    {0x0289, "Multichannel Flow Treatment Protocol"},
    {0x2063, "RTP IPHC Compressed TCP No Delta"}, {0x2065, "RTP IPHC Context State"},
    {0x2067, "RTP IPHC Compressed UDP 16"}, {0x2069, "RTP IPHC Compressed RTP 16"},
    {0x4001, "Cray Communications Control Protocol"},
    {0x4003, "CDPD Mobile Network Registration Protocol"},
    {0x4005, "Expand accelerator protocol"}, {0x4007, "ODSICP NCP"},
    {0x4009, "DOCSIS DLL"}, {0x400B, "Cetacean Network Detection Protocol"},
    {0x4021, "Stacker LZS"}, {0x4023, "RefTek Protocol"}, {0x4025, "Fibre Channel"},
    {0x4027, "EMIT Protocols"}, {0x405b, "Vendor-Specific Protocol (VSP)"},
    {0x8021, "Internet Protocol Control Protocol"},
    {0x8023, "OSI Network Layer Control Protocol"},
    {0x8025, "Xerox NS IDP Control Protocol"},
    {0x8027, "DECnet Phase IV Control Protocol"}, {0x8029, "Appletalk Control Protocol"},
    {0x802b, "Novell IPX Control Protocol"}, {0x8031, "Bridging NCP"},
    {0x8033, "Stream Protocol Control Protocol"},
    {0x8035, "Banyan Vines Control Protocol"}, {0x803d, "Multi-Link Control Protocol"},
    {0x803f, "NETBIOS Framing Control Protocol"},
    {0x8041, "Cisco Systems Control Protocol"}, {0x8043, "Ascom Timeplex"},
    {0x8045, "Fujitsu LBLB Control Protocol"},
    {0x8047, "DCA Remote Lan Network Control Protocol (RLNCP)"},
    {0x8049, "Serial Data Control Protocol (PPP-SDCP)"},
    {0x804b, "SNA over 802.2 Control Protocol"}, {0x804d, "SNA Control Protocol"},
    {0x804f, "IP6 Header Compression Control Protocol"},
    {0x8051, "KNX Bridging Control Protocol"}, {0x8053, "Encryption Control Protocol"},
    {0x8055, "Individual Link Encryption Control Protocol"},
    {0x8057, "IPv6 Control Protocol"}, {0x8059, "PPP Muxing Control Protocol"},
    {0x805b, "Vendor-Specific Network Control Protocol (VSNCP)"},
    {0x806f, "Stampede Bridging Control Protocol"}, {0x8073, "MP+ Control Protocol"},
    {0x80c1, "NTCITS IPI Control Protocol"},
    {0x80fb, "Single Link Compression Control Protocol"},
    {0x80fd, "Compression Control Protocol"},
    {0x8207, "Cisco Discovery Protocol Control"}, {0x8209, "Netcs Twin Routing"},
    {0x820b, "STP - Control Protocol"},
    {0x820d, "EDPCP - Extreme Discovery Protocol Ctrl Prtcl"},
    {0x8235, "Apple Client Server Protocol Control"}, {0x8281, "MPLSCP"},
    {0x8285, "IEEE p1284.4 standard - Protocol Control"},
    {0x8287, "ETSI TETRA TNP1 Control Protocol"},
    {0x8289, "Multichannel Flow Treatment Protocol"}, {0xc021, "Link Control Protocol"},
    {0xc023, "Password Authentication Protocol"}, {0xc025, "Link Quality Report"},
    {0xc027, "Shiva Password Authentication Protocol"},
    {0xc029, "CallBack Control Protocol (CBCP)"},
    {0xc02b, "BACP Bandwidth Allocation Control Protocol"}, {0xc02d, "BAP"},
    {0xc05b, "Vendor-Specific Authentication Protocol (VSAP)"},
    {0xc081, "Container Control Protocol"},
    {0xc223, "Challenge Handshake Authentication Protocol"},
    {0xc225, "RSA Authentication Protocol"},
    {0xc227, "Extensible Authentication Protocol"},
    {0xc229, "Mitsubishi Security Info Exch Ptcl (SIEP)"},
    {0xc26f, "Stampede Bridging Authorization Protocol"},
    {0xc281, "Proprietary Authentication Protocol"},
    {0xc283, "Proprietary Authentication Protocol"},
    {0xc481, "Proprietary Node ID Authentication Protocol"}, {0, nullptr},
}; /*
 * protocol_name - find a name for a PPP protocol.
 */
const char*
protocol_name(int proto)
{
    for (const struct protocol_list* lp = protocol_list; lp->proto != 0; ++lp)
    {
        if (proto == lp->proto)
        {
            return lp->name;
        }
    }
    return nullptr;
}
