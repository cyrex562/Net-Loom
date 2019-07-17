/*****************************************************************************
* ppp.h - Network Point to Point Protocol header file.
*
* Copyright (c) 2003 by Marc Boucher, Services Informatiques (MBSI) inc.
* portions Copyright (c) 1997 Global Election Systems Inc.
*
* The authors hereby grant permission to use, copy, modify, distribute,
* and license this software and its documentation for any purpose, provided
* that existing copyright notices are retained in all copies and that this
* notice and the following disclaimer are included verbatim in any 
* distributions. No written agreement, license, or royalty fee is required
* for any of the authorized uses.
*
* THIS SOFTWARE IS PROVIDED BY THE CONTRIBUTORS *AS IS* AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
* IN NO EVENT SHALL THE CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
* THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
******************************************************************************
* REVISION HISTORY
*
* 03-01-01 Marc Boucher <marc@mbsi.ca>
*   Ported to lwIP.
* 97-11-05 Guy Lancaster <glanca@gesn.com>, Global Election Systems Inc.
*   Original derived from BSD codes.
*****************************************************************************/
#pragma once
#include "netif.h"
#include "ccp.h"
#include "ip6_addr.h"
#include "mppe.h"
#include "ipv6cp.h"
#include "vj.h"
#include "chap_new.h"
#include "ip4_addr.h"
#include "fsm.h"
#include "lcp.h"
#include "ipcp.h"
#include "eap_state.h"
#include "upap.h"


#ifdef __cplusplus
extern "C" 
{
#endif

// Values for phase.
enum PppPhase
{
    PPP_PHASE_DEAD = 0,
    PPP_PHASE_MASTER = 1,
    PPP_PHASE_HOLDOFF = 2,
    PPP_PHASE_INITIALIZE = 3,
    PPP_PHASE_SERIALCONN = 4,
    PPP_PHASE_DORMANT = 5,
    PPP_PHASE_ESTABLISH = 6,
    PPP_PHASE_AUTHENTICATE = 7,
    PPP_PHASE_CALLBACK = 8,
    PPP_PHASE_NETWORK = 9,
    PPP_PHASE_RUNNING = 10,
    PPP_PHASE_TERMINATE = 11,
    PPP_PHASE_DISCONNECT = 12
};


// Error codes. 
enum PppErrorCode
{
    PPPERR_NONE = 0,
    /* No error. */
    PPPERR_PARAM = 1,
    /* Invalid parameter. */
    PPPERR_OPEN = 2,
    /* Unable to open PPP session. */
    PPPERR_DEVICE = 3,
    /* Invalid I/O device for PPP. */
    PPPERR_ALLOC = 4,
    /* Unable to allocate resources. */
    PPPERR_USER = 5,
    /* User interrupt. */
    PPPERR_CONNECT = 6,
    /* Connection lost. */
    PPPERR_AUTHFAIL = 7,
    /* Failed authentication challenge. */
    PPPERR_PROTOCOL = 8,
    /* Failed to meet protocol. */
    PPPERR_PEERDEAD = 9,
    /* Connection timeout */
    PPPERR_IDLETIMEOUT = 10,
    /* Idle Timeout */
    PPPERR_CONNECTTIME = 11,
    /* Max connect time reached */
    PPPERR_LOOPBACK = 12,
    /* Loopback detected */
};


/************************
*** PUBLIC DATA TYPES ***
************************/

/*
 * Other headers require PppPcb definition for prototypes, but PppPcb
 * require some structure definition from other headers as well, we are
 * fixing the dependency loop here by declaring the PppPcb type then
 * by including headers containing necessary struct definition for PppPcb
 */
struct PppPcb;



/* Link status callback function prototype */
typedef void (*ppp_link_status_cb_fn)(PppPcb *pcb, int err_code, void *ctx);

/*
 * PPP configuration.
 */
struct PppSettings
{
    bool auth_required; // Peer is required to authenticate */
    bool null_login; // Username of "" and a password of "" are acceptable 
    bool explicit_remote; // remote_name specified with remotename opt */
    bool refuse_pap; // Don't proceed auth. with PAP */
    bool refuse_chap; // Don't proceed auth. with CHAP */
    bool refuse_mschap; //Don't proceed auth. with MS-CHAP */
    bool refuse_mschap_v2; // Don't proceed auth. with MS-CHAPv2 */
    bool refuse_eap; // Don't proceed auth. with EAP */
    bool usepeerdns; // Ask peer for DNS adds */
    bool persist; // Persist mode, always try to open the connection */
    bool hide_password; // Hide password in dumped packets */
    bool noremoteip; // Let him have no IP address */
    bool lax_recv; // accept control chars in asyncmap */
    bool noendpoint; // don't send/accept endpoint discriminator */
    bool lcp_echo_adaptive; // request echo only if the link was idle */
    bool require_mppe; // Require MPPE (Microsoft Point to Point Encryption) 
    bool refuse_mppe_40; // Allow MPPE 40-bit mode? */
    bool refuse_mppe_128; // Allow MPPE 128-bit mode? */
    bool refuse_mppe_stateful; // Allow MPPE stateful mode? */
    uint64_t listen_time;
    // time to listen first (ms), waiting for peer to send LCP packet */
    uint64_t idle_time_limit; /* Disconnect if idle for this many seconds */
    uint64_t maxconnect; /* Maximum connect time (seconds) */ /* auth data */
    char user[0xff]; /* Username for PAP */
    char passwd[0xff]; /* Password for PAP, secret for CHAP */
    char remote_name[0xff]; /* Peer's name for authentication */
    uint64_t pap_timeout_time; /* Timeout (seconds) for auth-req retrans. */
    uint32_t pap_max_transmits; /* Number of auth-reqs sent */
    uint64_t pap_req_timeout; /* Time to wait for auth-req from peer */
    uint64_t chap_timeout_time; /* Timeout (seconds) for retransmitting req */
    uint32_t chap_max_transmits; /* max # times to send challenge */
    uint64_t chap_rechallenge_time; /* Time to wait for auth-req from peer */
    uint64_t eap_req_time; /* Time to wait (for retransmit/fail) */
    uint32_t eap_allow_req; /* Max Requests allowed */
    uint64_t eap_timeout_time; /* Time to wait (for retransmit/fail) */
    uint32_t eap_max_transmits; /* Max Requests allowed */
    uint64_t fsm_timeout_time; /* Timeout time in seconds */
    uint32_t fsm_max_conf_req_transmits; /* Maximum Configure-Request transmissions */
    uint32_t fsm_max_term_transmits; /* Maximum Terminate-Request transmissions */
    uint32_t fsm_max_nak_loops; /* Maximum number of nak loops tolerated */
    uint32_t lcp_loopbackfail;
    /* Number of times we receive our magic number from the peer
                                    before deciding the link is looped-back. */
    uint64_t lcp_echo_interval; /* Interval between LCP echo-requests */
    uint32_t lcp_echo_fails; /* Tolerance to unanswered echo-requests */
};

struct PppAddrs
{
    Ip4Addr our_ipaddr;
    Ip4Addr his_ipaddr;
    Ip4Addr netmask;
    Ip4Addr dns1;
    Ip4Addr dns2;
    Ip6Addr our6_ipaddr;
    Ip6Addr his6_ipaddr;
};


/*
 * PPP interface control block.
 */
struct PppPcb
{
    PppSettings settings;
    struct LinkCallbacks* link_cb;
    void* link_ctx_cb;
    void (*link_status_cb)(PppPcb* pcb, int err_code, void* ctx);
    /* Status change callback */
    void (*notify_phase_cb)(PppPcb* pcb, uint8_t phase, void* ctx);
    /* Notify phase callback */
    void* ctx_cb; /* Callbacks optional pointer */
    NetIfc* netif; /* PPP interface */
    uint8_t phase; /* where the link is at */
    uint8_t err_code; /* Code indicating why interface is down. */ /* flags */
    bool ask_for_local; /* request our address from peer */
    bool ipcp_is_open; /* haven't called np_finished() */
    bool ipcp_is_up; /* have called ipcp_up() */
    bool if4_up; /* True when the IPv4 interface is up. */
    bool proxy_arp_set; /* Have created proxy arp entry */
    bool ipv6_cp_is_up; /* have called ip6cp_up() */
    bool if6_up; /* True when the IPv6 interface is up. */
    bool lcp_echo_timer_running; /* set if a timer is running */
    bool vj_enabled; /* Flag indicating VJ compression enabled. */
    bool ccp_all_rejected; /* we rejected all peer's options */
    bool mppe_keys_set; /* Have the MPPE keys been set? */ /* auth data */
    char peer_authname[0xff]; /* The name by which the peer authenticated itself to us. */
    uint16_t auth_pending;
    /* Records which authentication operations haven't completed yet. */
    uint16_t auth_done; /* Records which authentication operations have been completed. */
    upap_state upap; /* PAP data */
    chap_client_state chap_client; /* CHAP client data */
    chap_server_state chap_server; /* CHAP server data */
    EapState eap; /* EAP data */
    Fsm lcp_fsm; /* LCP fsm structure */
    LcpOptions lcp_wantoptions; /* Options that we want to request */
    LcpOptions lcp_gotoptions; /* Options that peer ack'd */
    LcpOptions lcp_allowoptions; /* Options we allow peer to request */
    LcpOptions lcp_hisoptions; /* Options that we ack'd */
    uint16_t peer_mru; /* currently negotiated peer MRU */
    uint8_t lcp_echos_pending; /* Number of outstanding echo msgs */
    uint8_t lcp_echo_number; /* ID number of next echo frame */
    uint8_t num_np_open; /* Number of network protocols which we have opened. */
    uint8_t num_np_up; /* Number of network protocols which have come up. */
    struct vjcompress vj_comp; /* Van Jacobson compression header. */
    Fsm ccp_fsm; /* CCP fsm structure */
    CcpOptions ccp_wantoptions; /* what to request the peer to use */
    CcpOptions ccp_gotoptions; /* what the peer agreed to do */
    CcpOptions ccp_allowoptions; /* what we'll agree to do */
    CcpOptions ccp_hisoptions; /* what we agreed to do */
    uint8_t ccp_localstate;
    /* Local state (mainly for handling reset-reqs and reset-acks). */
    uint8_t ccp_receive_method; /* Method chosen on receive path */
    uint8_t ccp_transmit_method; /* Method chosen on transmit path */
    ppp_mppe_state mppe_comp; /* MPPE "compressor" structure */
    ppp_mppe_state mppe_decomp; /* MPPE "decompressor" structure */
    Fsm ipcp_fsm; /* IPCP fsm structure */
    IpcpOptions ipcp_wantoptions; /* Options that we want to request */
    IpcpOptions ipcp_gotoptions; /* Options that peer ack'd */
    IpcpOptions ipcp_allowoptions; /* Options we allow peer to request */
    IpcpOptions ipcp_hisoptions; /* Options that we ack'd */
    Fsm ipv6cp_fsm; /* IPV6CP fsm structure */
    ipv6cp_options ipv6cp_wantoptions; /* Options that we want to request */
    ipv6cp_options ipv6cp_gotoptions; /* Options that peer ack'd */
    ipv6cp_options ipv6cp_allowoptions; /* Options we allow peer to request */
    ipv6cp_options ipv6cp_hisoptions; /* Options that we ack'd */
};

/************************
 *** PUBLIC FUNCTIONS ***
 ************************/

/*
 * WARNING: For multi-threads environment, all ppp_set_* functions most
 * only be called while the PPP is in the dead phase (i.e. disconnected).
 */


/*
 * Set PPP authentication.
 *
 * Warning: Using PPPAUTHTYPE_ANY might have security consequences.
 * RFC 1994 says:
 *
 * In practice, within or associated with each PPP server, there is a
 * database which associates "user" names with authentication
 * information ("secrets").  It is not anticipated that a particular
 * named user would be authenticated by multiple methods.  This would
 * make the user vulnerable to attacks which negotiate the least secure
 * method from among a set (such as PAP rather than CHAP).  If the same
 * secret was used, PAP would reveal the secret to be used later with
 * CHAP.
 *
 * Instead, for each user name there should be an indication of exactly
 * one method used to authenticate that user name.  If a user needs to
 * make use of different authentication methods under different
 * circumstances, then distinct user names SHOULD be employed, each of
 * which identifies exactly one authentication method.
 *
 * Default is none auth type, unset (NULL) user and passwd.
 */
constexpr auto PPPAUTHTYPE_NONE = 0x00;
constexpr auto PPPAUTHTYPE_PAP = 0x01;
constexpr auto PPPAUTHTYPE_CHAP = 0x02;
constexpr auto PPPAUTHTYPE_MSCHAP = 0x04;
constexpr auto PPPAUTHTYPE_MSCHAP_V2 = 0x08;
constexpr auto PPPAUTHTYPE_EAP = 0x10;
constexpr auto PPPAUTHTYPE_ANY = 0xff;
void ppp_set_auth(PppPcb *pcb, uint8_t authtype, const char *user, const char *password);

/*
 * If set, peer is required to authenticate. This is mostly necessary for PPP server support.
 *
 * Default is false.
 */
inline void PppSetAuthRequired(PppPcb* ppp, const bool boolval)
{
    (ppp->settings.auth_required = (boolval));
}



/*
 * Set PPP interface "our" and "his" IPv4 addresses. This is mostly necessary for PPP server
 * support but it can also be used on a PPP link where each side choose its own IP address.
 *
 * Default is unset (0.0.0.0).
 */
inline void PppSetIpcpOuraddr(PppPcb* ppp, Ip4Addr* addr)
{
    (ppp)->ipcp_wantoptions.ouraddr = ip4_addr_get_u32(addr);
    (ppp)->ask_for_local = (ppp)->ipcp_wantoptions.ouraddr != 0;
}

inline void PppSetIpcpHisaddr(PppPcb* ppp, Ip4Addr* addr)
{
    ((ppp)->ipcp_wantoptions.hisaddr = ip4_addr_get_u32(addr));
}

/*
 * Set DNS server addresses that are sent if the peer asks for them. This is mostly necessary
 * for PPP server support.
 *
 * Default is unset (0.0.0.0).
 */
inline void PppSetIpcpDnsaddr(PppPcb* ppp, uint32_t index, Ip4Addr* addr)
{
    ((ppp)->ipcp_allowoptions.dnsaddr[index] = ip4_addr_get_u32(addr));
}

/*
 * If set, we ask the peer for up to 2 DNS server addresses. Received DNS server addresses are
 * registered using the dns_setserver() function.
 *
 * Default is false.
 */
#define PPP_SET_USEPEERDNS(ppp, boolval) ((ppp)->settings.usepeerdns = (boolval))



/* Disable MPPE (Microsoft Point to Point Encryption). This parameter is exclusive. */
constexpr auto kPppMppeDisable = 0x00;
/* Require the use of MPPE (Microsoft Point to Point Encryption). */
constexpr auto PPP_MPPE_ENABLE = 0x01;
/* Allow MPPE to use stateful mode. Stateless mode is still attempted first. */
constexpr auto PPP_MPPE_ALLOW_STATEFUL = 0x02;
/* Refuse the use of MPPE with 40-bit encryption. Conflict with PPP_MPPE_REFUSE_128. */
constexpr auto PPP_MPPE_REFUSE_40 = 0x04;
/* Refuse the use of MPPE with 128-bit encryption. Conflict with PPP_MPPE_REFUSE_40. */
constexpr auto PPP_MPPE_REFUSE_128 = 0x08;
/*
 * Set MPPE configuration
 *
 * Default is disabled.
 */
void ppp_set_mppe(PppPcb *pcb, uint8_t flags);


/*
 * Wait for up to intval milliseconds for a valid PPP packet from the peer.
 * At the end of this  time, or when a valid PPP packet is received from the
 * peer, we commence negotiation by sending our first LCP packet.
 *
 * Default is 0.
 */
#define ppp_set_listen_time(ppp, intval) ((ppp)->settings.listen_time = (intval))

/*
 * If set, we will attempt to initiate a connection but if no reply is received from
 * the peer, we will then just wait passively for a valid LCP packet from the peer.
 *
 * Default is false.
 */
#define ppp_set_passive(ppp, boolval) ((ppp)->lcp_wantoptions.passive = (boolval))

/*
 * If set, we will not transmit LCP packets to initiate a connection until a valid
 * LCP packet is received from the peer. This is what we usually call the server mode.
 *
 * Default is false.
 */
#define ppp_set_silent(ppp, boolval) ((ppp)->lcp_wantoptions.silent = (boolval))

/*
 * If set, enable protocol field compression negotiation in both the receive and
 * the transmit direction.
 *
 * Default is true.
 */
#define ppp_set_neg_pcomp(ppp, boolval) ((ppp)->lcp_wantoptions.neg_pcompression = \
                                         (ppp)->lcp_allowoptions.neg_pcompression = (boolval))

/*
 * If set, enable Address/Control compression in both the receive and the transmit
 * direction.
 *
 * Default is true.
 */
#define ppp_set_neg_accomp(ppp, boolval) ((ppp)->lcp_wantoptions.neg_accompression = \
                                          (ppp)->lcp_allowoptions.neg_accompression = (boolval))

/*
 * If set, enable asyncmap negotiation. Otherwise forcing all control characters to
 * be escaped for both the transmit and the receive direction.
 *
 * Default is true.
 */
#define ppp_set_neg_asyncmap(ppp, boolval) ((ppp)->lcp_wantoptions.neg_asyncmap = \
                                            (ppp)->lcp_allowoptions.neg_asyncmap = (boolval))

/*
 * This option sets the Async-Control-Character-Map (ACCM) for this end of the link.
 * The ACCM is a set of 32 bits, one for each of the ASCII control characters with
 * values from 0 to 31, where a 1 bit  indicates that the corresponding control
 * character should not be used in PPP packets sent to this system. The map is
 * an unsigned 32 bits integer where the least significant bit (00000001) represents
 * character 0 and the most significant bit (80000000) represents character 31.
 * We will then ask the peer to send these characters as a 2-byte escape sequence.
 *
 * Default is 0.
 */
#define ppp_set_asyncmap(ppp, intval) ((ppp)->lcp_wantoptions.asyncmap = (intval))

/*
 * Set a PPP interface as the default network interface
 * (used to output all packets for which no specific route is found).
 */
#define ppp_set_default(ppp)         netif_set_default((ppp)->netif)

/*
 * Set a PPP notify phase callback.
 *
 * This can be used for example to set a LED pattern depending on the
 * current phase of the PPP session.
 */
typedef void (*ppp_notify_phase_cb_fn)(PppPcb *pcb, uint8_t phase, void *ctx);
void ppp_set_notify_phase_callback(PppPcb *pcb, ppp_notify_phase_cb_fn notify_phase_cb);


/*
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
LwipError ppp_connect(PppPcb *pcb, uint16_t holdoff);


/*
 * Listen for an incoming PPP connection.
 *
 * This can only be called if PPP is in the dead phase.
 *
 * If this port connects to a modem, the modem connection must be
 * established before calling this.
 */
LwipError ppp_listen(PppPcb *pcb);


/*
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
LwipError ppp_close(PppPcb *pcb, uint8_t nocarrier);

/*
 * Release the control block.
 *
 * This can only be called if PPP is in the dead phase.
 *
 * You must use ppp_close() before if you wish to terminate
 * an established PPP session.
 *
 * Return 0 on success, an error code on failure.
 */
LwipError ppp_free(PppPcb *pcb);

/*
 * PPP IOCTL commands.
 *
 * Get the up status - 0 for down, non-zero for up.  The argument must
 * point to an int.
 */
#define PPPCTLG_UPSTATUS 0

/*
 * Get the PPP error code.  The argument must point to an int.
 * Returns a PPPERR_* value.
 */
constexpr auto kPppctlgErrcode = 1;

/*
 * Get the fd associated with a PPP over serial
 */
constexpr auto kPppctlgFd = 2;

/*
 * Get and set parameters for the given connection.
 * Return 0 on success, an error code on failure.
 */
LwipError ppp_ioctl(PppPcb *pcb, uint8_t cmd, void *arg);

/* Get the PPP netif interface */
#define ppp_netif(ppp)               ((ppp)->netif)

/* Set an lwIP-style status-callback for the selected PPP device */
#define ppp_set_netif_statuscallback(ppp, status_cb)       \
        netif_set_status_callback((ppp)->netif, status_cb);

/* Set an lwIP-style link-callback for the selected PPP device */
#define ppp_set_netif_linkcallback(ppp, link_cb)           \
        netif_set_link_callback((ppp)->netif, link_cb);

#ifdef __cplusplus
}
#endif


