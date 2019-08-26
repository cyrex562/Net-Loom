/**
 * @file: ppp.h
 */

#pragma once
#include "fsm_def.h"
#include "timeouts.h"
#include "chap_new.h"
#include "eap_state.h"
#include "ip4_addr.h"
#include "ip6_addr.h"
#include "ipcp_defs.h"
#include "ipv6cp.h"
#include "network_interface.h"
#include "upap_state.h"
#include "vj.h"
#include "lcp_options.h"
#include "ccp_options.h"
#include "mppe_def.h"
#include "ppp_def.h"





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


constexpr auto PPP_CTRL_PBUF_MAX_SIZE = 512;


/*
 * Lengths of configuration options.
 */
constexpr auto CILEN_VOID = 2;
constexpr auto CILEN_COMPRESS = 4 /* min length for compression protocol opt. */;
constexpr auto CILEN_VJ = 6 /* length for RFC1332 Van-Jacobson opt. */;
constexpr auto CILEN_ADDR = 6 /* new-style single address option */;
constexpr auto CILEN_ADDRS = 10 /* old-style dual address option */;


/*
 * Significant octet values.
 */
constexpr auto PPP_ALLSTATIONS = 0xff	/* All-Stations broadcast address */;
constexpr auto PPP_UI = 0x03	/* Unnumbered Information */;
constexpr auto PPP_FLAG = 0x7e	/* Flag Sequence */;
constexpr auto PPP_ESCAPE = 0x7d	/* Asynchronous Control Escape */;
constexpr auto PPP_TRANS = 0x20	/* Asynchronous transparency modifier */;


/*
 * What to do with network protocol (NP) packets.
 */
enum PppNetworkProtoMode {
    NPMODE_PASS,		/* pass the packet through */
    NPMODE_DROP,		/* silently drop the packet */
    NPMODE_ERROR,		/* return an error */
    NPMODE_QUEUE		/* save it up for later. */
};


/*
 * The following structure records the time in seconds since
 * the last NP packet was sent or received.
 */
struct PppIdle {
    time_t xmit_idle;		/* time since last NP packet sent */
    time_t recv_idle;		/* time since last NP packet received */
};


/* values for epdisc.class */
constexpr auto EPD_NULL = 0	/* null discriminator, no data */;
constexpr auto EPD_LOCAL = 1;
constexpr auto EPD_IP = 2;
constexpr auto EPD_MAC = 3;
constexpr auto EPD_MAGIC = 4;
constexpr auto EPD_PHONENUM = 5;

/*
 * Global variables.
 */
// extern uint8_t	multilink;	/* enable multilink operation */
// extern uint8_t	doing_multilink;
// extern uint8_t	multilink_master;
// extern uint8_t	bundle_eof;
// extern uint8_t	bundle_terminating;


// extern unsigned int maxoctets;	     /* Maximum octetes per session (in bytes) */
// extern int       maxoctets_dir;      /* Direction :
//                       0 - in+out (default)
//                       1 - in
//                       2 - out
//                       3 - max(in,out) */
// extern int       maxoctets_timeout;  /* Timeout for check of octets limit */
constexpr auto PPP_OCTETS_DIRECTION_SUM = 0;
constexpr auto PPP_OCTETS_DIRECTION_IN = 1;
constexpr auto PPP_OCTETS_DIRECTION_OUT = 2;
constexpr auto PPP_OCTETS_DIRECTION_MAXOVERAL = 3;
// same as previos, but little different on RADIUS side
constexpr auto PPP_OCTETS_DIRECTION_MAXSESSION = 4;

// Table of pointers to supported protocols
// extern const struct Protent* const kProtocols[];


// Values for auth_pending, auth_done
constexpr auto PAP_WITHPEER = 0x1;
constexpr auto PAP_PEER = 0x2;
constexpr auto CHAP_WITHPEER = 0x4;
constexpr auto CHAP_PEER = 0x8;
constexpr auto EAP_WITHPEER = 0x10;
constexpr auto EAP_PEER = 0x20;

// Values for auth_done only
constexpr auto CHAP_MD5_WITHPEER = 0x40;
constexpr auto CHAP_MD5_PEER = 0x80;
constexpr auto CHAP_MS_SHIFT = 8	/* LSB position for MS auths */;
constexpr auto CHAP_MS_WITHPEER = 0x100;
constexpr auto CHAP_MS_PEER = 0x200;
constexpr auto CHAP_MS2_WITHPEER = 0x400;
constexpr auto CHAP_MS2_PEER = 0x800;

//
// PPP private functions
//


//
// Functions called from lwIP core.
//

/* initialize the PPP subsystem */
int init_ppp_subsys();

/*
 * Functions called from PPP link protocols.
 */

/* Create a new PPP control block */
std::tuple<bool, PppPcb>
init_ppp_pcb(NetworkInterface& pppif, std::vector<NetworkInterface>& interfaces);


/* Initiate LCP open request */
bool
ppp_start(PppPcb& pcb);

/* Called when link failed to setup */
void ppp_link_failed(PppPcb& pcb);

/* Called when link is normally down (i.e. it was asked to end) */
void ppp_link_end(PppPcb& pcb);

/* function called to process input packet */
bool ppp_input(PppPcb& ppp_pcb, PacketBuffer& pkt_buf, Fsm& lcp_fsm);


/*
 * Functions called by PPP protocols.
 */

/* function called by all PPP subsystems to send packets */
bool
ppp_write(PppPcb& pcb, PacketBuffer& p);

/* functions called by auth.c link_terminated() */
bool
ppp_link_terminated(PppPcb& pcb);

void new_phase(PppPcb& pcb, int phase);

int ppp_send_config(PppPcb *pcb, int mtu, uint32_t accm, int pcomp, int accomp);
int ppp_recv_config(PppPcb *pcb, int mru, uint32_t accm, int pcomp, int accomp);

void netif_set_mtu(PppPcb *pcb, int mtu);
int netif_get_mtu(PppPcb*pcb);


bool
ccp_set(PppPcb& pcb, bool isopen, bool isup, uint8_t receive_method, uint8_t transmit_method);


bool
ccp_reset_comp(PppPcb& pcb);


bool
ccp_reset_decomp(PppPcb& pcb);




int get_idle_time(PppPcb *pcb, struct ppp_idle *ip);


/* Optional protocol names list, to make our messages a little more informative. */
const char * protocol_name(int proto);


inline std::tuple<bool,uint8_t> GETCHAR(std::vector<uint8_t>& cp, size_t index)
{
    if (index > cp.size()) {
        return std::make_tuple(false, 0);
    }
    return std::make_tuple(true, cp[index++]);
}


inline void PUTCHAR(uint8_t val, std::vector<uint8_t>& cp, size_t& index)
{
    cp.push_back(val);
    index += 1;
}


inline void PUTSTRING(std::string& str, std::vector<uint8_t>& cp, size_t& index)
{
    for (auto&c : str) {
        cp.push_back(c);
        index += 1;
    }
}

inline void PUTBYTES(std::vector<uint8_t>& bytes, std::vector<uint8_t>& cp , size_t& index)
{
    size_t inc = bytes.size();
    std::copy(bytes.begin(), bytes.begin() + bytes.size(), cp.begin() + index);
    index += inc;
}

inline std::tuple<bool, uint16_t> GETSHORT(std::vector<uint8_t>& cp, size_t& index)
{
    if (index > cp.size()) {
        return std::make_tuple(false, 0);
    }
    uint16_t s = cp[index++];
    s |= cp[index++];
    return std::make_tuple(true, s);
}


inline void PUTSHORT(uint16_t s, std::vector<uint8_t>& cp, size_t& index)
{
    cp.push_back(s >> 8);
    cp.push_back(s);
    index += 2;
}


inline std::tuple<bool, long>
GETLONG(std::vector<uint8_t>& cp, size_t& index)
{
    if (index > cp.size())
    {
        return std::make_tuple(false, 0);
    }
    long l = cp[index++] << 8;
    l |= cp[index++];
    l <<= 8;
    l |= cp[index++];
    l <<= 8;
    l |= cp[index++];
    return std::make_tuple(true, l);
}


inline void
PUTLONG(long l, std::vector<uint8_t>& cp, size_t& index)
{
    if (index + 4 > cp.size())
    {
        cp.resize(cp.size() + 4);
    }
    cp[index++] = l >> 24;
    cp[index++] = l >> 16;
    cp[index++] = l >> 8;
    cp[index++] = l;
}


// #define INCPTR(n, cp)	((cp) += (n))
// #define DECPTR(n, cp)	((cp) -= (n))

/*
 * System dependent definitions for user-level 4.3BSD UNIX implementation.
 */
// #define Timeout(f, a, t)        do { sys_untimeout((f), (a)); sys_timeout((t)*1000, (f), (a)); } while(0)

inline void Timeout(SysTimeoutHandler timeout_fn, void* arg, const uint32_t time)
{
    sys_untimeout(timeout_fn, arg);
    sys_timeout(time * 1000, timeout_fn, arg);
}


//#define TIMEOUTMS(f, a, t)      do { sys_untimeout((f), (a)); sys_timeout((t), (f), (a)); } while(0)
inline void timeout_ms(SysTimeoutHandler time_fn, void* arg, const uint32_t time)
{
    sys_untimeout(time_fn, arg);
    sys_timeout(time * 1000, time_fn, arg);
}


inline void Untimeout(SysTimeoutHandler time_fn, void* arg) {
    sys_untimeout((time_fn), (arg));
}
// #define BZERO(s, n)		memset(s, 0, n)
// #define	BCMP(s1, s2, l)		memcmp(s1, s2, l)

// #define PRINTMSG(m, l)		{ ppp_info("Remote message: %0.*v", l, m); }

/*
 * MAKEHEADER - Add Header fields to a packet.
 */
// #define MAKEHEADER(p, t) { \
//     PUTCHAR(PPP_ALLSTATIONS, p); \
//     PUTCHAR(PPP_UI, p); \
//     PUTSHORT(t, p); }

inline void
MAKEHEADER(std::vector<uint8_t>& p, PppProtoFieldValue t)
{
    auto put_size = 1 + 1 + 2;
    if (p.size() < put_size) { p.resize(p.size() + put_size); }
    size_t index = 0;
    PUTCHAR(PPP_ALLSTATIONS, p, index);
    PUTCHAR(PPP_UI, p, index);
    PUTSHORT(t, p, index);
}

/* Procedures exported from auth.c */
// bool link_required(PppPcb* pcb);     /* we are starting to use the link */
// void link_terminated(PppPcb *pcb);   /* we are finished with the link */
// void link_down(PppPcb *pcb, Protent** protocols);	      /* the LCP layer has left the Opened state */
// void upper_layers_down(PppPcb *pcb, Protent** protocols); /* take all NCPs down */
// void link_established(PppPcb *pcb, bool auth_required);  /* the link is up; authenticate now */
// void start_networks(PppPcb *pcb, LcpOptions* go, LcpOptions* ho, LcpOptions* ao, bool multilink, <unknown>, <
//                     unknown>) noexcept;    /* start all the network control protos */
// bool continue_networks(PppPcb* pcb); /* start network [ip, etc] control protos */
bool
auth_check_passwd(PppPcb& pcb, std::string& auser, std::string& apasswd, std::string& msg);
                                /* check the user name and passwd against configuration */
bool
auth_peer_fail(PppPcb& pcb, int protocol);
                /* peer failed to authenticate itself */
bool
auth_peer_success(PppPcb& pcb, int protocol, int prot_flavor, std::string& name);
                /* peer successfully authenticated itself */
bool
auth_withpeer_fail(PppPcb& pcb, int protocol);
                /* we failed to authenticate ourselves */
bool
auth_withpeer_success(PppPcb& pcb, int protocol, int prot_flavor);
                /* we successfully authenticated ourselves */
bool
np_up(PppPcb& pcb, int proto);    /* a network protocol has come up */
bool
np_down(PppPcb& pcb, int proto);  /* a network protocol has gone down */
void np_finished(PppPcb& pcb, int proto); /* a network protocol no longer needs link */
bool
get_secret(PppPcb& pcb, std::string& client, std::string& server, std::string& secret);
                /* get "secret" for chap */


/* Procedures exported from ipcp.c */
/* int parse_dotted_ip (char *, uint32_t *); */

/* Procedures exported from demand.c */

void demand_conf (void);	/* config interface(s) for demand-dial */
void demand_block (void);	/* set all NPs to queue up packets */
void demand_unblock (void); /* set all NPs to pass packets */
void demand_discard (void); /* set all NPs to discard packets */
void demand_rexmit (int, uint32_t); /* retransmit saved frames for an NP*/
int  loop_chars (unsigned char *, int); /* process chars from loopback */
int  loop_frame (unsigned char *, int); /* should we bring link up? */


/* Procedures exported from multilink.c */

void mp_check_options (LcpOptions* wo, LcpOptions* ao, bool* doing_multilink); /* Check multilink-related options */


//
// Join link to an appropriate bundle
//
bool mp_join_bundle(PppPcb& pcb,
                    std::string& peer_authname,
                    std::string& bundle_name,
                    const bool doing_multilink = true,
                    const bool demand = true);

void mp_exit_bundle (void);  /* have disconnected our link from bundle */
void mp_bundle_terminated (void);
char *epdisc_to_str (struct Epdisc *); /* string from endpoint discrim. */
int  str_to_epdisc (struct Epdisc *, char *); /* endpt disc. from str */


/* Procedures exported from utils.c. */
void ppp_print_string(const uint8_t *p, int len, void (*printer) (uint8_t *, const char *, ...), uint8_t *arg);   /* Format a string for output */
int ppp_slprintf(char *buf, int buflen, const char *fmt, ...);            /* sprintf++ */
int ppp_vslprintf(char *buf, int buflen, const char *fmt, va_list args);  /* vsprintf++ */
size_t ppp_strlcpy(char *dest, const char *src, size_t len);        /* safe strcpy */
size_t ppp_strlcat(char *dest, const char *src, size_t len);        /* safe strncpy */
void ppp_dbglog(const char *fmt, ...);    /* log a debug message */
void ppp_info(const char *fmt, ...);      /* log an informational message */
void ppp_notice(const char *fmt, ...);    /* log a notice-level message */
void ppp_warn(const char *fmt, ...);      /* log a warning message */
void ppp_error(const char *fmt, ...);     /* log an error message */
void ppp_fatal(const char *fmt, ...);     /* log an error message and die(1) */


/*
 * Number of necessary timers analysis.
 *
 * PPP use at least one timer per each of its protocol, but not all protocols are
 * active at the same time, thus the number of necessary timeouts is actually
 * lower than enabled protocols. Here is the actual necessary timeouts based
 * on code analysis.
 *
 * Note that many features analysed here are not working at all and are only
 * there for a comprehensive analysis of necessary timers in order to prevent
 * having to redo that each time we add a feature.
 *
 * Timer list
 *
 * | holdoff timeout
 *  | low level protocol timeout (PPPoE or PPPoL2P)
 *   | LCP delayed UP
 *    | LCP retransmit (FSM)
 *     | LCP Echo timer
 *     .| PAP or CHAP or EAP authentication
 *     . | ECP retransmit (FSM)
 *     .  | CCP retransmit (FSM) when MPPE is enabled
 *     .   | CCP retransmit (FSM) when MPPE is NOT enabled
 *     .    | IPCP retransmit (FSM)
 *     .    .| IP6CP retransmit (FSM)
 *     .    . | Idle time limit
 *     .    .  | Max connect time
 *     .    .   | Max octets
 *     .    .    | CCP RACK timeout
 *     .    .    .
 * PPP_PHASE_DEAD
 * PPP_PHASE_HOLDOFF
 * |   .    .    .
 * PPP_PHASE_INITIALIZE
 *  |  .    .    .
 * PPP_PHASE_ESTABLISH
 *   | .    .    .
 *    |.    .    .
 *     |    .    .
 * PPP_PHASE_AUTHENTICATE
 *     |    .    .
 *     ||   .    .
 * PPP_PHASE_NETWORK
 *     | || .    .
 *     |   |||   .
 * PPP_PHASE_RUNNING
 *     |    .|||||
 *     |    . ||||
 * PPP_PHASE_TERMINATE
 *     |    . ||||
 * PPP_PHASE_NETWORK
 *    |.         .
 * PPP_PHASE_ESTABLISH
 * PPP_PHASE_DISCONNECT
 * PPP_PHASE_DEAD
 *
 * Alright, PPP basic retransmission and LCP Echo consume one timer.
 *  1
 *
 * If authentication is enabled one timer is necessary during authentication.
 *  1 + PPP_AUTH_SUPPORT
 *
 * If ECP is enabled one timer is necessary before IPCP and/or IP6CP, one more
 * is necessary if CCP is enabled (only with MPPE support but we don't care much
 * up to this detail level).
 *  1 + ECP_SUPPORT + CCP_SUPPORT
 *
 * If CCP is enabled it might consume a timer during IPCP or IP6CP, thus
 * we might use IPCP, IP6CP and CCP timers simultaneously.
 *  1 + PPP_IPV4_SUPPORT + PPP_IPV6_SUPPORT + CCP_SUPPORT
 *
 * When entering running phase, IPCP or IP6CP is still running. If idle time limit
 * is enabled one more timer is necessary. Same for max connect time and max
 * octets features. Furthermore CCP RACK might be used past this point.
 *  1 + PPP_IPV4_SUPPORT + PPP_IPV6_SUPPORT -1 + PPP_IDLETIMELIMIT + PPP_MAXCONNECT + MAXOCTETS + CCP_SUPPORT
 *
 * IPv4 or IPv6 must be enabled, therefore we don't need to take care the authentication
 * and the CCP + ECP case, thus reducing overall complexity.
 * 1 + std::max(PPP_IPV4_SUPPORT + PPP_IPV6_SUPPORT + CCP_SUPPORT, PPP_IPV4_SUPPORT + PPP_IPV6_SUPPORT -1 + PPP_IDLETIMELIMIT + PPP_MAXCONNECT + MAXOCTETS + CCP_SUPPORT)
 *
 * We don't support PPP_IDLETIMELIMIT + PPP_MAXCONNECT + MAXOCTETS features
 * and adding those defines to ppp_opts.h just for having the value always
 * defined to 0 isn't worth it.
 * 1 + std::max(PPP_IPV4_SUPPORT + PPP_IPV6_SUPPORT + CCP_SUPPORT, PPP_IPV4_SUPPORT + PPP_IPV6_SUPPORT -1 + CCP_SUPPORT)
 *
 * Thus, the following is enough for now.
 * 1 + PPP_IPV4_SUPPORT + PPP_IPV6_SUPPORT + CCP_SUPPORT
 */




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
typedef void (*ppp_link_status_cb_fn)(PppPcb *pcb, int err_code, uint8_t *ctx);

/*
 * PPP configuration.
 */
struct PppSettings
{
    bool auth_required{}; // Peer is required to authenticate */
    bool null_login{}; // Username of "" and a password of "" are acceptable
    bool explicit_remote{}; // remote_name specified with remotename opt */
    bool refuse_pap{}; // Don't proceed auth. with PAP */
    bool refuse_chap{}; // Don't proceed auth. with CHAP */
    bool refuse_mschap{}; //Don't proceed auth. with MS-CHAP */
    bool refuse_mschap_v2{}; // Don't proceed auth. with MS-CHAPv2 */
    bool refuse_eap{}; // Don't proceed auth. with EAP */
    bool usepeerdns{}; // Ask peer for DNS adds */
    bool persist{}; // Persist mode, always try to open the connection */
    bool hide_password{}; // Hide password in dumped packets */
    bool noremoteip{}; // Let him have no IP address */
    bool lax_recv{}; // accept control chars in asyncmap */
    bool noendpoint{}; // don't send/accept endpoint discriminator */
    bool lcp_echo_adaptive{}; // request echo only if the link was idle */
    bool require_mppe{}; // Require MPPE (Microsoft Point to Point Encryption)
    bool refuse_mppe_40{}; // Allow MPPE 40-bit mode? */
    bool refuse_mppe_128{}; // Allow MPPE 128-bit mode? */
    bool refuse_mppe_stateful{}; // Allow MPPE stateful mode? */
    uint64_t listen_time{};
    // time to listen first (ms), waiting for peer to send LCP packet */
    uint64_t idle_time_limit{}; /* Disconnect if idle for this many seconds */
    uint64_t maxconnect{}; /* Maximum connect time (seconds) */ /* auth data */
    // char user[0xff]; /* Username for PAP */
    std::string user;
    // char passwd[0xff]; /* Password for PAP, secret for CHAP */
    std::string passwd;
    // char remote_name[0xff]; /* Peer's name for authentication */
    std::string remote_name;
    uint64_t pap_timeout_time{}; /* Timeout (seconds) for auth-req retrans. */
    uint32_t pap_max_transmits{}; /* Number of auth-reqs sent */
    uint64_t pap_req_timeout{}; /* Time to wait for auth-req from peer */
    uint64_t chap_timeout_time{}; /* Timeout (seconds) for retransmitting req */
    uint32_t chap_max_transmits{}; /* max # times to send challenge */
    uint64_t chap_rechallenge_time{}; /* Time to wait for auth-req from peer */
    uint64_t eap_req_time{}; /* Time to wait (for retransmit/fail) */
    uint32_t eap_allow_req{}; /* Max Requests allowed */
    uint64_t eap_timeout_time{}; /* Time to wait (for retransmit/fail) */
    uint32_t eap_max_transmits{}; /* Max Requests allowed */
    uint64_t fsm_timeout_time{}; /* Timeout time in seconds */
    uint32_t fsm_max_conf_req_transmits{}; /* Maximum Configure-Request transmissions */
    uint32_t fsm_max_term_transmits{}; /* Maximum Terminate-Request transmissions */
    uint32_t fsm_max_nak_loops{}; /* Maximum number of nak loops tolerated */
    uint32_t lcp_loopbackfail{};
    /* Number of times we receive our magic number from the peer
                                    before deciding the link is looped-back. */
    uint64_t lcp_echo_interval{}; /* Interval between LCP echo-requests */
    uint32_t lcp_echo_fails{}; /* Tolerance to unanswered echo-requests */
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
    // struct LinkCallbacks* link_cb{};
    void* link_ctx_cb{};
    // void (*link_status_cb)(PppPcb* pcb, int err_code, void* ctx){};
    /* Status change callback */
    // void (*notify_phase_cb)(PppPcb* pcb, uint8_t phase, void* ctx){};
    /* Notify phase callback */
    // void* ctx_cb{}; /* Callbacks optional pointer */
    NetworkInterface netif{}; /* PPP interface */
    PppPhase phase{}; /* where the link is at */
    PppErrorCode err_code{}; /* Code indicating why interface is down. */ /* flags */
    bool ask_for_local{}; /* request our address from peer */
    bool ipcp_is_open{}; /* haven't called np_finished() */
    bool ipcp_is_up{}; /* have called ipcp_up() */
    bool if4_up{}; /* True when the IPv4 interface is up. */
    bool proxy_arp_set{}; /* Have created proxy arp entry */
    bool ipv6_cp_is_up{}; /* have called ip6cp_up() */
    bool if6_up{}; /* True when the IPv6 interface is up. */
    bool lcp_echo_timer_running{}; /* set if a timer is running */
    bool vj_enabled{}; /* Flag indicating VJ compression enabled. */
    bool ccp_all_rejected{}; /* we rejected all peer's options */
    bool mppe_keys_set{}; /* Have the MPPE keys been set? */ /* auth data */
    std::string peer_authname; /* The name by which the peer authenticated itself to us. */
    uint16_t auth_pending{};
    /* Records which authentication operations haven't completed yet. */
    uint16_t auth_done{}; /* Records which authentication operations have been completed. */
    UpapState upap; /* PAP data */
    ChapClientState chap_client; /* CHAP client data */
    chap_server_state chap_server; /* CHAP server data */
    EapState eap; /* EAP data */
    Fsm lcp_fsm{}; /* LCP fsm structure */
    LcpOptions lcp_wantoptions{}; /* Options that we want to request */
    LcpOptions lcp_gotoptions{}; /* Options that peer ack'd */
    LcpOptions lcp_allowoptions{}; /* Options we allow peer to request */
    LcpOptions lcp_hisoptions{}; /* Options that we ack'd */
    uint16_t peer_mru{}; /* currently negotiated peer MRU */
    uint8_t lcp_echos_pending{}; /* Number of outstanding echo msgs */
    uint8_t lcp_echo_number{}; /* ID number of next echo frame */
    uint8_t num_np_open{}; /* Number of network protocols which we have opened. */
    uint8_t num_np_up{}; /* Number of network protocols which have come up. */
    VjCompress vj_comp{}; /* Van Jacobson compression header. */
    Fsm ccp_fsm{}; /* CCP fsm structure */
    CcpOptions ccp_wantoptions{}; /* what to request the peer to use */
    CcpOptions ccp_gotoptions{}; /* what the peer agreed to do */
    CcpOptions ccp_allowoptions{}; /* what we'll agree to do */
    CcpOptions ccp_hisoptions{}; /* what we agreed to do */
    uint8_t ccp_localstate{};
    /* Local state (mainly for handling reset-reqs and reset-acks). */
    uint8_t ccp_receive_method{}; /* Method chosen on receive path */
    uint8_t ccp_transmit_method{}; /* Method chosen on transmit path */
    PppMppeState mppe_comp{}; /* MPPE "compressor" structure */
    PppMppeState mppe_decomp{}; /* MPPE "decompressor" structure */
    Fsm ipcp_fsm{}; /* IPCP fsm structure */
    IpcpOptions ipcp_wantoptions{}; /* Options that we want to request */
    IpcpOptions ipcp_gotoptions{}; /* Options that peer ack'd */
    IpcpOptions ipcp_allowoptions{}; /* Options we allow peer to request */
    IpcpOptions ipcp_hisoptions{}; /* Options that we ack'd */
    Fsm ipv6cp_fsm{}; /* IPV6CP fsm structure */
    Ipv6CpOptions ipv6cp_wantoptions{}; /* Options that we want to request */
    Ipv6CpOptions ipv6cp_gotoptions{}; /* Options that peer ack'd */
    Ipv6CpOptions ipv6cp_allowoptions{}; /* Options we allow peer to request */
    Ipv6CpOptions ipv6cp_hisoptions{}; /* Options that we ack'd */
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
enum PppAuthTypes
{
    PPPAUTHTYPE_NONE = 0x00,
    PPPAUTHTYPE_PAP = 0x01,
    PPPAUTHTYPE_CHAP = 0x02,
    PPPAUTHTYPE_MSCHAP = 0x04,
    PPPAUTHTYPE_MSCHAP_V2 = 0x08,
    PPPAUTHTYPE_EAP = 0x10,
    PPPAUTHTYPE_ANY = 0xff,
};

void ppp_set_auth(PppPcb *pcb, const PppAuthTypes authtype, std::string& user, std::string& password);

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
inline void set_ppp_ipcp_our_addr(PppPcb& ppp, const Ip4Addr& addr)
{
    (ppp).ipcp_wantoptions.ouraddr = get_ip4_addr_u32(addr);
    (ppp).ask_for_local = (ppp).ipcp_wantoptions.ouraddr != 0;
}

inline void set_ppp_ipcp_his_addr(PppPcb& ppp, const Ip4Addr& addr)
{
    ((ppp).ipcp_wantoptions.hisaddr = get_ip4_addr_u32(addr));
}

/*
 * Set DNS server addresses that are sent if the peer asks for them. This is mostly necessary
 * for PPP server support.
 *
 * Default is unset (0.0.0.0).
 */
inline void set_ppp_ipcp_dns_addr(PppPcb& ppp, uint32_t index, Ip4Addr& addr)
{
    ((ppp).ipcp_allowoptions.dnsaddr[index] = get_ip4_addr_u32(addr));
}

/*
 * If set, we ask the peer for up to 2 DNS server addresses. Received DNS server addresses are
 * registered using the dns_setserver() function.
 *
 * Default is false.
 */
inline void
PPP_SET_USEPEERDNS(PppPcb& ppp, bool boolval)
{
    ((ppp).settings.usepeerdns = (boolval));
}



/* Disable MPPE (Microsoft Point to Point Encryption). This parameter is exclusive. */
constexpr auto PPP_MPPE_DISABLE = 0x00;
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
inline void
ppp_set_listen_time(PppPcb& ppp, uint64_t intval)
{
    ((ppp).settings.listen_time = (intval));
}

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
typedef void (*ppp_notify_phase_cb_fn)(PppPcb *pcb, uint8_t phase, uint8_t *ctx);
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
LwipStatus ppp_connect(PppPcb& pcb, uint64_t holdoff);


/*
 * Listen for an incoming PPP connection.
 *
 * This can only be called if PPP is in the dead phase.
 *
 * If this port connects to a modem, the modem connection must be
 * established before calling this.
 */
LwipStatus ppp_listen(PppPcb& pcb);


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
LwipStatus ppp_close(PppPcb& pcb, bool nocarrier);

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
LwipStatus ppp_free(PppPcb *pcb);

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
LwipStatus ppp_ioctl(PppPcb *pcb, uint8_t cmd, uint8_t *arg);

/* Get the PPP netif interface */
#define ppp_netif(ppp)               ((ppp)->netif)

/* Set an lwIP-style status-callback for the selected PPP device */
#define ppp_set_netif_statuscallback(ppp, status_cb)       \
        netif_set_status_callback((ppp)->netif, status_cb);

/* Set an lwIP-style link-callback for the selected PPP device */
#define ppp_set_netif_linkcallback(ppp, link_cb)           \
        netif_set_link_callback((ppp)->netif, link_cb);


static LwipStatus
ppp_do_connect(PppPcb& pcb);

static LwipStatus ppp_netif_init_cb(NetworkInterface* netif);

static LwipStatus ppp_netif_output_ip4(NetworkInterface& netif, PacketBuffer& pb, const Ip4Addr& ipaddr, PppPcb& ppp_pcb);

static LwipStatus ppp_netif_output_ip6(NetworkInterface& netif, PacketBuffer& pb, const Ip6Addr& ipaddr, PppPcb& ppp_pcb);

LwipStatus
ppp_netif_output(NetworkInterface& netif, PacketBuffer& pb, PppProtoFieldValue protocol, PppPcb& ppp_pcb);

int
sifnpmode(PppPcb* pcb, int proto, enum PppNetworkProtoMode mode);

int
sif6down(PppPcb* pcb);

int
sif6up(PppPcb* pcb);

int
sif6addr(PppPcb* pcb, Eui64 our_eui64, Eui64 his_eui64);

int
sifdown(PppPcb* pcb);

int
sifup(PppPcb* pcb);

int
sifaddr(PppPcb* pcb, uint32_t our_adr, uint32_t his_adr, uint32_t netmask);

uint32_t
get_mask(uint32_t addr);

int
sdns(PppPcb* pcb, uint32_t ns1, uint32_t ns2);

int
sifvjcomp(PppPcb* pcb, int vjcomp, int cidcomp, int maxcid);

int
cdns(PppPcb* pcb, uint32_t ns1, uint32_t ns2);

//
//
//