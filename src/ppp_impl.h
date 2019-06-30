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

#include "ppp_opts.h"
#include <cstdio> /* formats */
#include <cstdarg>
#include <cstring>
#include <cstdlib> /* strtol() */
#include "netif.h"
#include "def.h"
#include "timeouts.h"
#include "ppp.h"
#include "pppdebug.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Memory used for control packets.
 *
 * PPP_CTRL_PBUF_MAX_SIZE is the amount of memory we allocate when we
 * cannot figure out how much we are going to use before filling the buffer.
 */
#define PPP_CTRL_PBUF_TYPE       PBUF_RAM
#define PPP_CTRL_PBUF_MAX_SIZE   512


/*
 * The basic PPP frame.
 */
#define PPP_ADDRESS(p)	(((u_char *)(p))[0])
#define PPP_CONTROL(p)	(((u_char *)(p))[1])
#define PPP_PROTOCOL(p)	((((u_char *)(p))[2] << 8) + ((u_char *)(p))[3])

/*
 * Significant octet values.
 */
#define	PPP_ALLSTATIONS	0xff	/* All-Stations broadcast address */
#define	PPP_UI		0x03	/* Unnumbered Information */
#define	PPP_FLAG	0x7e	/* Flag Sequence */
#define	PPP_ESCAPE	0x7d	/* Asynchronous Control Escape */
#define	PPP_TRANS	0x20	/* Asynchronous transparency modifier */

/*
 * Protocol field values.
 */
#define PPP_IP		0x21	/* Internet Protocol */
#define	PPP_VJC_COMP	0x2d	/* VJ compressed TCP */
#define	PPP_VJC_UNCOMP	0x2f	/* VJ uncompressed TCP */
#define PPP_IPV6	0x57	/* Internet Protocol Version 6 */
#define PPP_COMP	0xfd	/* compressed packet */
#define PPP_IPCP	0x8021	/* IP Control Protocol */
#define PPP_IPV6CP	0x8057	/* IPv6 Control Protocol */
#define PPP_CCP		0x80fd	/* Compression Control Protocol */
#define PPP_ECP		0x8053	/* Encryption Control Protocol */
#define PPP_LCP		0xc021	/* Link Control Protocol */
#define PPP_PAP		0xc023	/* Password Authentication Protocol */
#define PPP_LQR		0xc025	/* Link Quality Report protocol */
#define PPP_CHAP	0xc223	/* Cryptographic Handshake Auth. Protocol */
#define PPP_CBCP	0xc029	/* Callback Control Protocol */
#define PPP_EAP		0xc227	/* Extensible Authentication Protocol */


/*
 * The following struct gives the addresses of procedures to call
 * for a particular lower link level protocol.
 */
struct LinkCallbacks {
  /* Start a connection (e.g. Initiate discovery phase) */
  void (*connect) (PppPcb *pcb, void *ctx);
  /* Listen for an incoming connection (Passive mode) */
  void (*listen) (PppPcb *pcb, void *ctx);
  /* End a connection (i.e. initiate disconnect phase) */
  void (*disconnect) (PppPcb *pcb, void *ctx);
  /* Free lower protocol control block */
  err_t (*free) (PppPcb *pcb, void *ctx);
  /* Write a pbuf to a ppp link, only used from PPP functions to send PPP packets. */
  err_t (*write)(PppPcb *pcb, void *ctx, struct pbuf *p);
  /* Send a packet from lwIP core (IPv4 or IPv6) */
  err_t (*netif_output)(PppPcb *pcb, void *ctx, struct pbuf *p, u_short protocol);
  /* configure the transmit-side characteristics of the PPP interface */
  void (*send_config)(PppPcb *pcb, void *ctx, uint32_t accm, int pcomp, int accomp);
  /* confire the receive-side characteristics of the PPP interface */
  void (*recv_config)(PppPcb *pcb, void *ctx, uint32_t accm, int pcomp, int accomp);
};

/*
 * What to do with network protocol (NP) packets.
 */
enum NPmode {
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
#define EPD_NULL	0	/* null discriminator, no data */
#define EPD_LOCAL	1
#define EPD_IP		2
#define EPD_MAC		3
#define EPD_MAGIC	4
#define EPD_PHONENUM	5

/*
 * Global variables.
 */
extern uint8_t	multilink;	/* enable multilink operation */
extern uint8_t	doing_multilink;
extern uint8_t	multilink_master;
extern uint8_t	bundle_eof;
extern uint8_t	bundle_terminating;

extern unsigned int maxoctets;	     /* Maximum octetes per session (in bytes) */
extern int       maxoctets_dir;      /* Direction :
				      0 - in+out (default)
				      1 - in
				      2 - out
				      3 - max(in,out) */
extern int       maxoctets_timeout;  /* Timeout for check of octets limit */
#define PPP_OCTETS_DIRECTION_SUM        0
#define PPP_OCTETS_DIRECTION_IN         1
#define PPP_OCTETS_DIRECTION_OUT        2
#define PPP_OCTETS_DIRECTION_MAXOVERAL  3
/* same as previos, but little different on RADIUS side */
#define PPP_OCTETS_DIRECTION_MAXSESSION 4

/* Data input may be used by CCP and ECP, remove this entry
 * from struct protent to save some flash
 */
#define PPP_DATAINPUT 0

/*
 * The following struct gives the addresses of procedures to call
 * for a particular protocol.
 */
struct Protent {
    u_short protocol;		/* PPP protocol number */
    /* Initialization procedure */
    void (*init) (PppPcb *pcb);
    /* Process a received packet */
    void (*input) (PppPcb *pcb, u_char *pkt, int len);
    /* Process a received protocol-reject */
    void (*protrej) (PppPcb *pcb);
    /* Lower layer has come up */
    void (*lowerup) (PppPcb *pcb);
    /* Lower layer has gone down */
    void (*lowerdown) (PppPcb *pcb);
    /* Open the protocol */
    void (*open) (PppPcb *pcb);
    /* Close the protocol */
    void (*close) (PppPcb *pcb, const char *reason);
    /* Process a received data packet */
    void (*datainput) (PppPcb *pcb, u_char *pkt, int len);
    // option_t *options;		/* List of command-line options */
    /* Check requested options, assign defaults */
    void (*check_options) (void);
    /* Configure interface for demand-dial */
    int  (*demand_conf) (int unit);
    /* Say whether to bring up link for this pkt */
    int  (*active_pkt) (u_char *pkt, int len);
};

/* Table of pointers to supported protocols */
extern const struct Protent* const kProtocols[];


/* Values for auth_pending, auth_done */
#define PAP_WITHPEER	0x1
#define PAP_PEER	0x2
#define CHAP_WITHPEER	0x4
#define CHAP_PEER	0x8
#define EAP_WITHPEER	0x10
#define EAP_PEER	0x20

/* Values for auth_done only */
#define CHAP_MD5_WITHPEER	0x40
#define CHAP_MD5_PEER		0x80
#define CHAP_MS_SHIFT		8	/* LSB position for MS auths */
#define CHAP_MS_WITHPEER	0x100
#define CHAP_MS_PEER		0x200
#define CHAP_MS2_WITHPEER	0x400
#define CHAP_MS2_PEER		0x800

/* Supported CHAP protocols */
#define CHAP_MDTYPE_SUPPORTED (MDTYPE_MICROSOFT_V2 | MDTYPE_MICROSOFT | MDTYPE_MD5)

/*
 * PPP private functions
 */

 
/*
 * Functions called from lwIP core.
 */

/* initialize the PPP subsystem */
int ppp_init(void);

/*
 * Functions called from PPP link protocols.
 */

/* Create a new PPP control block */
PppPcb *ppp_new(struct netif *pppif, const struct LinkCallbacks *callbacks, void *link_ctx_cb,
                 ppp_link_status_cb_fn link_status_cb, void *ctx_cb);

/* Initiate LCP open request */
void ppp_start(PppPcb *pcb);

/* Called when link failed to setup */
void ppp_link_failed(PppPcb *pcb);

/* Called when link is normally down (i.e. it was asked to end) */
void ppp_link_end(PppPcb *pcb);

/* function called to process input packet */
void ppp_input(PppPcb *pcb, struct pbuf *pb);


/*
 * Functions called by PPP protocols.
 */

/* function called by all PPP subsystems to send packets */
err_t ppp_write(PppPcb *pcb, struct pbuf *p);

/* functions called by auth.c link_terminated() */
void ppp_link_terminated(PppPcb *pcb);

void new_phase(PppPcb *pcb, int p);

int ppp_send_config(PppPcb *pcb, int mtu, uint32_t accm, int pcomp, int accomp);
int ppp_recv_config(PppPcb *pcb, int mru, uint32_t accm, int pcomp, int accomp);

int sifaddr(PppPcb *pcb, uint32_t our_adr, uint32_t his_adr, uint32_t netmask);
int cifaddr(PppPcb *pcb, uint32_t our_adr, uint32_t his_adr);
int sdns(PppPcb*pcb, uint32_t ns1, uint32_t ns2);
int cdns(PppPcb*pcb, uint32_t ns1, uint32_t ns2);
int sifvjcomp(PppPcb*pcb, int vjcomp, int cidcomp, int maxcid);
int sifup(PppPcb *pcb);
int sifdown (PppPcb *pcb);
uint32_t get_mask(uint32_t addr);
int sif6addr(PppPcb*pcb, eui64_t our_eui64, eui64_t his_eui64);
int cif6addr(PppPcb*pcb, eui64_t our_eui64, eui64_t his_eui64);
int sif6up(PppPcb*pcb);
int sif6down (PppPcb*pcb);


#if DEMAND_SUPPORT
int sifnpmode(ppp_pcb *pcb, int proto, enum NPmode mode);
#endif /* DEMAND_SUPPORt */

void netif_set_mtu(PppPcb *pcb, int mtu);
int netif_get_mtu(PppPcb *pcb);

#if CCP_SUPPORT
#if 0 /* unused */
int ccp_test(ppp_pcb *pcb, u_char *opt_ptr, int opt_len, int for_transmit);
#endif /* unused */
void ccp_set(ppp_pcb *pcb, uint8_t isopen, uint8_t isup, uint8_t receive_method, uint8_t transmit_method);
void ccp_reset_comp(ppp_pcb *pcb);
void ccp_reset_decomp(ppp_pcb *pcb);
#if 0 /* unused */
int ccp_fatal_error(ppp_pcb *pcb);
#endif /* unused */
#endif /* CCP_SUPPORT */

#if PPP_IDLETIMELIMIT
int get_idle_time(ppp_pcb *pcb, struct ppp_idle *ip);
#endif /* PPP_IDLETIMELIMIT */

#if DEMAND_SUPPORT
int get_loop_output(void);
#endif /* DEMAND_SUPPORT */

/* Optional protocol names list, to make our messages a little more informative. */
#if PPP_PROTOCOLNAME
const char * protocol_name(int proto);
#endif /* PPP_PROTOCOLNAME  */

/* Optional stats support, to get some statistics on the PPP interface */
#if PPP_STATS_SUPPORT
void print_link_stats(void); /* Print stats, if available */
void reset_link_stats(int u); /* Reset (init) stats when link goes up */
void update_link_stats(int u); /* Get stats at link termination */
#endif /* PPP_STATS_SUPPORT */



/*
 * Inline versions of get/put char/short/long.
 * Pointer is advanced; we assume that both arguments
 * are lvalues and will already be in registers.
 * cp MUST be u_char *.
 */
#define GETCHAR(c, cp) { \
	(c) = *(cp)++; \
}
#define PUTCHAR(c, cp) { \
	*(cp)++ = (u_char) (c); \
}
#define GETSHORT(s, cp) { \
	(s) = *(cp)++ << 8; \
	(s) |= *(cp)++; \
}
#define PUTSHORT(s, cp) { \
	*(cp)++ = (u_char) ((s) >> 8); \
	*(cp)++ = (u_char) (s); \
}
#define GETLONG(l, cp) { \
	(l) = *(cp)++ << 8; \
	(l) |= *(cp)++; (l) <<= 8; \
	(l) |= *(cp)++; (l) <<= 8; \
	(l) |= *(cp)++; \
}
#define PUTLONG(l, cp) { \
	*(cp)++ = (u_char) ((l) >> 24); \
	*(cp)++ = (u_char) ((l) >> 16); \
	*(cp)++ = (u_char) ((l) >> 8); \
	*(cp)++ = (u_char) (l); \
}

#define INCPTR(n, cp)	((cp) += (n))
#define DECPTR(n, cp)	((cp) -= (n))

/*
 * System dependent definitions for user-level 4.3BSD UNIX implementation.
 */
#define TIMEOUT(f, a, t)        do { sys_untimeout((f), (a)); sys_timeout((t)*1000, (f), (a)); } while(0)
#define TIMEOUTMS(f, a, t)      do { sys_untimeout((f), (a)); sys_timeout((t), (f), (a)); } while(0)
#define UNTIMEOUT(f, a)         sys_untimeout((f), (a))

#define BZERO(s, n)		memset(s, 0, n)
#define	BCMP(s1, s2, l)		memcmp(s1, s2, l)

#define PRINTMSG(m, l)		{ ppp_info("Remote message: %0.*v", l, m); }

/*
 * MAKEHEADER - Add Header fields to a packet.
 */
#define MAKEHEADER(p, t) { \
    PUTCHAR(PPP_ALLSTATIONS, p); \
    PUTCHAR(PPP_UI, p); \
    PUTSHORT(t, p); }

/* Procedures exported from auth.c */
void link_required(PppPcb *pcb);     /* we are starting to use the link */
void link_terminated(PppPcb *pcb);   /* we are finished with the link */
void link_down(PppPcb *pcb);	      /* the LCP layer has left the Opened state */
void upper_layers_down(PppPcb *pcb); /* take all NCPs down */
void link_established(PppPcb *pcb);  /* the link is up; authenticate now */
void start_networks(PppPcb *pcb);    /* start all the network control protos */
void continue_networks(PppPcb *pcb); /* start network [ip, etc] control protos */
#if PPP_AUTH_SUPPORT
#if PPP_SERVER
int auth_check_passwd(ppp_pcb *pcb, char *auser, int userlen, char *apasswd, int passwdlen, const char **msg, int *msglen);
                                /* check the user name and passwd against configuration */
void auth_peer_fail(ppp_pcb *pcb, int protocol);
				/* peer failed to authenticate itself */
void auth_peer_success(ppp_pcb *pcb, int protocol, int prot_flavor, const char *name, int namelen);
				/* peer successfully authenticated itself */
#endif /* PPP_SERVER */
void auth_withpeer_fail(PppPcb *pcb, int protocol);
				/* we failed to authenticate ourselves */
void auth_withpeer_success(PppPcb *pcb, int protocol, int prot_flavor);
				/* we successfully authenticated ourselves */
#endif /* PPP_AUTH_SUPPORT */
void np_up(PppPcb *pcb, int proto);    /* a network protocol has come up */
void np_down(PppPcb *pcb, int proto);  /* a network protocol has gone down */
void np_finished(PppPcb *pcb, int proto); /* a network protocol no longer needs link */
#if PPP_AUTH_SUPPORT
int get_secret(PppPcb *pcb, const char *client, const char *server, char *secret, int *secret_len, int am_server);
				/* get "secret" for chap */
#endif /* PPP_AUTH_SUPPORT */

/* Procedures exported from ipcp.c */
/* int parse_dotted_ip (char *, uint32_t *); */

/* Procedures exported from demand.c */
#if DEMAND_SUPPORT
void demand_conf (void);	/* config interface(s) for demand-dial */
void demand_block (void);	/* set all NPs to queue up packets */
void demand_unblock (void); /* set all NPs to pass packets */
void demand_discard (void); /* set all NPs to discard packets */
void demand_rexmit (int, uint32_t); /* retransmit saved frames for an NP*/
int  loop_chars (unsigned char *, int); /* process chars from loopback */
int  loop_frame (unsigned char *, int); /* should we bring link up? */
#endif /* DEMAND_SUPPORT */

/* Procedures exported from multilink.c */
#ifdef HAVE_MULTILINK
void mp_check_options (void); /* Check multilink-related options */
int  mp_join_bundle (void);  /* join our link to an appropriate bundle */
void mp_exit_bundle (void);  /* have disconnected our link from bundle */
void mp_bundle_terminated (void);
char *epdisc_to_str (struct epdisc *); /* string from endpoint discrim. */
int  str_to_epdisc (struct epdisc *, char *); /* endpt disc. from str */
#else
#define mp_bundle_terminated()	/* nothing */
#define mp_exit_bundle()	/* nothing */
#define doing_multilink		0
#define multilink_master	0
#endif

/* Procedures exported from utils.c. */
void ppp_print_string(const u_char *p, int len, void (*printer) (void *, const char *, ...), void *arg);   /* Format a string for output */
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
#if PRINTPKT_SUPPORT
void ppp_dump_packet(ppp_pcb *pcb, const char *tag, unsigned char *p, int len);
                                /* dump packet to debug log if interesting */
#endif /* PRINTPKT_SUPPORT */

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
 * 1 + LWIP_MAX(PPP_IPV4_SUPPORT + PPP_IPV6_SUPPORT + CCP_SUPPORT, PPP_IPV4_SUPPORT + PPP_IPV6_SUPPORT -1 + PPP_IDLETIMELIMIT + PPP_MAXCONNECT + MAXOCTETS + CCP_SUPPORT)
 *
 * We don't support PPP_IDLETIMELIMIT + PPP_MAXCONNECT + MAXOCTETS features
 * and adding those defines to ppp_opts.h just for having the value always
 * defined to 0 isn't worth it.
 * 1 + LWIP_MAX(PPP_IPV4_SUPPORT + PPP_IPV6_SUPPORT + CCP_SUPPORT, PPP_IPV4_SUPPORT + PPP_IPV6_SUPPORT -1 + CCP_SUPPORT)
 *
 * Thus, the following is enough for now.
 * 1 + PPP_IPV4_SUPPORT + PPP_IPV6_SUPPORT + CCP_SUPPORT
 */

#ifdef __cplusplus
}
#endif