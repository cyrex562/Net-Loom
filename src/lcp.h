// PPP LCP -- Link Control Protocol

#pragma once

#include <cstdint>
#include "fsm.h"
#include "chap_new.h"
#include "ppp.h"

/*
 * When the link comes up we want to be able to wait for a short while,
 * or until seeing some input from the peer, before starting to send
 * configure-requests.  We do this by delaying the fsm_lowerup call.
 */
/* steal a bit in fsm flags word */
constexpr auto DELAYED_UP = 0x80;

/*
 * Options.
 */
constexpr auto CI_VENDOR = 0	/* Vendor Specific */;
constexpr auto CI_MRU = 1	/* Maximum Receive Unit */;
constexpr auto CI_ASYNCMAP = 2	/* Async Control Character Map */;
constexpr auto CI_AUTHTYPE = 3	/* Authentication Type */;
constexpr auto CI_QUALITY = 4	/* Quality Protocol */;
constexpr auto CI_MAGICNUMBER = 5	/* Magic Number */;
constexpr auto CI_PCOMPRESSION = 7	/* Protocol Field Compression */;
constexpr auto CI_ACCOMPRESSION = 8	/* Address/Control Field Compression */;
constexpr auto CI_FCSALTERN = 9	/* FCS-Alternatives */;
constexpr auto CI_SDP = 10	/* Self-Describing-Pad */;
constexpr auto CI_NUMBERED = 11	/* Numbered-Mode */;
constexpr auto CI_CALLBACK = 13	/* callback */;
constexpr auto CI_MRRU = 17	/* max reconstructed receive unit; multilink */;
constexpr auto CI_SSNHF = 18	/* short sequence numbers for multilink */;
constexpr auto CI_EPDISC = 19	/* endpoint discriminator */;
constexpr auto CI_MPPLUS = 22	/* Multi-Link-Plus-Procedure */;
constexpr auto CI_LDISC = 23	/* Link-Discriminator */;
constexpr auto CI_LCPAUTH = 24	/* LCP Authentication */;
constexpr auto CI_COBS = 25	/* Consistent Overhead Byte Stuffing */;
constexpr auto CI_PREFELIS = 26	/* Prefix Elision */;
constexpr auto CI_MPHDRFMT = 27	/* MP Header Format */;
constexpr auto CI_I18N = 28	/* Internationalization */;
constexpr auto CI_SDL = 29	/* Simple Data Link */;

/*
 * LCP-specific packet types (code numbers).
 */
constexpr auto PROTREJ = 8	/* Protocol Reject */;
constexpr auto ECHOREQ = 9	/* Echo Request */;
constexpr auto ECHOREP = 10	/* Echo Reply */;
constexpr auto DISCREQ = 11	/* Discard Request */;
constexpr auto IDENTIF = 12	/* Identification */;
constexpr auto TIMEREM = 13	/* Time Remaining */;

/* Value used as data for CI_CALLBACK option */
constexpr auto CBCP_OPT = 6	/* Use callback control protocol */;


/* An endpoint discriminator, used with multilink. */
constexpr auto MAX_ENDP_LEN = 20	/* maximum length of discriminator value */;

struct Epdisc
{
    unsigned char class_; /* -- The word "class" is reserved in C++. */
    unsigned char length;

    unsigned char value[MAX_ENDP_LEN];
};



/*
 * Length of each type of configuration option (in octets)
 */
// #define CILEN_VOID	2
#define CILEN_CHAR	3
#define CILEN_SHORT	4	/* CILEN_VOID + 2 */

#define CILEN_CHAP	5	/* CILEN_VOID + 2 + 1 */

#define CILEN_LONG	6	/* CILEN_VOID + 4 */

#define CILEN_LQR	8	/* CILEN_VOID + 2 + 4 */

#define CILEN_CBCP	3

#define CODENAME(x)	((x) == CONFACK ? "ACK" : \
             (x) == CONFNAK ? "NAK" : "REJ")

void lcp_open(PppPcb& pcb);

bool
lcp_close(PppPcb& pcb, std::string& reason);
void lcp_lowerup(PppPcb& pcb);

bool
lcp_lowerdown(PppPcb& pcb);
void lcp_sprotrej(PppPcb *pcb, uint8_t *p, int len);    /* send protocol reject */
void lcp_delayed_up(void* arg);
// int setendpoint (char **);
void lcp_resetci(Fsm *f);	/* Reset our CI */
int  lcp_cilen(Fsm *f);		/* Return length of our CI */
void lcp_addci(Fsm *f, uint8_t *ucp, int *lenp); /* Add our CI to pkt */
int  lcp_ackci(Fsm *f, uint8_t *p, int len); /* Peer ack'd our CI */
int  lcp_nakci(Fsm *f, uint8_t *p, int len, int treat_as_reject); /* Peer nak'd our CI */
int  lcp_rejci(Fsm *f, uint8_t *p, int len); /* Peer rej'd our CI */
int  lcp_reqci(Fsm *f, uint8_t *inp, int *lenp, int reject_if_disagree); /* Rcv peer CI */
void lcp_up(Fsm *f);		/* We're UP */
void lcp_down(Fsm *f);		/* We're DOWN */
void lcp_starting (Fsm *);	/* We need lower layer up */
void lcp_finished (Fsm *);	/* We need lower layer down */
int  lcp_extcode(Fsm *f, int code, int id, uint8_t *inp, int len);
void lcp_rprotrej(Fsm *f, uint8_t *inp, int len);
void lcp_echo_lowerup(PppPcb *pcb);
void lcp_echo_lower_down(PppPcb *pcb, Fsm* f);
void lcp_echo_timeout(void* arg);
void lcp_received_echo_reply(Fsm *f, int id, uint8_t *inp, int len);
void lcp_send_echo_request(Fsm *f);
void lcp_link_failure(Fsm *f);
void lcp_echo_check(Fsm *f);
void lcp_init(PppPcb& pcb);
void lcp_input(PppPcb *pcb, uint8_t *p, int len);
void lcp_protrej(PppPcb *pcb);

extern const struct Protent kLcpProtent;

//
// END OF FILE
//


