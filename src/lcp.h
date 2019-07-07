// PPP LCP -- Link Control Protocol

#pragma once

#include "ppp_opts.h"
#include "ppp.h"

#ifdef __cplusplus
extern "C" {
#endif

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


struct Epdisc {
    unsigned char	class_; /* -- The word "class" is reserved in C++. */
    unsigned char	length;
    unsigned char	value[MAX_ENDP_LEN];
};

/*
 * The state of options is described by an lcp_options structure.
 */
struct LcpOptions {
    unsigned int passive           :1; /* Don't die if we don't get a response */
    unsigned int silent            :1; /* Wait for the other end to start first */
    unsigned int restart           :1; /* Restart vs. exit after close */
    unsigned int neg_mru           :1; /* Negotiate the MRU? */
    unsigned int neg_asyncmap      :1; /* Negotiate the async map? */
    unsigned int neg_upap          :1; /* Ask for UPAP authentication? */
    unsigned int neg_chap          :1; /* Ask for CHAP authentication? */
    unsigned int neg_eap           :1; /* Ask for EAP authentication? */
    unsigned int neg_magicnumber   :1; /* Ask for magic number? */
    unsigned int neg_pcompression  :1; /* HDLC Protocol Field Compression? */
    unsigned int neg_accompression :1; /* HDLC Address/Control Field Compression? */
    unsigned int neg_lqr           :1; /* Negotiate use of Link Quality Reports */
    unsigned int neg_cbcp          :1; /* Negotiate use of CBCP */
    unsigned int neg_mrru          :1; /* negotiate multilink MRRU */
    unsigned int neg_ssnhf         :1; /* negotiate short sequence numbers */
    unsigned int neg_endpoint      :1; /* negotiate endpoint discriminator */
    uint16_t mru;			/* Value of MRU */
    uint16_t mrru;			/* Value of MRRU, and multilink enable */
    uint8_t chap_mdtype;		/* which MD types (hashing algorithm) */
    uint32_t asyncmap;		/* Value of async map */
    uint32_t magicnumber;
    uint8_t  numloops;		/* Number of loops during magic number neg. */
    uint32_t lqr_period;	/* Reporting period for LQR 1/100ths second */
    struct Epdisc endpoint;	/* endpoint discriminator */
};

void lcp_open(PppPcb *pcb);
void lcp_close(PppPcb *pcb, const char *reason);
void lcp_lowerup(PppPcb *pcb);
void lcp_lowerdown(PppPcb *pcb);
void lcp_sprotrej(PppPcb *pcb, uint8_t *p, int len);    /* send protocol reject */

extern const struct Protent lcp_protent;

#if 0 /* moved to ppp_opts.h */
/* Default number of times we receive our magic number from the peer
   before deciding the link is looped-back. */
#define DEFLOOPBACKFAIL	10
#endif /* moved to ppp_opts.h */

#ifdef __cplusplus
}
#endif


