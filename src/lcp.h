// PPP LCP -- Link Control Protocol

#pragma once

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
struct LcpOptions
{
    bool passive; /* Don't die if we don't get a response */
    bool silent; /* Wait for the other end to start first */
    bool restart; /* Restart vs. exit after close */
    bool neg_mru; /* Negotiate the MRU? */
    bool neg_asyncmap; /* Negotiate the async map? */
    bool neg_upap; /* Ask for UPAP authentication? */
    bool neg_chap; /* Ask for CHAP authentication? */
    bool neg_eap; /* Ask for EAP authentication? */
    bool neg_magicnumber; /* Ask for magic number? */
    bool neg_pcompression; /* HDLC Protocol Field Compression? */
    bool neg_accompression; /* HDLC Address/Control Field Compression? */
    bool neg_lqr; /* Negotiate use of Link Quality Reports */
    bool neg_cbcp; /* Negotiate use of CBCP */
    bool neg_mrru; /* negotiate multilink MRRU */
    bool neg_ssnhf; /* negotiate short sequence numbers */
    bool neg_endpoint; /* negotiate endpoint discriminator */
    uint16_t mru; /* Value of MRU */
    uint16_t mrru; /* Value of MRRU, and multilink enable */
    uint8_t chap_mdtype; /* which MD types (hashing algorithm) */
    uint32_t asyncmap; /* Value of async map */
    uint32_t magicnumber;
    uint8_t numloops; /* Number of loops during magic number neg. */
    uint32_t lqr_period; /* Reporting period for LQR 1/100ths second */
    struct Epdisc endpoint; /* endpoint discriminator */
};

void lcp_open(PppPcb *pcb);
void lcp_close(PppPcb *pcb, const char *reason);
void lcp_lowerup(PppPcb *pcb);
void lcp_lowerdown(PppPcb *pcb);
void lcp_sprotrej(PppPcb *pcb, uint8_t *p, int len);    /* send protocol reject */

extern const struct Protent kLcpProtent;


#ifdef __cplusplus
}
#endif


