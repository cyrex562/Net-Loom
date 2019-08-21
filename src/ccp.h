#pragma once
#include <mppe.h>
#include "fsm_def.h"
struct PppPcb;

/*
 * CCP codes.
 */
enum CcpCode
{
    CCP_CONFREQ =1,
    CCP_CONFACK =2,
    CCP_TERMREQ =5,
    CCP_TERMACK =6,
    CCP_RESETREQ= 14,
    CCP_RESETACK= 15
};



/*
 * Max # bytes for a CCP option
 */
constexpr auto CCP_MAX_OPTION_LENGTH = 32;

constexpr auto kDeflateMinWorks = 9;

/*
 * Local state (mainly for handling reset-reqs and reset-acks).
 */
constexpr auto RESET_ACK_PENDING = 1	/* waiting for reset-ack */;
constexpr auto REPEAT_RESET_REQ = 2	/* send another reset-req if no reset-ack */;
constexpr auto RESET_ACK_TIMEOUT = 1	/* second */;

/*
 * Parts of a CCP packet.
 */

#define CCP_CODE(dp)		((dp)[0])
#define CCP_ID(dp)		((dp)[1])
#define CCP_LENGTH(dp)		(((dp)[2] << 8) + (dp)[3])
#define CCP_HDRLEN		4

#define CCP_OPT_CODE(dp)	((dp)[0])
#define CCP_OPT_LENGTH(dp)	((dp)[1])
#define CCP_OPT_MINLEN		2

/*
 * Definitions for BSD-Compress.
 */

#define CI_BSD_COMPRESS		21	/* config. option for BSD-Compress */
#define CILEN_BSD_COMPRESS	3	/* length of config. option */

/* Macros for handling the 3rd byte of the BSD-Compress config option. */
#define BSD_NBITS(x)		((x) & 0x1F)	/* number of bits requested */
#define BSD_VERSION(x)		((x) >> 5)	/* version of option format */
#define BSD_CURRENT_VERSION	1		/* current version number */
#define BSD_MAKE_OPT(v, n)	(((v) << 5) | (n))

#define BSD_MIN_BITS		9	/* smallest code size supported */
#define BSD_MAX_BITS		15	/* largest code size supported */



/*
 * Definitions for Deflate.
 */

#define CI_DEFLATE		26	/* config option for Deflate */
#define CI_DEFLATE_DRAFT	24	/* value used in original draft RFC */
#define CILEN_DEFLATE		4	/* length of its config option */

#define DEFLATE_MIN_SIZE	9
constexpr auto DEFLATE_MAX_SIZE = 15;
#define DEFLATE_METHOD_VAL	8
#define DEFLATE_SIZE(x)		(((x) >> 4) + 8)
#define DEFLATE_METHOD(x)	((x) & 0x0F)
#define DEFLATE_MAKE_OPT(w)	((((w) - 8) << 4) + DEFLATE_METHOD_VAL)
#define DEFLATE_CHK_SEQUENCE	0
/*
 * Definitions for MPPE.
 */

#define CI_MPPE                18      /* config option for MPPE */
#define CILEN_MPPE              6      /* length of config option */

    /*
 * Definitions for other, as yet unsupported, compression methods.
 */

#define CI_PREDICTOR_1		1	/* config option for Predictor-1 */
#define CILEN_PREDICTOR_1	2	/* length of its config option */
#define CI_PREDICTOR_2		2	/* config option for Predictor-2 */
#define CILEN_PREDICTOR_2	2	/* length of its config option */




extern const struct Protent kCcpProtent;



struct CcpRackTimeoutArgs
{
    Fsm* f;
    PppPcb* pcb;
};


/*
 * ccp_open - CCP is allowed to come up.
 */
void ccp_init(PppPcb* ppp_pcb);
bool ccp_open(PppPcb* pcb);


bool
ccp_close(PppPcb& pcb, std::string& reason);
void ccp_lowerup(PppPcb* pcb);
void ccp_lowerdown(PppPcb* pcb);
void ccp_input(PppPcb& pcb, std::vector<uint8_t>& pkt);
void ccp_protrej(PppPcb* pcb);
void ccp_datainput(PppPcb *pcb, uint8_t *pkt, int len);


bool
ccp_resetci(Fsm&, PppPcb& pcb);
size_t ccp_cilen(PppPcb* ppp_pcb);
void ccp_addci(Fsm*, uint8_t*, int*, PppPcb* pcb);
int ccp_ackci(Fsm*, uint8_t*, int, PppPcb* pcb);
int ccp_nakci(Fsm*, const uint8_t*, int, int, PppPcb* pcb);
int ccp_rejci(Fsm*, const uint8_t*, int, PppPcb* pcb);
int ccp_reqci(Fsm*, uint8_t*, size_t*, int, PppPcb* pcb);
void ccp_up(Fsm*, PppPcb* pcb, Protent** protocols);
void ccp_down(Fsm*, Fsm* lcp_fsm, PppPcb* pcb);
int ccp_extcode(Fsm*, int, int, uint8_t*, int, PppPcb* PppPcb);
void ccp_rack_timeout(void*);
const char* method_name(struct CcpOptions*, struct CcpOptions*);

 /** Issue a reset-request. */
bool
ccp_reset_request(uint8_t ppp_pcb_ccp_local_state, Fsm& f);


inline bool ccp_test(PppPcb* pcb, uint8_t* opt_buf, uint32_t option, uint32_t idx)
{
    // TODO: figure out what test should do and implement.
    return false;
}


//
// END OF FILE
//