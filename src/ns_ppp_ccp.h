#pragma once
// #include "mppe.h"
#include "fsm_def.h"
#include "ns_ppp.h"

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

constexpr auto DEFLATE_MIN_WORKS = 9;




/*
 * Parts of a CCP packet.
 */
// todo: modify these macros
// #define CCP_CODE(dp)		((dp)[0])
// #define CCP_ID(dp)		((dp)[1])
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

constexpr auto CI_DEFLATE = 26	/* config option for Deflate */;
constexpr auto CI_DEFLATE_DRAFT = 24	/* value used in original draft RFC */;
constexpr auto CILEN_DEFLATE = 4	/* length of its config option */;
constexpr auto DEFLATE_MIN_SIZE = 9;
constexpr auto DEFLATE_MAX_SIZE = 15;
constexpr auto DEFLATE_METHOD_VAL = 8;


inline uint8_t
DEFLATE_SIZE(uint8_t x) { return (((x) >> 4) + 8); }


inline uint8_t
DEFLATE_METHOD(uint8_t x) { return ((x) & 0x0F); }


inline uint32_t
DEFLATE_MAKE_OPT(uint32_t w) { return ((((w) - 8) << 4) + DEFLATE_METHOD_VAL); }

constexpr auto DEFLATE_CHK_SEQUENCE = 0;
/*
 * Definitions for MPPE.
 */

constexpr auto CI_MPPE = 18      /* config option for MPPE */;
constexpr auto CILEN_MPPE = 6      /* length of config option */;

/*
 * Definitions for other, as yet unsupported, compression methods.
 */
constexpr auto CI_PREDICTOR_1 = 1	/* config option for Predictor-1 */;
constexpr auto CILEN_PREDICTOR_1 = 2	/* length of its config option */;
constexpr auto CI_PREDICTOR_2 = 2	/* config option for Predictor-2 */;
constexpr auto CILEN_PREDICTOR_2 = 2	/* length of its config option */;

struct CcpRackTimeoutArgs
{
    Fsm f;
    PppPcb pcb;
};


/*
 * ccp_open - CCP is allowed to come up.
 */
bool
ccp_init(PppPcb& pcb);
bool ccp_open(PppPcb& pcb);


bool
ccp_close(PppPcb& pcb, std::string& reason);


bool
ccp_lowerup(PppPcb& pcb);


bool
ccp_lowerdown(PppPcb& pcb);


bool
ccp_input(PppPcb& pcb, std::vector<uint8_t>& pkt);


bool
ccp_proto_rejected(PppPcb& pcb);


bool
ccp_datainput(PppPcb& pcb, std::vector<uint8_t>& pkt);


bool
ccp_resetci(PppPcb& pcb);
size_t ccp_cilen(PppPcb& ppp_pcb);


bool
ccp_addci(Fsm&, std::vector<uint8_t>& pkt, PppPcb& pcb);

bool
ccp_proc_config_ack(Fsm&, std::vector<uint8_t>& pkt, PppPcb& pcb);
int ccp_nak_config(Fsm*, const uint8_t*, int, int, PppPcb* pcb);

bool
ccp_rejci(Fsm&, std::vector<uint8_t>& pkt, PppPcb& pcb);

bool
ccp_reqci(Fsm&, std::vector<uint8_t>& pkt, bool, PppPcb& pcb);


bool
ccp_up(Fsm&, PppPcb& pcb);


bool
ccp_down(Fsm&, Fsm& lcp_fsm, PppPcb& pcb);


bool
ccp_extcode(PppPcb& pcb, Fsm&, int, int, std::vector<uint8_t>& data);


bool
ccp_reset_ack_timeout(Fsm& f, PppPcb& pcb);


std::string
method_name(CcpOptions& opt1, CcpOptions&);

 /** Issue a reset-request. */
bool
ccp_reset_request(CcpLocalState& local_state, Fsm& f, PppPcb& pcb);


inline bool ccp_test(PppPcb& pcb, std::vector<uint8_t>& opt_buf, uint32_t option, uint32_t idx)
{
    // TODO: figure out what test should do and implement.
    return false;
}


//
// END OF FILE
//