#pragma once
#include <cstdint>
#include "fsm.h"

/*
 * Options.
 */
    // IP Addresses

constexpr auto CI_ADDRS = 1;	
constexpr auto CI_COMPRESSTYPE = 2;	/* Compression Type */;
constexpr auto CI_ADDR = 3;
constexpr auto CI_MS_DNS1 = 129	/* Primary DNS value */;
constexpr auto CI_MS_DNS2 = 131     /* Secondary DNS value */;
constexpr auto MAX_STATES = 16		/* from slcompress.h */;
constexpr auto IPCP_VJMODE_OLD = 1	/* "old" mode (option # = 0x0037) */;
constexpr auto IPCP_VJMODE_RFC1172 = 2	/* "old-rfc"mode (option # = 0x002d) */;
constexpr auto IPCP_VJMODE_RFC1332 = 3	/* "new-rfc"mode (option # = 0x002d, */;
                                /*  maxslot and slot number compression) */
constexpr auto IPCP_VJ_COMP = 0x002d	/* current value for VJ compression option*/;
constexpr auto IPCP_VJ_COMP_OLD = 0x0037	/* "old" (i.e, broken) value for VJ */;
				/* compression option*/ 


static void ipcp_resetci(Fsm *f);	/* Reset our CI */
static int  ipcp_cilen(Fsm *f);	        /* Return length of our CI */
static void ipcp_addci(Fsm *f, uint8_t *ucp, int *lenp); /* Add our CI */
static int  ipcp_ackci(Fsm *f, uint8_t *p, int len);	/* Peer ack'd our CI */
static int  ipcp_nakci(Fsm *f, uint8_t *p, int len, int treat_as_reject);/* Peer nak'd our CI */
static int  ipcp_rejci(Fsm *f, uint8_t *p, int len);	/* Peer rej'd our CI */
static int  ipcp_reqci(Fsm *f, uint8_t *inp, int *len, int reject_if_disagree); /* Rcv CI */
static void ipcp_up(Fsm *f);		/* We're UP */
static void ipcp_down(Fsm *f);		/* We're DOWN */
static void ipcp_finished(Fsm *f);	/* Don't need lower layer */