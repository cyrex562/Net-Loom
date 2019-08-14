#pragma once
#include <string>


/*
 * Each FSM is described by an fsm structure and fsm callbacks.
 */
struct Fsm
{
    // PppPcb pcb; /* PPP Interface */
    // const struct FsmCallbacks* callbacks; /* Callback routines */
    std::string term_reason;
    uint8_t seen_ack; /* Have received valid Ack/Nak/Rej to Req */
    /* -- This is our only flag, we might use u_int :1 if we have more flags */
    uint16_t protocol; /* Data Link Layer Protocol field value */
    uint8_t state; /* State */
    uint8_t flags; /* Contains option bits */
    uint8_t id; /* Current id */
    uint8_t reqid; /* Current request id */
    uint8_t retransmits; /* Number of retransmissions left */
    uint8_t nakloops; /* Number of nak loops since last ack */
    uint8_t rnakloops; /* Number of naks received */
    uint8_t maxnakloops; /* Maximum number of nak loops tolerated
                   (necessary because IPCP require a custom large max nak loops value) */
    uint8_t term_reason_len; /* Length of term_reason */
    // PppPcb unit;
};


//
// END OF FILE
//