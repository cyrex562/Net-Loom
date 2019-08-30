#pragma once
#include <string>
// #include "ppp.h"
#include "ppp_def.h"


/*
 * Link states.
 */
enum PppFsmLinkState
{
    PPP_FSM_INITIAL = 0,
    /* Down, hasn't been opened */
    PPP_FSM_STARTING = 1,
    /* Down, been opened */
    PPP_FSM_CLOSED = 2,
    /* Up, hasn't been opened */
    PPP_FSM_STOPPED = 3,
    /* Open, waiting for down event */
    PPP_FSM_CLOSING = 4,
    /* Terminating the connection, not open */
    PPP_FSM_STOPPING = 5,
    /* Terminating, but open */
    PPP_FSM_REQSENT = 6,
    /* We've sent a Config Request */
    PPP_FSM_ACKRCVD = 7,
    /* We've received a Config Ack */
    PPP_FSM_ACKSENT = 8,
    /* We've sent a Config Ack */
    PPP_FSM_OPENED = 9,
    /* Connection available */
};


struct FsmOptions
{
    bool passive;
    bool restart;
    bool silent;
    bool delayed_up;
};


/*
 * Each FSM is described by an fsm structure and fsm callbacks.
 */
struct Fsm
{
    std::string term_reason;
    bool seen_ack; /* Have received valid Ack/Nak/Rej to Req */
    /* -- This is our only flag, we might use u_int :1 if we have more flags */
    PppProtoFieldValue protocol; /* Data Link Layer Protocol field value */
    PppFsmLinkState state; /* State */
    FsmOptions options; /* Contains option bits */
    uint8_t id; /* Current id */
    uint8_t reqid; /* Current request id */
    uint8_t retransmits; /* Number of retransmissions left */
    uint8_t nakloops; /* Number of nak loops since last ack */
    uint8_t rnakloops; /* Number of naks received */
    uint8_t maxnakloops; /* Maximum number of nak loops tolerated
                   (necessary because IPCP require a custom large max nak loops value) */
};


//
// END OF FILE
//