#pragma once
#include <string>
#include <cstdint>

constexpr auto EAP_MAX_CHALLENGE_LENGTH = 24;

/*
 * Complete EAP state for one PPP session.
 */
enum EapStateCode {
    EAP_INITIAL = 0,	/* No EAP authentication yet requested */
    EAP_PENDING,	/* Waiting for LCP (no timer) */
    EAP_CLOSED,	/* Authentication not in use */
    EAP_LISTEN,	/* Client ready (and timer running) */
    EAP_IDENTIFY,	/* EAP Identify sent */
    EAP_SRP1,	/* Sent EAP SRP-SHA1 Subtype 1 */
    EAP_SRP2,	/* Sent EAP SRP-SHA1 Subtype 2 */
    EAP_SRP3,	/* Sent EAP SRP-SHA1 Subtype 3 */
    EAP_MD5_CHALL,	/* Sent MD5-Challenge */
    EAP_OPEN,	/* Completed authentication */
    EAP_SRP4,	/* Sent EAP SRP-SHA1 Subtype 4 */
    EAP_BAD_AUTH	/* Failed authentication */
};

struct EapAuth
{
    std::string ea_name; /* Our name */
    std::string ea_peer; /* Peer's name */
    uint8_t* ea_session; /* Authentication library linkage */
    uint8_t* ea_skey; /* Shared encryption key */
    enum EapStateCode ea_state;
    uint8_t ea_id; /* Current id */
    uint8_t ea_requests; /* Number of Requests sent/received */
    uint8_t ea_responses; /* Number of Responses */
    uint8_t ea_type; /* One of EAPT_* */
    uint32_t ea_keyflags; /* SRP shared key usage flags */
};

struct EapState
{
    EapAuth es_client; /* Client (authenticatee) data */
    EapAuth es_server; /* Server (authenticator) data */
    uint64_t es_savedtime; /* Saved timeout */
    uint64_t es_rechallenge; /* EAP rechallenge interval */
    uint64_t es_lwrechallenge; /* SRP lightweight rechallenge inter */
    bool es_usepseudo; /* Use SRP Pseudonym if offered one */
    bool es_usedpseudo; /* Set if we already sent PN */
    std::vector<uint8_t> es_challenge;
};

//
// END OF FILE
//