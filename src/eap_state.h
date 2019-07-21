#pragma once
#include <cstdint>

/*
 * Complete EAP state for one PPP session.
 */
enum EapStateCode {
	eapInitial = 0,	/* No EAP authentication yet requested */
	eapPending,	/* Waiting for LCP (no timer) */
	eapClosed,	/* Authentication not in use */
	kEapListen,	/* Client ready (and timer running) */
	eapIdentify,	/* EAP Identify sent */
	eapSRP1,	/* Sent EAP SRP-SHA1 Subtype 1 */
	eapSRP2,	/* Sent EAP SRP-SHA1 Subtype 2 */
	eapSRP3,	/* Sent EAP SRP-SHA1 Subtype 3 */
	eapMD5Chall,	/* Sent MD5-Challenge */
	eapOpen,	/* Completed authentication */
	eapSRP4,	/* Sent EAP SRP-SHA1 Subtype 4 */
	eapBadAuth	/* Failed authentication */
};

struct EapAuth {
	const char *ea_name;	/* Our name */
	char ea_peer[0xff];	/* Peer's name */
	uint8_t *ea_session;	/* Authentication library linkage */
	uint8_t *ea_skey;	/* Shared encryption key */
	size_t ea_namelen;	/* Length of our name */
	size_t ea_peerlen;	/* Length of peer's name */
	enum EapStateCode ea_state;
	uint8_t ea_id;		/* Current id */
	uint8_t ea_requests;	/* Number of Requests sent/received */
	uint8_t ea_responses;	/* Number of Responses */
	uint8_t ea_type;		/* One of EAPT_* */
	uint32_t ea_keyflags;	/* SRP shared key usage flags */
};

constexpr auto EAP_MAX_CHALLENGE_LENGTH = 24;

struct EapState
{
    struct EapAuth es_client; /* Client (authenticatee) data */
    struct EapAuth es_server; /* Server (authenticator) data */
    int es_savedtime; /* Saved timeout */
    int es_rechallenge; /* EAP rechallenge interval */
    int es_lwrechallenge; /* SRP lightweight rechallenge inter */
    uint8_t es_usepseudo; /* Use SRP Pseudonym if offered one */
    int es_usedpseudo; /* Set if we already sent PN */
    int es_challen; /* Length of challenge string */
    uint8_t es_challenge[EAP_MAX_CHALLENGE_LENGTH];
};
//
// END OF FILE
//