/**
 * chap-new.c - New CHAP implementation.
 *
 * Copyright (c) 2003 Paul Mackerras. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. The name(s) of the authors of this software must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 3. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Paul Mackerras
 *     <paulus@samba.org>".
 *
 * THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#pragma once
#include "ppp_defs.h"
#include "ppp_opts.h"
#include <string>
#include <vector>
struct PppPcb;

/*
 * CHAP packets begin with a standard header with code, id, len (2 bytes).
 */
constexpr auto CHAP_HDR_LEN = 4;

/*
 * Values for the code field.
 */
enum ChapFieldCodes
{
    CHAP_CHALLENGE = 1,
    CHAP_RESPONSE = 2,
    CHAP_SUCCESS = 3,
    CHAP_FAILURE = 4,
};


/*
 * CHAP digest codes.
 */
enum ChapDigestCode
{
    CHAP_MD5 = 5,
    CHAP_MICROSOFT = 0x80,
    CHAP_MICROSOFT_V2 = 0x81,
    CHAP_NONE = 0,
};



/*
 * Semi-arbitrary limits on challenge and response fields.
 */
constexpr auto MAX_CHALLENGE_LEN = 64;
constexpr auto MAX_RESPONSE_LEN = 64;

/*
 * These limits apply to challenge and response packets we send.
 * The +4 is the +1 that we actually need rounded up.
 */
constexpr auto CHAL_MAX_PKTLEN = (PPP_HDRLEN + CHAP_HDR_LEN + 4 + MAX_CHALLENGE_LEN + MAXNAMELEN);
constexpr auto RESP_MAX_PKTLEN = (PPP_HDRLEN + CHAP_HDR_LEN + 4 + MAX_RESPONSE_LEN + MAXNAMELEN);

/* bitmask of supported algorithms */
enum ChapMdTypes
{
    MDTYPE_MICROSOFT_V2 = 0x1,
    MDTYPE_MICROSOFT = 0x2,
    MDTYPE_MD5 = 0x4,
    MDTYPE_NONE = 0,
};



/* Return the digest alg. ID for the most preferred digest type. */
inline ChapDigestCode
CHAP_DIGEST(const ChapMdTypes mdtype)
{
    if (((mdtype) & MDTYPE_MD5))
    {
        return CHAP_MD5;
    }
    if (mdtype & MDTYPE_MICROSOFT_V2)
    {
        return CHAP_MICROSOFT_V2;
    }
    if (mdtype & MDTYPE_MICROSOFT)
    {
        return CHAP_MICROSOFT;
    }
    return CHAP_NONE;
}


/* Return the bit flag (lsb set) for our most preferred digest type. */
#define CHAP_MDTYPE(mdtype) ((mdtype) ^ ((mdtype) - 1)) & (mdtype)

/* Return the bit flag for a given digest algorithm ID. */
inline ChapMdTypes
chap_mdtype_d(const ChapDigestCode digest)
{
    return ((digest) == CHAP_MICROSOFT_V2)
               ? MDTYPE_MICROSOFT_V2
               : ((digest) == CHAP_MICROSOFT)
               ? MDTYPE_MICROSOFT
               : ((digest) == CHAP_MD5)
               ? MDTYPE_MD5
               : MDTYPE_NONE;
}


/* Can we do the requested digest? */
inline bool
chap_candigest(ChapMdTypes mdtype, ChapDigestCode digest)
{
    return digest == CHAP_MICROSOFT_V2
               ? mdtype & MDTYPE_MICROSOFT_V2
               : digest == CHAP_MICROSOFT
               ? mdtype & MDTYPE_MICROSOFT
               : digest == CHAP_MD5
               ? mdtype & MDTYPE_MD5
               : 0;
}


/*
 * The code for each digest type has to supply one of these.
 */
// struct ChapDigestType
// {
//      ChapDigestCodes code; /*
//      * Note: challenge and response arguments below are formatted as
//      * a length byte followed by the actual challenge/response data.
//      */
//     void
//     (*generate_challenge)(PppPcb* pcb, unsigned char* challenge);
//
//
//     int
//     (*verify_response)(PppPcb* pcb,
//                        int id,
//                        std::string& name,
//                        std::string& secret,
//                        const unsigned char* challenge,
//                        const unsigned char* response,
//                        std::string& message,
//                        int message_space);
//
//
//     void
//     (*make_response)(PppPcb* pcb,
//                      unsigned char* response,
//                      int id,
//                      std::string& our_name,
//                      const unsigned char* challenge,
//                      std::string& secret,
//                      unsigned char* priv);
//
//
//     int
//     (*check_success)(PppPcb* pcb, unsigned char* pkt, int len, unsigned char* priv);
//
//
//     void
//     (*handle_failure)(PppPcb* pcb, unsigned char* pkt, int len);
// };


struct ChapStateFlags
{
    bool lower_up;
    bool auth_started;
    bool auth_failed;
    bool timeout_pending;
    bool challenge_valid;
    bool auth_done;
};


inline void clear_chap_state_flags(ChapStateFlags& flags)
{
    flags.lower_up = false;
    flags.auth_started = false;
    flags.auth_failed = false;
    flags.timeout_pending = false;
    flags.challenge_valid = false;
    flags.auth_done = false;
}


/*
 * Each interface is described by chap structure.
 */
struct ChapClientState
{
    ChapStateFlags flags;
    std::string name;
    // ChapDigestType digest;
    std::vector<uint8_t> priv; /* private area for digest's use */

};


struct ChapServerState
{
    ChapStateFlags flags;
    uint8_t id;
    std::string name;
    // ChapDigestType digest;
    ChapDigestCode digest_code;
    size_t challenge_xmits;
    size_t challenge_pktlen;
    std::vector<uint8_t> challenge;
};


/* Called by authentication code to start authenticating the peer. */
extern void chap_auth_peer(PppPcb& pcb, std::string& our_name, int digest_code);


/* Called by auth. code to start authenticating us to the peer. */
bool chap_auth_with_peer(PppPcb& pcb, std::string& our_name, int digest_code);

/* Represents the CHAP protocol to the main pppd code */
extern const struct Protent kChapProtent;

bool
chap_init(PppPcb& pcb);

bool
chap_lowerup(PppPcb& pcb);

bool
chap_lower_down(PppPcb& pcb);

bool
chap_timeout(PppPcb& pcb);

void chap_generate_challenge(PppPcb& pcb);

bool
chap_handle_response(PppPcb& pcb, int code, std::vector<uint8_t>& pkt);


bool
chap_verify_response(PppPcb& pcb,
                     std::string& name,
                     std::string& ourname,
                     int id,
                     std::vector<uint8_t>& challenge,
                     std::vector<uint8_t>& response,
                     std::string& message,
                     int message_space);

bool
chap_respond(PppPcb& pcb,
             int id,
             std::vector<uint8_t>& pkt_data);

bool
chap_handle_status(PppPcb& pcb,
                   int code,
                   int id,
                   std::vector<uint8_t>& pkt);

bool
chap_protrej(PppPcb& pcb);

bool
chap_input(PppPcb& pcb, std::vector<uint8_t>& pkt);

//
// END OF FILE
//