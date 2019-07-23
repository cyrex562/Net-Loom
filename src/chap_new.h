/*
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
#include <ppp_opts.h>
#include <ppp_defs.h>


struct PppPcb;

/*
 * CHAP packets begin with a standard header with code, id, len (2 bytes).
 */
constexpr auto kChapHdrlen = 4;

/*
 * Values for the code field.
 */
constexpr auto CHAP_CHALLENGE = 1;
constexpr auto CHAP_RESPONSE = 2;
constexpr auto CHAP_SUCCESS = 3;
constexpr auto CHAP_FAILURE = 4;

/*
 * CHAP digest codes.
 */
constexpr auto CHAP_MD5 = 5;

constexpr auto CHAP_MICROSOFT = 0x80;
constexpr auto CHAP_MICROSOFT_V2 = 0x81;


/*
 * Semi-arbitrary limits on challenge and response fields.
 */
constexpr auto MAX_CHALLENGE_LEN = 64;
constexpr auto MAX_RESPONSE_LEN = 64;

/*
 * These limits apply to challenge and response packets we send.
 * The +4 is the +1 that we actually need rounded up.
 */
constexpr auto CHAL_MAX_PKTLEN = (PPP_HDRLEN + kChapHdrlen + 4 + MAX_CHALLENGE_LEN + MAXNAMELEN);
constexpr auto RESP_MAX_PKTLEN = (PPP_HDRLEN + kChapHdrlen + 4 + MAX_RESPONSE_LEN + MAXNAMELEN);

/* bitmask of supported algorithms */

constexpr auto MDTYPE_MICROSOFT_V2 = 0x1;
constexpr auto MDTYPE_MICROSOFT = 0x2;

constexpr auto MDTYPE_MD5 = 0x4;
constexpr auto MDTYPE_NONE = 0;


/* Return the digest alg. ID for the most preferred digest type. */
#define CHAP_DIGEST(mdtype) \
    ((mdtype) & MDTYPE_MD5)? CHAP_MD5: \
    ((mdtype) & MDTYPE_MICROSOFT_V2)? CHAP_MICROSOFT_V2: \
    ((mdtype) & MDTYPE_MICROSOFT)? CHAP_MICROSOFT: \
    0

/* Return the bit flag (lsb set) for our most preferred digest type. */
#define CHAP_MDTYPE(mdtype) ((mdtype) ^ ((mdtype) - 1)) & (mdtype)

/* Return the bit flag for a given digest algorithm ID. */

#define CHAP_MDTYPE_D(digest) \
    ((digest) == CHAP_MICROSOFT_V2)? MDTYPE_MICROSOFT_V2: \
    ((digest) == CHAP_MICROSOFT)? MDTYPE_MICROSOFT: \
    ((digest) == CHAP_MD5)? MDTYPE_MD5: \
    0


/* Can we do the requested digest? */

#define CHAP_CANDIGEST(mdtype, digest) \
    ((digest) == CHAP_MICROSOFT_V2)? (mdtype) & MDTYPE_MICROSOFT_V2: \
    ((digest) == CHAP_MICROSOFT)? (mdtype) & MDTYPE_MICROSOFT: \
    ((digest) == CHAP_MD5)? (mdtype) & MDTYPE_MD5: \
    0


/*
 * The code for each digest type has to supply one of these.
 */
struct ChapDigestType
{
    int code;


    /*
     * Note: challenge and response arguments below are formatted as
     * a length byte followed by the actual challenge/response data.
     */
    void (*generate_challenge)(PppPcb* pcb, unsigned char* challenge);

    int (*verify_response)(PppPcb* pcb,
                           int id,
                           const char* name,
                           const unsigned char* secret,
                           int secret_len,
                           const unsigned char* challenge,
                           const unsigned char* response,
                           char* message,
                           int message_space);

    void (*make_response)(PppPcb* pcb,
                          unsigned char* response,
                          int id,
                          const char* our_name,
                          const unsigned char* challenge,
                          const char* secret,
                          int secret_len,
                          unsigned char* priv);

    int (*check_success)(PppPcb* pcb, unsigned char* pkt, int len, unsigned char* priv);

    void (*handle_failure)(PppPcb* pcb, unsigned char* pkt, int len);
};


/*
 * Each interface is described by chap structure.
 */

typedef struct chap_client_state
{
    uint8_t flags;
    const char* name;
    const ChapDigestType* digest;
    unsigned char priv[64]; /* private area for digest's use */
} chap_client_state;


typedef struct chap_server_state
{
    uint8_t flags;
    uint8_t id;
    const char* name;
    const ChapDigestType* digest;
    int challenge_xmits;
    int challenge_pktlen;
    unsigned char challenge[CHAL_MAX_PKTLEN];
} chap_server_state;


/* Called by authentication code to start authenticating the peer. */
extern void chap_auth_peer(PppPcb* pcb, const char* our_name, int digest_code);


/* Called by auth. code to start authenticating us to the peer. */
extern void chap_auth_with_peer(PppPcb* pcb, const char* our_name, int digest_code);

/* Represents the CHAP protocol to the main pppd code */
extern const struct Protent kChapProtent;

static void chap_init(PppPcb* pcb);

static void chap_lowerup(PppPcb* pcb);

static void chap_lowerdown(PppPcb* pcb);

static void chap_timeout(void* arg);

static void chap_generate_challenge(PppPcb* pcb);

static void chap_handle_response(PppPcb* pcb,
                                 int code,
                                 unsigned char* pkt,
                                 size_t len,
                                 Protent** protocols);

int chap_verify_response(PppPcb* pcb,
                                const char* name,
                                const char* ourname,
                                int id,
                                const struct ChapDigestType* digest,
                                const unsigned char* challenge,
                                const unsigned char* response,
                                char* message,
                                int message_space);

static void chap_respond(PppPcb* pcb,
                         int id,
                         unsigned char* pkt,
                         int len);

static void chap_handle_status(PppPcb* pcb,
                               int code,
                               int id,
                               unsigned char* pkt,
                               int len,
                               Protent** protocols);

static void chap_protrej(PppPcb* pcb);

static void chap_input(PppPcb* pcb, unsigned char* pkt, int pktlen, Protent** protocols);
