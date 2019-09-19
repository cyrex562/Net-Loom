/*
 * chap_ms.h - Challenge Handshake Authentication Protocol definitions.
 *
 * Copyright (c) 1995 Eric Rosenquist.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name(s) of the authors of this software must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * $Id: chap_ms.h,v 1.13 2004/11/15 22:13:26 paulus Exp $
 */
#pragma once
#include "ns_ppp.h"
#include <string>
#include <vector>
extern const struct ChapDigestType CHAP_MS_DIGEST;
extern const struct ChapDigestType CHAP_MS_2_DIGEST;
const size_t LANMAN_KEY_LEN = 8;
constexpr auto SHA1_SIGNATURE_SIZE = 20;
constexpr auto MD4_SIGNATURE_SIZE = 16; /* 16 bytes in a MD4 message digest */
constexpr auto MAX_NT_PASSWORD = 256; /* Max (Unicode) chars in an NT pass */
constexpr auto MS_CHAP_RESPONSE_LEN = 49; /* Response length for MS-CHAP */
constexpr auto MS_CHAP2_RESPONSE_LEN = 49; /* Response length for MS-CHAPv2 */
constexpr auto MS_AUTH_RESPONSE_LENGTH =
    40; /* MS-CHAPv2 authenticator response,  as ASCII */

/* Error codes for MS-CHAP failure messages. */
enum MsChapErrorCode
{
    MS_CHAP_ERROR_RESTRICTED_LOGON_HOURS= 646,
    MS_CHAP_ERROR_ACCT_DISABLED = 647,
    MS_CHAP_ERROR_PASSWD_EXPIRED = 648,
    MS_CHAP_ERROR_NO_DIALIN_PERMISSION =649,
    MS_CHAP_ERROR_AUTHENTICATION_FAILURE =691,
    MS_CHAP_ERROR_CHANGING_PASSWORD = 709,
};


/*
 * Offsets within the response field for MS-CHAP
 */
#define MS_CHAP_LANMANRESP	0
#define MS_CHAP_LANMANRESP_LEN	24
#define MS_CHAP_NTRESP		24
#define MS_CHAP_NTRESP_LEN	24
#define MS_CHAP_USENT		48

/*
 * Offsets within the response field for MS-CHAP2
 */
#define MS_CHAP2_PEER_CHALLENGE	0
#define MS_CHAP2_PEER_CHAL_LEN	16
#define MS_CHAP2_RESERVED_LEN	8
#define MS_CHAP2_NTRESP		24
#define MS_CHAP2_NTRESP_LEN	24
#define MS_CHAP2_FLAGS		48

/* Are we the authenticator or authenticatee?  For MS-CHAPv2 key derivation. */
#define MS_CHAP2_AUTHENTICATEE 0
#define MS_CHAP2_AUTHENTICATOR 1

// void	ascii_to_unicode (const char[], int, uint8_t[]);


// bool	ms_lanman = false;    	/* Use LanMan password instead of NT */
                /* Has meaning only with MS-CHAP challenges */

/* For MPPE debug */
constexpr char* MSCHAP_CHALLENGE = "[]|}{?/><,`!2&&(";

constexpr char* MSCHAP2_PEER_CHALLENGE = "!@\#$%^&*()_+:3|~";

constexpr char* STD_TEXT = "KGS!@#$%";



/* Use "[]|}{?/><,`!2&&(" (sans quotes) for RFC 3079 MS-CHAPv2 test value */
// static char *mschap_challenge = nullptr;
/* Use "!@\#$%^&*()_+:3|~" (sans quotes, backslash is to escape #) for ... */
// static char *mschap2_peer_challenge = nullptr;

// static uint8_t* StdText = (uint8_t *)"KGS!@#$%"; /* key from rasapi32.dll */


/*
     * "Magic" constants used in response generation, from RFC 2759.
     */
/* "Magic server to client signing constant" */
static const uint8_t MAGIC_1[39] = {
    0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x74,
    0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69,
    0x6E, 0x67, 0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74
};

static const uint8_t MAGIC_2[41] = /* "Pad to make it do more than one iteration" */{
    0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B, 0x65, 0x20, 0x69, 0x74,
    0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F, 0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20,
    0x6F, 0x6E, 0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E
};

/* "This is the MPPE Master Key" */
static const uint8_t MAGIC4[27] = {
    0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20, 0x4d, 0x50,
    0x50, 0x45, 0x20, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x4b, 0x65, 0x79
};

/* "On the client side, this is the send key; "
       "on the server side, it is the receive key." */
static const uint8_t MAGIC5[84] = {
    0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20,
    0x73, 0x69, 0x64, 0x65, 0x2c, 0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
    0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20, 0x6b, 0x65, 0x79, 0x3b, 0x20,
    0x6f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20,
    0x73, 0x69, 0x64, 0x65, 0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
    0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20, 0x6b, 0x65, 0x79, 0x2e
};

/* "On the client side, this is the receive key;  on the server side, it is the send
 * key." */
static const uint8_t MAGIC3[84] = {
    0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20,
    0x73, 0x69, 0x64, 0x65, 0x2c, 0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
    0x74, 0x68, 0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20, 0x6b, 0x65,
    0x79, 0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x72, 0x76,
    0x65, 0x72, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73,
    0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20, 0x6b, 0x65, 0x79, 0x2e
};

std::vector<uint8_t>
nt_password_hash(std::vector<uint8_t>&);

std::tuple<bool, std::vector<uint8_t>>
challenge_response(std::vector<uint8_t>&, size_t challenge_offset, std::vector<uint8_t>&);

std::tuple<bool, std::vector<uint8_t>>
challenge_hash(std::vector<uint8_t>& peer_challenge, std::vector<uint8_t>&, std::string&);

void
chap_ms_nt(std::vector<uint8_t>& r_challenge,
           std::string&,
           std::vector<uint8_t>& nt_response,
           size_t challenge_offset,
           size_t response_offset);

std::tuple<bool, std::vector<uint8_t>>
chap_ms2_nt(std::vector<uint8_t>&, std::vector<uint8_t>&, std::string&, std::string&);

std::tuple<bool, std::vector<uint8_t>>
gen_authenticator_response_plain(std::string& secret,
                                 std::vector<uint8_t>& nt_response,
                                 std::vector<uint8_t>& peer_challenge,
                                 std::vector<uint8_t>& rchallenge,
                                 std::string& username);

std::tuple<bool, std::vector<uint8_t>>
chap_ms_lanman(std::vector<uint8_t>&, std::string&, size_t rchallenge_offset);

std::tuple<bool, std::vector<uint8_t>>
gen_authenticator_resp(std::vector<uint8_t>& password_hash_hash,
                       std::vector<uint8_t>& nt_response,
                       std::vector<uint8_t>& peer_challenge,
                       std::vector<uint8_t>& rchallenge,
                       std::string& username);

bool
set_start_key(::PppPcb& pcb, std::vector<uint8_t>&, std::string&);

bool
set_master_keys(PppPcb& pcb,
                std::string&,
                std::vector<uint8_t>& nt_response,
                bool is_server);

bool
chap_ms(PppPcb& pcb,
        std::vector<uint8_t>& challenge,
        std::string& secret,
        std::vector<uint8_t>& response,
        size_t challenge_offset,
        size_t response_offset);

std::tuple<bool, std::vector<uint8_t>, std::vector<uint8_t>>
chap_ms2(PppPcb& pcb,
         std::vector<uint8_t>& rchallenge,
         std::vector<uint8_t>& peer_challenge,
         std::string& user,
         std::string& secret,
         int authenticator);

//
// END OF FILE
//