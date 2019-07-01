/*
 * chap_ms.c - Microsoft MS-CHAP compatible implementation.
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
 */

/*
 * Modifications by Lauri Pesonen / lpesonen@clinet.fi, april 1997
 *
 *   Implemented LANManager type password response to MS-CHAP challenges.
 *   Now pppd provides both NT style and LANMan style blocks, and the
 *   prefered is set by option "ms-lanman". Default is to use NT.
 *   The hash text (StdText) was taken from Win95 RASAPI32.DLL.
 *
 *   You should also use DOMAIN\\USERNAME as described in README.MSCHAP80
 */

/*
 * Modifications by Frank Cusack, frank@google.com, March 2002.
 *
 *   Implemented MS-CHAPv2 functionality, heavily based on sample
 *   implementation in RFC 2759.  Implemented MPPE functionality,
 *   heavily based on sample implementation in RFC 3079.
 *
 * Copyright (c) 2002 Google, Inc.  All rights reserved.
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
 */

#include "ppp_opts.h"
#include "ppp_impl.h"
#include "chap-new.h"
#include "chap_ms.h"
#include "pppcrypt.h"
#include "magic.h"
#include "mppe.h" /* For mppe_sha1_pad*, mppe_set_key() */


#define SHA1_SIGNATURE_SIZE	20
#define MD4_SIGNATURE_SIZE	16	/* 16 bytes in a MD4 message digest */
#define MAX_NT_PASSWORD		256	/* Max (Unicode) chars in an NT pass */

#define MS_CHAP_RESPONSE_LEN	49	/* Response length for MS-CHAP */
#define MS_CHAP2_RESPONSE_LEN	49	/* Response length for MS-CHAPv2 */
#define MS_AUTH_RESPONSE_LENGTH	40	/* MS-CHAPv2 authenticator response, */
					/* as ASCII */

/* Error codes for MS-CHAP failure messages. */
#define MS_CHAP_ERROR_RESTRICTED_LOGON_HOURS	646
#define MS_CHAP_ERROR_ACCT_DISABLED		647
#define MS_CHAP_ERROR_PASSWD_EXPIRED		648
#define MS_CHAP_ERROR_NO_DIALIN_PERMISSION	649
#define MS_CHAP_ERROR_AUTHENTICATION_FAILURE	691
#define MS_CHAP_ERROR_CHANGING_PASSWORD		709

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

#if MPPE_SUPPORT
#if 0 /* UNUSED */
/* These values are the RADIUS attribute values--see RFC 2548. */
#define MPPE_ENC_POL_ENC_ALLOWED 1
#define MPPE_ENC_POL_ENC_REQUIRED 2
#define MPPE_ENC_TYPES_RC4_40 2
#define MPPE_ENC_TYPES_RC4_128 4

/* used by plugins (using above values) */
extern void set_mppe_enc_types(int, int);
#endif /* UNUSED */
#endif /* MPPE_SUPPORT */

/* Are we the authenticator or authenticatee?  For MS-CHAPv2 key derivation. */
#define MS_CHAP2_AUTHENTICATEE 0
#define MS_CHAP2_AUTHENTICATOR 1

static void	ascii2unicode (const char[], int, uint8_t[]);
static void	NTPasswordHash (uint8_t *, int, uint8_t[MD4_SIGNATURE_SIZE]);
static void	ChallengeResponse (const uint8_t *, const uint8_t *, uint8_t[24]);
static void	ChallengeHash (const uint8_t[16], const uint8_t *, const char *, uint8_t[8]);
static void	ChapMS_NT (const uint8_t *, const char *, int, uint8_t[24]);
static void	ChapMS2_NT (const uint8_t *, const uint8_t[16], const char *, const char *, int,
				uint8_t[24]);
static void	GenerateAuthenticatorResponsePlain
			(const char*, int, uint8_t[24], const uint8_t[16], const uint8_t *,
			     const char *, uint8_t[41]);
#ifdef MSLANMAN
static void	ChapMS_LANMan (uint8_t *, char *, int, uint8_t *);
#endif

static void GenerateAuthenticatorResponse(const uint8_t PasswordHashHash[MD4_SIGNATURE_SIZE],
			uint8_t NTResponse[24], const uint8_t PeerChallenge[16],
			const uint8_t *rchallenge, const char *username,
			uint8_t authResponse[MS_AUTH_RESPONSE_LENGTH+1]);


static void	Set_Start_Key (PppPcb *pcb, const uint8_t *, const char *, int);
static void	SetMasterKeys (PppPcb *pcb, const char *, int, uint8_t[24], int);


static void ChapMS (PppPcb *pcb, const uint8_t *, const char *, int, uint8_t *);
static void ChapMS2 (PppPcb *pcb, const uint8_t *, const uint8_t *, const char *, const char *, int,
		  uint8_t *, uint8_t[MS_AUTH_RESPONSE_LENGTH+1], int);

bool	ms_lanman = 0;    	/* Use LanMan password instead of NT */
			  	/* Has meaning only with MS-CHAP challenges */


/* For MPPE debug */
/* Use "[]|}{?/><,`!2&&(" (sans quotes) for RFC 3079 MS-CHAPv2 test value */
static char *mschap_challenge = nullptr;
/* Use "!@\#$%^&*()_+:3|~" (sans quotes, backslash is to escape #) for ... */
static char *mschap2_peer_challenge = nullptr;


#include "fsm.h"		/* Need to poke MPPE options */
#include "ccp.h"


// /*
//  * Command-line options.
//  */
// static option_t chapms_option_list[] = {
// #ifdef MSLANMAN
// 	{ "ms-lanman", o_bool, &ms_lanman,
// 	  "Use LanMan passwd when using MS-CHAP", 1 },
// #endif
// #ifdef DEBUGMPPEKEY
// 	{ "mschap-challenge", o_string, &mschap_challenge,
// 	  "specify CHAP challenge" },
// 	{ "mschap2-peer-challenge", o_string, &mschap2_peer_challenge,
// 	  "specify CHAP peer challenge" },
// #endif
// 	{ NULL }
// };

/*
 * chapms_generate_challenge - generate a challenge for MS-CHAP.
 * For MS-CHAP the challenge length is fixed at 8 bytes.
 * The length goes in challenge[0] and the actual challenge starts
 * at challenge[1].
 */
static void chapms_generate_challenge(PppPcb *pcb, unsigned char *challenge) {
	LWIP_UNUSED_ARG(pcb);

	*challenge++ = 8;
#ifdef DEBUGMPPEKEY
	if (mschap_challenge && strlen(mschap_challenge) == 8)
		memcpy(challenge, mschap_challenge, 8);
	else
#endif
		magic_random_bytes(challenge, 8);
}

static void chapms2_generate_challenge(PppPcb *pcb, unsigned char *challenge) {
	LWIP_UNUSED_ARG(pcb);

	*challenge++ = 16;
#ifdef DEBUGMPPEKEY
	if (mschap_challenge && strlen(mschap_challenge) == 16)
		memcpy(challenge, mschap_challenge, 16);
	else
#endif
		magic_random_bytes(challenge, 16);
}

static int chapms_verify_response(PppPcb *pcb, int id, const char *name,
		       const unsigned char *secret, int secret_len,
		       const unsigned char *challenge, const unsigned char *response,
		       char *message, int message_space) {
	unsigned char md[MS_CHAP_RESPONSE_LEN];
	int diff;
	int challenge_len, response_len;
	LWIP_UNUSED_ARG(id);
	LWIP_UNUSED_ARG(name);

	challenge_len = *challenge++;	/* skip length, is 8 */
	response_len = *response++;
	if (response_len != MS_CHAP_RESPONSE_LEN)
		goto bad;

#ifndef MSLANMAN
	if (!response[MS_CHAP_USENT]) {
		/* Should really propagate this into the error packet. */
		ppp_notice("Peer request for LANMAN auth not supported");
		goto bad;
	}
#endif

	/* Generate the expected response. */
	ChapMS(pcb, (const uint8_t *)challenge, (const char *)secret, secret_len, md);

#ifdef MSLANMAN
	/* Determine which part of response to verify against */
	if (!response[MS_CHAP_USENT])
		diff = memcmp(&response[MS_CHAP_LANMANRESP],
			      &md[MS_CHAP_LANMANRESP], MS_CHAP_LANMANRESP_LEN);
	else
#endif
		diff = memcmp(&response[MS_CHAP_NTRESP], &md[MS_CHAP_NTRESP],
			      MS_CHAP_NTRESP_LEN);

	if (diff == 0) {
		ppp_slprintf(message, message_space, "Access granted");
		return 1;
	}

 bad:
	/* See comments below for MS-CHAP V2 */
	ppp_slprintf(message, message_space, "E=691 R=1 C=%0.*B V=0",
		 challenge_len, challenge);
	return 0;
}

static int chapms2_verify_response(PppPcb *pcb, int id, const char *name,
			const unsigned char *secret, int secret_len,
			const unsigned char *challenge, const unsigned char *response,
			char *message, int message_space) {
	unsigned char md[MS_CHAP2_RESPONSE_LEN];
	char saresponse[MS_AUTH_RESPONSE_LENGTH+1];
	int challenge_len, response_len;
	LWIP_UNUSED_ARG(id);

	challenge_len = *challenge++;	/* skip length, is 16 */
	response_len = *response++;
	if (response_len != MS_CHAP2_RESPONSE_LEN)
		goto bad;	/* not even the right length */

	/* Generate the expected response and our mutual auth. */
	ChapMS2(pcb, (const uint8_t*)challenge, (const uint8_t*)&response[MS_CHAP2_PEER_CHALLENGE], name,
		(const char *)secret, secret_len, md,
		(unsigned char *)saresponse, MS_CHAP2_AUTHENTICATOR);

	/* compare MDs and send the appropriate status */
	/*
	 * Per RFC 2759, success message must be formatted as
	 *     "S=<auth_string> M=<message>"
	 * where
	 *     <auth_string> is the Authenticator Response (mutual auth)
	 *     <message> is a text message
	 *
	 * However, some versions of Windows (win98 tested) do not know
	 * about the M=<message> part (required per RFC 2759) and flag
	 * it as an error (reported incorrectly as an encryption error
	 * to the user).  Since the RFC requires it, and it can be
	 * useful information, we supply it if the peer is a conforming
	 * system.  Luckily (?), win98 sets the Flags field to 0x04
	 * (contrary to RFC requirements) so we can use that to
	 * distinguish between conforming and non-conforming systems.
	 *
	 * Special thanks to Alex Swiridov <say@real.kharkov.ua> for
	 * help debugging this.
	 */
	if (memcmp(&md[MS_CHAP2_NTRESP], &response[MS_CHAP2_NTRESP],
		   MS_CHAP2_NTRESP_LEN) == 0) {
		if (response[MS_CHAP2_FLAGS])
			ppp_slprintf(message, message_space, "S=%s", saresponse);
		else
			ppp_slprintf(message, message_space, "S=%s M=%s",
				 saresponse, "Access granted");
		return 1;
	}

 bad:
	/*
	 * Failure message must be formatted as
	 *     "E=e R=r C=c V=v M=m"
	 * where
	 *     e = error code (we use 691, ERROR_AUTHENTICATION_FAILURE)
	 *     r = retry (we use 1, ok to retry)
	 *     c = challenge to use for next response, we reuse previous
	 *     v = Change Password version supported, we use 0
	 *     m = text message
	 *
	 * The M=m part is only for MS-CHAPv2.  Neither win2k nor
	 * win98 (others untested) display the message to the user anyway.
	 * They also both ignore the E=e code.
	 *
	 * Note that it's safe to reuse the same challenge as we don't
	 * actually accept another response based on the error message
	 * (and no clients try to resend a response anyway).
	 *
	 * Basically, this whole bit is useless code, even the small
	 * implementation here is only because of overspecification.
	 */
	ppp_slprintf(message, message_space, "E=691 R=1 C=%0.*B V=0 M=%s",
		 challenge_len, challenge, "Access denied");
	return 0;
}


static void chapms_make_response(PppPcb *pcb, unsigned char *response, int id, const char *our_name,
		     const unsigned char *challenge, const char *secret, int secret_len,
		     unsigned char *private_) {
	LWIP_UNUSED_ARG(id);
	LWIP_UNUSED_ARG(our_name);
	LWIP_UNUSED_ARG(private_);
	challenge++;	/* skip length, should be 8 */
	*response++ = MS_CHAP_RESPONSE_LEN;
	ChapMS(pcb, challenge, secret, secret_len, response);
}

static void chapms2_make_response(PppPcb *pcb, unsigned char *response, int id, const char *our_name,
		      const unsigned char *challenge, const char *secret, int secret_len,
		      unsigned char *private_) {
	LWIP_UNUSED_ARG(id);
	challenge++;	/* skip length, should be 16 */
	*response++ = MS_CHAP2_RESPONSE_LEN;
	ChapMS2(pcb, challenge,
#ifdef DEBUGMPPEKEY
		mschap2_peer_challenge,
#else
		nullptr,
#endif
		our_name, secret, secret_len, response, private_,
		MS_CHAP2_AUTHENTICATEE);
}

static int chapms2_check_success(PppPcb *pcb, unsigned char *msg, int len, unsigned char *private_) {
	LWIP_UNUSED_ARG(pcb);

	if ((len < MS_AUTH_RESPONSE_LENGTH + 2) ||
	    strncmp((char *)msg, "S=", 2) != 0) {
		/* Packet does not start with "S=" */
		ppp_error("MS-CHAPv2 Success packet is badly formed.");
		return 0;
	}
	msg += 2;
	len -= 2;
	if (len < MS_AUTH_RESPONSE_LENGTH
	    || memcmp(msg, private_, MS_AUTH_RESPONSE_LENGTH)) {
		/* Authenticator Response did not match expected. */
		ppp_error("MS-CHAPv2 mutual authentication failed.");
		return 0;
	}
	/* Authenticator Response matches. */
	msg += MS_AUTH_RESPONSE_LENGTH; /* Eat it */
	len -= MS_AUTH_RESPONSE_LENGTH;
	if ((len >= 3) && !strncmp((char *)msg, " M=", 3)) {
		msg += 3; /* Eat the delimiter */
	} else if (len) {
		/* Packet has extra text which does not begin " M=" */
		ppp_error("MS-CHAPv2 Success packet is badly formed.");
		return 0;
	}
	return 1;
}

static void chapms_handle_failure(PppPcb *pcb, unsigned char *inp, int len) {
	int err;
	const char *p;
	char msg[64];
	LWIP_UNUSED_ARG(pcb);

	/* We want a null-terminated string for strxxx(). */
	len = LWIP_MIN(len, 63);
	MEMCPY(msg, inp, len);
	msg[len] = 0;
	p = msg;

	/*
	 * Deal with MS-CHAP formatted failure messages; just print the
	 * M=<message> part (if any).  For MS-CHAP we're not really supposed
	 * to use M=<message>, but it shouldn't hurt.  See
	 * chapms[2]_verify_response.
	 */
	if (!strncmp(p, "E=", 2))
		err = strtol(p+2, nullptr, 10); /* Remember the error code. */
	else
		goto print_msg; /* Message is badly formatted. */

	if (len && ((p = strstr(p, " M=")) != nullptr)) {
		/* M=<message> field found. */
		p += 3;
	} else {
		/* No M=<message>; use the error code. */
		switch (err) {
		case MS_CHAP_ERROR_RESTRICTED_LOGON_HOURS:
			p = "E=646 Restricted logon hours";
			break;

		case MS_CHAP_ERROR_ACCT_DISABLED:
			p = "E=647 Account disabled";
			break;

		case MS_CHAP_ERROR_PASSWD_EXPIRED:
			p = "E=648 Password expired";
			break;

		case MS_CHAP_ERROR_NO_DIALIN_PERMISSION:
			p = "E=649 No dialin permission";
			break;

		case MS_CHAP_ERROR_AUTHENTICATION_FAILURE:
			p = "E=691 Authentication failure";
			break;

		case MS_CHAP_ERROR_CHANGING_PASSWORD:
			/* Should never see this, we don't support Change Password. */
			p = "E=709 Error changing password";
			break;

		default:
			ppp_error("Unknown MS-CHAP authentication failure: %.*v",
			      len, inp);
			return;
		}
	}
print_msg:
	if (p != nullptr)
		ppp_error("MS-CHAP authentication failed: %v", p);
}

static void ChallengeResponse(const uint8_t* challenge,
                              const uint8_t PasswordHash[MD4_SIGNATURE_SIZE],
                              uint8_t response[24])
{
    uint8_t ZPasswordHash[21];
    lwip_des_context des;
    uint8_t des_key[8];

    BZERO(ZPasswordHash, sizeof(ZPasswordHash));
    MEMCPY(ZPasswordHash, PasswordHash, MD4_SIGNATURE_SIZE);

    pppcrypt_56_to_64_bit_key(ZPasswordHash + 0, des_key);
    lwip_des_init(&des);
    lwip_des_setkey_enc(&des, des_key);
    lwip_des_crypt_ecb(&des, challenge, response + 0);
    lwip_des_free(&des);

    pppcrypt_56_to_64_bit_key(ZPasswordHash + 7, des_key);
    lwip_des_init(&des);
    lwip_des_setkey_enc(&des, des_key);
    lwip_des_crypt_ecb(&des, challenge, response + 8);
    lwip_des_free(&des);

    pppcrypt_56_to_64_bit_key(ZPasswordHash + 14, des_key);
    lwip_des_init(&des);
    lwip_des_setkey_enc(&des, des_key);
    lwip_des_crypt_ecb(&des, challenge, response + 16);
    lwip_des_free(&des);
}

static void ChallengeHash(const uint8_t PeerChallenge[16], const uint8_t *rchallenge,
	      const char *username, uint8_t Challenge[8]) {
    lwip_sha1_context	sha1Context;
    uint8_t	sha1Hash[SHA1_SIGNATURE_SIZE];
    const char	*user;

    /* remove domain from "domain\username" */
    if ((user = strrchr(username, '\\')) != nullptr)
	++user;
    else
	user = username;

    lwip_sha1_init(&sha1Context);
    lwip_sha1_starts(&sha1Context);
    lwip_sha1_update(&sha1Context, PeerChallenge, 16);
    lwip_sha1_update(&sha1Context, rchallenge, 16);
    lwip_sha1_update(&sha1Context, (const unsigned char*)user, strlen(user));
    lwip_sha1_finish(&sha1Context, sha1Hash);
    lwip_sha1_free(&sha1Context);

    MEMCPY(Challenge, sha1Hash, 8);
}

/*
 * Convert the ASCII version of the password to Unicode.
 * This implicitly supports 8-bit ISO8859/1 characters.
 * This gives us the little-endian representation, which
 * is assumed by all M$ CHAP RFCs.  (Unicode byte ordering
 * is machine-dependent.)
 */
static void ascii2unicode(const char ascii[], int ascii_len, uint8_t unicode[]) {
    int i;

    BZERO(unicode, ascii_len * 2);
    for (i = 0; i < ascii_len; i++)
	unicode[i * 2] = (uint8_t) ascii[i];
}

static void NTPasswordHash(uint8_t *secret, int secret_len, uint8_t hash[MD4_SIGNATURE_SIZE]) {
    lwip_md4_context		md4Context;

    lwip_md4_init(&md4Context);
    lwip_md4_starts(&md4Context);
    lwip_md4_update(&md4Context, secret, secret_len);
    lwip_md4_finish(&md4Context, hash);
    lwip_md4_free(&md4Context);
}

static void ChapMS_NT(const uint8_t *rchallenge, const char *secret, int secret_len,
	  uint8_t NTResponse[24]) {
    uint8_t	unicodePassword[MAX_NT_PASSWORD * 2];
    uint8_t	PasswordHash[MD4_SIGNATURE_SIZE];

    /* Hash the Unicode version of the secret (== password). */
    ascii2unicode(secret, secret_len, unicodePassword);
    NTPasswordHash(unicodePassword, secret_len * 2, PasswordHash);

    ChallengeResponse(rchallenge, PasswordHash, NTResponse);
}

static void ChapMS2_NT(const uint8_t *rchallenge, const uint8_t PeerChallenge[16], const char *username,
	   const char *secret, int secret_len, uint8_t NTResponse[24]) {
    uint8_t	unicodePassword[MAX_NT_PASSWORD * 2];
    uint8_t	PasswordHash[MD4_SIGNATURE_SIZE];
    uint8_t	Challenge[8];

    ChallengeHash(PeerChallenge, rchallenge, username, Challenge);

    /* Hash the Unicode version of the secret (== password). */
    ascii2unicode(secret, secret_len, unicodePassword);
    NTPasswordHash(unicodePassword, secret_len * 2, PasswordHash);

    ChallengeResponse(Challenge, PasswordHash, NTResponse);
}

#ifdef MSLANMAN
static uint8_t *StdText = (uint8_t *)"KGS!@#$%"; /* key from rasapi32.dll */

static void ChapMS_LANMan(uint8_t *rchallenge, char *secret, int secret_len,
	      unsigned char *response) {
    int			i;
    uint8_t		UcasePassword[MAX_NT_PASSWORD]; /* max is actually 14 */
    uint8_t		PasswordHash[MD4_SIGNATURE_SIZE];
    lwip_des_context des;
    uint8_t des_key[8];

    /* LANMan password is case insensitive */
    BZERO(UcasePassword, sizeof(UcasePassword));
    for (i = 0; i < secret_len; i++)
       UcasePassword[i] = (uint8_t)toupper(secret[i]);

    pppcrypt_56_to_64_bit_key(UcasePassword +0, des_key);
    lwip_des_init(&des);
    lwip_des_setkey_enc(&des, des_key);
    lwip_des_crypt_ecb(&des, StdText, PasswordHash +0);
    lwip_des_free(&des);

    pppcrypt_56_to_64_bit_key(UcasePassword +7, des_key);
    lwip_des_init(&des);
    lwip_des_setkey_enc(&des, des_key);
    lwip_des_crypt_ecb(&des, StdText, PasswordHash +8);
    lwip_des_free(&des);

    ChallengeResponse(rchallenge, PasswordHash, &response[MS_CHAP_LANMANRESP]);
}
#endif


static void GenerateAuthenticatorResponse(const uint8_t PasswordHashHash[MD4_SIGNATURE_SIZE],
			      uint8_t NTResponse[24], const uint8_t PeerChallenge[16],
			      const uint8_t *rchallenge, const char *username,
			      uint8_t authResponse[MS_AUTH_RESPONSE_LENGTH+1]) {
    /*
     * "Magic" constants used in response generation, from RFC 2759.
     */
    static const uint8_t Magic1[39] = /* "Magic server to client signing constant" */
	{ 0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
	  0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
	  0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
	  0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74 };
    static const uint8_t Magic2[41] = /* "Pad to make it do more than one iteration" */
	{ 0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
	  0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
	  0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
	  0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
	  0x6E };

    int		i;
    lwip_sha1_context	sha1Context;
    uint8_t	Digest[SHA1_SIGNATURE_SIZE];
    uint8_t	Challenge[8];

    lwip_sha1_init(&sha1Context);
    lwip_sha1_starts(&sha1Context);
    lwip_sha1_update(&sha1Context, PasswordHashHash, MD4_SIGNATURE_SIZE);
    lwip_sha1_update(&sha1Context, NTResponse, 24);
    lwip_sha1_update(&sha1Context, Magic1, sizeof(Magic1));
    lwip_sha1_finish(&sha1Context, Digest);
    lwip_sha1_free(&sha1Context);

    ChallengeHash(PeerChallenge, rchallenge, username, Challenge);

    lwip_sha1_init(&sha1Context);
    lwip_sha1_starts(&sha1Context);
    lwip_sha1_update(&sha1Context, Digest, sizeof(Digest));
    lwip_sha1_update(&sha1Context, Challenge, sizeof(Challenge));
    lwip_sha1_update(&sha1Context, Magic2, sizeof(Magic2));
    lwip_sha1_finish(&sha1Context, Digest);
    lwip_sha1_free(&sha1Context);

    /* Convert to ASCII hex string. */
    for (i = 0; i < LWIP_MAX((MS_AUTH_RESPONSE_LENGTH / 2), (int)sizeof(Digest)); i++)
	sprintf((char *)&authResponse[i * 2], "%02X", Digest[i]);
}


static void GenerateAuthenticatorResponsePlain(
		 const char *secret, int secret_len,
		 uint8_t NTResponse[24], const uint8_t PeerChallenge[16],
		 const uint8_t *rchallenge, const char *username,
		 uint8_t authResponse[MS_AUTH_RESPONSE_LENGTH+1]) {
    uint8_t	unicodePassword[MAX_NT_PASSWORD * 2];
    uint8_t	PasswordHash[MD4_SIGNATURE_SIZE];
    uint8_t	PasswordHashHash[MD4_SIGNATURE_SIZE];

    /* Hash (x2) the Unicode version of the secret (== password). */
    ascii2unicode(secret, secret_len, unicodePassword);
    NTPasswordHash(unicodePassword, secret_len * 2, PasswordHash);
    NTPasswordHash(PasswordHash, sizeof(PasswordHash),
		   PasswordHashHash);

    GenerateAuthenticatorResponse(PasswordHashHash, NTResponse, PeerChallenge,
				  rchallenge, username, authResponse);
}


#if MPPE_SUPPORT
/*
 * Set mppe_xxxx_key from MS-CHAP credentials. (see RFC 3079)
 */
static void Set_Start_Key(PppPcb *pcb, const uint8_t *rchallenge, const char *secret, int secret_len) {
    uint8_t	unicodePassword[MAX_NT_PASSWORD * 2];
    uint8_t	PasswordHash[MD4_SIGNATURE_SIZE];
    uint8_t	PasswordHashHash[MD4_SIGNATURE_SIZE];
    lwip_sha1_context	sha1Context;
    uint8_t	Digest[SHA1_SIGNATURE_SIZE];	/* >= MPPE_MAX_KEY_LEN */

    /* Hash (x2) the Unicode version of the secret (== password). */
    ascii2unicode(secret, secret_len, unicodePassword);
    NTPasswordHash(unicodePassword, secret_len * 2, PasswordHash);
    NTPasswordHash(PasswordHash, sizeof(PasswordHash), PasswordHashHash);

    lwip_sha1_init(&sha1Context);
    lwip_sha1_starts(&sha1Context);
    lwip_sha1_update(&sha1Context, PasswordHashHash, MD4_SIGNATURE_SIZE);
    lwip_sha1_update(&sha1Context, PasswordHashHash, MD4_SIGNATURE_SIZE);
    lwip_sha1_update(&sha1Context, rchallenge, 8);
    lwip_sha1_finish(&sha1Context, Digest);
    lwip_sha1_free(&sha1Context);

    /* Same key in both directions. */
    mppe_set_key(pcb, &pcb->mppe_comp, Digest);
    mppe_set_key(pcb, &pcb->mppe_decomp, Digest);

    pcb->mppe_keys_set = 1;
}

/*
 * Set mppe_xxxx_key from MS-CHAPv2 credentials. (see RFC 3079)
 */
static void SetMasterKeys(PppPcb *pcb, const char *secret, int secret_len, uint8_t NTResponse[24], int IsServer) {
    uint8_t	unicodePassword[MAX_NT_PASSWORD * 2];
    uint8_t	PasswordHash[MD4_SIGNATURE_SIZE];
    uint8_t	PasswordHashHash[MD4_SIGNATURE_SIZE];
    lwip_sha1_context	sha1Context;
    uint8_t	MasterKey[SHA1_SIGNATURE_SIZE];	/* >= MPPE_MAX_KEY_LEN */
    uint8_t	Digest[SHA1_SIGNATURE_SIZE];	/* >= MPPE_MAX_KEY_LEN */
    const uint8_t *s;

    /* "This is the MPPE Master Key" */
    static const uint8_t Magic1[27] =
	{ 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74,
	  0x68, 0x65, 0x20, 0x4d, 0x50, 0x50, 0x45, 0x20, 0x4d,
	  0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x4b, 0x65, 0x79 };
    /* "On the client side, this is the send key; "
       "on the server side, it is the receive key." */
    static const uint8_t Magic2[84] =
	{ 0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
	  0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
	  0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
	  0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20, 0x6b, 0x65, 0x79,
	  0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73,
	  0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73, 0x69, 0x64, 0x65,
	  0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
	  0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
	  0x6b, 0x65, 0x79, 0x2e };
    /* "On the client side, this is the receive key; "
       "on the server side, it is the send key." */
    static const uint8_t Magic3[84] =
	{ 0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
	  0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
	  0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
	  0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
	  0x6b, 0x65, 0x79, 0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68,
	  0x65, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73,
	  0x69, 0x64, 0x65, 0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73,
	  0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20,
	  0x6b, 0x65, 0x79, 0x2e };

    /* Hash (x2) the Unicode version of the secret (== password). */
    ascii2unicode(secret, secret_len, unicodePassword);
    NTPasswordHash(unicodePassword, secret_len * 2, PasswordHash);
    NTPasswordHash(PasswordHash, sizeof(PasswordHash), PasswordHashHash);

    lwip_sha1_init(&sha1Context);
    lwip_sha1_starts(&sha1Context);
    lwip_sha1_update(&sha1Context, PasswordHashHash, MD4_SIGNATURE_SIZE);
    lwip_sha1_update(&sha1Context, NTResponse, 24);
    lwip_sha1_update(&sha1Context, Magic1, sizeof(Magic1));
    lwip_sha1_finish(&sha1Context, MasterKey);
    lwip_sha1_free(&sha1Context);

    /*
     * generate send key
     */
    if (IsServer)
	s = Magic3;
    else
	s = Magic2;
    lwip_sha1_init(&sha1Context);
    lwip_sha1_starts(&sha1Context);
    lwip_sha1_update(&sha1Context, MasterKey, 16);
    lwip_sha1_update(&sha1Context, mppe_sha1_pad1, SHA1_PAD_SIZE);
    lwip_sha1_update(&sha1Context, s, 84);
    lwip_sha1_update(&sha1Context, mppe_sha1_pad2, SHA1_PAD_SIZE);
    lwip_sha1_finish(&sha1Context, Digest);
    lwip_sha1_free(&sha1Context);

    mppe_set_key(pcb, &pcb->mppe_comp, Digest);

    /*
     * generate recv key
     */
    if (IsServer)
	s = Magic2;
    else
	s = Magic3;
    lwip_sha1_init(&sha1Context);
    lwip_sha1_starts(&sha1Context);
    lwip_sha1_update(&sha1Context, MasterKey, 16);
    lwip_sha1_update(&sha1Context, mppe_sha1_pad1, SHA1_PAD_SIZE);
    lwip_sha1_update(&sha1Context, s, 84);
    lwip_sha1_update(&sha1Context, mppe_sha1_pad2, SHA1_PAD_SIZE);
    lwip_sha1_finish(&sha1Context, Digest);
    lwip_sha1_free(&sha1Context);

    mppe_set_key(pcb, &pcb->mppe_decomp, Digest);

    pcb->mppe_keys_set = 1;
}

#endif /* MPPE_SUPPORT */


static void ChapMS(PppPcb *pcb, const uint8_t *rchallenge, const char *secret, int secret_len,
       unsigned char *response) {
#if !MPPE_SUPPORT
    LWIP_UNUSED_ARG(pcb);
#endif /* !MPPE_SUPPORT */
    BZERO(response, MS_CHAP_RESPONSE_LEN);

    ChapMS_NT(rchallenge, secret, secret_len, &response[MS_CHAP_NTRESP]);

#ifdef MSLANMAN
    ChapMS_LANMan(rchallenge, secret, secret_len,
		  &response[MS_CHAP_LANMANRESP]);

    /* preferred method is set by option  */
    response[MS_CHAP_USENT] = !ms_lanman;
#else
    response[MS_CHAP_USENT] = 1;
#endif

#if MPPE_SUPPORT
    Set_Start_Key(pcb, rchallenge, secret, secret_len);
#endif /* MPPE_SUPPORT */
}


/*
 * If PeerChallenge is NULL, one is generated and the PeerChallenge
 * field of response is filled in.  Call this way when generating a response.
 * If PeerChallenge is supplied, it is copied into the PeerChallenge field.
 * Call this way when verifying a response (or debugging).
 * Do not call with PeerChallenge = response.
 *
 * The PeerChallenge field of response is then used for calculation of the
 * Authenticator Response.
 */
static void ChapMS2(PppPcb *pcb, const uint8_t *rchallenge, const uint8_t *PeerChallenge,
	const char *user, const char *secret, int secret_len, unsigned char *response,
	uint8_t authResponse[], int authenticator) {
    /* ARGSUSED */
    LWIP_UNUSED_ARG(authenticator);
#if !MPPE_SUPPORT
    LWIP_UNUSED_ARG(pcb);
#endif /* !MPPE_SUPPORT */

    BZERO(response, MS_CHAP2_RESPONSE_LEN);

    /* Generate the Peer-Challenge if requested, or copy it if supplied. */
    if (!PeerChallenge)
	magic_random_bytes(&response[MS_CHAP2_PEER_CHALLENGE], MS_CHAP2_PEER_CHAL_LEN);
    else
	MEMCPY(&response[MS_CHAP2_PEER_CHALLENGE], PeerChallenge,
	      MS_CHAP2_PEER_CHAL_LEN);

    /* Generate the NT-Response */
    ChapMS2_NT(rchallenge, &response[MS_CHAP2_PEER_CHALLENGE], user,
	       secret, secret_len, &response[MS_CHAP2_NTRESP]);

    /* Generate the Authenticator Response. */
    GenerateAuthenticatorResponsePlain(secret, secret_len,
				       &response[MS_CHAP2_NTRESP],
				       &response[MS_CHAP2_PEER_CHALLENGE],
				       rchallenge, user, authResponse);

#if MPPE_SUPPORT
    SetMasterKeys(pcb, secret, secret_len,
		  &response[MS_CHAP2_NTRESP], authenticator);
#endif /* MPPE_SUPPORT */
}

#if 0 /* UNUSED */
#if MPPE_SUPPORT
/*
 * Set MPPE options from plugins.
 */
void set_mppe_enc_types(int policy, int types) {
    /* Early exit for unknown policies. */
    if (policy != MPPE_ENC_POL_ENC_ALLOWED ||
	policy != MPPE_ENC_POL_ENC_REQUIRED)
	return;

    /* Don't modify MPPE if it's optional and wasn't already configured. */
    if (policy == MPPE_ENC_POL_ENC_ALLOWED && !ccp_wantoptions[0].mppe)
	return;

    /*
     * Disable undesirable encryption types.  Note that we don't ENABLE
     * any encryption types, to avoid overriding manual configuration.
     */
    switch(types) {
	case MPPE_ENC_TYPES_RC4_40:
	    ccp_wantoptions[0].mppe &= ~MPPE_OPT_128;	/* disable 128-bit */
	    break;
	case MPPE_ENC_TYPES_RC4_128:
	    ccp_wantoptions[0].mppe &= ~MPPE_OPT_40;	/* disable 40-bit */
	    break;
	default:
	    break;
    }
}
#endif /* MPPE_SUPPORT */
#endif /* UNUSED */

const struct ChapDigestType kChapmsDigest = {
	CHAP_MICROSOFT,		/* code */
	chapms_generate_challenge,
	chapms_verify_response,
	chapms_make_response,
	nullptr,			/* check_success */
	chapms_handle_failure,
};

const struct ChapDigestType kChapms2Digest = {
	CHAP_MICROSOFT_V2,	/* code */
	chapms2_generate_challenge,
	chapms2_verify_response,
	chapms2_make_response,
	chapms2_check_success,
	chapms_handle_failure,
};
