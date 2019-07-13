
#include "ppp_opts.h"
#include "ppp_impl.h"
#include "chap_new.h"
#include "chap_ms.h"
#include "pppcrypt.h"
#include "magic.h"
#include "mppe.h" /* For mppe_sha1_pad*, mppe_set_key() */
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
static void chapms_generate_challenge(PppPcb* pcb, unsigned char* challenge)
{
    *challenge++ = 8;
    if (mschap_challenge && strlen(mschap_challenge) == 8)
        memcpy(challenge, mschap_challenge, 8);
    else
        magic_random_bytes(challenge, 8);
}

static void chapms2_generate_challenge(PppPcb* pcb, unsigned char* challenge)
{
    *challenge++ = 16;
    if (mschap_challenge && strlen(mschap_challenge) == 16)
        memcpy(challenge, mschap_challenge, 16);
    else
        magic_random_bytes(challenge, 16);
}

static int chapms_verify_response(PppPcb* pcb,
                                  int id,
                                  const char* name,
                                  const unsigned char* secret,
                                  const int secret_len,
                                  const unsigned char* challenge,
                                  const unsigned char* response,
                                  char* message,
                                  const int message_space)
{
    unsigned char md[MS_CHAP_RESPONSE_LEN];
    int diff;
    const int challenge_len = *challenge++; /* skip length, is 8 */
    const int response_len = *response++;
    if (response_len != MS_CHAP_RESPONSE_LEN)
    {
        ppp_slprintf(message,
                     message_space,
                     "E=691 R=1 C=%0.*B V=0",
                     challenge_len,
                     challenge);
        return 0;
    }
    if (!response[MS_CHAP_USENT])
    {
        /* Should really propagate this into the error packet. */
        ppp_notice("Peer request for LANMAN auth not supported");
        ppp_slprintf(message,
                     message_space,
                     "E=691 R=1 C=%0.*B V=0",
                     challenge_len,
                     challenge);
        return 0;
    } /* Generate the expected response. */
    ChapMS(pcb,
           static_cast<const uint8_t *>(challenge),
           reinterpret_cast<const char *>(secret),
           secret_len,
           md); /* Determine which part of response to verify against */
    if (!response[MS_CHAP_USENT])
        diff = memcmp(&response[MS_CHAP_LANMANRESP],
                      &md[MS_CHAP_LANMANRESP],
                      MS_CHAP_LANMANRESP_LEN);
    else
        diff = memcmp(&response[MS_CHAP_NTRESP], &md[MS_CHAP_NTRESP], MS_CHAP_NTRESP_LEN);
    if (diff == 0)
    {
        ppp_slprintf(message, message_space, "Access granted");
        return 1;
    }
    ppp_slprintf(message,
                 message_space,
                 "E=691 R=1 C=%0.*B V=0",
                 challenge_len,
                 challenge);
    return 0;
}

static int chapms2_verify_response(PppPcb* pcb,
                                   int id,
                                   const char* name,
                                   const unsigned char* secret,
                                   int secret_len,
                                   const unsigned char* challenge,
                                   const unsigned char* response,
                                   char* message,
                                   int message_space)
{
    unsigned char md[MS_CHAP2_RESPONSE_LEN];
    char saresponse[MS_AUTH_RESPONSE_LENGTH + 1];
    const int challenge_len = *challenge++; /* skip length, is 16 */
    const int response_len = *response++;
    if (response_len != MS_CHAP2_RESPONSE_LEN)
    {
        ppp_slprintf(message,
                     message_space,
                     "E=691 R=1 C=%0.*B V=0 M=%s",
                     challenge_len,
                     challenge,
                     "Access denied");
        return 0; /* not even the right length */
    } /* Generate the expected response and our mutual auth. */
    ChapMS2(pcb,
            static_cast<const uint8_t*>(challenge),
            static_cast<const uint8_t*>(&response[MS_CHAP2_PEER_CHALLENGE]),
            name,
            reinterpret_cast<const char *>(secret),
            secret_len,
            md,
            reinterpret_cast<unsigned char *>(saresponse),
            MS_CHAP2_AUTHENTICATOR); /* compare MDs and send the appropriate status */ /*
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
    if (memcmp(&md[MS_CHAP2_NTRESP],
               &response[MS_CHAP2_NTRESP],
               MS_CHAP2_NTRESP_LEN) == 0)
    {
        if (response[MS_CHAP2_FLAGS])
            ppp_slprintf(message, message_space, "S=%s", saresponse);
        else
            ppp_slprintf(message,
                         message_space,
                         "S=%s M=%s",
                         saresponse,
                         "Access granted");
        return 1;
    }
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
	 */ ppp_slprintf(message,
                     message_space,
                     "E=691 R=1 C=%0.*B V=0 M=%s",
                     challenge_len,
                     challenge,
                     "Access denied");
    return 0;
}

static void chapms_make_response(PppPcb* pcb,
                                 unsigned char* response,
                                 int id,
                                 const char* our_name,
                                 const unsigned char* challenge,
                                 const char* secret,
                                 int secret_len,
                                 unsigned char* private_)
{
    challenge++; /* skip length, should be 8 */
    *response++ = MS_CHAP_RESPONSE_LEN;
    ChapMS(pcb, challenge, secret, secret_len, response);
}

static void chapms2_make_response(PppPcb* pcb,
                                  unsigned char* response,
                                  int id,
                                  const char* our_name,
                                  const unsigned char* challenge,
                                  const char* secret,
                                  int secret_len,
                                  unsigned char* private_)
{
    challenge++; /* skip length, should be 16 */
    *response++ = MS_CHAP2_RESPONSE_LEN;
    ChapMS2(pcb,
            challenge,
            nullptr,
            our_name,
            secret,
            secret_len,
            response,
            private_,
            MS_CHAP2_AUTHENTICATEE);
}

static int chapms2_check_success(PppPcb* pcb,
                                 unsigned char* msg,
                                 int len,
                                 unsigned char* private_)
{
    if ((len < MS_AUTH_RESPONSE_LENGTH + 2) || strncmp((char *)msg, "S=", 2) != 0)
    {
        /* Packet does not start with "S=" */
        ppp_error("MS-CHAPv2 Success packet is badly formed.");
        return 0;
    }
    msg += 2;
    len -= 2;
    if (len < MS_AUTH_RESPONSE_LENGTH || memcmp(msg, private_, MS_AUTH_RESPONSE_LENGTH))
    {
        /* Authenticator Response did not match expected. */
        ppp_error("MS-CHAPv2 mutual authentication failed.");
        return 0;
    } /* Authenticator Response matches. */
    msg += MS_AUTH_RESPONSE_LENGTH; /* Eat it */
    len -= MS_AUTH_RESPONSE_LENGTH;
    if ((len >= 3) && !strncmp((char *)msg, " M=", 3))
    {
        msg += 3; /* Eat the delimiter */
    }
    else if (len)
    {
        /* Packet has extra text which does not begin " M=" */
        ppp_error("MS-CHAPv2 Success packet is badly formed.");
        return 0;
    }
    return 1;
}

static void chapms_handle_failure(PppPcb* pcb, unsigned char* inp, int len)
{
    int err;
    const char* p;
    char msg[64]; /* We want a null-terminated string for strxxx(). */
    len = LWIP_MIN(len, 63);
    MEMCPY(msg, inp, len);
    msg[len] = 0;
    p = msg; /*
	 * Deal with MS-CHAP formatted failure messages; just print the
	 * M=<message> part (if any).  For MS-CHAP we're not really supposed
	 * to use M=<message>, but it shouldn't hurt.  See
	 * chapms[2]_verify_response.
	 */
    if (!strncmp(p, "E=", 2))
        err = strtol(p + 2, nullptr, 10); /* Remember the error code. */ else
        goto print_msg; /* Message is badly formatted. */
    if (len && ((p = strstr(p, " M=")) != nullptr))
    {
        /* M=<message> field found. */
        p += 3;
    }
    else
    {
        /* No M=<message>; use the error code. */
        switch (err)
        {
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
            /* Should never see this, we don't support Change Password. */ p =
                "E=709 Error changing password";
            break;
        default:
            ppp_error("Unknown MS-CHAP authentication failure: %.*v", len, inp);
            return;
        }
    }
print_msg: if (p != nullptr)
        ppp_error("MS-CHAP authentication failed: %v", p);
}

static void ChallengeResponse(const uint8_t* challenge,
                              const uint8_t password_hash[MD4_SIGNATURE_SIZE],
                              uint8_t response[24])
{
    uint8_t ZPasswordHash[21];
    lwip_des_context des;
    uint8_t des_key[8];
    BZERO(ZPasswordHash, sizeof(ZPasswordHash));
    MEMCPY(ZPasswordHash, password_hash, MD4_SIGNATURE_SIZE);
    pppcrypt_56_to_64_bit_key(ZPasswordHash + 0, des_key);
    // lwip_des_init(&des);
    des_setkey_enc(&des, des_key);
    des_crypt_ecb(&des, challenge, response + 0);
    // lwip_des_free(&des);
    pppcrypt_56_to_64_bit_key(ZPasswordHash + 7, des_key);
    // lwip_des_init(&des);
    des_setkey_enc(&des, des_key);
    des_crypt_ecb(&des, challenge, response + 8);
    // lwip_des_free(&des);
    pppcrypt_56_to_64_bit_key(ZPasswordHash + 14, des_key);
    // lwip_des_init(&des);
    des_setkey_enc(&des, des_key);
    des_crypt_ecb(&des, challenge, response + 16);
    // lwip_des_free(&des);
}

static void ChallengeHash(const uint8_t PeerChallenge[16],
                          const uint8_t* rchallenge,
                          const char* username,
                          uint8_t Challenge[8])
{
    lwip_sha1_context sha1Context;
    uint8_t sha1Hash[SHA1_SIGNATURE_SIZE];
    const char* user; /* remove domain from "domain\username" */
    if ((user = strrchr(username, '\\')) != nullptr)
        ++user;
    else
        user = username;
    lwip_sha1_init(&sha1Context);
    lwip_sha1_starts(&sha1Context);
    lwip_sha1_update(&sha1Context, PeerChallenge, 16);
    lwip_sha1_update(&sha1Context, rchallenge, 16);
    lwip_sha1_update(&sha1Context, reinterpret_cast<const unsigned char*>(user), strlen(user));
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
static void ascii2unicode(const char ascii[], int ascii_len, uint8_t unicode[])
{
    int i;
    BZERO(unicode, ascii_len * 2);
    for (i = 0; i < ascii_len; i++)
        unicode[i * 2] = (uint8_t)ascii[i];
}

static void NTPasswordHash(uint8_t* secret,
                           int secret_len,
                           uint8_t hash[MD4_SIGNATURE_SIZE])
{
    lwip_md4_context md4Context;
    lwip_md4_init(&md4Context);
    lwip_md4_starts(&md4Context);
    lwip_md4_update(&md4Context, secret, secret_len);
    lwip_md4_finish(&md4Context, hash);
    lwip_md4_free(&md4Context);
}

static void ChapMS_NT(const uint8_t* rchallenge,
                      const char* secret,
                      int secret_len,
                      uint8_t NTResponse[24])
{
    uint8_t unicodePassword[MAX_NT_PASSWORD * 2];
    uint8_t PasswordHash[MD4_SIGNATURE_SIZE];
    /* Hash the Unicode version of the secret (== password). */
    ascii2unicode(secret, secret_len, unicodePassword);
    NTPasswordHash(unicodePassword, secret_len * 2, PasswordHash);
    ChallengeResponse(rchallenge, PasswordHash, NTResponse);
}

static void ChapMS2_NT(const uint8_t* rchallenge,
                       const uint8_t PeerChallenge[16],
                       const char* username,
                       const char* secret,
                       int secret_len,
                       uint8_t NTResponse[24])
{
    uint8_t unicodePassword[MAX_NT_PASSWORD * 2];
    uint8_t PasswordHash[MD4_SIGNATURE_SIZE];
    uint8_t Challenge[8];
    ChallengeHash(PeerChallenge, rchallenge, username, Challenge);
    /* Hash the Unicode version of the secret (== password). */
    ascii2unicode(secret, secret_len, unicodePassword);
    NTPasswordHash(unicodePassword, secret_len * 2, PasswordHash);
    ChallengeResponse(Challenge, PasswordHash, NTResponse);
}

static void ChapMsLanMan(const uint8_t* rchallenge,
                         const char* secret,
                         const int secret_len,
                         uint8_t* response)
{
    uint8_t ucase_password[MAX_NT_PASSWORD]; /* max is actually 14 */
    uint8_t password_hash[MD4_SIGNATURE_SIZE];
    des_context des;
    uint8_t des_key[8]; /* LANMan password is case insensitive */
    BZERO(ucase_password, sizeof(ucase_password));
    for (auto i = 0; i < secret_len; i++)
        ucase_password[i] = static_cast<uint8_t>(toupper(secret[i]));
    pppcrypt_56_to_64_bit_key(ucase_password + 0, des_key); // lwip_des_init(&des);
    des_setkey_enc(&des, des_key);
    des_crypt_ecb(&des, StdText, password_hash + 0); // lwip_des_free(&des);
    pppcrypt_56_to_64_bit_key(ucase_password + 7, des_key); // lwip_des_init(&des);
    des_setkey_enc(&des, des_key);
    des_crypt_ecb(&des, StdText, password_hash + 8); // lwip_des_free(&des);
    ChallengeResponse(rchallenge, password_hash, &response[MS_CHAP_LANMANRESP]);
}

static void GenerateAuthenticatorResponse(
    const uint8_t PasswordHashHash[MD4_SIGNATURE_SIZE],
    uint8_t NTResponse[24],
    const uint8_t PeerChallenge[16],
    const uint8_t* rchallenge,
    const char* username,
    uint8_t authResponse[MS_AUTH_RESPONSE_LENGTH + 1])
{
    int i;
    lwip_sha1_context sha1Context;
    uint8_t Digest[SHA1_SIGNATURE_SIZE];
    uint8_t Challenge[8];
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
    lwip_sha1_free(&sha1Context); /* Convert to ASCII hex string. */
    for (i = 0; i < LWIP_MAX((MS_AUTH_RESPONSE_LENGTH / 2), (int)sizeof(Digest)); i++)
        sprintf((char *)&authResponse[i * 2], "%02X", Digest[i]);
}

static void GenerateAuthenticatorResponsePlain(const char* secret,
                                               int secret_len,
                                               uint8_t NTResponse[24],
                                               const uint8_t PeerChallenge[16],
                                               const uint8_t* rchallenge,
                                               const char* username,
                                               uint8_t authResponse[
                                                   MS_AUTH_RESPONSE_LENGTH + 1])
{
    uint8_t unicodePassword[MAX_NT_PASSWORD * 2];
    uint8_t PasswordHash[MD4_SIGNATURE_SIZE];
    uint8_t PasswordHashHash[MD4_SIGNATURE_SIZE];
    /* Hash (x2) the Unicode version of the secret (== password). */
    ascii2unicode(secret, secret_len, unicodePassword);
    NTPasswordHash(unicodePassword, secret_len * 2, PasswordHash);
    NTPasswordHash(PasswordHash, sizeof(PasswordHash), PasswordHashHash);
    GenerateAuthenticatorResponse(PasswordHashHash,
                                  NTResponse,
                                  PeerChallenge,
                                  rchallenge,
                                  username,
                                  authResponse);
}

/*
 * Set mppe_xxxx_key from MS-CHAP credentials. (see RFC 3079)
 */
static void Set_Start_Key(PppPcb* pcb,
                          const uint8_t* rchallenge,
                          const char* secret,
                          int secret_len)
{
    uint8_t unicodePassword[MAX_NT_PASSWORD * 2];
    uint8_t PasswordHash[MD4_SIGNATURE_SIZE];
    uint8_t PasswordHashHash[MD4_SIGNATURE_SIZE];
    lwip_sha1_context sha1Context;
    uint8_t Digest[SHA1_SIGNATURE_SIZE]; /* >= MPPE_MAX_KEY_LEN */
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
    lwip_sha1_free(&sha1Context); /* Same key in both directions. */
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



    /* Hash (x2) the Unicode version of the secret (== password). */
    ascii2unicode(secret, secret_len, unicodePassword);
    NTPasswordHash(unicodePassword, secret_len * 2, PasswordHash);
    NTPasswordHash(PasswordHash, sizeof(PasswordHash), PasswordHashHash);

    lwip_sha1_init(&sha1Context);
    lwip_sha1_starts(&sha1Context);
    lwip_sha1_update(&sha1Context, PasswordHashHash, MD4_SIGNATURE_SIZE);
    lwip_sha1_update(&sha1Context, NTResponse, 24);
    lwip_sha1_update(&sha1Context, Magic4, sizeof(Magic4));
    lwip_sha1_finish(&sha1Context, MasterKey);
    lwip_sha1_free(&sha1Context);

    /*
     * generate send key
     */
    if (IsServer)
	s = Magic3;
    else
	s = Magic5;
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
	s = Magic5;
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

static void ChapMS(PppPcb* pcb,
                   const uint8_t* rchallenge,
                   const char* secret,
                   int secret_len,
                   unsigned char* response)
{
    BZERO(response, MS_CHAP_RESPONSE_LEN);
    ChapMS_NT(rchallenge, secret, secret_len, &response[MS_CHAP_NTRESP]);
    ChapMsLanMan(rchallenge, secret, secret_len, &response[MS_CHAP_LANMANRESP]);
    /* preferred method is set by option  */
    response[MS_CHAP_USENT] = !ms_lanman;
    Set_Start_Key(pcb, rchallenge, secret, secret_len);
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
static void ChapMS2(PppPcb* pcb,
                    const uint8_t* rchallenge,
                    const uint8_t* PeerChallenge,
                    const char* user,
                    const char* secret,
                    int secret_len,
                    unsigned char* response,
                    uint8_t authResponse[],
                    int authenticator)
{
    /* ARGSUSED */
    BZERO(response, MS_CHAP2_RESPONSE_LEN);
    /* Generate the Peer-Challenge if requested, or copy it if supplied. */
    if (!PeerChallenge)
        magic_random_bytes(&response[MS_CHAP2_PEER_CHALLENGE], MS_CHAP2_PEER_CHAL_LEN);
    else MEMCPY(&response[MS_CHAP2_PEER_CHALLENGE],
                PeerChallenge,
                MS_CHAP2_PEER_CHAL_LEN); /* Generate the NT-Response */
    ChapMS2_NT(rchallenge,
               &response[MS_CHAP2_PEER_CHALLENGE],
               user,
               secret,
               secret_len,
               &response[MS_CHAP2_NTRESP]); /* Generate the Authenticator Response. */
    GenerateAuthenticatorResponsePlain(secret,
                                       secret_len,
                                       &response[MS_CHAP2_NTRESP],
                                       &response[MS_CHAP2_PEER_CHALLENGE],
                                       rchallenge,
                                       user,
                                       authResponse);
    SetMasterKeys(pcb, secret, secret_len, &response[MS_CHAP2_NTRESP], authenticator);
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
