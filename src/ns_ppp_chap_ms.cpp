#define NOMINMAX
#include "chap_ms.h"
#include "ns_ppp_chap_new.h"
#include "pppcrypt.h"
#include "magic.h"
#include "mppe.h"
#include "ns_ppp_ccp.h"
#include "util.h"
#include "spdlog/spdlog.h"
#include "mbedtls/des.h"
#include "mbedtls/sha1.h"
#include "mbedtls/md4.h"
#include <string>
#include <array>
#include <cstdint>
// #include <locale>
// #include <codecvt>

/**
 * chapms_generate_challenge - generate a challenge for MS-CHAP.
 * For MS-CHAP the challenge length is fixed at 8 bytes.
 * The length goes in challenge[0] and the actual challenge starts
 * at challenge[1].
 */
void
chapms_generate_challenge(PppPcb& pcb, std::vector<uint8_t>& challenge)
{
    size_t ptr = 0;
    challenge[ptr++] = 8;
    if (strlen(MSCHAP_CHALLENGE) == 8) memcpy(challenge.data(), MSCHAP_CHALLENGE, 8);
    else magic_random_bytes(challenge, 8, ptr);
}

/**
 *
 */
void
chapms2_generate_challenge(PppPcb& pcb, std::vector<uint8_t>& challenge)
{
    size_t ptr = 0;
    challenge[ptr++] = 16;
    if (strlen(MSCHAP_CHALLENGE) == 16) memcpy(
        challenge.data() + ptr,
        MSCHAP_CHALLENGE,
        16);
    else magic_random_bytes(challenge, 16, ptr);
}


bool
chapms_verify_response(PppPcb& pcb,
                       int id,
                       std::string& name,
                       std::string& secret,
                       std::vector<uint8_t>& challenge,
                       std::vector<uint8_t>& response,
                       std::string& message,
                       const int message_space)
{
    //unsigned char md[MS_CHAP_RESPONSE_LEN];
    size_t chall_ptr = 0;
    size_t resp_ptr = 0;
    std::vector<uint8_t> md;
    md.reserve(MS_CHAP_RESPONSE_LEN);
    int diff;
    const int challenge_len = challenge[chall_ptr++]; /* skip length, is 8 */
    const int response_len = response[resp_ptr++];
    if (response_len != MS_CHAP_RESPONSE_LEN) {
        message.append(fmt::format("E=691 R=1 C={} V=0",
                       reinterpret_cast<char*>(challenge.data())));
        return false;
    }
    if (!response[MS_CHAP_USENT]) {
        /* Should really propagate this into the error packet. */
        spdlog::info("Peer request for LANMAN auth not supported");
        message.append(fmt::format("E=691 R=1 C={} V=0", reinterpret_cast<char*>(challenge.data())));
        return false;
    }
    // Generate the expected response.
    chap_ms(pcb, challenge, secret, md,chall_ptr,resp_ptr);
    /* Determine which part of response to verify against */
    if (!response[MS_CHAP_USENT])
        diff = memcmp(&response[MS_CHAP_LANMANRESP],
                      &md[MS_CHAP_LANMANRESP],
                      MS_CHAP_LANMANRESP_LEN);
    else {
        diff = memcmp(&response[MS_CHAP_NTRESP], &md[MS_CHAP_NTRESP], MS_CHAP_NTRESP_LEN);
    }
    if (diff == 0) {
        // ppp_slprintf(message, message_space, "Access granted");
        message = "access granted";
        return 1;
    } // ppp_slprintf(message,
    //              message_space,
    //              "E=691 R=1 C=%0.*B V=0",
    //              challenge_len,
    //              challenge);
    message = "E=691 R=1 C=";
    message += (const char*)challenge.data();
    message += " V=0";
    return 0;
}


bool
chapms2_verify_response(PppPcb& pcb,
                        int id,
                        std::string& name,
                        std::string& secret,
                        std::vector<uint8_t>& challenge,
                        std::vector<uint8_t>& response,
                        std::string& message,
                        int message_space)
{
    // unsigned char md[MS_CHAP2_RESPONSE_LEN];
    // char saresponse[MS_AUTH_RESPONSE_LENGTH + 1];
    std::vector<uint8_t> chap_ms2_resp(MS_CHAP2_RESPONSE_LEN);
    std::vector<uint8_t> chap_ms2_auth_resp(MS_AUTH_RESPONSE_LENGTH + 1);
    const int challenge_len = challenge[0]; /* skip length, is 16 */
    const int response_len = response[0];
    if (response_len != MS_CHAP2_RESPONSE_LEN) {
        // "E=691 R=1 C=%0.*B V=0 M=%s"
        message = "E=691 R=1 C=";
        message += reinterpret_cast<const char*>(challenge.data() + 1);
        message += " V=0 M=";
        message += "Access denied";
        return false; /* not even the right length */
    }

    /* Generate the expected response and our mutual auth. */
    std::vector<uint8_t> peer_challenge(response.begin() + MS_CHAP2_PEER_CHALLENGE,
                                        response.begin() + MS_CHAP2_PEER_CHALLENGE +
                                        MS_CHAP2_PEER_CHAL_LEN);
    bool ok;

    std::tie(ok, chap_ms2_resp, chap_ms2_auth_resp) = chap_ms2(pcb,
             challenge,
             peer_challenge,
             name,
             secret,
             MS_CHAP2_AUTHENTICATOR);
    if (!ok) {
        return false;
    }
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
    const std::vector<uint8_t> ms_chap2_nt_resp(chap_ms2_resp.begin() + MS_CHAP2_NTRESP, chap_ms2_resp.begin() + MS_CHAP2_NTRESP + MS_CHAP2_NTRESP_LEN);
    std::vector<uint8_t> ms_chap2_nt_response(response.begin() + MS_CHAP2_NTRESP, response.begin() + MS_CHAP2_NTRESP + MS_CHAP2_NTRESP_LEN);

    if (ms_chap2_nt_resp != ms_chap2_nt_response) {
        if (response[MS_CHAP2_FLAGS]) {
            message = "S=";
            message += reinterpret_cast<char*>(chap_ms2_auth_resp.data());
        }
        else {
            message = "S=";
            message += reinterpret_cast<char*>(chap_ms2_auth_resp.data());
            message += " M=";
            message += "Access granted";
        }
        return true;
    }


    /**
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
    message = "E=691 R=1 C=";
    message += reinterpret_cast<const char*>(challenge.data());
    message += " V=0 M=";
    message += "Access denied";
    return false;
}


void
chapms_make_response(PppPcb& pcb,
                     std::vector<uint8_t>& response,
                     int id,
                     std::string& our_name,
                     std::vector<uint8_t>& challenge,
                     std::string& secret,
                     std::vector<uint8_t>& private_)
{
    size_t chall_ptr = 0;
    chall_ptr++;
    // challenge++; /* skip length, should be 8 */
    // *response++ = MS_CHAP_RESPONSE_LEN;
    size_t resp_ptr = 0;
    response[resp_ptr++] = MS_CHAP_RESPONSE_LEN;

    chap_ms(pcb, challenge, secret, response,chall_ptr,resp_ptr);
}


std::tuple<bool, std::vector<uint8_t>, std::vector<uint8_t>>
chapms2_make_response(PppPcb& pcb,
                      int id,
                      std::string& our_name,
                      std::vector<uint8_t>& challenge,
                      std::string& secret)
{
    std::vector<uint8_t> _challenge(challenge.begin() + 1, challenge.end());
    /* skip length, should be 16 */
    // response[0] = MS_CHAP2_RESPONSE_LEN;
    // std::vector<uint8_t> _response(response.begin() + 1, response.end());
    bool ok;
    std::vector<uint8_t> ms_chap2_nt_resp;
    std::vector<uint8_t> ms_chap2_nt_auth_resp;
    std::vector<uint8_t> peer_challenge;
    return chap_ms2(pcb,
             _challenge,
             peer_challenge,
             our_name,
             secret,
             MS_CHAP2_AUTHENTICATEE);
}


bool
chapms2_check_success(PppPcb& pcb,
                      std::vector<uint8_t>& msg,
                      std::vector<uint8_t>& private_)
{
    size_t len = msg.size();
    size_t offset = 0;
    if ((len < MS_AUTH_RESPONSE_LENGTH + 2) || strncmp(
        reinterpret_cast<char *>(msg.data()),
        "S=",
        2) != 0) {
        /* Packet does not start with "S=" */
        spdlog::error("MS-CHAPv2 Success packet is badly formed.");
        return false;
    }
    offset += 2;
    len -= 2;
    if (len < MS_AUTH_RESPONSE_LENGTH || memcmp(msg.data() + offset,
                                                private_.data(),
                                                MS_AUTH_RESPONSE_LENGTH)) {
        /* Authenticator Response did not match expected. */
        spdlog::error("MS-CHAPv2 mutual authentication failed.");
        return false;
    } /* Authenticator Response matches. */
    offset += MS_AUTH_RESPONSE_LENGTH; /* Eat it */
    len -= MS_AUTH_RESPONSE_LENGTH;
    if ((len >= 3) && !strncmp((char *)msg.data() + offset, " M=", 3)) {
        offset += 3; /* Eat the delimiter */
    }
    else if (len) {
        /* Packet has extra text which does not begin " M=" */
        spdlog::error("MS-CHAPv2 Success packet is badly formed.");
        return false;
    }
    return true;
}


void
chapms_handle_failure(PppPcb& pcb, std::vector<uint8_t>& inp)
{
    int err;
    std::string msg; /* We want a null-terminated string for strxxx(). */
    size_t len = std::min(inp.size(), (size_t)63);
    std::copy(inp.begin(), inp.begin() + len, msg.begin());
    msg[len] = 0;
    const char* p = msg.data(); /*
     * Deal with MS-CHAP formatted failure messages; just print the
     * M=<message> part (if any).  For MS-CHAP we're not really supposed
     * to use M=<message>, but it shouldn't hurt.  See
     * chapms[2]_verify_response.
     */
    if (!strncmp(p, "E=", 2)) {
        err = strtol(p + 2, nullptr, 10); /* Remember the error code. */
    }
    else { goto print_msg; /* Message is badly formatted. */ }
    if (len && ((p = strstr(p, " M=")) != nullptr)) {
        /* M=<message> field found. */
        p += 3;
    }
    else {
        /* No M=<message>; use the error code. */
        switch (err) {
        case MS_CHAP_ERROR_RESTRICTED_LOGON_HOURS: p = "E=646 Restricted logon hours";
            break;
        case MS_CHAP_ERROR_ACCT_DISABLED: p = "E=647 Account disabled";
            break;
        case MS_CHAP_ERROR_PASSWD_EXPIRED: p = "E=648 Password expired";
            break;
        case MS_CHAP_ERROR_NO_DIALIN_PERMISSION: p = "E=649 No dialin permission";
            break;
        case MS_CHAP_ERROR_AUTHENTICATION_FAILURE: p = "E=691 Authentication failure";
            break;
        case MS_CHAP_ERROR_CHANGING_PASSWORD:
            /* Should never see this, we don't support Change Password. */ p =
                "E=709 Error changing password";
            break;
        default: spdlog::error("Unknown MS-CHAP authentication failure: %.*v", len, inp);
            return;
        }
    }
print_msg: if (p != nullptr) { spdlog::error("MS-CHAP authentication failed: %v", p); }
}


/**
 *
 */
std::tuple<bool, std::vector<uint8_t>>
challenge_response(std::vector<uint8_t>& challenge,
                   size_t challenge_offset,
                   std::vector<uint8_t>& password_hash)
{
    std::vector<uint8_t> response(256);
    std::array<uint8_t, 21> z_password_hash;
    std::array<uint8_t, 8> des_key;
    mbedtls_des_context des_ctx;
    // memset(z_password_hash, 0, sizeof(z_password_hash));
    // memcpy(z_password_hash, password_hash.data(), MD4_SIGNATURE_SIZE);
    pppcrypt_56_to_64_bit_key(z_password_hash.data() + 0, des_key.data());
    // lwip_des_init(&des);
    mbedtls_des_setkey_dec(&des_ctx, des_key.data());
    mbedtls_des_crypt_ecb(&des_ctx, challenge.data(), response.data() + 0);
    // lwip_des_free(&des);
    pppcrypt_56_to_64_bit_key(z_password_hash.data() + 7, des_key.data());
    // lwip_des_init(&des);
    mbedtls_des_setkey_enc(&des_ctx, des_key.data());
    mbedtls_des_crypt_ecb(&des_ctx, challenge.data(), response.data() + 8);
    // lwip_des_free(&des);
    pppcrypt_56_to_64_bit_key(z_password_hash.data() + 14, des_key.data());
    // lwip_des_init(&des);
    mbedtls_des_setkey_enc(&des_ctx, des_key.data());
    mbedtls_des_crypt_ecb(&des_ctx, challenge.data(), response.data() + 16);
    // lwip_des_free(&des);
    return std::make_tuple(true, response);
}


std::tuple<bool, std::vector<uint8_t>>
challenge_hash(std::vector<uint8_t>& peer_challenge,
               std::vector<uint8_t>& rchallenge,
               std::string& username)
{
    std::vector<uint8_t> challenge;
    mbedtls_sha1_context sha1_context;
    uint8_t sha1_hash[SHA1_SIGNATURE_SIZE] = {};
    const char* user = username.c_str(); /* remove domain from "domain\username" */
    // TODO: re-write to remove domain from username
    // if
    // if ((user = strrchr(username, '\\')) != nullptr)
    //     ++user;
    // else
    //     user = username;
    mbedtls_sha1_init(&sha1_context);
    mbedtls_sha1_starts_ret(&sha1_context);
    mbedtls_sha1_update_ret(&sha1_context, peer_challenge.data(), 16);
    mbedtls_sha1_update_ret(&sha1_context, rchallenge.data(), 16);
    mbedtls_sha1_update_ret(&sha1_context,
                            reinterpret_cast<const unsigned char*>(user),
                            strlen(user));
    mbedtls_sha1_finish_ret(&sha1_context, sha1_hash);
    mbedtls_sha1_free(&sha1_context);
    std::copy(sha1_hash, sha1_hash + SHA1_SIGNATURE_SIZE - 1, challenge);
    return std::make_tuple(true, challenge);
}


std::vector<uint8_t>
nt_password_hash(std::vector<uint8_t>& secret)
{
    std::vector<uint8_t> hash;
    mbedtls_md4_context md4Context;
    mbedtls_md4_init(&md4Context);
    mbedtls_md4_starts_ret(&md4Context);
    mbedtls_md4_update_ret(&md4Context, secret.data(), secret.size());
    mbedtls_md4_finish_ret(&md4Context, hash.data());
    mbedtls_md4_free(&md4Context);
    return hash;
}


void
chap_ms_nt(std::vector<uint8_t>& r_challenge,
           std::string& secret,
           std::vector<uint8_t>& nt_response,
           size_t challenge_offset,
           size_t response_offset)
{
    std::wstring unicode_password;
    unicode_password.reserve(MAX_NT_PASSWORD * 2);
    // uint8_t unicodePassword[MAX_NT_PASSWORD * 2];
    // uint8_t PasswordHash[MD4_SIGNATURE_SIZE];
    std::vector<uint8_t> password_hash;
    password_hash.reserve(MD4_SIGNATURE_SIZE);
    // std::wstring_convert<std::codecvt_utf8<char>> converter;
    // unicode_password = converter.from_bytes(secret);


    bool ok;
    std::wstring unicode_password_wstr;
    std::tie(ok, unicode_password_wstr) = ascii_to_unicode(secret);
    std::vector<uint8_t> unicode_password_vector(unicode_password.begin(), unicode_password.end());

    /* Hash the Unicode version of the secret (== password). */
    password_hash = nt_password_hash(unicode_password_vector);
    challenge_response(r_challenge, 0, password_hash);
}


/**
 *
 */
std::tuple<bool, std::vector<uint8_t>>
chap_ms2_nt(std::vector<uint8_t>& rchallenge,
            std::vector<uint8_t>& peer_challenge,
            std::string& username,
            std::string& secret)
{
    bool ok;
    std::vector<uint8_t> challenge;
    std::vector<uint8_t> response;
    std::tie(ok, challenge) = challenge_hash(peer_challenge, rchallenge, username);
    /* Hash the Unicode version of the secret (== password). */
    std::wstring converted_secret;
    std::tie(ok, converted_secret) = ascii_to_unicode(secret);
    if (!ok) { return std::make_tuple(false, response); }
    std::vector<uint8_t> converted_secret_vec(converted_secret.begin(),
                                              converted_secret.end());
    auto password_hash = nt_password_hash(converted_secret_vec);
    return challenge_response(challenge, 0, password_hash);
}


std::tuple<bool, std::vector<uint8_t>>
chap_ms_lanman(std::vector<uint8_t>& rchallenge,
               std::string& secret,
               size_t rchallenge_offset)
{
    std::vector<uint8_t> ucase_password(MAX_NT_PASSWORD);
    std::vector<uint8_t> password_hash(MD4_SIGNATURE_SIZE);
    mbedtls_des_context des_ctx;
    std::array<uint8_t, 8> des_key;
    /* LANMan password is case insensitive */
    for (auto& c : secret) { ucase_password.push_back(toupper(c)); }
    pppcrypt_56_to_64_bit_key(ucase_password.data() + 0, des_key.data());
    // lwip_des_init(&des);
    mbedtls_des_setkey_enc(&des_ctx, des_key.data());
    mbedtls_des_crypt_ecb(&des_ctx, (uint8_t*)STD_TEXT, password_hash.data() + 0);
    // lwip_des_free(&des);
    pppcrypt_56_to_64_bit_key(ucase_password.data() + 7, des_key.data());
    // lwip_des_init(&des);
    mbedtls_des_setkey_enc(&des_ctx, des_key.data());
    mbedtls_des_crypt_ecb(&des_ctx,
                          (uint8_t*)STD_TEXT,
                          password_hash.data() + LANMAN_KEY_LEN);
    // lwip_des_free(&des);
    return challenge_response(rchallenge, 0, password_hash);
}


/**
 * password_hash_hash should be MD4_SIGNATURE_SIZE bytes long
 * nt_response should be 24 bytes long
 * peer_challenge should be 16 bytes long
 * auth_response should MS_AUTH_RESPONSE_LENGTH + 1
 */
std::tuple<bool, std::vector<uint8_t>>
gen_authenticator_resp(std::vector<uint8_t>& password_hash_hash,
                       std::vector<uint8_t>& nt_response,
                       std::vector<uint8_t>& peer_challenge,
                       std::vector<uint8_t>& rchallenge,
                       std::string& username)
{
    mbedtls_sha1_context sha1_ctx;
    std::array<uint8_t, SHA1_SIGNATURE_SIZE> digest{};
    std::array<uint8_t, 8> challenge{};
    std::vector<uint8_t> auth_response(SHA1_SIGNATURE_SIZE);
    mbedtls_sha1_init(&sha1_ctx);
    mbedtls_sha1_starts_ret(&sha1_ctx);
    mbedtls_sha1_update_ret(&sha1_ctx, password_hash_hash.data(), MD4_SIGNATURE_SIZE);
    mbedtls_sha1_update_ret(&sha1_ctx, nt_response.data(), 24);
    mbedtls_sha1_update_ret(&sha1_ctx, const_cast<uint8_t*>(MAGIC_1), sizeof(MAGIC_1));
    mbedtls_sha1_finish_ret(&sha1_ctx, digest.data());
    mbedtls_sha1_free(&sha1_ctx);
    challenge_hash(peer_challenge, rchallenge, username);
    mbedtls_sha1_init(&sha1_ctx);
    mbedtls_sha1_starts_ret(&sha1_ctx);
    mbedtls_sha1_update_ret(&sha1_ctx, digest.data(), sizeof(digest));
    mbedtls_sha1_update_ret(&sha1_ctx, challenge.data(), 8);
    mbedtls_sha1_update_ret(&sha1_ctx, const_cast<uint8_t*>(MAGIC_2), sizeof(MAGIC_2));
    mbedtls_sha1_finish_ret(&sha1_ctx, digest.data());
    mbedtls_sha1_free(&sha1_ctx); /* Convert to ASCII hex string. */
    std::copy(digest.begin(), digest.end(), auth_response.begin());
    // for (int i = 0; i < std::max((MS_AUTH_RESPONSE_LENGTH / 2), (int)sizeof(digest)); i++
    // ) { sprintf((char *)&auth_response[i * 2], "%02X", digest[i]); }
    return std::make_tuple(true, auth_response);
}


/**
 * NT response length is 24 bytes
 * Peer challenge length is 16 bytes
 * Auth response length is MS_AUTH_RESPONSE_LENGTH + 1
 */
std::tuple<bool, std::vector<uint8_t>>
gen_authenticator_response_plain(std::string& secret,
                                 std::vector<uint8_t>& nt_response,
                                 std::vector<uint8_t>& peer_challenge,
                                 std::vector<uint8_t>& rchallenge,
                                 std::string& username)
{
    std::vector<uint8_t> auth_response(MS_AUTH_RESPONSE_LENGTH + 1);
    std::wstring unicode_password;
    std::vector<uint8_t> password_hash(MD4_SIGNATURE_SIZE);
    std::vector<uint8_t> password_hash_hash(MD4_SIGNATURE_SIZE);
    /* Hash (x2) the Unicode version of the secret (== password). */
    bool ok;
    std::tie(ok, unicode_password) = ascii_to_unicode(secret);
    if (!ok) { return std::make_tuple(false, auth_response); }
    std::vector<uint8_t> unicode_pass_vec(MAX_NT_PASSWORD * 2);
    std::copy(unicode_password.begin(), unicode_password.end(), unicode_pass_vec);
    password_hash = nt_password_hash(unicode_pass_vec);
    password_hash_hash = nt_password_hash(password_hash);
    return gen_authenticator_resp(password_hash_hash,
                                  nt_response,
                                  peer_challenge,
                                  rchallenge,
                                  username);
}


/**
 * Set mppe_xxxx_key from MS-CHAP credentials. (see RFC 3079)
 */
bool
set_start_key(PppPcb& pcb, std::vector<uint8_t>& rchallenge, std::string& secret)
{
    std::wstring unicode_password;
    std::vector<uint8_t> unicode_password_vec(MAX_NT_PASSWORD * 2);
    bool ok;
    std::vector<uint8_t> password_hash(MD4_SIGNATURE_SIZE);
    std::vector<uint8_t> password_hash_hash(MD4_SIGNATURE_SIZE);
    std::vector<uint8_t> digest(SHA1_SIGNATURE_SIZE);
    mbedtls_sha1_context sha1_ctx;

    /* Hash (x2) the Unicode version of the secret (== password). */
    std::tie(ok, unicode_password) = ascii_to_unicode(secret);
    if (!ok) { return false; }
    std::copy(unicode_password.begin(), unicode_password.end(), unicode_password_vec);
    password_hash = nt_password_hash(unicode_password_vec);
    password_hash_hash = nt_password_hash(password_hash);
    mbedtls_sha1_init(&sha1_ctx);
    mbedtls_sha1_starts_ret(&sha1_ctx);
    mbedtls_sha1_update_ret(&sha1_ctx, password_hash_hash.data(), MD4_SIGNATURE_SIZE);
    mbedtls_sha1_update_ret(&sha1_ctx, password_hash_hash.data(), MD4_SIGNATURE_SIZE);
    mbedtls_sha1_update_ret(&sha1_ctx, rchallenge.data(), 8);
    mbedtls_sha1_finish_ret(&sha1_ctx, digest.data());
    mbedtls_sha1_free(&sha1_ctx); /* Same key in both directions. */
    mppe_set_key(pcb.mppe_comp, digest);
    mppe_set_key(pcb.mppe_decomp, digest);
    pcb.mppe_keys_set = true;
    return true;
}

/**
 * Set mppe_xxxx_key from MS-CHAPv2 credentials. (see RFC 3079)
 * nt_response should be 24 bytes in length
 */
bool
set_master_keys(PppPcb& pcb,
                std::string& secret,
                std::vector<uint8_t>& nt_response,
                const bool is_server)
{
    // uint8_t unicodePassword[MAX_NT_PASSWORD * 2];
    std::vector<uint8_t> unicode_password_vec(MAX_NT_PASSWORD * 2);
    std::wstring unicode_password;
    // uint8_t PasswordHash[MD4_SIGNATURE_SIZE];
    std::vector<uint8_t> password_hash(MD4_SIGNATURE_SIZE);
    // uint8_t PasswordHashHash[MD4_SIGNATURE_SIZE];
    std::vector<uint8_t> password_hash_hash(MD4_SIGNATURE_SIZE);
    // uint8_t MasterKey[SHA1_SIGNATURE_SIZE]; /* >= MPPE_MAX_KEY_LEN */
    std::vector<uint8_t> master_key(SHA1_SIGNATURE_SIZE);
    // uint8_t Digest[SHA1_SIGNATURE_SIZE]; /* >= MPPE_MAX_KEY_LEN */
    std::vector<uint8_t> digest(SHA1_SIGNATURE_SIZE);
    const uint8_t* s = nullptr;
    mbedtls_sha1_context sha1_ctx;
    bool ok;
    /* Hash (x2) the Unicode version of the secret (== password). */
    std::tie(ok, unicode_password) = ascii_to_unicode(secret);
    std::copy(unicode_password.begin(), unicode_password.end(), unicode_password_vec);
    password_hash = nt_password_hash(unicode_password_vec);
    password_hash_hash = nt_password_hash(password_hash);
    mbedtls_sha1_init(&sha1_ctx);
    mbedtls_sha1_starts_ret(&sha1_ctx);
    mbedtls_sha1_update_ret(&sha1_ctx, password_hash_hash.data(), MD4_SIGNATURE_SIZE);
    mbedtls_sha1_update_ret(&sha1_ctx, nt_response.data(), 24);
    mbedtls_sha1_update_ret(&sha1_ctx, MAGIC4, sizeof(MAGIC4));
    mbedtls_sha1_finish_ret(&sha1_ctx, master_key.data());
    mbedtls_sha1_free(&sha1_ctx);
    // generate send key
    if (is_server) s = MAGIC3;
    else { s = MAGIC5; }
    mbedtls_sha1_init(&sha1_ctx);
    mbedtls_sha1_starts_ret(&sha1_ctx);
    mbedtls_sha1_update_ret(&sha1_ctx, master_key.data(), 16);
    mbedtls_sha1_update_ret(&sha1_ctx, MPPE_SHA1_PAD1, SHA1_PAD_SIZE);
    mbedtls_sha1_update_ret(&sha1_ctx, s, 84);
    mbedtls_sha1_update_ret(&sha1_ctx, MPPE_SHA1_PAD2, SHA1_PAD_SIZE);
    mbedtls_sha1_finish_ret(&sha1_ctx, digest.data());
    mbedtls_sha1_free(&sha1_ctx);
    mppe_set_key(pcb.mppe_comp, digest);

    /*
     * generate recv key
     */
    if (is_server) { s = MAGIC5; }
    else { s = MAGIC3; }
    mbedtls_sha1_init(&sha1_ctx);
    mbedtls_sha1_starts_ret(&sha1_ctx);
    mbedtls_sha1_update_ret(&sha1_ctx, master_key.data(), 16);
    mbedtls_sha1_update_ret(&sha1_ctx, MPPE_SHA1_PAD1, SHA1_PAD_SIZE);
    mbedtls_sha1_update_ret(&sha1_ctx, s, 84);
    mbedtls_sha1_update_ret(&sha1_ctx, MPPE_SHA1_PAD2, SHA1_PAD_SIZE);
    mbedtls_sha1_finish_ret(&sha1_ctx, digest.data());
    mbedtls_sha1_free(&sha1_ctx);
    mppe_set_key(pcb.mppe_decomp, digest);
    pcb.mppe_keys_set = true;
    return true;
}


bool
chap_ms(PppPcb& pcb,
        std::vector<uint8_t>& challenge,
        std::string& secret,
        std::vector<uint8_t>& response,
        const size_t challenge_offset,
        const size_t response_offset)
{
    response.erase(response.begin() + challenge_offset);
    chap_ms_nt(challenge,
               secret,
               response,
               challenge_offset,
               MS_CHAP_NTRESP + response_offset);
    bool ok;
    std::vector<uint8_t> ms_lanman;
    std::tie(ok, ms_lanman) = chap_ms_lanman(challenge, secret, challenge_offset);
    if (!ok) {
        return false;
    }
    /* preferred method is set by option  */
    response[MS_CHAP_USENT] = !ms_lanman[0];
    return set_start_key(pcb, challenge, secret);
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
std::tuple<bool, std::vector<uint8_t>, std::vector<uint8_t>>
chap_ms2(PppPcb& pcb,
         std::vector<uint8_t>& rchallenge,
         std::vector<uint8_t>& peer_challenge,
         std::string& user,
         std::string& secret,
         int authenticator)
{
    /* ARGSUSED */
    std::vector<uint8_t> response = std::vector<uint8_t>(MS_CHAP2_RESPONSE_LEN);
    std::vector<uint8_t> auth_response;

    bool ok;
    bool peer_challenge_empty = false;
    /* Generate the Peer-Challenge if requested, or copy it if supplied. */
    if (peer_challenge_empty) {
       ok = magic_random_bytes(response, MS_CHAP2_RESPONSE_LEN, MS_CHAP2_PEER_CHALLENGE);
        if (!ok) {
            return std::make_tuple(false, response, auth_response);
        }
    } else {
        std::copy(peer_challenge.begin(), peer_challenge.end(), response.begin() + MS_CHAP2_PEER_CHALLENGE);
    }

    std::vector<uint8_t> nt_response;
    std::tie(ok, nt_response) = chap_ms2_nt(rchallenge,
                peer_challenge,
                user,
                secret);
    if (!ok) {
        return std::make_tuple(false, response, auth_response);
    }

    std::copy(nt_response.begin(), nt_response.end(), response.begin() + MS_CHAP2_NTRESP);

    /* Generate the Authenticator Response. */
    std::tie(ok, auth_response) = gen_authenticator_response_plain(secret,
                                       nt_response,
                                       peer_challenge,
                                       rchallenge,
                                       user);
    if (!ok) {
        return std::make_tuple(false, response, auth_response);
    }

    ok = set_master_keys(pcb, secret, nt_response, authenticator);
    if (!ok) {
        return std::make_tuple(false, response, auth_response);
    }

    return std::make_tuple(true, response, auth_response);
}

//
// END OF FILE
//
