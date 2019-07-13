/*
 * chap-md5.c - New CHAP/MD5 implementation.
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

#include "ppp_opts.h"
#include "ppp_impl.h"
#include "chap_new.h"
#include "chap_md5.h"
#include "magic.h"
#include "pppcrypt.h"

void chap_md5_generate_challenge(PppPcb* pcb, unsigned char* cp)
{
    const auto clen = kMd5MinChallenge + magic_pow(kMd5MinMaxPowerOfTwoChallenge);
    *cp++ = clen;
    magic_random_bytes(cp, clen);
}

static int chap_md5_verify_response(PppPcb* pcb,
                                    const int id,
                                    const char* name,
                                    const unsigned char* secret,
                                    const int secret_len,
                                    const unsigned char* challenge,
                                    const unsigned char* response,
                                    char* message,
                                    const int message_space)
{
    lwip_md5_context ctx;
    unsigned char idbyte = id;
    unsigned char hash[kMd5HashSize];
    const int challenge_len = *challenge++;
    const int response_len = *response++;
    if (response_len == kMd5HashSize)
    {
        /* Generate hash of ID, secret, challenge */
        lwip_md5_init(&ctx);
        lwip_md5_starts(&ctx);
        lwip_md5_update(&ctx, &idbyte, 1);
        lwip_md5_update(&ctx, secret, secret_len);
        lwip_md5_update(&ctx, challenge, challenge_len);
        lwip_md5_finish(&ctx, hash);
        lwip_md5_free(&ctx); /* Test if our hash matches the peer's response */
        if (memcmp(hash, response, kMd5HashSize) == 0)
        {
            ppp_slprintf(message, message_space, "Access granted");
            return 1;
        }
    }
    ppp_slprintf(message, message_space, "Access denied");
    return 0;
}

void chap_md5_make_response(PppPcb* pcb,
                                   unsigned char* response,
                                   const int id,
                                   const char* our_name,
                                   const unsigned char* challenge,
                                   const char* secret,
                                   const int secret_len,
                                   unsigned char* private_)
{
    lwip_md5_context ctx;
    unsigned char idbyte = id;
    int challenge_len = *challenge++;
    lwip_md5_init(&ctx);
    lwip_md5_starts(&ctx);
    lwip_md5_update(&ctx, &idbyte, 1);
    lwip_md5_update(&ctx, reinterpret_cast<const uint8_t *>(secret), secret_len);
    lwip_md5_update(&ctx, challenge, challenge_len);
    lwip_md5_finish(&ctx, &response[1]);
    lwip_md5_free(&ctx);
    response[0] = kMd5HashSize;
}

//
// END OF FILE
//