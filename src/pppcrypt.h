/*
 * pppcrypt.c - PPP/DES linkage for MS-CHAP and EAP SRP-SHA1
 *
 * Extracted from chap_ms.c by James Carlson.
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
#pragma once

/* This header file is included in all PPP modules needing hashes and/or ciphers */

/*
 * If included PolarSSL copy is not used, user is expected to include
 * external libraries in cc.h (which is included by arch.h).
 */

#include <mbedtls/md4.h>
#include <mbedtls/md5.h>
#include <mbedtls/sha1.h>
#include <mbedtls/des.h>
#include <mbedtls/arc4.h>

/*
 * Map hashes and ciphers functions to PolarSSL
 */



// #define lwip_md4_context md4_context
// #define lwip_md4_init(context)
// #define lwip_md4_starts md4_starts
// #define lwip_md4_update md4_update
// #define lwip_md4_finish md4_finish
// #define lwip_md4_free(context)


// #define lwip_md5_context md5_context
// #define mbedtls_md5_init(context)
// #define mbedtls_md5_starts_ret md5_starts
// #define mbedtls_md5_update_ret md5_update
// #define mbedtls_md5_finish_ret md5_finish
#define lwip_md5_free(context)


// #define lwip_sha1_context Sha1Context
#define lwip_sha1_init(context)
#define lwip_sha1_starts sha1_starts
#define lwip_sha1_update sha1_update
#define lwip_sha1_finish sha1_finish
#define lwip_sha1_free(context)


// #define lwip_des_context des_context
#define lwip_des_init(context)
#define lwip_des_setkey_enc des_setkey_enc
#define lwip_des_crypt_ecb des_crypt_ecb
#define lwip_des_free(context)


// #define mbed_tls_arc4_context Arc4Context
#define lwip_arc4_init(context)
#define lwip_arc4_setup arc4_setup
#define lwip_arc4_crypt arc4_crypt
#define lwip_arc4_free(context)




void pppcrypt_56_to_64_bit_key(uint8_t*key, uint8_t*des_key);

