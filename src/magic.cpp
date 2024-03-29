/*
 * magic.c - PPP Magic Number routines.
 *
 * Copyright (c) 1984-2000 Carnegie Mellon University. All rights reserved.
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
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/*****************************************************************************
* randm.c - Random number generator program file.
*
* Copyright (c) 2003 by Marc Boucher, Services Informatiques (MBSI) inc.
* Copyright (c) 1998 by Global Election Systems Inc.
*
* The authors hereby grant permission to use, copy, modify, distribute,
* and license this software and its documentation for any purpose, provided
* that existing copyright notices are retained in all copies and that this
* notice and the following disclaimer are included verbatim in any
* distributions. No written agreement, license, or royalty fee is required
* for any of the authorized uses.
*
* THIS SOFTWARE IS PROVIDED BY THE CONTRIBUTORS *AS IS* AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
* IN NO EVENT SHALL THE CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
* THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
******************************************************************************
* REVISION HISTORY
*
* 03-01-01 Marc Boucher <marc@mbsi.ca>
*   Ported to lwIP.
* 98-06-03 Guy Lancaster <lancasterg@acm.org>, Global Election Systems Inc.
*   Extracted from avos.
*****************************************************************************/

#define NOMINMAX
#include <ppp_opts.h>
#include <cstdint>
#include <sys.h>
#include <pppcrypt.h>

#include <magic.h>
#include <pppcrypt.h>
#include <algorithm>

constexpr auto MD5_HASH_SIZE = 16;
static char magic_randpool[MD5_HASH_SIZE];   /* Pool of randomness. */
static long magic_randcount;      /* Pseudo-random incrementer */
static uint32_t magic_randomseed;    /* Seed used for random number generation. */

/*
 * Churn the randomness pool on a random event.  Call this early and often
 *  on random and semi-random system events to build randomness in time for
 *  usage.  For randomly timed events, pass a null pointer and a zero length
 *  and this will use the system timer and other sources to add randomness.
 *  If new random data is available, pass a pointer to that and it will be
 *  included.
 *
 * Ref: Applied Cryptography 2nd Ed. by Bruce Schneier p. 427
 */
static void magic_churnrand(char *rand_data, uint32_t rand_len) {
  mbedtls_md5_context md5_ctx;

  /* Logf(LOG_INFO, ("magic_churnrand: %u@%P\n", rand_len, rand_data)); */
  mbedtls_md5_init(&md5_ctx);
  mbedtls_md5_starts_ret(&md5_ctx);
  mbedtls_md5_update_ret(&md5_ctx, (uint8_t *)magic_randpool, sizeof(magic_randpool));
  if (rand_data) {
    mbedtls_md5_update_ret(&md5_ctx, (uint8_t *)rand_data, rand_len);
  } else {
    struct {
      /* INCLUDE fields for any system sources of randomness */
      uint32_t jiffies;

      uint32_t rand;

    } sys_data;
    magic_randomseed += sys_jiffies();
    sys_data.jiffies = magic_randomseed;

    sys_data.rand = lwip_rand();

    /* Load sys_data fields here. */
    mbedtls_md5_update_ret(&md5_ctx, (uint8_t *)&sys_data, sizeof(sys_data));
  }
  mbedtls_md5_finish_ret(&md5_ctx, (uint8_t *)magic_randpool);
  mbedtls_md5_free(&md5_ctx);
/*  Logf(LOG_INFO, ("magic_churnrand: -> 0\n")); */
}

/*
 * Initialize the random number generator.
 */
void magic_init(void) {
  magic_churnrand(nullptr, 0);
}

/*
 * Randomize our random seed value.
 */
void magic_randomize(void) {
  magic_churnrand(nullptr, 0);
}

/*
 * magic_random_bytes - Fill a buffer with random bytes.
 *
 * Use the random pool to generate random data.  This degrades to pseudo
 *  random when used faster than randomness is supplied using magic_churnrand().
 * Note: It's important that there be sufficient randomness in magic_randpool
 *  before this is called for otherwise the range of the result may be
 *  narrow enough to make a search feasible.
 *
 * Ref: Applied Cryptography 2nd Ed. by Bruce Schneier p. 427
 *
 * XXX Why does he not just call magic_churnrand() for each block?  Probably
 *  so that you don't ever publish the seed which could possibly help
 *  predict future values.
 * XXX Why don't we preserve md5 between blocks and just update it with
 *  magic_randcount each time?  Probably there is a weakness but I wish that
 *  it was documented.
 */
void magic_random_bytes(uint8_t* buf, size_t buf_len) {
  mbedtls_md5_context md5_ctx;
  uint8_t tmp[MD5_HASH_SIZE];
  while (buf_len > 0) {
    mbedtls_md5_init(&md5_ctx);
    mbedtls_md5_starts_ret(&md5_ctx);
    mbedtls_md5_update_ret(&md5_ctx, (uint8_t *)magic_randpool, sizeof(magic_randpool));
    mbedtls_md5_update_ret(&md5_ctx, (uint8_t *)&magic_randcount, sizeof(magic_randcount));
    mbedtls_md5_finish_ret(&md5_ctx, tmp);
    mbedtls_md5_free(&md5_ctx);
    magic_randcount++;
    uint32_t n = std::min(buf_len, size_t(MD5_HASH_SIZE));
    memcpy(buf, tmp, n);
    buf += n;
    buf_len -= n;
  }
}

/*
 * Return a new random number.
 */
uint32_t magic(void) {
  uint32_t new_rand;

  magic_random_bytes((unsigned char *)&new_rand, sizeof(new_rand));

  return new_rand;
}



/*****************************/
/*** LOCAL DATA STRUCTURES ***/
/*****************************/


/*
 * Return a new random number between 0 and (2^pow)-1 included.
 */
uint32_t magic_pow(uint8_t pow) {
  return magic() & ~(~0UL<<pow);
}


