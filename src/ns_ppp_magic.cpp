/**
 * @file: magic.cpp
 */

#define NOMINMAX
#include "ns_ppp_config.h"
#include "ns_sys.h"
#include "pppcrypt.h"
#include "magic.h"
#include "mbedtls/md5.h"
#include <algorithm>
#include <cstdint>
#include <random>




constexpr auto MD5_HASH_SIZE = 16;
// static char magic_randpool[MD5_HASH_SIZE];   /* Pool of randomness. */
// static long magic_randcount;      /* Pseudo-random incrementer */
// static uint32_t magic_randomseed;    /* Seed used for random number generation. */


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
// static void
// magic_churnrand(char* rand_data, uint32_t rand_len)
// {
//     mbedtls_md5_context md5_ctx;
//     mbedtls_md5_init(&md5_ctx);
//     mbedtls_md5_starts_ret(&md5_ctx);
//     mbedtls_md5_update_ret(&md5_ctx, (uint8_t *)magic_randpool, sizeof(magic_randpool));
//     if (rand_data)
//     {
//         mbedtls_md5_update_ret(&md5_ctx, (uint8_t *)rand_data, rand_len);
//     }
//     else
//     {
//         struct
//         {
//             /* INCLUDE fields for any system sources of randomness */
//             uint32_t jiffies;
//             uint32_t rand;
//         } sys_data;
//         magic_randomseed += sys_jiffies();
//         sys_data.jiffies = magic_randomseed;
//         sys_data.rand = lwip_rand(); /* Load sys_data fields here. */
//         mbedtls_md5_update_ret(&md5_ctx, (uint8_t *)&sys_data, sizeof(sys_data));
//     }
//     mbedtls_md5_finish_ret(&md5_ctx, (uint8_t *)magic_randpool);
//     mbedtls_md5_free(&md5_ctx);
// }

/*
 * Initialize the random number generator.
 */
// void magic_init(void) {
//   magic_churnrand(nullptr, 0);
// }

/*
 * Randomize our random seed value.
 */
// void magic_randomize(void) {
//   magic_churnrand(nullptr, 0);
// }

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
bool
magic_random_bytes(std::vector<uint8_t> buffer, const size_t count, const size_t offset)
{
    if (offset + count < buffer.capacity()) { return false; }
    mbedtls_md5_context md5_ctx;
    uint8_t tmp[MD5_HASH_SIZE];
    auto it = buffer.begin() + offset;
    for (auto i = 0; i < count; i++) { buffer[i] = uint8_t(magic_rand()); }
    return true;
}

/*
 * Return a new random number.
 */
uint32_t
magic()
{
    uint32_t new_rand = 0;
    std::vector<uint8_t> buffer;
    buffer.reserve(4);
    magic_random_bytes(buffer, 4, 0);
    new_rand = buffer[0] << 24 | buffer[1] << 16 | buffer[2] << 8 | buffer[3];
    return new_rand;
}


/*
 * Return a new random number between 0 and (2^pow)-1 included.
 */
uint32_t
magic_pow(const uint8_t pow) { return magic() & ~(~0UL << pow); }


//
// END OF FILE
//