/**
 * @file: pppcrypt.h
 * @brief: internal crypto functions for LWIP PPP implementation.
 */
#pragma once
#include <cstdint>
#include "mbedtls/arc4.h"


void pppcrypt_56_to_64_bit_key(uint8_t*key, uint8_t*des_key);

inline bool cmp_arc4_ctx(mbedtls_arc4_context& ctx1, mbedtls_arc4_context& ctx2)
{
    if (ctx1.x != ctx2.x)
    {
        return false;
    }

    if (ctx1.y != ctx2.y)
    {
        return false;
    }

    for (auto i = 0; i < 256; i++)
    {
        if (ctx1.m[i] != ctx2.m[i]) { return false; }
    }

    return true;
}


//
// END OF FILE
//