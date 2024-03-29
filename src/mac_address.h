/**
 *
 * @file mac_address.h
 *
 */

#pragma once
#include <cstdint>

constexpr auto ETH_ADDR_LEN = 6;

struct MacAddress
{
    uint8_t bytes[ETH_ADDR_LEN];
}; 

/**
 * Initialize a struct MacAddress with its 6 bytes (takes care of correct braces)
 */
inline MacAddress
make_eth_addr_from_bytes(const uint8_t b0,
                         const uint8_t b1,
                         const uint8_t b2,
                         const uint8_t b3,
                         const uint8_t b4,
                         const uint8_t b5)
{
    return {
        b0,
        b1,
        b2,
        b3,
        b4,
        b5
    };
} 

inline bool cmp_mac_address(const MacAddress& mac1, const MacAddress& mac2)
{
    for (auto i = 0; i < 6; i++)
    {
        if (mac1.bytes[i] != mac2.bytes[i])
        {
            return false;
        }
    }

    return true;
}


//
// END OF FILE
//