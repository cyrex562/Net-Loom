#pragma once
#include <cstdint>
#include <string>

/*
 * Each interface is described by upap structure.
 */
struct UpapState
{
    std::string us_user; /* User */
    std::string us_passwd; /* Password */
    uint8_t us_clientstate; /* Client state */
    uint8_t us_serverstate; /* Server state */
    uint8_t us_id; /* Current id */
    uint8_t us_transmits; /* Number of auth-reqs sent */
};

//
// END OF FILE
//