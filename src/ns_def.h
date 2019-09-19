#pragma once
#include <cstdint>
// #define std::max(x , y
// )  (((x) > (y)) ? (x) : (y))  // NOLINT(cppcoreguidelines-macro-usage)
// #define std::min(x , y
// )  (((x) < (y)) ? (x) : (y))  // NOLINT(cppcoreguidelines-macro-usage)
/* Get the number of entries in an array ('x' must NOT be a pointer!) */

constexpr uint8_t kLwipMacAddrBase[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x5};
constexpr unsigned int NETIF_MAX_HWADDR_LEN = 6; // typedef int64_t LONGLONG;
//typedef struct _LARGE_INTEGER {
//  LONGLONG QuadPart;
//} LARGE_INTEGER;
// typedef void* HANDLE;

typedef uintptr_t HCRYPTPROV;


typedef uint32_t LwipInAddr;

struct LwipInAddrStruct
{
    uint32_t _s_addr;
};


struct LwipIn6Addr
{
    union
    {
        uint32_t u32_addr[4];
        uint8_t u8_addr[16];
    } un; // #define s6_addr  un.u8_addr
};



//
// END OF FILE
//