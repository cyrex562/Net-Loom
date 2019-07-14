#pragma once

#include <cstdint>


#ifdef __cplusplus
extern "C" {
#endif

#define LWIP_MAX(x , y)  (((x) > (y)) ? (x) : (y))  // NOLINT(cppcoreguidelines-macro-usage)
#define LWIP_MIN(x , y)  (((x) < (y)) ? (x) : (y))  // NOLINT(cppcoreguidelines-macro-usage)

/* Get the number of entries in an array ('x' must NOT be a pointer!) */
#define LWIP_ARRAYSIZE(x) (sizeof(x)/sizeof((x)[0]))  // NOLINT(cppcoreguidelines-macro-usage)

inline uint32_t LwipMakeu32(const uint8_t a,
                            const uint8_t b,
                            const uint8_t c,
                            const uint8_t d)
{
    return uint32_t(a & 0xff) << 24 |
        uint32_t(b & 0xff) << 16 |
        uint32_t(c & 0xff) << 8 |
        uint32_t(d & 0xff);
}

inline uint16_t PpHtons(const uint16_t x)
{
    return uint16_t((x & uint16_t(0x00ffU)) << 8 | (x & uint16_t(0xff00U)) >> 8);
}

inline uint16_t PpNtohs(const uint16_t x) {
    return PpHtons(x);
}

inline uint32_t PP_HTONL(const uint32_t x)
{
    return (x & uint32_t(0x000000ffUL)) << 24 |
        (x & uint32_t(0x0000ff00UL)) << 8 |
        (x & uint32_t(0x00ff0000UL)) >> 8 |
        (x & uint32_t(0xff000000UL)) >> 24;
}

inline uint32_t PpNtohl(const uint32_t x) {
    return PP_HTONL(x);
}

    /* Functions that are not available as standard implementations.
 * In cc.h, you can #define these to implementations available on
 * your platform to save some code bytes if you use these functions
 * in your application, too.
 */

/* This can be #defined to itoa() or snprintf(result, bufsize, "%d", number) depending on your platform */
void  lwip_itoa(char* result, size_t bufsize, int number);

/* This can be #defined to strnicmp() or strncasecmp() depending on your platform */
int   lwip_strnicmp(const char* str1, const char* str2, size_t len);

/* This can be #defined to stricmp() or strcasecmp() depending on your platform */
int   lwip_stricmp(const char* str1, const char* str2);

/* This can be #defined to strnstr() depending on your platform */
char* lwip_strnstr(const char* buffer, const char* token, size_t n);


uint32_t lwip_htonl(uint32_t n);

uint32_t lwip_ntohl(uint32_t n);

uint16_t lwip_htons(uint16_t n);

uint16_t lwip_ntohs(uint16_t n);

constexpr uint8_t kLwipMacAddrBase[] = { 0x00,0x01,0x02,0x03,0x04,0x5 };

constexpr auto kNetifMaxHwaddrLen = 6;

// typedef int64_t LONGLONG;

//typedef struct _LARGE_INTEGER {
//  LONGLONG QuadPart;
//} LARGE_INTEGER;

// typedef void* HANDLE;

typedef uintptr_t HCRYPTPROV;

int lwip_getpid();

#ifdef __cplusplus
}
#endif
