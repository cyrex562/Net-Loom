#pragma once
#include "netloom_status.h"
#include <cstdint>
#include <vector>
#define NOMINMAX
#ifdef _WIN32
#include "Windows.h"
#include <process.h>
#endif


#define OUTCHAR(c)	(buflen > 0? (--buflen, *buf++ = (c)): 0)

#define LWIP_ARRAYSIZE(x) (sizeof(x)/sizeof((x)[0]))  // NOLINT(cppcoreguidelines-macro-usage)


inline uint32_t
make_u32(const uint8_t a, const uint8_t b, const uint8_t c, const uint8_t d)
{
    return uint32_t(a & 0xff) << 24 | uint32_t(b & 0xff) << 16 | uint32_t(c & 0xff) << 8 |
        uint32_t(d & 0xff);
}


inline uint16_t
pp_htons(const uint16_t x)
{
    return uint16_t((x & uint16_t(0x00ffU)) << 8 | (x & uint16_t(0xff00U)) >> 8);
}


inline uint16_t
pp_ntohs(const uint16_t x) { return pp_htons(x); }


inline uint32_t
pp_htonl(const uint32_t x)
{
    return (x & uint32_t(0x000000ffUL)) << 24 | (x & uint32_t(0x0000ff00UL)) << 8 | (x &
        uint32_t(0x00ff0000UL)) >> 8 | (x & uint32_t(0xff000000UL)) >> 24;
}


inline uint32_t
pp_ntohl(const uint32_t x) { return pp_htonl(x); }


/* Functions that are not available as standard implementations.
 * In cc.h, you can #define these to implementations available on
 * your platform to save some code bytes if you use these functions
 * in your application, too.
 */

/* This can be #defined to strnicmp() or strncasecmp() depending on your platform */
int
lwip_strnicmp(const char* str1, const char* str2, size_t len);

int
ns_getpid();


inline std::tuple<NsStatus, uint32_t>
u8_vector_to_u32(std::vector<uint8_t> vec, const size_t offset)
{
    uint32_t out_u32;
    if (offset >= vec.size() || offset + 4 > vec.size()) {
        return std::make_tuple(STATUS_ERROR, out_u32);
    }
    out_u32 = vec[offset] << 24 | vec[offset + 1] << 16 | vec[offset + 2] << 8 | vec[
        offset + 3];
    return std::make_tuple(STATUS_SUCCESS, out_u32);
}


inline void
zero_mem(void* buf, const size_t len) { memset(buf, 0, len); }

/**
 * Convert the ASCII version of the password to Unicode. This implicitly supports 8-bit
 * ISO8859/1 characters. This gives us the little-endian representation, which is
 * assumed by all M$ CHAP RFCs.  (Unicode byte ordering is machine-dependent.)
 *
 */
inline std::tuple<NsStatus, std::wstring>
ascii_to_unicode(const std::string& str)
{
    std::wstring ret_wstr;
    const size_t wstr_len = str.length() * 2;
    wchar_t* wstr_raw = new wchar_t[wstr_len];
    memset(wstr_raw, 0, wstr_len);

#ifdef _WIN32
    if (MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.size(), wstr_raw, wstr_len) == 0
    ) { return std::make_tuple(STATUS_ERROR, ret_wstr); }
#elif unix
    // todo: call appropriate native function on Unix
#elif __APPLE__
    // todo: call appropriate native function on Mac OS X
#elif __linux__
    // todo: call appropriate native function on Linux
#elif __FreeBSD__
    // todo: call appropriate native function on Free BSD
#else
    // todo: throw an error/exception
#endif
    ret_wstr = std::wstring(wstr_raw);

    // std::wstring wstr;
    // wstr.reserve(str.length() * 2);
    //     std::wstring_convert<std::codecvt_utf8<char>> converter;
    //     wstr = converter.from_bytes(str);
    delete[] wstr_raw;
    return std::make_tuple(STATUS_SUCCESS, ret_wstr);
}




/**
 * Convert an uint16_t from host- to network byte order.
 *
 * @param n uint16_t in host byte order
 * @return n in network byte order
 */
uint16_t ns_htons(const uint16_t n) { return pp_htons(n); }

uint16_t ns_ntohs(const uint16_t n) { return pp_ntohs(n); }

uint32_t ns_ntohl(const uint32_t n) { return pp_ntohl(n); }

int ns_getpid()
{
    #if defined _WIN32
        return _getpid();
    #endif
}


/**
 * Convert an uint32_t from host- to network byte order.
 *
 * @param n uint32_t in host byte order
 * @return n in network byte order
 */
uint32_t lwip_htonl(const uint32_t n)
{
    return pp_htonl(n);
}




/**
 * @ingroup sys_nonstandard
 * lwIP default implementation for strnstr() non-standard function.
 * This can be \#defined to strnstr() depending on your platform port.
 */
char* lwip_strnstr(char* buffer, char* token, const size_t n)
{
    const auto tokenlen = strlen(token);
    if (tokenlen == 0)
    {
        return buffer;
    }
    for (auto p = buffer; *p && (p + tokenlen <= buffer + n); p++)
    {
        if ((*p == *token) && (strncmp(p, token, tokenlen) == 0))
        {
            return p;
        }
    }
    return nullptr;
}


/**
 * @ingroup sys_nonstandard
 * lwIP default implementation for stricmp() non-standard function.
 * This can be \#defined to stricmp() depending on your platform port.
 */
int lwip_stricmp(const char* str1, const char* str2)
{
    char c1;
    do
    {
        c1 = *str1++;
        const auto c2 = *str2++;
        if (c1 != c2)
        {
            const char c1_upc = c1 | 0x20;
            if ((c1_upc >= 'a') && (c1_upc <= 'z'))
            {
                /* characters are not equal an one is in the alphabet range:
                downcase both chars and check again */
                const char c2_upc = c2 | 0x20;
                if (c1_upc != c2_upc)
                {
                    /* still not equal */ /* don't care for < or > */
                    return 1;
                }
            }
            else
            {
                /* characters are not equal but none is in the alphabet range */
                return 1;
            }
        }
    }
    while (c1 != 0);
    return 0;
}



/**
 * @ingroup sys_nonstandard
 * lwIP default implementation for strnicmp() non-standard function.
 * This can be \#defined to strnicmp() depending on your platform port.
 */
int lwip_strnicmp(const char* str1, const char* str2, size_t len)
{
    char c1;
    do
    {
        c1 = *str1++;
        const auto c2 = *str2++;
        if (c1 != c2)
        {
            const char c1_upc = c1 | 0x20;
            if ((c1_upc >= 'a') && (c1_upc <= 'z'))
            {
                /* characters are not equal an one is in the alphabet range:
                downcase both chars and check again */
                const char c2_upc = c2 | 0x20;
                if (c1_upc != c2_upc)
                {
                    /* still not equal */ /* don't care for < or > */
                    return 1;
                }
            }
            else
            {
                /* characters are not equal but none is in the alphabet range */
                return 1;
            }
        }
        len--;
    }
    while ((len != 0) && (c1 != 0));
    return 0;
}



/**
 * @ingroup sys_nonstandard
 * lwIP default implementation for itoa() non-standard function.
 * This can be \#defined to itoa() or snprintf(result, bufsize, "%d", number)
 * depending on your platform port.
 */
void lwip_itoa(char* result, const size_t bufsize, const int number)
{
    auto res = result;
    auto tmp = result + bufsize - 1;
    auto n = (number >= 0) ? number : -number; /* handle invalid bufsize */
    if (bufsize < 2)
    {
        if (bufsize == 1)
        {
            *result = 0;
        }
        return;
    } /* First, add sign */
    if (number < 0)
    {
        *res++ = '-';
    } /* Then create the string from the end and stop if buffer full,
     and ensure output string is zero terminated */
    *tmp = 0;
    while ((n != 0) && (tmp > res))
    {
        const auto val = char('0' + (n % 10));
        tmp--;
        *tmp = val;
        n = n / 10;
    }
    if (n)
    {
        /* buffer is too small */
        *result = 0;
        return;
    }
    if (*tmp == 0)
    {
        /* Nothing added? */
        *res++ = '0';
        *res++ = 0;
        return;
    } /* move from temporary buffer to output buffer (sign is not moved) */
    memmove(res, tmp, size_t((result + bufsize) - tmp));
}
