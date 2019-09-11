#pragma once
#include <cstdint>
#include <vector>
#include "lwip_status.h"
#include <locale>
#include <codecvt>


inline LwipStatus u8_vector_to_u32(std::vector<uint8_t> vec, const size_t offset, uint32_t out_u32)
{
    if (offset >= vec.size() || offset + 4 > vec.size()) {
        return STATUS_ERROR;
    }

    out_u32 = vec[offset] << 24 | vec[offset +1] << 16 | vec[offset + 2] << 8 | vec[offset + 3];
    return STATUS_SUCCESS;
}

inline void zero_mem(void* buf, size_t len)
{
    memset(buf ,0, len);
}

/**
 * Convert the ASCII version of the password to Unicode. This implicitly supports 8-bit
 * ISO8859/1 characters. This gives us the little-endian representation, which is
 * assumed by all M$ CHAP RFCs.  (Unicode byte ordering is machine-dependent.)
 *
 */
inline std::tuple<bool, std::wstring>
ascii_to_unicode(const std::string& str)
{
    std::wstring ret_wstr;
    const size_t wstr_len = str.length() * 2;
    wchar_t* wstr_raw = new wchar_t[wstr_len];
    memset(wstr_raw, 0, wstr_len);
    if (MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.size(), wstr_raw, wstr_len) == 0
    ) { return std::make_tuple(false, ret_wstr); }
#ifdef _MSVC_LANG
    ret_wstr = std::wstring(wstr_raw);
#else
    // todo: define use of the posix standard
#endif

    // std::wstring wstr;
    // wstr.reserve(str.length() * 2);
    //     std::wstring_convert<std::codecvt_utf8<char>> converter;
    //     wstr = converter.from_bytes(str);
    delete[] wstr_raw;
    return std::make_tuple(true, ret_wstr);
}
