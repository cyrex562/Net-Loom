#pragma once
#include <cstdint>
#include <vector>
#include "lwip_status.h"


inline LwipStatus u8_vector_to_u32(std::vector<uint8_t> vec, const size_t offset, uint32_t out_u32)
{
    if (offset >= vec.size() || offset + 4 > vec.size()) {
        return STATUS_ERROR;
    }

    out_u32 = vec[offset] << 24 | vec[offset +1] << 16 | vec[offset + 2] << 8 | vec[offset + 3];
    return STATUS_SUCCESS;
}
