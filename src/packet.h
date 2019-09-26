/**
 * @file packet_buffer.h
 */

#pragma once

#include <cstdint>
#include "netloom_status.h"
#include <vector>

enum Direction
{
    DIR_IN,
    DIR_OUT
};

/** Main packet buffer struct */
struct PacketContainer
{
    std::vector<uint8_t> data;
    uint32_t input_netif_idx;
    Direction direction;
    // todo: add an {offset : header/framing} map for processing
};


inline PacketContainer
init_pkt_buf(size_t size = 0xffff)
{
    PacketContainer p{};
    p.data.reserve(size);
    return p;
}


/* Initializes the pbuf module. This call is empty for now, but may not be in future. */
inline bool init_pkt_buf_module()
{
    return true;
}


void copy_pkt_buf(PacketContainer& dst_pbuf, PacketContainer& src_pbuf);


bool pbuf_copy_partial(const PacketContainer& pbuf,
                       std::vector<uint8_t> data,
                       size_t len,
                       size_t offset);


NsStatus pbuf_take_at(PacketContainer& buf,
                        std::vector<uint8_t> dataptr,
                        size_t offset);


PacketContainer pbuf_clone(PacketContainer& pbuf_to_copy);

uint8_t get_pbuf_byte_at(const PacketContainer& p, size_t offset);

NsStatus pbuf_put_at(PacketContainer& p, size_t offset, uint8_t data);



//
// END OF FILE
//
