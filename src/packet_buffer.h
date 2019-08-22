/**
 * @file packet_buffer.h
 */

#pragma once

#include <cstdint>
#include <lwip_status.h>
#include <vector>

enum Direction
{
    DIR_IN,
    DIR_OUT
};

/** Main packet buffer struct */
struct PacketBuffer
{
    std::vector<uint8_t> bytes;
    uint32_t input_netif_idx;
    Direction direction;
    // todo: add an {offset : header/framing} map for processing
};


/* Initializes the pbuf module. This call is empty for now, but may not be in future. */
inline bool init_pkt_buf_module()
{
    return true;
}


void copy_pkt_buf(PacketBuffer& dst_pbuf, PacketBuffer& src_pbuf);


bool pbuf_copy_partial(const PacketBuffer& pbuf,
                       std::vector<uint8_t> data,
                       size_t len,
                       size_t offset);


LwipStatus pbuf_take_at(PacketBuffer& buf,
                        std::vector<uint8_t> dataptr,
                        size_t offset);


PacketBuffer pbuf_clone(PacketBuffer& pbuf_to_copy);

uint8_t get_pbuf_byte_at(const PacketBuffer& p, size_t offset);

LwipStatus pbuf_put_at(PacketBuffer& p, size_t offset, uint8_t data);



//
// END OF FILE
//
