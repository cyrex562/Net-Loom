///
/// file: packet_buffer.cpp
///

#define NOMINMAX
#include "network_interface.h"
#include "packet_buffer.h"
#include "sys.h"
#include "inet_chksum.h"
#include <cstring>
#include "lwip_debug.h"
#include <algorithm>



/**
 * @ingroup PacketBuffer
 * Create PBUF_RAM copies of pbufs.
 *
 * Used to queue packets on behalf of the lwIP stack, such as
 * ARP based queueing.
 *
 * @note You MUST explicitly use p = pbuf_take(p);
 *
 * @note Only one packet is copied, no packet queue!
 *
 * @param dst_pbuf PacketBuffer destination of the copy
 * @param src_pbuf PacketBuffer source of the copy
 *
 * @return ERR_OK if PacketBuffer was copied
 *         ERR_ARG if one of the pbufs is NULL or p_to is not big
 *                 enough to hold p_from
 */
void
copy_pkt_buf(PacketBuffer& dst_pbuf, PacketBuffer& src_pbuf)
{
    dst_pbuf = src_pbuf;
}


/**
* @ingroup PacketBuffer
* Copy (part of) the contents of a packet buffer
* to an application supplied buffer.
*
* @param pbuf the PacketBuffer from which to copy data
* @param data the application supplied buffer
* @param len length of data to copy (dataptr must be big enough). No more
* than buf->tot_len will be copied, irrespective of len
* @param offset offset into the packet buffer from where to begin copying len
* bytes
* @return the number of bytes copied, or 0 on failure
*/
bool pbuf_copy_partial(const PacketBuffer& pbuf,
                       std::vector<uint8_t> data,
                       const size_t len,
                       const size_t offset)
{
    const auto buf_begin = pbuf.data.begin() + offset;
    const auto buf_end = buf_begin + len;
    data = std::vector<uint8_t>(buf_begin, buf_end);
    return true;
}


/**
 * @ingroup PacketBuffer
 * Same as pbuf_take() but puts data at an offset
 *
 * @param buf PacketBuffer to fill with data
 * @param dataptr application supplied data buffer
 * @param len length of the application supplied data buffer
 * @param offset offset in PacketBuffer where to copy dataptr to
 *
 * @return ERR_OK if successful, ERR_MEM if the PacketBuffer is not big enough
 */
LwipStatus
pbuf_take_at(PacketBuffer& buf,
             std::vector<uint8_t> dataptr,
             size_t offset)
{

    if (offset > buf.data.size()) {
        return STATUS_E_INVALID_PARAM;
    }

    auto i = offset;
    
    for (auto& it : dataptr) {
        if (i >= offset) {
            buf.data.push_back(it);
        } else {
            buf.data[i] = it;
        }
        i++;
    }

    return STATUS_SUCCESS;
} 


/**
 * @ingroup PacketBuffer
 * Allocates a new PacketBuffer of same length (via pbuf_alloc()) and copies the source
 * PacketBuffer into this new PacketBuffer (using pbuf_copy()).
 *
 * @param layer PbufLayer of the new PacketBuffer
 * @param type this parameter decides how and where the PacketBuffer should be allocated
 *             (@see pbuf_alloc())
 * @param pbuf_to_copy the source PacketBuffer
 *
 * @return a new PacketBuffer or NULL if allocation fails
 */
PacketBuffer
pbuf_clone(
    PacketBuffer& pbuf_to_copy)
{
    // struct PacketBuffer* q = pbuf_alloc();
    PacketBuffer q{};

    q = pbuf_to_copy;

    return q;
} 


/**
 * @ingroup PacketBuffer
 * Get one byte from the specified position in a PacketBuffer
 *
 * @param p PacketBuffer to parse
 * @param offset offset into p of the byte to return
 * @return byte at an offset into p [0..0xFF] OR negative if 'offset' >=
 * p->tot_len
 */
uint8_t
get_pbuf_byte_at(const PacketBuffer& p, size_t offset)
{
    return p.data[offset];
} 


/**
 * @ingroup PacketBuffer
 * Put one byte to the specified position in a PacketBuffer
 * WARNING: silently ignores offset >= p->tot_len
 *
 * @param p PacketBuffer to fill
 * @param offset offset into p of the byte to write
 * @param data byte to write at an offset into p
 */
LwipStatus
pbuf_put_at(PacketBuffer& p, size_t offset, uint8_t data)
{
    if (offset > p.data.size() - 1) {
        return STATUS_E_INVALID_PARAM;
    }
    else if (offset == p.data.size() - 1) {
        p.data.push_back(data);
    }
    else {
        p.data[offset] = data;
    }

    return STATUS_SUCCESS;
} 

//
// END OF FILE
//
