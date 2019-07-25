///
/// file: packet_buffer.cpp
/// 
#include <opt.h>
#include <def.h>
#include <netif.h>
#include <packet_buffer.h>
#include <sys.h>
#include <inet_chksum.h>
#include <cstring>
#include <lwip_debug.h>
#define SIZEOF_STRUCT_PBUF LWIP_MEM_ALIGN_SIZE(sizeof(struct PacketBuffer))
/* Since the pool is created in memp, PBUF_POOL_BUFSIZE will be automatically
   aligned there. Therefore, PBUF_POOL_BUFSIZE_ALIGNED can be used here. */
#define PBUF_POOL_BUFSIZE_ALIGNED LWIP_MEM_ALIGN_SIZE(PBUF_POOL_BUFSIZE)

static const struct PacketBuffer* pbuf_skip_const(const struct PacketBuffer* in,
                                                  uint16_t in_offset,
                                                  uint16_t* out_offset);

/// Initialize members of struct PacketBuffer after allocation
static void
pbuf_init_alloced_pbuf(struct PacketBuffer* pbuf,
                       uint8_t* payload,
                       const size_t tot_len,
                       const size_t len,
                       const PbufType type
)
{
    pbuf->next = nullptr;
    pbuf->payload = payload;
    pbuf->tot_len = tot_len;
    pbuf->len = len;
    pbuf->type_internal = type;
    // pbuf->flags = flags;
    pbuf->ref = 1;
    pbuf->if_idx = NETIF_NO_INDEX;
}


///
/// @ingroup PacketBuffer
/// Allocates a PacketBuffer of the given type (possibly a chain for PBUF_POOL type).
///
/// The actual memory allocated for the PacketBuffer is determined by the
/// layer at which the PacketBuffer is allocated and the requested size
/// (from the size parameter).
///
/// @param layer header size
/// @param length size of the PacketBuffer's payload
/// @param type this parameter decides how and where the PacketBuffer
/// should be allocated as follows:
///
/// - PBUF_RAM: buffer memory for PacketBuffer is allocated as one large
///             chunk. This includes protocol headers as well.
/// - PBUF_ROM: no buffer memory is allocated for the PacketBuffer, even for
///             protocol headers. Additional headers must be prepended
///             by allocating another PacketBuffer and chain in to the front of
///             the ROM PacketBuffer. It is assumed that the memory used is really
///             similar to ROM in that it is immutable and will not be
///             changed. Memory which is dynamic should generally not
///             be attached to PBUF_ROM pbufs. Use PBUF_REF instead.
/// - PBUF_REF: no buffer memory is allocated for the PacketBuffer, even for
///             protocol headers. It is assumed that the PacketBuffer is only
///             being used in a single thread. If the PacketBuffer gets queued,
///             then pbuf_take should be called to copy the buffer.
/// - PBUF_POOL: the PacketBuffer is allocated as a PacketBuffer chain, with pbufs from
///              the PacketBuffer pool that is allocated during pbuf_init().
///
/// @return the allocated PacketBuffer. If multiple pbufs where allocated, this
/// is the first PacketBuffer of a PacketBuffer chain.
///
struct PacketBuffer*
pbuf_alloc(PbufLayer layer, size_t length)
{
    PbufType type = PBUF_RAM;
    struct PacketBuffer* p;
    auto offset = (uint16_t)layer;
    Logf(true | LWIP_DBG_TRACE, "pbuf_alloc(length=%d)\n", length);
    switch (type) {
    case PBUF_REF: /* fall through */ case PBUF_ROM:
        p = pbuf_alloc_reference(nullptr, length, type);
        break;
    case PBUF_POOL:
        {
            struct PacketBuffer *q, *last;
            uint16_t rem_len; /* remaining length */
            p = nullptr;
            last = nullptr;
            rem_len = length;
            do {
                uint16_t qlen; // q = (struct PacketBuffer *)memp_malloc(MEMP_PBUF_POOL);
                q = new PacketBuffer;
                if (q == nullptr) {
                    // pbuf_pool_is_empty(); /* free chain so far allocated */
                    if (p) {
                        // pbuf_free(p);
                    } /* bail out unsuccessfully */
                    return nullptr;
                }
                qlen = LWIP_MIN(rem_len,
                                (uint16_t)(PBUF_POOL_BUFSIZE_ALIGNED - LWIP_MEM_ALIGN_SIZE(
                                    offset)));
                // pbuf_init_alloced_pbuf(q,
                //                        q + LWIP_MEM_ALIGN_SIZE(sizeof(struct PacketBuffer)) +
                //                        offset,
                //                        rem_len,
                //                        qlen,
                //                        type,
                //                        0);
                // lwip_assert("pbuf_alloc: pbuf q->payload properly aligned",
                //             ((uintptr_t)q->payload % 1) == 0);
                lwip_assert("PBUF_POOL_BUFSIZE must be bigger than 1",
                            (PBUF_POOL_BUFSIZE_ALIGNED - LWIP_MEM_ALIGN_SIZE(offset)) > 0);
                if (p == nullptr) {
                    /* allocated head of PacketBuffer chain (into p) */
                    p = q;
                }
                else {
                    /* make previous PacketBuffer point to this PacketBuffer */
                    last->next = q;
                }
                last = q;
                rem_len = (uint16_t)(rem_len - qlen);
                offset = 0;
            }
            while (rem_len > 0);
            break;
        }
    case PBUF_RAM:
        {
            const auto payload_len = uint16_t(
                LWIP_MEM_ALIGN_SIZE(offset) + LWIP_MEM_ALIGN_SIZE(length));
            const auto alloc_len = size_t(
                LWIP_MEM_ALIGN_SIZE(LWIP_MEM_ALIGN_SIZE(sizeof(struct PacketBuffer))) +
                payload_len);
            /* bug #50040: Check for integer overflow when calculating alloc_len */
            if ((payload_len < LWIP_MEM_ALIGN_SIZE(length)) || (alloc_len <
                LWIP_MEM_ALIGN_SIZE(length))) {
                return nullptr;
            } /* If PacketBuffer is to be allocated in RAM, allocate memory for it. */
            p = new PacketBuffer;
            if (p == nullptr) {
                return nullptr;
            }
            // pbuf_init_alloced_pbuf(p,
            //                        p + LWIP_MEM_ALIGN_SIZE(sizeof(struct PacketBuffer)) +
            //                        offset,
            //                        length,
            //                        length,
            //                        type,
            //                        0);
            break;
        }
    default:
        lwip_assert("pbuf_alloc: erroneous type", false);
        return nullptr;
    }
    Logf(true | LWIP_DBG_TRACE,
         "pbuf_alloc(length=%d) == %p\n",
         length,
         static_cast<void *>(p));
    return p;
} /**
 * @ingroup PacketBuffer
 * Allocates a PacketBuffer for referenced data.
 * Referenced data can be volatile (PBUF_REF) or long-lived (PBUF_ROM).
 *
 * The actual memory allocated for the PacketBuffer is determined by the
 * layer at which the PacketBuffer is allocated and the requested size
 * (from the size parameter).
 *
 * @param payload referenced payload
 * @param length size of the PacketBuffer's payload
 * @param type this parameter decides how and where the PacketBuffer
 * should be allocated as follows:
 *
 * - PBUF_ROM: It is assumed that the memory used is really
 *             similar to ROM in that it is immutable and will not be
 *             changed. Memory which is dynamic should generally not
 *             be attached to PBUF_ROM pbufs. Use PBUF_REF instead.
 * - PBUF_REF: It is assumed that the PacketBuffer is only
 *             being used in a single thread. If the PacketBuffer gets queued,
 *             then pbuf_take should be called to copy the buffer.
 *
 * @return the allocated PacketBuffer.
 */
struct PacketBuffer*
pbuf_alloc_reference(uint8_t* payload,
                     const size_t length,
                     const PbufType type)
{
    lwip_assert("invalid PbufType", (type == PBUF_REF) || (type == PBUF_ROM));
    /* only allocate memory for the PacketBuffer structure */
    // p = (struct PacketBuffer *)memp_malloc(MEMP_PBUF);
    auto p = new PacketBuffer;
    if (p == nullptr) {
        Logf(true | LWIP_DBG_LEVEL_SERIOUS,
             "pbuf_alloc_reference: Could not allocate MEMP_PBUF for PBUF_%s.\n",
             type == PBUF_ROM ? "ROM" : "REF");
        return nullptr;
    }
    // pbuf_init_alloced_pbuf(p, payload, length, length, type, 0);
    return p;
} /**
 * @ingroup PacketBuffer
 * Initialize a custom PacketBuffer (already allocated).
 * Example of custom PacketBuffer usage: @ref zerocopyrx
 *
 * @param l header size
 * @param length size of the PacketBuffer's payload
 * @param type type of the PacketBuffer (only used to treat the PacketBuffer accordingly, as
 *        this function allocates no memory)
 * @param p pointer to the custom PacketBuffer to initialize (already allocated)
 * @param payload_mem pointer to the buffer that is used for payload and
 * headers, must be at least big enough to hold 'length' plus the header size,
 *        may be NULL if set later.
 *        ATTENTION: The caller is responsible for correct alignment of this
 * buffer!!
 * @param payload_mem_len the size of the 'payload_mem' buffer, must be at least
 *        big enough to hold 'length' plus the header size
 */
struct PacketBuffer*
pbuf_alloced_custom(PbufLayer l,
                    uint16_t length,
                    PbufType type,
                    struct pbuf_custom* p,
                    void* payload_mem,
                    uint16_t payload_mem_len)
{
    const auto offset = uint16_t(l);
    void* payload;
    Logf(true | LWIP_DBG_TRACE, "pbuf_alloced_custom(length=%d)\n", length);
    if (LWIP_MEM_ALIGN_SIZE(offset) + length > payload_mem_len) {
        Logf(true | LWIP_DBG_LEVEL_WARNING,
             "pbuf_alloced_custom(length=%d) buffer too short\n",
             length);
        return nullptr;
    }
    if (payload_mem != nullptr) {
        payload = static_cast<uint8_t *>(payload_mem) + LWIP_MEM_ALIGN_SIZE(offset);
    }
    else {
        payload = nullptr;
    }
    // pbuf_init_alloced_pbuf(&p->pbuf, payload, length, length, type, PBUF_FLAG_IS_CUSTOM);
    return &p->pbuf;
} /**
 * @ingroup PacketBuffer
 * Shrink a PacketBuffer chain to a desired length.
 *
 * @param p pbuf to shrink.
 * @param size desired new length of pbuf chain
 *
 * Depending on the desired length, the first few pbufs in a chain might
 * be skipped and left unchanged. The new last PacketBuffer in the chain will be
 * resized, and any remaining pbufs will be freed.
 *
 * @note If the PacketBuffer is ROM/REF, only the ->tot_len and ->len fields are
 * adjusted.
 * @note May not be called on a packet queue.
 *
 * @note Despite its name, pbuf_realloc cannot grow the size of a PacketBuffer (chain).
 */
void
pbuf_realloc(struct PacketBuffer* p, size_t size)
{
    lwip_assert("pbuf_realloc: p != NULL", p != nullptr);
    /* desired length larger than current length? */
    if (size >= p->tot_len) {
        /* enlarging not yet supported */
        return;
    } /* the pbuf chain grows by (size - p->tot_len) bytes
     * (which may be negative in case of shrinking) */
    const auto shrink = uint16_t(p->tot_len - size);
    /* first, step over any pbufs that should remain in the chain */
    uint16_t rem_len = size;
    struct PacketBuffer* q = p; /* should this PacketBuffer be kept? */
    while (rem_len > q->len) {
        /* decrease remaining length by PacketBuffer length */
        rem_len = (uint16_t)(rem_len - q->len); /* decrease total length indicator */
        q->tot_len = (uint16_t)(q->tot_len - shrink);
        /* proceed to next PacketBuffer in chain */
        q = q->next;
        lwip_assert("pbuf_realloc: q != NULL", q != nullptr);
    } /* we have now reached the new last PacketBuffer (in q) */
    /* rem_len == desired length for PacketBuffer q */
    /* shrink allocated memory for PBUF_RAM */
    /* (other types merely adjust their length fields */
    // if (rem_len != q->len && (q->flags & PBUF_FLAG_IS_CUSTOM) == 0)
    // {
    //     /* reallocate and adjust the length of the PacketBuffer that will be split */
    //     q = (PacketBuffer *)mem_trim(
    //         q, (mem_size_t)(((uint8_t *)q->payload - (uint8_t *)q) + rem_len));
    //     lwip_assert("mem_trim returned q == NULL", q != nullptr);
    // }
    /* adjust length fields for new last PacketBuffer */
    q->len = rem_len;
    q->tot_len = q->len; /* any remaining pbufs in chain? */
    if (q->next != nullptr) {
        /* free remaining pbufs in chain */
        // pbuf_free(q->next);
    } /* q is last packet in chain */
    q->next = nullptr;
} /**
 * Adjusts the payload pointer to reveal headers in the payload.
 * @see pbuf_add_header.
 *
 * @param p PacketBuffer to change the header size.
 * @param header_size_increment Number of bytes to increment header size.
 * @param force Allow 'header_size_increment > 0' for PBUF_REF/PBUF_ROM types
 *
 * @return non-zero on failure, zero on success.
 *
 */
static uint8_t
pbuf_add_header_impl(struct PacketBuffer* p,
                     const size_t header_size_increment,
                     const uint8_t force)
{
    uint8_t* payload;
    lwip_assert("p != NULL", p != nullptr);
    if ((p == nullptr) || (header_size_increment > 0xFFFF)) {
        return 1;
    }
    if (header_size_increment == 0) {
        return 0;
    }
    const auto increment_magnitude = uint16_t(header_size_increment);
    /* Do not allow tot_len to wrap as a result. */
    if (uint16_t(increment_magnitude + p->tot_len) < increment_magnitude) {
        return 1;
    }
    const uint16_t type_internal = p->type_internal; /* pbuf types containing payloads? */
    if (type_internal) {
        /* set new payload pointer */
        payload = static_cast<uint8_t *>(p->payload) - header_size_increment;
        /* boundary check fails? */
        if (static_cast<uint8_t *>(payload) < reinterpret_cast<uint8_t *>(p) +
            LWIP_MEM_ALIGN_SIZE(sizeof(struct PacketBuffer))) {
            Logf(true | LWIP_DBG_TRACE,
                 "pbuf_add_header: failed as %p < %p (not enough space for "
                 "new header size)\n",
                 (void *)payload,
                 (void *)((uint8_t *)p + LWIP_MEM_ALIGN_SIZE(sizeof(struct PacketBuffer))
                 )); /* bail out unsuccessfully */
            return 1;
        } /* PacketBuffer types referring to external payloads? */
    }
    else {
        /* hide a header in the payload? */
        if (force) {
            payload = (uint8_t *)p->payload - header_size_increment;
        }
        else {
            /* cannot expand payload to front (yet!)
             * bail out unsuccessfully */
            return 1;
        }
    }
    Logf(true | LWIP_DBG_TRACE,
         "pbuf_add_header: old %p new %p (%d)\n",
         static_cast<void *>(p->payload),
         static_cast<void *>(payload),
         increment_magnitude); /* modify PacketBuffer fields */
    p->payload = payload;
    p->len = uint16_t(p->len + increment_magnitude);
    p->tot_len = uint16_t(p->tot_len + increment_magnitude);
    return 0;
} /**
 * Adjusts the payload pointer to reveal headers in the payload.
 *
 * Adjusts the ->payload pointer so that space for a header
 * appears in the PacketBuffer payload.
 *
 * The ->payload, ->tot_len and ->len fields are adjusted.
 *
 * @param p PacketBuffer to change the header size.
 * @param header_size_increment Number of bytes to increment header size which
 *          increases the size of the PacketBuffer. New space is on the front.
 *          If header_size_increment is 0, this function does nothing and
 * returns successful.
 *
 * PBUF_ROM and PBUF_REF type buffers cannot have their sizes increased, so
 * the call will fail. A check is made that the increase in header size does
 * not move the payload pointer in front of the start of the buffer.
 *
 * @return non-zero on failure, zero on success.
 *
 */
uint8_t
pbuf_add_header(struct PacketBuffer* p, size_t header_size_increment)
{
    return pbuf_add_header_impl(p, header_size_increment, 0);
} /**
 * Same as @ref pbuf_add_header but does not check if 'header_size > 0' is
 * allowed. This is used internally only, to allow PBUF_REF for RX.
 */
uint8_t
pbuf_add_header_force(struct PacketBuffer* p, size_t header_size_increment)
{
    return pbuf_add_header_impl(p, header_size_increment, 1);
} /**
 * Adjusts the payload pointer to hide headers in the payload.
 *
 * Adjusts the ->payload pointer so that space for a header
 * disappears in the PacketBuffer payload.
 *
 * The ->payload, ->tot_len and ->len fields are adjusted.
 *
 * @param p PacketBuffer to change the header size.
 * @param header_size_decrement Number of bytes to decrement header size which
 *          decreases the size of the PacketBuffer.
 *          If header_size_decrement is 0, this function does nothing and
 * returns successful.
 * @return non-zero on failure, zero on success.
 *
 */
uint8_t
pbuf_remove_header(struct PacketBuffer* p, size_t header_size_decrement)
{
    lwip_assert("p != NULL", p != nullptr);
    if ((p == nullptr) || (header_size_decrement > 0xFFFF)) {
        return 1;
    }
    if (header_size_decrement == 0) {
        return 0;
    }
    uint16_t increment_magnitude = (uint16_t)header_size_decrement;
    /* Check that we aren't going to move off the end of the pbuf */
    // LWIP_ERROR("increment_magnitude <= p->len", (increment_magnitude <= p->len),
    //            return 1;);
    if (increment_magnitude > p->len) {
        return 1;
    } /* remember current payload pointer */
    void* payload = p->payload; // ; /* only used in Logf below */
    /* increase payload pointer (guarded by length check above) */
    p->payload = (uint8_t *)p->payload + header_size_decrement;
    /* modify PacketBuffer length fields */
    p->len = (uint16_t)(p->len - increment_magnitude);
    p->tot_len = (uint16_t)(p->tot_len - increment_magnitude);
    Logf(true | LWIP_DBG_TRACE,
         "pbuf_remove_header: old %p new %p (%d)\n",
         payload,
         p->payload,
         increment_magnitude);
    return 0;
}


//
// increment_magnitude
// =
// (uint16_t)header_size_decrement;
// /* Check that we aren't going to move off the end of the pbuf */
// // lwip_error("increment_magnitude <= p->len", (increment_magnitude <= p->len),
// //            return 1;);
// if
// (increment_magnitude
// >
// p
// ->
// len
// )
//   {
//       return 1;
//   }
//
//
// /* remember current payload pointer */
// payload
// =
// p
// ->
// payload; // ; /* only used in Logf below */
// /* increase payload pointer (guarded by length check above) */
// p
// ->
// payload
// =
// (uint8_t
// *
// )
// p
// ->
// payload
// +
// header_size_decrement; /* modify PacketBuffer length fields */
// p
// ->
// len
// =
// (uint16_t)(p->len - increment_magnitude);
// p
// ->
// tot_len
// =
// (uint16_t)(p->tot_len - increment_magnitude);
// Logf (
// true
// |
// LWIP_DBG_TRACE
// ,
// "pbuf_remove_header: old %p new %p (%d)\n"
// ,
// (
// void*
// )
// payload
// ,
// (
// void*
// )
// p
// ->
// payload
// ,
// increment_magnitude
// );
// return
// 0;
// }
static uint8_t
pbuf_header_impl(struct PacketBuffer* p,
                 int16_t header_size_increment,
                 uint8_t force)
{
    if (header_size_increment < 0) {
        return pbuf_remove_header(p, (size_t)-header_size_increment);
    }
    else {
        return pbuf_add_header_impl(p, (size_t)header_size_increment, force);
    }
} /**
 * Adjusts the payload pointer to hide or reveal headers in the payload.
 *
 * Adjusts the ->payload pointer so that space for a header
 * (dis)appears in the PacketBuffer payload.
 *
 * The ->payload, ->tot_len and ->len fields are adjusted.
 *
 * @param p PacketBuffer to change the header size.
 * @param header_size_increment Number of bytes to increment header size which
 * increases the size of the PacketBuffer. New space is on the front.
 * (Using a negative value decreases the header size.)
 * If header_size_increment is 0, this function does nothing and returns
 * successful.
 *
 * PBUF_ROM and PBUF_REF type buffers cannot have their sizes increased, so
 * the call will fail. A check is made that the increase in header size does
 * not move the payload pointer in front of the start of the buffer.
 * @return non-zero on failure, zero on success.
 *
 */
uint8_t
pbuf_header(struct PacketBuffer* p, int16_t header_size_increment)
{
    return pbuf_header_impl(p, header_size_increment, 0);
} /**
 * Same as pbuf_header but does not check if 'header_size > 0' is allowed.
 * This is used internally only, to allow PBUF_REF for RX.
 */
uint8_t
pbuf_header_force(struct PacketBuffer* p, int16_t header_size_increment)
{
    return pbuf_header_impl(p, header_size_increment, 1);
} /** Similar to pbuf_header(-size) but de-refs header pbufs for (size >= p->len)
 *
 * @param q pbufs to operate on
 * @param size The number of bytes to remove from the beginning of the PacketBuffer
 * list. While size >= p->len, pbufs are freed. ATTENTION: this is the opposite
 * direction as @ref pbuf_header, but takes an uint16_t not int16_t!
 * @return the new head PacketBuffer
 */
struct PacketBuffer*
pbuf_free_header(struct PacketBuffer* q, uint16_t size)
{
    struct PacketBuffer* p = q;
    uint16_t free_left = size;
    while (free_left && p) {
        if (free_left >= p->len) {
            struct PacketBuffer* f = p;
            free_left = (uint16_t)(free_left - p->len);
            p = p->next;
            f->next = nullptr;
            // pbuf_free(f);
        }
        else {
            pbuf_remove_header(p, free_left);
            free_left = 0;
        }
    }
    return p;
} /**
 * @ingroup PacketBuffer
 * Dereference a PacketBuffer chain or queue and deallocate any no-longer-used
 * pbufs at the head of this chain or queue.
 *
 * Decrements the PacketBuffer reference count. If it reaches zero, the PacketBuffer is
 * deallocated.
 *
 * For a PacketBuffer chain, this is repeated for each PacketBuffer in the chain,
 * up to the first PacketBuffer which has a non-zero reference count after
 * decrementing. So, when all reference counts are one, the whole
 * chain is free'd.
 *
 * @param p The PacketBuffer (chain) to be dereferenced.
 *
 * @return the number of pbufs that were de-allocated
 * from the head of the chain.
 *
 * @note MUST NOT be called on a packet queue (Not verified to work yet).
 * @note the reference counter of a PacketBuffer equals the number of pointers
 * that refer to the PacketBuffer (or into the PacketBuffer).
 *
 * @internal examples:
 *
 * Assuming existing chains a->b->c with the following reference
 * counts, calling free_pkt_buf(a) results in:
 *
 * 1->2->3 becomes ...1->3
 * 3->3->3 becomes 2->3->3
 * 1->1->2 becomes ......1
 * 2->1->1 becomes 1->1->1
 * 1->1->1 becomes .......
 *
 */
uint8_t
pbuf_free(struct PacketBuffer* p)
{
    struct PacketBuffer* q;
    if (p == nullptr) {
        lwip_assert("p != NULL", p != nullptr);
        /* if assertions are disabled, proceed with debug output */
        Logf(true | LWIP_DBG_LEVEL_SERIOUS, ("free_pkt_buf(p == NULL) was called.\n"));
        return 0;
    }
    Logf(true | LWIP_DBG_TRACE, "free_pkt_buf(%p)\n", (void *)p);
    uint8_t count = 0;
    /* de-allocate all consecutive pbufs from the head of the chain that
        * obtain a zero reference count after decrementing*/
    while (p != nullptr) {
        LWIP_PBUF_REF_T ref;
        sys_prot_t old_level;
        /* Since decrementing ref cannot be guaranteed to be a single machine
                * operation we must protect it. We put the new ref into a local variable to
                * prevent further protection. */
        SYS_ARCH_PROTECT(old_level);
        /* all pbufs in a chain are referenced at least once */
        lwip_assert("free_pkt_buf: p->ref > 0", p->ref > 0);
        /* decrease reference count (number of pointers to PacketBuffer) */
        ref = --(p->ref);
        sys_arch_unprotect(old_level); /* this PacketBuffer is no longer referenced to? */
        if (ref == 0) {
            /* remember next PacketBuffer in chain for next iteration */
            q = p->next;
            Logf(true | LWIP_DBG_TRACE, "free_pkt_buf: deallocating %p\n", (void *)p);
            uint8_t alloc_src = pbuf_get_allocsrc(p); /* is this a custom PacketBuffer? */
            if (p->is_custom) {
                struct pbuf_custom* pc = (struct pbuf_custom *)p;
                pc->custom_free_function(p);
            }
            else {
                delete p;
            }
            count++; /* proceed to next PacketBuffer */
            p = q; /* p->ref > 0, this PacketBuffer is still referenced to */
            /* (and so the remaining pbufs in chain as well) */
        }
        else {
            Logf(true | LWIP_DBG_TRACE,
                 "free_pkt_buf: %p has ref %d, ending here.\n",
                 static_cast<void *>(p),
                 uint16_t(ref)); /* stop walking through the chain */
            p = nullptr;
        }
    } /* return number of de-allocated pbufs */
    return count;
} /**
 * Count number of pbufs in a chain
 *
 * @param p first PacketBuffer of chain
 * @return the number of pbufs in a chain
 */
uint16_t
pbuf_clen(const struct PacketBuffer* p)
{
    uint16_t len = 0;
    while (p != nullptr) {
        ++len;
        p = p->next;
    }
    return len;
} /**
 * @ingroup PacketBuffer
 * Increment the reference count of the PacketBuffer.
 *
 * @param p PacketBuffer to increase reference counter of
 *
 */
void
pbuf_ref(struct PacketBuffer* p)
{
    /* PacketBuffer given? */
    if (p != nullptr) {
        // SYS_ARCH_SET(p->ref, (LWIP_PBUF_REF_T)(p->ref + 1));
        lwip_assert("PacketBuffer ref overflow", p->ref > 0);
    }
} /**
 * @ingroup PacketBuffer
 * Concatenate two pbufs (each may be a PacketBuffer chain) and take over
 * the caller's reference of the tail PacketBuffer.
 *
 * @note The caller MAY NOT reference the tail PacketBuffer afterwards.
 * Use pbuf_chain() for that purpose.
 *
 * This function explicitly does not check for tot_len overflow to prevent
 * failing to queue too long pbufs. This can produce invalid pbufs, so
 * handle with care!
 *
 * @see pbuf_chain()
 */
void
pbuf_cat(struct PacketBuffer* h, struct PacketBuffer* t)
{
    struct PacketBuffer* p;
    //    lwip_error("(h != NULL) && (t != NULL) (programmer violates API)",
    //               ((h != nullptr) && (t != nullptr)),
    // return;
    //    )
    //    ; /* proceed to last PacketBuffer of chain */
    for (p = h; p->next != nullptr; p = p->next) {
        /* add total length of second chain to all totals of first chain */
        p->tot_len = (uint16_t)(p->tot_len + t->tot_len);
        /* chain last PacketBuffer of head (p) with first of tail (t) */
        p->next = t;
        /* p->next now references t, but the caller will drop its reference to t,
          * so netto there is no change to the reference count of t.
          */
    }
}


/**

* @ingroup PacketBuffer
* Chain two pbufs (or PacketBuffer chains) together.
*
* The caller MUST call free_pkt_buf(t) once it has stopped
* using it. Use pbuf_cat() instead if you no longer use t.
*
* @param h head PacketBuffer (chain)
* @param t tail PacketBuffer (chain)
* @note The pbufs MUST belong to the same packet.
* @note MAY NOT be called on a packet queue.
*
* The ->tot_len fields of all pbufs of the head chain are adjusted.
* The ->next field of the last PacketBuffer of the head chain is adjusted.
* The ->ref field of the first PacketBuffer of the tail chain is adjusted.
*
*/
void
pbuf_chain(struct PacketBuffer* h, struct PacketBuffer* t)
{
    pbuf_cat(h, t); /* t is now referenced by h */
    pbuf_ref(t);
    Logf(true | LWIP_DBG_TRACE,
         "pbuf_chain: %p references %p\n",
         (uint8_t *)h,
         (uint8_t *)t);
}


/**
* Dechains the first PacketBuffer from its succeeding pbufs in the chain.
*
* Makes p->tot_len field equal to p->len.
* @param p PacketBuffer to dechain
* @return remainder of the PacketBuffer chain, or NULL if it was de-allocated.
* @note May not be called on a packet queue.
*/
struct PacketBuffer*
pbuf_dechain(struct PacketBuffer* p)
{
    uint8_t tail_gone = 1; /* tail */
    struct PacketBuffer* q = p->next; /* PacketBuffer has successor in chain? */
    if (q != nullptr) {
        /* assert tot_len invariant: (p->tot_len == p->len + (p->next?
         * p->next->tot_len: 0) */
        lwip_assert("p->tot_len == p->len + q->tot_len",
                    q->tot_len == p->tot_len - p->len);
        /* enforce invariant if assertion is disabled */
        q->tot_len = (uint16_t)(p->tot_len - p->len);
        /* decouple PacketBuffer from remainder */
        p->next = nullptr; /* total length of PacketBuffer p is its own length only */
        p->tot_len = p->len; /* q is no longer referenced by p, free it */
        Logf(true | LWIP_DBG_TRACE, "pbuf_dechain: unreferencing %p\n", (uint8_t *)q);
        tail_gone = pbuf_free(q);
        if (tail_gone > 0) {
            Logf(true | LWIP_DBG_TRACE,
                 "pbuf_dechain: deallocated %p (as it is no longer referenced)\n",
                 (uint8_t *)q);
        } /* return remaining tail or NULL if deallocated */
    } /* assert tot_len invariant: (p->tot_len == p->len + (p->next?
   * p->next->tot_len: 0) */
    lwip_assert("p->tot_len == p->len", p->tot_len == p->len);
    return ((tail_gone > 0) ? nullptr : q);
} /**
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
 * @param p_to PacketBuffer destination of the copy
 * @param p_from PacketBuffer source of the copy
 *
 * @return ERR_OK if PacketBuffer was copied
 *         ERR_ARG if one of the pbufs is NULL or p_to is not big
 *                 enough to hold p_from
 */
LwipStatus
pbuf_copy(struct PacketBuffer* p_to, const struct PacketBuffer* p_from)
{
    size_t offset_to = 0, offset_from = 0, len;
    Logf(true | LWIP_DBG_TRACE,
         "pbuf_copy(%p, %p)\n",
         (const void *)p_to,
         (const void *)p_from);
    /* is the target big enough to hold the source? */
    //        lwip_error("pbuf_copy: target not big enough to hold source",
    //                   ((p_to != nullptr) && (p_from != nullptr) && (p_to->tot_len >= p_from->
    //                       tot_len)),
    // return ERR_ARG;
    //        )
    //        ; /* iterate through PacketBuffer chain */
    do {
        /* copy one part of the original chain */
        if ((p_to->len - offset_to) >= (p_from->len - offset_from)) {
            /* complete current p_from fits into current p_to */
            len = p_from->len - offset_from;
        }
        else {
            /* current p_from does not fit into current p_to */
            len = p_to->len - offset_to;
        }
        memcpy((uint8_t *)p_to->payload + offset_to,
               (uint8_t *)p_from->payload + offset_from,
               len);
        offset_to += len;
        offset_from += len;
        lwip_assert("offset_to <= p_to->len", offset_to <= p_to->len);
        lwip_assert("offset_from <= p_from->len", offset_from <= p_from->len);
        if (offset_from >= p_from->len) {
            /* on to next p_from (if any) */
            offset_from = 0;
            p_from = p_from->next;
        }
        if (offset_to == p_to->len) {
            /* on to next p_to (if any) */
            offset_to = 0;
            p_to = p_to->next;
            //                lwip_error("p_to != NULL",
            //                           (p_to != nullptr) || (p_from == nullptr),
            // return ERR_ARG;
            //                )
            //                ;
        }
        if ((p_from != nullptr) && (p_from->len == p_from->tot_len)) {
            /* don't copy more than one packet! */
            //                lwip_error("pbuf_copy() does not allow packet queues!",
            //                           (p_from->next == nullptr),
            // return ERR_VAL;
            //                )
            //                ;
        }
        if ((p_to != nullptr) && (p_to->len == p_to->tot_len)) {
            /* don't copy more than one packet! */
            //                lwip_error("pbuf_copy() does not allow packet queues!",
            //                           (p_to->next == nullptr),
            // return ERR_VAL;
            //                )
            //                ;
        }
    }while (p_from);
        Logf(true | LWIP_DBG_TRACE, ("pbuf_copy: end of chain reached.\n"));
        return ERR_OK;
}


/**
* @ingroup PacketBuffer
* Copy (part of) the contents of a packet buffer
* to an application supplied buffer.
*
* @param buf the PacketBuffer from which to copy data
* @param dataptr the application supplied buffer
* @param len length of data to copy (dataptr must be big enough). No more
* than buf->tot_len will be copied, irrespective of len
* @param offset offset into the packet buffer from where to begin copying len
* bytes
* @return the number of bytes copied, or 0 on failure
*/
uint16_t
pbuf_copy_partial(const struct PacketBuffer* buf,
                  uint8_t* dataptr,
                  size_t len,
                  size_t offset)
{
    uint16_t left = 0;
    uint16_t copied_total = 0;
    //            lwip_error("pbuf_copy_partial: invalid dataptr",
    //                       (dataptr != nullptr),
    // return 0;
    //            )
    //            ; /* Note some systems use byte copy if dataptr or one of the PacketBuffer payload
    // * pointers are unaligned. */
    for (const struct PacketBuffer* p = buf; len != 0 && p != nullptr; p = p->next
    ) {
        if ((offset != 0) && (offset >= p->len)) {
            /* don't copy from this buffer -> on to the next */
            offset = (uint16_t)(offset - p->len);
        }
        else {
            /* copy from this buffer. maybe only partially. */
            uint16_t buf_copy_len = (uint16_t)(p->len - offset);
            if (buf_copy_len > len) {
                buf_copy_len = len;
            } /* copy the necessary parts of the buffer */
            memcpy(&((char *)dataptr)[left],
                   &((char *)p->payload)[offset],
                   buf_copy_len);
            copied_total = (uint16_t)(copied_total + buf_copy_len);
            left = (uint16_t)(left + buf_copy_len);
            len = (uint16_t)(len - buf_copy_len);
            offset = 0;
        }
    }
    return copied_total;
}


/**
 * @ingroup PacketBuffer
 * Get part of a PacketBuffer's payload as contiguous memory. The returned memory is
 * either a pointer into the PacketBuffer's payload or, if split over multiple pbufs,
 * a copy into the user-supplied buffer.
 *
 * @param p the PacketBuffer from which to copy data
 * @param buffer the application supplied buffer
 * @param bufsize size of the application supplied buffer
 * @param len length of data to copy (dataptr must be big enough). No more
 * than buf->tot_len will be copied, irrespective of len
 * @param offset offset into the packet buffer from where to begin copying len
 * bytes
 * @return the number of bytes copied, or 0 on failure
 */
uint8_t*
pbuf_get_contiguous(const struct PacketBuffer* p,
                    uint8_t* buffer,
                    size_t bufsize,
                    size_t len,
                    size_t offset)
{
    uint16_t out_offset;
 //    lwip_error("pbuf_get_contiguous: invalid dataptr",
 //               (buffer != nullptr),
 // return NULL;
 //    )
 //    ;
 //    lwip_error("pbuf_get_contiguous: invalid dataptr",
 //               (bufsize >= len),
 // return NULL;
 //    )
 //    ;
    const struct PacketBuffer* q = pbuf_skip_const(p, offset, &out_offset);
    if (q != nullptr) {
        if (q->len >= (out_offset + len)) {
            /* all data in this PacketBuffer, return zero-copy */
            return (uint8_t *)q->payload + out_offset;
        } /* need to copy */
        if (pbuf_copy_partial(q, buffer, len, out_offset) != len) {
            /* copying failed: PacketBuffer is too short */
            return nullptr;
        }
        return buffer;
    } /* PacketBuffer is too short (offset does not fit in) */
    return nullptr;
} /**
 * This method modifies a 'PacketBuffer chain', so that its total length is
 * smaller than 64K. The remainder of the original PacketBuffer chain is stored
 * in *rest.
 * This function never creates new pbufs, but splits an existing chain
 * in two parts. The tot_len of the modified packet queue will likely be
 * smaller than 64K.
 * 'packet queues' are not supported by this function.
 *
 * @param p the PacketBuffer queue to be split
 * @param rest pointer to store the remainder (after the first 64K)
 */
void
pbuf_split_64k(struct PacketBuffer* p, struct PacketBuffer** rest)
{
    *rest = nullptr;
    if ((p != nullptr) && (p->next != nullptr)) {
        uint16_t tot_len_front = p->len;
        struct PacketBuffer* i = p;
        struct PacketBuffer* r = p->next;
        /* continue until the total length (summed up as uint16_t) overflows */
        while ((r != nullptr) && ((uint16_t)(tot_len_front + r->len) >=
            tot_len_front)) {
            tot_len_front = (uint16_t)(tot_len_front + r->len);
            i = r;
            r = r->next;
        } /* i now points to last packet of the first segment. Set next
       pointer to NULL */
        i->next = nullptr;
        if (r != nullptr) {
            /* Update the tot_len field in the first part */
            for (i = p; i != nullptr; i = i->next) {
                i->tot_len = (uint16_t)(i->tot_len - r->tot_len);
                lwip_assert("tot_len/len mismatch in last PacketBuffer",
                            (i->next != nullptr) || (i->tot_len == i->len));
            }
            if (p->has_tcp_fin_flag) {
                    r->has_tcp_fin_flag = true;
            } /* tot_len field in rest does not need modifications */
            /* reference counters do not need modifications */
            *rest = r;
        }
    }
} /* Actual implementation of pbuf_skip() but returning const pointer... */
static const struct PacketBuffer*
pbuf_skip_const(const struct PacketBuffer* in,
                uint16_t in_offset,
                uint16_t* out_offset)
{
    uint16_t offset_left = in_offset;
    const struct PacketBuffer* q = in; /* get the correct PacketBuffer */
    while ((q != nullptr) && (q->len <= offset_left)) {
        offset_left = (uint16_t)(offset_left - q->len);
        q = q->next;
    }
    if (out_offset != nullptr) {
        *out_offset = offset_left;
    }
    return q;
} /**
 * @ingroup PacketBuffer
 * Skip a number of bytes at the start of a PacketBuffer
 *
 * @param in input PacketBuffer
 * @param in_offset offset to skip
 * @param out_offset resulting offset in the returned PacketBuffer
 * @return the PacketBuffer in the queue where the offset is
 */
struct PacketBuffer*
pbuf_skip(struct PacketBuffer* in,
          uint16_t in_offset,
          uint16_t* out_offset)
{
    PacketBuffer* out = pbuf_skip(in, in_offset, out_offset);
    return out;
} /**
 * @ingroup PacketBuffer
 * Copy application supplied data into a PacketBuffer.
 * This function can only be used to copy the equivalent of buf->tot_len data.
 *
 * @param buf PacketBuffer to fill with data
 * @param dataptr application supplied data buffer
 * @param len length of the application supplied data buffer
 *
 * @return ERR_OK if successful, ERR_MEM if the PacketBuffer is not big enough
 */
LwipStatus
pbuf_take(struct PacketBuffer* buf, const void* dataptr, size_t len)
{
    struct PacketBuffer* p;
    size_t buf_copy_len;
    size_t total_copy_len = len;
    size_t copied_total = 0;
 //    lwip_error("pbuf_take: buf not large enough",
 //               (buf->tot_len >= len),
 // return ERR_MEM;
 //    )
 //    ;
    if ((buf == nullptr) || (dataptr == nullptr) || (buf->tot_len < len)) {
        return ERR_ARG;
    } /* Note some systems use byte copy if dataptr or one of the PacketBuffer payload
   * pointers are unaligned. */
    for (struct PacketBuffer* p = buf; total_copy_len != 0; p = p->next) {
        lwip_assert("pbuf_take: invalid pbuf", p != nullptr);
        size_t buf_copy_len = total_copy_len;
        if (buf_copy_len > p->len) {
            /* this PacketBuffer cannot hold all remaining data */
            buf_copy_len = p->len;
        } /* copy the necessary parts of the buffer */
        memcpy(p->payload, &((const char *)dataptr)[copied_total], buf_copy_len);
        total_copy_len -= buf_copy_len;
        copied_total += buf_copy_len;
    }
    lwip_assert("did not copy all data",
                total_copy_len == 0 && copied_total == len);
    return ERR_OK;
} /**
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
pbuf_take_at(struct PacketBuffer* buf,
             const uint8_t* dataptr,
             uint16_t len,
             uint16_t offset)
{
    uint16_t target_offset;
    struct PacketBuffer* q = pbuf_skip(buf, offset, &target_offset);
    /* return requested data if PacketBuffer is OK */
    if ((q != nullptr) && (q->tot_len >= target_offset + len)) {
        uint16_t remaining_len = len;
        const uint8_t* src_ptr = (const uint8_t *)dataptr;
        lwip_assert("check pbuf_skip result", target_offset < q->len);
        uint16_t first_copy_len = (uint16_t)LWIP_MIN(q->len - target_offset, len);
        memcpy(((uint8_t *)q->payload) + target_offset, dataptr, first_copy_len);
        remaining_len = (uint16_t)(remaining_len - first_copy_len);
        src_ptr += first_copy_len;
        if (remaining_len > 0) {
            return pbuf_take(q->next, src_ptr, remaining_len);
        }
        return ERR_OK;
    }
    return ERR_MEM;
} /**
 * @ingroup PacketBuffer
 * Creates a single PacketBuffer out of a queue of pbufs.
 *
 * @remark: Either the source PacketBuffer 'p' is freed by this function or the original
 *          PacketBuffer 'p' is returned, therefore the caller has to check the result!
 *
 * @param p the source PacketBuffer
 * @param layer PbufLayer of the new PacketBuffer
 *
 * @return a new, single PacketBuffer (p->next is NULL)
 *         or the old PacketBuffer if allocation fails
 */
struct PacketBuffer*
pbuf_coalesce(struct PacketBuffer* p, PbufLayer layer)
{
    if (p->next == nullptr) {
        return p;
    }
    struct PacketBuffer* q = pbuf_clone(layer, PBUF_RAM, p);
    if (q == nullptr) {
        /* @todo: what do we do now? */
        return p;
    }
    pbuf_free(p);
    return q;
} /**
 * @ingroup PacketBuffer
 * Allocates a new PacketBuffer of same length (via pbuf_alloc()) and copies the source
 * PacketBuffer into this new PacketBuffer (using pbuf_copy()).
 *
 * @param layer PbufLayer of the new PacketBuffer
 * @param type this parameter decides how and where the PacketBuffer should be allocated
 *             (@see pbuf_alloc())
 * @param p the source PacketBuffer
 *
 * @return a new PacketBuffer or NULL if allocation fails
 */
struct PacketBuffer*
pbuf_clone(PbufLayer layer,
           PbufType type,
           struct PacketBuffer* p)
{
    struct PacketBuffer* q = pbuf_alloc(layer, p->tot_len);
    if (q == nullptr) {
        return nullptr;
    }
    LwipStatus err = pbuf_copy(q, p);; /* in case of LWIP_NOASSERT */
    lwip_assert("pbuf_copy failed", err == ERR_OK);
    return q;
} /**
 * Copies data into a single PacketBuffer (*not* into a PacketBuffer queue!) and updates
 * the checksum while copying
 *
 * @param p the PacketBuffer to copy data into
 * @param start_offset offset of p->payload where to copy the data to
 * @param dataptr data to copy into the PacketBuffer
 * @param len length of data to copy into the PacketBuffer
 * @param chksum pointer to the checksum which is updated
 * @return ERR_OK if successful, another error if the data does not fit
 *         within the (first) PacketBuffer (no PacketBuffer queues!)
 */
LwipStatus
pbuf_fill_chksum(struct PacketBuffer* p,
                 size_t start_offset,
                 const uint8_t* dataptr,
                 size_t len,
                 uint16_t* chksum)
{
    uint32_t acc;
    uint16_t copy_chksum;
    uint8_t* dst_ptr;
    lwip_assert("p != NULL", p != nullptr);
    lwip_assert("dataptr != NULL", dataptr != nullptr);
    lwip_assert("chksum != NULL", chksum != nullptr);
    lwip_assert("len != 0", len != 0);
    if ((start_offset >= p->len) || (start_offset + len > p->len)) {
        return ERR_ARG;
    }
    dst_ptr = ((uint8_t *)p->payload) + start_offset;
    copy_chksum = lwip_standard_checksum_COPY(dst_ptr, dataptr, len);
    if ((start_offset & 1) != 0) {
        copy_chksum = SWAP_BYTES_IN_WORD(copy_chksum);
    }
    acc = *chksum;
    acc += copy_chksum;
    *chksum = fold_u32(acc);
    return ERR_OK;
} /**
 * @ingroup PacketBuffer
 * Get one byte from the specified position in a PacketBuffer
 * WARNING: returns zero for offset >= p->tot_len
 *
 * @param p PacketBuffer to parse
 * @param offset offset into p of the byte to return
 * @return byte at an offset into p OR ZERO IF 'offset' >= p->tot_len
 */
uint8_t
pbuf_get_at(const struct PacketBuffer* p, uint16_t offset)
{
    int ret = pbuf_try_get_at(p, offset);
    if (ret >= 0) {
        return (uint8_t)ret;
    }
    return 0;
} /**
 * @ingroup PacketBuffer
 * Get one byte from the specified position in a PacketBuffer
 *
 * @param p PacketBuffer to parse
 * @param offset offset into p of the byte to return
 * @return byte at an offset into p [0..0xFF] OR negative if 'offset' >=
 * p->tot_len
 */
int
pbuf_try_get_at(const struct PacketBuffer* p, uint16_t offset)
{
    uint16_t q_idx;
    const struct PacketBuffer* q = pbuf_skip_const(p, offset, &q_idx);
    /* return requested data if PacketBuffer is OK */
    if ((q != nullptr) && (q->len > q_idx)) {
        return ((uint8_t *)q->payload)[q_idx];
    }
    return -1;
} /**
 * @ingroup PacketBuffer
 * Put one byte to the specified position in a PacketBuffer
 * WARNING: silently ignores offset >= p->tot_len
 *
 * @param p PacketBuffer to fill
 * @param offset offset into p of the byte to write
 * @param data byte to write at an offset into p
 */
void
pbuf_put_at(struct PacketBuffer* p, uint16_t offset, uint8_t data)
{
    uint16_t q_idx;
    struct PacketBuffer* q = pbuf_skip(p, offset, &q_idx);
    /* write requested data if PacketBuffer is OK */
    if ((q != nullptr) && (q->len > q_idx)) {
        ((uint8_t *)q->payload)[q_idx] = data;
    }
} /**
 * @ingroup PacketBuffer
 * Compare PacketBuffer contents at specified offset with memory s2, both of length n
 *
 * @param p PacketBuffer to compare
 * @param offset offset into p at which to start comparing
 * @param s2 buffer to compare
 * @param n length of buffer to compare
 * @return zero if equal, nonzero otherwise
 *         (0xffff if p is too short, diffoffset+1 otherwise)
 */
uint16_t
pbuf_memcmp(const struct PacketBuffer* p,
            uint16_t offset,
            const uint8_t* s2,
            uint16_t n)
{
    uint16_t start = offset;
    const struct PacketBuffer* q = p;
    /* PacketBuffer long enough to perform check? */
    if (p->tot_len < (offset + n)) {
        return 0xffff;
    } /* get the correct PacketBuffer from chain. We know it succeeds because of p->tot_len
   * check above. */
    while ((q != nullptr) && (q->len <= start)) {
        start = (uint16_t)(start - q->len);
        q = q->next;
    } /* return requested data if PacketBuffer is OK */
    for (uint16_t i = 0; i < n; i++) {
        /* We know pbuf_get_at() succeeds because of p->tot_len check above. */
        uint8_t a = pbuf_get_at(q, (uint16_t)(start + i));
        uint8_t b = ((const uint8_t *)s2)[i];
        if (a != b) {
            return (uint16_t)LWIP_MIN(i + 1, 0xFFFF);
        }
    }
    return 0;
} /**
 * @ingroup PacketBuffer
 * Find occurrence of mem (with length mem_len) in PacketBuffer p, starting at offset
 * start_offset.
 *
 * @param p PacketBuffer to search, maximum length is 0xFFFE since 0xFFFF is used as
 *        return value 'not found'
 * @param mem search for the contents of this buffer
 * @param mem_len length of 'mem'
 * @param start_offset offset into p at which to start searching
 * @return 0xFFFF if substr was not found in p or the index where it was found
 */
uint16_t
pbuf_memfind(const struct PacketBuffer* p,
             const uint8_t* mem,
             uint16_t mem_len,
             uint16_t start_offset)
{
    uint16_t max_cmp_start = (uint16_t)(p->tot_len - mem_len);
    if (p->tot_len >= mem_len + start_offset) {
        for (uint16_t i = start_offset; i <= max_cmp_start; i++) {
            uint16_t plus = pbuf_memcmp(p, i, mem, mem_len);
            if (plus == 0) {
                return i;
            }
        }
    }
    return 0xFFFF;
} /**
 * Find occurrence of substr with length substr_len in PacketBuffer p, start at offset
 * start_offset
 * WARNING: in contrast to strstr(), this one does not stop at the first \0 in
 * the PacketBuffer/source string!
 *
 * @param p PacketBuffer to search, maximum length is 0xFFFE since 0xFFFF is used as
 *        return value 'not found'
 * @param substr string to search for in p, maximum length is 0xFFFE
 * @return 0xFFFF if substr was not found in p or the index where it was found
 */
uint16_t
pbuf_strstr(const struct PacketBuffer* p, const char* substr)
{
    if ((substr == nullptr) || (substr[0] == 0) || (p->tot_len == 0xFFFF)) {
        return 0xFFFF;
    }
    size_t substr_len = strlen(substr);
    if (substr_len >= 0xFFFF) {
        return 0xFFFF;
    }
    return pbuf_memfind(p, substr, (uint16_t)substr_len, 0);
}
