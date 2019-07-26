//
// file: packet_buffer.h
//

#pragma once

#include <cstdint>
#include <lwip_debug.h>
#include <lwip_status.h>
#include <opt.h>


/* @todo: We need a mechanism to prevent wasting memory in every pbuf
   (TCP vs. UDP, IPv4 vs. IPv6: UDP/IPv4 packets may waste up to 28 bytes) */

constexpr auto PBUF_TRANSPORT_HLEN = 20;
constexpr auto PBUF_IP_HLEN = 40;

///
/// @ingroup pbuf
/// Enumeration of pbuf layers
///
enum PbufLayer
{
    /** Includes spare room for transport layer header, e.g. UDP header.
     * Use this if you intend to pass the pbuf to functions like udp_send().
     */
    PBUF_TRANSPORT = PBUF_LINK_ENCAPSULATION_HLEN + PBUF_LINK_HLEN + PBUF_IP_HLEN +
    PBUF_TRANSPORT_HLEN,
    /** Includes spare room for IP header.
      * Use this if you intend to pass the pbuf to functions like raw_send().
      */
    PBUF_IP = PBUF_LINK_ENCAPSULATION_HLEN + PBUF_LINK_HLEN + PBUF_IP_HLEN,
    /** Includes spare room for link layer header (ethernet header).
      * Use this if you intend to pass the pbuf to functions like ethernet_output().
      * @see PBUF_LINK_HLEN
      */
    PBUF_LINK = PBUF_LINK_ENCAPSULATION_HLEN + PBUF_LINK_HLEN,
    /** Includes spare room for additional encapsulation header before ethernet
      * headers (e.g. 802.11).
      * Use this if you intend to pass the pbuf to functions like netif->linkoutput().
      * @see PBUF_LINK_ENCAPSULATION_HLEN
      */
    PBUF_RAW_TX = PBUF_LINK_ENCAPSULATION_HLEN,
    /** Use this for input packets in a netif driver when calling netif->input()
      * in the most common case - ethernet-layer netif driver. */
    PBUF_RAW = 0
};


/* Base flags for PbufType definitions: */
/** Indicates that the payload directly follows the PacketBuffer.
*  This makes @ref pbuf_header work in both directions. */
constexpr auto PBUF_TYPE_FLAG_STRUCT_DATA_CONTIGUOUS = 0x80;
/** Indicates the data stored in this pbuf can change. If this pbuf needs
* to be queued, it must be copied/duplicated. */
constexpr auto PBUF_TYPE_FLAG_DATA_VOLATILE = 0x40;
/** 4 bits are reserved for 16 allocation sources (e.g. heap, pool1, pool2, etc)
* Internally, we use: 0=heap, 1=MEMP_PBUF, 2=MEMP_PBUF_POOL -> 13 types free*/
constexpr auto PBUF_TYPE_ALLOC_SRC_MASK = 0x0F;
/** Indicates this pbuf is used for RX (if not set, indicates use for TX).
* This information can be used to keep some spare RX buffers e.g. for
* receiving TCP ACKs to unblock a connection) */
constexpr auto PBUF_ALLOC_FLAG_RX = 0x0100;
/** Indicates the application needs the pbuf payload to be in one piece */
constexpr auto PBUF_ALLOC_FLAG_DATA_CONTIGUOUS = 0x0200;
constexpr auto PBUF_TYPE_ALLOC_SRC_MASK_STD_HEAP = 0x00;
constexpr auto PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF = 0x01;
constexpr auto PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF_POOL = 0x02;
/** First pbuf allocation type for applications */
constexpr auto PBUF_TYPE_ALLOC_SRC_MASK_APP_MIN = 0x03;
/** Last pbuf allocation type for applications */
constexpr auto PBUF_TYPE_ALLOC_SRC_MASK_APP_MAX = PBUF_TYPE_ALLOC_SRC_MASK;

/**
 * @ingroup pbuf
 * Enumeration of pbuf types
 */
enum PbufType{
  /** pbuf data is stored in RAM, used for TX mostly, PacketBuffer and its payload
      are allocated in one piece of contiguous memory (so the first payload byte
      can be calculated from PacketBuffer).
      pbuf_alloc() allocates PBUF_RAM pbufs as unchained pbufs (although that might
      change in future versions).
      This should be used for all OUTGOING packets (TX).*/
  PBUF_RAM = (PBUF_ALLOC_FLAG_DATA_CONTIGUOUS | PBUF_TYPE_FLAG_STRUCT_DATA_CONTIGUOUS | PBUF_TYPE_ALLOC_SRC_MASK_STD_HEAP),
  /** pbuf data is stored in ROM, i.e. PacketBuffer and its payload are located in
      totally different memory areas. Since it points to ROM, payload does not
      have to be copied when queued for transmission. */
  PBUF_ROM = PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF,
  /** pbuf comes from the pbuf pool. Much like PBUF_ROM but payload might change
      so it has to be duplicated when queued before transmitting, depending on
      who has a 'ref' to it. */
  PBUF_REF = (PBUF_TYPE_FLAG_DATA_VOLATILE | PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF),
  /** pbuf payload refers to RAM. This one comes from a pool and should be used
      for RX. Payload can be chained (scatter-gather RX) but like PBUF_RAM, struct
      pbuf and its payload are allocated in one piece of contiguous memory (so
      the first payload byte can be calculated from PacketBuffer).
      Don't use this for TX, if the pool becomes empty e.g. because of TCP queuing,
      you are unable to receive TCP acks! */
  PBUF_POOL = (PBUF_ALLOC_FLAG_RX | PBUF_TYPE_FLAG_STRUCT_DATA_CONTIGUOUS | PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF_POOL)
} ;


/** indicates this packet's data should be immediately passed to the application */
// enum PbufFlags : uint8_t
// {
//     PBUF_FLAG_PUSH = 0x01U,
//     /** indicates this is a custom pbuf: free_pkt_buf calls pbuf_custom->custom_free_function()
//         when the last reference is released (plus custom PBUF_RAM cannot be trimmed) */
//     PBUF_FLAG_IS_CUSTOM =0x02U,
//     /**  */
//     PBUF_FLAG_MCASTLOOP =0x04U,
//     /**  */
//     PBUF_FLAG_LLBCAST =0x08U,
//     /** indicates this pbuf was received as link-level multicast */
//     PBUF_FLAG_LLMCAST =0x10U,
//     /
//     PBUF_FLAG_TCP_FIN =0x20U,
// };


/** Main packet buffer struct */
struct PacketBuffer {
  /** next pbuf in singly linked pbuf chain */
  struct PacketBuffer *next;

  /** pointer to the actual data in the buffer */
  uint8_t *payload;

  /**
   * total length of this buffer and all next buffers in chain
   * belonging to the same packet.
   *
   * For non-queue packet chains this is the invariant:
   * p->tot_len == p->len + (p->next? p->next->tot_len: 0)
   */
  size_t tot_len;

  /** length of this buffer */
  size_t len;

  /** a bit field indicating pbuf type and allocation sources
      (see PBUF_TYPE_FLAG_*, PBUF_ALLOC_FLAG_* and PBUF_TYPE_ALLOC_SRC_MASK)
    */
  PbufType type_internal;

  /** misc flags */
  // PbufFlags flags;
    /// indicates this is a custom pbuf: free_pkt_buf calls pbuf_custom->custom_free_function()
    /// when the last reference is released (plus custom PBUF_RAM cannot be trimmed)
    bool is_custom;
    /// indicates this pbuf is UDP multicast to be looped back
    bool multicast_loop;
    ///
    bool push;
    /// indicates this pbuf was received as link-level broadcast
    bool ll_broadcast;
    /// indicates this pbuf was received as link-level multicast
    bool ll_multicast;
    ///  indicates this pbuf includes a TCP FIN flag
    bool has_tcp_fin_flag;

  /**
   * the reference count always equals the number of pointers
   * that refer to this pbuf. This can be pointers from an application,
   * the stack itself, or pbuf->next pointers from a chain.
   */
  LWIP_PBUF_REF_T ref;

  /** For incoming packets, this contains the input netif's index */
  int if_idx;
};





/** @ingroup pbuf
 * PBUF_NEEDS_COPY(p): return a boolean value indicating whether the given
 * pbuf needs to be copied in order to be kept around beyond the current call
 * stack without risking being corrupted. The default setting provides safety:
 * it will make a copy iof any pbuf chain that does not consist entirely of
 * PBUF_ROM type pbufs. For setups with zero-copy support, it may be redefined
 * to evaluate to true in all cases, for example. However, doing so also has an
 * effect on the application side: any buffers that are *not* copied must also
 * *not* be reused by the application after passing them to lwIP. For example,
 * when setting PBUF_NEEDS_COPY to (0), after using udp_send() with a PBUF_RAM
 * pbuf, the application must free the pbuf immediately, rather than reusing it
 * for other purposes. For more background information on this, see tasks #6735
 * and #7896, and bugs #11400 and #49914. */
inline bool PbufNeedsCopy(PacketBuffer *p) {
  return p->type_internal & PBUF_TYPE_FLAG_DATA_VOLATILE;
}



/** Helper struct for const-correctness only.
 * The only meaning of this one is to provide a const payload pointer
 * for PBUF_ROM type.
 */
struct pbuf_rom {
  /** next pbuf in singly linked pbuf chain */
  struct PacketBuffer *next;

  /** pointer to the actual data in the buffer */
  const uint8_t *payload;
};

/** Prototype for a function to free a custom pbuf */
using pbuf_free_custom_fn = void (*)(struct PacketBuffer*);

/** A custom pbuf: like a pbuf, but following a function pointer to free it. */
struct pbuf_custom {
  /** The actual pbuf */
  struct PacketBuffer pbuf;
  /** This function is called when free_pkt_buf deallocates this pbuf(_custom) */
  pbuf_free_custom_fn custom_free_function;
};


/** Define this to 0 to prevent freeing ooseq pbufs when the PBUF_POOL is empty */

extern volatile uint8_t pbuf_free_ooseq_pending;

/** When not using sys_check_timeouts(), call PBUF_CHECK_FREE_OOSEQ()
    at regular intervals from main level to check if ooseq pbufs need to be
    freed! */
inline void pbuf_check_free_ooseq()
{
    // fixme: missing global ref and param ref.
    // if (pbuf_free_ooseq_pending)
    // {
    //     /* pbuf_alloc() reported PBUF_POOL to be empty -> try to free some \
    //        ooseq queued pbufs now */
    //     pbuf_free_ooseq();
    // }
}



/* Initializes the pbuf module. This call is empty for now, but may not be in future. */
#define pbuf_init()

struct PacketBuffer *pbuf_alloc(PbufLayer layer, size_t length);
struct PacketBuffer *pbuf_alloc_reference(uint8_t* payload, const size_t length, PbufType type);

struct PacketBuffer *pbuf_alloced_custom(PbufLayer l, uint16_t length, PbufType type,
                                 struct pbuf_custom *p, uint8_t *payload_mem,
                                 uint16_t payload_mem_len);

void pbuf_realloc(struct PacketBuffer *p, size_t size);

inline uint8_t pbuf_get_allocsrc(PacketBuffer* p)
{
    return ((p)->type_internal & PBUF_TYPE_ALLOC_SRC_MASK);
}

inline bool pbuf_match_allocsrc(PacketBuffer* p, const uint8_t type)
{
    return (pbuf_get_allocsrc(p) == ((type) & PBUF_TYPE_ALLOC_SRC_MASK));
}

inline bool pbuf_match_type(PacketBuffer* p, uint8_t type)
{
    return pbuf_match_allocsrc(p, type);
}

uint8_t pbuf_header(struct PacketBuffer* p, int16_t header_size);

uint8_t pbuf_header_force(struct PacketBuffer* p, int16_t header_size);

uint8_t pbuf_add_header(struct PacketBuffer* p, size_t header_size_increment);

uint8_t pbuf_add_header_force(struct PacketBuffer* p, size_t header_size_increment);

uint8_t pbuf_remove_header(struct PacketBuffer* p, size_t header_size);

struct PacketBuffer* pbuf_free_header(struct PacketBuffer* q, uint16_t size);

void pbuf_ref(struct PacketBuffer* p);

uint8_t free_pkt_buf(struct PacketBuffer* p);

uint16_t pbuf_clen(const struct PacketBuffer* p);

void pbuf_cat(struct PacketBuffer* head, struct PacketBuffer* tail);

void pbuf_chain(struct PacketBuffer* head, struct PacketBuffer* tail);

struct PacketBuffer* pbuf_dechain(struct PacketBuffer* p);

LwipStatus pbuf_copy(struct PacketBuffer* p_to, const struct PacketBuffer* p_from);

uint16_t pbuf_copy_partial(const struct PacketBuffer* pbuf,
                           uint8_t* dataptr,
                           size_t len,
                           size_t offset);

uint8_t* pbuf_get_contiguous(const struct PacketBuffer* p,
                             uint8_t* buffer,
                             size_t bufsize,
                             size_t len,
                             size_t offset);

LwipStatus pbuf_take(struct PacketBuffer* buf, const uint8_t* dataptr, size_t len);

LwipStatus pbuf_take_at(struct PacketBuffer* buf,
                        const uint8_t* dataptr,
                        size_t len,
                        size_t offset);

struct PacketBuffer* pbuf_skip(struct PacketBuffer* in,
                               uint16_t in_offset,
                               uint16_t* out_offset);

struct PacketBuffer* pbuf_coalesce(struct PacketBuffer* p, PbufLayer layer);

struct PacketBuffer* pbuf_clone(PbufLayer l, PbufType type, struct PacketBuffer* p);

LwipStatus pbuf_fill_chksum(PacketBuffer* p,
                            uint16_t start_offset,
                            const uint8_t* dataptr,
                            uint16_t len,
                            uint16_t* chksum);

void pbuf_split_64k(PacketBuffer* p, PacketBuffer** rest);


uint8_t pbuf_get_at(const struct PacketBuffer* p, uint16_t offset);
int pbuf_try_get_at(const struct PacketBuffer* p, uint16_t offset);
void pbuf_put_at(struct PacketBuffer* p, uint16_t offset, uint8_t data);
uint16_t pbuf_memcmp(const struct PacketBuffer* p, uint16_t offset, const void* s2, uint16_t n);
uint16_t pbuf_memfind(const struct PacketBuffer* p, const void* mem, uint16_t mem_len, uint16_t start_offset);
uint16_t pbuf_strstr(const struct PacketBuffer* p, const char* substr);

/** pbufs passed to IP must have a ref-count of 1 as their payload pointer
    gets altered as the packet is passed down the stack */
inline void check_pbuf_ip_rec_cnt_for_tx(PacketBuffer* p)
{
    lwip_assert("p->ref == 1", (p)->ref == 1);
}

//
// END OF FILE
//
