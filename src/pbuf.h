
#pragma once

#include "opt.h"
#include "lwip_error.h"

#include <cstdint>

#ifdef __cplusplus
extern "C" 
{
#endif

struct pbuf;

constexpr uint32_t kPbufTransportHlen = 20;
constexpr uint32_t kPbufIpHlen = 40;


/**
 * @ingroup PacketBuffer
 * Enumeration of PacketBuffer layers
 */
enum PbufLayer {
  /** Includes spare room for transport layer header, e.g. UDP header.
   * Use this if you intend to pass the PacketBuffer to functions like udp_send().
   */
  PBUF_TRANSPORT = PBUF_LINK_ENCAPSULATION_HLEN + PBUF_LINK_HLEN + kPbufIpHlen + kPbufTransportHlen,
  /** Includes spare room for IP header.
   * Use this if you intend to pass the PacketBuffer to functions like raw_send().
   */
  PBUF_IP = PBUF_LINK_ENCAPSULATION_HLEN + PBUF_LINK_HLEN + kPbufIpHlen,
  /** Includes spare room for link layer header (ethernet header).
   * Use this if you intend to pass the PacketBuffer to functions like ethernet_output().
   * @see PBUF_LINK_HLEN
   */
  PBUF_LINK = PBUF_LINK_ENCAPSULATION_HLEN + PBUF_LINK_HLEN,
  /** Includes spare room for additional encapsulation header before ethernet
   * headers (e.g. 802.11).
   * Use this if you intend to pass the PacketBuffer to functions like netif->linkoutput().
   * @see PBUF_LINK_ENCAPSULATION_HLEN
   */
  PBUF_RAW_TX = PBUF_LINK_ENCAPSULATION_HLEN,
  /** Use this for input packets in a netif driver when calling netif->input()
   * in the most common case - ethernet-layer netif driver. */
  PBUF_RAW = 0
} ;


/* Base flags for pbuf_type definitions: */

/** Indicates that the payload directly follows the struct PacketBuffer.
 *  This makes @ref pbuf_header work in both directions. */
constexpr auto kPbufTypeFlagStructDataContiguous = 0x80;
/** Indicates the data stored in this pbuf can change. If this pbuf needs
 * to be queued, it must be copied/duplicated. */
constexpr auto kPbufTypeFlagDataVolatile = 0x40;
/** 4 bits are reserved for 16 allocation sources (e.g. heap, pool1, pool2, etc)
 * Internally, we use: 0=heap, 1=MEMP_PBUF, 2=MEMP_PBUF_POOL -> 13 types free*/
constexpr auto kPbufTypeAllocSrcMask = 0x0F;
/** Indicates this pbuf is used for RX (if not set, indicates use for TX).
 * This information can be used to keep some spare RX buffers e.g. for
 * receiving TCP ACKs to unblock a connection) */
constexpr auto kPbufAllocFlagRx = 0x0100;
/** Indicates the application needs the pbuf payload to be in one piece */
constexpr auto kPbufAllocFlagDataContiguous = 0x0200;

constexpr auto kPbufTypeAllocSrcMaskStdHeap = 0x00;
constexpr auto kPbufTypeAllocSrcMaskStdMempPbuf = 0x01;
constexpr auto kPbufTypeAllocSrcMaskStdMempPbufPool = 0x02;
/** First pbuf allocation type for applications */
constexpr auto kPbufTypeAllocSrcMaskAppMin = 0x03;
/** Last pbuf allocation type for applications */
constexpr int kPbufTypeAllocSrcMaskAppMax = kPbufTypeAllocSrcMask;

/**
 * @ingroup PacketBuffer
 * Enumeration of PacketBuffer types
 */
typedef enum {
  /** PacketBuffer data is stored in RAM, used for TX mostly, struct PacketBuffer and its payload
      are allocated in one piece of contiguous memory (so the first payload byte
      can be calculated from struct PacketBuffer).
      pbuf_alloc() allocates PBUF_RAM pbufs as unchained pbufs (although that might
      change in future versions).
      This should be used for all OUTGOING packets (TX).*/
  PBUF_RAM = (kPbufAllocFlagDataContiguous | kPbufTypeFlagStructDataContiguous | kPbufTypeAllocSrcMaskStdHeap),
  /** pbuf data is stored in ROM, i.e. struct pbuf and its payload are located in
      totally different memory areas. Since it points to ROM, payload does not
      have to be copied when queued for transmission. */
  PBUF_ROM = kPbufTypeAllocSrcMaskStdMempPbuf,
  /** pbuf comes from the pbuf pool. Much like PBUF_ROM but payload might change
      so it has to be duplicated when queued before transmitting, depending on
      who has a 'ref' to it. */
  PBUF_REF = (kPbufTypeFlagDataVolatile | kPbufTypeAllocSrcMaskStdMempPbuf),
  /** pbuf payload refers to RAM. This one comes from a pool and should be used
      for RX. Payload can be chained (scatter-gather RX) but like PBUF_RAM, struct
      PacketBuffer and its payload are allocated in one piece of contiguous memory (so
      the first payload byte can be calculated from struct PacketBuffer).
      Don't use this for TX, if the pool becomes empty e.g. because of TCP queuing,
      you are unable to receive TCP acks! */
  PBUF_POOL = (kPbufAllocFlagRx | kPbufTypeFlagStructDataContiguous | kPbufTypeAllocSrcMaskStdMempPbufPool)
} pbuf_type;


/** indicates this packet's data should be immediately passed to the application */
constexpr auto PBUF_FLAG_PUSH = 0x01U;
/** indicates this is a custom pbuf: pbuf_free calls pbuf_custom->custom_free_function()
    when the last reference is released (plus custom PBUF_RAM cannot be trimmed) */
constexpr auto PBUF_FLAG_IS_CUSTOM = 0x02U;
/** indicates this pbuf is UDP multicast to be looped back */
constexpr auto PBUF_FLAG_MCASTLOOP = 0x04U;
/** indicates this pbuf was received as link-level broadcast */
constexpr auto PBUF_FLAG_LLBCAST = 0x08U;
/** indicates this pbuf was received as link-level multicast */
constexpr auto PBUF_FLAG_LLMCAST = 0x10U;
/** indicates this pbuf includes a TCP FIN flag */
constexpr auto PBUF_FLAG_TCP_FIN = 0x20U;

/** Main packet buffer struct */
struct PacketBuffer {
  /** next PacketBuffer in singly linked PacketBuffer chain */
  struct PacketBuffer *next;

  /** pointer to the actual data in the buffer */
  void *payload;

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

  /** a bit field indicating PacketBuffer type and allocation sources
      (see PBUF_TYPE_FLAG_*, PBUF_ALLOC_FLAG_* and PBUF_TYPE_ALLOC_SRC_MASK)
    */
  uint8_t type_internal;

  /** misc flags */
  uint8_t flags;

  /**
   * the reference count always equals the number of pointers
   * that refer to this PacketBuffer. This can be pointers from an application,
   * the stack itself, or PacketBuffer->next pointers from a chain.
   */
  uint32_t ref;

  /** For incoming packets, this contains the input netif's index */
  uint32_t if_idx;
};


inline bool PbufNeedsCopy(struct pbuf* p) {
    return (p->type_internal & kPbufTypeFlagDataVolatile);
}

/** Helper struct for const-correctness only.
 * The only meaning of this one is to provide a const payload pointer
 * for PBUF_ROM type.
 */
struct pbuf_rom {
  /** next PacketBuffer in singly linked PacketBuffer chain */
  struct PacketBuffer *next;

  /** pointer to the actual data in the buffer */
  const void *payload;
};


/** Prototype for a function to free a custom pbuf */
typedef void (*pbuf_free_custom_fn)(struct pbuf *p);

/** A custom PacketBuffer: like a PacketBuffer, but following a function pointer to free it. */
struct pbuf_custom {
  /** The actual PacketBuffer */
  struct PacketBuffer pbuf;
  /** This function is called when pbuf_free deallocates this PacketBuffer(_custom) */
  pbuf_free_custom_fn custom_free_function;
};


/** Define this to 0 to prevent freeing ooseq pbufs when the PBUF_POOL is empty */

extern volatile uint8_t pbuf_free_ooseq_pending;
void pbuf_free_ooseq();
/** When not using sys_check_timeouts(), call PBUF_CHECK_FREE_OOSEQ()
    at regular intervals from main level to check if ooseq pbufs need to be
    freed! */
inline void PbufCheckFreeOoseq()
{
    if (pbuf_free_ooseq_pending)
    {
        /* pbuf_alloc() reported PBUF_POOL to be empty -> try to free some \
           ooseq queued pbufs now */
        pbuf_free_ooseq();
    }
}


/* Initializes the PacketBuffer module. This call is empty for now, but may not be in future. */
#define pbuf_init()
struct pbuf* pbuf_alloc(PbufLayer l, uint16_t length, pbuf_type type);
struct pbuf* pbuf_alloc_reference(void* payload, uint16_t length, pbuf_type type);
struct pbuf* pbuf_alloced_custom(PbufLayer l,
                                 uint16_t length,
                                 pbuf_type type,
                                 struct pbuf_custom* p,
                                 void* payload_mem,
                                 uint16_t payload_mem_len);
void pbuf_realloc(struct pbuf* p, size_t size);

inline bool pbuf_get_allocsrc(pbuf* p)
{
    return ((p)->type_internal & kPbufTypeAllocSrcMask);
}

inline bool pbuf_match_allocsrc(pbuf* p, const int type)
{
    return (pbuf_get_allocsrc(p) == ((type) & kPbufTypeAllocSrcMask));
}

inline bool pbuf_match_type(pbuf* p, const int type)
{
    return pbuf_match_allocsrc(p, type);
}

uint8_t pbuf_header(struct pbuf* p, int16_t header_size);
uint8_t pbuf_header_force(struct pbuf* p, int16_t header_size);
uint8_t pbuf_add_header(struct pbuf* p, size_t header_size_increment);
uint8_t pbuf_add_header_force(struct pbuf* p, size_t header_size_increment);
uint8_t pbuf_remove_header(struct pbuf* p, size_t header_size);
struct pbuf* pbuf_free_header(struct pbuf* q, uint16_t size);
void pbuf_ref(struct pbuf* p);
uint8_t pbuf_free(struct pbuf* p);
uint16_t pbuf_clen(const struct pbuf* p);
void pbuf_cat(struct pbuf* head, struct pbuf* tail);
void pbuf_chain(struct pbuf* head, struct pbuf* tail);
struct pbuf* pbuf_dechain(struct pbuf* p);
err_t pbuf_copy(struct pbuf* p_to, const struct pbuf* p_from);
uint16_t pbuf_copy_partial(const struct pbuf* buf,
                           void* dataptr,
                           uint16_t len,
                           uint16_t offset);
void* pbuf_get_contiguous(const struct pbuf* p,
                          void* buffer,
                          size_t bufsize,
                          uint16_t len,
                          uint16_t offset);
err_t pbuf_take(struct pbuf* buf, const void* dataptr, uint16_t len);
err_t pbuf_take_at(struct pbuf* buf, const void* dataptr, uint16_t len, uint16_t offset);
struct pbuf* pbuf_skip(struct pbuf* in, uint16_t in_offset, uint16_t* out_offset);
struct pbuf* pbuf_coalesce(struct pbuf* p, PbufLayer layer);
struct pbuf* pbuf_clone(PbufLayer l, pbuf_type type, struct pbuf* p);
err_t pbuf_fill_chksum(struct pbuf* p,
                       uint16_t start_offset,
                       const void* dataptr,
                       uint16_t len,
                       uint16_t* chksum);


void pbuf_split_64k(struct pbuf *p, struct pbuf **rest);


uint8_t pbuf_get_at(const struct PacketBuffer* p, uint16_t offset);
int pbuf_try_get_at(const struct PacketBuffer* p, uint16_t offset);
void pbuf_put_at(struct PacketBuffer* p, uint16_t offset, uint8_t data);
uint16_t pbuf_memcmp(const struct PacketBuffer* p, uint16_t offset, const void* s2, uint16_t n);
uint16_t pbuf_memfind(const struct PacketBuffer* p, const void* mem, uint16_t mem_len, uint16_t start_offset);
uint16_t pbuf_strstr(const struct PacketBuffer* p, const char* substr);

#ifdef __cplusplus
}
#endif

