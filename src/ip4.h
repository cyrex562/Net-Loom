#pragma once
#include <packet_buffer.h>
#include <ip4_addr.h>
#include <lwip_error.h>
#include <netif.h>
#include <arch.h>
#include <ip_addr.h>
/** This is the packed version of Ip4Addr,
     used in network headers that are itself packed */ // struct Ip4AddrPacked {
//     uint32_t addr;
// } ;
// typedef struct Ip4AddrPacked Ip4AddrPT;
/* Size of the IPv4 header. Same as 'sizeof(struct Ip4Hdr)'. */
constexpr auto kIp4HdrLen = 20; /* Maximum size of the IPv4 header with options. */
constexpr auto kIp4HdrLenMax = 60;
constexpr auto kIpResFlag = 0x8000U; /* reserved fragment flag */
constexpr auto kIpDFFlag = 0x4000U; /* don't fragment flag */
constexpr auto kIpMFFlag = 0x2000U; /* more fragments flag */
constexpr auto kIpOffMask = 0x1fffU; /* mask for fragmenting bits */ /* The IPv4 header */
struct Ip4Hdr
{
    /* version / header length */
    uint8_t _v_hl; /* type of service */
    uint8_t _tos; /* total length */
    uint16_t _len; /* identification */
    int16_t _id; /* fragment offset field */
    uint16_t _offset; /* time to live */
    uint8_t _ttl; /* protocol*/
    uint8_t _proto; /* checksum */
    uint16_t _chksum; /* source and destination IP addresses */
    Ip4Addr src;
    Ip4Addr dest;
}; /* Macros to get struct Ip4Hdr fields: */
inline uint8_t get_ip4_hdr_version(Ip4Hdr* hdr)
{
    return ((hdr)->_v_hl >> 4);
}

inline uint8_t get_ip4_hdr_hdr_len(Ip4Hdr* hdr)
{
    return ((hdr)->_v_hl & 0x0f);
}

inline uint8_t get_ip4_hdr_hdr_len_bytes(Ip4Hdr* hdr)
{
    return uint8_t(get_ip4_hdr_hdr_len(hdr) * 4);
}

inline uint8_t get_ip4_hdr_tos(Ip4Hdr* hdr)
{
    return ((hdr)->_tos);
}

inline uint16_t get_ip4_hdr_len(Ip4Hdr* hdr)
{
    return ((hdr)->_len);
}

inline uint16_t get_ip4_hdr_id(Ip4Hdr* hdr)
{
    return ((hdr)->_id);
}

inline uint16_t get_ip4_hdr_offset(Ip4Hdr* hdr)
{
    return ((hdr)->_offset);
}

inline uint16_t get_ip4_hdr_offset_bytes(Ip4Hdr* hdr)
{
    return uint16_t((lwip_ntohs(get_ip4_hdr_offset(hdr)) & kIpOffMask) * 8U);
}

inline uint8_t get_ip4_hdr_ttl(Ip4Hdr* hdr)
{
    return ((hdr)->_ttl);
}

inline uint8_t get_ip4_hdr_proto(Ip4Hdr* hdr)
{
    return ((hdr)->_proto);
}

inline uint16_t get_ip4_hdr_checksum(Ip4Hdr* hdr)
{
    return ((hdr)->_chksum);
} /* Macros to set struct Ip4Hdr fields: */
// ReSharper disable once CppInconsistentNaming
inline void set_ip4_hdr_vhl(Ip4Hdr* hdr, const uint8_t v, const uint8_t hl)
{
    hdr->_v_hl = uint8_t(v << 4 | hl);
}

inline void set_ip4_hdr_tos(Ip4Hdr* hdr, const uint8_t tos)
{
    (hdr)->_tos = (tos);
}

inline void set_ip4_hdr_len(Ip4Hdr* hdr, const uint16_t len)
{
    (hdr)->_len = (len);
}

inline void set_ip4_hdr_id(Ip4Hdr* hdr, const uint16_t id)
{
    (hdr)->_id = (id);
}

inline void set_ip4_hdr_offset(Ip4Hdr* hdr, const uint16_t off)
{
    (hdr)->_offset = (off);
}

inline void set_ip4_hdr_ttl(Ip4Hdr* hdr, const uint8_t ttl)
{
    (hdr)->_ttl = uint8_t(ttl);
}

inline void set_ip4_hdr_proto(Ip4Hdr* hdr, const uint8_t proto)
{
    (hdr)->_proto = uint8_t(proto);
}

inline void set_ip4_hdr_checksum(Ip4Hdr* hdr, const uint16_t chksum)
{
    (hdr)->_chksum = (chksum);
}

constexpr auto kLwipIpv4SrcRouting = 1; /* Compatibility define, no init needed. */
inline bool ip_init()
{
    return true;
}

NetIfc* ip4_route(const Ip4Addr* dest);

NetIfc* ip4_route_src(const Ip4Addr* src, const Ip4Addr* dest);

LwipStatus ip4_input(struct PacketBuffer* p, NetIfc* inp);

LwipStatus ip4_output(struct PacketBuffer* p,
                      const Ip4Addr* src,
                      const Ip4Addr* dest,
                      uint8_t ttl,
                      uint8_t tos,
                      uint8_t proto);

LwipStatus ip4_output_if(struct PacketBuffer* p,
                         const Ip4Addr* src,
                         const Ip4Addr* dest,
                         uint8_t ttl,
                         uint8_t tos,
                         uint8_t proto,
                         NetIfc* netif);

LwipStatus ip4_output_if_src(struct PacketBuffer* p,
                             const Ip4Addr* src,
                             const Ip4Addr* dest,
                             uint8_t ttl,
                             uint8_t tos,
                             uint8_t proto,
                             NetIfc* netif);

LwipStatus ip4_output_hinted(struct PacketBuffer* p,
                             const Ip4Addr* src,
                             const Ip4Addr* dest,
                             uint8_t ttl,
                             uint8_t tos,
                             uint8_t proto,
                             NetIfc* netif_hint);

LwipStatus ip4_output_if_opt(struct PacketBuffer* p,
                             const Ip4Addr* src,
                             const Ip4Addr* dest,
                             uint8_t ttl,
                             uint8_t tos,
                             uint8_t proto,
                             NetIfc* netif,
                             uint8_t* ip_options,
                             uint16_t optlen);

LwipStatus ip4_output_if_opt_src(struct PacketBuffer* p,
                                 const Ip4Addr* src,
                                 const Ip4Addr* dest,
                                 uint8_t ttl,
                                 uint8_t tos,
                                 uint8_t proto,
                                 NetIfc* netif,
                                 uint8_t* ip_options,
                                 uint16_t optlen);

void ip4_set_default_multicast_netif(NetIfc** default_multicast_netif);

// void ip4_debug_print(struct PacketBuffer *p);
