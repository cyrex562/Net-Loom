#pragma once
#include <network_interface.h>
#include <packet_buffer.h>
#include <ip4_addr.h>
#include <lwip_status.h>

/** This is the packed version of Ip4Addr,
     used in network headers that are itself packed */ // struct Ip4AddrPacked {
//     uint32_t addr;
// } ;
// typedef struct Ip4AddrPacked Ip4AddrPT;
/* Size of the IPv4 header. Same as 'sizeof(struct Ip4Hdr)'. */
constexpr size_t IP4_HDR_LEN = 20; /* Maximum size of the IPv4 header with options. */
constexpr size_t IP4_HDR_LEN_MAX = 60;
constexpr uint16_t IP4_RES_FLAG = 0x8000U; /* reserved fragment flag */
constexpr uint16_t IP4_DF_FLAG = 0x4000U; /* don't fragment flag */
constexpr uint16_t IP4_MF_FLAG = 0x2000U; /* more fragments flag */
constexpr uint16_t IP4_OFF_MASK = 0x1fffU; /* mask for fragmenting bits */ /* The IPv4 header */

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
};

/* Macros to get struct Ip4Hdr fields: */
inline uint8_t get_ip4_hdr_version(const Ip4Hdr& hdr)
{
    return ((hdr)._v_hl >> 4);
}

inline uint8_t get_ip4_hdr_version2(const Ip4Hdr* hdr)
{
    return ((hdr)->_v_hl >> 4);
}

inline uint8_t get_ip4_hdr_hdr_len(const Ip4Hdr& hdr)
{
    return ((hdr)._v_hl & 0x0f);
}


inline uint8_t get_ip4_hdr_hdr_len2(const Ip4Hdr* hdr)
{
    return ((hdr)->_v_hl & 0x0f);
}


inline uint8_t get_ip4_hdr_hdr_len_bytes(const Ip4Hdr& hdr)
{
    return uint8_t(get_ip4_hdr_hdr_len(hdr) * 4);
}

inline uint8_t get_ip4_hdr_hdr_len_bytes2(const Ip4Hdr* hdr)
{
    return uint8_t(get_ip4_hdr_hdr_len2(hdr) * 4);
}

inline uint8_t get_ip4_hdr_tos(const Ip4Hdr& hdr)
{
    return ((hdr)._tos);
}

inline uint16_t get_ip4_hdr_len(const Ip4Hdr& hdr)
{
    return hdr._len;
}

inline uint16_t get_ip4_hdr_len2(const Ip4Hdr* hdr)
{
    return hdr->_len;
}

inline uint16_t get_ip4_hdr_id(const Ip4Hdr& hdr)
{
    return ((hdr)._id);
}

inline uint16_t get_ip4_hdr_offset(const Ip4Hdr& hdr)
{
    return ((hdr)._offset);
}

inline uint16_t get_ip4_hdr_offset_bytes(const Ip4Hdr& hdr)
{
    return uint16_t((lwip_ntohs(get_ip4_hdr_offset(hdr)) & IP4_OFF_MASK) * 8U);
}

inline uint8_t get_ip4_hdr_ttl(const Ip4Hdr& hdr)
{
    return ((hdr)._ttl);
}

inline uint8_t get_ip4_hdr_proto(const Ip4Hdr& hdr)
{
    return ((hdr)._proto);
}

inline uint16_t get_ip4_hdr_checksum(const Ip4Hdr& hdr)
{
    return ((hdr)._chksum);
} /* Macros to set struct Ip4Hdr fields: */
// ReSharper disable once CppInconsistentNaming
inline void set_ip4_hdr_vhl(Ip4Hdr& hdr, const uint8_t v, const uint8_t hl)
{
    hdr._v_hl = uint8_t(v << 4 | hl);
}

inline void set_ip4_hdr_tos(Ip4Hdr& hdr, const uint8_t tos)
{
    (hdr)._tos = (tos);
}

inline void set_ip4_hdr_len(Ip4Hdr& hdr, const uint16_t len)
{
    (hdr)._len = (len);
}

inline void set_ip4_hdr_id(Ip4Hdr& hdr, const uint16_t id)
{
    (hdr)._id = (id);
}

inline void set_ip4_hdr_offset(Ip4Hdr& hdr, const uint16_t off)
{
    (hdr)._offset = (off);
}

inline void set_ip4_hdr_ttl(Ip4Hdr& hdr, const uint8_t ttl)
{
    (hdr)._ttl = uint8_t(ttl);
}

inline void set_ip4_hdr_proto(Ip4Hdr& hdr, const uint8_t proto)
{
    (hdr)._proto = uint8_t(proto);
}

inline void set_ip4_hdr_checksum(Ip4Hdr& hdr, const uint16_t chksum)
{
    (hdr)._chksum = (chksum);
}

inline bool init_ip4_module()
{
    return true;
}


LwipStatus
get_netif_for_dst_ip4_addr(const Ip4Addr& dst_addr,
                           const std::vector<NetworkInterface>& netifs_to_check,
                           NetworkInterface& found_netif);


LwipStatus
source_route_ip4_addr(const Ip4AddrInfo& src,
                      const Ip4AddrInfo& dest,
                      NetworkInterface& out_netif,
                      const std::vector<NetworkInterface>& netifs);


bool
ip4_input(PacketBuffer& pkt_buf, NetworkInterface& netif, std::vector<NetworkInterface>& interfaces);
LwipStatus ip4_output(PacketBuffer& p,
                      const Ip4AddrInfo& src,
                      const Ip4AddrInfo& dest,
                      uint8_t ttl,
                      uint8_t tos,
                      uint8_t proto);
LwipStatus ip4_output_if(PacketBuffer& p,
                         const Ip4AddrInfo& src,
                         const Ip4AddrInfo& dest,
                         uint8_t ttl,
                         uint8_t tos,
                         uint8_t proto,
                         NetworkInterface& netif);
LwipStatus ip4_output_if_src(PacketBuffer& p,
                             const Ip4AddrInfo& src,
                             const Ip4AddrInfo& dest,
                             uint8_t ttl,
                             uint8_t tos,
                             uint8_t proto,
                             NetworkInterface& netif);

// LwipStatus ip4_output_hinted(struct PacketBuffer *p,
//                              const Ip4Addr *src,
//                              const Ip4Addr *dest,
//                              uint8_t ttl,
//                              uint8_t tos,
//                              uint8_t proto,
//                              NetIfcHint* netif_hint);


LwipStatus ip4_output_if_opt(struct PacketBuffer* p,
                             const Ip4Addr* src,
                             const Ip4Addr* dest,
                             uint8_t ttl,
                             uint8_t tos,
                             uint8_t proto,
                             NetworkInterface* netif,
                             uint8_t* ip_options,
                             uint16_t optlen);

LwipStatus ip4_output_if_opt_src(struct PacketBuffer* p,
                                 const Ip4Addr* src,
                                 const Ip4Addr* dest,
                                 uint8_t ttl,
                                 uint8_t tos,
                                 uint8_t proto,
                                 NetworkInterface* netif,
                                 uint8_t* ip_options,
                                 uint16_t optlen);

void ip4_set_default_multicast_netif(NetworkInterface** default_multicast_netif);

bool
can_forward_ip4_pkt(PacketBuffer& pkt_buf);


//
// END OF FILE
//
