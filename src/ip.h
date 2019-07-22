#pragma once
#include <ip4.h>
#include <ip6.h>
#include <ip_addr.h>
#include <lwip_error.h>
#include <packet_buffer.h>

enum IpProto
{
    IP_PROTO_ICMP= 1,
    IP_PROTO_IGMP= 2,
    IP_PROTO_UDP= 17,
    IP_PROTO_UDPLITE= 136,
    IP_PROTO_TCP= 6,
};


/** This operates on a void* by loading the first byte */
inline uint8_t get_ip_hdr_version(void* ptr)
{
    return *static_cast<uint8_t *>(ptr) >> 4;
}



struct IpPcb
{
    /* Common members of all PCB types */
    IpAddr local_ip;
    IpAddr remote_ip; /* Bound netif index */
    uint8_t netif_idx; /* Socket options */
    uint8_t so_options; /* Type Of Service */
    uint8_t tos; /* Time To Live */
    uint8_t ttl; /* link layer address resolution hint */
    NetIfc* netif_hints;
};

// struct IpPcb;
//
inline bool match_exact_ip_addr_pcb_vers(IpPcb* pcb, IpAddr* ipaddr)
{
    return (get_ip_addr_type(&pcb->local_ip) == get_ip_addr_type(ipaddr));
}

inline bool match_ip_addr_pcb_version(IpPcb* pcb, IpAddr* ipaddr)
{
    return (is_ip_addr_any_type_val(pcb->local_ip) || match_exact_ip_addr_pcb_vers(pcb, ipaddr));
}

/*
 * Option flags per-socket. These are the same like SO_XXX in sockets.h
 */
enum IpSockOptFlags : uint16_t
{
    SOF_REUSEADDR = 0x04U,
    SOF_KEEPALIVE = 0x08U,
    SOF_BROADCAST = 0x20U,
};


/* These flags are inherited (e.g. from a listen-pcb to a connection-pcb): */
constexpr auto  kSofInherited = (SOF_REUSEADDR | SOF_KEEPALIVE);

/** Global variables of this module, kept in a struct for efficient access using
 * base+index. */
struct IpGlobals
{
    /** The interface that accepted the packet for the current callback
     * invocation. */
    NetIfc* current_netif;
    /** The interface that received the packet for the current callback
      * invocation. */
    NetIfc* current_input_netif;
    /** Header of the input packet currently being processed. */
    const struct Ip4Hdr* current_ip4_header;
    /** Header of the input IPv6 packet currently being processed. */
    struct Ip6Hdr* current_ip6_header;
    /** Total header length of current_ip4/6_header (i.e. after this, the UDP/TCP
      * header starts) */
    uint16_t current_ip_header_tot_len; /** Source IP address of current_header */
    IpAddr current_iphdr_src; /** Destination IP address of current_header */
    IpAddr current_iphdr_dest;
};

// extern struct IpGlobals ip_data;

/** Get the interface that accepted the current packet.
 * This may or may not be the receiving netif, depending on your network setup.
 * This function must only be called from a receive callback (udp_recv,
 * raw_recv, tcp_accept). It will return NULL otherwise. */
// inline NetIfc* ip_current_netif()
// {
//     return (ip_data.current_netif);
// }

/** Get the interface that received the current packet.
 * This function must only be called from a receive callback (udp_recv,
 * raw_recv, tcp_accept). It will return NULL otherwise. */
// #define ip_current_input_netif() (ip_data.current_input_netif)
/** Total header length of ip(6)_current_header() (i.e. after this, the UDP/TCP
 * header starts) */
// #define ip_current_header_tot_len() (ip_data.current_ip_header_tot_len)
/** Source IP address of current_header */
// #define ip_current_src_addr() (&ip_data.current_iphdr_src)
/** Destination IP address of current_header */
// #define ip_current_dest_addr() (&ip_data.current_iphdr_dest)

/** Get the IPv4 header of the current packet.
 * This function must only be called from a receive callback (udp_recv,
 * raw_recv, tcp_accept). It will return NULL otherwise. */
// #define ip4_current_header() ip_data.current_ip4_header
/** Get the IPv6 header of the current packet.
 * This function must only be called from a receive callback (udp_recv,
 * raw_recv, tcp_accept). It will return NULL otherwise. */
// #define ip6_current_header() \
//   ((const struct ip6_hdr *)(ip_data.current_ip6_header))
/** Returns TRUE if the current IP input packet is IPv6, FALSE if it is IPv4 */
// #define ip_current_is_v6() (ip6_current_header() != NULL)

// Source IPv6 address of current_header
// inline const Ip6Addr* ip6_current_src_addr()
// {
//     return (convert_ip_addr_to_ip6_addr(&ip_data.current_iphdr_src));
// }


// Destination IPv6 address of current_header
// inline const Ip6Addr* ip6_current_dest_addr()
// {
//     return (convert_ip_addr_to_ip6_addr(&ip_data.current_iphdr_dest));
// }


/** Get the transport layer protocol */
// #define ip_current_header_proto()                        \
//   (ip_current_is_v6() ? IP6H_NEXTH(ip6_current_header()) \
//                       : IPH_PROTO(ip4_current_header()))
/** Get the transport layer header */
// #define ip_next_header_ptr()                                      \
//   ((const uint8_t *)((ip_current_is_v6()                             \
//                        ? (const uint8_t *)ip6_current_header()    \
//                        : (const uint8_t *)ip4_current_header()) + \
//                   ip_current_header_tot_len()))

// Source IP4 address of current_header
// inline const Ip4Addr *ip4_current_src_addr() {
//   return convert_ip_addr_to_ip4_addr(&ip_data.current_iphdr_src);
// }

// Destination IP4 address of current_header
// inline const Ip4Addr *ip4_current_dest_addr() {
//   return (convert_ip_addr_to_ip4_addr(&ip_data.current_iphdr_dest));
// }

/** Union source address of current_header */
// #define ip_current_src_addr() (&ip_data.current_iphdr_src)
/** Union destination address of current_header */
// inline IpAddr* ip_current_dest_addr()
//  { return &ip_data.current_iphdr_dest; }

//
// Gets an IP pcb option (SOF_* flags)
//
inline uint8_t ip_get_option(IpPcb* pcb, const uint8_t opt)
{
    return ((pcb)->so_options & (opt));
}

//
// Sets an IP pcb option (SOF_* flags)
//
inline void ip_set_option(uint8_t* so_options, const uint8_t opt)
{
    *so_options = uint8_t(*so_options | opt);
}

//
// Resets an IP pcb option (SOF_* flags)
//
inline void ip_reset_option(IpPcb* pcb, const uint8_t opt)
{
    pcb->so_options = uint8_t(pcb->so_options & ~opt);
}

/**
 * @ingroup ip
 * Output IP packet, netif is selected by source address
 */
#define ip_output(p, src, dest, ttl, tos, proto)                       \
  (IpIsV6(dest)                                                        \
       ? ip6_output(p, ip_2_ip6(src), ip_2_ip6(dest), ttl, tos, proto) \
       : ip4_output(p, ip_2_ip4(src), ip_2_ip4(dest), ttl, tos, proto))
/**
 * @ingroup ip
 * Output IP packet to specified interface
 */
#define ip_output_if(p, src, dest, ttl, tos, proto, netif)                  \
  (IpIsV6(dest) ? ip6_output_if(p, ip_2_ip6(src), ip_2_ip6(dest), ttl, tos, \
                                proto, netif)                               \
                : ip4_output_if(p, ip_2_ip4(src), ip_2_ip4(dest), ttl, tos, \
                                proto, netif))
/**
 * @ingroup ip
 * Output IP packet to interface specifying source address
 */
#define ip_output_if_src(p, src, dest, ttl, tos, proto, netif)             \
  (IpIsV6(dest) ? ip6_output_if_src(p, ip_2_ip6(src), ip_2_ip6(dest), ttl, \
                                    tos, proto, netif)                     \
                : ip4_output_if_src(p, ip_2_ip4(src), ip_2_ip4(dest), ttl, \
                                    tos, proto, netif))
/** Output IP packet that already includes an IP header. */
#define ip_output_if_hdrincl(p, src, dest, netif)                         \
  (IpIsV6(dest)                                                           \
       ? ip6_output_if(p, ip_2_ip6(src), LWIP_IP_HDRINCL, 0, 0, 0, netif) \
       : ip4_output_if(p, ip_2_ip4(src), LWIP_IP_HDRINCL, 0, 0, 0, netif))
/** Output IP packet with netif_hint */
#define ip_output_hinted(p, src, dest, ttl, tos, proto, netif_hint)        \
  (IpIsV6(dest) ? ip6_output_hinted(p, ip_2_ip6(src), ip_2_ip6(dest), ttl, \
                                    tos, proto, netif_hint)                \
                : ip4_output_hinted(p, ip_2_ip4(src), ip_2_ip4(dest), ttl, \
                                    tos, proto, netif_hint))
/**
 * @ingroup ip
 * Get netif for address combination. See \ref ip6_route and \ref ip4_route
 */
#define ip_route(src, dest)                                \
  (IpIsV6(dest) ? ip6_route(ip_2_ip6(src), ip_2_ip6(dest)) \
                : ip4_route_src(ip_2_ip4(src), ip_2_ip4(dest)))
/**
 * @ingroup ip
 * Get netif for IP.
 */
#define ip_netif_get_local_ip(netif, dest)                      \
  (IpIsV6(dest) ? ip6_netif_get_local_ip(netif, ip_2_ip6(dest)) \
                : ip4_netif_get_local_ip(netif))
#define ip_debug_print(is_ipv6, p) \
  ((is_ipv6) ? ip6_debug_print(p) : ip4_debug_print(p))

LwipStatus ip_input(struct PacketBuffer *p, NetIfc *inp);

#define ip_route_get_local_ip(src, dest, netif, ipaddr) \
  do {                                                  \
    (netif) = ip_route(src, dest);                      \
    (ipaddr) = ip_netif_get_local_ip(netif, dest);      \
  } while (0)
