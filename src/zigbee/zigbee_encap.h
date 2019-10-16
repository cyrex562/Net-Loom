/**
 * @file
 *
 * A netif implementing the ZigBee Eencapsulation Protocol (ZEP).
 * This is used to tunnel 6LowPAN over UDP.
 */

#pragma once
#include "lowpan6.h"
#include "network_interface.h"

constexpr auto ZEPIF_DEFAULT_UDP_PORT = 17754;


/** 
  * Pass this struct as 'state' to netif_add to control the behaviour of this netif. If NULL is 
  * passed, default behaviour is chosen 
  * 
 */
struct ZepifInit
{
    /** The UDP port used to ZEP frames from (0 = default) */
    uint16_t zep_src_udp_port;
    /** The UDP port used to ZEP frames to (0 = default) */
    uint16_t zep_dst_udp_port;
    /** The IP address to sed ZEP frames from (NULL = ANY) */
    IpAddrInfo zep_src_ip_addr;
    /** The IP address to sed ZEP frames to (NULL = BROADCAST) */
    IpAddrInfo zep_dst_ip_addr;
    /** If != NULL, the udp pcb is bound to this netif */
    NetworkInterface zep_netif;
    /** MAC address of the 6LowPAN device */
    MacAddress addr;
};


constexpr auto ZEP_MAX_DATA_LEN = 127;


struct ZepHdr {
  uint8_t prot_id[2];
  uint8_t prot_version;
  uint8_t type;
  uint8_t channel_id;
  uint16_t device_id;
  uint8_t crc_mode;
  uint8_t unknown_1;
  uint32_t timestamp[2];
  uint32_t seq_num;
  uint8_t unknown_2[10];
  uint8_t len;
} ;

struct ZepifState
{
    struct ZepifInit init;
    // struct UdpPcb* pcb;
    uint32_t seqno;
};

NsStatus zepif_init(NetworkInterface*netif);

//
// END OF FILE
//
