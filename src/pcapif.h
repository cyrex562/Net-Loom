#pragma once

#include <lwip_status.h>
#include <network_interface.h>
// #include "pcap/pcap.h"
/* Define those to better describe your network interface.
   For now, we use 'e0', 'e1', 'e2' and so on */
#define IFNAME0                       'e'
#define IFNAME1                       '0'




#define PCAPIF_LINKCHECK_INTERVAL_MS 500

/* link state notification macro */

#define PCAPIF_NOTIFY_LINKSTATE(netif, linkfunc) sys_timeout(PCAPIF_LINKUP_DELAY, (sys_timeout_handler)linkfunc, netif)



/* Define PCAPIF_RX_LOCK_LWIP and PCAPIF_RX_UNLOCK_LWIP if you need to lock the lwIP core
   before/after pbuf_alloc() or netif->input() are called on RX. */

#define PCAPIF_RX_LOCK_LWIP()

#define PCAPIF_RX_UNLOCK_LWIP()


#define ETH_MIN_FRAME_LEN      60U
#define ETH_MAX_FRAME_LEN      1518U

#define ADAPTER_NAME_LEN       128
#define ADAPTER_DESC_LEN       128

#ifndef PCAPIF_LOOPBACKFILTER_NUM_TX_PACKETS
#define PCAPIF_LOOPBACKFILTER_NUM_TX_PACKETS  128
#endif



struct pcapipf_pending_packet {
  struct pcapipf_pending_packet *next;
  uint16_t len;
  uint8_t data[ETH_MAX_FRAME_LEN];
};

struct pcap_t;

/* Packet Adapter informations */
struct pcapif_private {
  void            *input_fn_arg;
  pcap_t          *adapter;
  char             name[ADAPTER_NAME_LEN];
  char             description[ADAPTER_DESC_LEN];
  int              shutdown_called;

  volatile int     rx_run;
  volatile int     rx_running;

  struct pcapifh_linkstate *link_state;
  enum pcapifh_link_event last_link_event;

  struct pcapipf_pending_packet packets[PCAPIF_LOOPBACKFILTER_NUM_TX_PACKETS];
  struct pcapipf_pending_packet *tx_packets;
  struct pcapipf_pending_packet *free_packets;

};


struct pcapif_pbuf_custom
{
   // struct pbuf_custom pc;
   struct PacketBuffer* p;
};


LwipStatus pcapif_init    (NetworkInterface*netif);
void  pcapif_shutdown(NetworkInterface*netif);

constexpr auto GUID_LEN = 128;

//
//
//

