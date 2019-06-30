/**
 * @file
 *
 * A netif implementing the ZigBee Eencapsulation Protocol (ZEP).
 * This is used to tunnel 6LowPAN over UDP.
 */

#pragma once

#include "opt.h"
#include "lowpan6.h"
#include "netif.h"

#ifdef __cplusplus
extern "C" {
#endif

constexpr auto kZepifDefaultUdpPort = 17754;

/** Pass this struct as 'state' to netif_add to control the behaviour
 * of this netif. If NULL is passed, default behaviour is chosen */
struct ZepifInit {
  /** The UDP port used to ZEP frames from (0 = default) */
  uint16_t               zep_src_udp_port;
  /** The UDP port used to ZEP frames to (0 = default) */
  uint16_t               zep_dst_udp_port;
  /** The IP address to sed ZEP frames from (NULL = ANY) */
  const ip_addr_t    *zep_src_ip_addr;
  /** The IP address to sed ZEP frames to (NULL = BROADCAST) */
  const ip_addr_t    *zep_dst_ip_addr;
  /** If != NULL, the udp pcb is bound to this netif */
  const struct netif *zep_netif;
  /** MAC address of the 6LowPAN device */
  uint8_t                addr[6];
};

err_t zepif_init(struct netif *netif);

#ifdef __cplusplus
}
#endif
