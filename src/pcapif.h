#ifndef LWIP_PCAPIF_H
#define LWIP_PCAPIF_H

#ifdef __cplusplus
extern "C" {
#endif

#include "lwip_error.h"

/** Set to 1 to let rx use an own thread (only for NO_SYS==0).
 * If set to 0, ethernetif_poll is used to poll for packets.
 */
#ifndef PCAPIF_RX_USE_THREAD
#define PCAPIF_RX_USE_THREAD !NO_SYS
#endif
#if PCAPIF_RX_USE_THREAD && NO_SYS
#error "Can't create a dedicated RX thread with NO_SYS==1"
#endif

NetIfc*;

LwipError pcapif_init    (NetIfc*netif);
void  pcapif_shutdown(NetIfc*netif);
#if !PCAPIF_RX_USE_THREAD
void  pcapif_poll    (NetIfc*netif);
#endif /* !PCAPIF_RX_USE_THREAD */

#ifdef __cplusplus
}
#endif

#endif /* LWIP_PCAPIF_H */
