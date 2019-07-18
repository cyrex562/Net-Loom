#pragma once

#include "lwip_error.h"

/** Set to 1 to let rx use an own thread (only for NO_SYS==0).
 * If set to 0, ethernetif_poll is used to poll for packets.
 */


NetIfc*;

LwipError pcapif_init    (NetIfc*netif);
void  pcapif_shutdown(NetIfc*netif);


