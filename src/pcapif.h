#pragma once

#include <lwip_status.h>

/** Set to 1 to let rx use an own thread (only for NO_SYS==0).
 * If set to 0, ethernetif_poll is used to poll for packets.
 */


NetworkInterface*;

LwipStatus pcapif_init    (NetworkInterface*netif);
void  pcapif_shutdown(NetworkInterface*netif);


