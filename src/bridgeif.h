/**
 * @file
 * lwIP netif implementing an IEEE 802.1D MAC Bridge
 */

/*
 * Copyright (c) 2017 Simon Goldschmidt.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Simon Goldschmidt <goldsimon@gmx.de>
 *
 */
#pragma once

#include "bridgeif_opts.h"
#include "lwip_error.h"
#include "ethernet.h"

#ifdef __cplusplus
extern "C" {
#endif

struct NetIfc;
typedef uint64_t bridgeif_portmask_t;

constexpr auto kBrFlood = bridgeif_portmask_t(-1);

/** @ingroup bridgeif
 * Initialisation data for @ref bridgeif_init.
 * An instance of this type must be passed as parameter 'state' to @ref netif_add
 * when the bridge is added.
 */
struct bridgeif_initdata_t {
  /** MAC address of the bridge (cannot use the netif's addresses) */
  struct EthAddr ethaddr;
  /** Maximum number of ports in the bridge (ports are stored in an array, this
      influences memory allocated for netif->state of the bridge netif). */
  uint8_t            max_ports;
  /** Maximum number of dynamic/learning entries in the bridge's forwarding database.
      In the default implementation, this controls memory consumption only. */
  uint16_t           max_fdb_dynamic_entries;
  /** Maximum number of static forwarding entries. Influences memory consumption! */
  uint16_t           max_fdb_static_entries;
} ;

/** @ingroup bridgeif
 * Use this for constant initialization of a bridgeif_initdat_t
 * (ethaddr must be passed as MakeEthAddrFromBytes())
 */
#define BRIDGEIF_INITDATA1(max_ports, max_fdb_dynamic_entries, max_fdb_static_entries, ethaddr) {ethaddr, max_ports, max_fdb_dynamic_entries, max_fdb_static_entries}
/** @ingroup bridgeif
 * Use this for constant initialization of a bridgeif_initdat_t
 * (each byte of ethaddr must be passed)
 */
#define BRIDGEIF_INITDATA2(max_ports, max_fdb_dynamic_entries, max_fdb_static_entries, e0, e1, e2, e3, e4, e5) {{e0, e1, e2, e3, e4, e5}, max_ports, max_fdb_dynamic_entries, max_fdb_static_entries}

LwipError bridgeif_init(struct NetIfc *netif);
LwipError bridgeif_add_port(struct NetIfc *bridgeif, struct NetIfc *portif);
LwipError bridgeif_fdb_add(struct NetIfc *bridgeif, const struct EthAddr *addr, bridgeif_portmask_t ports);
LwipError bridgeif_fdb_remove(struct NetIfc *bridgeif, const struct EthAddr *addr);

/* FDB interface, can be replaced by own implementation */
void                bridgeif_fdb_update_src(void *fdb_ptr, struct EthAddr *src_addr, uint8_t port_idx);
bridgeif_portmask_t bridgeif_fdb_get_dst_ports(void *fdb_ptr, struct EthAddr *dst_addr);
void*               bridgeif_fdb_init(uint16_t max_fdb_entries);

#define BRIDGEIF_DECL_PROTECT(lev)    sys_prot_t lev
#define BRIDGEIF_READ_PROTECT(lev)    SYS_ARCH_PROTECT(lev)
#define BRIDGEIF_READ_UNPROTECT(lev)  SYS_ARCH_UNPROTECT(lev)
#define BRIDGEIF_WRITE_PROTECT(lev)
#define BRIDGEIF_WRITE_UNPROTECT(lev)


#ifdef __cplusplus
}
#endif

