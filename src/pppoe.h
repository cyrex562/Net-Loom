/*****************************************************************************
* pppoe.h - PPP Over Ethernet implementation for lwIP.
*
* Copyright (c) 2006 by Marc Boucher, Services Informatiques (MBSI) inc.
*
* The authors hereby grant permission to use, copy, modify, distribute,
* and license this software and its documentation for any purpose, provided
* that existing copyright notices are retained in all copies and that this
* notice and the following disclaimer are included verbatim in any 
* distributions. No written agreement, license, or royalty fee is required
* for any of the authorized uses.
*
* THIS SOFTWARE IS PROVIDED BY THE CONTRIBUTORS *AS IS* AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
* IN NO EVENT SHALL THE CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
* THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
******************************************************************************
* REVISION HISTORY
*
* 06-01-01 Marc Boucher <marc@mbsi.ca>
*   Ported to lwIP.
*****************************************************************************/



/* based on NetBSD: if_pppoe.c,v 1.64 2006/01/31 23:50:15 martin Exp */

/*-
 * Copyright (c) 2002 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Martin Husemann <martin@NetBSD.org>.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#pragma once

#include "ppp_opts.h"

#include "ppp.h"
#include "etharp.h"

#ifdef __cplusplus
extern "C" {
#endif

struct pppoehdr {
  (uint8_t vertype);
  (uint8_t code);
  (uint16_t session);
  (uint16_t plen);
} ;

struct pppoetag {
  (uint16_t tag);
  (uint16_t len);
} ;

constexpr auto PPPOE_STATE_INITIAL = 0;
constexpr auto PPPOE_STATE_PADI_SENT = 1;
constexpr auto PPPOE_STATE_PADR_SENT = 2;
constexpr auto PPPOE_STATE_SESSION = 3;
constexpr auto PPPOE_STATE_PADO_SENT = 1;
#define PPPOE_HEADERLEN       sizeof(struct pppoehdr)
constexpr auto PPPOE_VERTYPE = 0x11    /* VER=1, TYPE = 1 */;
constexpr auto PPPOE_TAG_EOL = 0x0000  /* end of list */;
constexpr auto PPPOE_TAG_SNAME = 0x0101  /* service name */;
constexpr auto PPPOE_TAG_ACNAME = 0x0102  /* access concentrator name */;
constexpr auto PPPOE_TAG_HUNIQUE = 0x0103  /* host unique */;
constexpr auto PPPOE_TAG_ACCOOKIE = 0x0104  /* AC cookie */;
constexpr auto PPPOE_TAG_VENDOR = 0x0105  /* vendor specific */;
constexpr auto PPPOE_TAG_RELAYSID = 0x0110  /* relay session id */;
constexpr auto PPPOE_TAG_SNAME_ERR = 0x0201  /* service name error */;
constexpr auto PPPOE_TAG_ACSYS_ERR = 0x0202  /* AC system error */;
constexpr auto PPPOE_TAG_GENERIC_ERR = 0x0203  /* gerneric error */;
constexpr auto PPPOE_CODE_PADI = 0x09    /* Active Discovery Initiation */;
constexpr auto PPPOE_CODE_PADO = 0x07    /* Active Discovery Offer */;
constexpr auto PPPOE_CODE_PADR = 0x19    /* Active Discovery Request */;
constexpr auto PPPOE_CODE_PADS = 0x65    /* Active Discovery Session confirmation */;
constexpr auto PPPOE_CODE_PADT = 0xA7    /* Active Discovery Terminate */;
constexpr auto PPPOE_MAX_AC_COOKIE_LEN = 64;


struct pppoe_softc {
  struct pppoe_softc *next;
  NetIfc*sc_ethif;      /* ethernet interface we are using */
  PppPcb *pcb;                /* PPP PCB */
  struct EthAddr sc_dest;     /* hardware address of concentrator */
  uint16_t sc_session;            /* PPPoE session id */
  uint8_t sc_state;               /* discovery phase or session connected */

#ifdef PPPOE_TODO
  uint8_t *sc_service_name;       /* if != NULL: requested name of service */
  uint8_t *sc_concentrator_name;  /* if != NULL: requested concentrator id */
#endif /* PPPOE_TODO */
  uint8_t sc_ac_cookie[PPPOE_MAX_AC_COOKIE_LEN]; /* content of AC cookie we must echo back */
  uint8_t sc_ac_cookie_len;       /* length of cookie data */
#ifdef PPPOE_SERVER
  uint8_t *sc_hunique;            /* content of host unique we must echo back */
  uint8_t sc_hunique_len;         /* length of host unique */
#endif
  uint8_t sc_padi_retried;        /* number of PADI retries already done */
  uint8_t sc_padr_retried;        /* number of PADR retries already done */
};


#define pppoe_init() /* compatibility define, no initialization needed */

PppPcb *pppoe_create(NetIfc*pppif,
       NetIfc*ethif,
       const char *service_name, const char *concentrator_name,
       ppp_link_status_cb_fn link_status_cb, void *ctx_cb);

/*
 * Functions called from lwIP
 * DO NOT CALL FROM lwIP USER APPLICATION.
 */
void pppoe_disc_input(NetIfc*netif, struct PacketBuffer *p);
void pppoe_data_input(NetIfc*netif, struct PacketBuffer *p);

#ifdef __cplusplus
}
#endif