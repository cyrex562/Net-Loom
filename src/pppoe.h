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

#include <cstdint>


constexpr auto PPPOE_VERTYPE = 0x11    /* VER=1, TYPE = 1 */;

constexpr auto PPPOE_DISC_TIMEOUT = (5*1000)  /* base for quick timeout calculation */;
constexpr auto PPPOE_SLOW_RETRY = (60*1000) /* persistent retry interval */;
constexpr auto PPPOE_DISC_MAXPADI = 4        /* retry PADI four times (quickly) */;
constexpr auto PPPOE_DISC_MAXPADR = 2        /* retry PADR twice */;

constexpr auto PPPOE_MAX_AC_COOKIE_LEN = 64;

/* from if_spppsubr.c */
// #define IFF_PASSIVE IFF_LINK0 /* wait passively for connection */

constexpr auto PPPOE_ERRORSTRING_LEN = 64;

enum PppoeCode : uint8_t
{
    PPPOE_CODE_PADI = 0x09,
    /* Active Discovery Initiation */
    PPPOE_CODE_PADO = 0x07,
    /* Active Discovery Offer */
    PPPOE_CODE_PADR = 0x19,
    /* Active Discovery Request */
    PPPOE_CODE_PADS = 0x65,
    /* Active Discovery Session confirmation */
    PPPOE_CODE_PADT = 0xA7 /* Active Discovery Terminate */
};

struct PppoeHdr
{
    uint8_t vertype;
    PppoeCode code;
    uint16_t session;
    uint16_t plen;
};


enum PppoeTagValue : uint16_t
{
    PPPOE_TAG_EOL = 0x0000,
    /* end of list */
    PPPOE_TAG_SNAME = 0x0101,
    /* service name */
    PPPOE_TAG_ACNAME = 0x0102,
    /* access concentrator name */
    PPPOE_TAG_HUNIQUE = 0x0103,
    /* host unique */
    PPPOE_TAG_ACCOOKIE = 0x0104,
    /* AC cookie */
    PPPOE_TAG_VENDOR = 0x0105,
    /* vendor specific */
    PPPOE_TAG_RELAYSID = 0x0110,
    /* relay session id */
    PPPOE_TAG_SNAME_ERR = 0x0201,
    /* service name error */
    PPPOE_TAG_ACSYS_ERR = 0x0202,
    /* AC system error */
    PPPOE_TAG_GENERIC_ERR = 0x0203,
    /* gerneric error */
};


struct PppoeTag
{
    PppoeTagValue tag;
    uint16_t len;
};


enum PppoeState
{
    PPPOE_STATE_INITIAL = 0,
    PPPOE_STATE_PADI_SENT = 1,
    PPPOE_STATE_PADR_SENT = 2,
    PPPOE_STATE_SESSION = 3,
    PPPOE_STATE_PADO_SENT = 1,
};




struct PppoeSoftc
{
    // struct pppoe_softc* next;
    NetworkInterface sc_ethif; /* ethernet interface we are using */
    PppPcb pcb; /* PPP PCB */
    struct MacAddress sc_dest; /* hardware address of concentrator */
    uint16_t sc_session; /* PPPoE session id */
    uint8_t sc_state; /* discovery phase or session connected */
    std::vector<uint8_t> sc_ac_cookie;
    /* content of AC cookie we must echo back */
    std::vector<uint8_t> sc_hunique; /* content of host unique we must echo back */
    uint32_t sc_padi_retried; /* number of PADI retries already done */
    uint32_t sc_padr_retried; /* number of PADR retries already done */
    std::string sc_service_name;
};


/* Add a 16 bit unsigned value to a buffer pointed to by PTR */
inline void
PPPOE_ADD_16(uint8_t* ptr, uint16_t val)
{
    *(ptr)++ = (uint8_t)((val) / 256);
    *(ptr)++ = (uint8_t)((val) % 256);
}

/* Add a complete PPPoE header to the buffer pointed to by PTR */
inline void
PPPOE_ADD_HEADER(uint8_t* ptr, uint16_t code, uint16_t session_id, uint16_t length)
{
    *(ptr)++ = PPPOE_VERTYPE;
    *(ptr)++ = (code);
    PPPOE_ADD_16(ptr, session_id);
    PPPOE_ADD_16(ptr, length);
}


#define pppoe_init() /* compatibility define, no initialization needed */

std::tuple<bool, PppPcb>
pppoe_create(NetworkInterface& ppp_netif,
             NetworkInterface& eth_netif,
             std::string& service_name,
             std::string& concentrator_name,
             std::vector<NetworkInterface>& interfaces,
             std::vector<PppoeSoftc>& pppoe_softc_list);

bool
pppoe_disc_input(NetworkInterface& netif,
                 PacketBuffer& pkt_buf,
                 std::vector<PppoeSoftc>& pppoe_softc_list);

void
pppoe_data_input(NetworkInterface* netif, struct PacketBuffer* p);

//
// END OF FILE
//