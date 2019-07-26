/*
 * ecp.c - PPP Encryption Control Protocol.
 *
 * Copyright (c) 2002 Google, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name(s) of the authors of this software must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Derived from ccp.c, which is:
 *
 * Copyright (c) 1994-2002 Paul Mackerras. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. The name(s) of the authors of this software must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 3. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Paul Mackerras
 *     <paulus@samba.org>".
 *
 * THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define NOMINMAX
#include <ppp_impl.h>
#include <fsm.h>
#include <ecp.h>

/*
 * Protocol entry points from main code.
 */
void ecp_init (PppPcb* unit);
bool ecp_open(PppPcb* ppp_pcb, int unit);
void ecp_close (int unit, char *);
void ecp_lowerup (int unit);
void ecp_lowerdown (int);
void ecp_input (int unit, uint8_t *pkt, int len);
void ecp_protrej (int unit);

constexpr auto NUM_PPP = 0xff;

Fsm ecp_fsm[NUM_PPP];
EcpOptions ecp_wantoptions[NUM_PPP];	/* what to request the peer to use */
EcpOptions ecp_gotoptions[NUM_PPP];	/* what the peer agreed to do */
EcpOptions ecp_allowoptions[NUM_PPP];	/* what we'll agree to do */
EcpOptions ecp_hisoptions[NUM_PPP];	/* what we agreed to do */

// static const FsmCallbacks ecp_callbacks = {
//     nullptr, /* ecp_resetci, */
//  nullptr, /* ecp_cilen, */
//  nullptr, /* ecp_addci, */
//  nullptr, /* ecp_ackci, */
//  nullptr, /* ecp_nakci, */
//  nullptr, /* ecp_rejci, */
//  nullptr, /* ecp_reqci, */
//  nullptr, /* ecp_up, */
//  nullptr, /* ecp_down, */
//  nullptr,
//  nullptr,
//  nullptr,
//  nullptr,
//  nullptr, /* ecp_extcode, */
//     "ECP"
// };

/*
 * ecp_init - initialize ECP.
 */
static void ecp_init(PppPcb* unit)
{
    // auto f = &ecp_fsm[unit];
    // f->unit = unit;
    // f->protocol = PPP_ECP;
    // // f->callbacks = &ecp_callbacks;
    // fsm_init(f);
}

bool ecp_open(PppPcb* ppp_pcb, int unit)
{
    return false;
}

//
// END OF FILE
//