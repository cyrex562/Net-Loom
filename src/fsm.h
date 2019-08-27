/*
 * fsm.h - {Link, IP} Control Protocol Finite State Machine definitions.
 *
 * Copyright (c) 1984-2000 Carnegie Mellon University. All rights reserved.
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
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * $Id: fsm.h,v 1.10 2004/11/13 02:28:15 paulus Exp $
 */
#pragma once
#include "fsm_def.h"
#include <cstdint>
#include <vector>
#include "auth.h"

/*
 * Packet header = Code, id, length.
 */
constexpr auto FSM_PKT_HDR_LEN = 4;


/*
 *  CP (LCP, IPCP, etc.) codes.
 */
enum CpCodes
{
    CONFREQ =1,
    /* Configuration Request */
    CONFACK = 2,
    /* Configuration Ack */
    CONFNAK = 3,
    /* Configuration Nak */
    CONFREJ = 4,
    /* Configuration Reject */
    TERMREQ = 5,
    /* Termination Request */
    TERMACK = 6,
    /* Termination Ack */
    CODEREJ = 7,
    /* Code Reject */
};

/*
 * Prototypes
 */
bool
fsm_init(Fsm& fsm, PppPcb& pcb);


bool
fsm_lowerup(PppPcb& pcb, Fsm& f);


bool
fsm_lowerdown(Fsm& f);


bool
fsm_open(PppPcb& pcb, Fsm& f);


bool
fsm_close(PppPcb& pcb, Fsm& fsm, std::string& reason);


bool
fsm_input(PppPcb& pcb, ::Fsm& fsm, std::vector<uint8_t>& packet);


bool
fsm_proto_rej(PppPcb& pcb, Fsm& f);


bool
fsm_send_data2(PppPcb& pcb,
               Fsm& fsm,
               uint8_t code,
               uint8_t id,
               std::vector<uint8_t>& data);


bool
fsm_recv_term_req(PppPcb& pcb, Fsm& f, int id, std::vector<uint8_t>& packet);


bool
fsm_timeout(PppPcb& pcb, Fsm& fsm);


bool
fsm_recv_conf_req(PppPcb& pcb, Fsm& f, uint8_t id, std::vector<uint8_t>& packet);


bool
fsm_recv_conf_ack(PppPcb& pcb, Fsm& f, int id, std::vector<uint8_t> packet);


bool
fsm_recv_conf_nak_rej(PppPcb& pcb,
                      Fsm& f,
                      int code,
                      int id,
                      std::vector<uint8_t>& packet);


bool
fsm_recv_term_ack(PppPcb& pcb, Fsm& f);


bool
fsm_recv_code_rej(PppPcb& pcb, Fsm& f, std::vector<uint8_t> packet);


bool
fsm_senc_conf_req(PppPcb& pcb, Fsm& f, bool retransmit);

//
// END OF FILE
//
