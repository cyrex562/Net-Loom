/*
 * upap.h - User/Password Authentication Protocol definitions.
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
 * $Id: upap.h,v 1.8 2002/12/04 23:03:33 paulus Exp $
 */

#pragma once
#include "ppp.h"
#include "upap_state.h"

/*
 * Packet header = Code, id, length.
 */
constexpr auto UPAP_HEADERLEN = 4;


/*
 * UPAP codes.
 */
enum UpapCodes
{
    UPAP_AUTHREQ =1,
    /* Authenticate-Request */
    UPAP_AUTHACK =2,
    /* Authenticate-Ack */
    UPAP_AUTHNAK =3,
    /* Authenticate-Nak */
};



/*
 * Client states.
 */
enum UpapClientStates
{
    UPAPCS_INITIAL =0,
    /* Connection down */
    UPAPCS_CLOSED =1,
    /* Connection up, haven't requested auth */
    UPAPCS_PENDING =2,
    /* Connection down, have requested auth */
    UPAPCS_AUTHREQ =3,
    /* We've sent an Authenticate-Request */
    UPAPCS_OPEN =4,
    /* We've received an Ack */
    UPAPCS_BADAUTH =5,
    /* We've received a Nak */
};


/*
 * Server states.
 */
enum UpapServerStates
{
    UPAPSS_INITIAL =0,
    /* Connection down */
    UPAPSS_CLOSED =1,
    /* Connection up, haven't requested auth */
    UPAPSS_PENDING =2,
    /* Connection down, have requested auth */
    UPAPSS_LISTEN =3,
    /* Listening for an Authenticate */
    UPAPSS_OPEN =4,
    /* We've sent an Ack */
    UPAPSS_BADAUTH =5,
    /* We've sent a Nak */
};



/*
 * Timeouts.
 */




bool
upap_authwithpeer(PppPcb& pcb,
                  std::string& user,
                  std::string& password,
                  upap_state& upap);

bool
upap_authpeer(PppPcb& pcb, upap_state& upap);

bool
upap_sresp(PppPcb& pcb, uint8_t code, uint8_t id, std::string& msg);

std::tuple<bool, upap_state>
upap_init(PppPcb& pcb);

bool
upap_lowerup(PppPcb& pcb, upap_state& upap);

bool
upap_lowerdown(PppPcb& pcb, upap_state& upap);

bool
upap_input(PppPcb& pcb, std::vector<uint8_t>& in_packet, upap_state& upap);

bool
upap_proto_rejected(PppPcb& pcb, upap_state& upap);

bool
upap_timeout(upap_state& upap, PppPcb& pcb);

bool
upap_reqtimeout(PppPcb& pcb, upap_state& upap);

bool
upap_recv_auth_req(PppPcb& pcb, std::vector<uint8_t>& in_pkt, int id, upap_state& upap);

bool
upap_rcv_auth_ack(PppPcb& pcb, std::vector<uint8_t>& in_pkt, int id, upap_state& upap);

bool
upap_rauthnak(PppPcb& pcb, std::vector<uint8_t>& in_pkt, int id, upap_state& upap);

bool
upap_sauthreq(PppPcb& pcb, upap_state& upap);


//
//
//