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

/*
 * Each interface is described by upap structure.
 */
struct upap_state
{
    std::string us_user; /* User */
    std::string us_passwd; /* Password */
    uint8_t us_clientstate; /* Client state */
    uint8_t us_serverstate; /* Server state */
    uint8_t us_id; /* Current id */
    uint8_t us_transmits; /* Number of auth-reqs sent */
};



void upap_authwithpeer(PppPcb *pcb, std::string& user, std::string& password);

void upap_authpeer(PppPcb*pcb);


extern const struct Protent pap_protent;

