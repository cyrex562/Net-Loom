/*
 * eap.h - Extensible Authentication Protocol for PPP (RFC 2284)
 *
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Non-exclusive rights to redistribute, modify, translate, and use
 * this software in source and binary forms, in whole or in part, is
 * hereby granted, provided that the above copyright notice is
 * duplicated in any source form, and that neither the name of the
 * copyright holder nor the author is used to endorse or promote
 * products derived from this software.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Original version by James Carlson
 *
 * $Id: eap.h,v 1.2 2003/06/11 23:56:26 paulus Exp $
 */

#pragma once
#include "eap_state.h"
#include <cstdint>
#include <complex>
#include "ppp.h"
constexpr auto SHA_DIGESTSIZE = 20;
/*
 * Packet header = Code, id, length.
 */
constexpr auto EAP_HEADERLEN = 4;


static const uint8_t wkmodulus[] = {
0xAC, 0x6B, 0xDB, 0x41, 0x32, 0x4A, 0x9A, 0x9B, 0xF1, 0x66, 0xDE, 0x5E,
0x13, 0x89, 0x58, 0x2F, 0xAF, 0x72, 0xB6, 0x65, 0x19, 0x87, 0xEE, 0x07,
0xFC, 0x31, 0x92, 0x94, 0x3D, 0xB5, 0x60, 0x50, 0xA3, 0x73, 0x29, 0xCB,
0xB4, 0xA0, 0x99, 0xED, 0x81, 0x93, 0xE0, 0x75, 0x77, 0x67, 0xA1, 0x3D,
0xD5, 0x23, 0x12, 0xAB, 0x4B, 0x03, 0x31, 0x0D, 0xCD, 0x7F, 0x48, 0xA9,
0xDA, 0x04, 0xFD, 0x50, 0xE8, 0x08, 0x39, 0x69, 0xED, 0xB7, 0x67, 0xB0,
0xCF, 0x60, 0x95, 0x17, 0x9A, 0x16, 0x3A, 0xB3, 0x66, 0x1A, 0x05, 0xFB,
0xD5, 0xFA, 0xAA, 0xE8, 0x29, 0x18, 0xA9, 0x96, 0x2F, 0x0B, 0x93, 0xB8,
0x55, 0xF9, 0x79, 0x93, 0xEC, 0x97, 0x5E, 0xEA, 0xA8, 0x0D, 0x74, 0x0A,
0xDB, 0xF4, 0xFF, 0x74, 0x73, 0x59, 0xD0, 0x41, 0xD5, 0xC3, 0x3E, 0xA7,
0x1D, 0x28, 0x1E, 0x44, 0x6B, 0x14, 0x77, 0x3B, 0xCA, 0x97, 0xB4, 0x3A,
0x23, 0xFB, 0x80, 0x16, 0x76, 0xBD, 0x20, 0x7A, 0x43, 0x6C, 0x64, 0x81,
0xF1, 0xD2, 0xB9, 0x07, 0x87, 0x17, 0x46, 0x1A, 0x5B, 0x9D, 0x32, 0xE6,
0x88, 0xF8, 0x77, 0x48, 0x54, 0x45, 0x23, 0xB5, 0x24, 0xB0, 0xD5, 0x7D,
0x5E, 0xA7, 0x7A, 0x27, 0x75, 0xD2, 0xEC, 0xFA, 0x03, 0x2C, 0xFB, 0xDB,
0xF5, 0x2F, 0xB3, 0x78, 0x61, 0x60, 0x27, 0x90, 0x04, 0xE5, 0x7A, 0xE6,
0xAF, 0x87, 0x4E, 0x73, 0x03, 0xCE, 0x53, 0x29, 0x9C, 0xCC, 0x04, 0x1C,
0x7B, 0xC3, 0x08, 0xD8, 0x2A, 0x56, 0x98, 0xF3, 0xA8, 0xD0, 0xC3, 0x82,
0x71, 0xAE, 0x35, 0xF8, 0xE9, 0xDB, 0xFB, 0xB6, 0x94, 0xB5, 0xC8, 0x03,
0xD8, 0x9F, 0x7A, 0xE4, 0x35, 0xDE, 0x23, 0x6D, 0x52, 0x5F, 0x54, 0x75,
0x9B, 0x65, 0xE3, 0x72, 0xFC, 0xD6, 0x8E, 0xF2, 0x0F, 0xA7, 0x11, 0x1F,
0x9E, 0x4A, 0xFF, 0x73};

/* EAP message codes. */
enum EapMsgCode
{
    EAP_REQUEST =1,
    EAP_RESPONSE= 2,
    EAP_SUCCESS =3,
    EAP_FAILURE =4,
};


/* EAP types */
enum EapType
{
    EAPT_IDENTITY = 1,
    EAPT_NOTIFICATION= 2,
    EAPT_NAK = 3,
    /* (response only) */
    EAPT_MD5CHAP = 4,
    EAPT_OTP = 5,
    /* One-Time Password; RFC 1938 */
    EAPT_TOKEN = 6,
    /* Generic Token Card */
    /* 7 and 8 are unassigned. */
    EAPT_RSA = 9,
    /* RSA Public Key Authentication */
    EAPT_DSS = 10,
    /* DSS Unilateral */
    EAPT_KEA =11,
    /* KEA */
    EAPT_KEA_VALIDATE =12,
    /* KEA-VALIDATE	*/
    EAPT_TLS =13,
    /* EAP-TLS */
    EAPT_DEFENDER = 14,
    /* Defender Token (AXENT) */
    EAPT_W2K = 15,
    /* Windows 2000 EAP */
    EAPT_ARCOT = 16,
    /* Arcot Systems */
    EAPT_CISCOWIRELESS =17,
    /* Cisco Wireless */
    EAPT_NOKIACARD = 18,
    /* Nokia IP smart card */
    EAPT_SRP =19,
    /* Secure Remote Password */
    /* 20 is deprecated */
};


/* EAP SRP-SHA1 Subtypes */
#define	EAPSRP_CHALLENGE	1	/* Request 1 - Challenge */
#define	EAPSRP_CKEY		1	/* Response 1 - Client Key */
#define	EAPSRP_SKEY		2	/* Request 2 - Server Key */
#define	EAPSRP_CVALIDATOR	2	/* Response 2 - Client Validator */
#define	EAPSRP_SVALIDATOR	3	/* Request 3 - Server Validator */
#define	EAPSRP_ACK		3	/* Response 3 - final ack */
#define	EAPSRP_LWRECHALLENGE	4	/* Req/resp 4 - Lightweight rechal */

constexpr auto SRPVAL_EBIT = 0x00000001	/* Use shared key for ECP */;

constexpr auto SRP_PSEUDO_ID = "pseudo_";
constexpr auto SRP_PSEUDO_LEN = 7;

constexpr auto MD5_SIGNATURE_SIZE = 16;
constexpr auto EAP_MIN_CHALLENGE_LENGTH = 17;
// constexpr auto EAP_MAX_CHALLENGE_LENGTH = 24;
constexpr auto EAP_MIN_MAX_POWER_OF_TWO_CHALLENGE_LENGTH = 3   /* 2^3-1 = 7, 17+7 = 24 */;

// #define	EAP_STATES	\
//    "Initial", "Pending", "Closed", "Listen", "Identify", \
//    "SRP1", "SRP2", "SRP3", "MD5Chall", "Open", "SRP4", "BadAuth"
inline bool
eap_server_active(const EapState* eap)
{
    return eap->es_server.ea_state >= EAP_IDENTIFY && eap->es_server.ea_state <=
        EAP_MD5_CHALL;
}


struct Base64State
{
    uint32_t bs_bits;
    int bs_offs;
};

static char base64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

bool
eap_authwithpeer(PppPcb& pcb);

void eap_authpeer(PppPcb& pcb, std::string& localname);

// extern const struct Protent eap_protent;

//
// END OF FILE
//