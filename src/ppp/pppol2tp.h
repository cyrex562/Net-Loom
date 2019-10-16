/**
 * @file
 * Network Point to Point Protocol over Layer 2 Tunneling Protocol header file.
 *
 */

/*
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
 */

#pragma once
#include "ppp.h"

/* Timeout */
constexpr auto PPPOL2TP_CONTROL_TIMEOUT = (5*1000)  /* base for quick timeout calculation */;
constexpr auto PPPOL2TP_SLOW_RETRY = (60*1000) /* persistent retry interval */;

constexpr auto PPPOL2TP_MAXSCCRQ = 4         /* retry SCCRQ four times (quickly) */;
constexpr auto PPPOL2TP_MAXICRQ = 4         /* retry IRCQ four times */;
constexpr auto PPPOL2TP_MAXICCN = 4         /* retry ICCN four times */;

// L2TP header flags
enum L2tpHdrFlags
{
    PPPOL2TP_HEADERFLAG_CONTROL = 0x8000,
    PPPOL2TP_HEADERFLAG_LENGTH =0x4000,
    PPPOL2TP_HEADERFLAG_SEQUENCE =0x0800,
    PPPOL2TP_HEADERFLAG_OFFSET =0x0200,
    PPPOL2TP_HEADERFLAG_PRIORITY =0x0100,
    PPPOL2TP_HEADERFLAG_VERSION =0x0002,
};


/* Mandatory bits for control: Control, Length, Sequence, Version 2 */
#define PPPOL2TP_HEADERFLAG_CONTROL_MANDATORY     (PPPOL2TP_HEADERFLAG_CONTROL|PPPOL2TP_HEADERFLAG_LENGTH|PPPOL2TP_HEADERFLAG_SEQUENCE|PPPOL2TP_HEADERFLAG_VERSION)
/* Forbidden bits for control: Offset, Priority */
#define PPPOL2TP_HEADERFLAG_CONTROL_FORBIDDEN     (PPPOL2TP_HEADERFLAG_OFFSET|PPPOL2TP_HEADERFLAG_PRIORITY)

/* Mandatory bits for data: Version 2 */
#define PPPOL2TP_HEADERFLAG_DATA_MANDATORY        (PPPOL2TP_HEADERFLAG_VERSION)

/* AVP (Attribute Value Pair) header */
enum Pppol2tpAvpHdrFlags
{
    PPPOL2TP_AVPHEADERFLAG_MANDATORY = 0x8000,
    PPPOL2TP_AVPHEADERFLAG_HIDDEN = 0x4000,
    PPPOL2TP_AVPHEADERFLAG_LENGTHMASK = 0x03ff,
};


/* -- AVP - Message type */
constexpr auto PPPOL2TP_AVPTYPE_MESSAGE = 0 /* Message type */;

/* Control Connection Management */
enum Pppol2tpMsgType
{
    PPPOL2TP_MESSAGETYPE_SCCRQ =1,
    /* Start Control Connection Request */
    PPPOL2TP_MESSAGETYPE_SCCRP =2,
    /* Start Control Connection Reply */
    PPPOL2TP_MESSAGETYPE_SCCCN =3,
    /* Start Control Connection Connected */
    PPPOL2TP_MESSAGETYPE_STOPCCN =4,
    /* Stop Control Connection Notification */
    PPPOL2TP_MESSAGETYPE_HELLO =6,
    /* Hello */
    /* Call Management */
    PPPOL2TP_MESSAGETYPE_OCRQ =7,
    /* Outgoing Call Request */
    PPPOL2TP_MESSAGETYPE_OCRP =8,
    /* Outgoing Call Reply */
    PPPOL2TP_MESSAGETYPE_OCCN =9,
    /* Outgoing Call Connected */
    PPPOL2TP_MESSAGETYPE_ICRQ =10,
    /* Incoming Call Request */
    PPPOL2TP_MESSAGETYPE_ICRP =11,
    /* Incoming Call Reply */
    PPPOL2TP_MESSAGETYPE_ICCN =12,
    /* Incoming Call Connected */
    PPPOL2TP_MESSAGETYPE_CDN =14,
    /* Call Disconnect Notify */
    /* Error reporting */
    PPPOL2TP_MESSAGETYPE_WEN =15,
    /* WAN Error Notify */
    /* PPP Session Control */
    PPPOL2TP_MESSAGETYPE_SLI =16,
    /* Set Link Info */
};


/* -- AVP - Result code */
constexpr auto PPPOL2TP_AVPTYPE_RESULTCODE = 1 /* Result code */;
constexpr auto PPPOL2TP_RESULTCODE = 1 /* General request to clear control connection */;

/* -- AVP - Protocol version (!= L2TP Header version) */
constexpr auto PPPOL2TP_AVPTYPE_VERSION = 2;
constexpr auto PPPOL2TP_VERSION = 0x0100 /* L2TP Protocol version 1, revision 0 */;

/* -- AVP - Framing capabilities */
constexpr auto PPPOL2TP_AVPTYPE_FRAMINGCAPABILITIES = 3 /* Bearer capabilities */;
constexpr auto PPPOL2TP_FRAMINGCAPABILITIES = 0x00000003 /* Async + Sync framing */;

/* -- AVP - Bearer capabilities */
constexpr auto PPPOL2TP_AVPTYPE_BEARERCAPABILITIES = 4 /* Bearer capabilities */;
constexpr auto PPPOL2TP_BEARERCAPABILITIES = 0x00000003 /* Analog + Digital Access */;

/* -- AVP - Tie breaker */
constexpr auto PPPOL2TP_AVPTYPE_TIEBREAKER = 5;

/* -- AVP - Host name */
constexpr auto PPPOL2TP_AVPTYPE_HOSTNAME = 7 /* Host name */;
constexpr auto PPPOL2TP_HOSTNAME = "lwIP" /* FIXME: make it configurable */;

/* -- AVP - Vendor name */
constexpr auto PPPOL2TP_AVPTYPE_VENDORNAME = 8 /* Vendor name */;
constexpr auto PPPOL2TP_VENDORNAME = "lwIP" /* FIXME: make it configurable */;

/* -- AVP - Assign tunnel ID */
constexpr auto PPPOL2TP_AVPTYPE_TUNNELID = 9 /* Assign Tunnel ID */;

/* -- AVP - Receive window size */
constexpr auto PPPOL2TP_AVPTYPE_RECEIVEWINDOWSIZE = 10 /* Receive window size */;
constexpr auto PPPOL2TP_RECEIVEWINDOWSIZE = 8 /* FIXME: make it configurable */;

/* -- AVP - Challenge */
constexpr auto PPPOL2TP_AVPTYPE_CHALLENGE = 11 /* Challenge */;

/* -- AVP - Cause code */
constexpr auto PPPOL2TP_AVPTYPE_CAUSECODE = 12 /* Cause code*/;

/* -- AVP - Challenge response */
constexpr auto PPPOL2TP_AVPTYPE_CHALLENGERESPONSE = 13 /* Challenge response */;
constexpr auto PPPOL2TP_AVPTYPE_CHALLENGERESPONSE_SIZE = 16;

/* -- AVP - Assign session ID */
constexpr auto PPPOL2TP_AVPTYPE_SESSIONID = 14 /* Assign Session ID */;

/* -- AVP - Call serial number */
constexpr auto PPPOL2TP_AVPTYPE_CALLSERIALNUMBER = 15 /* Call Serial Number */;

/* -- AVP - Framing type */
constexpr auto PPPOL2TP_AVPTYPE_FRAMINGTYPE = 19 /* Framing Type */;
constexpr auto PPPOL2TP_FRAMINGTYPE = 0x00000001 /* Sync framing */;

/* -- AVP - TX Connect Speed */
constexpr auto PPPOL2TP_AVPTYPE_TXCONNECTSPEED = 24 /* TX Connect Speed */;
constexpr auto PPPOL2TP_TXCONNECTSPEED = 100000000 /* Connect speed: 100 Mbits/s */;

// L2TP Session state
enum Pppol2tpSessionState
{
    PPPOL2TP_STATE_INITIAL =0,
    PPPOL2TP_STATE_SCCRQ_SENT =1,
    PPPOL2TP_STATE_ICRQ_SENT =2,
    PPPOL2TP_STATE_ICCN_SENT =3,
    PPPOL2TP_STATE_DATA =4,
};


constexpr auto PPPOL2TP_OUTPUT_DATA_HEADER_LEN = 6 /* Our data header len */;

/*
 * PPPoL2TP interface control block.
 */
// typedef struct pppol2tp_pcb_s Pppol2tpPcb;
struct Pppol2tpPcb
{
    PppPcb* ppp; /* PPP PCB */
    uint8_t phase; /* L2TP phase */
    struct UdpPcb* udp; /* UDP L2TP Socket */
    NetworkInterface* netif; /* Output interface, used as a default route */
    IpAddrInfo remote_ip; /* LNS IP Address */
    uint16_t remote_port; /* LNS port */
    const uint8_t* secret; /* Secret string */
    size_t secret_len; /* Secret string length */
    uint8_t secret_rv[16]; /* Random vector */
    uint8_t challenge_hash[16]; /* Challenge response */
    uint8_t send_challenge;
    /* Boolean whether the next sent packet should contains a challenge response */
    uint16_t tunnel_port; /* Tunnel port */
    uint16_t our_ns; /* NS to peer */
    uint16_t peer_nr; /* NR from peer */
    uint16_t peer_ns; /* Expected NS from peer */
    uint16_t source_tunnel_id; /* Tunnel ID assigned by peer */
    uint16_t remote_tunnel_id; /* Tunnel ID assigned to peer */
    uint16_t source_session_id; /* Session ID assigned by peer */
    uint16_t remote_session_id; /* Session ID assigned to peer */
    uint8_t sccrq_retried; /* number of SCCRQ retries already done */
    uint8_t icrq_retried; /* number of ICRQ retries already done */
    uint8_t iccn_retried; /* number of ICCN retries already done */
};


/* Create a new L2TP session. */
PppPcb* CreatePppol2tpSession(NetworkInterface* pppif,
                              NetworkInterface* netif,
                              const IpAddrInfo* ipaddr,
                              uint16_t port,
                              const uint8_t* secret,
                              size_t secret_len,
                              ppp_link_status_cb_fn link_status_cb,
                              void* ctx_cb);


static void
pppol2tp_input(void* arg,
               struct UdpPcb* pcb,
               struct PacketContainer* p,
               const IpAddrInfo* addr,
               uint16_t port,
               NetworkInterface* netif);

//
// END OF FILE
//