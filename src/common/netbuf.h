/**
 * @file
 * netbuf API (for NetconnDesc API)
 */

/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
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
 * Author: Adam Dunkels <adam@sics.se>
 *
 */
#pragma once

#include "netloom_config.h"

/* Note: Netconn API is always available when sockets are enabled -
 * sockets are implemented on top of them */

#include "packet.h"
#include "ip_addr.h"
#include "ip6_addr.h"


/** This netbuf has dest-addr/port set */
#define NETBUF_FLAG_DESTADDR    0x01
/** This netbuf includes a checksum */
#define NETBUF_FLAG_CHKSUM      0x02

/** "Network buffer" - contains data and addressing info */
struct netbuf {
  struct PacketContainer *p, *ptr;
  IpAddrInfo addr;
  uint16_t port;  uint8_t flags;
  uint16_t toport_chksum;
  IpAddrInfo toaddr;

};

/* Network buffer functions: */
struct netbuf *   netbuf_new      (void);
void              netbuf_delete   (struct netbuf *buf);
uint8_t *            netbuf_alloc    (struct netbuf *buf, uint16_t size);
void              netbuf_free     (struct netbuf *buf);
NsStatus             netbuf_ref      (struct netbuf *buf,
                                   const uint8_t *dataptr, uint16_t size);
void              netbuf_chain    (struct netbuf *head, struct netbuf *tail);

NsStatus             netbuf_data     (struct netbuf *buf,
                                   uint8_t **dataptr, uint16_t *len);
int8_t              netbuf_next     (struct netbuf *buf);
void              netbuf_first    (struct netbuf *buf);


#define netbuf_copy_partial(buf, dataptr, len, offset) \
  pbuf_copy_partial((buf)->p, (dataptr), (len), (offset))
#define netbuf_copy(buf,dataptr,len) netbuf_copy_partial(buf, dataptr, len, 0)
#define netbuf_take(buf, dataptr, len) pbuf_take((buf)->p, dataptr, len)
#define netbuf_len(buf)              ((buf)->p->tot_len)
#define netbuf_fromaddr(buf)         (&((buf)->addr))
#define netbuf_set_fromaddr(buf, fromaddr) ip_addr_set(&((buf)->addr), fromaddr)
#define netbuf_fromport(buf)         ((buf)->port)
#define netbuf_destaddr(buf)         (&((buf)->toaddr))
#define netbuf_set_destaddr(buf, destaddr) ip_addr_set(&((buf)->toaddr), destaddr)
#define netbuf_destport(buf)         (((buf)->flags & NETBUF_FLAG_DESTADDR) ? (buf)->toport_chksum : 0)

#define netbuf_set_chksum(buf, chksum) do { (buf)->flags = NETBUF_FLAG_CHKSUM; \
                                            (buf)->toport_chksum = chksum; } while(0)

