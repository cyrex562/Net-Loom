/**
 * @file
 * IP checksum calculation functions
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
#ifndef LWIP_HDR_INET_CHKSUM_H
#define LWIP_HDR_INET_CHKSUM_H

#include "opt.h"

#include "packet_buffer.h"
#include "ip_addr.h"

/** Swap the bytes in an uint16_t: much like lwip_htons() for little-endian */
#ifndef SWAP_BYTES_IN_WORD
#define SWAP_BYTES_IN_WORD(w) (((w) & 0xff) << 8) | (((w) & 0xff00) >> 8)
#endif /* SWAP_BYTES_IN_WORD */

/** Split an uint32_t in two u16_ts and add them up */
#ifndef FOLD_U32T
#define FOLD_U32T(u)          ((uint32_t)(((u) >> 16) + ((u) & 0x0000ffffUL)))
#endif

#if LWIP_CHECKSUM_ON_COPY
/** Function-like macro: same as MEMCPY but returns the checksum of copied data
    as uint16_t */
# ifndef LWIP_CHKSUM_COPY
#  define LWIP_CHKSUM_COPY(dst, src, len) lwip_chksum_copy(dst, src, len)
#  ifndef LWIP_CHKSUM_COPY_ALGORITHM
#   define LWIP_CHKSUM_COPY_ALGORITHM 1
#  endif /* LWIP_CHKSUM_COPY_ALGORITHM */
# else /* LWIP_CHKSUM_COPY */
#  define LWIP_CHKSUM_COPY_ALGORITHM 0
# endif /* LWIP_CHKSUM_COPY */
#else /* LWIP_CHECKSUM_ON_COPY */
# define LWIP_CHKSUM_COPY_ALGORITHM 0
#endif /* LWIP_CHECKSUM_ON_COPY */

#ifdef __cplusplus
extern "C" {
#endif

uint16_t inet_chksum(const void *dataptr, uint16_t len);
uint16_t inet_chksum_pbuf(struct PacketBuffer *p);
#if LWIP_CHKSUM_COPY_ALGORITHM
uint16_t lwip_chksum_copy(void *dst, const void *src, uint16_t len);
#endif /* LWIP_CHKSUM_COPY_ALGORITHM */

#if LWIP_IPV4
uint16_t inet_chksum_pseudo(struct PacketBuffer *p, uint8_t proto, uint16_t proto_len,
       const Ip4Addr *src, const Ip4Addr *dest);
uint16_t inet_chksum_pseudo_partial(struct PacketBuffer *p, uint8_t proto,
       uint16_t proto_len, uint16_t chksum_len, const Ip4Addr *src, const Ip4Addr *dest);
#endif /* LWIP_IPV4 */

#if LWIP_IPV6
uint16_t ip6_chksum_pseudo(struct PacketBuffer *p, uint8_t proto, uint16_t proto_len,
       const LwipIp6Addr *src, const LwipIp6Addr *dest);
uint16_t ip6_chksum_pseudo_partial(struct PacketBuffer *p, uint8_t proto, uint16_t proto_len,
       uint16_t chksum_len, const LwipIp6Addr *src, const LwipIp6Addr *dest);
#endif /* LWIP_IPV6 */


uint16_t ip_chksum_pseudo(struct PacketBuffer *p, uint8_t proto, uint16_t proto_len,
       const IpAddr *src, const IpAddr *dest);
uint16_t ip_chksum_pseudo_partial(struct PacketBuffer *p, uint8_t proto, uint16_t proto_len,
       uint16_t chksum_len, const IpAddr *src, const IpAddr *dest);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_HDR_INET_H */

