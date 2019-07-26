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
#pragma once
#include <ip_addr.h>
#include <packet_buffer.h>


/** Swap the bytes in an uint16_t: much like lwip_htons() for little-endian */
#define SWAP_BYTES_IN_WORD(w) (((w) & 0xff) << 8) | (((w) & 0xff00) >> 8)


/** Split an uint32_t in two u16_ts and add them up */
inline uint32_t fold_u32(uint32_t& u)
{
    return uint32_t(((u) >> 16) + ((u) & 0x0000ffffUL));
}


/** Function-like macro: same as memcpy but returns the checksum of copied data
    as uint16_t */

#  define lwip_standard_checksum_COPY(dst, src, len) lwip_standard_checksum_copy(dst, src, len)

#   define lwip_standard_checksum_COPY_ALGORITHM 1





uint16_t inet_chksum(const uint8_t *dataptr, uint16_t len);
uint16_t inet_chksum_pbuf(struct PacketBuffer *p);

uint16_t lwip_standard_checksum_copy(uint8_t *dst, const uint8_t *src, uint16_t len);

uint16_t inet_chksum_pseudo(struct PacketBuffer *p, uint8_t proto, uint16_t proto_len,
       const Ip4Addr *src, const Ip4Addr *dest);
uint16_t inet_chksum_pseudo_partial(struct PacketBuffer *p, uint8_t proto,
       uint16_t proto_len, uint16_t chksum_len, const Ip4Addr *src, const Ip4Addr *dest);

uint16_t ip6_chksum_pseudo(struct PacketBuffer *p,
                           uint8_t proto,
                           size_t proto_len,
                           const Ip6Addr *src,
                           const Ip6Addr *dest);
uint16_t ip6_chksum_pseudo_partial(struct PacketBuffer *p, uint8_t proto, uint16_t proto_len,
       uint16_t chksum_len, const Ip6Addr *src, const Ip6Addr *dest);



uint16_t ip_chksum_pseudo(struct PacketBuffer *p, uint8_t proto, uint16_t proto_len,
       const IpAddr *src, const IpAddr *dest);
uint16_t ip_chksum_pseudo_partial(struct PacketBuffer *p, uint8_t proto, uint16_t proto_len,
       uint16_t chksum_len, const IpAddr *src, const IpAddr *dest);


uint16_t
ip6_chksum_pseudo(struct PacketBuffer *p,
                  uint8_t proto,
                  size_t proto_len,
                  const Ip6Addr *src,
                  const Ip6Addr *dest);

uint16_t
lwip_standard_chksum_1(const uint8_t *dataptr, int len);

uint16_t
lwip_standard_chksum_2(const uint8_t *dataptr, const size_t len);

uint16_t
lwip_standard_chksum_3(const uint8_t *dataptr, const size_t len);

constexpr auto kLwipStandardChecksumAlgorithm = 2;

uint16_t lwip_standard_checksum(const uint8_t* dataptr,
                                const size_t len,
                                const int checksum_algorithm = kLwipStandardChecksumAlgorithm);

//
// END OF FILE
//