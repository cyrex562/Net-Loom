/**
 * @file
 *
 * Common 6LowPAN routines for IPv6. Uses ND tables for link-layer addressing. Fragments packets to 6LowPAN units.
 */

/*
 * Copyright (c) 2015 Inico Technologies Ltd.
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
 * Author: Ivan Delamer <delamer@inicotech.com>
 *
 *
 * Please coordinate changes and requests with Ivan Delamer
 * <delamer@inicotech.com>
 */

#pragma once

#include <packet_buffer.h>
#include <ip.h>
#include <ip6_addr.h>
#include <network_interface.h>
#include <cstdint>

/** Helper define for a link layer address, which can be encoded as 0, 2 or 8 bytes */
struct Lowpan6LinkAddr {
  /* encoded length of the address */
  uint8_t addr_len;
  /* address bytes */
  uint8_t addr[8];
};

int8_t lowpan6_get_address_mode(const Ip6Addr* ip6addr,
                                const struct Lowpan6LinkAddr* mac_addr);
LwipStatus lowpan6_compress_headers(NetworkInterface* netif,
                               uint8_t* inbuf,
                               size_t inbuf_size,
                               uint8_t* outbuf,
                               size_t outbuf_size,
                               uint8_t* lowpan6_header_len_out,
                               uint8_t* hidden_header_len_out,
                               Ip6Addr* lowpan6_contexts,
                               const struct Lowpan6LinkAddr* src,
                               const struct Lowpan6LinkAddr* dst);
struct PacketBuffer* lowpan6_decompress(struct PacketBuffer* p,
                                uint16_t datagram_size,
                                Ip6Addr* lowpan6_contexts,
                                struct Lowpan6LinkAddr* src,
                                struct Lowpan6LinkAddr* dest);
