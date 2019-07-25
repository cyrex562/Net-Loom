/**
 * @file
 *
 * 6LowPAN output for IPv6. Uses ND tables for link-layer addressing. Fragments packets to 6LowPAN units.
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
#include <lowpan6_opts.h>
#include <lowpan6_common.h>
#include <packet_buffer.h>
#include <ip.h>
#include <ip_addr.h>
#include <netif.h>

#ifdef __cplusplus
extern "C" {
#endif

/** 1 second period for reassembly */
constexpr auto kLowpan6TmrInterval = 1000;

void lowpan6_tmr(void);

LwipStatus lowpan6_set_context(uint8_t idx, const Ip6Addr* context);
LwipStatus lowpan6_set_short_addr(uint8_t addr_high, uint8_t addr_low);
LwipStatus lowpan4_output(NetworkInterface*netif, struct PacketBuffer *q, const Ip4Addr *ipaddr);
LwipStatus lowpan6_output(NetworkInterface*netif, struct PacketBuffer *q, const Ip6Addr*ip6addr);
LwipStatus lowpan6_input(struct PacketBuffer * p, NetworkInterface*netif);
LwipStatus lowpan6_if_init(NetworkInterface*netif);

/* pan_id in network byte order. */
LwipStatus lowpan6_set_pan_id(uint16_t pan_id);
uint16_t lowpan6_calc_crc(const uint8_t *buf, uint16_t len);
LwipStatus tcpip_6lowpan_input(struct PacketBuffer *p, NetworkInterface*inp);


#ifdef __cplusplus
}
#endif
