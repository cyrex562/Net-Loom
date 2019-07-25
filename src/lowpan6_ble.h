/**
 * @file
 * 6LowPAN over BLE for IPv6 (RFC7668).
 */

/*
 * Copyright (c) 2017 Benjamin Aigner
 * Copyright (c) 2015 Inico Technologies Ltd. , Author: Ivan Delamer <delamer@inicotech.com>
 * 
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
 * Author: Benjamin Aigner <aignerb@technikum-wien.at>
 * 
 * Based on the original 6lowpan implementation of lwIP ( @see 6lowpan.c)
 */

#pragma once

#include <lowpan6_opts.h>
#include <lowpan6_common.h>
#include <packet_buffer.h>
#include <ip.h>
#include <ip_addr.h>
#include <netif.h>

LwipStatus rfc7668_output(NetworkInterface*netif, struct PacketBuffer *q, const Ip6Addr *ip6addr);
LwipStatus rfc7668_input(struct PacketBuffer * p, NetworkInterface*netif);
LwipStatus rfc7668_set_local_addr_eui64(NetworkInterface*netif, const uint8_t *local_addr, size_t local_addr_len);
LwipStatus rfc7668_set_local_addr_mac48(NetworkInterface*netif, const uint8_t *local_addr, size_t local_addr_len, int is_public_addr);
LwipStatus rfc7668_set_peer_addr_eui64(NetworkInterface*netif, const uint8_t *peer_addr, size_t peer_addr_len);
LwipStatus rfc7668_set_peer_addr_mac48(NetworkInterface*netif, const uint8_t *peer_addr, size_t peer_addr_len, int is_public_addr);
LwipStatus rfc7668_set_context(uint8_t index, const Ip6Addr * context);
LwipStatus rfc7668_if_init(NetworkInterface*netif);
LwipStatus tcpip_rfc7668_input(struct PacketBuffer *p, NetworkInterface*inp);

void ble_addr_to_eui64(uint8_t *dst, const uint8_t *src, int public_addr);
void eui64_to_ble_addr(uint8_t *dst, const uint8_t *src);
