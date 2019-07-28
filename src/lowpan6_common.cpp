/**
 * @file
 *
 * Common 6LowPAN routines for IPv6. Uses ND tables for link-layer addressing. Fragments packets to 6LowPAN units.
 *
 * This implementation aims to conform to IEEE 802.15.4(-2015), RFC 4944 and RFC 6282.
 * @todo: RFC 6775.
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

/**
 * @defgroup sixlowpan 6LoWPAN (RFC4944)
 * @ingroup netifs
 * 6LowPAN netif implementation
 */

#include <lowpan6_common.h>

#include <ip.h>
#include <packet_buffer.h>
#include <ip_addr.h>
#include <network_interface.h>
#include <udp.h>

#include <string.h>
#include "lowpan6_opts.h"

/* Determine compression mode for unicast address. */
int8_t
lowpan6_get_address_mode(const Ip6Addr *ip6addr, const Lowpan6LinkAddr *mac_addr)
{
  if (mac_addr->addr_len == 2) {
    if ((ip6addr->addr[2] == (uint32_t)pp_htonl(0x000000ff)) &&
        ((ip6addr->addr[3]  & pp_htonl(0xffff0000)) == pp_ntohl(0xfe000000))) {
      if ((ip6addr->addr[3]  & pp_htonl(0x0000ffff)) == lwip_ntohl((mac_addr->addr[0] << 8) | mac_addr->addr[1])) {
        return 3;
      }
    }
  } else if (mac_addr->addr_len == 8) {
    if ((ip6addr->addr[2] == lwip_ntohl(((mac_addr->addr[0] ^ 2) << 24) | (mac_addr->addr[1] << 16) | mac_addr->addr[2] << 8 | mac_addr->addr[3])) &&
        (ip6addr->addr[3] == lwip_ntohl((mac_addr->addr[4] << 24) | (mac_addr->addr[5] << 16) | mac_addr->addr[6] << 8 | mac_addr->addr[7]))) {
      return 3;
    }
  }

  if ((ip6addr->addr[2] == pp_htonl(0x000000ffUL)) &&
      ((ip6addr->addr[3]  & pp_htonl(0xffff0000)) == pp_ntohl(0xfe000000UL))) {
    return 2;
  }

  return 1;
}


/* Determine compression mode for multicast address. */
static int8_t
lowpan6_get_address_mode_mc(const Ip6Addr *ip6addr)
{
  if ((ip6addr->addr[0] == pp_htonl(0xff020000)) &&
      (ip6addr->addr[1] == 0) &&
      (ip6addr->addr[2] == 0) &&
      ((ip6addr->addr[3]  & pp_htonl(0xffffff00)) == 0)) {
    return 3;
  } else if (((ip6addr->addr[0] & pp_htonl(0xff00ffff)) == pp_htonl(0xff000000)) &&
             (ip6addr->addr[1] == 0)) {
    if ((ip6addr->addr[2] == 0) &&
        ((ip6addr->addr[3]  & pp_htonl(0xff000000)) == 0)) {
      return 2;
    } else if ((ip6addr->addr[2]  & pp_htonl(0xffffff00)) == 0) {
      return 1;
    }
  }

  return 0;
}

static int8_t
lowpan6_context_lookup(const Ip6Addr *lowpan6_contexts, const Ip6Addr *ip6addr)
{
    for (int8_t i = 0; i < LWIP_6LOWPAN_NUM_CONTEXTS; i++) {
    if (ip6_addr_on_same_net(&lowpan6_contexts[i], ip6addr)) {
      return i;
    }
  }
  return -1;
}


/*
 * Compress IPv6 and/or UDP headers.
 * */
LwipStatus
lowpan6_compress_headers(NetworkInterface*netif, uint8_t *inbuf, size_t inbuf_size, uint8_t *outbuf, size_t outbuf_size,
                         uint8_t *lowpan6_header_len_out, uint8_t *hidden_header_len_out, Ip6Addr *lowpan6_contexts,
                         const Lowpan6LinkAddr *src, const Lowpan6LinkAddr *dst)
{
    uint8_t hidden_header_len = 0;
    IpAddr ip6src, ip6dst;

  lwip_assert("netif != NULL", netif != nullptr);
  lwip_assert("inbuf != NULL", inbuf != nullptr);
  lwip_assert("outbuf != NULL", outbuf != nullptr);
  lwip_assert("lowpan6_header_len_out != NULL", lowpan6_header_len_out != nullptr);
  lwip_assert("hidden_header_len_out != NULL", hidden_header_len_out != nullptr);

  /* Perform 6LowPAN IPv6 header compression according to RFC 6282 */
  uint8_t* buffer = outbuf;
  uint8_t* inptr = inbuf;

  if (inbuf_size < IP6_HDR_LEN) {
    /* input buffer too short */
    return ERR_VAL;
  }
  if (outbuf_size < IP6_HDR_LEN) {
    /* output buffer too short for worst case */
    return ERR_MEM;
  }

  /* Point to ip6 header and align copies of src/dest addresses. */
  Ip6Hdr* ip6hdr = (Ip6Hdr *)inptr;

  ip_addr_copy_from_ip6_packed(&ip6dst, &ip6hdr->dest);
  assign_ip6_addr_zone((&ip6dst.u_addr.ip6), IP6_UNKNOWN, netif,);
  ip_addr_copy_from_ip6_packed(&ip6src, &ip6hdr->src);
  assign_ip6_addr_zone((&ip6src.u_addr.ip6), IP6_UNKNOWN, netif,);

  /* Basic length of 6LowPAN header, set dispatch and clear fields. */
  uint8_t lowpan6_header_len = 2;
  buffer[0] = 0x60;
  buffer[1] = 0;

  /* Determine whether there will be a Context Identifier Extension byte or not.
   * If so, set it already. */

  buffer[2] = 0;

  int8_t i = lowpan6_context_lookup(lowpan6_contexts, (&ip6src.u_addr.ip6));
  if (i >= 0) {
    /* Stateful source address compression. */
    buffer[1] |= 0x40;
    buffer[2] |= (i & 0x0f) << 4;
  }

  i = lowpan6_context_lookup(lowpan6_contexts, (&ip6dst.u_addr.ip6));
  if (i >= 0) {
    /* Stateful destination address compression. */
    buffer[1] |= 0x04;
    buffer[2] |= i & 0x0f;
  }

  if (buffer[2] != 0x00) {
    /* Context identifier extension byte is appended. */
    buffer[1] |= 0x80;
    lowpan6_header_len++;
  }


  /* Determine TF field: Traffic Class, Flow Label */
  if (IP6H_FL(ip6hdr) == 0) {
    /* Flow label is elided. */
    buffer[0] |= 0x10;
    if (get_ip6_hdr_tc(ip6hdr) == 0) {
      /* Traffic class (ECN+DSCP) elided too. */
      buffer[0] |= 0x08;
    } else {
      /* Traffic class (ECN+DSCP) appended. */
      buffer[lowpan6_header_len++] = get_ip6_hdr_tc(ip6hdr);
    }
  } else {
    if (((get_ip6_hdr_tc(ip6hdr) & 0x3f) == 0)) {
      /* DSCP portion of Traffic Class is elided, ECN and FL are appended (3 bytes) */
      buffer[0] |= 0x08;

      buffer[lowpan6_header_len] = get_ip6_hdr_tc(ip6hdr) & 0xc0;
      buffer[lowpan6_header_len++] |= (IP6H_FL(ip6hdr) >> 16) & 0x0f;
      buffer[lowpan6_header_len++] = (IP6H_FL(ip6hdr) >> 8) & 0xff;
      buffer[lowpan6_header_len++] = IP6H_FL(ip6hdr) & 0xff;
    } else {
      /* Traffic class and flow label are appended (4 bytes) */
      buffer[lowpan6_header_len++] = get_ip6_hdr_tc(ip6hdr);
      buffer[lowpan6_header_len++] = (IP6H_FL(ip6hdr) >> 16) & 0x0f;
      buffer[lowpan6_header_len++] = (IP6H_FL(ip6hdr) >> 8) & 0xff;
      buffer[lowpan6_header_len++] = IP6H_FL(ip6hdr) & 0xff;
    }
  }

  /* Compress NH?
  * Only if UDP for now. @todo support other NH compression. */
  if (IP6H_NEXTH(ip6hdr) == IP6_NEXTH_UDP) {
    buffer[0] |= 0x04;
  } else {
    /* append nexth. */
    buffer[lowpan6_header_len++] = IP6H_NEXTH(ip6hdr);
  }

  /* Compress hop limit? */
  if (IP6H_HOPLIM(ip6hdr) == 255) {
    buffer[0] |= 0x03;
  } else if (IP6H_HOPLIM(ip6hdr) == 64) {
    buffer[0] |= 0x02;
  } else if (IP6H_HOPLIM(ip6hdr) == 1) {
    buffer[0] |= 0x01;
  } else {
    /* append hop limit */
    buffer[lowpan6_header_len++] = IP6H_HOPLIM(ip6hdr);
  }

  /* Compress source address */
  if (((buffer[1] & 0x40) != 0) ||
      (ip6_addr_islinklocal((&ip6src.u_addr.ip6)))) {
    /* Context-based or link-local source address compression. */
    i = lowpan6_get_address_mode((&ip6src.u_addr.ip6), src);
    buffer[1] |= (i & 0x03) << 4;
    if (i == 1) {
      memcpy(buffer + lowpan6_header_len, inptr + 16, 8);
      lowpan6_header_len += 8;
    } else if (i == 2) {
      memcpy(buffer + lowpan6_header_len, inptr + 22, 2);
      lowpan6_header_len += 2;
    }
  } else if (is_ip6_addr_any((&ip6src.u_addr.ip6))) {
    /* Special case: mark SAC and leave SAM=0 */
    buffer[1] |= 0x40;
  } else {
    /* Append full address. */
    memcpy(buffer + lowpan6_header_len, inptr + 8, 16);
    lowpan6_header_len += 16;
  }

  /* Compress destination address */
  if (is_ip6_addr_mcast((&ip6dst.u_addr.ip6))) {
    /* @todo support stateful multicast address compression */

    buffer[1] |= 0x08;

    i = lowpan6_get_address_mode_mc((&ip6dst.u_addr.ip6));
    buffer[1] |= i & 0x03;
    if (i == 0) {
      memcpy(buffer + lowpan6_header_len, inptr + 24, 16);
      lowpan6_header_len += 16;
    } else if (i == 1) {
      buffer[lowpan6_header_len++] = inptr[25];
      memcpy(buffer + lowpan6_header_len, inptr + 35, 5);
      lowpan6_header_len += 5;
    } else if (i == 2) {
      buffer[lowpan6_header_len++] = inptr[25];
      memcpy(buffer + lowpan6_header_len, inptr + 37, 3);
      lowpan6_header_len += 3;
    } else if (i == 3) {
      buffer[lowpan6_header_len++] = (inptr)[39];
    }
  } else if (((buffer[1] & 0x04) != 0) ||
              (ip6_addr_islinklocal((&ip6dst.u_addr.ip6)))) {
    /* Context-based or link-local destination address compression. */
    i = lowpan6_get_address_mode((&ip6dst.u_addr.ip6), dst);
    buffer[1] |= i & 0x03;
    if (i == 1) {
      memcpy(buffer + lowpan6_header_len, inptr + 32, 8);
      lowpan6_header_len += 8;
    } else if (i == 2) {
      memcpy(buffer + lowpan6_header_len, inptr + 38, 2);
      lowpan6_header_len += 2;
    }
  } else {
    /* Append full address. */
    memcpy(buffer + lowpan6_header_len, inptr + 24, 16);
    lowpan6_header_len += 16;
  }

  /* Move to payload. */
  inptr += IP6_HDR_LEN;
  hidden_header_len += IP6_HDR_LEN;

  /* Compress UDP header? */
  if (IP6H_NEXTH(ip6hdr) == IP6_NEXTH_UDP) {
    /* @todo support optional checksum compression */

    if (inbuf_size < IP6_HDR_LEN + UDP_HDR_LEN) {
      /* input buffer too short */
      return ERR_VAL;
    }
    if (outbuf_size < (size_t)(hidden_header_len + 7)) {
      /* output buffer too short for worst case */
      return ERR_MEM;
    }

    buffer[lowpan6_header_len] = 0xf0;

    /* determine port compression mode. */
    if ((inptr[0] == 0xf0) && ((inptr[1] & 0xf0) == 0xb0) &&
        (inptr[2] == 0xf0) && ((inptr[3] & 0xf0) == 0xb0)) {
      /* Compress source and dest ports. */
      buffer[lowpan6_header_len++] |= 0x03;
      buffer[lowpan6_header_len++] = ((inptr[1] & 0x0f) << 4) | (inptr[3] & 0x0f);
    } else if (inptr[0] == 0xf0) {
      /* Compress source port. */
      buffer[lowpan6_header_len++] |= 0x02;
      buffer[lowpan6_header_len++] = inptr[1];
      buffer[lowpan6_header_len++] = inptr[2];
      buffer[lowpan6_header_len++] = inptr[3];
    } else if (inptr[2] == 0xf0) {
      /* Compress dest port. */
      buffer[lowpan6_header_len++] |= 0x01;
      buffer[lowpan6_header_len++] = inptr[0];
      buffer[lowpan6_header_len++] = inptr[1];
      buffer[lowpan6_header_len++] = inptr[3];
    } else {
      /* append full ports. */
      lowpan6_header_len++;
      buffer[lowpan6_header_len++] = inptr[0];
      buffer[lowpan6_header_len++] = inptr[1];
      buffer[lowpan6_header_len++] = inptr[2];
      buffer[lowpan6_header_len++] = inptr[3];
    }

    /* elide length and copy checksum */
    buffer[lowpan6_header_len++] = inptr[6];
    buffer[lowpan6_header_len++] = inptr[7];

    hidden_header_len += UDP_HDR_LEN;
  }


  *lowpan6_header_len_out = lowpan6_header_len;
  *hidden_header_len_out = hidden_header_len;

  return ERR_OK;
}

/** Decompress IPv6 and UDP headers compressed according to RFC 6282
 *
 * @param lowpan6_buffer compressed headers, first byte is the dispatch byte
 * @param lowpan6_bufsize size of lowpan6_buffer (may include data after headers)
 * @param decomp_buffer buffer where the decompressed headers are stored
 * @param decomp_bufsize size of decomp_buffer
 * @param hdr_size_comp returns the size of the compressed headers (skip to get to data)
 * @param hdr_size_decomp returns the size of the decompressed headers (IPv6 + UDP)
 * @param datagram_size datagram size from fragments or 0 if unfragmented
 * @param compressed_size compressed datagram size (for unfragmented rx)
 * @param lowpan6_contexts context addresses
 * @param src source address of the outer layer, used for address compression
 * @param dest destination address of the outer layer, used for address compression
 * @return ERR_OK if decompression succeeded, an error otherwise
 */
static LwipStatus
lowpan6_decompress_hdr(uint8_t *lowpan6_buffer, size_t lowpan6_bufsize,
                       uint8_t *decomp_buffer, size_t decomp_bufsize,
                       uint16_t *hdr_size_comp, uint16_t *hdr_size_decomp,
                       uint16_t datagram_size, uint16_t compressed_size,
                       Ip6Addr *lowpan6_contexts,
                       Lowpan6LinkAddr *src, Lowpan6LinkAddr *dest)
{
    int8_t i;
  uint32_t header_temp;
  uint16_t ip6_offset = IP6_HDR_LEN;

  lwip_assert("lowpan6_buffer != NULL", lowpan6_buffer != nullptr);
  lwip_assert("decomp_buffer != NULL", decomp_buffer != nullptr);
  lwip_assert("src != NULL", src != nullptr);
  lwip_assert("dest != NULL", dest != nullptr);
  lwip_assert("hdr_size_comp != NULL", hdr_size_comp != nullptr);
  lwip_assert("dehdr_size_decompst != NULL", hdr_size_decomp != nullptr);

  Ip6Hdr* ip6hdr = (Ip6Hdr *)decomp_buffer;
  if (decomp_bufsize < IP6_HDR_LEN) {
    return ERR_MEM;
  }

  /* output the full compressed packet, if set in @see lowpan6_opts.h */

  {
      Logf(LWIP_LOWPAN6_IP_COMPRESSED_DEBUG, ("lowpan6_decompress_hdr: IP6 payload (compressed): \n"));
    for (uint16_t j = 0; j < lowpan6_bufsize; j++) {
      if ((j % 4) == 0) {
        Logf(LWIP_LOWPAN6_IP_COMPRESSED_DEBUG, ("\n"));
      }
      Logf(LWIP_LOWPAN6_IP_COMPRESSED_DEBUG, "%2X ", lowpan6_buffer[j]);
    }
    Logf(LWIP_LOWPAN6_IP_COMPRESSED_DEBUG, "\np->len: %d", lowpan6_bufsize);
  }
  /* offset for inline IP headers (RFC 6282 ch3)*/
  uint16_t lowpan6_offset = 2;
  /* if CID is set (context identifier), the context byte 
   * follows immediately after the header, so other IPHC fields are @+3 */
  if (lowpan6_buffer[1] & 0x80) {
    lowpan6_offset++;
  }

  /* Set IPv6 version, traffic class and flow label. (RFC6282, ch 3.1.1.)*/
  if ((lowpan6_buffer[0] & 0x18) == 0x00) {
    header_temp = ((lowpan6_buffer[lowpan6_offset+1] & 0x0f) << 16) | \
      (lowpan6_buffer[lowpan6_offset + 2] << 8) | lowpan6_buffer[lowpan6_offset+3];
    Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, "TF: 00, ECN: 0x%2x, Flowlabel+DSCP: 0x%8X\n", \
      lowpan6_buffer[lowpan6_offset],header_temp);
    get_ip6_hdr_vTCFL_SET(ip6hdr, 6, lowpan6_buffer[lowpan6_offset], header_temp);
    /* increase offset, processed 4 bytes here:
     * TF=00:  ECN + DSCP + 4-bit Pad + Flow Label (4 bytes)*/
    lowpan6_offset += 4;
  } else if ((lowpan6_buffer[0] & 0x18) == 0x08) {
    header_temp = ((lowpan6_buffer[lowpan6_offset] & 0x0f) << 16) | (lowpan6_buffer[lowpan6_offset + 1] << 8) | lowpan6_buffer[lowpan6_offset+2];
    Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, "TF: 01, ECN: 0x%2x, Flowlabel: 0x%2X, DSCP ignored\n", \
      lowpan6_buffer[lowpan6_offset] & 0xc0,header_temp);
    get_ip6_hdr_vTCFL_SET(ip6hdr, 6, lowpan6_buffer[lowpan6_offset] & 0xc0, header_temp);
    /* increase offset, processed 3 bytes here:
     * TF=01:  ECN + 2-bit Pad + Flow Label (3 bytes), DSCP is elided.*/
    lowpan6_offset += 3;
  } else if ((lowpan6_buffer[0] & 0x18) == 0x10) {
    Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, "TF: 10, DCSP+ECN: 0x%2x, Flowlabel ignored\n", lowpan6_buffer[lowpan6_offset]);
    get_ip6_hdr_vTCFL_SET(ip6hdr, 6, lowpan6_buffer[lowpan6_offset],0);
    /* increase offset, processed 1 byte here:
     * ECN + DSCP (1 byte), Flow Label is elided.*/
    lowpan6_offset += 1;
  } else if ((lowpan6_buffer[0] & 0x18) == 0x18) {
    Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("TF: 11, DCSP/ECN & Flowlabel ignored\n"));
    /* don't increase offset, no bytes processed here */
    get_ip6_hdr_vTCFL_SET(ip6hdr, 6, 0, 0);
  }

  /* Set Next Header (NH) */
  if ((lowpan6_buffer[0] & 0x04) == 0x00) {
    /* 0: full next header byte carried inline (increase offset)*/
    Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, "NH: 0x%2X\n", lowpan6_buffer[lowpan6_offset+1]);
    IP6H_NEXTH_SET(ip6hdr, lowpan6_buffer[lowpan6_offset++]);
  } else {
    /* 1: NH compression, LOWPAN_NHC (RFC6282, ch 4.1) */
    /* We should fill this later with NHC decoding */
    Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("NH: skipped, later done with NHC\n"));
    IP6H_NEXTH_SET(ip6hdr, 0);
  }

  /* Set Hop Limit, either carried inline or 3 different hops (1,64,255) */
  if ((lowpan6_buffer[0] & 0x03) == 0x00) {
    Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, "Hops: full value: %d\n", lowpan6_buffer[lowpan6_offset+1]);
    set_ip6_hdr_hop_limit(ip6hdr, lowpan6_buffer[lowpan6_offset++]);
  } else if ((lowpan6_buffer[0] & 0x03) == 0x01) {
    Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("Hops: compressed: 1\n"));
    set_ip6_hdr_hop_limit(ip6hdr, 1);
  } else if ((lowpan6_buffer[0] & 0x03) == 0x02) {
    Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("Hops: compressed: 64\n"));
    set_ip6_hdr_hop_limit(ip6hdr, 64);
  } else if ((lowpan6_buffer[0] & 0x03) == 0x03) {
    Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("Hops: compressed: 255\n"));
    set_ip6_hdr_hop_limit(ip6hdr, 255);
  }

  /* Source address decoding. */
  if ((lowpan6_buffer[1] & 0x40) == 0x00) {
    /* Source address compression (SAC) = 0 -> stateless compression */
    Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("SAC == 0, no context byte\n"));
    /* Stateless compression */
    if ((lowpan6_buffer[1] & 0x30) == 0x00) {
      Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("SAM == 00, no src compression, fetching 128bits inline\n"));
      /* copy full address, increase offset by 16 Bytes */
      memcpy(&ip6hdr->src.addr[0], lowpan6_buffer + lowpan6_offset, 16);
      lowpan6_offset += 16;
    } else if ((lowpan6_buffer[1] & 0x30) == 0x10) {
      Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("SAM == 01, src compression, 64bits inline\n"));
      /* set 64 bits to link local */
      ip6hdr->src.addr[0] = pp_htonl(0xfe800000UL);
      ip6hdr->src.addr[1] = 0;
      /* copy 8 Bytes, increase offset */
      memcpy(&ip6hdr->src.addr[2], lowpan6_buffer + lowpan6_offset, 8);
      lowpan6_offset += 8;
    } else if ((lowpan6_buffer[1] & 0x30) == 0x20) {
      Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("SAM == 10, src compression, 16bits inline\n"));
      /* set 96 bits to link local */
      ip6hdr->src.addr[0] = pp_htonl(0xfe800000UL);
      ip6hdr->src.addr[1] = 0;
      ip6hdr->src.addr[2] = pp_htonl(0x000000ffUL);
      /* extract remaining 16bits from inline bytes, increase offset */
      ip6hdr->src.addr[3] = lwip_htonl(0xfe000000UL | (lowpan6_buffer[lowpan6_offset] << 8) |
                                       lowpan6_buffer[lowpan6_offset + 1]);
      lowpan6_offset += 2;
    } else if ((lowpan6_buffer[1] & 0x30) == 0x30) {
      Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("SAM == 11, src compression, 0bits inline, using other headers\n"));
      /* no information avalaible, using other layers, see RFC6282 ch 3.2.2 */
      ip6hdr->src.addr[0] = pp_htonl(0xfe800000UL);
      ip6hdr->src.addr[1] = 0;
      if (src->addr_len == 2) {
        ip6hdr->src.addr[2] = pp_htonl(0x000000ffUL);
        ip6hdr->src.addr[3] = lwip_htonl(0xfe000000UL | (src->addr[0] << 8) | src->addr[1]);
      } else if (src->addr_len == 8) {
        ip6hdr->src.addr[2] = lwip_htonl(((src->addr[0] ^ 2) << 24) | (src->addr[1] << 16) |
                                         (src->addr[2] << 8) | src->addr[3]);
        ip6hdr->src.addr[3] = lwip_htonl((src->addr[4] << 24) | (src->addr[5] << 16) |
                                         (src->addr[6] << 8) | src->addr[7]);
      } else {
        /* invalid source address length */
        Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("Invalid source address length\n"));
        return ERR_VAL;
      }
    }
  } else {
    /* Source address compression (SAC) = 1 -> stateful/context-based compression */
    Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("SAC == 1, additional context byte\n"));
    if ((lowpan6_buffer[1] & 0x30) == 0x00) {
      /* SAM=00, address=> :: (ANY) */
      ip6hdr->src.addr[0] = 0;
      ip6hdr->src.addr[1] = 0;
      ip6hdr->src.addr[2] = 0;
      ip6hdr->src.addr[3] = 0;
      Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("SAM == 00, context compression, ANY (::)\n"));
    } else {
      /* Set prefix from context info */
      if (lowpan6_buffer[1] & 0x80) {
        i = (lowpan6_buffer[2] >> 4) & 0x0f;
      } else {
        i = 0;
      }
      if (i >= LWIP_6LOWPAN_NUM_CONTEXTS) {
        /* Error */
        return ERR_VAL;
      }

      ip6hdr->src.addr[0] = lowpan6_contexts[i].addr[0];
      ip6hdr->src.addr[1] = lowpan6_contexts[i].addr[1];
      Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, "SAM == xx, context compression found @%d: %8X, %8X\n", (int)i, ip6hdr->src.addr[0], ip6hdr->src.addr[1]);

    }

    /* determine further address bits */
    if ((lowpan6_buffer[1] & 0x30) == 0x10) {
      /* SAM=01, load additional 64bits */
      memcpy(&ip6hdr->src.addr[2], lowpan6_buffer + lowpan6_offset, 8);
      Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("SAM == 01, context compression, 64bits inline\n"));
      lowpan6_offset += 8;
    } else if ((lowpan6_buffer[1] & 0x30) == 0x20) {
      /* SAM=01, load additional 16bits */
      ip6hdr->src.addr[2] = pp_htonl(0x000000ffUL);
      ip6hdr->src.addr[3] = lwip_htonl(0xfe000000UL | (lowpan6_buffer[lowpan6_offset] << 8) | lowpan6_buffer[lowpan6_offset + 1]);
      Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("SAM == 10, context compression, 16bits inline\n"));
      lowpan6_offset += 2;
    } else if ((lowpan6_buffer[1] & 0x30) == 0x30) {
      /* SAM=11, address is fully elided, load from other layers */
      Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("SAM == 11, context compression, 0bits inline, using other headers\n"));
      if (src->addr_len == 2) {
        ip6hdr->src.addr[2] = pp_htonl(0x000000ffUL);
        ip6hdr->src.addr[3] = lwip_htonl(0xfe000000UL | (src->addr[0] << 8) | src->addr[1]);
      } else if (src->addr_len == 8) {
        ip6hdr->src.addr[2] = lwip_htonl(((src->addr[0] ^ 2) << 24) | (src->addr[1] << 16) | (src->addr[2] << 8) | src->addr[3]);
        ip6hdr->src.addr[3] = lwip_htonl((src->addr[4] << 24) | (src->addr[5] << 16) | (src->addr[6] << 8) | src->addr[7]);
      } else {
        /* invalid source address length */
        Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("Invalid source address length\n"));
        return ERR_VAL;
      }
    }
  }

  /* Destination address decoding. */
  if (lowpan6_buffer[1] & 0x08) {
    Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("M=1: multicast\n"));
    /* Multicast destination */
    if (lowpan6_buffer[1] & 0x04) {
      Logf(true,("DAC == 1, context multicast: unsupported!!!\n"));
      /* @todo support stateful multicast addressing */
      return ERR_VAL;
    }

    if ((lowpan6_buffer[1] & 0x03) == 0x00) {
      /* DAM = 00, copy full address (128bits) */
      Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("DAM == 00, no dst compression, fetching 128bits inline\n"));
      memcpy(&ip6hdr->dest.addr[0], lowpan6_buffer + lowpan6_offset, 16);
      lowpan6_offset += 16;
    } else if ((lowpan6_buffer[1] & 0x03) == 0x01) {
      /* DAM = 01, copy 4 bytes (32bits) */
      Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("DAM == 01, dst address form (48bits): ffXX::00XX:XXXX:XXXX\n"));
      ip6hdr->dest.addr[0] = lwip_htonl(0xff000000UL | (lowpan6_buffer[lowpan6_offset++] << 16));
      ip6hdr->dest.addr[1] = 0;
      ip6hdr->dest.addr[2] = lwip_htonl(lowpan6_buffer[lowpan6_offset++]);
      ip6hdr->dest.addr[3] = lwip_htonl((lowpan6_buffer[lowpan6_offset] << 24) | (lowpan6_buffer[lowpan6_offset + 1] << 16) | (lowpan6_buffer[lowpan6_offset + 2] << 8) | lowpan6_buffer[lowpan6_offset + 3]);
      lowpan6_offset += 4;
    } else if ((lowpan6_buffer[1] & 0x03) == 0x02) {
      /* DAM = 10, copy 3 bytes (24bits) */
      Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("DAM == 10, dst address form (32bits): ffXX::00XX:XXXX\n"));
      ip6hdr->dest.addr[0] = lwip_htonl(0xff000000UL | (lowpan6_buffer[lowpan6_offset++] << 16));
      ip6hdr->dest.addr[1] = 0;
      ip6hdr->dest.addr[2] = 0;
      ip6hdr->dest.addr[3] = lwip_htonl((lowpan6_buffer[lowpan6_offset] << 16) | (lowpan6_buffer[lowpan6_offset + 1] << 8) | lowpan6_buffer[lowpan6_offset + 2]);
      lowpan6_offset += 3;
    } else if ((lowpan6_buffer[1] & 0x03) == 0x03) {
      /* DAM = 11, copy 1 byte (8bits) */
      Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("DAM == 11, dst address form (8bits): ff02::00XX\n"));
      ip6hdr->dest.addr[0] = pp_htonl(0xff020000UL);
      ip6hdr->dest.addr[1] = 0;
      ip6hdr->dest.addr[2] = 0;
      ip6hdr->dest.addr[3] = lwip_htonl(lowpan6_buffer[lowpan6_offset++]);
    }

  } else {
    /* no Multicast (M=0) */
    if (lowpan6_buffer[1] & 0x04) {
      Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("DAC == 1, stateful compression\n"));
      /* Stateful destination compression */
      /* Set prefix from context info */
      if (lowpan6_buffer[1] & 0x80) {
        i = lowpan6_buffer[2] & 0x0f;
      } else {
        i = 0;
      }
      if (i >= LWIP_6LOWPAN_NUM_CONTEXTS) {
        /* Error */
        return ERR_VAL;
      }

      ip6hdr->dest.addr[0] = lowpan6_contexts[i].addr[0];
      ip6hdr->dest.addr[1] = lowpan6_contexts[i].addr[1];

    } else {
      Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("DAC == 0, stateless compression, setting link local prefix\n"));
      /* Link local address compression */
      ip6hdr->dest.addr[0] = pp_htonl(0xfe800000UL);
      ip6hdr->dest.addr[1] = 0;
    }

    /* M=0, DAC=0, determining destination address length via DAM=xx */
    if ((lowpan6_buffer[1] & 0x03) == 0x00) {
      Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("DAM == 00, no dst compression, fetching 128bits inline"));
      /* DAM=00, copy full address */
      memcpy(&ip6hdr->dest.addr[0], lowpan6_buffer + lowpan6_offset, 16);
      lowpan6_offset += 16;
    } else if ((lowpan6_buffer[1] & 0x03) == 0x01) {
      Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("DAM == 01, dst compression, 64bits inline\n"));
      /* DAM=01, copy 64 inline bits, increase offset */
      memcpy(&ip6hdr->dest.addr[2], lowpan6_buffer + lowpan6_offset, 8);
      lowpan6_offset += 8;
    } else if ((lowpan6_buffer[1] & 0x03) == 0x02) {
      Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("DAM == 01, dst compression, 16bits inline\n"));
      /* DAM=10, copy 16 inline bits, increase offset */
      ip6hdr->dest.addr[2] = pp_htonl(0x000000ffUL);
      ip6hdr->dest.addr[3] = lwip_htonl(0xfe000000UL | (lowpan6_buffer[lowpan6_offset] << 8) | lowpan6_buffer[lowpan6_offset + 1]);
      lowpan6_offset += 2;
    } else if ((lowpan6_buffer[1] & 0x03) == 0x03) {
      /* DAM=11, no bits available, use other headers (not done here) */
      Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG,("DAM == 01, dst compression, 0bits inline, using other headers\n"));
      if (dest->addr_len == 2) {
        ip6hdr->dest.addr[2] = pp_htonl(0x000000ffUL);
        ip6hdr->dest.addr[3] = lwip_htonl(0xfe000000UL | (dest->addr[0] << 8) | dest->addr[1]);
      } else if (dest->addr_len == 8) {
        ip6hdr->dest.addr[2] = lwip_htonl(((dest->addr[0] ^ 2) << 24) | (dest->addr[1] << 16) | dest->addr[2] << 8 | dest->addr[3]);
        ip6hdr->dest.addr[3] = lwip_htonl((dest->addr[4] << 24) | (dest->addr[5] << 16) | dest->addr[6] << 8 | dest->addr[7]);
      } else {
        /* invalid destination address length */
        Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("Invalid destination address length\n"));
        return ERR_VAL;
      }
    }
  }


  /* Next Header Compression (NHC) decoding? */
  if (lowpan6_buffer[0] & 0x04) {
    Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("NHC decoding\n"));

    if ((lowpan6_buffer[lowpan6_offset] & 0xf8) == 0xf0) {
        Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("NHC: UDP\n"));

      /* UDP compression */
      IP6H_NEXTH_SET(ip6hdr, IP6_NEXTH_UDP);
      UdpHdr* udphdr = (UdpHdr *)((uint8_t *)decomp_buffer + ip6_offset);
      if (decomp_bufsize < IP6_HDR_LEN + UDP_HDR_LEN) {
        return ERR_MEM;
      }

      /* Checksum decompression */
      if (lowpan6_buffer[lowpan6_offset] & 0x04) {
        /* @todo support checksum decompress */
        Logf(true, ("NHC: UDP chechsum decompression UNSUPPORTED\n"));
        return ERR_VAL;
      }

      /* Decompress ports, according to RFC4944 */
      i = lowpan6_buffer[lowpan6_offset++] & 0x03;
      if (i == 0) {
        udphdr->src = lwip_htons(lowpan6_buffer[lowpan6_offset] << 8 | lowpan6_buffer[lowpan6_offset + 1]);
        udphdr->dest = lwip_htons(lowpan6_buffer[lowpan6_offset + 2] << 8 | lowpan6_buffer[lowpan6_offset + 3]);
        lowpan6_offset += 4;
      } else if (i == 0x01) {
        udphdr->src = lwip_htons(lowpan6_buffer[lowpan6_offset] << 8 | lowpan6_buffer[lowpan6_offset + 1]);
        udphdr->dest = lwip_htons(0xf000 | lowpan6_buffer[lowpan6_offset + 2]);
        lowpan6_offset += 3;
      } else if (i == 0x02) {
        udphdr->src = lwip_htons(0xf000 | lowpan6_buffer[lowpan6_offset]);
        udphdr->dest = lwip_htons(lowpan6_buffer[lowpan6_offset + 1] << 8 | lowpan6_buffer[lowpan6_offset + 2]);
        lowpan6_offset += 3;
      } else if (i == 0x03) {
        udphdr->src = lwip_htons(0xf0b0 | ((lowpan6_buffer[lowpan6_offset] >> 4) & 0x0f));
        udphdr->dest = lwip_htons(0xf0b0 | (lowpan6_buffer[lowpan6_offset] & 0x0f));
        lowpan6_offset += 1;
      }

      udphdr->chksum = lwip_htons(lowpan6_buffer[lowpan6_offset] << 8 | lowpan6_buffer[lowpan6_offset + 1]);
      lowpan6_offset += 2;
      ip6_offset += UDP_HDR_LEN;
      if (datagram_size == 0) {
        datagram_size = compressed_size - lowpan6_offset + ip6_offset;
      }
      udphdr->len = lwip_htons(datagram_size - IP6_HDR_LEN);

    } else

    {
      Logf(true,("NHC: unsupported protocol!\n"));
      /* @todo support NHC other than UDP */
      return ERR_VAL;
    }
  }
  if (datagram_size == 0) {
    datagram_size = compressed_size - lowpan6_offset + ip6_offset;
  }
  /* Infer IPv6 payload length for header */
  set_ip6_hdr_plen(ip6hdr, datagram_size - IP6_HDR_LEN);

  if (lowpan6_offset > lowpan6_bufsize) {
    /* input buffer overflow */
    return ERR_VAL;
  }
  *hdr_size_comp = lowpan6_offset;
  *hdr_size_decomp = ip6_offset;

  return ERR_OK;
}

struct PacketBuffer *
lowpan6_decompress(struct PacketBuffer *p, uint16_t datagram_size, Ip6Addr *lowpan6_contexts,
                   Lowpan6LinkAddr *src, Lowpan6LinkAddr *dest)
{
    uint16_t lowpan6_offset, ip6_offset;
#define UDP_HLEN_ALLOC UDP_HDR_LEN


  /* Allocate a buffer for decompression. This buffer will be too big and will be
     trimmed once the final size is known. */
  struct PacketBuffer* q = pbuf_alloc(PBUF_IP, p->len + IP6_HDR_LEN + UDP_HLEN_ALLOC);
  if (q == nullptr) {
    free_pkt_buf(p);
    return nullptr;
  }
  if (q->len < IP6_HDR_LEN + UDP_HLEN_ALLOC) {
    /* The headers need to fit into the first PacketBuffer */
    free_pkt_buf(p);
    free_pkt_buf(q);
    return nullptr;
  }

  /* Decompress the IPv6 (and possibly UDP) header(s) into the new PacketBuffer */
  LwipStatus err = lowpan6_decompress_hdr((uint8_t *)p->payload,
                                          p->len,
                                          (uint8_t *)q->payload,
                                          q->len,
                                          &lowpan6_offset,
                                          &ip6_offset,
                                          datagram_size,
                                          p->tot_len,
                                          lowpan6_contexts,
                                          src,
                                          dest);
  if (err != ERR_OK) {
    free_pkt_buf(p);
    free_pkt_buf(q);
    return nullptr;
  }

  /* Now we copy leftover contents from p to q, so we have all L2 and L3 headers
     (and L4?) in a single PacketBuffer: */

  /* Hide the compressed headers in p */
  pbuf_remove_header(p, lowpan6_offset);
  /* Temporarily hide the headers in q... */
  pbuf_remove_header(q, ip6_offset);
  /* ... copy the rest of p into q... */
  pbuf_copy(q, p);
  /* ... and reveal the headers again... */
  pbuf_add_header_force(q, ip6_offset);
  /* ... trim the PacketBuffer to its correct size... */
  pbuf_realloc(q);
  /* ... and cat possibly remaining (data-only) pbufs */
  if (p->next != nullptr) {
    pbuf_cat(q, p->next);
  }
  /* the original (first) PacketBuffer can now be freed */
  p->next = nullptr;
  free_pkt_buf(p);

  /* all done */
  return q;
}
