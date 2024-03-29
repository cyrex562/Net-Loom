/**
 * @file
 * 6LowPAN over BLE output for IPv6 (RFC7668).
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


/**
 * @defgroup rfc7668if 6LoWPAN over BLE (RFC7668)
 * @ingroup netifs
 * This file implements a RFC7668 implementation for 6LoWPAN over
 * Bluetooth Low Energy. The specification is very similar to 6LoWPAN,
 * so most of the code is re-used.
 * Compared to 6LoWPAN, much functionality is already implemented in
 * lower BLE layers (fragmenting, session management,...).
 *
 * Usage:
 * - add this netif
 *   - don't add IPv4 addresses (no IPv4 support in RFC7668), pass 'NULL','NULL','NULL'
 *   - use the BLE to EUI64 conversation util to create an IPv6 link-local address from the BLE MAC (@ref ble_addr_to_eui64)
 *   - input function: @ref rfc7668_input
 * - set the link output function, which transmits output data to an established L2CAP channel
 * - If data arrives (HCI event "L2CAP_DATA_PACKET"):
 *   - allocate a @ref PBUF_RAW buffer
 *   - let the PacketBuffer struct point to the incoming data or copy it to the buffer
 *   - call netif->input
 *
 * @todo:
 * - further testing
 * - support compression contexts
 * - support multiple addresses
 * - support multicast
 * - support neighbor discovery
 */


#include <cstring>
#include <ip.h>
#include <lowpan6_ble.h>
#include <lowpan6_common.h>
#include <nd6.h>
#include <network_interface.h>
#include <packet_buffer.h>
#include <tcpip.h>
/** context memory, containing IPv6 addresses */
static Ip6Addr rfc7668_context[LWIP_6LOWPAN_NUM_CONTEXTS];

static struct Lowpan6LinkAddr rfc7668_local_addr;
static struct Lowpan6LinkAddr rfc7668_peer_addr;

/**
 * @ingroup rfc7668if
 *  convert BT address to EUI64 addr
 *
 * This method converts a Bluetooth MAC address to an EUI64 address,
 * which is used within IPv6 communication
 *
 * @param dst IPv6 destination space
 * @param src BLE MAC address source
 * @param public_addr If the LWIP_RFC7668_LINUX_WORKAROUND_PUBLIC_ADDRESS
 * option is set, bit 0x02 will be set if param=0 (no public addr); cleared otherwise
 *
 * @see LWIP_RFC7668_LINUX_WORKAROUND_PUBLIC_ADDRESS
 */
void
ble_addr_to_eui64(uint8_t *dst, const uint8_t *src, int public_addr)
{
  /* according to RFC7668 ch 3.2.2. */
  memcpy(dst, src, 3);
  dst[3] = 0xFF;
  dst[4] = 0xFE;
  memcpy(&dst[5], &src[3], 3);

  if(public_addr) {
    dst[0] &= ~0x02;
  } else {
    dst[0] |= 0x02;
  }
}

/**
 * @ingroup rfc7668if
 *  convert EUI64 address to Bluetooth MAC addr
 *
 * This method converts an EUI64 address to a Bluetooth MAC address,
 *
 * @param dst BLE MAC address destination
 * @param src IPv6 source
 *
 */
void
eui64_to_ble_addr(uint8_t *dst, const uint8_t *src)
{
  /* according to RFC7668 ch 3.2.2. */
  memcpy(dst,src,3);
  memcpy(&dst[3],&src[5],3);
}

/** Set an address used for stateful compression.
 * This expects an address of 6 or 8 bytes.
 */
static LwipStatus
rfc7668_set_addr(struct Lowpan6LinkAddr *addr, const uint8_t *in_addr, size_t in_addr_len, int is_mac_48, int is_public_addr)
{
  if ((in_addr == nullptr) || (addr == nullptr)) {
    return ERR_VAL;
  }
  if (is_mac_48) {
    if (in_addr_len != 6) {
      return ERR_VAL;
    }
    addr->addr_len = 8;
    ble_addr_to_eui64(addr->addr, in_addr, is_public_addr);
  } else {
    if (in_addr_len != 8) {
      return ERR_VAL;
    }
    addr->addr_len = 8;
    memcpy(addr->addr, in_addr, 8);
  }
  return STATUS_SUCCESS;
}


/** Set the local address used for stateful compression.
 * This expects an address of 8 bytes.
 */
LwipStatus
rfc7668_set_local_addr_eui64(NetworkInterface*netif, const uint8_t *local_addr, size_t local_addr_len)
{
    return rfc7668_set_addr(&rfc7668_local_addr, local_addr, local_addr_len, 0, 0);
}

/** Set the local address used for stateful compression.
 * This expects an address of 6 bytes.
 */
LwipStatus
rfc7668_set_local_addr_mac48(NetworkInterface*netif, const uint8_t *local_addr, size_t local_addr_len, int is_public_addr)
{
    return rfc7668_set_addr(&rfc7668_local_addr, local_addr, local_addr_len, 1, is_public_addr);
}

/** Set the peer address used for stateful compression.
 * This expects an address of 8 bytes.
 */
LwipStatus
rfc7668_set_peer_addr_eui64(NetworkInterface*netif, const uint8_t *peer_addr, size_t peer_addr_len)
{
    return rfc7668_set_addr(&rfc7668_peer_addr, peer_addr, peer_addr_len, 0, 0);
}

/** Set the peer address used for stateful compression.
 * This expects an address of 6 bytes.
 */
LwipStatus
rfc7668_set_peer_addr_mac48(NetworkInterface*netif, const uint8_t *peer_addr, size_t peer_addr_len, int is_public_addr)
{
    return rfc7668_set_addr(&rfc7668_peer_addr, peer_addr, peer_addr_len, 1, is_public_addr);
}

/** Encapsulate IPv6 frames for BLE transmission
 *
 * This method implements the IPv6 header compression:
 *  *) According to RFC6282
 *  *) See Figure 2, contains base format of bit positions
 *  *) Fragmentation not necessary (done at L2CAP layer of BLE)
 * @note Currently the PacketBuffer allocation uses 256 bytes. If longer packets are used (possible due to MTU=1480Bytes), increase it here!
 *
 * @param p Pbuf struct, containing the payload data
 * @param netif Output network interface. Should be of RFC7668 type
 *
 * @return Same as netif->output.
 */
static LwipStatus
rfc7668_compress(NetworkInterface*netif, struct PacketBuffer *p)
{
    uint8_t lowpan6_header_len;
  uint8_t hidden_header_len; //  lwip_assert("lowpan6_frag: netif->linkoutput not set", netif->linkoutput != NULL);


  /* We'll use a dedicated PacketBuffer for building BLE fragments.
   * We'll over-allocate it by the bytes saved for header compression.
   */
  // struct PacketBuffer* p_frag = pbuf_alloc();
    PacketBuffer p_frag{};
  if (p_frag == nullptr) {
    return ERR_MEM;
  }
//  lwip_assert("this needs a PacketBuffer in one piece", p_frag->len == p_frag->tot_len);

  /* Write IP6 header (with IPHC). */
  uint8_t* buffer = (uint8_t*)p_frag->payload;

  LwipStatus err = lowpan6_compress_headers(netif,
                                            (uint8_t *)p->payload,
                                            p->len,
                                            buffer,
                                            p_frag->len,
                                            &lowpan6_header_len,
                                            &hidden_header_len,
                                            rfc7668_context,
                                            &rfc7668_local_addr,
                                            &rfc7668_peer_addr);
  if (err != STATUS_SUCCESS) {

    free_pkt_buf(p_frag);
    return err;
  }
  // pbuf_remove_header(p, hidden_header_len);

  /* Calculate remaining packet length */
  uint16_t remaining_len = p->tot_len;

  /* Copy IPv6 packet */
  pbuf_copy_partial(p, buffer + lowpan6_header_len, remaining_len, 0);

  /* Calculate frame length */
  p_frag->len = p_frag->tot_len = remaining_len + lowpan6_header_len;

  /* send the packet */

//  Logf(LWIP_LOWPAN6_DEBUG|LWIP_DBG_TRACE, ("rfc7668_output: sending packet %p\n", (uint8_t *)p));
  err = netif->linkoutput(netif, p_frag);

  free_pkt_buf(p_frag);

  return err;

}

/**
 * @ingroup rfc7668if
 * Set context id IPv6 address
 *
 * Store one IPv6 address to a given context id.
 *
 * @param idx Context id
 * @param context IPv6 addr for this context
 *
 * @return ERR_OK (if everything is fine), ERR_ARG (if the context id is out of range), ERR_VAL (if contexts disabled)
 */
LwipStatus
rfc7668_set_context(uint8_t idx, const Ip6Addr*context)
{

  /* check if the ID is possible */
  if (idx >= LWIP_6LOWPAN_NUM_CONTEXTS) {
    return STATUS_E_INVALID_ARG;
  }
  /* copy IPv6 address to context storage */
  set_ip6_addr(&rfc7668_context[idx], context);
  return STATUS_SUCCESS;

}

/**
 * @ingroup rfc7668if
 * Compress outgoing IPv6 packet and pass it on to netif->linkoutput
 *
 * @param netif The lwIP network interface which the IP packet will be sent on.
 * @param q The PacketBuffer(s) containing the IP packet to be sent.
 * @param ip6addr The IP address of the packet destination.
 *
 * @return See rfc7668_compress
 */
LwipStatus
rfc7668_output(NetworkInterface*netif, struct PacketBuffer *q, const Ip6Addr*ip6addr)
{
  /* dst ip6addr is not used here, we only have one peer */
  return rfc7668_compress(netif, q);
}

/**
 * @ingroup rfc7668if
 * Process a received raw payload from an L2CAP channel
 *
 * @param p the received packet, p->payload pointing to the
 *        IPv6 header (maybe compressed)
 * @param netif the network interface on which the packet was received
 *
 * @return ERR_OK if everything was fine
 */
LwipStatus
rfc7668_input(struct PacketBuffer * p, NetworkInterface*netif)
{
    /* Load first header byte */
  uint8_t* puc = (uint8_t*)p->payload;

  /* no IP header compression */
  if (*puc == 0x41) {
//    Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("Completed packet, removing dispatch: 0x%2x \n", *puc));
    /* This is a complete IPv6 packet, just skip header byte. */
    // pbuf_remove_header(p, 1);
  /* IPHC header compression */
  } else if ((*puc & 0xe0 )== 0x60) {
//    Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("Completed packet, decompress dispatch: 0x%2x \n", *puc));
    /* IPv6 headers are compressed using IPHC. */
    p = lowpan6_decompress(p, 0, rfc7668_context, &rfc7668_peer_addr, &rfc7668_local_addr);
    /* if no PacketBuffer is returned, handle as discarded packet */
    if (p == nullptr) {
      return STATUS_SUCCESS;
    }
  /* invalid header byte, discard */
  } else {
//    Logf(LWIP_LOWPAN6_DECOMPRESSION_DEBUG, ("Completed packet, discarding: 0x%2x \n", *puc));
    free_pkt_buf(p);
    return STATUS_SUCCESS;
  }
  /* @todo: distinguish unicast/multicast */

  {
      Logf(LWIP_RFC7668_IP_UNCOMPRESSED_DEBUG, ("IPv6 payload:\n"));
    for (uint16_t i = 0; i < p->len; i++) {
      if ((i%4)==0) {
        Logf(LWIP_RFC7668_IP_UNCOMPRESSED_DEBUG, ("\n"));
      }
      // Logf(LWIP_RFC7668_IP_UNCOMPRESSED_DEBUG, ("%2X ", *((uint8_t *)p->payload+i)));
    }
    // Logf(LWIP_RFC7668_IP_UNCOMPRESSED_DEBUG, ("\np->len: %d\n", p->len));
  }

  /* pass data to ip6_input */
  return recv_ip6_pkt(p, netif);
}

/**
 * @ingroup rfc7668if
 * Initialize the netif
 *
 * No flags are used (broadcast not possible, not ethernet, ...)
 * The shortname for this netif is "BT"
 *
 * @param netif the network interface to be initialized as RFC7668 netif
 *
 * @return ERR_OK if everything went fine
 */
LwipStatus
rfc7668_if_init(NetworkInterface*netif)
{
  netif->name[0] = 'b';
  netif->name[1] = 't';
  /* local function as IPv6 output */
  netif->output_ip6 = rfc7668_output;


  /* maximum transfer unit, set according to RFC7668 ch2.4 */
  netif->mtu = 1280;

  /* no flags set (no broadcast, ethernet,...)*/
  netif->flags = 0;

  /* everything fine */
  return STATUS_SUCCESS;
}

/**
 * Pass a received packet to tcpip_thread for input processing
 *
 * @param p the received packet, p->payload pointing to the
 *          IEEE 802.15.4 header.
 * @param inp the network interface on which the packet was received
 *
 * @return see @ref tcpip_inpkt, same return values
 */
LwipStatus
tcpip_rfc7668_input(struct PacketBuffer *p, NetworkInterface*inp)
{
  /* send data to upper layer, return the result */
  return tcpip_inpkt(p, inp, rfc7668_input);
}

