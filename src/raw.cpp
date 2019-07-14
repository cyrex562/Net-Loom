/**
 * @file
 * Implementation of raw protocol PCBs for low-level handling of
 * different types of protocols besides (or overriding) those
 * already available in lwIP.\n
 * See also @ref raw_raw
 *
 * @defgroup raw_raw RAW
 * @ingroup callbackstyle_api
 * Implementation of raw protocol PCBs for low-level handling of
 * different types of protocols besides (or overriding) those
 * already available in lwIP.\n
 * @see @ref api
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

#include "opt.h"

#include "def.h"
#include "memp.h"
#include "ip_addr.h"
#include "netif.h"
#include "raw.h"
#include "raw_priv.h"
#include "stats.h"
#include "ip6.h"
#include "ip6_addr.h"
#include "inet_chksum.h"
#include <cstring>
#include "ip.h"
/** The list of RAW PCBs */
static struct raw_pcb *raw_pcbs;

static uint8_t
raw_input_local_match(struct raw_pcb *pcb, uint8_t broadcast)
{
  /* check if PCB is bound to specific netif */
  if ((pcb->netif_idx != NETIF_NO_INDEX) &&
      (pcb->netif_idx != netif_get_index(ip_data.current_input_netif))) {
    return 0;
  }

  /* Dual-stack: PCBs listening to any IP type also listen to any IP address */
  if (IpIsAnyTypeVal(pcb->local_ip)) {

    if ((broadcast != 0) && !ip_get_option(pcb, SOF_BROADCAST)) {
      return 0;
    }
    return 1;
  }

  /* Only need to check PCB if incoming IP version matches PCB IP version */
  if (IpAddrPcbVersionMatchExact(pcb, ip_current_dest_addr())) {
    /* Special case: IPv4 broadcast: receive all broadcasts
     * Note: broadcast variable can only be 1 if it is an IPv4 broadcast */
    if (broadcast != 0) {
      if (ip_get_option(pcb, SOF_BROADCAST))

      {
        if (ip4_addr_isany(IpAddrToIp4Addr(&pcb->local_ip))) {
          return 1;
        }
      }
    } else

      /* Handle IPv4 and IPv6: catch all or exact match */
      if (ip_addr_isany(&pcb->local_ip) ||
          ip_addr_cmp(&pcb->local_ip, ip_current_dest_addr())) {
        return 1;
      }
  }

  return 0;
}

/**
 * Determine if in incoming IP packet is covered by a RAW PCB
 * and if so, pass it to a user-provided receive callback function.
 *
 * Given an incoming IP datagram (as a chain of pbufs) this function
 * finds a corresponding RAW PCB and calls the corresponding receive
 * callback function.
 *
 * @param p PacketBuffer to be demultiplexed to a RAW PCB.
 * @param inp network interface on which the datagram was received.
 * @return - 1 if the packet has been eaten by a RAW PCB receive
 *           callback function. The caller MAY NOT not reference the
 *           packet any longer, and MAY NOT call pbuf_free().
 * @return - 0 if packet is not eaten (PacketBuffer is still referenced by the
 *           caller).
 *
 */
raw_input_state_t
raw_input(struct PacketBuffer *p, NetIfc*inp)
{
  struct raw_pcb *pcb, *prev;
  int16_t proto;
  raw_input_state_t ret = RAW_INPUT_NONE;
  uint8_t broadcast = ip_addr_isbroadcast(ip_current_dest_addr(), ip_current_netif());

  ;


  if (IP_HDR_GET_VERSION(p->payload) == 6)
  {
    struct Ip6Hdr *ip6hdr = (struct Ip6Hdr *)p->payload;
    proto = IP6H_NEXTH(ip6hdr);
  }
  else
  {
    proto = IPH_PROTO((struct Ip4Hdr *)p->payload);
  }

  prev = nullptr;
  pcb = raw_pcbs;
  /* loop through all raw pcbs until the packet is eaten by one */
  /* this allows multiple pcbs to match against the packet by design */
  while (pcb != nullptr) {
    if ((pcb->protocol == proto) && raw_input_local_match(pcb, broadcast) &&
        (((pcb->flags & RAW_FLAGS_CONNECTED) == 0) ||
         ip_addr_cmp(&pcb->remote_ip, ip_current_src_addr()))) {
      /* receive callback function available? */
      if (pcb->recv != nullptr) {
        uint8_t eaten;

        void *old_payload = p->payload;
        ret = RAW_INPUT_DELIVERED;
        /* the receive callback function did not eat the packet? */
        eaten = pcb->recv(pcb->recv_arg, pcb, p, ip_current_src_addr());
        if (eaten != 0) {
          /* receive function ate the packet */
          p = nullptr;
          if (prev != nullptr) {
            /* move the pcb to the front of raw_pcbs so that is
               found faster next time */
            prev->next = pcb->next;
            pcb->next = raw_pcbs;
            raw_pcbs = pcb;
          }
          return RAW_INPUT_EATEN;
        } else {
          /* sanity-check that the receive callback did not alter the PacketBuffer */
          LWIP_ASSERT("raw pcb recv callback altered PacketBuffer payload pointer without eating packet",
                      p->payload == old_payload);
        }
      }
      /* no receive callback function was set for this raw PCB */
    }
    /* drop the packet */
    prev = pcb;
    pcb = pcb->next;
  }
  return ret;
}

/**
 * @ingroup raw_raw
 * Bind a RAW PCB.
 *
 * @param pcb RAW PCB to be bound with a local address ipaddr.
 * @param ipaddr local IP address to bind with. Use IP4_ADDR_ANY to
 * bind to all local interfaces.
 *
 * @return lwIP error code.
 * - ERR_OK. Successful. No error occurred.
 * - ERR_USE. The specified IP address is already bound to by
 * another RAW PCB.
 *
 * @see raw_disconnect()
 */
LwipError
raw_bind(struct raw_pcb *pcb, const IpAddr *ipaddr)
{
  LWIP_ASSERT_CORE_LOCKED();
  if ((pcb == nullptr) || (ipaddr == nullptr)) {
    return ERR_VAL;
  }
  ip_addr_set_ipaddr(&pcb->local_ip, ipaddr);

  /* If the given IP address should have a zone but doesn't, assign one now.
   * This is legacy support: scope-aware callers should always provide properly
   * zoned source addresses. */
  if (IpIsV6(&pcb->local_ip) &&
      ip6_addr_lacks_zone(ip_2_ip6(&pcb->local_ip), IP6_UNKNOWN)) {
    ip6_addr_select_zone(ip_2_ip6(&pcb->local_ip), IpAddrToIp6Addr(&pcb->local_ip));
  }
  return ERR_OK;
}

/**
 * @ingroup raw_raw
 * Bind an RAW PCB to a specific netif.
 * After calling this function, all packets received via this PCB
 * are guaranteed to have come in via the specified netif, and all
 * outgoing packets will go out via the specified netif.
 *
 * @param pcb RAW PCB to be bound with netif.
 * @param netif netif to bind to. Can be NULL.
 *
 * @see raw_disconnect()
 */
void
raw_bind_netif(struct raw_pcb *pcb, const NetIfc*netif)
{
  LWIP_ASSERT_CORE_LOCKED();
  if (netif != nullptr) {
    pcb->netif_idx = netif_get_index(netif);
  } else {
    pcb->netif_idx = NETIF_NO_INDEX;
  }
}

/**
 * @ingroup raw_raw
 * Connect an RAW PCB. This function is required by upper layers
 * of lwip. Using the raw api you could use raw_sendto() instead
 *
 * This will associate the RAW PCB with the remote address.
 *
 * @param pcb RAW PCB to be connected with remote address ipaddr and port.
 * @param ipaddr remote IP address to connect with.
 *
 * @return lwIP error code
 *
 * @see raw_disconnect() and raw_sendto()
 */
LwipError
raw_connect(struct raw_pcb *pcb, const IpAddr *ipaddr)
{
  LWIP_ASSERT_CORE_LOCKED();
  if ((pcb == nullptr) || (ipaddr == nullptr)) {
    return ERR_VAL;
  }
  ip_addr_set_ipaddr(&pcb->remote_ip, ipaddr);

  /* If the given IP address should have a zone but doesn't, assign one now,
   * using the bound address to make a more informed decision when possible. */
  if (IpIsV6(&pcb->remote_ip) &&
      ip6_addr_lacks_zone(ip_2_ip6(&pcb->remote_ip), IP6_UNKNOWN)) {
    ip6_addr_select_zone(ip_2_ip6(&pcb->remote_ip), IpAddrToIp6Addr(&pcb->local_ip));
  }
  raw_set_flags(pcb, RAW_FLAGS_CONNECTED);
  return ERR_OK;
}

/**
 * @ingroup raw_raw
 * Disconnect a RAW PCB.
 *
 * @param pcb the raw pcb to disconnect.
 */
void
raw_disconnect(struct raw_pcb *pcb)
{
  LWIP_ASSERT_CORE_LOCKED();
  /* reset remote address association */
  if (IP_IS_ANY_TYPE_VAL(pcb->local_ip)) {
    ip_addr_copy(pcb->remote_ip, *IP_ANY_TYPE);
  } else {
    ip_addr_set_any(IP_IS_V6_VAL(pcb->remote_ip), &pcb->remote_ip);

  }
  pcb->netif_idx = NETIF_NO_INDEX;
  /* mark PCB as unconnected */
  raw_clear_flags(pcb, RAW_FLAGS_CONNECTED);
}

/**
 * @ingroup raw_raw
 * Set the callback function for received packets that match the
 * raw PCB's protocol and binding.
 *
 * The callback function MUST either
 * - eat the packet by calling pbuf_free() and returning non-zero. The
 *   packet will not be passed to other raw PCBs or other protocol layers.
 * - not free the packet, and return zero. The packet will be matched
 *   against further PCBs and/or forwarded to another protocol layers.
 */
void
raw_recv(struct raw_pcb *pcb, raw_recv_fn recv, void *recv_arg)
{
  LWIP_ASSERT_CORE_LOCKED();
  /* remember recv() callback and user data */
  pcb->recv = recv;
  pcb->recv_arg = recv_arg;
}

/**
 * @ingroup raw_raw
 * Send the raw IP packet to the given address. An IP header will be prepended
 * to the packet, unless the RAW_FLAGS_HDRINCL flag is set on the PCB. In that
 * case, the packet must include an IP header, which will then be sent as is.
 *
 * @param pcb the raw pcb which to send
 * @param p the IP payload to send
 * @param ipaddr the destination address of the IP packet
 *
 */
LwipError
raw_sendto(struct raw_pcb *pcb, struct PacketBuffer *p, const IpAddr *ipaddr)
{
  NetIfc*netif;
  const IpAddr *src_ip;

  if ((pcb == nullptr) || (ipaddr == nullptr) || !IpAddrPcbVersionMatch(pcb, ipaddr)) {
    return ERR_VAL;
  }

  Logf(RAW_DEBUG | LWIP_DBG_TRACE, ("raw_sendto\n"));

  if (pcb->netif_idx != NETIF_NO_INDEX) {
    netif = netif_get_by_index(pcb->netif_idx);
  } else {
#if LWIP_MULTICAST_TX_OPTIONS
    netif = NULL;
    if (ip_addr_ismulticast(ipaddr)) {
      /* For multicast-destined packets, use the user-provided interface index to
       * determine the outgoing interface, if an interface index is set and a
       * matching netif can be found. Otherwise, fall back to regular routing. */
      netif = netif_get_by_index(pcb->mcast_ifindex);
    }

    if (netif == NULL)
#endif /* LWIP_MULTICAST_TX_OPTIONS */
    {
      netif = ip_route(&pcb->local_ip, ipaddr);
    }
  }

  if (netif == nullptr) {
    Logf(RAW_DEBUG | LWIP_DBG_LEVEL_WARNING, ("raw_sendto: No route to "));
    ip_addr_debug_print(RAW_DEBUG | LWIP_DBG_LEVEL_WARNING, ipaddr);
    return ERR_RTE;
  }

  if (ip_addr_isany(&pcb->local_ip) || ip_addr_ismulticast(&pcb->local_ip)) {
    /* use outgoing network interface IP address as source address */
    src_ip = ip_netif_get_local_ip(netif, ipaddr);
#if LWIP_IPV6
    if (src_ip == NULL) {
      return ERR_RTE;
    }
#endif /* LWIP_IPV6 */
  } else {
    /* use RAW PCB local IP address as source address */
    src_ip = &pcb->local_ip;
  }

  return raw_sendto_if_src(pcb, p, ipaddr, netif, src_ip);
}

/**
 * @ingroup raw_raw
 * Send the raw IP packet to the given address, using a particular outgoing
 * netif and source IP address. An IP header will be prepended to the packet,
 * unless the RAW_FLAGS_HDRINCL flag is set on the PCB. In that case, the
 * packet must include an IP header, which will then be sent as is.
 *
 * @param pcb RAW PCB used to send the data
 * @param p chain of pbufs to be sent
 * @param dst_ip destination IP address
 * @param netif the netif used for sending
 * @param src_ip source IP address
 */
LwipError
raw_sendto_if_src(struct raw_pcb *pcb, struct PacketBuffer *p, const IpAddr *dst_ip,
                  NetIfc*netif, const IpAddr *src_ip)
{
  LwipError err;
  struct PacketBuffer *q; /* q will be sent down the stack */
  uint16_t header_size;
  uint8_t ttl;

  LWIP_ASSERT_CORE_LOCKED();

  if ((pcb == nullptr) || (dst_ip == nullptr) || (netif == nullptr) || (src_ip == nullptr) ||
      !IpAddrPcbVersionMatch(pcb, src_ip) || !IpAddrPcbVersionMatch(pcb, dst_ip)) {
    return ERR_VAL;
  }

  header_size = (
#if LWIP_IPV4 && LWIP_IPV6
                  IpIsV6(dst_ip) ? IP6_HLEN : IP_HLEN);
#elif LWIP_IPV4
                  IP_HLEN);
#else
                  IP6_HLEN);
#endif

  /* Handle the HDRINCL option as an exception: none of the code below applies
   * to this case, and sending the packet needs to be done differently too. */
  if (pcb->flags & RAW_FLAGS_HDRINCL) {
    /* A full header *must* be present in the first PacketBuffer of the chain, as the
     * output routines may access its fields directly. */
    if (p->len < header_size) {
      return ERR_VAL;
    }
    /* @todo multicast loop support, if at all desired for this scenario.. */
    NETIF_SET_HINTS(netif, &pcb->netif_hints);
    err = ip_output_if_hdrincl(p, src_ip, dst_ip, netif);
    NETIF_RESET_HINTS(netif);
    return err;
  }

  /* packet too large to add an IP header without causing an overflow? */
  if ((uint16_t)(p->tot_len + header_size) < p->tot_len) {
    return ERR_MEM;
  }
  /* not enough space to add an IP header to first PacketBuffer in given p chain? */
  if (pbuf_add_header(p, header_size)) {
    /* allocate header in new PacketBuffer */
    q = pbuf_alloc(PBUF_IP, 0, PBUF_RAM);
    /* new header PacketBuffer could not be allocated? */
    if (q == nullptr) {
      Logf(RAW_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS, ("raw_sendto: could not allocate header\n"));
      return ERR_MEM;
    }
    if (p->tot_len != 0) {
      /* chain header q in front of given PacketBuffer p */
      pbuf_chain(q, p);
    }
    /* { first PacketBuffer q points to header PacketBuffer } */
    Logf(RAW_DEBUG, ("raw_sendto: added header PacketBuffer %p before given PacketBuffer %p\n", (void *)q, (void *)p));
  } else {
    /* first PacketBuffer q equals given PacketBuffer */
    q = p;
    if (pbuf_remove_header(q, header_size)) {
      LWIP_ASSERT("Can't restore header we just removed!", 0);
      return ERR_MEM;
    }
  }

#if IP_SOF_BROADCAST
  if (IP_IS_V4(dst_ip)) {
    /* broadcast filter? */
    if (!ip_get_option(pcb, SOF_BROADCAST) && ip_addr_isbroadcast(dst_ip, netif)) {
      Logf(RAW_DEBUG | LWIP_DBG_LEVEL_WARNING, ("raw_sendto: SOF_BROADCAST not enabled on pcb %p\n", (void *)pcb));
      /* free any temporary header PacketBuffer allocated by pbuf_header() */
      if (q != p) {
        pbuf_free(q);
      }
      return ERR_VAL;
    }
  }
#endif /* IP_SOF_BROADCAST */

  /* Multicast Loop? */
#if LWIP_MULTICAST_TX_OPTIONS
  if (((pcb->flags & RAW_FLAGS_MULTICAST_LOOP) != 0) && ip_addr_ismulticast(dst_ip)) {
    q->flags |= PBUF_FLAG_MCASTLOOP;
  }
#endif /* LWIP_MULTICAST_TX_OPTIONS */

#if LWIP_IPV6
  /* If requested, based on the IPV6_CHECKSUM socket option per RFC3542,
     compute the checksum and update the checksum in the payload. */
  if (IpIsV6(dst_ip) && pcb->chksum_reqd) {
    uint16_t chksum = ip6_chksum_pseudo(p, pcb->protocol, p->tot_len, ip_2_ip6(src_ip), ip_2_ip6(dst_ip));
    LWIP_ASSERT("Checksum must fit into first PacketBuffer", p->len >= (pcb->chksum_offset + 2));
    SMEMCPY(((uint8_t *)p->payload) + pcb->chksum_offset, &chksum, sizeof(uint16_t));
  }
#endif

  /* Determine TTL to use */
#if LWIP_MULTICAST_TX_OPTIONS
  ttl = (ip_addr_ismulticast(dst_ip) ? raw_get_multicast_ttl(pcb) : pcb->ttl);
#else /* LWIP_MULTICAST_TX_OPTIONS */
  ttl = pcb->ttl;
#endif /* LWIP_MULTICAST_TX_OPTIONS */

  NETIF_SET_HINTS(netif, &pcb->netif_hints);
  err = ip_output_if(q, src_ip, dst_ip, ttl, pcb->tos, pcb->protocol, netif);
  NETIF_RESET_HINTS(netif);

  /* did we chain a header earlier? */
  if (q != p) {
    /* free the header */
    pbuf_free(q);
  }
  return err;
}

/**
 * @ingroup raw_raw
 * Send the raw IP packet to the address given by raw_connect()
 *
 * @param pcb the raw pcb which to send
 * @param p the IP payload to send
 *
 */
LwipError
raw_send(struct raw_pcb *pcb, struct PacketBuffer *p)
{
  return raw_sendto(pcb, p, &pcb->remote_ip);
}

/**
 * @ingroup raw_raw
 * Remove an RAW PCB.
 *
 * @param pcb RAW PCB to be removed. The PCB is removed from the list of
 * RAW PCB's and the data structure is freed from memory.
 *
 * @see raw_new()
 */
void
raw_remove(struct raw_pcb *pcb)
{
  struct raw_pcb *pcb2;
  LWIP_ASSERT_CORE_LOCKED();
  /* pcb to be removed is first in list? */
  if (raw_pcbs == pcb) {
    /* make list start at 2nd pcb */
    raw_pcbs = raw_pcbs->next;
    /* pcb not 1st in list */
  } else {
    for (pcb2 = raw_pcbs; pcb2 != nullptr; pcb2 = pcb2->next) {
      /* find pcb in raw_pcbs list */
      if (pcb2->next != nullptr && pcb2->next == pcb) {
        /* remove pcb from list */
        pcb2->next = pcb->next;
        break;
      }
    }
  }
  memp_free(MEMP_RAW_PCB, pcb);
}

/**
 * @ingroup raw_raw
 * Create a RAW PCB.
 *
 * @return The RAW PCB which was created. NULL if the PCB data structure
 * could not be allocated.
 *
 * @param proto the protocol number of the IPs payload (e.g. IP_PROTO_ICMP)
 *
 * @see raw_remove()
 */
struct raw_pcb *
raw_new(uint8_t proto)
{
  struct raw_pcb *pcb;

  Logf(RAW_DEBUG | LWIP_DBG_TRACE, ("raw_new\n"));
  LWIP_ASSERT_CORE_LOCKED();

  pcb = (struct raw_pcb *)memp_malloc(MEMP_RAW_PCB);
  /* could allocate RAW PCB? */
  if (pcb != nullptr) {
    /* initialize PCB to all zeroes */
    memset(pcb, 0, sizeof(struct raw_pcb));
    pcb->protocol = proto;
    pcb->ttl = RAW_TTL;
#if LWIP_MULTICAST_TX_OPTIONS
    raw_set_multicast_ttl(pcb, RAW_TTL);
#endif /* LWIP_MULTICAST_TX_OPTIONS */
    pcb->next = raw_pcbs;
    raw_pcbs = pcb;
  }
  return pcb;
}

/**
 * @ingroup raw_raw
 * Create a RAW PCB for specific IP type.
 *
 * @return The RAW PCB which was created. NULL if the PCB data structure
 * could not be allocated.
 *
 * @param type IP address type, see @ref lwip_ip_addr_type definitions.
 * If you want to listen to IPv4 and IPv6 (dual-stack) packets,
 * supply @ref IPADDR_TYPE_ANY as argument and bind to @ref IP_ANY_TYPE.
 * @param proto the protocol number (next header) of the IPv6 packet payload
 *              (e.g. IP6_NEXTH_ICMP6)
 *
 * @see raw_remove()
 */
struct raw_pcb *
raw_new_ip_type(uint8_t type, uint8_t proto)
{
  struct raw_pcb *pcb;
  LWIP_ASSERT_CORE_LOCKED();
  pcb = raw_new(proto);

  if (pcb != nullptr) {
    IpAdderSetTypeVal(pcb->local_ip,  type);
    IpAdderSetTypeVal(pcb->remote_ip, type);
  }
  return pcb;
}

/** This function is called from netif.c when address is changed
 *
 * @param old_addr IP address of the netif before change
 * @param new_addr IP address of the netif after change
 */
void raw_netif_ip_addr_changed(const IpAddr *old_addr, const IpAddr *new_addr)
{
  struct raw_pcb *rpcb;

  if (!ip_addr_isany(old_addr) && !ip_addr_isany(new_addr)) {
    for (rpcb = raw_pcbs; rpcb != nullptr; rpcb = rpcb->next) {
      /* PCB bound to current local interface address? */
      if (ip_addr_cmp(&rpcb->local_ip, old_addr)) {
        /* The PCB is bound to the old ipaddr and
         * is set to bound to the new one instead */
        ip_addr_copy(rpcb->local_ip, *new_addr);
      }
    }
  }
}