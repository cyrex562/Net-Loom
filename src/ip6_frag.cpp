/**
 * @file
 *
 * IPv6 fragmentation and reassembly.
 */

/*
 * Copyright (c) 2010 Inico Technologies Ltd.
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

#include <opt.h>
#include <ip6_frag.h>
#include <ip6.h>
#include <icmp6.h>
#include <nd6.h>
#include <packet_buffer.h>
#include "ip4_frag.h"
/* The number of bytes we need to "borrow" from (i.e., overwrite in) the header
 * that precedes the fragment header for reassembly pruposes. */
#define IPV6_FRAG_REQROOM ((int16_t)(sizeof(struct ip6_reass_helper) - IP6_FRAG_OFFSET_MASK))


#define IP_REASS_FLAG_LASTFRAG 0x01

/** This is a helper struct which holds the starting
 * offset and the ending offset of this fragment to
 * easily chain the fragments.
 * It has the same packing requirements as the IPv6 header, since it replaces
 * the Fragment Header in memory in incoming fragments to keep
 * track of the various fragments.
*/

struct ip6_reass_helper {
  struct PacketBuffer *next_pbuf;
  uint16_t start;
  uint16_t end;
} ;


/* static variables */
static struct Ip6ReassemblyData *reassdatagrams;
static uint16_t ip6_reass_pbufcount;

/* Forward declarations. */
static void ip6_reass_free_complete_datagram(struct Ip6ReassemblyData *ipr);

static void ip6_reass_remove_oldest_datagram(struct Ip6ReassemblyData *ipr, int pbufs_needed);

void
ip6_reass_tmr(void)
{
    struct Ip6ReassemblyData* r = reassdatagrams;
  while (r != nullptr) {
    /* Decrement the timer. Once it reaches 0,
     * clean up the incomplete fragment assembly */
    if (r->timer > 0) {
      r->timer--;
      r = r->next;
    } else {
      /* reassembly timed out */
      struct Ip6ReassemblyData* tmp = r;
      /* get the next pointer before freeing */
      r = r->next;
      /* free the helper struct and all enqueued pbufs */
      ip6_reass_free_complete_datagram(tmp);
     }
   }
}

/**
 * Free a datagram (struct ip6_reassdata) and all its pbufs.
 * Updates the total count of enqueued pbufs (ip6_reass_pbufcount),
 * sends an ICMP time exceeded packet.
 *
 * @param ipr datagram to free
 */
static void
ip6_reass_free_complete_datagram(struct Ip6ReassemblyData *ipr)
{
    uint16_t pbufs_freed = 0;
  uint16_t clen;
  struct PacketBuffer *p;
    struct ip6_reass_helper* iprh = (struct ip6_reass_helper *)ipr->p->payload;
  if (iprh->start == 0) {
    /* The first fragment was received, send ICMP time exceeded. */
    /* First, de-queue the first PacketBuffer from r->p. */
    p = ipr->p;
    ipr->p = iprh->next_pbuf;
    /* Restore the part that we've overwritten with our helper structure, or we
     * might send garbage (and disclose a pointer) in the ICMPv6 reply. */
    memcpy(p->payload, ipr->orig_hdr, sizeof(iprh));
    /* Then, move back to the original ipv6 header (we are now pointing to Fragment header).
       This cannot fail since we already checked when receiving this fragment. */
    if (pbuf_header_force(p, (int16_t)((uint8_t*)p->payload - (uint8_t*)ipr->iphdr))) {
      lwip_assert("ip6_reass_free: moving p->payload to ip6 header failed\n", false);
    }
    else {
        Ip6Addr src_addr{};
        Ip6Addr dest_addr{};
        ip6_addr_copy_from_packed(&src_addr, &((ipr)->src));
      ip6_addr_set_zone(&src_addr, ipr->src_zone);
      ip6_addr_copy_from_packed(&dest_addr, &((ipr)->dest));
      ip6_addr_set_zone(&dest_addr, ipr->dest_zone);
      /* Send the actual ICMP response. */
      icmp6_time_exceeded_with_addrs(p, ICMP6_TE_FRAG, &src_addr, &dest_addr);
    }
    clen = pbuf_clen(p);
    lwip_assert("pbufs_freed + clen <= 0xffff", pbufs_freed + clen <= 0xffff);
    pbufs_freed = (uint16_t)(pbufs_freed + clen);
    free_pkt_buf(p);
  }


  /* First, free all received pbufs.  The individual pbufs need to be released
     separately as they have not yet been chained */
  p = ipr->p;
  while (p != nullptr) {
      iprh = (struct ip6_reass_helper *)p->payload;
    struct PacketBuffer* pcur = p;
    /* get the next pointer before freeing */
    p = iprh->next_pbuf;
    clen = pbuf_clen(pcur);
    lwip_assert("pbufs_freed + clen <= 0xffff", pbufs_freed + clen <= 0xffff);
    pbufs_freed = (uint16_t)(pbufs_freed + clen);
    free_pkt_buf(pcur);
  }

  /* Then, unchain the struct ip6_reassdata from the list and free it. */
  if (ipr == reassdatagrams) {
    reassdatagrams = ipr->next;
  } else {
    struct Ip6ReassemblyData* prev = reassdatagrams;
    while (prev != nullptr) {
      if (prev->next == ipr) {
        break;
      }
      prev = prev->next;
    }
    if (prev != nullptr) {
      prev->next = ipr->next;
    }
  }
  delete ipr;

  /* Finally, update number of pbufs in reassembly queue */
  lwip_assert("ip_reass_pbufcount >= clen", ip6_reass_pbufcount >= pbufs_freed);
  ip6_reass_pbufcount = (uint16_t)(ip6_reass_pbufcount - pbufs_freed);
}

/**
 * Free the oldest datagram to make room for enqueueing new fragments.
 * The datagram ipr is not freed!
 *
 * @param ipr ip6_reassdata for the current fragment
 * @param pbufs_needed number of pbufs needed to enqueue
 *        (used for freeing other datagrams if not enough space)
 */
static void
ip6_reass_remove_oldest_datagram(struct Ip6ReassemblyData *ipr, int pbufs_needed)
{
  struct Ip6ReassemblyData*oldest;

  /* Free datagrams until being allowed to enqueue 'pbufs_needed' pbufs,
   * but don't free the current datagram! */
  do {
    struct Ip6ReassemblyData* r = oldest = reassdatagrams;
    while (r != nullptr) {
      if (r != ipr) {
        if (r->timer <= oldest->timer) {
          /* older than the previous oldest */
          oldest = r;
        }
      }
      r = r->next;
    }
    if (oldest == ipr) {
      /* nothing to free, ipr is the only element on the list */
      return;
    }
    if (oldest != nullptr) {
      ip6_reass_free_complete_datagram(oldest);
    }
  } while (((ip6_reass_pbufcount + pbufs_needed) > IP_REASS_MAX_PBUFS) && (reassdatagrams != nullptr));
}

/**
 * Reassembles incoming IPv6 fragments into an IPv6 datagram.
 *
 * @param p points to the IPv6 Fragment Header
 * @return NULL if reassembly is incomplete, PacketBuffer pointing to
 *         IPv6 Header if reassembly is complete
 */
struct PacketBuffer *
ip6_reass(struct PacketBuffer *p)
{
  struct Ip6ReassemblyData *ipr, *ipr_prev;
  struct ip6_reass_helper *iprh_tmp, *iprh_prev= nullptr;
  uint8_t valid = 1;
  struct PacketBuffer *q;
    Ip6Hdr* curr_ip6_hdr = nullptr;
    Ip6Addr* curr_src_addr = nullptr;
    Ip6Addr* curr_dst_addr = nullptr;


  /* ip6_frag_hdr must be in the first PacketBuffer, not chained. Checked by caller. */
  lwip_assert("IPv6 fragment header does not fit in first PacketBuffer",
    p->len >= sizeof(Ip6FragHdr));

  Ip6FragHdr* frag_hdr = (Ip6FragHdr *)p->payload;

  uint16_t clen = pbuf_clen(p);

  uint16_t offset = lwip_ntohs(frag_hdr->_fragment_offset);

  /* Calculate fragment length from IPv6 payload length.
   * Adjust for headers before Fragment Header.
   * And finally adjust by Fragment Header length. */
  uint16_t len = lwip_ntohs(curr_ip6_hdr->_plen);
  ptrdiff_t hdrdiff = (uint8_t*)p->payload - (const uint8_t*)curr_ip6_hdr;
  lwip_assert("not a valid PacketBuffer (ip6_input check missing?)", hdrdiff <= 0xFFFF);
  lwip_assert("not a valid PacketBuffer (ip6_input check missing?)", hdrdiff >= IP6_HDR_LEN);
  hdrdiff -= IP6_HDR_LEN;
  hdrdiff += IP6_FRAG_OFFSET_MASK;
  if (hdrdiff > len) {

    goto nullreturn;
  }
  len = (uint16_t)(len - hdrdiff);
  uint16_t start = (offset & IP6_FRAG_OFFSET_MASK);
  if (start > (0xFFFF - len)) {
    /* uint16_t overflow, cannot handle this */

    goto nullreturn;
  }

  /* Look for the datagram the fragment belongs to in the current datagram queue,
   * remembering the previous in the queue for later dequeueing. */
  for (ipr = reassdatagrams, ipr_prev = nullptr; ipr != nullptr; ipr = ipr->next) {
    /* Check if the incoming fragment matches the one currently present
       in the reassembly buffer. If so, we proceed with copying the
       fragment into the buffer. */
    if ((frag_hdr->_identification == ipr->identification) &&
        ip6_addr_cmp_packed(curr_src_addr, &(IPV6_FRAG_SRC(ipr)), ipr->src_zone) &&
        ip6_addr_cmp_packed(curr_dst_addr, &(IPV6_FRAG_DEST(ipr)), ipr->dest_zone)) {
      break;
    }
    ipr_prev = ipr;
  }

  if (ipr == nullptr) {
  /* Enqueue a new datagram into the datagram queue */
    // ipr = (struct ip6_reassdata *)memp_malloc(MEMP_IP6_REASSDATA);
      ipr = new Ip6ReassemblyData;
    if (ipr == nullptr) {

      /* Make room and try again. */
      ip6_reass_remove_oldest_datagram(ipr, clen);
      ipr = new Ip6ReassemblyData;
      if (ipr != nullptr) {
        /* re-search ipr_prev since it might have been removed */
        for (ipr_prev = reassdatagrams; ipr_prev != nullptr; ipr_prev = ipr_prev->next) {
          if (ipr_prev->next == ipr) {
            break;
          }
        }
      } else

      {
        goto nullreturn;
      }
    }

    memset(ipr, 0, sizeof(struct Ip6ReassemblyData));
    ipr->timer = 0xff;

    /* enqueue the new structure to the front of the list */
    ipr->next = reassdatagrams;
    reassdatagrams = ipr;

    /* Use the current IPv6 header for src/dest address reference.
     * Eventually, we will replace it when we get the first fragment
     * (it might be this one, in any case, it is done later). */
    /* need to use the none-const pointer here: */
    ipr->iphdr =curr_ip6_hdr;

    memcpy(&ipr->src, &curr_ip6_hdr->src, sizeof(ipr->src));
    memcpy(&ipr->dest, &curr_ip6_hdr->dest, sizeof(ipr->dest));


    /* Also store the address zone information.
     * @todo It is possible that due to netif destruction and recreation, the
     * stored zones end up resolving to a different interface. In that case, we
     * risk sending a "time exceeded" ICMP response over the wrong link.
     * Ideally, netif destruction would clean up matching pending reassembly
     * structures, but custom zone mappings would make that non-trivial. */
    ipr->src_zone = curr_src_addr->zone;
    ipr->dest_zone = curr_dst_addr->zone;

    /* copy the fragmented packet id. */
    ipr->identification = frag_hdr->_identification;

    /* copy the nexth field */
    ipr->nexth = frag_hdr->_nexth;
  }

  /* Check if we are allowed to enqueue more datagrams. */
  if ((ip6_reass_pbufcount + clen) > IP_REASS_MAX_PBUFS) {

    ip6_reass_remove_oldest_datagram(ipr, clen);
    if ((ip6_reass_pbufcount + clen) <= IP_REASS_MAX_PBUFS) {
      /* re-search ipr_prev since it might have been removed */
      for (ipr_prev = reassdatagrams; ipr_prev != nullptr; ipr_prev = ipr_prev->next) {
        if (ipr_prev->next == ipr) {
          break;
        }
      }
    } else

    {
      /* @todo: send ICMPv6 time exceeded here? */
      /* drop this PacketBuffer */
      goto nullreturn;
    }
  }

  /* Overwrite Fragment Header with our own helper struct. */

  if (IPV6_FRAG_REQROOM > 0) {
    /* Make room for struct ip6_reass_helper (only required if sizeof(void*) > 4).
       This cannot fail since we already checked when receiving this fragment. */
    uint8_t hdrerr = pbuf_header_force(p, IPV6_FRAG_REQROOM);
    lwip_assert("no room for struct ip6_reass_helper", hdrerr == 0);
  }

  /* Prepare the pointer to the helper structure, and its initial values.
   * Do not yet write to the structure itself, as we still have to make a
   * backup of the original data, and we should not do that until we know for
   * sure that we are going to add this packet to the list. */
  struct ip6_reass_helper* iprh = (struct ip6_reass_helper *)p->payload;
  struct PacketBuffer* next_pbuf = nullptr;
  uint16_t end = (uint16_t)(start + len);

  /* find the right place to insert this PacketBuffer */
  /* Iterate through until we either get to the end of the list (append),
   * or we find on with a larger offset (insert). */
  for (q = ipr->p; q != nullptr;) {
    iprh_tmp = (struct ip6_reass_helper*)q->payload;
    if (start < iprh_tmp->start) {

      if (end > iprh_tmp->start) {
        /* fragment overlaps with following, throw away */
        goto nullreturn;
      }
      if (iprh_prev != nullptr) {
        if (start < iprh_prev->end) {
          /* fragment overlaps with previous, throw away */
          goto nullreturn;
        }
      }

      /* the new PacketBuffer should be inserted before this */
      next_pbuf = q;
      if (iprh_prev != nullptr) {
        /* not the fragment with the lowest offset */
        iprh_prev->next_pbuf = p;
      } else {
        /* fragment with the lowest offset */
        ipr->p = p;
      }
      break;
    } else if (start == iprh_tmp->start) {
      /* received the same datagram twice: no need to keep the datagram */
      goto nullreturn;

    } else if (start < iprh_tmp->end) {
      /* overlap: no need to keep the new datagram */
      goto nullreturn;

    } else {
      /* Check if the fragments received so far have no gaps. */
      if (iprh_prev != nullptr) {
        if (iprh_prev->end != iprh_tmp->start) {
          /* There is a fragment missing between the current
           * and the previous fragment */
          valid = 0;
        }
      }
    }
    q = iprh_tmp->next_pbuf;
    iprh_prev = iprh_tmp;
  }

  /* If q is NULL, then we made it to the end of the list. Determine what to do now */
  if (q == nullptr) {
    if (iprh_prev != nullptr) {
      /* this is (for now), the fragment with the highest offset:
       * chain it to the last fragment */

      lwip_assert("check fragments don't overlap", iprh_prev->end <= start);

      iprh_prev->next_pbuf = p;
      if (iprh_prev->end != start) {
        valid = 0;
      }
    } else {

      lwip_assert("no previous fragment, this must be the first fragment!",
        ipr->p == nullptr);

      /* this is the first fragment we ever received for this ip datagram */
      ipr->p = p;
    }
  }

  /* Track the current number of pbufs current 'in-flight', in order to limit
  the number of fragments that may be enqueued at any one time */
  ip6_reass_pbufcount = (uint16_t)(ip6_reass_pbufcount + clen);

  /* Remember IPv6 header if this is the first fragment. */
  if (start == 0) {
    /* need to use the none-const pointer here: */
    ipr->iphdr = curr_ip6_hdr;
    /* Make a backup of the part of the packet data that we are about to
     * overwrite, so that we can restore the original later. */
    memcpy(ipr->orig_hdr, p->payload, sizeof(*iprh));
    /* For IPV6_FRAG_COPYHEADER there is no need to copy src/dst again, as they
     * will be the same as they were. With LWIP_IPV6_SCOPES, the same applies
     * to the source/destination zones. */
  }
  /* Only after the backup do we get to fill in the actual helper structure. */
  iprh->next_pbuf = next_pbuf;
  iprh->start = start;
  iprh->end = end;

  /* If this is the last fragment, calculate total packet length. */
  if ((offset & IP6_FRAG_MORE_FLAG) == 0) {
    ipr->datagram_len = iprh->end;
  }

  /* Additional validity tests: we have received first and last fragment. */
  iprh_tmp = (struct ip6_reass_helper*)ipr->p->payload;
  if (iprh_tmp->start != 0) {
    valid = 0;
  }
  if (ipr->datagram_len == 0) {
    valid = 0;
  }

  /* Final validity test: no gaps between current and last fragment. */
  iprh_prev = iprh;
  q = iprh->next_pbuf;
  while ((q != nullptr) && valid) {
    iprh = (struct ip6_reass_helper*)q->payload;
    if (iprh_prev->end != iprh->start) {
      valid = 0;
      break;
    }
    iprh_prev = iprh;
    q = iprh->next_pbuf;
  }

  if (valid) {
      /* chain together the pbufs contained within the ip6_reassdata list. */
    iprh = (struct ip6_reass_helper*) ipr->p->payload;
    while (iprh != nullptr) {
      next_pbuf = iprh->next_pbuf;
      if (next_pbuf != nullptr) {
        /* Save next helper struct (will be hidden in next step). */
        iprh_tmp = (struct ip6_reass_helper*)next_pbuf->payload;

        /* hide the fragment header for every succeeding fragment */
        pbuf_remove_header(next_pbuf, IP6_FRAG_OFFSET_MASK);

        if (IPV6_FRAG_REQROOM > 0) {
          /* hide the extra bytes borrowed from ip6_hdr for struct ip6_reass_helper */
          uint8_t hdrerr = pbuf_remove_header(next_pbuf, IPV6_FRAG_REQROOM);
          lwip_assert("no room for struct ip6_reass_helper", hdrerr == 0);
        }

        pbuf_cat(ipr->p, next_pbuf);
      }
      else {
        iprh_tmp = nullptr;
      }

      iprh = iprh_tmp;
    }

    /* Get the first PacketBuffer. */
    p = ipr->p;


    if (IPV6_FRAG_REQROOM > 0) {
        /* Restore (only) the bytes that we overwrote beyond the fragment header.
       * Those bytes may belong to either the IPv6 header or an extension
       * header placed before the fragment header. */
      memcpy(p->payload, ipr->orig_hdr, IPV6_FRAG_REQROOM);
      /* get back room for struct ip6_reass_helper (only required if sizeof(void*) > 4) */
      uint8_t hdrerr = pbuf_remove_header(p, IPV6_FRAG_REQROOM);
        lwip_assert("no room for struct ip6_reass_helper", hdrerr == 0);
    }


    /* We need to get rid of the fragment header itself, which is somewhere in
     * the middle of the packet (but still in the first PacketBuffer of the chain).
     * Getting rid of the header is required by RFC 2460 Sec. 4.5 and necessary
     * in order to be able to reassemble packets that are close to full size
     * (i.e., around 65535 bytes). We simply move up all the headers before the
     * fragment header, including the IPv6 header, and adjust the payload start
     * accordingly. This works because all these headers are in the first PacketBuffer
     * of the chain, and because the caller adjusts all its pointers on
     * successful reassembly. */
    memmove((uint8_t*)ipr->iphdr + sizeof(Ip6FragHdr),ipr->iphdr,(size_t)((uint8_t*)p->payload - (uint8_t*)ipr->iphdr));

    /* This is where the IPv6 header is now. */
    struct Ip6Hdr* iphdr_ptr = (struct Ip6Hdr*)((uint8_t*)ipr->iphdr + sizeof(Ip6FragHdr)
    );

    /* Adjust datagram length by adding header lengths. */
    ipr->datagram_len = (uint16_t)(ipr->datagram_len + ((uint8_t*)p->payload - (uint8_t*)iphdr_ptr)
                         - IP6_HDR_LEN);

    /* Set payload length in ip header. */
    iphdr_ptr->_plen = lwip_htons(ipr->datagram_len);

    /* With the fragment header gone, we now need to adjust the next-header
     * field of whatever header was originally before it. Since the packet made
     * it through the original header processing routines at least up to the
     * fragment header, we do not need any further sanity checks here. */
    if (IP6H_NEXTH(iphdr_ptr) == IP6_NEXTH_FRAGMENT) {
      iphdr_ptr->_nexth = ipr->nexth;
    } else {
      uint8_t *ptr = (uint8_t *)iphdr_ptr + IP6_HDR_LEN;
      while (*ptr != IP6_NEXTH_FRAGMENT) {
        ptr += 8 * (1 + ptr[1]);
      }
      *ptr = ipr->nexth;
    }

    /* release the resources allocated for the fragment queue entry */
    if (reassdatagrams == ipr) {
      /* it was the first in the list */
      reassdatagrams = ipr->next;
    } else {
      /* it wasn't the first, so it must have a valid 'prev' */
      lwip_assert("sanity check linked list", ipr_prev != nullptr);
      ipr_prev->next = ipr->next;
    }
    delete ipr;

    /* adjust the number of pbufs currently queued for reassembly. */
    clen = pbuf_clen(p);
    lwip_assert("ip6_reass_pbufcount >= clen", ip6_reass_pbufcount >= clen);
    ip6_reass_pbufcount = (uint16_t)(ip6_reass_pbufcount - clen);

    /* Move PacketBuffer back to IPv6 header. This should never fail. */
    if (pbuf_header_force(p, (int16_t)((uint8_t*)p->payload - (uint8_t*)iphdr_ptr))) {
      lwip_assert("ip6_reass: moving p->payload to ip6 header failed\n", false);
      free_pkt_buf(p);
      return nullptr;
    }

    /* Return the PacketBuffer chain */
    return p;
  }
  /* the datagram is not (yet?) reassembled completely */
  return nullptr;

nullreturn:
  free_pkt_buf(p);
  return nullptr;
}

/** Allocate a new struct pbuf_custom_ref */
static struct PbufCustomRef*
ip6_frag_alloc_pbuf_custom_ref(void)
{
  return new PbufCustomRef;
}

/** Free a struct pbuf_custom_ref */
static void
ip6_frag_free_pbuf_custom_ref(struct PbufCustomRef* p)
{
  lwip_assert("p != NULL", p != nullptr);
  delete p;
}

/** Free-callback function to free a 'struct pbuf_custom_ref', called by
 * free_pkt_buf. */
static void
ip6_frag_free_pbuf_custom(struct PacketBuffer *p)
{
  struct PbufCustomRef *pcr = (struct PbufCustomRef*)p;
  lwip_assert("pcr != NULL", pcr != nullptr);
  lwip_assert("pcr == p", (void*)pcr == (void*)p);
  if (pcr->original != nullptr) {
    free_pkt_buf(pcr->original);
  }
  ip6_frag_free_pbuf_custom_ref(pcr);
}

/**
 * Fragment an IPv6 datagram if too large for the netif or path MTU.
 *
 * Chop the datagram in MTU sized chunks and send them in order
 * by pointing PBUF_REFs into p
 *
 * @param p ipv6 packet to send
 * @param netif the netif on which to send
 * @param dest destination ipv6 address to which to send
 *
 * @return ERR_OK if sent successfully, LwipStatus otherwise
 */
LwipStatus
ip6_frag(struct PacketBuffer *p, NetworkInterface*netif, const Ip6Addr *dest)
{
    uint16_t newpbuflen = 0;
    static uint32_t identification;
    const uint16_t mtu = nd6_get_destination_mtu(dest, netif);
  const uint16_t nfb = (uint16_t)((mtu - (IP6_HDR_LEN + IP6_FRAG_OFFSET_MASK)) & IP6_FRAG_OFFSET_MASK);
  uint16_t fragment_offset = 0;
    uint16_t poff = IP6_HDR_LEN;

  identification++;

  struct Ip6Hdr* original_ip6hdr = (struct Ip6Hdr *)p->payload;

  /* @todo we assume there are no options in the unfragmentable part (IPv6 header). */
  lwip_assert("p->tot_len >= IP6_HDR_LEN", p->tot_len >= IP6_HDR_LEN);
  uint16_t left = (uint16_t)(p->tot_len - IP6_HDR_LEN);

  while (left) {
    uint16_t last = (left <= nfb);

    /* Fill this fragment */
    uint16_t cop = last ? left : nfb;

    /* When not using a static buffer, create a chain of pbufs.
     * The first will be a PBUF_RAM holding the link, IPv6, and Fragment header.
     * The rest will be PBUF_REFs mirroring the PacketBuffer chain to be fragged,
     * but limited to the size of an mtu.
     */
    struct PacketBuffer* rambuf = pbuf_alloc(PBUF_LINK,
                                             IP6_HDR_LEN + IP6_FRAG_OFFSET_MASK);
    if (rambuf == nullptr) {
      return ERR_MEM;
    }
    lwip_assert("this needs a PacketBuffer in one piece!",
                (p->len >= (IP6_HDR_LEN)));
    memcpy(rambuf->payload, original_ip6hdr, IP6_HDR_LEN);
    struct Ip6Hdr* ip6hdr = (Ip6Hdr *)rambuf->payload;
    Ip6FragHdr* frag_hdr = (Ip6FragHdr *)((uint8_t*)rambuf->payload + IP6_HDR_LEN);

    /* Can just adjust p directly for needed offset. */
    p->payload = (uint8_t *)p->payload + poff;
    p->len = (uint16_t)(p->len - poff);
    p->tot_len = (uint16_t)(p->tot_len - poff);

    uint16_t left_to_copy = cop;
    while (left_to_copy) {
        newpbuflen = (left_to_copy < p->len) ? left_to_copy : p->len;
      /* Is this PacketBuffer already empty? */
      if (!newpbuflen) {
        p = p->next;
        continue;
      }
      struct PbufCustomRef* pcr = ip6_frag_alloc_pbuf_custom_ref();
      if (pcr == nullptr) {
        free_pkt_buf(rambuf);
        return ERR_MEM;
      }
      /* Mirror this PacketBuffer, although we might not need all of it. */
      struct PacketBuffer* newpbuf = pbuf_alloced_custom(
          PBUF_RAW,
          newpbuflen,
          PBUF_REF,
          &pcr->pc,
          p->payload,
          newpbuflen);
      if (newpbuf == nullptr) {
        ip6_frag_free_pbuf_custom_ref(pcr);
        free_pkt_buf(rambuf);
        return ERR_MEM;
      }
      pbuf_ref(p);
      pcr->original = p;
      pcr->pc.custom_free_function = ip6_frag_free_pbuf_custom;

      /* Add it to end of rambuf's chain, but using pbuf_cat, not pbuf_chain
       * so that it is removed when pbuf_dechain is later called on rambuf.
       */
      pbuf_cat(rambuf, newpbuf);
      left_to_copy = (uint16_t)(left_to_copy - newpbuflen);
      if (left_to_copy) {
        p = p->next;
      }
    }
    poff = newpbuflen;


    /* Set headers */
    frag_hdr->_nexth = original_ip6hdr->_nexth;
    frag_hdr->reserved = 0;
    frag_hdr->_fragment_offset = lwip_htons((uint16_t)((fragment_offset & IP6_FRAG_OFFSET_MASK) | (last ? 0 : IP6_FRAG_MORE_FLAG)));
    frag_hdr->_identification = lwip_htonl(identification);

    IP6H_NEXTH_SET(ip6hdr, IP6_NEXTH_FRAGMENT);
    set_ip6_hdr_plen(ip6hdr, (uint16_t)(cop + IP6_FRAG_OFFSET_MASK));

    /* No need for separate header PacketBuffer - we allowed room for it in rambuf
     * when allocated.
     */
    netif->output_ip6(netif, rambuf, dest);

    /* Unfortunately we can't reuse rambuf - the hardware may still be
     * using the buffer. Instead we free it (and the ensuing chain) and
     * recreate it next time round the loop. If we're lucky the hardware
     * will have already sent the packet, the free will really free, and
     * there will be zero memory penalty.
     */

    free_pkt_buf(rambuf);
    left = (uint16_t)(left - cop);
    fragment_offset = (uint16_t)(fragment_offset + cop);
  }
  return ERR_OK;
}

