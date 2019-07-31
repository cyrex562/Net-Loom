#include <opt.h>
#include <def.h>
#include <icmp.h>
#include <inet_chksum.h>
#include <ip4_frag.h>
#include <network_interface.h>
#include <ip4.h>
#include <lwip_debug.h>
#include <cstring>

constexpr auto kIpReassFlagLastfrag = 0x01;

enum IpReassValidate
{
    IP_REASS_VALIDATE_TELEGRAM_FINISHED = 1,
    IP_REASS_VALIDATE_PBUF_QUEUED = 0,
    IP_REASS_VALIDATE_PBUF_DROPPED = -1,
};


/** This is a helper struct which holds the starting
 * offset and the ending offset of this fragment to
 * easily chain the fragments.
 * It has the same packing requirements as the IP header, since it replaces
 * the IP header in memory in incoming fragments (after copying it) to keep
 * track of the various fragments. (-> If the IP header doesn't need packing,
 * this struct doesn't need packing, too.)
 */

struct IpReassHelper {
    struct PacketBuffer* next_pbuf;
    uint16_t start;
    uint16_t end;
};


inline bool
ip_addresses_and_id_match(Ip4Hdr& iphdr_a, Ip4Hdr& iphdr_b)
{
    return
        is_ip4_addr_equal(&(iphdr_a)->src, &(iphdr_b)->src) && is_ip4_addr_equal(&(iphdr_a)->dest, &(iphdr_b)->dest) &&
        get_ip4_hdr_id(iphdr_a) == get_ip4_hdr_id(iphdr_b);
}

/* global variables */
static struct ip_reassdata *reassdatagrams;
static uint16_t ip_reass_pbufcount;

/* function prototypes */
static void ip_reass_dequeue_datagram(struct ip_reassdata *ipr, struct ip_reassdata *prev);
static int ip_reass_free_complete_datagram(struct ip_reassdata *ipr, struct ip_reassdata *prev);

/**
 * Reassembly timer base function
 * for both NO_SYS == 0 and 1 (!).
 *
 * Should be called every 1000 msec (defined by IP_TMR_INTERVAL).
 */
void ip_reass_tmr(void)
{
    struct ip_reassdata*prev = nullptr;
    struct ip_reassdata* r = reassdatagrams;
    while (r != nullptr)
    {
        /* Decrement the timer. Once it reaches 0,
         * clean up the incomplete fragment assembly */
        if (r->timer > 0)
        {
            r->timer--;
            //      Logf(true, ("ip_reass_tmr: timer dec %d\n", (uint16_t)r->timer));
            prev = r;
            r = r->next;
        }
        else
        {
            //      Logf(true, ("ip_reass_tmr: timer timed out\n"));
            struct ip_reassdata* tmp = r; /* get the next pointer before freeing */
            r = r->next; /* free the helper struct and all enqueued pbufs */
            ip_reass_free_complete_datagram(tmp, prev);
        }
    }
}

/**
 * Free a datagram (struct ip_reassdata) and all its pbufs.
 * Updates the total count of enqueued pbufs (ip_reass_pbufcount),
 * SNMP counters and sends an ICMP time exceeded packet.
 *
 * @param ipr datagram to free
 * @param prev the previous datagram in the linked list
 * @return the number of pbufs freed
 */
static int
ip_reass_free_complete_datagram(struct ip_reassdata *ipr, struct ip_reassdata *prev)
{
  uint16_t pbufs_freed = 0;
  uint16_t clen;
  struct PacketBuffer *p;
  lwip_assert("prev != ipr", prev != ipr);
  if (prev != nullptr) {
    lwip_assert("prev->next == ipr", prev->next == ipr);
  }

  struct IpReassHelper* iprh = (struct IpReassHelper *)ipr->p->payload;
  if (iprh->start == 0) {
    /* The first fragment was received, send ICMP time exceeded. */
    /* First, de-queue the first PacketBuffer from r->p. */
    p = ipr->p;
    ipr->p = iprh->next_pbuf;
    /* Then, copy the original header into it. */
    memcpy(p->payload, &ipr->iphdr, IP4_HDR_LEN);
    icmp_time_exceeded(p, ICMP_TE_FRAG);
    // clen = pbuf_clen(p);
    lwip_assert("pbufs_freed + clen <= 0xffff", pbufs_freed + clen <= 0xffff);
    pbufs_freed = (uint16_t)(pbufs_freed + clen);
    free_pkt_buf(p);
  }


  /* First, free all received pbufs.  The individual pbufs need to be released
     separately as they have not yet been chained */
  p = ipr->p;
  while (p != nullptr) {
      iprh = (struct IpReassHelper *)p->payload;
    struct PacketBuffer* pcur = p;
    /* get the next pointer before freeing */
    p = iprh->next_pbuf;
    // clen = pbuf_clen(pcur);
    lwip_assert("pbufs_freed + clen <= 0xffff", pbufs_freed + clen <= 0xffff);
    pbufs_freed = (uint16_t)(pbufs_freed + clen);
    free_pkt_buf(pcur);
  }
  /* Then, unchain the struct ip_reassdata from the list and free it. */
  ip_reass_dequeue_datagram(ipr, prev);
  lwip_assert("ip_reass_pbufcount >= pbufs_freed", ip_reass_pbufcount >= pbufs_freed);
  ip_reass_pbufcount = (uint16_t)(ip_reass_pbufcount - pbufs_freed);

  return pbufs_freed;
}


/**
 * Free the oldest datagram to make room for enqueueing new fragments.
 * The datagram 'fraghdr' belongs to is not freed!
 *
 * @param fraghdr IP header of the current fragment
 * @param pbufs_needed number of pbufs needed to enqueue
 *        (used for freeing other datagrams if not enough space)
 * @return the number of pbufs freed
 */
static int
ip_reass_remove_oldest_datagram(struct Ip4Hdr *fraghdr, int pbufs_needed)
{
    int pbufs_freed = 0;
  int other_datagrams;

  /* Free datagrams until being allowed to enqueue 'pbufs_needed' pbufs,
   * but don't free the datagram that 'fraghdr' belongs to! */
  do {
    struct ip_reassdata* oldest = nullptr;
    struct ip_reassdata* prev = nullptr;
    struct ip_reassdata* oldest_prev = nullptr;
    other_datagrams = 0;
    struct ip_reassdata* r = reassdatagrams;
    while (r != nullptr) {
      if (!ip_addresses_and_id_match(&r->iphdr, fraghdr)) {
        /* Not the same datagram as fraghdr */
        other_datagrams++;
        if (oldest == nullptr) {
          oldest = r;
          oldest_prev = prev;
        } else if (r->timer <= oldest->timer) {
          /* older than the previous oldest */
          oldest = r;
          oldest_prev = prev;
        }
      }
      if (r->next != nullptr) {
        prev = r;
      }
      r = r->next;
    }
    if (oldest != nullptr) {
      int pbufs_freed_current = ip_reass_free_complete_datagram(oldest, oldest_prev);
      pbufs_freed += pbufs_freed_current;
    }
  } while ((pbufs_freed < pbufs_needed) && (other_datagrams > 1));
  return pbufs_freed;
}


/**
 * Enqueues a new fragment into the fragment queue
 * @param fraghdr points to the new fragments IP hdr
 * @param clen number of pbufs needed to enqueue (used for freeing other datagrams if not enough space)
 * @return A pointer to the queue location into which the fragment was enqueued
 */
static struct ip_reassdata *
ip_reass_enqueue_new_datagram(struct Ip4Hdr *fraghdr, int clen)
{
    /* No matching previous fragment found, allocate a new reassdata struct */
  // ipr = (struct ip_reassdata *)memp_malloc(MEMP_REASSDATA);
  struct ip_reassdata* ipr = new ip_reassdata;
  if (ipr == nullptr) {

    if (ip_reass_remove_oldest_datagram(fraghdr, clen) >= clen) {
      // ipr = (struct ip_reassdata *)memp_malloc(MEMP_REASSDATA);
      ipr = new struct ip_reassdata;
    }
    if (ipr == nullptr)

    {
      Logf(true, ("Failed to alloc reassdata struct\n"));
      return nullptr;
    }
  }
  memset(ipr, 0, sizeof(struct ip_reassdata));
  ipr->timer = IP_REASS_MAXAGE;

  /* enqueue the new structure to the front of the list */
  ipr->next = reassdatagrams;
  reassdatagrams = ipr;
  /* copy the ip header for later tests and input */
  /* @todo: no ip options supported? */
  memcpy(&(ipr->iphdr), fraghdr, IP4_HDR_LEN);
  return ipr;
}

/**
 * Dequeues a datagram from the datagram queue. Doesn't deallocate the pbufs.
 * @param ipr points to the queue entry to dequeue
 */
static void
ip_reass_dequeue_datagram(struct ip_reassdata *ipr, struct ip_reassdata *prev)
{
  /* dequeue the reass struct  */
  if (reassdatagrams == ipr) {
    /* it was the first in the list */
    reassdatagrams = ipr->next;
  } else {
    /* it wasn't the first, so it must have a valid 'prev' */
    lwip_assert("sanity check linked list", prev != nullptr);
    prev->next = ipr->next;
  }

  /* now we can free the ip_reassdata struct */
  // memp_free(MEMP_REASSDATA, ipr);
  delete ipr;
}

/**
 * Chain a new PacketBuffer into the PacketBuffer list that composes the datagram.  The PacketBuffer list
 * will grow over time as  new pbufs are rx.
 * Also checks that the datagram passes basic continuity checks (if the last
 * fragment was received at least once).
 * @param ipr points to the reassembly state
 * @param new_p points to the PacketBuffer for the current fragment
 * @param is_last is 1 if this PacketBuffer has MF==0 (ipr->flags not updated yet)
 * @return see IP_REASS_VALIDATE_* defines
 */
static int
ip_reass_chain_frag_into_datagram_and_validate(struct ip_reassdata *ipr, struct PacketBuffer *new_p, int is_last)
{
  struct IpReassHelper*iprh_prev = nullptr;
  struct PacketBuffer *q;
  int valid = 1;

  /* Extract length and fragment offset from current fragment */
  struct Ip4Hdr& fraghdr = (struct Ip4Hdr *)new_p->payload;
  uint16_t len = lwip_ntohs(get_ip4_hdr_len(fraghdr));
  uint8_t hlen = get_ip4_hdr_hdr_len_bytes(fraghdr);
  if (hlen > len) {
    /* invalid datagram */
    return IP_REASS_VALIDATE_PBUF_DROPPED;
  }
  len = (uint16_t)(len - hlen);
  uint16_t offset = get_ip4_hdr_offset_bytes(fraghdr);

  /* overwrite the fragment's ip header from the PacketBuffer with our helper struct,
   * and setup the embedded helper structure. */
  /* make sure the struct ip_reass_helper fits into the IP header */
  lwip_assert("sizeof(struct ip_reass_helper) <= IP_HLEN",
              sizeof(struct IpReassHelper) <= IP4_HDR_LEN);
  struct IpReassHelper* iprh = (struct IpReassHelper *)new_p->payload;
  iprh->next_pbuf = nullptr;
  iprh->start = offset;
  iprh->end = (uint16_t)(offset + len);
  if (iprh->end < offset) {
    /* uint16_t overflow, cannot handle this */
    return IP_REASS_VALIDATE_PBUF_DROPPED;
  }

  /* Iterate through until we either get to the end of the list (append),
   * or we find one with a larger offset (insert). */
  for (q = ipr->p; q != nullptr;) {
    struct IpReassHelper* iprh_tmp = (struct IpReassHelper *)q->payload;
    if (iprh->start < iprh_tmp->start) {
      /* the new PacketBuffer should be inserted before this */
      iprh->next_pbuf = q;
      if (iprh_prev != nullptr) {
        /* not the fragment with the lowest offset */

        if ((iprh->start < iprh_prev->end) || (iprh->end > iprh_tmp->start)) {
          /* fragment overlaps with previous or following, throw away */
          return IP_REASS_VALIDATE_PBUF_DROPPED;
        }

        iprh_prev->next_pbuf = new_p;
        if (iprh_prev->end != iprh->start) {
          /* There is a fragment missing between the current
           * and the previous fragment */
          valid = 0;
        }
      } else {

        if (iprh->end > iprh_tmp->start) {
          /* fragment overlaps with following, throw away */
          return IP_REASS_VALIDATE_PBUF_DROPPED;
        }

        /* fragment with the lowest offset */
        ipr->p = new_p;
      }
      break;
    } else if (iprh->start == iprh_tmp->start) {
      /* received the same datagram twice: no need to keep the datagram */
      return IP_REASS_VALIDATE_PBUF_DROPPED;

    } else if (iprh->start < iprh_tmp->end) {
      /* overlap: no need to keep the new datagram */
      return IP_REASS_VALIDATE_PBUF_DROPPED;

    } else {
      /* Check if the fragments received so far have no holes. */
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

      lwip_assert("check fragments don't overlap", iprh_prev->end <= iprh->start);

      iprh_prev->next_pbuf = new_p;
      if (iprh_prev->end != iprh->start) {
        valid = 0;
      }
    } else {

      lwip_assert("no previous fragment, this must be the first fragment!",
                  ipr->p == nullptr);

      /* this is the first fragment we ever received for this ip datagram */
      ipr->p = new_p;
    }
  }

  /* At this point, the validation part begins: */
  /* If we already received the last fragment */
  if (is_last || ((ipr->flags & kIpReassFlagLastfrag) != 0)) {
    /* and had no holes so far */
    if (valid) {
      /* then check if the rest of the fragments is here */
      /* Check if the queue starts with the first datagram */
      if ((ipr->p == nullptr) || (((struct IpReassHelper *)ipr->p->payload)->start != 0)) {
        valid = 0;
      } else {
        /* and check that there are no holes after this datagram */
        iprh_prev = iprh;
        q = iprh->next_pbuf;
        while (q != nullptr) {
          iprh = (struct IpReassHelper *)q->payload;
          if (iprh_prev->end != iprh->start) {
            valid = 0;
            break;
          }
          iprh_prev = iprh;
          q = iprh->next_pbuf;
        }
        /* if still valid, all fragments are received
         * (because to the MF==0 already arrived */
        if (valid) {
          lwip_assert("sanity check", ipr->p != nullptr);
          lwip_assert("sanity check",
                      ((struct IpReassHelper *)ipr->p->payload) != iprh);
          lwip_assert("validate_datagram:next_pbuf!=NULL",
                      iprh->next_pbuf == nullptr);
        }
      }
    }
    /* If valid is 0 here, there are some fragments missing in the middle
     * (since MF == 0 has already arrived). Such datagrams simply time out if
     * no more fragments are received... */
    return valid ? IP_REASS_VALIDATE_TELEGRAM_FINISHED : IP_REASS_VALIDATE_PBUF_QUEUED;
  }
  /* If we come here, not all fragments were received, yet! */
  return IP_REASS_VALIDATE_PBUF_QUEUED; /* not yet valid! */
}

/**
 * Reassembles incoming IP fragments into an IP datagram.
 *
 * @param p points to a PacketBuffer chain of the fragment
 * @return NULL if reassembly is incomplete, ? otherwise
 */
struct PacketBuffer *
ip4_reass(struct PacketBuffer *p)
{
    struct ip_reassdata *ipr;
    struct Ip4Hdr& fraghdr = (struct Ip4Hdr *)p->payload;

  if (get_ip4_hdr_hdr_len_bytes(fraghdr) != IP4_HDR_LEN) {
    Logf(true, ("ip4_reass: IP options currently not supported!\n"));
    goto nullreturn;
  }

  uint16_t offset = get_ip4_hdr_offset_bytes(fraghdr);
  uint16_t len = lwip_ntohs(get_ip4_hdr_len(fraghdr));
  uint8_t hlen = get_ip4_hdr_hdr_len_bytes(fraghdr);
  if (hlen > len) {
    /* invalid datagram */
    goto nullreturn;
  }
  len = (uint16_t)(len - hlen);

  /* Check if we are allowed to enqueue more datagrams. */
  // uint16_t clen = pbuf_clen(p);
  if ((ip_reass_pbufcount + clen) > IP_REASS_MAX_PBUFS) {

    if (!ip_reass_remove_oldest_datagram(fraghdr, clen) ||
        ((ip_reass_pbufcount + clen) > IP_REASS_MAX_PBUFS))

    {
      /* No datagram could be freed and still too many pbufs enqueued */
      Logf(true, "ip4_reass: Overflow condition: pbufct=%d, clen=%d, MAX=%d\n",
               ip_reass_pbufcount, clen, IP_REASS_MAX_PBUFS);
      /* @todo: send ICMP time exceeded here? */
      /* drop this PacketBuffer */
      goto nullreturn;
    }
  }

  /* Look for the datagram the fragment belongs to in the current datagram queue,
   * remembering the previous in the queue for later dequeueing. */
  for (ipr = reassdatagrams; ipr != nullptr; ipr = ipr->next) {
    /* Check if the incoming fragment matches the one currently present
       in the reassembly buffer. If so, we proceed with copying the
       fragment into the buffer. */
    if (ip_addresses_and_id_match(&ipr->iphdr, fraghdr)) {
//      Logf(true, ("ip4_reass: matching previous fragment ID=%x\n",
//                                   lwip_ntohs(IPH_ID(fraghdr))));
      break;
    }
  }

  if (ipr == nullptr) {
    /* Enqueue a new datagram into the datagram queue */
    ipr = ip_reass_enqueue_new_datagram(fraghdr, clen);
    /* Bail if unable to enqueue */
    if (ipr == nullptr) {
      goto nullreturn;
    }
  } else {
    if (((lwip_ntohs(get_ip4_hdr_offset(fraghdr)) & IP4_OFF_MASK) == 0) &&
        ((lwip_ntohs(get_ip4_hdr_offset(&ipr->iphdr)) & IP4_OFF_MASK) != 0)) {
      /* ipr->iphdr is not the header from the first fragment, but fraghdr is
       * -> copy fraghdr into ipr->iphdr since we want to have the header
       * of the first fragment (for ICMP time exceeded and later, for copying
       * all options, if supported)*/
      memcpy(&ipr->iphdr, fraghdr, IP4_HDR_LEN);
    }
  }

  /* At this point, we have either created a new entry or pointing
   * to an existing one */

  /* check for 'no more fragments', and update queue entry*/
  int is_last = (get_ip4_hdr_offset(fraghdr) & pp_ntohs(IP4_MF_FLAG)) == 0;
  if (is_last) {
    uint16_t datagram_len = (uint16_t)(offset + len);
    if ((datagram_len < offset) || (datagram_len > (0xFFFF - IP4_HDR_LEN))) {
      /* uint16_t overflow, cannot handle this */
      goto nullreturn_ipr;
    }
  }
  /* find the right place to insert this PacketBuffer */
  /* @todo: trim pbufs if fragments are overlapping */
  int valid = ip_reass_chain_frag_into_datagram_and_validate(ipr, p, is_last);
  if (valid == IP_REASS_VALIDATE_PBUF_DROPPED) {
    goto nullreturn_ipr;
  }
  /* if we come here, the PacketBuffer has been enqueued */

  /* Track the current number of pbufs current 'in-flight', in order to limit
     the number of fragments that may be enqueued at any one time
     (overflow checked by testing against IP_REASS_MAX_PBUFS) */
  ip_reass_pbufcount = (uint16_t)(ip_reass_pbufcount + clen);
  if (is_last) {
    uint16_t datagram_len = (uint16_t)(offset + len);
    ipr->datagram_len = datagram_len;
    ipr->flags |= kIpReassFlagLastfrag;
//    Logf(true,
//                ("ip4_reass: last fragment seen, total len %"S16_F"\n",
//                 ipr->datagram_len));
  }

  if (valid == IP_REASS_VALIDATE_TELEGRAM_FINISHED) {
    struct ip_reassdata *ipr_prev;
    /* the totally last fragment (flag more fragments = 0) was received at least
     * once AND all fragments are received */
    uint16_t datagram_len = (uint16_t)(ipr->datagram_len + IP4_HDR_LEN);

    /* save the second pbuf before copying the header over the pointer */
    struct PacketBuffer* r = ((struct IpReassHelper *)ipr->p->payload)->next_pbuf;

    /* copy the original ip header back to the first PacketBuffer */
    fraghdr = (struct Ip4Hdr *)(ipr->p->payload);
    memcpy(fraghdr, &ipr->iphdr, IP4_HDR_LEN);
    set_ip4_hdr_len(fraghdr, lwip_htons(datagram_len));
    set_ip4_hdr_offset(fraghdr, 0);
    set_ip4_hdr_checksum(fraghdr, 0);
    /* @todo: do we need to set/calculate the correct checksum? */

      NetworkInterface* curr_input_netif = nullptr;

    if(is_netif_checksum_enabled(curr_input_netif, NETIF_CHECKSUM_GEN_IP)) {
      set_ip4_hdr_checksum(fraghdr, inet_chksum((uint8_t*)fraghdr, IP4_HDR_LEN));
    }


    p = ipr->p;

    /* chain together the pbufs contained within the reass_data list. */
    while (r != nullptr) {
      struct IpReassHelper* iprh = (struct IpReassHelper *)r->payload;

      /* hide the ip header for every succeeding fragment */
      // pbuf_remove_header(r, IP4_HDR_LEN);
      // pbuf_cat(p, r);
      r = iprh->next_pbuf;
    }

    /* find the previous entry in the linked list */
    if (ipr == reassdatagrams) {
      ipr_prev = nullptr;
    } else {
      for (ipr_prev = reassdatagrams; ipr_prev != nullptr; ipr_prev = ipr_prev->next) {
        if (ipr_prev->next == ipr) {
          break;
        }
      }
    }

    /* release the sources allocate for the fragment queue entry */
    ip_reass_dequeue_datagram(ipr, ipr_prev);

    /* and adjust the number of pbufs currently queued for reassembly. */
    // clen = pbuf_clen(p);
    lwip_assert("ip_reass_pbufcount >= clen", ip_reass_pbufcount >= clen);
    ip_reass_pbufcount = (uint16_t)(ip_reass_pbufcount - clen);

    

    /* Return the PacketBuffer chain */
    return p;
  }
  /* the datagram is not (yet?) reassembled completely */
  Logf(true, "ip_reass_pbufcount: %d out\n", ip_reass_pbufcount);
  return nullptr;

nullreturn_ipr:
  lwip_assert("ipr != NULL", ipr != nullptr);
  if (ipr->p == nullptr) {
    /* dropped PacketBuffer after creating a new datagram entry: remove the entry, too */
    lwip_assert("not firstalthough just enqueued", ipr == reassdatagrams);
    ip_reass_dequeue_datagram(ipr, nullptr);
  }

nullreturn:
  Logf(true, ("ip4_reass: nullreturn\n"));
  free_pkt_buf(p);
  return nullptr;
}

/** Allocate a new struct pbuf_custom_ref */
static struct PbufCustomRef *
ip_frag_alloc_pbuf_custom_ref(void)
{
  // return (struct pbuf_custom_ref *)memp_malloc(MEMP_FRAG_PBUF);
  return new PbufCustomRef;
}

/** Free a struct pbuf_custom_ref */
static void
ip_frag_free_pbuf_custom_ref(struct PbufCustomRef *p)
{
  lwip_assert("p != NULL", p != nullptr);
  // memp_free(MEMP_FRAG_PBUF, p);
  delete p;
}

/** Free-callback function to free a 'struct pbuf_custom_ref', called by
 * free_pkt_buf. */
static void
ipfrag_free_pbuf_custom(struct PacketBuffer *p)
{
  struct PbufCustomRef *pcr = (struct PbufCustomRef *)p;
  lwip_assert("pcr != NULL", pcr != nullptr);
  lwip_assert("pcr == p", (uint8_t *)pcr == (uint8_t *)p);
  if (pcr->original != nullptr) {
    free_pkt_buf(pcr->original);
  }
  ip_frag_free_pbuf_custom_ref(pcr);
}


/**
 * Fragment an IP datagram if too large for the netif.
 *
 * Chop the datagram in MTU sized chunks and send them in order
 * by pointing PBUF_REFs into p.
 *
 * @param pkt_buf ip packet to send
 * @param netif the netif on which to send
 * @param dst_addr destination ip address to which to send
 *
 * @return ERR_OK if sent successfully, LwipStatus otherwise
 */
LwipStatus
ip4_frag(PacketBuffer& pkt_buf, NetworkInterface& netif, const Ip4Addr& dst_addr)
{
  struct PacketBuffer rambuf{};
#if !LWIP_NETIF_TX_SINGLE_PBUF
  uint16_t newpbuflen = 0;
#endif
  const uint16_t nfb = (uint16_t)((netif->mtu - IP4_HDR_LEN) / 8);
  uint16_t poff = IP4_HDR_LEN;
  struct Ip4Hdr& original_iphdr = (struct Ip4Hdr *)pkt_buf->payload;
  struct Ip4Hdr& iphdr = original_iphdr;
  if (get_ip4_hdr_hdr_len_bytes(iphdr) != IP4_HDR_LEN) {
    /* ip4_frag() does not support IP options */
    return ERR_VAL;
  }
  // 
  if (pkt_buf->len < IP4_HDR_LEN)
  {
      printf("pbuf too short\n");
      return ERR_VAL;
  }


  /* Save original offset */
  uint16_t tmp = lwip_ntohs(get_ip4_hdr_offset(iphdr));
  uint16_t ofo = tmp & IP4_OFF_MASK;
  /* already fragmented? if so, the last fragment we create must have MF, too */
  int mf_set = tmp & IP4_MF_FLAG;

  uint16_t left = (uint16_t)(pkt_buf->tot_len - IP4_HDR_LEN);

  while (left) {
    /* Fill this fragment */
    uint16_t fragsize = std::min(left, (uint16_t)(nfb * 8));


    /* When not using a static buffer, create a chain of pbufs.
     * The first will be a PBUF_RAM holding the link and IP header.
     * The rest will be PBUF_REFs mirroring the PacketBuffer chain to be fragged,
     * but limited to the size of an mtu.
     */
    // rambuf = pbuf_alloc();
    if (rambuf == nullptr) {
      goto memerr;
    }
    lwip_assert("this needs a PacketBuffer in one piece!",
                (rambuf->len >= (IP4_HDR_LEN)));
    memcpy(rambuf->payload, original_iphdr, IP4_HDR_LEN);
    iphdr = (struct Ip4Hdr *)rambuf->payload;

    uint16_t left_to_copy = fragsize;
    while (left_to_copy) {
        uint16_t plen = (uint16_t)(pkt_buf->len - poff);
      lwip_assert("p->len >= poff", pkt_buf->len >= poff);
      newpbuflen = std::min(left_to_copy, plen);
      /* Is this PacketBuffer already empty? */
      if (!newpbuflen) {
        poff = 0;
        pkt_buf = pkt_buf->next;
        continue;
      }
      struct PbufCustomRef* pcr = ip_frag_alloc_pbuf_custom_ref();
      if (pcr == nullptr) {
        free_pkt_buf(rambuf);
        goto memerr;
      }
      /* Mirror this PacketBuffer, although we might not need all of it. */
      // struct PacketBuffer* newpbuf = pbuf_alloced_custom(
      //     PBUF_RAW,
      //     newpbuflen,
      //     PBUF_REF,
      //     &pcr->pc,
      //     (uint8_t *)pkt_buf->payload + poff,
      //     newpbuflen);
      if (newpbuf == nullptr) {
        ip_frag_free_pbuf_custom_ref(pcr);
        free_pkt_buf(rambuf);
        goto memerr;
      }
      // pbuf_ref(pkt_buf);
      pcr->original = pkt_buf;
      pcr->pc.custom_free_function = ipfrag_free_pbuf_custom;

      /* Add it to end of rambuf's chain, but using pbuf_cat, not pbuf_chain
       * so that it is removed when pbuf_dechain is later called on rambuf.
       */
      // pbuf_cat(rambuf, newpbuf);
      left_to_copy = (uint16_t)(left_to_copy - newpbuflen);
      if (left_to_copy) {
        poff = 0;
        pkt_buf = pkt_buf->next;
      }
    }
    poff = (uint16_t)(poff + newpbuflen);


    /* Correct header */
    int last = (left <= netif->mtu - IP4_HDR_LEN);

    /* Set new offset and MF flag */
    tmp = (IP4_OFF_MASK & (ofo));
    if (!last || mf_set) {
      /* the last fragment has MF set if the input frame had it */
      tmp = tmp | IP4_MF_FLAG;
    }
    set_ip4_hdr_offset(iphdr, lwip_htons(tmp));
    set_ip4_hdr_len(iphdr, lwip_htons((uint16_t)(fragsize + IP4_HDR_LEN)));
    set_ip4_hdr_checksum(iphdr, 0);

    if(is_netif_checksum_enabled(netif, NETIF_CHECKSUM_GEN_IP)) {
      set_ip4_hdr_checksum(iphdr, inet_chksum((uint8_t*)iphdr, IP4_HDR_LEN));
    }


    /* No need for separate header PacketBuffer - we allowed room for it in rambuf
     * when allocated.
     */
    netif->output(netif, rambuf, dst_addr);

    /* Unfortunately we can't reuse rambuf - the hardware may still be
     * using the buffer. Instead we free it (and the ensuing chain) and
     * recreate it next time round the loop. If we're lucky the hardware
     * will have already sent the packet, the free will really free, and
     * there will be zero memory penalty.
     */

    free_pkt_buf(rambuf);
    left = (uint16_t)(left - fragsize);
    ofo = (uint16_t)(ofo + nfb);
  }
  
  return STATUS_OK;
memerr:
  
  return ERR_MEM;
}
