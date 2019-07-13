#include "opt.h"
#include "def.h"
#include "icmp.h"
#include "inet_chksum.h"
#include "ip4_frag.h"
#include "netif.h"
#include "stats.h"
#include "ip4.h"
#include "lwip_debug.h"
#include <cstring>
#if IP_REASSEMBLY

#define IP_REASS_FLAG_LASTFRAG 0x01

#define IP_REASS_VALIDATE_TELEGRAM_FINISHED  1
#define IP_REASS_VALIDATE_PBUF_QUEUED        0
#define IP_REASS_VALIDATE_PBUF_DROPPED       -1

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


#define IP_ADDRESSES_AND_ID_MATCH(iphdrA, iphdrB)  \
  (ip4_addr_cmp(&(iphdrA)->src, &(iphdrB)->src) && \
   ip4_addr_cmp(&(iphdrA)->dest, &(iphdrB)->dest) && \
   IPH_ID(iphdrA) == IPH_ID(iphdrB)) ? 1 : 0

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
    struct ip_reassdata *r, *prev = nullptr;
    r = reassdatagrams;
    while (r != nullptr)
    {
        /* Decrement the timer. Once it reaches 0,
         * clean up the incomplete fragment assembly */
        if (r->timer > 0)
        {
            r->timer--;
            //      Logf(IP_REASS_DEBUG, ("ip_reass_tmr: timer dec %"U16_F"\n", (uint16_t)r->timer));
            prev = r;
            r = r->next;
        }
        else
        {
            /* reassembly timed out */
            struct ip_reassdata* tmp;
            //      Logf(IP_REASS_DEBUG, ("ip_reass_tmr: timer timed out\n"));
            tmp = r; /* get the next pointer before freeing */
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
  struct IpReassHelper *iprh;

  LWIP_ASSERT("prev != ipr", prev != ipr);
  if (prev != nullptr) {
    LWIP_ASSERT("prev->next == ipr", prev->next == ipr);
  }

  MIB2_STATS_INC(mib2.ipreasmfails);
#if LWIP_ICMP
  iprh = (struct IpReassHelper *)ipr->p->payload;
  if (iprh->start == 0) {
    /* The first fragment was received, send ICMP time exceeded. */
    /* First, de-queue the first PacketBuffer from r->p. */
    p = ipr->p;
    ipr->p = iprh->next_pbuf;
    /* Then, copy the original header into it. */
    SMEMCPY(p->payload, &ipr->iphdr, IP_HLEN);
    icmp_time_exceeded(p, ICMP_TE_FRAG);
    clen = pbuf_clen(p);
    LWIP_ASSERT("pbufs_freed + clen <= 0xffff", pbufs_freed + clen <= 0xffff);
    pbufs_freed = (uint16_t)(pbufs_freed + clen);
    pbuf_free(p);
  }
#endif /* LWIP_ICMP */

  /* First, free all received pbufs.  The individual pbufs need to be released
     separately as they have not yet been chained */
  p = ipr->p;
  while (p != nullptr) {
    struct PacketBuffer *pcur;
    iprh = (struct IpReassHelper *)p->payload;
    pcur = p;
    /* get the next pointer before freeing */
    p = iprh->next_pbuf;
    clen = pbuf_clen(pcur);
    LWIP_ASSERT("pbufs_freed + clen <= 0xffff", pbufs_freed + clen <= 0xffff);
    pbufs_freed = (uint16_t)(pbufs_freed + clen);
    pbuf_free(pcur);
  }
  /* Then, unchain the struct ip_reassdata from the list and free it. */
  ip_reass_dequeue_datagram(ipr, prev);
  LWIP_ASSERT("ip_reass_pbufcount >= pbufs_freed", ip_reass_pbufcount >= pbufs_freed);
  ip_reass_pbufcount = (uint16_t)(ip_reass_pbufcount - pbufs_freed);

  return pbufs_freed;
}

#if IP_REASS_FREE_OLDEST
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
  /* @todo Can't we simply remove the last datagram in the
   *       linked list behind reassdatagrams?
   */
  struct ip_reassdata *r, *oldest, *prev, *oldest_prev;
  int pbufs_freed = 0, pbufs_freed_current;
  int other_datagrams;

  /* Free datagrams until being allowed to enqueue 'pbufs_needed' pbufs,
   * but don't free the datagram that 'fraghdr' belongs to! */
  do {
    oldest = nullptr;
    prev = nullptr;
    oldest_prev = nullptr;
    other_datagrams = 0;
    r = reassdatagrams;
    while (r != nullptr) {
      if (!IP_ADDRESSES_AND_ID_MATCH(&r->iphdr, fraghdr)) {
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
      pbufs_freed_current = ip_reass_free_complete_datagram(oldest, oldest_prev);
      pbufs_freed += pbufs_freed_current;
    }
  } while ((pbufs_freed < pbufs_needed) && (other_datagrams > 1));
  return pbufs_freed;
}
#endif /* IP_REASS_FREE_OLDEST */

/**
 * Enqueues a new fragment into the fragment queue
 * @param fraghdr points to the new fragments IP hdr
 * @param clen number of pbufs needed to enqueue (used for freeing other datagrams if not enough space)
 * @return A pointer to the queue location into which the fragment was enqueued
 */
static struct ip_reassdata *
ip_reass_enqueue_new_datagram(struct Ip4Hdr *fraghdr, int clen)
{
  struct ip_reassdata *ipr;
#if ! IP_REASS_FREE_OLDEST
  ;
#endif

  /* No matching previous fragment found, allocate a new reassdata struct */
  // ipr = (struct ip_reassdata *)memp_malloc(MEMP_REASSDATA);
  ipr = new ip_reassdata;
  if (ipr == nullptr) {
#if IP_REASS_FREE_OLDEST
    if (ip_reass_remove_oldest_datagram(fraghdr, clen) >= clen) {
      // ipr = (struct ip_reassdata *)memp_malloc(MEMP_REASSDATA);
      ipr = new struct ip_reassdata;
    }
    if (ipr == nullptr)
#endif /* IP_REASS_FREE_OLDEST */
    {
      IPFRAG_STATS_INC(ip_frag.memerr);
      Logf(IP_REASS_DEBUG, ("Failed to alloc reassdata struct\n"));
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
  SMEMCPY(&(ipr->iphdr), fraghdr, IP_HLEN);
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
    LWIP_ASSERT("sanity check linked list", prev != nullptr);
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
  struct IpReassHelper *iprh, *iprh_tmp, *iprh_prev = nullptr;
  struct PacketBuffer *q;
  uint16_t offset, len;
  uint8_t hlen;
  struct Ip4Hdr *fraghdr;
  int valid = 1;

  /* Extract length and fragment offset from current fragment */
  fraghdr = (struct Ip4Hdr *)new_p->payload;
  len = lwip_ntohs(IPH_LEN(fraghdr));
  hlen = IPH_HL_BYTES(fraghdr);
  if (hlen > len) {
    /* invalid datagram */
    return IP_REASS_VALIDATE_PBUF_DROPPED;
  }
  len = (uint16_t)(len - hlen);
  offset = IPH_OFFSET_BYTES(fraghdr);

  /* overwrite the fragment's ip header from the PacketBuffer with our helper struct,
   * and setup the embedded helper structure. */
  /* make sure the struct ip_reass_helper fits into the IP header */
  LWIP_ASSERT("sizeof(struct ip_reass_helper) <= IP_HLEN",
              sizeof(struct IpReassHelper) <= IP_HLEN);
  iprh = (struct IpReassHelper *)new_p->payload;
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
    iprh_tmp = (struct IpReassHelper *)q->payload;
    if (iprh->start < iprh_tmp->start) {
      /* the new PacketBuffer should be inserted before this */
      iprh->next_pbuf = q;
      if (iprh_prev != nullptr) {
        /* not the fragment with the lowest offset */
#if IP_REASS_CHECK_OVERLAP
        if ((iprh->start < iprh_prev->end) || (iprh->end > iprh_tmp->start)) {
          /* fragment overlaps with previous or following, throw away */
          return IP_REASS_VALIDATE_PBUF_DROPPED;
        }
#endif /* IP_REASS_CHECK_OVERLAP */
        iprh_prev->next_pbuf = new_p;
        if (iprh_prev->end != iprh->start) {
          /* There is a fragment missing between the current
           * and the previous fragment */
          valid = 0;
        }
      } else {
#if IP_REASS_CHECK_OVERLAP
        if (iprh->end > iprh_tmp->start) {
          /* fragment overlaps with following, throw away */
          return IP_REASS_VALIDATE_PBUF_DROPPED;
        }
#endif /* IP_REASS_CHECK_OVERLAP */
        /* fragment with the lowest offset */
        ipr->p = new_p;
      }
      break;
    } else if (iprh->start == iprh_tmp->start) {
      /* received the same datagram twice: no need to keep the datagram */
      return IP_REASS_VALIDATE_PBUF_DROPPED;
#if IP_REASS_CHECK_OVERLAP
    } else if (iprh->start < iprh_tmp->end) {
      /* overlap: no need to keep the new datagram */
      return IP_REASS_VALIDATE_PBUF_DROPPED;
#endif /* IP_REASS_CHECK_OVERLAP */
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
#if IP_REASS_CHECK_OVERLAP
      LWIP_ASSERT("check fragments don't overlap", iprh_prev->end <= iprh->start);
#endif /* IP_REASS_CHECK_OVERLAP */
      iprh_prev->next_pbuf = new_p;
      if (iprh_prev->end != iprh->start) {
        valid = 0;
      }
    } else {
#if IP_REASS_CHECK_OVERLAP
      LWIP_ASSERT("no previous fragment, this must be the first fragment!",
                  ipr->p == nullptr);
#endif /* IP_REASS_CHECK_OVERLAP */
      /* this is the first fragment we ever received for this ip datagram */
      ipr->p = new_p;
    }
  }

  /* At this point, the validation part begins: */
  /* If we already received the last fragment */
  if (is_last || ((ipr->flags & IP_REASS_FLAG_LASTFRAG) != 0)) {
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
          LWIP_ASSERT("sanity check", ipr->p != nullptr);
          LWIP_ASSERT("sanity check",
                      ((struct IpReassHelper *)ipr->p->payload) != iprh);
          LWIP_ASSERT("validate_datagram:next_pbuf!=NULL",
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
  struct PacketBuffer *r;
  struct Ip4Hdr *fraghdr;
  struct ip_reassdata *ipr;
  struct IpReassHelper *iprh;
  uint16_t offset, len, clen;
  uint8_t hlen;
  int valid;
  int is_last;

  IPFRAG_STATS_INC(ip_frag.recv);
  MIB2_STATS_INC(mib2.ipreasmreqds);

  fraghdr = (struct Ip4Hdr *)p->payload;

  if (IPH_HL_BYTES(fraghdr) != IP_HLEN) {
    Logf(IP_REASS_DEBUG, ("ip4_reass: IP options currently not supported!\n"));
    IPFRAG_STATS_INC(ip_frag.err);
    goto nullreturn;
  }

  offset = IPH_OFFSET_BYTES(fraghdr);
  len = lwip_ntohs(IPH_LEN(fraghdr));
  hlen = IPH_HL_BYTES(fraghdr);
  if (hlen > len) {
    /* invalid datagram */
    goto nullreturn;
  }
  len = (uint16_t)(len - hlen);

  /* Check if we are allowed to enqueue more datagrams. */
  clen = pbuf_clen(p);
  if ((ip_reass_pbufcount + clen) > IP_REASS_MAX_PBUFS) {
#if IP_REASS_FREE_OLDEST
    if (!ip_reass_remove_oldest_datagram(fraghdr, clen) ||
        ((ip_reass_pbufcount + clen) > IP_REASS_MAX_PBUFS))
#endif /* IP_REASS_FREE_OLDEST */
    {
      /* No datagram could be freed and still too many pbufs enqueued */
      Logf(IP_REASS_DEBUG, ("ip4_reass: Overflow condition: pbufct=%d, clen=%d, MAX=%d\n",
               ip_reass_pbufcount, clen, IP_REASS_MAX_PBUFS));
      IPFRAG_STATS_INC(ip_frag.memerr);
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
    if (IP_ADDRESSES_AND_ID_MATCH(&ipr->iphdr, fraghdr)) {
//      Logf(IP_REASS_DEBUG, ("ip4_reass: matching previous fragment ID=%"X16_F"\n",
//                                   lwip_ntohs(IPH_ID(fraghdr))));
      IPFRAG_STATS_INC(ip_frag.cachehit);
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
    if (((lwip_ntohs(IPH_OFFSET(fraghdr)) & IP_OFFMASK) == 0) &&
        ((lwip_ntohs(IPH_OFFSET(&ipr->iphdr)) & IP_OFFMASK) != 0)) {
      /* ipr->iphdr is not the header from the first fragment, but fraghdr is
       * -> copy fraghdr into ipr->iphdr since we want to have the header
       * of the first fragment (for ICMP time exceeded and later, for copying
       * all options, if supported)*/
      SMEMCPY(&ipr->iphdr, fraghdr, IP_HLEN);
    }
  }

  /* At this point, we have either created a new entry or pointing
   * to an existing one */

  /* check for 'no more fragments', and update queue entry*/
  is_last = (IPH_OFFSET(fraghdr) & PP_NTOHS(IP_MF)) == 0;
  if (is_last) {
    uint16_t datagram_len = (uint16_t)(offset + len);
    if ((datagram_len < offset) || (datagram_len > (0xFFFF - IP_HLEN))) {
      /* uint16_t overflow, cannot handle this */
      goto nullreturn_ipr;
    }
  }
  /* find the right place to insert this PacketBuffer */
  /* @todo: trim pbufs if fragments are overlapping */
  valid = ip_reass_chain_frag_into_datagram_and_validate(ipr, p, is_last);
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
    ipr->flags |= IP_REASS_FLAG_LASTFRAG;
//    Logf(IP_REASS_DEBUG,
//                ("ip4_reass: last fragment seen, total len %"S16_F"\n",
//                 ipr->datagram_len));
  }

  if (valid == IP_REASS_VALIDATE_TELEGRAM_FINISHED) {
    struct ip_reassdata *ipr_prev;
    /* the totally last fragment (flag more fragments = 0) was received at least
     * once AND all fragments are received */
    uint16_t datagram_len = (uint16_t)(ipr->datagram_len + IP_HLEN);

    /* save the second pbuf before copying the header over the pointer */
    r = ((struct IpReassHelper *)ipr->p->payload)->next_pbuf;

    /* copy the original ip header back to the first PacketBuffer */
    fraghdr = (struct Ip4Hdr *)(ipr->p->payload);
    SMEMCPY(fraghdr, &ipr->iphdr, IP_HLEN);
    IPH_LEN_SET(fraghdr, lwip_htons(datagram_len));
    IPH_OFFSET_SET(fraghdr, 0);
    IPH_CHKSUM_SET(fraghdr, 0);
    /* @todo: do we need to set/calculate the correct checksum? */
#if CHECKSUM_GEN_IP
    IF__NETIF_CHECKSUM_ENABLED(ip_current_input_netif(), NETIF_CHECKSUM_GEN_IP) {
      IPH_CHKSUM_SET(fraghdr, inet_chksum(fraghdr, IP_HLEN));
    }
#endif /* CHECKSUM_GEN_IP */

    p = ipr->p;

    /* chain together the pbufs contained within the reass_data list. */
    while (r != nullptr) {
      iprh = (struct IpReassHelper *)r->payload;

      /* hide the ip header for every succeeding fragment */
      pbuf_remove_header(r, IP_HLEN);
      pbuf_cat(p, r);
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
    clen = pbuf_clen(p);
    LWIP_ASSERT("ip_reass_pbufcount >= clen", ip_reass_pbufcount >= clen);
    ip_reass_pbufcount = (uint16_t)(ip_reass_pbufcount - clen);

    MIB2_STATS_INC(mib2.ipreasmoks);

    /* Return the PacketBuffer chain */
    return p;
  }
  /* the datagram is not (yet?) reassembled completely */
  Logf(IP_REASS_DEBUG, ("ip_reass_pbufcount: %d out\n", ip_reass_pbufcount));
  return nullptr;

nullreturn_ipr:
  LWIP_ASSERT("ipr != NULL", ipr != nullptr);
  if (ipr->p == nullptr) {
    /* dropped PacketBuffer after creating a new datagram entry: remove the entry, too */
    LWIP_ASSERT("not firstalthough just enqueued", ipr == reassdatagrams);
    ip_reass_dequeue_datagram(ipr, nullptr);
  }

nullreturn:
  Logf(IP_REASS_DEBUG, ("ip4_reass: nullreturn\n"));
  IPFRAG_STATS_INC(ip_frag.drop);
  pbuf_free(p);
  return nullptr;
}
#endif /* IP_REASSEMBLY */

#if IP_FRAG
#if !LWIP_NETIF_TX_SINGLE_PBUF
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
  LWIP_ASSERT("p != NULL", p != nullptr);
  // memp_free(MEMP_FRAG_PBUF, p);
  delete p;
}

/** Free-callback function to free a 'struct pbuf_custom_ref', called by
 * pbuf_free. */
static void
ipfrag_free_pbuf_custom(struct PacketBuffer *p)
{
  struct PbufCustomRef *pcr = (struct PbufCustomRef *)p;
  LWIP_ASSERT("pcr != NULL", pcr != nullptr);
  LWIP_ASSERT("pcr == p", (void *)pcr == (void *)p);
  if (pcr->original != nullptr) {
    pbuf_free(pcr->original);
  }
  ip_frag_free_pbuf_custom_ref(pcr);
}
#endif /* !LWIP_NETIF_TX_SINGLE_PBUF */

/**
 * Fragment an IP datagram if too large for the netif.
 *
 * Chop the datagram in MTU sized chunks and send them in order
 * by pointing PBUF_REFs into p.
 *
 * @param p ip packet to send
 * @param netif the netif on which to send
 * @param dest destination ip address to which to send
 *
 * @return ERR_OK if sent successfully, LwipError otherwise
 */
LwipError
ip4_frag(struct PacketBuffer *p, NetIfc*netif, const Ip4Addr *dest)
{
  struct PacketBuffer *rambuf;
#if !LWIP_NETIF_TX_SINGLE_PBUF
  struct PacketBuffer *newpbuf;
  uint16_t newpbuflen = 0;
  uint16_t left_to_copy;
#endif
  struct Ip4Hdr *original_iphdr;
  struct Ip4Hdr *iphdr;
  const uint16_t nfb = (uint16_t)((netif->mtu - IP_HLEN) / 8);
  uint16_t left, fragsize;
  uint16_t ofo;
  int last;
  uint16_t poff = IP_HLEN;
  uint16_t tmp;
  int mf_set;

  original_iphdr = (struct Ip4Hdr *)p->payload;
  iphdr = original_iphdr;
  if (IPH_HL_BYTES(iphdr) != IP_HLEN) {
    /* ip4_frag() does not support IP options */
    return ERR_VAL;
  }
  // LWIP_ERROR("ip4_frag(): pbuf too short", p->len >= IP_HLEN, return ERR_VAL);
  if (p->len < IP_HLEN)
  {
      printf("pbuf too short\n");
      return ERR_VAL;
  }


  /* Save original offset */
  tmp = lwip_ntohs(IPH_OFFSET(iphdr));
  ofo = tmp & IP_OFFMASK;
  /* already fragmented? if so, the last fragment we create must have MF, too */
  mf_set = tmp & IP_MF;

  left = (uint16_t)(p->tot_len - IP_HLEN);

  while (left) {
    /* Fill this fragment */
    fragsize = LWIP_MIN(left, (uint16_t)(nfb * 8));

#if LWIP_NETIF_TX_SINGLE_PBUF
    rambuf = pbuf_alloc(PBUF_IP, fragsize, PBUF_RAM);
    if (rambuf == NULL) {
      goto memerr;
    }
    LWIP_ASSERT("this needs a PacketBuffer in one piece!",
                (rambuf->len == rambuf->tot_len) && (rambuf->next == NULL));
    poff += pbuf_copy_partial(p, rambuf->payload, fragsize, poff);
    /* make room for the IP header */
    if (pbuf_add_header(rambuf, IP_HLEN)) {
      pbuf_free(rambuf);
      goto memerr;
    }
    /* fill in the IP header */
    SMEMCPY(rambuf->payload, original_iphdr, IP_HLEN);
    iphdr = (struct Ip4Hdr *)rambuf->payload;
#else /* LWIP_NETIF_TX_SINGLE_PBUF */
    /* When not using a static buffer, create a chain of pbufs.
     * The first will be a PBUF_RAM holding the link and IP header.
     * The rest will be PBUF_REFs mirroring the PacketBuffer chain to be fragged,
     * but limited to the size of an mtu.
     */
    rambuf = pbuf_alloc(PBUF_LINK, IP_HLEN, PBUF_RAM);
    if (rambuf == nullptr) {
      goto memerr;
    }
    LWIP_ASSERT("this needs a PacketBuffer in one piece!",
                (rambuf->len >= (IP_HLEN)));
    SMEMCPY(rambuf->payload, original_iphdr, IP_HLEN);
    iphdr = (struct Ip4Hdr *)rambuf->payload;

    left_to_copy = fragsize;
    while (left_to_copy) {
      struct PbufCustomRef *pcr;
      uint16_t plen = (uint16_t)(p->len - poff);
      LWIP_ASSERT("p->len >= poff", p->len >= poff);
      newpbuflen = LWIP_MIN(left_to_copy, plen);
      /* Is this PacketBuffer already empty? */
      if (!newpbuflen) {
        poff = 0;
        p = p->next;
        continue;
      }
      pcr = ip_frag_alloc_pbuf_custom_ref();
      if (pcr == nullptr) {
        pbuf_free(rambuf);
        goto memerr;
      }
      /* Mirror this PacketBuffer, although we might not need all of it. */
      newpbuf = pbuf_alloced_custom(PBUF_RAW, newpbuflen, PBUF_REF, &pcr->pc,
                                    (uint8_t *)p->payload + poff, newpbuflen);
      if (newpbuf == nullptr) {
        ip_frag_free_pbuf_custom_ref(pcr);
        pbuf_free(rambuf);
        goto memerr;
      }
      pbuf_ref(p);
      pcr->original = p;
      pcr->pc.custom_free_function = ipfrag_free_pbuf_custom;

      /* Add it to end of rambuf's chain, but using pbuf_cat, not pbuf_chain
       * so that it is removed when pbuf_dechain is later called on rambuf.
       */
      pbuf_cat(rambuf, newpbuf);
      left_to_copy = (uint16_t)(left_to_copy - newpbuflen);
      if (left_to_copy) {
        poff = 0;
        p = p->next;
      }
    }
    poff = (uint16_t)(poff + newpbuflen);
#endif /* LWIP_NETIF_TX_SINGLE_PBUF */

    /* Correct header */
    last = (left <= netif->mtu - IP_HLEN);

    /* Set new offset and MF flag */
    tmp = (IP_OFFMASK & (ofo));
    if (!last || mf_set) {
      /* the last fragment has MF set if the input frame had it */
      tmp = tmp | IP_MF;
    }
    IPH_OFFSET_SET(iphdr, lwip_htons(tmp));
    IPH_LEN_SET(iphdr, lwip_htons((uint16_t)(fragsize + IP_HLEN)));
    IPH_CHKSUM_SET(iphdr, 0);
#if CHECKSUM_GEN_IP
    IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_IP) {
      IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, IP_HLEN));
    }
#endif /* CHECKSUM_GEN_IP */

    /* No need for separate header PacketBuffer - we allowed room for it in rambuf
     * when allocated.
     */
    netif->output(netif, rambuf, dest);
    IPFRAG_STATS_INC(ip_frag.xmit);

    /* Unfortunately we can't reuse rambuf - the hardware may still be
     * using the buffer. Instead we free it (and the ensuing chain) and
     * recreate it next time round the loop. If we're lucky the hardware
     * will have already sent the packet, the free will really free, and
     * there will be zero memory penalty.
     */

    pbuf_free(rambuf);
    left = (uint16_t)(left - fragsize);
    ofo = (uint16_t)(ofo + nfb);
  }
  MIB2_STATS_INC(mib2.ipfragoks);
  return ERR_OK;
memerr:
  MIB2_STATS_INC(mib2.ipfragfails);
  return ERR_MEM;
}
#endif /* IP_FRAG */
