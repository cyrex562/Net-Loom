/*****************************************************************************
* pppoe.c - PPP Over Ethernet implementation for lwIP.
*
* Copyright (c) 2006 by Marc Boucher, Services Informatiques (MBSI) inc.
*
* The authors hereby grant permission to use, copy, modify, distribute,
* and license this software and its documentation for any purpose, provided
* that existing copyright notices are retained in all copies and that this
* notice and the following disclaimer are included verbatim in any
* distributions. No written agreement, license, or royalty fee is required
* for any of the authorized uses.
*
* THIS SOFTWARE IS PROVIDED BY THE CONTRIBUTORS *AS IS* AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
* IN NO EVENT SHALL THE CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
* THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
******************************************************************************
* REVISION HISTORY
*
* 06-01-01 Marc Boucher <marc@mbsi.ca>
*   Ported to lwIP.
*****************************************************************************/



/* based on NetBSD: if_pppoe.c,v 1.64 2006/01/31 23:50:15 martin Exp */

/*-
 * Copyright (c) 2002 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Martin Husemann <martin@NetBSD.org>.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#define NOMINMAX
#include <timeouts.h>
#include <ieee.h>
#include <ethernet.h>
#include <ipcp.h>
#include <lcp.h>
#include <ppp_impl.h>
#include <pppoe.h>
#include <algorithm>


/* Add a 16 bit unsigned value to a buffer pointed to by PTR */
#define PPPOE_ADD_16(PTR, VAL) \
    *(PTR)++ = (uint8_t)((VAL) / 256);    \
    *(PTR)++ = (uint8_t)((VAL) % 256)

/* Add a complete PPPoE header to the buffer pointed to by PTR */
#define PPPOE_ADD_HEADER(PTR, CODE, SESS, LEN)  \
    *(PTR)++ = PPPOE_VERTYPE;  \
    *(PTR)++ = (CODE);         \
    PPPOE_ADD_16(PTR, SESS);   \
    PPPOE_ADD_16(PTR, LEN)

constexpr auto PPPOE_DISC_TIMEOUT = (5*1000)  /* base for quick timeout calculation */;
constexpr auto PPPOE_SLOW_RETRY = (60*1000) /* persistent retry interval */;
constexpr auto PPPOE_DISC_MAXPADI = 4        /* retry PADI four times (quickly) */;
constexpr auto PPPOE_DISC_MAXPADR = 2        /* retry PADR twice */;

/* from if_spppsubr.c */
// #define IFF_PASSIVE IFF_LINK0 /* wait passively for connection */

constexpr auto PPPOE_ERRORSTRING_LEN = 64;


/* callbacks called from PPP core */
static LwipStatus pppoe_write(PppPcb *ppp, uint8_t *ctx, struct PacketBuffer *p);
static LwipStatus pppoe_netif_output(PppPcb *ppp, uint8_t *ctx, struct PacketBuffer *p, u_short protocol);
static void pppoe_connect(PppPcb *ppp, uint8_t *ctx);
static void pppoe_disconnect(PppPcb *ppp, uint8_t *ctx);
static LwipStatus pppoe_destroy(PppPcb *ppp, uint8_t *ctx);

/* management routines */
static void pppoe_abort_connect(struct pppoe_softc *);

/* internal timeout handling */
static void pppoe_timeout(void*);

/* sending actual protocol controll packets */
static LwipStatus pppoe_send_padi(struct pppoe_softc *);
static LwipStatus pppoe_send_padr(struct pppoe_softc *);
static LwipStatus pppoe_send_pado(struct pppoe_softc *);
static LwipStatus pppoe_send_pads(struct pppoe_softc *);
static LwipStatus pppoe_send_padt(NetworkInterface*, u_int, const uint8_t *);

/* internal helper functions */
static LwipStatus pppoe_xmit(struct pppoe_softc *sc, struct PacketBuffer *pb);
static struct pppoe_softc* pppoe_find_softc_by_session(u_int session, NetworkInterface*rcvif);
static struct pppoe_softc* pppoe_find_softc_by_hunique(uint8_t *token, size_t len, NetworkInterface*rcvif);

/** linked list of created pppoe interfaces */
static struct pppoe_softc *pppoe_softc_list;

/* Callbacks structure for PPP core */
// static const struct LinkCallbacks pppoe_callbacks = {
//   pppoe_connect,
//   nullptr,
//   pppoe_disconnect,
//   pppoe_destroy,
//   pppoe_write,
//   pppoe_netif_output,
//   nullptr,
//   nullptr
// };

/*
 * Create a new PPP Over Ethernet (PPPoE) connection.
 *
 * Return 0 on success, an error code on failure.
 */
PppPcb *pppoe_create(NetworkInterface*pppif,
                     NetworkInterface*ethif,
                     const char *service_name,
                     const char *concentrator_name,
                     ppp_link_status_cb_fn link_status_cb,
                     void* ctx_cb)
{
    // sc = (struct pppoe_softc *)LWIP_MEMPOOL_ALLOC(PPPOE_IF);
  struct pppoe_softc* sc = new pppoe_softc;
    if (sc == nullptr) {
    return nullptr;
  }

  PppPcb* ppp = init_ppp_pcb(pppif, sc, link_status_cb, ctx_cb);
  if (ppp == nullptr) {
      delete sc;
    return nullptr;
  }

  memset(sc, 0, sizeof(struct pppoe_softc));
  sc->pcb = ppp;
  sc->sc_ethif = ethif;
  /* put the new interface at the head of the list */
  sc->next = pppoe_softc_list;
  pppoe_softc_list = sc;
  return ppp;
}

/* Called by PPP core */
static LwipStatus pppoe_write(PppPcb *ppp, uint8_t *ctx, struct PacketBuffer *p) {
  struct pppoe_softc *sc = (struct pppoe_softc *)ctx; /* skip address & flags */
  // pbuf_remove_header(p, 2);

  // struct PacketBuffer* ph = pbuf_alloc();
    PacketBuffer ph{};
  if(!ph) {

    free_pkt_buf(p);
    return ERR_MEM;
  }

  // pbuf_remove_header(ph, PPPOE_HEADERLEN); /* hide PPPoE header */
  // pbuf_cat(ph, p);


  LwipStatus ret = pppoe_xmit(sc, ph);
  if (ret != STATUS_OK) {

    return ret;
  }


  return STATUS_OK;
}

/* Called by PPP core */
static LwipStatus pppoe_netif_output(PppPcb *ppp, uint8_t *ctx, struct PacketBuffer *p, u_short protocol) {
  struct pppoe_softc *sc = (struct pppoe_softc *)ctx;
  LwipStatus err; /* @todo: try to use pbuf_header() here! */
  // struct PacketBuffer* pb = pbuf_alloc(,);
    PacketBuffer pb{};
  if(!pb) {

    return ERR_MEM;
  }

  // pbuf_remove_header(pb, PPPOE_HEADERLEN);

  uint8_t* pl = (uint8_t*)pb->payload;
  PUTSHORT(protocol, pl);

  // pbuf_chain(pb, p);

  auto tot_len = pb->tot_len;


  if( (err = pppoe_xmit(sc, pb)) != STATUS_OK) {

    return err;
  }

  return STATUS_OK;
}

static LwipStatus
pppoe_destroy(PppPcb *ppp, uint8_t *ctx)
{
  struct pppoe_softc *sc = (struct pppoe_softc *)ctx;
  struct pppoe_softc*freep;
  sys_untimeout(pppoe_timeout, sc);

  /* remove interface from list */
  for (struct pppoe_softc** copp = &pppoe_softc_list; (freep = *copp); copp = &freep->next) {
    if (freep == sc) {
       *copp = freep->next;
       break;
    }
  }

  delete sc;

  return STATUS_OK;
}

/*
 * Find the interface handling the specified session.
 * Note: O(number of sessions open), this is a client-side only, mean
 * and lean implementation, so number of open sessions typically should
 * be 1.
 */
static struct pppoe_softc* pppoe_find_softc_by_session(u_int session, NetworkInterface*rcvif) {
    for (struct pppoe_softc* sc = pppoe_softc_list; sc != nullptr; sc = sc->next) {
    if (sc->sc_state == PPPOE_STATE_SESSION
        && sc->sc_session == session
         && sc->sc_ethif == rcvif) {
           return sc;
      }
  }
  return nullptr;
}

/* Check host unique token passed and return appropriate softc pointer,
 * or NULL if token is bogus. */
static struct pppoe_softc* pppoe_find_softc_by_hunique(uint8_t *token, size_t len, NetworkInterface*rcvif) {
  struct pppoe_softc *sc, *t;

  if (len != sizeof sc) {
    return nullptr;
  }
  memcpy(&t, token, len);

  for (sc = pppoe_softc_list; sc != nullptr; sc = sc->next) {
    if (sc == t) {
      break;
    }
  }

  if (sc == nullptr) {
    // PPPDEBUG(LOG_DEBUG, ("pppoe: alien host unique tag, no session found\n"));
    return nullptr;
  }

  /* should be safe to access *sc now */
  if (sc->sc_state < PPPOE_STATE_PADI_SENT || sc->sc_state >= PPPOE_STATE_SESSION) {
    // PPPDEBUG(LOG_DEBUG, ("%c%c%d: host unique tag found, but it belongs to a connection in state %d\n",
      // sc->sc_ethif->name[0], sc->sc_ethif->name[1], sc->sc_ethif->num, sc->sc_state));
    return nullptr;
  }
  if (sc->sc_ethif != rcvif) {
    // PPPDEBUG(LOG_DEBUG, ("%c%c%d: wrong interface, not accepting host unique\n",
      // sc->sc_ethif->name[0], sc->sc_ethif->name[1], sc->sc_ethif->num));
    return nullptr;
  }
  return sc;
}

/* analyze and handle a single received packet while not in session state */
void
pppoe_disc_input(NetworkInterface*netif, struct PacketBuffer *pb)
{
    const char *err_msg = nullptr;
    struct pppoetag pt;
  int err;

  /* don't do anything if there is not a single PPPoE instance */
  if (pppoe_softc_list == nullptr) {
    free_pkt_buf(pb);
    return;
  }

  // pb = pbuf_coalesce(pb, PBUF_RAW);

  struct EthHdr* ethhdr = (struct EthHdr *)pb->payload;

  uint8_t* ac_cookie = nullptr;
  uint16_t ac_cookie_len = 0;

  uint8_t* hunique = nullptr;
  size_t hunique_len = 0;

  uint16_t session = 0;
  uint16_t off = sizeof(struct EthHdr) + sizeof(struct pppoehdr);
  if (pb->len < off) {
    // PPPDEBUG(LOG_DEBUG, ("pppoe: packet too short: %d\n", pb->len));
    goto done;
  }

  struct pppoehdr* ph = (struct pppoehdr *)(ethhdr + 1);
  if (ph->vertype != PPPOE_VERTYPE) {
    // PPPDEBUG(LOG_DEBUG, ("pppoe: unknown version/type packet: 0x%x\n", ph->vertype));
    goto done;
  }
  session = lwip_ntohs(ph->session);
  uint16_t plen = lwip_ntohs(ph->plen);

  if (plen > (pb->len - off)) {
    // PPPDEBUG(LOG_DEBUG, ("pppoe: packet content does not fit: data available = %d, packet size = %u\n",
        // pb->len - off, plen));
    goto done;
  }
  if(pb->tot_len == pb->len) {
    uint16_t framelen = off + plen;
    if (framelen < pb->len) {
      /* ignore trailing garbage */
      pb->tot_len = pb->len = framelen;
    }
  }
  uint16_t tag = 0;
  size_t len = 0;
  struct pppoe_softc* sc = nullptr;
  while (off + sizeof(pt) <= pb->len) {
    memcpy(&pt, (uint8_t*)pb->payload + off, sizeof(pt));
    tag = lwip_ntohs(pt.tag);
    len = lwip_ntohs(pt.len);
    if (off + sizeof(pt) + len > pb->len) {
      // PPPDEBUG(LOG_DEBUG, ("pppoe: tag 0x%x len 0x%x is too long\n", tag, len));
      goto done;
    }
    switch (tag) {
      case PPPOE_TAG_EOL:
        goto breakbreak;
      case PPPOE_TAG_SNAME:
        break;  /* ignored */
      case PPPOE_TAG_ACNAME:
        break;  /* ignored */
      case PPPOE_TAG_HUNIQUE:
        if (sc != nullptr) {
          break;
        }

        hunique = static_cast<uint8_t*>(pb->payload) + off + sizeof(pt);
        hunique_len = len;

        sc = pppoe_find_softc_by_hunique(static_cast<uint8_t*>(pb->payload) + off + sizeof(pt), len, netif);
        break;
      case PPPOE_TAG_ACCOOKIE:
        if (ac_cookie == nullptr) {
          if (len > PPPOE_MAX_AC_COOKIE_LEN) {
            // PPPDEBUG(LOG_DEBUG, ("pppoe: AC cookie is too long: len = %d, max = %d\n", len, PPPOE_MAX_AC_COOKIE_LEN));
            goto done;
          }
          ac_cookie = (uint8_t*)pb->payload + off + sizeof(pt);
          ac_cookie_len = len;
        }
        break;

      case PPPOE_TAG_SNAME_ERR:
        err_msg = "SERVICE NAME ERROR";
        break;
      case PPPOE_TAG_ACSYS_ERR:
        err_msg = "AC SYSTEM ERROR";
        break;
      case PPPOE_TAG_GENERIC_ERR:
        err_msg = "GENERIC ERROR";
        break;

      default:
        break;
    }

    if (err_msg != nullptr) {
      char error_tmp[PPPOE_ERRORSTRING_LEN];
      uint16_t error_len = std::min(len, (size_t)(sizeof(error_tmp)-1));
      strncpy(error_tmp, (char*)pb->payload + off + sizeof(pt), error_len);
      error_tmp[error_len] = '\0';
      if (sc) {
        // PPPDEBUG(LOG_DEBUG, ("pppoe: %c%c%d: %s: %s\n", sc->sc_ethif->name[0], sc->sc_ethif->name[1], sc->sc_ethif->num, err_msg, error_tmp));
      } else {
        // PPPDEBUG(LOG_DEBUG, ("pppoe: %s: %s\n", err_msg, error_tmp));
      }
    }

    off += sizeof(pt) + len;
  }

breakbreak:;
  switch (ph->code) {
    case PPPOE_CODE_PADI:

      /*
       * got service name, concentrator name, and/or host unique.
       * ignore if we have no interfaces with IFF_PASSIVE|IFF_UP.
       */
      // if (LIST_EMPTY(&pppoe_softc_list)) {
      //   goto done;
      // }
      // LIST_FOREACH(sc, &pppoe_softc_list, sc_list) {
      //   if (!(sc->sc_sppp.pp_if.if_flags & IFF_UP)) {
      //     continue;
      //   }
      //   if (!(sc->sc_sppp.pp_if.if_flags & IFF_PASSIVE)) {
      //     continue;
      //   }
      //   if (sc->sc_state == PPPOE_STATE_INITIAL) {
      //     break;
      //   }
      // }
      if (sc == nullptr) {
        /* PPPDEBUG(LOG_DEBUG, ("pppoe: free passive interface is not found\n")); */
        goto done;
      }
      if (hunique) {
        if (sc->sc_hunique) {
          // mem_free(sc->sc_hunique);
            delete[] sc->sc_hunique;
        }
        // sc->sc_hunique = mem_malloc(hunique_len);
          sc->sc_hunique = new uint8_t[hunique_len];
        if (sc->sc_hunique == nullptr) {
          goto done;
        }
        sc->sc_hunique_len = hunique_len;
        memcpy(sc->sc_hunique, hunique, hunique_len);
      }
      // memcpy(&sc->sc_dest, eh->ether_shost, sizeof sc->sc_dest);
      sc->sc_state = PPPOE_STATE_PADO_SENT;
      pppoe_send_pado(sc);
      break;

    case PPPOE_CODE_PADR:

      /*
       * get sc from ac_cookie if IFF_PASSIVE
       */
      if (ac_cookie == nullptr) {
        /* be quiet if there is not a single pppoe instance */
        // PPPDEBUG(LOG_DEBUG, ("pppoe: received PADR but not includes ac_cookie\n"));
        goto done;
      }
      sc = pppoe_find_softc_by_hunique(ac_cookie, ac_cookie_len, netif);
      if (sc == nullptr) {
        /* be quiet if there is not a single pppoe instance */
        // if (!LIST_EMPTY(&pppoe_softc_list)) {
        //   PPPDEBUG(LOG_DEBUG, ("pppoe: received PADR but could not find request for it\n"));
        // }
        goto done;
      }
      if (sc->sc_state != PPPOE_STATE_PADO_SENT) {
        // PPPDEBUG(LOG_DEBUG, ("%c%c%d: received unexpected PADR\n", sc->sc_ethif->name[0], sc->sc_ethif->name[1], sc->sc_ethif->num));
        goto done;
      }
      if (hunique) {
        if (sc->sc_hunique) {
          // mem_free(sc->sc_hunique);
            delete[] sc->sc_hunique;
        }
        // sc->sc_hunique = mem_malloc(hunique_len);
          sc->sc_hunique = new uint8_t[hunique_len];
        if (sc->sc_hunique == nullptr) {
          goto done;
        }
        sc->sc_hunique_len = hunique_len;
        memcpy(sc->sc_hunique, hunique, hunique_len);
      }
      pppoe_send_pads(sc);
      sc->sc_state = PPPOE_STATE_SESSION;
      ppp_start(sc->pcb); /* notify upper layers */
      break;

    case PPPOE_CODE_PADO:
      if (sc == nullptr) {
        /* be quiet if there is not a single pppoe instance */
        if (pppoe_softc_list != nullptr) {
          // PPPDEBUG(LOG_DEBUG, ("pppoe: received PADO but could not find request for it\n"));
        }
        goto done;
      }
      if (sc->sc_state != PPPOE_STATE_PADI_SENT) {
        // PPPDEBUG(LOG_DEBUG, ("%c%c%d: received unexpected PADO\n", sc->sc_ethif->name[0], sc->sc_ethif->name[1], sc->sc_ethif->num));
        goto done;
      }
      if (ac_cookie) {
        sc->sc_ac_cookie_len = ac_cookie_len;
        memcpy(sc->sc_ac_cookie, ac_cookie, ac_cookie_len);
      }
      memcpy(&sc->sc_dest, ethhdr->src.addr, sizeof(sc->sc_dest.addr));
      sys_untimeout(pppoe_timeout, sc);
      sc->sc_padr_retried = 0;
      sc->sc_state = PPPOE_STATE_PADR_SENT;
      if ((err = pppoe_send_padr(sc)) != 0) {
      }
      sys_timeout_debug((5*1000) * (1 + sc->sc_padr_retried), pppoe_timeout, sc, "pppoe_timeout");
      break;
    case PPPOE_CODE_PADS:
      if (sc == nullptr) {
        goto done;
      }
      sc->sc_session = session;
      sys_untimeout(pppoe_timeout, sc);
      // PPPDEBUG(LOG_DEBUG, ("pppoe: %c%c%d: session 0x%x connected\n", sc->sc_ethif->name[0], sc->sc_ethif->name[1], sc->sc_ethif->num, session));
      sc->sc_state = PPPOE_STATE_SESSION;
      ppp_start(sc->pcb); /* notify upper layers */
      break;
    case PPPOE_CODE_PADT:
      /* Don't disconnect here, we let the LCP Echo/Reply find the fact
       * that PPP session is down. Asking the PPP stack to end the session
       * require strict checking about the PPP phase to prevent endless
       * disconnection loops.
       */

      break;
    default:
      if(sc) {
        // PPPDEBUG(LOG_DEBUG, ("%c%c%d: unknown code (0x%"X16_F") session = 0x%"X16_F"\n",
        //     sc->sc_ethif->name[0], sc->sc_ethif->name[1], sc->sc_ethif->num,
        //     (uint16_t)ph->code, session));
      } else {
        // PPPDEBUG(LOG_DEBUG, ("pppoe: unknown code (0x%x) session = 0x%x\n", (uint16_t)ph->code, session));
      }
      break;
  }

done:
  free_pkt_buf(pb);
}

void
pppoe_data_input(NetworkInterface*netif, struct PacketBuffer *pb)
{
    struct pppoehdr *ph;

  uint8_t shost[6];


  memcpy(shost, ((struct EthHdr *)pb->payload)->src.addr, sizeof(shost));

  // if (pbuf_remove_header(pb, sizeof(struct EthHdr)) != 0) {
  //   /* bail out */
  //   // PPPDEBUG(LOG_ERR, ("pppoe_data_input: pbuf_remove_header failed\n"));
  //   // LINK_STATS_INC(link.lenerr);
  //   goto drop;
  // }

  if (pb->len < sizeof(*ph)) {
    // PPPDEBUG(LOG_DEBUG, ("pppoe_data_input: could not get PPPoE header\n"));
    goto drop;
  }
  ph = (struct pppoehdr *)pb->payload;

  if (ph->vertype != PPPOE_VERTYPE) {
    // PPPDEBUG(LOG_DEBUG, ("pppoe (data): unknown version/type packet: 0x%x\n", ph->vertype));
    goto drop;
  }
  if (ph->code != 0) {
    goto drop;
  }

  uint16_t session = lwip_ntohs(ph->session);
  struct pppoe_softc* sc = pppoe_find_softc_by_session(session, netif);
  if (sc == nullptr) {

    // PPPDEBUG(LOG_DEBUG, ("pppoe: input for unknown session 0x%x, sending PADT\n", session));
    pppoe_send_padt(netif, session, shost);

    goto drop;
  }

  uint16_t plen = lwip_ntohs(ph->plen);

  // if (pbuf_remove_header(pb, PPPOE_HEADERLEN) != 0) {
  //   /* bail out */
  //   // PPPDEBUG(LOG_ERR, ("pppoe_data_input: pbuf_remove_header PPPOE_HEADERLEN failed\n"));
  //   // LINK_STATS_INC(link.lenerr);
  //   goto drop;
  // }

  // PPPDEBUG(LOG_DEBUG, ("pppoe_data_input: %c%c%d: pkthdr.len=%d, pppoe.len=%d\n",
  //       sc->sc_ethif->name[0], sc->sc_ethif->name[1], sc->sc_ethif->num,
  //       pb->len, plen));

  if (pb->tot_len < plen) {
    goto drop;
  }

  /* Dispatch the packet thereby consuming it. */
    Fsm* fsm = nullptr;
  ppp_input(sc->pcb, pb, fsm);
  return;

drop:
  free_pkt_buf(pb);
}

static LwipStatus
pppoe_output(struct pppoe_softc *sc, struct PacketBuffer *pb)
{
    /* make room for Ethernet header - should not fail */
  // if (pbuf_add_header(pb, sizeof(struct EthHdr)) != 0) {
  //   /* bail out */
  //   // PPPDEBUG(LOG_ERR, ("pppoe: %c%c%d: pppoe_output: could not allocate room for Ethernet header\n", sc->sc_ethif->name[0], sc->sc_ethif->name[1], sc->sc_ethif->num));
  //   // LINK_STATS_INC(link.lenerr);
  //   free_pkt_buf(pb);
  //   return ERR_BUF;
  // }
  struct EthHdr* ethhdr = (struct EthHdr *)pb->payload;
  uint16_t etype = sc->sc_state == PPPOE_STATE_SESSION ? ETHTYPE_PPPOE : ETHTYPE_PPPOEDISC;
  ethhdr->type = lwip_htons(etype);
  memcpy(&ethhdr->dest.addr, &sc->sc_dest.addr, sizeof(ethhdr->dest.addr));
  memcpy(&ethhdr->src.addr, &sc->sc_ethif->hwaddr, sizeof(ethhdr->src.addr));

  // PPPDEBUG(LOG_DEBUG, ("pppoe: %c%c%d (%x) state=%d, session=0x%x output -> %02"X16_F":%02"X16_F":%02"X16_F":%02"X16_F":%02"X16_F":%02"X16_F", len=%d\n",
  //     sc->sc_ethif->name[0], sc->sc_ethif->name[1], sc->sc_ethif->num, etype,
  //     sc->sc_state, sc->sc_session,
  //     sc->sc_dest.addr[0], sc->sc_dest.addr[1], sc->sc_dest.addr[2], sc->sc_dest.addr[3], sc->sc_dest.addr[4], sc->sc_dest.addr[5],
  //     pb->tot_len));

  LwipStatus res = sc->sc_ethif->linkoutput(sc->sc_ethif, pb);

  free_pkt_buf(pb);

  return res;
}

static LwipStatus
pppoe_send_padi(struct pppoe_softc *sc)
{
    int l1 = 0, l2 = 0; /* XXX: gcc */


  /* calculate length of frame (excluding ethernet header + pppoe header) */
  int len = 2 + 2 + 2 + 2 + sizeof sc;  /* service name tag is required, host unique is send too */

  lwip_assert("sizeof(struct EthHdr) + PPPOE_HEADERLEN + len <= 0xffff",
              sizeof(struct EthHdr) + PPPOE_HEADERLEN + len <= 0xffff);

  /* allocate a buffer */
  // struct PacketBuffer* pb = pbuf_alloc();
    PacketBuffer pb{};
  if (!pb) {
    return ERR_MEM;
  }
  lwip_assert("pb->tot_len == pb->len", pb->tot_len == pb->len);

  uint8_t* p = (uint8_t*)pb->payload;
  /* fill in pkt */
  PPPOE_ADD_HEADER(p, PPPOE_CODE_PADI, 0, (uint16_t)len);
  PPPOE_ADD_16(p, PPPOE_TAG_SNAME);

  {
    PPPOE_ADD_16(p, 0);
  }

  PPPOE_ADD_16(p, PPPOE_TAG_HUNIQUE);
  PPPOE_ADD_16(p, sizeof(sc));
  memcpy(p, &sc, sizeof sc);

  /* send pkt */
  return pppoe_output(sc, pb);
}

static void
pppoe_timeout(void* arg)
{
  uint32_t retry_wait;
  int err;
  struct pppoe_softc *sc = (struct pppoe_softc*)arg;



  switch (sc->sc_state) {
    case PPPOE_STATE_PADI_SENT:
      /*
       * We have two basic ways of retrying:
       *  - Quick retry mode: try a few times in short sequence
       *  - Slow retry mode: we already had a connection successfully
       *    established and will try infinitely (without user
       *    intervention)
       * We only enter slow retry mode if IFF_LINK1 (aka autodial)
       * is not set.
       */
      if (sc->sc_padi_retried < 0xff) {
        sc->sc_padi_retried++;
      }
      if (!sc->pcb->settings.persist && sc->sc_padi_retried >= PPPOE_DISC_MAXPADI) {

        {
          pppoe_abort_connect(sc);
          return;
        }
      }
      /* initialize for quick retry mode */
      retry_wait = std::min(PPPOE_DISC_TIMEOUT * sc->sc_padi_retried, PPPOE_SLOW_RETRY);
      if ((err = pppoe_send_padi(sc)) != 0) {
        sc->sc_padi_retried--;
      }
      sys_timeout_debug(retry_wait, pppoe_timeout, sc, "pppoe_timeout");
      break;

    case PPPOE_STATE_PADR_SENT:
      sc->sc_padr_retried++;
      if (sc->sc_padr_retried >= PPPOE_DISC_MAXPADR) {
        memcpy(&sc->sc_dest, ETH_BCAST_ADDR.addr, sizeof(sc->sc_dest));
        sc->sc_state = PPPOE_STATE_PADI_SENT;
        sc->sc_padr_retried = 0;
        if ((err = pppoe_send_padi(sc)) != 0) {
        }
        sys_timeout_debug((5*1000) * (1 + sc->sc_padi_retried), pppoe_timeout, sc, "pppoe_timeout");
        return;
      }
      if ((err = pppoe_send_padr(sc)) != 0) {
        sc->sc_padr_retried--;
      }
      sys_timeout_debug((5*1000) * (1 + sc->sc_padr_retried), pppoe_timeout, sc, "pppoe_timeout");
      break;
    default:
      return;  /* all done, work in peace */
  }
}

/* Start a connection (i.e. initiate discovery phase) */
static void
pppoe_connect(PppPcb *ppp, uint8_t *ctx)
{
  LwipStatus err;
  struct pppoe_softc *sc = (struct pppoe_softc *)ctx;
  sc->sc_session = 0;
  sc->sc_ac_cookie_len = 0;
  sc->sc_padi_retried = 0;
  sc->sc_padr_retried = 0;
  /* changed to real address later */
  memcpy(&sc->sc_dest, ETH_BCAST_ADDR.addr, sizeof(sc->sc_dest));

  /* wait PADI if IFF_PASSIVE */
  // if ((sc->sc_sppp.pp_if.if_flags & IFF_PASSIVE)) {
  //   return 0;
  // }


  LcpOptions* lcp_wo = &ppp->lcp_wantoptions;
  lcp_wo->mru = sc->sc_ethif->mtu-PPPOE_HEADERLEN-2; /* two byte PPP protocol discriminator, then IP data */
  lcp_wo->neg_asyncmap = false;
  lcp_wo->neg_pcompression = false;
  lcp_wo->neg_accompression = false;
  lcp_wo->passive = false;
  lcp_wo->silent = false;

  LcpOptions* lcp_ao = &ppp->lcp_allowoptions;
  lcp_ao->mru = sc->sc_ethif->mtu-PPPOE_HEADERLEN-2; /* two byte PPP protocol discriminator, then IP data */
  lcp_ao->neg_asyncmap = false;
  lcp_ao->neg_pcompression = false;
  lcp_ao->neg_accompression = false;


  IpcpOptions* ipcp_wo = &ppp->ipcp_wantoptions;
  ipcp_wo->neg_vj = false;
  ipcp_wo->old_vj = false;

  IpcpOptions* ipcp_ao = &ppp->ipcp_allowoptions;
  ipcp_ao->neg_vj = false;
  ipcp_ao->old_vj = false;


  /* save state, in case we fail to send PADI */
  sc->sc_state = PPPOE_STATE_PADI_SENT;
  if ((err = pppoe_send_padi(sc)) != 0) {
    // PPPDEBUG(LOG_DEBUG, ("pppoe: %c%c%d: failed to send PADI, error=%d\n", sc->sc_ethif->name[0], sc->sc_ethif->name[1], sc->sc_ethif->num, err));
  }
  sys_timeout_debug((5*1000), pppoe_timeout, sc, "pppoe_timeout");
}

/* disconnect */
static void
pppoe_disconnect(PppPcb *ppp, uint8_t *ctx)
{
  struct pppoe_softc *sc = (struct pppoe_softc *)ctx;

  // PPPDEBUG(LOG_DEBUG, ("pppoe: %c%c%d: disconnecting\n", sc->sc_ethif->name[0], sc->sc_ethif->name[1], sc->sc_ethif->num));
  if (sc->sc_state == PPPOE_STATE_SESSION) {
    pppoe_send_padt(sc->sc_ethif, sc->sc_session, (const uint8_t *)&sc->sc_dest);
  }

  /* stop any timer, disconnect can be called while initiating is in progress */
  sys_untimeout(pppoe_timeout, sc);
  sc->sc_state = PPPOE_STATE_INITIAL;

  if (sc->sc_hunique) {
    // mem_free(sc->sc_hunique);
      delete[] sc->sc_hunique;
    sc->sc_hunique = nullptr; /* probably not necessary, if state is initial we shouldn't have to access hunique anyway  */
  }
  sc->sc_hunique_len = 0; /* probably not necessary, if state is initial we shouldn't have to access hunique anyway  */

  ppp_link_end(ppp); /* notify upper layers */
}

/* Connection attempt aborted */
static void
pppoe_abort_connect(struct pppoe_softc *sc)
{
  // PPPDEBUG(LOG_DEBUG, ("%c%c%d: could not establish connection\n", sc->sc_ethif->name[0], sc->sc_ethif->name[1], sc->sc_ethif->num));
  sc->sc_state = PPPOE_STATE_INITIAL;
  ppp_link_failed(sc->pcb); /* notify upper layers */
}

/* Send a PADR packet */
static LwipStatus
pppoe_send_padr(struct pppoe_softc *sc)
{
    size_t len = 2 + 2 + 2 + 2 + sizeof(sc);    /* service name, host unique */

  if (sc->sc_ac_cookie_len > 0) {
    len += 2 + 2 + sc->sc_ac_cookie_len;  /* AC cookie */
  }
  lwip_assert("sizeof(struct EthHdr) + PPPOE_HEADERLEN + len <= 0xffff",
              sizeof(struct EthHdr) + PPPOE_HEADERLEN + len <= 0xffff);
  // struct PacketBuffer* pb = pbuf_alloc();
    PacketBuffer pb{};
  if (!pb) {
    return ERR_MEM;
  }
  lwip_assert("pb->tot_len == pb->len", pb->tot_len == pb->len);
  uint8_t* p = (uint8_t*)pb->payload;
  PPPOE_ADD_HEADER(p, PPPOE_CODE_PADR, 0, len);
  PPPOE_ADD_16(p, PPPOE_TAG_SNAME);

  {
    PPPOE_ADD_16(p, 0);
  }
  if (sc->sc_ac_cookie_len > 0) {
    PPPOE_ADD_16(p, PPPOE_TAG_ACCOOKIE);
    PPPOE_ADD_16(p, sc->sc_ac_cookie_len);
    memcpy(p, sc->sc_ac_cookie, sc->sc_ac_cookie_len);
    p += sc->sc_ac_cookie_len;
  }
  PPPOE_ADD_16(p, PPPOE_TAG_HUNIQUE);
  PPPOE_ADD_16(p, sizeof(sc));
  memcpy(p, &sc, sizeof sc);

  return pppoe_output(sc, pb);
}

/* send a PADT packet */
static LwipStatus
pppoe_send_padt(NetworkInterface*outgoing_if, u_int session, const uint8_t *dest)
{
    // struct PacketBuffer* pb = pbuf_alloc();
    PacketBuffer pb{};
  if (!pb) {
    return ERR_MEM;
  }
  lwip_assert("pb->tot_len == pb->len", pb->tot_len == pb->len);

  // if (pbuf_add_header(pb, sizeof(struct EthHdr))) {
  //   // PPPDEBUG(LOG_ERR, ("pppoe: pppoe_send_padt: could not allocate room for PPPoE header\n"));
  //   // LINK_STATS_INC(link.lenerr);
  //   free_pkt_buf(pb);
  //   return ERR_BUF;
  // }
  EthHdr* eth_hdr = (EthHdr *)pb->payload;
  eth_hdr->type = pp_htons(ETHTYPE_PPPOEDISC);
  memcpy(&eth_hdr->dest.addr, dest, sizeof(eth_hdr->dest.addr));
  memcpy(&eth_hdr->src.addr, &outgoing_if->hwaddr, sizeof(eth_hdr->src.addr));

  uint8_t* p = (uint8_t*)(eth_hdr + 1);
  PPPOE_ADD_HEADER(p, PPPOE_CODE_PADT, session, 0);

  LwipStatus res = outgoing_if->linkoutput(outgoing_if, pb);

  free_pkt_buf(pb);

  return res;
}

static LwipStatus
pppoe_send_pado(struct pppoe_softc *sc)
{
    /* calc length */
  size_t len = 0;
  /* include ac_cookie */
  len += 2 + 2 + sizeof(sc);
  /* include hunique */
  len += 2 + 2 + sc->sc_hunique_len;
  // struct PacketBuffer* pb = pbuf_alloc();
    PacketBuffer pb{};
  if (!pb) {
    return ERR_MEM;
  }
  lwip_assert("pb->tot_len == pb->len", pb->tot_len == pb->len);
  uint8_t* p = (uint8_t*)pb->payload;
  PPPOE_ADD_HEADER(p, PPPOE_CODE_PADO, 0, len);
  PPPOE_ADD_16(p, PPPOE_TAG_ACCOOKIE);
  PPPOE_ADD_16(p, sizeof(sc));
  memcpy(p, &sc, sizeof(sc));
  p += sizeof(sc);
  PPPOE_ADD_16(p, PPPOE_TAG_HUNIQUE);
  PPPOE_ADD_16(p, sc->sc_hunique_len);
  memcpy(p, sc->sc_hunique, sc->sc_hunique_len);
  return pppoe_output(sc, pb);
}

static LwipStatus
pppoe_send_pads(struct pppoe_softc *sc)
{
    size_t l1 = 0;  /* XXX: gcc */

  // sc->sc_session = mono_time.tv_sec % 0xff + 1;
  /* calc length */
  size_t len = 0;
  /* include hunique */
  len += 2 + 2 + 2 + 2 + sc->sc_hunique_len;  /* service name, host unique*/
  // if (sc->sc_service_name != NULL) {    /* service name tag maybe empty */
  //   l1 = strlen(sc->sc_service_name);
  //   len += l1;
  // }
  // struct PacketBuffer* pb = pbuf_alloc();
  PacketBuffer pb{};
    if (!pb) {
    return ERR_MEM;
  }
  lwip_assert("pb->tot_len == pb->len", pb->tot_len == pb->len);
  uint8_t* p = (uint8_t*)pb->payload;
  PPPOE_ADD_HEADER(p, PPPOE_CODE_PADS, sc->sc_session, len);
  PPPOE_ADD_16(p, PPPOE_TAG_SNAME);
  // if (sc->sc_service_name != NULL) {
  //   PPPOE_ADD_16(p, l1);
  //   memcpy(p, sc->sc_service_name, l1);
  //   p += l1;
  // } else {
  //   PPPOE_ADD_16(p, 0);
  // }
  PPPOE_ADD_16(p, PPPOE_TAG_HUNIQUE);
  PPPOE_ADD_16(p, sc->sc_hunique_len);
  memcpy(p, sc->sc_hunique, sc->sc_hunique_len);
  return pppoe_output(sc, pb);
}


static LwipStatus
pppoe_xmit(struct pppoe_softc *sc, struct PacketBuffer *pb)
{
    size_t len = pb->tot_len;

  /* make room for PPPoE header - should not fail */
  // if (pbuf_add_header(pb, PPPOE_HEADERLEN) != 0) {
  //   /* bail out */
  //   // PPPDEBUG(LOG_ERR, ("pppoe: %c%c%d: pppoe_xmit: could not allocate room for PPPoE header\n", sc->sc_ethif->name[0], sc->sc_ethif->name[1], sc->sc_ethif->num));
  //   // LINK_STATS_INC(link.lenerr);
  //   free_pkt_buf(pb);
  //   return ERR_BUF;
  // }

  uint8_t* p = (uint8_t*)pb->payload;
  PPPOE_ADD_HEADER(p, 0, sc->sc_session, len);

  return pppoe_output(sc, pb);
}


