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
#include "timeouts.h"
#include "ieee.h"
#include "ethernet.h"
#include "ipcp.h"
#include "lcp.h"
#include "pppoe.h"
#include <algorithm>







/* callbacks called from PPP core */
static bool
pppoe_write(PppPcb& ppp_pcb, PacketBuffer& pkt_buf, PppoeSoftc& sc);
static bool
pppoe_netif_output(PppPcb& ppp_pcb, PacketBuffer& pkt_buf, uint16_t protocol, PppoeSoftc& sc);
static void pppoe_connect(PppPcb *ppp, uint8_t *ctx);
static void pppoe_disconnect(PppPcb *ppp, uint8_t *ctx);
static bool
pppoe_destroy(PppPcb& ppp_pcb, PppoeSoftc& sc, std::vector<PppoeSoftc>& pppoe_softc_list);

/* management routines */
static void pppoe_abort_connect(struct PppoeSoftc *);

/* internal timeout handling */
static void pppoe_timeout(void*);

/* sending actual protocol controll packets */
static LwipStatus pppoe_send_padi(struct PppoeSoftc *);
static bool
pppoe_send_padr(PppoeSoftc&);
static bool
pppoe_send_pado(PppoeSoftc&);
static bool
pppoe_send_pads(PppoeSoftc&);
static LwipStatus pppoe_send_padt(NetworkInterface*, u_int, const uint8_t *);

/* internal helper functions */
static bool
pppoe_xmit(PppoeSoftc& sc, PacketBuffer& pb);
static std::tuple<bool, PppoeSoftc>
pppoe_find_softc_by_session(uint32_t session_id, NetworkInterface& rcv_netif, std::vector<PppoeSoftc>&
                            pppoe_softc_list);
static std::tuple<bool, PppoeSoftc>
pppoe_find_softc_by_hunique(std::vector<uint8_t>& target_host_unique_token,
                            NetworkInterface& rcv_netif,
                            std::vector<
                                PppoeSoftc>& pppoe_softc_list);

/** linked list of created pppoe interfaces */
static struct PppoeSoftc *pppoe_softc_list;

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
std::tuple<bool, PppPcb>
pppoe_create(NetworkInterface& ppp_netif,
             NetworkInterface& eth_netif,
             std::string& service_name,
             std::string& concentrator_name,
             std::vector<NetworkInterface>& interfaces,
             std::vector<PppoeSoftc>& pppoe_softc_list)
{
    // sc = (struct pppoe_softc *)LWIP_MEMPOOL_ALLOC(PPPOE_IF);
    PppoeSoftc sc{};
    PppPcb ppp_pcb{};
    bool ok = true;
    std::tie(ok, ppp_pcb) = init_ppp_pcb(ppp_netif, interfaces);

    if (!ok) {
        return std::make_tuple(false, ppp_pcb);
    }

    sc.pcb = ppp_pcb;
    sc.sc_ethif = eth_netif; /* put the new interface at the head of the list */

    pppoe_softc_list.push_back(sc);
    return std::make_tuple(ok, ppp_pcb);
}



/* Called by PPP core */
static bool
pppoe_write(PppPcb& ppp_pcb, PacketBuffer& pkt_buf, PppoeSoftc& sc)
{
    // todo: fix headers; encapsulate packet in a set of PPPoE headers.
    // todo: remove header from pkt_buf
    // pbuf_remove_header(pkt_buf, 2);
    // struct PacketBuffer* ph = pbuf_alloc();
    PacketBuffer pkt_buf2{};

    // pbuf_remove_header(pkt_buf2, PPPOE_HEADERLEN); /* hide PPPoE header */

    // pbuf_cat(pkt_buf2, pkt_buf);

    return pppoe_xmit(sc, pkt_buf2);

}

/* Called by PPP core */
static bool
pppoe_netif_output(PppPcb& ppp_pcb,
                   PacketBuffer& pkt_buf,
                   uint16_t protocol,
                   PppoeSoftc& sc)
{
    // struct PacketBuffer* pb = pbuf_alloc(,);
    PacketBuffer pb{}; // todo: remove PPPOE header
    // pbuf_remove_header(pb, PPPOE_HEADERLEN);
    // todo: set IP Protocol
    // uint8_t* pl = (uint8_t*)pb->payload;
    //PUTSHORT(protocol, pl);
    // pbuf_chain(pb, p);
    // todo: cat together packet bufs
    // auto tot_len = pb->tot_len;
    return pppoe_xmit(sc, pb);
}

/**
 * Remove a PPPoE Softc from the list.
 * This function matches iff the sc_session value of each instance is equal.
 */
static bool
pppoe_destroy(PppPcb& ppp_pcb, PppoeSoftc& sc, std::vector<PppoeSoftc>& pppoe_softc_list)
{
    struct PppoeSoftc* freep;
    auto matching_index = -1;
    for (auto i = 0; i < pppoe_softc_list.size(); i++) {
        if (pppoe_softc_list[i].sc_session == sc.sc_session) {
            matching_index = i;
        }
    }
    if (matching_index > -1) {
        pppoe_softc_list.erase(pppoe_softc_list.begin() + matching_index);
        return true;
    }
    return false;
}


/*
 * Find the interface handling the specified session.
 * Note: O(number of sessions open), this is a client-side only, mean
 * and lean implementation, so number of open sessions typically should
 * be 1.
 */
static std::tuple<bool, PppoeSoftc>
pppoe_find_softc_by_session(uint32_t session_id,
                            NetworkInterface& rcv_netif,
                            std::vector<PppoeSoftc>& pppoe_softc_list)
{
    for (auto& sc : pppoe_softc_list) {
        if (sc.sc_session == session_id) {
            return std::make_tuple(true, sc);
        }
    }
    return std::make_tuple(false, PppoeSoftc());
}

/* Check host unique token passed and return appropriate softc pointer,
 * or NULL if token is bogus. */
static std::tuple<bool, PppoeSoftc>
pppoe_find_softc_by_hunique(std::vector<uint8_t>& target_host_unique_token,
                            NetworkInterface& rcv_netif,
                            std::vector<
                                PppoeSoftc>& pppoe_softc_list)
{
    for (auto& sc : pppoe_softc_list) {
        if (std::equal(sc.sc_hunique.begin(), sc.sc_hunique.end(), target_host_unique_token.begin(), target_host_unique_token.end())) {
            return std::make_tuple(true, sc);
        }
    }

    return std::make_tuple(false, PppoeSoftc());
}

/* analyze and handle a single received packet while not in session state */
bool
pppoe_disc_input(NetworkInterface& netif, PacketBuffer& pkt_buf, std::vector<PppoeSoftc>& pppoe_softc_list)
{


    int err; /* don't do anything if there is not a single PPPoE instance */


    // pb = pbuf_coalesce(pb, PBUF_RAW);
    auto ethhdr = reinterpret_cast<struct EthHdr *>(pkt_buf.bytes.data());



    auto offset = sizeof(struct EthHdr) + sizeof(struct PppoeHdr);
    auto ok = true;
    if (offset > pkt_buf.bytes.size()) {
        return false;
    }

    auto* ph = reinterpret_cast<PppoeHdr*>(reinterpret_cast<uint8_t*>(ethhdr) + sizeof(EthHdr));
    if (ph->vertype != PPPOE_VERTYPE) {
        return false;
    }
    const auto session = lwip_ntohs(ph->session);
    auto plen = lwip_ntohs(ph->plen);

    if (plen > (pkt_buf.bytes.size() - offset)) {
        return false;
    }

    // todo: check for trailing garbage
    // if (pkt_buf->tot_len == pkt_buf->len) {
    //     uint16_t framelen = off + plen;
    //     if (framelen < pkt_buf->len) {
    //         /* ignore trailing garbage */
    //         pkt_buf->tot_len = pkt_buf->len = framelen;
    //     }
    // }

    uint16_t tag = 0;
    size_t len = 0;
    PppoeTag pt{};
    PppoeSoftc sc{};
    uint8_t* hu_ptr = nullptr;
    size_t hunique_len = 0;
    uint8_t* ac_cookie = nullptr;
    uint16_t ac_cookie_len = 0;
    std::string err_msg;
    std::vector<uint8_t> hunique;
    while (offset + sizeof(PppoeTag) <= pkt_buf.bytes.size()) {
        memcpy(&pt, pkt_buf.bytes.data() + offset, sizeof(pt));
        tag = lwip_ntohs(pt.tag);
        len = lwip_ntohs(pt.len);
        if (offset + sizeof(PppoeTag) + len > pkt_buf.bytes.size()) {
            return false;
        }

        if (tag == PPPOE_TAG_EOL) {
            // ignored
        }
        else if (tag == PPPOE_TAG_SNAME) {
            // ignored
        }
        else if (tag == PPPOE_TAG_ACNAME) {
            // ignored
        }
        else if (tag == PPPOE_TAG_HUNIQUE) {
           hu_ptr = pkt_buf.bytes.data() + offset + sizeof(PppoeTag);
           hunique_len = len;
            std::vector<uint8_t> hunique;
            for (auto i = 0; i < hunique_len; i++) {
                hunique.push_back(hu_ptr[i]);
            }
            bool ok;
            std::tie(ok, sc) = pppoe_find_softc_by_hunique(hunique, netif, pppoe_softc_list);
            // todo: what to do if ok is false
        }
        else if (tag == PPPOE_TAG_ACCOOKIE) {
            if (len > PPPOE_MAX_AC_COOKIE_LEN) {
                return false;
            }
            ac_cookie = pkt_buf.bytes.data() + offset + sizeof(PppoeTag);
            ac_cookie_len = len;
        } else if (tag == PPPOE_TAG_SNAME_ERR) {
            err_msg = "service name error";
        } else if (tag == PPPOE_TAG_ACSYS_ERR) {
            err_msg = "ac system error";
        } else if (tag == PPPOE_TAG_GENERIC_ERR) {
            err_msg = "generic error";
        } else {

        }

        if (!err_msg.empty()) {
            // todo: publish error message
        }

        offset += sizeof(PppoeTag) + len;
    }

    if (ph->code == PPPOE_CODE_PADI) {
       // got service name, concentrator name, and/or host unique. ignore if we have no interfaces with IFF_PASSIVE|IFF_UP.

        if (pppoe_softc_list.empty()) {
            return false;
        }

        for (auto& ele : pppoe_softc_list) {
            if (!ele.pcb.netif.link_up) {
                continue;
            }
            if (!ele.pcb.netif.passive) {
                continue;
            }
            if (ele.sc_state == PPPOE_STATE_INITIAL) {
                break;
            }
        }

        // todo: what do we do with ele at this point? does it become sc?

        if (!hunique.empty()) {
            if (!sc.sc_hunique.empty()) {
                sc.sc_hunique.clear();
            }
        }
        // memcpy(&sc->sc_dest, eh->ether_shost, sizeof sc->sc_dest);
        sc.sc_state = PPPOE_STATE_PADO_SENT;
        if (!pppoe_send_pado(sc)) {
            // todo: handle case where this function fails
        }
    }
    else if (ph->code == PPPOE_CODE_PADR) {
         // get sc from ac_cookie if IFF_PASSIVEif (ac_cookie == nullptr) {
            /* be quiet if there is not a single pppoe instance */
            // PPPDEBUG(LOG_DEBUG, ("pppoe: received PADR but not includes ac_cookie\n"));
            if (ac_cookie == nullptr) {
                return false;
            }
        }

        std::vector<uint8_t> ac_cookie_vector;
        for (auto i = 0; i < ac_cookie_len; i++) {
            ac_cookie_vector.push_back(ac_cookie[i]);
        }
        std::tie(ok, sc) = pppoe_find_softc_by_hunique(ac_cookie_vector, netif, pppoe_softc_list);
        if (!ok) {
            return false;
        }
        if (sc.sc_state != PPPOE_STATE_PADO_SENT) {
            // PPPDEBUG(LOG_DEBUG, ("%c%c%d: received unexpected PADR\n", sc->sc_ethif->name[0], sc->sc_ethif->name[1], sc->sc_ethif->num));
            return false;
        }
        if (!hunique.empty()) {
            sc.sc_hunique.clear();
            sc.sc_hunique = hunique;
        }
        pppoe_send_pads(sc);
        sc.sc_state = PPPOE_STATE_SESSION;
        ppp_start(sc.pcb); /* notify upper layers */
    }

breakbreak:;
    switch (ph->code) {
    case PPPOE_CODE_PADR: /*

        break;
    case PPPOE_CODE_PADO: if (sc == nullptr) {
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
        if ((err = pppoe_send_padr(sc)) != 0) { }
        sys_timeout_debug((5 * 1000) * (1 + sc->sc_padr_retried),
                          pppoe_timeout,
                          sc,
                          "pppoe_timeout");
        break;
    case PPPOE_CODE_PADS: if (sc == nullptr) {
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
              */ break;
    default: if (sc) {
            // PPPDEBUG(LOG_DEBUG, ("%c%c%d: unknown code (0x%"X16_F") session = 0x%"X16_F"\n",
            //     sc->sc_ethif->name[0], sc->sc_ethif->name[1], sc->sc_ethif->num,
            //     (uint16_t)ph->code, session));
        }
        else {
            // PPPDEBUG(LOG_DEBUG, ("pppoe: unknown code (0x%x) session = 0x%x\n", (uint16_t)ph->code, session));
        }
        break;
    }
done: free_pkt_buf(pkt_buf);
}

void
pppoe_data_input(NetworkInterface*netif, struct PacketBuffer *pb)
{
    struct PppoeHdr *ph;

  uint8_t shost[6];


  memcpy(shost, ((struct EthHdr *)pb->payload)->src.bytes, sizeof(shost));

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
  ph = (struct PppoeHdr *)pb->payload;

  if (ph->vertype != PPPOE_VERTYPE) {
    // PPPDEBUG(LOG_DEBUG, ("pppoe (data): unknown version/type packet: 0x%x\n", ph->vertype));
    goto drop;
  }
  if (ph->code != 0) {
    goto drop;
  }

  uint16_t session = lwip_ntohs(ph->session);
  struct PppoeSoftc* sc = pppoe_find_softc_by_session(session, netif,);
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


static bool
pppoe_output(PppoeSoftc& sc, PacketBuffer& pb)
{
    // todo: add ethernet header to packet
    auto* ethhdr = reinterpret_cast<EthHdr *>(pb.bytes.data());
    uint16_t ether_type = ETHTYPE_PPPOEDISC;
    if (sc.sc_state == PPPOE_STATE_SESSION) {
        ether_type = ETHTYPE_PPPOE;
    }
    ethhdr->type = lwip_htons(ether_type);
    memcpy(&ethhdr->dest.bytes, &sc.sc_dest.bytes, sizeof(ethhdr->dest.bytes));
    memcpy(&ethhdr->src.bytes, &sc.sc_ethif.mac_address, sizeof(ethhdr->src.bytes));
    auto res = false;
    // todo: transmit using link specific to netif
    // LwipStatus res = sc.sc_ethif->linkoutput(sc->sc_ethif, pb);
    return res;
}


static LwipStatus
pppoe_send_padi(struct PppoeSoftc* sc)
{
    int l1 = 0, l2 = 0; /* XXX: gcc */
    /* calculate length of frame (excluding ethernet header + pppoe header) */
    int len = 2 + 2 + 2 + 2 + sizeof sc;
    /* service name tag is required, host unique is send too */
    lwip_assert("sizeof(struct EthHdr) + PPPOE_HEADERLEN + len <= 0xffff",
                sizeof(struct EthHdr) + sizeof(struct PppoeHdr) + len <= 0xffff);
    /* allocate a buffer */ // struct PacketBuffer* pb = pbuf_alloc();
    PacketBuffer pb{};
    if (!pb) {
        return ERR_MEM;
    }
    lwip_assert("pb->tot_len == pb->len", pb->tot_len == pb->len);
    uint8_t* p = (uint8_t*)pb->payload; /* fill in pkt */
    PPPOE_ADD_HEADER(p, PPPOE_CODE_PADI, 0, (uint16_t)len);
    PPPOE_ADD_16(p, PPPOE_TAG_SNAME);
    {
        PPPOE_ADD_16(p, 0);
    }
    PPPOE_ADD_16(p, PPPOE_TAG_HUNIQUE);
    PPPOE_ADD_16(p, sizeof(sc));
    memcpy(p, &sc, sizeof sc); /* send pkt */
    return pppoe_output(sc, pb);
}

static void
pppoe_timeout(void* arg)
{
  uint32_t retry_wait;
  int err;
  struct PppoeSoftc *sc = (struct PppoeSoftc*)arg;



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
        memcpy(&sc->sc_dest, ETH_BCAST_ADDR.bytes, sizeof(sc->sc_dest));
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
  struct PppoeSoftc *sc = (struct PppoeSoftc *)ctx;
  sc->sc_session = 0;
  sc->sc_ac_cookie_len = 0;
  sc->sc_padi_retried = 0;
  sc->sc_padr_retried = 0;
  /* changed to real address later */
  memcpy(&sc->sc_dest, ETH_BCAST_ADDR.bytes, sizeof(sc->sc_dest));

  /* wait PADI if IFF_PASSIVE */
  // if ((sc->sc_sppp.pp_if.if_flags & IFF_PASSIVE)) {
  //   return 0;
  // }


  LcpOptions* lcp_wo = &ppp->lcp_wantoptions;
  lcp_wo->mru = sc->sc_ethif->mtu-sizeof(struct PppoeHdr)-2; /* two byte PPP protocol discriminator, then IP data */
  lcp_wo->neg_asyncmap = false;
  lcp_wo->neg_pcompression = false;
  lcp_wo->neg_accompression = false;
  lcp_wo->passive = false;
  lcp_wo->silent = false;

  LcpOptions* lcp_ao = &ppp->lcp_allowoptions;
  lcp_ao->mru = sc->sc_ethif->mtu-sizeof(struct PppoeHdr)-2; /* two byte PPP protocol discriminator, then IP data */
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
  struct PppoeSoftc *sc = (struct PppoeSoftc *)ctx;

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
pppoe_abort_connect(struct PppoeSoftc *sc)
{
  // PPPDEBUG(LOG_DEBUG, ("%c%c%d: could not establish connection\n", sc->sc_ethif->name[0], sc->sc_ethif->name[1], sc->sc_ethif->num));
  sc->sc_state = PPPOE_STATE_INITIAL;
  ppp_link_failed(sc->pcb); /* notify upper layers */
}

/* Send a PADR packet */
static bool
pppoe_send_padr(PppoeSoftc& sc)
{
    size_t len = 2 + 2 + 2 + 2 + sizeof(sc); /* service name, host unique */
    if (!sc.sc_ac_cookie.empty()) {
        len += 2 + 2 + sc.sc_ac_cookie.size(); /* AC cookie */
    }

    PacketBuffer pb{};

    uint8_t* p = pb.bytes.data();
    PPPOE_ADD_HEADER(p, PPPOE_CODE_PADR, 0, len);
    PPPOE_ADD_16(p, PPPOE_TAG_SNAME);
    PPPOE_ADD_16(p, 0);
    if (sc.sc_ac_cookie.size() > 0) {
        PPPOE_ADD_16(p, PPPOE_TAG_ACCOOKIE);
        PPPOE_ADD_16(p, sc.sc_ac_cookie.size());
        memcpy(p, sc.sc_ac_cookie.data(), sc.sc_ac_cookie.size());
        p += sc.sc_ac_cookie.size();
    }
    PPPOE_ADD_16(p, PPPOE_TAG_HUNIQUE);
    PPPOE_ADD_16(p, sizeof(PppoeSoftc));
    // todo: why are we trying to copy the PppoeSoftc into the packet?
    // memcpy(p, sc, sizeof(PppoeSoftc));
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
  memcpy(&eth_hdr->dest.bytes, dest, sizeof(eth_hdr->dest.bytes));
  memcpy(&eth_hdr->src.bytes, &outgoing_if->hwaddr, sizeof(eth_hdr->src.bytes));

  uint8_t* p = (uint8_t*)(eth_hdr + 1);
  PPPOE_ADD_HEADER(p, PPPOE_CODE_PADT, session, 0);

  LwipStatus res = outgoing_if->linkoutput(outgoing_if, pb);

  free_pkt_buf(pb);

  return res;
}


static bool
pppoe_send_pado(PppoeSoftc& sc)
{
    /* calc length */
    size_t len = 0; /* include ac_cookie */
    len += 2 + 2 + sizeof(sc); /* include hunique */
    len += 2 + 2 + sc.sc_hunique.size();
    PacketBuffer pb{};
    auto* p = pb.bytes.data();
    PPPOE_ADD_HEADER(p, PPPOE_CODE_PADO, 0, len);
    PPPOE_ADD_16(p, PPPOE_TAG_ACCOOKIE);
    // todo: why are we copying the PppoeSoftc data structure into the packet?
    // PPPOE_ADD_16(p, sizeof(sc));
    // memcpy(p, &sc, sizeof(sc));
    // p += sizeof(sc);
    PPPOE_ADD_16(p, PPPOE_TAG_HUNIQUE);
    PPPOE_ADD_16(p, sc.sc_hunique.size());
    memcpy(p, sc.sc_hunique.data(), sc.sc_hunique.size());
    return pppoe_output(sc, pb);
}


static bool
pppoe_send_pads(PppoeSoftc& sc)
{
    size_t l1 = 0; /* XXX: gcc */ // sc->sc_session = mono_time.tv_sec % 0xff + 1;
    /* calc length */
    size_t len = 0; /* include hunique */
    len += 2 + 2 + 2 + 2 + sc.sc_hunique.size(); /* service name, host unique*/
    if (!sc.sc_service_name.empty()) {
        l1 = sc.sc_service_name.size();
        len += l1;
    }
    PacketBuffer pb{};
    auto p = pb.bytes.data();
    PPPOE_ADD_HEADER(p, PPPOE_CODE_PADS, sc.sc_session, len);
    PPPOE_ADD_16(p, PPPOE_TAG_SNAME);
    if (!sc.sc_service_name.empty()) {
        PPPOE_ADD_16(p, l1);
        memcpy(p, sc.sc_service_name.c_str(), sc.sc_service_name.size());
        p += l1;
    }
    else {
        PPPOE_ADD_16(p, 0);
    }
    PPPOE_ADD_16(p, PPPOE_TAG_HUNIQUE);
    PPPOE_ADD_16(p, sc.sc_hunique.size());
    memcpy(p, sc.sc_hunique.data(), sc.sc_hunique.size());
    return pppoe_output(sc, pb);
}


static bool
pppoe_xmit(PppoeSoftc& sc, PacketBuffer& pkt_buf)
{
    size_t len = pkt_buf.bytes.size(); // todo: add pppoe header to packet
    // uint8_t* p = (uint8_t*)pkt_buf->payload;
    // PPPOE_ADD_HEADER(p, 0, sc->sc_session, len);
    // /* make room for PPPoE header - should not fail */
    // if (pbuf_add_header(pb, PPPOE_HEADERLEN) != 0) {
    //   /* bail out */
    //   // PPPDEBUG(LOG_ERR, ("pppoe: %c%c%d: pppoe_xmit: could not allocate room for PPPoE header\n", sc->sc_ethif->name[0], sc->sc_ethif->name[1], sc->sc_ethif->num));
    //   // LINK_STATS_INC(link.lenerr);
    //   free_pkt_buf(pb);
    //   return ERR_BUF;
    // }
    return pppoe_output(sc, pkt_buf);
}


