//
// file: pppol2tp.cpp
//

#include <pppol2tp.h>
#include <ppp_opts.h>
#include <lwip_status.h>
#include <network_interface.h>
#include <udp.h>

#include <ppp_impl.h>
#include <lcp.h>
#include <ipcp.h>
#include <pppcrypt.h>
#include <magic.h>

/* callbacks called from PPP core */
static LwipStatus pppol2tp_write(PppPcb *ppp, uint8_t *ctx, struct PacketBuffer *p);
static LwipStatus pppol2tp_netif_output(PppPcb *ppp, uint8_t *ctx, struct PacketBuffer *p, u_short protocol);
static LwipStatus pppol2tp_destroy(PppPcb *ppp, uint8_t *ctx);    /* Destroy a L2TP control block */
static void pppol2tp_connect(PppPcb *ppp, uint8_t *ctx);    /* Be a LAC, connect to a LNS. */
static void pppol2tp_disconnect(PppPcb *ppp, uint8_t *ctx);  /* Disconnect */

 /* Prototypes for procedures local to this file. */

static void pppol2tp_dispatch_control_packet(Pppol2tpPcb *l2tp, uint16_t port, struct PacketBuffer *p, uint16_t ns, uint16_t nr);
static void pppol2tp_timeout(void* arg);
static void pppol2tp_abort_connect(Pppol2tpPcb *l2tp);
static LwipStatus pppol2tp_send_sccrq(Pppol2tpPcb *l2tp);
static LwipStatus pppol2tp_send_scccn(Pppol2tpPcb *l2tp, uint16_t ns);
static LwipStatus pppol2tp_send_icrq(Pppol2tpPcb *l2tp, uint16_t ns);
static LwipStatus pppol2tp_send_iccn(Pppol2tpPcb *l2tp, uint16_t ns);
static LwipStatus pppol2tp_send_zlb(Pppol2tpPcb *l2tp, uint16_t ns, uint16_t nr);
static LwipStatus pppol2tp_send_stopccn(Pppol2tpPcb *l2tp, uint16_t ns);
static LwipStatus pppol2tp_xmit(Pppol2tpPcb *l2tp, struct PacketBuffer *pb);
static LwipStatus pppol2tp_udp_send(Pppol2tpPcb *l2tp, struct PacketBuffer *pb);

/* Create a new L2TP session. */
PppPcb* create_pppol2tp_session(NetworkInterface* pppif,
                                NetworkInterface* netif,
                                const IpAddr* ipaddr,
                                const uint16_t port,
                                const uint8_t* secret,
                                const size_t secret_len,
                                const ppp_link_status_cb_fn link_status_cb,
                                void* ctx_cb)
{
    if (ipaddr == nullptr)
    {
        return nullptr;
    } // ReSharper disable once CppInconsistentNaming
    const auto l2tp_pcb = new Pppol2tpPcb;
    if (l2tp_pcb == nullptr)
    {
        return nullptr;
    }
    const auto udp = udp_new_ip_type(get_ip_addr_type(ipaddr));
    if (udp == nullptr)
    {
        delete l2tp_pcb;
        return nullptr;
    }
    udp_recv(udp, pppol2tp_input, l2tp_pcb);
    PppPcb* ppp = init_ppp_pcb(pppif, l2tp_pcb, link_status_cb, ctx_cb);
    if (ppp == nullptr)
    {
        udp_remove(udp);
        delete l2tp_pcb;
        return nullptr;
    }
    memset(l2tp_pcb, 0, sizeof(Pppol2tpPcb));
    l2tp_pcb->phase = PPPOL2TP_STATE_INITIAL;
    l2tp_pcb->ppp = ppp;
    l2tp_pcb->udp = udp;
    l2tp_pcb->netif = netif;
    // copy_ip_addr(l2tcp_pcb->remote_ip, *ipaddr);
    l2tp_pcb->remote_port = port;
    l2tp_pcb->secret = secret;
    l2tp_pcb->secret_len = secret_len;
    return ppp;
}

/* Called by PPP core */
static LwipStatus pppol2tp_write(PppPcb* ppp, void* ctx, struct PacketBuffer* p)
{
    const auto l2tp_pcb = static_cast<Pppol2tpPcb *>(ctx);
    struct PacketBuffer* ph = pbuf_alloc(PBUF_TRANSPORT,
                                         (uint16_t)(PPPOL2TP_OUTPUT_DATA_HEADER_LEN));
    if (!ph)
    {
        free_pkt_buf(p);
        return ERR_MEM;
    }
    pbuf_remove_header(ph, PPPOL2TP_OUTPUT_DATA_HEADER_LEN); /* hide L2TP header */
    pbuf_cat(ph, p);
    auto tot_len = ph->tot_len;
    LwipStatus ret = pppol2tp_xmit(l2tp_pcb, ph);
    if (ret != STATUS_OK)
    {
        return ret;
    }

    return STATUS_OK;
}

/* Called by PPP core */
static LwipStatus pppol2tp_netif_output(PppPcb *ppp, uint8_t *ctx, struct PacketBuffer *p, u_short protocol) {
  Pppol2tpPcb *l2tp = (Pppol2tpPcb *)ctx;
  LwipStatus err; /* @todo: try to use pbuf_header() here! */
  struct PacketBuffer* pb = pbuf_alloc(PBUF_TRANSPORT,
                                       PPPOL2TP_OUTPUT_DATA_HEADER_LEN + sizeof(protocol
                                       ));
  if(!pb) {

    return ERR_MEM;
  }

  pbuf_remove_header(pb, PPPOL2TP_OUTPUT_DATA_HEADER_LEN);

  uint8_t* pl = (uint8_t*)pb->payload;
  PUTSHORT(protocol, pl);

  pbuf_chain(pb, p);

  uint16_t tot_len = pb->tot_len;


  if( (err = pppol2tp_xmit(l2tp, pb)) != STATUS_OK) {

    return err;
  }

  return STATUS_OK;
}

/* Destroy a L2TP control block */
static LwipStatus pppol2tp_destroy(PppPcb *ppp, uint8_t *ctx) {
  Pppol2tpPcb *l2tp = (Pppol2tpPcb *)ctx;
  sys_untimeout(pppol2tp_timeout, l2tp);
  udp_remove(l2tp->udp);
  delete l2tp;
  return STATUS_OK;
}

/* Be a LAC, connect to a LNS. */
static void pppol2tp_connect(PppPcb *ppp, uint8_t *ctx) {
  LwipStatus err;
  Pppol2tpPcb *l2tp = (Pppol2tpPcb *)ctx;
  l2tp->tunnel_port = l2tp->remote_port;
  l2tp->our_ns = 0;
  l2tp->peer_nr = 0;
  l2tp->peer_ns = 0;
  l2tp->source_tunnel_id = 0;
  l2tp->remote_tunnel_id = 0;
  l2tp->source_session_id = 0;
  l2tp->remote_session_id = 0;
  /* l2tp->*_retried are cleared when used */

  LcpOptions* lcp_wo = &ppp->lcp_wantoptions;
  lcp_wo->mru = PPPOL2TP_DEFMRU;
  lcp_wo->neg_asyncmap = false;
  lcp_wo->neg_pcompression = false;
  lcp_wo->neg_accompression = false;
  lcp_wo->passive = false;
  lcp_wo->silent = false;

  LcpOptions* lcp_ao = &ppp->lcp_allowoptions;
  lcp_ao->mru = PPPOL2TP_DEFMRU;
  lcp_ao->neg_asyncmap = false;
  lcp_ao->neg_pcompression = false;
  lcp_ao->neg_accompression = false;


  IpcpOptions* ipcp_wo = &ppp->ipcp_wantoptions;
  ipcp_wo->neg_vj = false;
  ipcp_wo->old_vj = false;

  IpcpOptions* ipcp_ao = &ppp->ipcp_allowoptions;
  ipcp_ao->neg_vj = false;
  ipcp_ao->old_vj = false;


  /* Listen to a random source port, we need to do that instead of using udp_connect()
   * because the L2TP LNS might answer with its own random source port (!= 1701)
   */
  IpAddr any_addr = make_ip_addr_ip6_any();
  if (is_ip_addr_v6(&l2tp->udp->local_ip))
  {
      udp_bind(l2tp->udp, &any_addr, 0);
  }
  else
      udp_bind(l2tp->udp, &any_addr, 0);


  /* Generate random vector */
  if (l2tp->secret != nullptr) {
    magic_random_bytes(l2tp->secret_rv, sizeof(l2tp->secret_rv));
  }


  do {
    l2tp->remote_tunnel_id = magic();
  } while(l2tp->remote_tunnel_id == 0);
  /* save state, in case we fail to send SCCRQ */
  l2tp->sccrq_retried = 0;
  l2tp->phase = PPPOL2TP_STATE_SCCRQ_SENT;
  if ((err = pppol2tp_send_sccrq(l2tp)) != 0) {
    // PPPDEBUG(LOG_DEBUG, ("pppol2tp: failed to send SCCRQ, error=%d\n", err));
  }
  sys_timeout_debug((5*1000), pppol2tp_timeout, l2tp, "pppol2tp_timeout");
}

/* Disconnect */
static void pppol2tp_disconnect(PppPcb *ppp, uint8_t *ctx) {
  Pppol2tpPcb *l2tp = (Pppol2tpPcb *)ctx;

  l2tp->our_ns++;
  pppol2tp_send_stopccn(l2tp, l2tp->our_ns);

  /* stop any timer, disconnect can be called while initiating is in progress */
  sys_untimeout(pppol2tp_timeout, l2tp);
  l2tp->phase = PPPOL2TP_STATE_INITIAL;
  ppp_link_end(ppp); /* notify upper layers */
}

/* UDP Callback for incoming IPv4 L2TP frames */
static void
pppol2tp_input(void* arg,
               struct UdpPcb* pcb,
               struct PacketBuffer* p,
               const IpAddr* addr,
               uint16_t port,
               NetworkInterface* netif)
{
    auto* l2tp = static_cast<Pppol2tpPcb*>(arg);
    uint16_t hflags;
    uint16_t len = 0;
    uint16_t tunnel_id = 0;
    uint16_t session_id = 0;
    uint16_t ns = 0;
    uint16_t nr = 0;
    uint16_t offset
        = 0; /* we can't unbound a UDP pcb, thus we can still receive UDP frames after the link is closed */
    if (l2tp->phase < PPPOL2TP_STATE_SCCRQ_SENT)
    {
        goto free_and_return;
    }

  if (!compare_ip_addr(&l2tp->remote_ip, addr)) {
    goto free_and_return;
  }

  /* discard packet if port mismatch, but only if we received a SCCRP */
  if (l2tp->phase > PPPOL2TP_STATE_SCCRQ_SENT && l2tp->tunnel_port != port) {
    goto free_and_return;
  }

  /* printf("-----------\nL2TP INPUT, %d\n", p->len); */

  /* L2TP header */
  if (p->len < sizeof(hflags) + sizeof(tunnel_id) + sizeof(session_id) ) {
    goto packet_too_short;
  }

  uint8_t* inp = (uint8_t*)p->payload;
  GETSHORT(hflags, inp);

  if (hflags & PPPOL2TP_HEADERFLAG_CONTROL) {
    /* check mandatory flags for a control packet */
    if ( (hflags & PPPOL2TP_HEADERFLAG_CONTROL_MANDATORY) != PPPOL2TP_HEADERFLAG_CONTROL_MANDATORY ) {
      // PPPDEBUG(LOG_DEBUG, ("pppol2tp: mandatory header flags for control packet not set\n"));
      goto free_and_return;
    }
    /* check forbidden flags for a control packet */
    if (hflags & PPPOL2TP_HEADERFLAG_CONTROL_FORBIDDEN) {
      // PPPDEBUG(LOG_DEBUG, ("pppol2tp: forbidden header flags for control packet found\n"));
      goto free_and_return;
    }
  } else {
    /* check mandatory flags for a data packet */
    if ( (hflags & PPPOL2TP_HEADERFLAG_DATA_MANDATORY) != PPPOL2TP_HEADERFLAG_DATA_MANDATORY) {
      // PPPDEBUG(LOG_DEBUG, ("pppol2tp: mandatory header flags for data packet not set\n"));
      goto free_and_return;
    }
  }

  /* Expected header size  */
  uint16_t hlen = sizeof(hflags) + sizeof(tunnel_id) + sizeof(session_id);
  if (hflags & PPPOL2TP_HEADERFLAG_LENGTH) {
    hlen += sizeof(len);
  }
  if (hflags & PPPOL2TP_HEADERFLAG_SEQUENCE) {
    hlen += sizeof(ns) + sizeof(nr);
  }
  if (hflags & PPPOL2TP_HEADERFLAG_OFFSET) {
    hlen += sizeof(offset);
  }
  if (p->len < hlen) {
    goto packet_too_short;
  }

  if (hflags & PPPOL2TP_HEADERFLAG_LENGTH) {
    GETSHORT(len, inp);
    if (p->len < len || len < hlen) {
      goto packet_too_short;
    }
  }
  GETSHORT(tunnel_id, inp);
  GETSHORT(session_id, inp);
  if (hflags & PPPOL2TP_HEADERFLAG_SEQUENCE) {
    GETSHORT(ns, inp);
    GETSHORT(nr, inp);
  }
  if (hflags & PPPOL2TP_HEADERFLAG_OFFSET) {
    GETSHORT(offset, inp)
    if (offset > 4096) { /* don't be fooled with large offset which might overflow hlen */
      // PPPDEBUG(LOG_DEBUG, ("pppol2tp: strange packet received, offset=%d\n", offset));

        goto free_and_return;
    }
    hlen += offset;
    if (p->len < hlen) {
      goto packet_too_short;
    }
    INCPTR(offset, inp);
  }

  /* printf("HLEN = %d\n", hlen); */

  /* skip L2TP header */
  if (pbuf_remove_header(p, hlen) != 0) {
    goto free_and_return;
  }

  /* printf("LEN=%d, TUNNEL_ID=%d, SESSION_ID=%d, NS=%d, NR=%d, OFFSET=%d\n", len, tunnel_id, session_id, ns, nr, offset); */
  // PPPDEBUG(LOG_DEBUG, ("pppol2tp: input packet, len=%d, tunnel=%d, session=%d, ns=%d, nr=%d\n",
    // len, tunnel_id, session_id, ns, nr));

  /* Control packet */
  if (hflags & PPPOL2TP_HEADERFLAG_CONTROL) {
    pppol2tp_dispatch_control_packet(l2tp, port, p, ns, nr);
    goto free_and_return;
  }

  /* Data packet */
  if(l2tp->phase != PPPOL2TP_STATE_DATA) {
    goto free_and_return;
  }
  if(tunnel_id != l2tp->remote_tunnel_id) {
     // PPPDEBUG(LOG_DEBUG, ("pppol2tp: tunnel ID mismatch, assigned=%d, received=%d\n", l2tp->remote_tunnel_id, tunnel_id));
     goto free_and_return;
  }
  if(session_id != l2tp->remote_session_id) {
     // PPPDEBUG(LOG_DEBUG, ("pppol2tp: session ID mismatch, assigned=%d, received=%d\n", l2tp->remote_session_id, session_id));
     goto free_and_return;
  }
  /*
   * skip address & flags if necessary
   *
   * RFC 2661 does not specify whether the PPP frame in the L2TP payload should
   * have a HDLC header or not. We handle both cases for compatibility.
   */
  if (p->len >= 2) {
    GETSHORT(hflags, inp);
    if (hflags == 0xff03) {
      pbuf_remove_header(p, 2);
    }
  }
  /* Dispatch the packet thereby consuming it. */
    Fsm* fsm = nullptr;
  ppp_input(l2tp->ppp, p, fsm);
  return;

packet_too_short:
  // PPPDEBUG(LOG_DEBUG, ("pppol2tp: packet too short: %d\n", p->len));
free_and_return:
  free_pkt_buf(p);
}

/* L2TP Control packet entry point */
static void pppol2tp_dispatch_control_packet(Pppol2tpPcb *l2tp, uint16_t port, struct PacketBuffer *p, uint16_t ns, uint16_t nr) {
    uint16_t avpflags, vendorid, attributetype, messagetype=0;
  LwipStatus err;

  lwip_md5_context md5_ctx;
  uint8_t md5_hash[16];
  uint8_t challenge_id = 0;


  /* printf("L2TP CTRL INPUT, ns=%d, nr=%d, len=%d\n", ns, nr, p->len); */

  /* Drop unexpected packet */
  if (ns != l2tp->peer_ns) {
    // PPPDEBUG(LOG_DEBUG, ("pppol2tp: drop unexpected packet: received NS=%d, expected NS=%d\n", ns, l2tp->peer_ns));
    /*
     * In order to ensure that all messages are acknowledged properly
     * (particularly in the case of a lost ZLB ACK message), receipt
     * of duplicate messages MUST be acknowledged.
     *
     * In this very special case we Ack a packet we previously received.
     * Therefore our NS is the NR we just received. And our NR is the
     * NS we just received plus one.
     */
    if ((int16_t)(ns - l2tp->peer_ns) < 0) {
      pppol2tp_send_zlb(l2tp, nr, ns+1);
    }
    return;
  }

  l2tp->peer_nr = nr;

  /* Handle the special case of the ICCN acknowledge */
  if (l2tp->phase == PPPOL2TP_STATE_ICCN_SENT && (int16_t)(l2tp->peer_nr - l2tp->our_ns) > 0) {
    l2tp->phase = PPPOL2TP_STATE_DATA;
    sys_untimeout(pppol2tp_timeout, l2tp);
    ppp_start(l2tp->ppp); /* notify upper layers */
  }

  /* ZLB packets */
  if (p->tot_len == 0) {
    return;
  }
  /* A ZLB packet does not consume a NS slot thus we don't record the NS value for ZLB packets */
  l2tp->peer_ns = ns+1;

  p = pbuf_coalesce(p, PBUF_RAW);
  uint8_t* inp = (uint8_t*)p->payload;
  /* Decode AVPs */
  while (p->len > 0) {
    if (p->len < sizeof(avpflags) + sizeof(vendorid) + sizeof(attributetype) ) {
      return;
    }
    GETSHORT(avpflags, inp);
    uint16_t avplen = avpflags & PPPOL2TP_AVPHEADERFLAG_LENGTHMASK;
    /* printf("AVPLEN = %d\n", avplen); */
    if (p->len < avplen || avplen < sizeof(avpflags) + sizeof(vendorid) + sizeof(attributetype)) {
      return;
    }
    GETSHORT(vendorid, inp);
    GETSHORT(attributetype, inp);
    avplen -= sizeof(avpflags) + sizeof(vendorid) + sizeof(attributetype);

    /* Message type must be the first AVP */
    if (messagetype == 0) {
      if (attributetype != 0 || vendorid != 0 || avplen != sizeof(messagetype) ) {
        // PPPDEBUG(LOG_DEBUG, ("pppol2tp: message type must be the first AVP\n"));
        return;
      }
      GETSHORT(messagetype, inp);
      /* printf("Message type = %d\n", messagetype); */
      switch(messagetype) {
        /* Start Control Connection Reply */
        case PPPOL2TP_MESSAGETYPE_SCCRP:
          /* Only accept SCCRP packet if we sent a SCCRQ */
          if (l2tp->phase != PPPOL2TP_STATE_SCCRQ_SENT) {
            goto send_zlb;
          }
          break;
        /* Incoming Call Reply */
        case PPPOL2TP_MESSAGETYPE_ICRP:
          /* Only accept ICRP packet if we sent a IRCQ */
          if (l2tp->phase != PPPOL2TP_STATE_ICRQ_SENT) {
            goto send_zlb;
          }
          break;
        /* Stop Control Connection Notification */
        case PPPOL2TP_MESSAGETYPE_STOPCCN:
          pppol2tp_send_zlb(l2tp, l2tp->our_ns+1, l2tp->peer_ns); /* Ack the StopCCN before we switch to down state */
          if (l2tp->phase < PPPOL2TP_STATE_DATA) {
            pppol2tp_abort_connect(l2tp);
          } else if (l2tp->phase == PPPOL2TP_STATE_DATA) {
            /* Don't disconnect here, we let the LCP Echo/Reply find the fact
             * that PPP session is down. Asking the PPP stack to end the session
             * require strict checking about the PPP phase to prevent endless
             * disconnection loops.
             */
          }
          return;
        default:
          break;
      }
      goto nextavp;
    }

    /* Skip proprietary L2TP extensions */
    if (vendorid != 0) {
      goto skipavp;
    }

    switch (messagetype) {
      /* Start Control Connection Reply */
      case PPPOL2TP_MESSAGETYPE_SCCRP:
       switch (attributetype) {
          case PPPOL2TP_AVPTYPE_TUNNELID:
            if (avplen != sizeof(l2tp->source_tunnel_id) ) {
               // PPPDEBUG(LOG_DEBUG, ("pppol2tp: AVP Assign tunnel ID length check failed\n"));
               return;
            }
            GETSHORT(l2tp->source_tunnel_id, inp);
            // PPPDEBUG(LOG_DEBUG, ("pppol2tp: Assigned tunnel ID %d\n", l2tp->source_tunnel_id));
            goto nextavp;

          case PPPOL2TP_AVPTYPE_CHALLENGE:
            if (avplen == 0) {
               // PPPDEBUG(LOG_DEBUG, ("pppol2tp: Challenge length check failed\n"));
               return;
            }
            if (l2tp->secret == nullptr) {
              // PPPDEBUG(LOG_DEBUG, ("pppol2tp: Received challenge from peer and no secret key available\n"));
              pppol2tp_abort_connect(l2tp);
              return;
            }
            /* Generate hash of ID, secret, challenge */
            lwip_md5_init(&md5_ctx);
            lwip_md5_starts(&md5_ctx);
            challenge_id = PPPOL2TP_MESSAGETYPE_SCCCN;
            lwip_md5_update(&md5_ctx, &challenge_id, 1);
            lwip_md5_update(&md5_ctx, l2tp->secret, l2tp->secret_len);
            lwip_md5_update(&md5_ctx, inp, avplen);
            lwip_md5_finish(&md5_ctx, l2tp->challenge_hash);
            lwip_md5_free(&md5_ctx);
            l2tp->send_challenge = 1;
            goto skipavp;
          case PPPOL2TP_AVPTYPE_CHALLENGERESPONSE:
            if (avplen != PPPOL2TP_AVPTYPE_CHALLENGERESPONSE_SIZE) {
               // PPPDEBUG(LOG_DEBUG, ("pppol2tp: AVP Challenge Response length check failed\n"));
               return;
            }
            /* Generate hash of ID, secret, challenge */
            lwip_md5_init(&md5_ctx);
            lwip_md5_starts(&md5_ctx);
            challenge_id = PPPOL2TP_MESSAGETYPE_SCCRP;
            lwip_md5_update(&md5_ctx, &challenge_id, 1);
            lwip_md5_update(&md5_ctx, l2tp->secret, l2tp->secret_len);
            lwip_md5_update(&md5_ctx, l2tp->secret_rv, sizeof(l2tp->secret_rv));
            lwip_md5_finish(&md5_ctx, md5_hash);
            lwip_md5_free(&md5_ctx);
            if ( memcmp(inp, md5_hash, sizeof(md5_hash)) ) {
              // PPPDEBUG(LOG_DEBUG, ("pppol2tp: Received challenge response from peer and secret key do not match\n"));
              pppol2tp_abort_connect(l2tp);
              return;
            }
        default:
            break;
        }
        break;
      /* Incoming Call Reply */
      case PPPOL2TP_MESSAGETYPE_ICRP:
        switch (attributetype) {
         case PPPOL2TP_AVPTYPE_SESSIONID:
            if (avplen != sizeof(l2tp->source_session_id) ) {
               // PPPDEBUG(LOG_DEBUG, ("pppol2tp: AVP Assign session ID length check failed\n"));
               return;
            }
            GETSHORT(l2tp->source_session_id, inp);
            // PPPDEBUG(LOG_DEBUG, ("pppol2tp: Assigned session ID %d\n", l2tp->source_session_id));
            goto nextavp;
          default:
            break;
        }
        break;
      default:
        break;
    }

skipavp:
    INCPTR(avplen, inp);
nextavp:
    /* printf("AVP Found, vendor=%d, attribute=%d, len=%d\n", vendorid, attributetype, avplen); */
    /* next AVP */
    if (pbuf_remove_header(p, avplen + sizeof(avpflags) + sizeof(vendorid) + sizeof(attributetype)) != 0) {
      return;
    }
  }

  switch(messagetype) {
    /* Start Control Connection Reply */
    case PPPOL2TP_MESSAGETYPE_SCCRP:
      do {
        l2tp->remote_session_id = magic();
      } while(l2tp->remote_session_id == 0);
      l2tp->tunnel_port = port; /* LNS server might have chosen its own local port */
      l2tp->icrq_retried = 0;
      l2tp->phase = PPPOL2TP_STATE_ICRQ_SENT;
      l2tp->our_ns++;
      if ((err = pppol2tp_send_scccn(l2tp, l2tp->our_ns)) != 0) {
      }
      l2tp->our_ns++;
      if ((err = pppol2tp_send_icrq(l2tp, l2tp->our_ns)) != 0) {
      }
      sys_untimeout(pppol2tp_timeout, l2tp);
      sys_timeout_debug((5*1000), pppol2tp_timeout, l2tp, "pppol2tp_timeout");
      break;
    /* Incoming Call Reply */
    case PPPOL2TP_MESSAGETYPE_ICRP:
      l2tp->iccn_retried = 0;
      l2tp->phase = PPPOL2TP_STATE_ICCN_SENT;
      l2tp->our_ns++;
      if ((err = pppol2tp_send_iccn(l2tp, l2tp->our_ns)) != 0) {
      }
      sys_untimeout(pppol2tp_timeout, l2tp);
      sys_timeout_debug((5*1000), pppol2tp_timeout, l2tp, "pppol2tp_timeout");
      break;
    /* Unhandled packet, send ZLB ACK */
    default:
      goto send_zlb;
  }
  return;

send_zlb:
  pppol2tp_send_zlb(l2tp, l2tp->our_ns+1, l2tp->peer_ns);
}

/* L2TP Timeout handler */
static void pppol2tp_timeout(void* arg) {
  Pppol2tpPcb *l2tp = (Pppol2tpPcb*)arg;
  LwipStatus err;
  uint32_t retry_wait;

  // PPPDEBUG(LOG_DEBUG, ("pppol2tp: timeout\n"));

  switch (l2tp->phase) {
    case PPPOL2TP_STATE_SCCRQ_SENT:
      /* backoff wait */
      if (l2tp->sccrq_retried < 0xff) {
        l2tp->sccrq_retried++;
      }
      if (!l2tp->ppp->settings.persist && l2tp->sccrq_retried >= PPPOL2TP_MAXSCCRQ) {
        pppol2tp_abort_connect(l2tp);
        return;
      }
      retry_wait = std::min(PPPOL2TP_CONTROL_TIMEOUT * l2tp->sccrq_retried, PPPOL2TP_SLOW_RETRY);
      // PPPDEBUG(LOG_DEBUG, ("pppol2tp: sccrq_retried=%d\n", l2tp->sccrq_retried));
      if ((err = pppol2tp_send_sccrq(l2tp)) != 0) {
        l2tp->sccrq_retried--;
      }
      sys_timeout_debug(retry_wait, pppol2tp_timeout, l2tp, "pppol2tp_timeout");
      break;

    case PPPOL2TP_STATE_ICRQ_SENT:
      l2tp->icrq_retried++;
      if (l2tp->icrq_retried >= PPPOL2TP_MAXICRQ) {
        pppol2tp_abort_connect(l2tp);
        return;
      }
      // PPPDEBUG(LOG_DEBUG, ("pppol2tp: icrq_retried=%d\n", l2tp->icrq_retried));
      if ((int16_t)(l2tp->peer_nr - l2tp->our_ns) < 0) { /* the SCCCN was not acknowledged */
        if ((err = pppol2tp_send_scccn(l2tp, l2tp->our_ns -1)) != 0) {
          l2tp->icrq_retried--;
          sys_timeout_debug((5*1000), pppol2tp_timeout, l2tp, "pppol2tp_timeout");
          break;
        }
      }
      if ((err = pppol2tp_send_icrq(l2tp, l2tp->our_ns)) != 0) {
        l2tp->icrq_retried--;
      }
      sys_timeout_debug((5*1000), pppol2tp_timeout, l2tp, "pppol2tp_timeout");
      break;

    case PPPOL2TP_STATE_ICCN_SENT:
      l2tp->iccn_retried++;
      if (l2tp->iccn_retried >= PPPOL2TP_MAXICCN) {
        pppol2tp_abort_connect(l2tp);
        return;
      }
      // PPPDEBUG(LOG_DEBUG, ("pppol2tp: iccn_retried=%d\n", l2tp->iccn_retried));
      if ((err = pppol2tp_send_iccn(l2tp, l2tp->our_ns)) != 0) {
        l2tp->iccn_retried--;
      }
      sys_timeout(PPPOL2TP_CONTROL_TIMEOUT, pppol2tp_timeout, l2tp);
      break;

    default:
      return;  /* all done, work in peace */
  }
}

/* Connection attempt aborted */
static void pppol2tp_abort_connect(Pppol2tpPcb *l2tp) {
  // PPPDEBUG(LOG_DEBUG, ("pppol2tp: could not establish connection\n"));
  l2tp->phase = PPPOL2TP_STATE_INITIAL;
  ppp_link_failed(l2tp->ppp); /* notify upper layers */
}

/* Initiate a new tunnel */
static LwipStatus pppol2tp_send_sccrq(Pppol2tpPcb *l2tp) {
    size_t len = 12 + 8 + 8 + 10 + 10 + 6 + sizeof(PPPOL2TP_HOSTNAME) - 1 + 6 + sizeof(
      PPPOL2TP_VENDORNAME) - 1 + 8 + 8;

  if (l2tp->secret != nullptr) {
    len += 6 + sizeof(l2tp->secret_rv);
  }


  /* allocate a buffer */
    auto pb = pbuf_alloc(PBUF_TRANSPORT, len);
  if (pb == nullptr) {
    return ERR_MEM;
  }
  lwip_assert("pb->tot_len == pb->len", pb->tot_len == pb->len);

  uint8_t* p = (uint8_t*)pb->payload;
  /* fill in pkt */
  /* L2TP control header */
  PUTSHORT(PPPOL2TP_HEADERFLAG_CONTROL_MANDATORY, p);
  PUTSHORT(len, p); /* Length */
  PUTSHORT(0, p); /* Tunnel Id */
  PUTSHORT(0, p); /* Session Id */
  PUTSHORT(0, p); /* NS Sequence number - to peer */
  PUTSHORT(0, p); /* NR Sequence number - expected for peer */

  /* AVP - Message type */
  PUTSHORT(PPPOL2TP_AVPHEADERFLAG_MANDATORY + 8, p); /* Mandatory flag + len field */
  PUTSHORT(0, p); /* Vendor ID */
  PUTSHORT(PPPOL2TP_AVPTYPE_MESSAGE, p); /* Attribute type: Message Type */
  PUTSHORT(PPPOL2TP_MESSAGETYPE_SCCRQ, p); /* Attribute value: Message type: SCCRQ */

  /* AVP - L2TP Version */
  PUTSHORT(PPPOL2TP_AVPHEADERFLAG_MANDATORY + 8, p); /* Mandatory flag + len field */
  PUTSHORT(0, p); /* Vendor ID */
  PUTSHORT(PPPOL2TP_AVPTYPE_VERSION, p); /* Attribute type: Version */
  PUTSHORT(PPPOL2TP_VERSION, p); /* Attribute value: L2TP Version */

  /* AVP - Framing capabilities */
  PUTSHORT(PPPOL2TP_AVPHEADERFLAG_MANDATORY + 10, p); /* Mandatory flag + len field */
  PUTSHORT(0, p); /* Vendor ID */
  PUTSHORT(PPPOL2TP_AVPTYPE_FRAMINGCAPABILITIES, p); /* Attribute type: Framing capabilities */
  PUTLONG(PPPOL2TP_FRAMINGCAPABILITIES, p); /* Attribute value: Framing capabilities */

  /* AVP - Bearer capabilities */
  PUTSHORT(PPPOL2TP_AVPHEADERFLAG_MANDATORY + 10, p); /* Mandatory flag + len field */
  PUTSHORT(0, p); /* Vendor ID */
  PUTSHORT(PPPOL2TP_AVPTYPE_BEARERCAPABILITIES, p); /* Attribute type: Bearer capabilities */
  PUTLONG(PPPOL2TP_BEARERCAPABILITIES, p); /* Attribute value: Bearer capabilities */

  /* AVP - Host name */
  PUTSHORT(PPPOL2TP_AVPHEADERFLAG_MANDATORY + 6+sizeof(PPPOL2TP_HOSTNAME)-1, p); /* Mandatory flag + len field */
  PUTSHORT(0, p); /* Vendor ID */
  PUTSHORT(PPPOL2TP_AVPTYPE_HOSTNAME, p); /* Attribute type: Hostname */
  memcpy(p, PPPOL2TP_HOSTNAME, sizeof(PPPOL2TP_HOSTNAME)-1); /* Attribute value: Hostname */
  INCPTR(sizeof(PPPOL2TP_HOSTNAME)-1, p);

  /* AVP - Vendor name */
  PUTSHORT(6+sizeof(PPPOL2TP_VENDORNAME)-1, p); /* len field */
  PUTSHORT(0, p); /* Vendor ID */
  PUTSHORT(PPPOL2TP_AVPTYPE_VENDORNAME, p); /* Attribute type: Vendor name */
  memcpy(p, PPPOL2TP_VENDORNAME, sizeof(PPPOL2TP_VENDORNAME)-1); /* Attribute value: Vendor name */
  INCPTR(sizeof(PPPOL2TP_VENDORNAME)-1, p);

  /* AVP - Assign tunnel ID */
  PUTSHORT(PPPOL2TP_AVPHEADERFLAG_MANDATORY + 8, p); /* Mandatory flag + len field */
  PUTSHORT(0, p); /* Vendor ID */
  PUTSHORT(PPPOL2TP_AVPTYPE_TUNNELID, p); /* Attribute type: Tunnel ID */
  PUTSHORT(l2tp->remote_tunnel_id, p); /* Attribute value: Tunnel ID */

  /* AVP - Receive window size */
  PUTSHORT(PPPOL2TP_AVPHEADERFLAG_MANDATORY + 8, p); /* Mandatory flag + len field */
  PUTSHORT(0, p); /* Vendor ID */
  PUTSHORT(PPPOL2TP_AVPTYPE_RECEIVEWINDOWSIZE, p); /* Attribute type: Receive window size */
  PUTSHORT(PPPOL2TP_RECEIVEWINDOWSIZE, p); /* Attribute value: Receive window size */


  /* AVP - Challenge */
  if (l2tp->secret != nullptr) {
    PUTSHORT(PPPOL2TP_AVPHEADERFLAG_MANDATORY + 6 + sizeof(l2tp->secret_rv), p); /* Mandatory flag + len field */
    PUTSHORT(0, p); /* Vendor ID */
    PUTSHORT(PPPOL2TP_AVPTYPE_CHALLENGE, p); /* Attribute type: Challenge */
    memcpy(p, l2tp->secret_rv, sizeof(l2tp->secret_rv)); /* Attribute value: Random vector */
    INCPTR(sizeof(l2tp->secret_rv), p);
  }


  return pppol2tp_udp_send(l2tp, pb);
}

/* Complete tunnel establishment */
static LwipStatus pppol2tp_send_scccn(Pppol2tpPcb *l2tp, uint16_t ns) {
    /* calculate UDP packet length */
  uint16_t len = 12 + 8;

  if (l2tp->send_challenge) {
    len += 6 + sizeof(l2tp->challenge_hash);
  }


  /* allocate a buffer */
  struct PacketBuffer* pb = pbuf_alloc(PBUF_TRANSPORT, len);
  if (pb == nullptr) {
    return ERR_MEM;
  }
  lwip_assert("pb->tot_len == pb->len", pb->tot_len == pb->len);

  uint8_t* p = (uint8_t*)pb->payload;
  /* fill in pkt */
  /* L2TP control header */
  PUTSHORT(PPPOL2TP_HEADERFLAG_CONTROL_MANDATORY, p);
  PUTSHORT(len, p); /* Length */
  PUTSHORT(l2tp->source_tunnel_id, p); /* Tunnel Id */
  PUTSHORT(0, p); /* Session Id */
  PUTSHORT(ns, p); /* NS Sequence number - to peer */
  PUTSHORT(l2tp->peer_ns, p); /* NR Sequence number - expected for peer */

  /* AVP - Message type */
  PUTSHORT(PPPOL2TP_AVPHEADERFLAG_MANDATORY + 8, p); /* Mandatory flag + len field */
  PUTSHORT(0, p); /* Vendor ID */
  PUTSHORT(PPPOL2TP_AVPTYPE_MESSAGE, p); /* Attribute type: Message Type */
  PUTSHORT(PPPOL2TP_MESSAGETYPE_SCCCN, p); /* Attribute value: Message type: SCCCN */


  /* AVP - Challenge response */
  if (l2tp->send_challenge) {
    PUTSHORT(PPPOL2TP_AVPHEADERFLAG_MANDATORY + 6 + sizeof(l2tp->challenge_hash), p); /* Mandatory flag + len field */
    PUTSHORT(0, p); /* Vendor ID */
    PUTSHORT(PPPOL2TP_AVPTYPE_CHALLENGERESPONSE, p); /* Attribute type: Challenge response */
    memcpy(p, l2tp->challenge_hash, sizeof(l2tp->challenge_hash)); /* Attribute value: Computed challenge */
    INCPTR(sizeof(l2tp->challenge_hash), p);
  }


  return pppol2tp_udp_send(l2tp, pb);
}

/* Initiate a new session */
static LwipStatus pppol2tp_send_icrq(Pppol2tpPcb *l2tp, uint16_t ns) {
    /* calculate UDP packet length */
  uint16_t len = 12 + 8 + 8 + 10;

  /* allocate a buffer */
  struct PacketBuffer* pb = pbuf_alloc(PBUF_TRANSPORT, len);
  if (pb == nullptr) {
    return ERR_MEM;
  }
  lwip_assert("pb->tot_len == pb->len", pb->tot_len == pb->len);

  uint8_t* p = (uint8_t*)pb->payload;
  /* fill in pkt */
  /* L2TP control header */
  PUTSHORT(PPPOL2TP_HEADERFLAG_CONTROL_MANDATORY, p);
  PUTSHORT(len, p); /* Length */
  PUTSHORT(l2tp->source_tunnel_id, p); /* Tunnel Id */
  PUTSHORT(0, p); /* Session Id */
  PUTSHORT(ns, p); /* NS Sequence number - to peer */
  PUTSHORT(l2tp->peer_ns, p); /* NR Sequence number - expected for peer */

  /* AVP - Message type */
  PUTSHORT(PPPOL2TP_AVPHEADERFLAG_MANDATORY + 8, p); /* Mandatory flag + len field */
  PUTSHORT(0, p); /* Vendor ID */
  PUTSHORT(PPPOL2TP_AVPTYPE_MESSAGE, p); /* Attribute type: Message Type */
  PUTSHORT(PPPOL2TP_MESSAGETYPE_ICRQ, p); /* Attribute value: Message type: ICRQ */

  /* AVP - Assign session ID */
  PUTSHORT(PPPOL2TP_AVPHEADERFLAG_MANDATORY + 8, p); /* Mandatory flag + len field */
  PUTSHORT(0, p); /* Vendor ID */
  PUTSHORT(PPPOL2TP_AVPTYPE_SESSIONID, p); /* Attribute type: Session ID */
  PUTSHORT(l2tp->remote_session_id, p); /* Attribute value: Session ID */

  /* AVP - Call Serial Number */
  PUTSHORT(PPPOL2TP_AVPHEADERFLAG_MANDATORY + 10, p); /* Mandatory flag + len field */
  PUTSHORT(0, p); /* Vendor ID */
  PUTSHORT(PPPOL2TP_AVPTYPE_CALLSERIALNUMBER, p); /* Attribute type: Serial number */
  uint32_t serialnumber = magic();
  PUTLONG(serialnumber, p); /* Attribute value: Serial number */

  return pppol2tp_udp_send(l2tp, pb);
}

/* Complete tunnel establishment */
static LwipStatus pppol2tp_send_iccn(Pppol2tpPcb *l2tp, uint16_t ns) {
    /* calculate UDP packet length */
  uint16_t len = 12 + 8 + 10 + 10;

  /* allocate a buffer */
  struct PacketBuffer* pb = pbuf_alloc(PBUF_TRANSPORT, len);
  if (pb == nullptr) {
    return ERR_MEM;
  }
  lwip_assert("pb->tot_len == pb->len", pb->tot_len == pb->len);

  uint8_t* p = (uint8_t*)pb->payload;
  /* fill in pkt */
  /* L2TP control header */
  PUTSHORT(PPPOL2TP_HEADERFLAG_CONTROL_MANDATORY, p);
  PUTSHORT(len, p); /* Length */
  PUTSHORT(l2tp->source_tunnel_id, p); /* Tunnel Id */
  PUTSHORT(l2tp->source_session_id, p); /* Session Id */
  PUTSHORT(ns, p); /* NS Sequence number - to peer */
  PUTSHORT(l2tp->peer_ns, p); /* NR Sequence number - expected for peer */

  /* AVP - Message type */
  PUTSHORT(PPPOL2TP_AVPHEADERFLAG_MANDATORY + 8, p); /* Mandatory flag + len field */
  PUTSHORT(0, p); /* Vendor ID */
  PUTSHORT(PPPOL2TP_AVPTYPE_MESSAGE, p); /* Attribute type: Message Type */
  PUTSHORT(PPPOL2TP_MESSAGETYPE_ICCN, p); /* Attribute value: Message type: ICCN */

  /* AVP - Framing type */
  PUTSHORT(PPPOL2TP_AVPHEADERFLAG_MANDATORY + 10, p); /* Mandatory flag + len field */
  PUTSHORT(0, p); /* Vendor ID */
  PUTSHORT(PPPOL2TP_AVPTYPE_FRAMINGTYPE, p); /* Attribute type: Framing type */
  PUTLONG(PPPOL2TP_FRAMINGTYPE, p); /* Attribute value: Framing type */

  /* AVP - TX Connect speed */
  PUTSHORT(PPPOL2TP_AVPHEADERFLAG_MANDATORY + 10, p); /* Mandatory flag + len field */
  PUTSHORT(0, p); /* Vendor ID */
  PUTSHORT(PPPOL2TP_AVPTYPE_TXCONNECTSPEED, p); /* Attribute type: TX Connect speed */
  PUTLONG(PPPOL2TP_TXCONNECTSPEED, p); /* Attribute value: TX Connect speed */

  return pppol2tp_udp_send(l2tp, pb);
}

/* Send a ZLB ACK packet */
static LwipStatus pppol2tp_send_zlb(Pppol2tpPcb *l2tp, uint16_t ns, uint16_t nr) {
    /* calculate UDP packet length */
  uint16_t len = 12;

  /* allocate a buffer */
  struct PacketBuffer* pb = pbuf_alloc(PBUF_TRANSPORT, len);
  if (pb == nullptr) {
    return ERR_MEM;
  }
  lwip_assert("pb->tot_len == pb->len", pb->tot_len == pb->len);

  uint8_t* p = (uint8_t*)pb->payload;
  /* fill in pkt */
  /* L2TP control header */
  PUTSHORT(PPPOL2TP_HEADERFLAG_CONTROL_MANDATORY, p);
  PUTSHORT(len, p); /* Length */
  PUTSHORT(l2tp->source_tunnel_id, p); /* Tunnel Id */
  PUTSHORT(0, p); /* Session Id */
  PUTSHORT(ns, p); /* NS Sequence number - to peer */
  PUTSHORT(nr, p); /* NR Sequence number - expected for peer */

  return pppol2tp_udp_send(l2tp, pb);
}

/* Send a StopCCN packet */
static LwipStatus pppol2tp_send_stopccn(Pppol2tpPcb *l2tp, uint16_t ns) {
    /* calculate UDP packet length */
  uint16_t len = 12 + 8 + 8 + 8;

  /* allocate a buffer */
  struct PacketBuffer* pb = pbuf_alloc(PBUF_TRANSPORT, len);
  if (pb == nullptr) {
    return ERR_MEM;
  }
  lwip_assert("pb->tot_len == pb->len", pb->tot_len == pb->len);

  uint8_t* p = (uint8_t*)pb->payload;
  /* fill in pkt */
  /* L2TP control header */
  PUTSHORT(PPPOL2TP_HEADERFLAG_CONTROL_MANDATORY, p);
  PUTSHORT(len, p); /* Length */
  PUTSHORT(l2tp->source_tunnel_id, p); /* Tunnel Id */
  PUTSHORT(0, p); /* Session Id */
  PUTSHORT(ns, p); /* NS Sequence number - to peer */
  PUTSHORT(l2tp->peer_ns, p); /* NR Sequence number - expected for peer */

  /* AVP - Message type */
  PUTSHORT(PPPOL2TP_AVPHEADERFLAG_MANDATORY + 8, p); /* Mandatory flag + len field */
  PUTSHORT(0, p); /* Vendor ID */
  PUTSHORT(PPPOL2TP_AVPTYPE_MESSAGE, p); /* Attribute type: Message Type */
  PUTSHORT(PPPOL2TP_MESSAGETYPE_STOPCCN, p); /* Attribute value: Message type: StopCCN */

  /* AVP - Assign tunnel ID */
  PUTSHORT(PPPOL2TP_AVPHEADERFLAG_MANDATORY + 8, p); /* Mandatory flag + len field */
  PUTSHORT(0, p); /* Vendor ID */
  PUTSHORT(PPPOL2TP_AVPTYPE_TUNNELID, p); /* Attribute type: Tunnel ID */
  PUTSHORT(l2tp->remote_tunnel_id, p); /* Attribute value: Tunnel ID */

  /* AVP - Result code */
  PUTSHORT(PPPOL2TP_AVPHEADERFLAG_MANDATORY + 8, p); /* Mandatory flag + len field */
  PUTSHORT(0, p); /* Vendor ID */
  PUTSHORT(PPPOL2TP_AVPTYPE_RESULTCODE, p); /* Attribute type: Result code */
  PUTSHORT(PPPOL2TP_RESULTCODE, p); /* Attribute value: Result code */

  return pppol2tp_udp_send(l2tp, pb);
}

static LwipStatus pppol2tp_xmit(Pppol2tpPcb *l2tp, struct PacketBuffer *pb) {
    /* make room for L2TP header - should not fail */
  if (pbuf_add_header(pb, PPPOL2TP_OUTPUT_DATA_HEADER_LEN) != 0) {
    /* bail out */
    // PPPDEBUG(LOG_ERR, ("pppol2tp: pppol2tp_pcb: could not allocate room for L2TP header\n"));
    // LINK_STATS_INC(link.lenerr);
    free_pkt_buf(pb);
    return ERR_BUF;
  }

  uint8_t* p = (uint8_t*)pb->payload;
  PUTSHORT(PPPOL2TP_HEADERFLAG_DATA_MANDATORY, p);
  PUTSHORT(l2tp->source_tunnel_id, p); /* Tunnel Id */
  PUTSHORT(l2tp->source_session_id, p); /* Session Id */

  return pppol2tp_udp_send(l2tp, pb);
}

static LwipStatus pppol2tp_udp_send(Pppol2tpPcb *l2tp, struct PacketBuffer *pb) {
  LwipStatus err;
  if (l2tp->netif) {
    err = udp_sendto_if(l2tp->udp, pb, &l2tp->remote_ip, l2tp->tunnel_port, l2tp->netif);
  } else {
    err = udp_sendto(l2tp->udp, pb, &l2tp->remote_ip, l2tp->tunnel_port);
  }
  free_pkt_buf(pb);
  return err;
}

//#endif /* PPP_SUPPORT && PPPOL2TP_SUPPORT */
