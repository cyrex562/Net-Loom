///
/// file: tcp_in.cpp
///
#include <algorithm>
#include <cstring>
#include <def.h>
#include <inet_chksum.h>
#include <ip6.h>
#include <ip6_addr.h>
#include <ip_addr.h>
#include <lwip_debug.h>
#include <nd6.h>
#include <network_interface.h>
#include <opt.h>
#include <tcp_priv.h>
#include <tcp_in.h>



 struct TcpSeg inseg;
 struct TcpHdr* tcphdr;
 uint16_t tcphdr_optlen;
 uint16_t tcphdr_opt1_len;
 uint8_t* tcphdr_opt2;
 uint16_t tcp_optidx;
 int32_t seqno;
 int32_t ackno;
 TcpWndSize recv_acked;
 uint16_t tcplen;
 uint8_t flags;
 uint8_t recv_flags;
 struct PacketBuffer* recv_data;
struct TcpPcb* tcp_input_pcb;
 /**
 * The initial input processing of TCP. It verifies the TCP header, demultiplexes
 * the segment between the PCBs and passes it on to tcp_process(), which implements
 * the TCP finite state machine. This function is called by the IP layer (in
 * ip_input()).
 *
 * @param p received TCP segment to process (p->payload pointing to the TCP header)
 * @param inp network interface on which this segment was received
 */
void
tcp_input(struct PacketBuffer* p, NetworkInterface* inp)
{
    IpAddrInfo* curr_dst_addr = nullptr;
    IpAddrInfo* curr_src_addr = nullptr;
    NetworkInterface* curr_netif = nullptr;
    TcpPcb* pcb;
    TcpPcbListen* lpcb;
    TcpPcb* lpcb_prev = nullptr;
    TcpPcbListen* lpcb_any = nullptr;
    lwip_assert("tcp_input: invalid pbuf", p != nullptr);
    tcphdr = reinterpret_cast<struct TcpHdr *>(p->payload);
    /// Check that TCP header fits in payload
    if (p->len < TCP_HDR_LEN)
    {
        /* drop short packets */
        Logf(true, "tcp_input: short packet (%d bytes) discarded\n", p->tot_len);
        goto dropped;
    } /// Don't even process incoming broadcasts/multicasts.
    if (is_netif_ip4_addr_bcast(curr_dst_addr, curr_netif) || ip_addr_ismulticast(
        curr_dst_addr))
    {
        goto dropped;
    } ///
    if (is_netif_checksum_enabled(inp, NETIF_CHECKSUM_CHECK_TCP))
    {
        /* Verify TCP checksum. */
        const auto chksum = ip_chksum_pseudo(p,
                                             IP_PROTO_TCP,
                                             p->tot_len,
                                             curr_src_addr,
                                             curr_dst_addr);
        if (chksum != 0)
        {
            Logf(true,
                 "tcp_input: packet discarded due to failing checksum 0x%04x\n",
                 chksum);
            goto dropped;
        }
    } /// sanity-check header length
    const uint8_t hdrlen_bytes = get_tcp_hdr_len(tcphdr, true);
    if ((hdrlen_bytes < TCP_HDR_LEN) || (hdrlen_bytes > p->tot_len))
    {
        Logf(true, "tcp_input: invalid header length (%d)\n", uint16_t(hdrlen_bytes));
        goto dropped;
    } /// Move the payload pointer in the PacketBuffer so that it points to the TCP data instead of the TCP header.
    tcphdr_optlen = uint16_t(hdrlen_bytes - TCP_HDR_LEN);
    tcphdr_opt2 = nullptr;
    if (p->len >= hdrlen_bytes)
    {
        /* all options are in the first PacketBuffer */
        tcphdr_opt1_len = tcphdr_optlen;
        pbuf_remove_header(p, hdrlen_bytes); /* cannot fail */
    }
    else
    {
        /* TCP header fits into first pbuf, options don't - data is in the next pbuf */
        /* there must be a next pbuf, due to hdrlen_bytes sanity check above */
        lwip_assert("p->next != NULL", p->next != nullptr);
        /* advance over the TCP header (cannot fail) */
        pbuf_remove_header(p, TCP_HDR_LEN);
        /* determine how long the first and second parts of the options are */
        tcphdr_opt1_len = p->len;
        uint16_t opt2len = (uint16_t)(tcphdr_optlen - tcphdr_opt1_len);
        /* options continue in the next PacketBuffer: set p to zero length and hide the
                   options in the next PacketBuffer (adjusting p->tot_len) */
        pbuf_remove_header(p, tcphdr_opt1_len);
        /* check that the options fit in the second PacketBuffer */
        if (opt2len > p->next->len)
        {
            /* drop short packets */
            Logf(true,
                 "tcp_input: options overflow second PacketBuffer (%d bytes)\n",
                 p->next->len);
            goto dropped;
        } /* remember the pointer to the second part of the options */
        tcphdr_opt2 = static_cast<uint8_t *>(p->next->payload);
        /* advance p->next to point after the options, and manually
                   adjust p->tot_len to keep it consistent with the changed p->next */
        pbuf_remove_header(p->next, opt2len);
        p->tot_len = uint16_t(p->tot_len - opt2len);
        lwip_assert("p->len == 0", p->len == 0);
        lwip_assert("p->tot_len == p->next->tot_len", p->tot_len == p->next->tot_len);
    } /* Convert fields in TCP header to host byte order. */
    tcphdr->src = lwip_ntohs(tcphdr->src);
    tcphdr->dest = lwip_ntohs(tcphdr->dest);
    seqno = tcphdr->seqno = lwip_ntohl(tcphdr->seqno);
    ackno = tcphdr->ackno = lwip_ntohl(tcphdr->ackno);
    tcphdr->wnd = lwip_ntohs(tcphdr->wnd);
    flags = tcph_flags(tcphdr);
    tcplen = p->tot_len;
    if ((flags & (TCP_FIN | TCP_SYN)) != 0)
    {
        tcplen++;
        if (tcplen < p->tot_len)
        {
            /* uint16_t overflow, cannot handle this */
            Logf(true, ("tcp_input: length uint16_t overflow, cannot handle this\n"));
            goto dropped;
        }
    } /// Demultiplex an incoming segment. First, we check if it is destined for an active connection.
    TcpPcb* prev = nullptr;
    for (pcb = tcp_active_pcbs; pcb != nullptr; pcb = pcb->next)
    {
        lwip_assert("tcp_input: active pcb->state != CLOSED", pcb->state != CLOSED);
        lwip_assert("tcp_input: active pcb->state != TIME-WAIT", pcb->state != TIME_WAIT);
        lwip_assert("tcp_input: active pcb->state != LISTEN", pcb->state != LISTEN);
        /* check if PCB is bound to specific netif */
        NetworkInterface* curr_input_netif = nullptr;
        if ((pcb->netif_idx != NETIF_NO_INDEX) && (pcb->netif_idx != get_and_inc_netif_num(
            curr_input_netif)))
        {
            prev = pcb;
            continue;
        }
        if (pcb->remote_port == tcphdr->src && pcb->local_port == tcphdr->dest &&
            compare_ip_addr(&pcb->remote_ip, curr_src_addr) && compare_ip_addr(
                &pcb->local_ip,
                curr_dst_addr))
        {
            /// Move this PCB to the front of the list so that subsequent lookups will be faster (we exploit locality in TCP segment arrivals).
            lwip_assert("tcp_input: pcb->next != pcb (before cache)", pcb->next != pcb);
            if (prev != nullptr)
            {
                prev->next = pcb->next;
                pcb->next = tcp_active_pcbs;
                tcp_active_pcbs = pcb;
            }
            else
            {
            }
            lwip_assert("tcp_input: pcb->next != pcb (after cache)", pcb->next != pcb);
            break;
        }
        prev = pcb;
    }
    if (pcb == nullptr)
    {
        /* If it did not go to an active connection, we check the connections
           in the TIME-WAIT state. */
        for (pcb = tcp_tw_pcbs; pcb != nullptr; pcb = pcb->next)
        {
            lwip_assert("tcp_input: TIME-WAIT pcb->state == TIME-WAIT",
                        pcb->state == TIME_WAIT);
            /* check if PCB is bound to specific netif */
            if ((pcb->netif_idx != NETIF_NO_INDEX) && (pcb->netif_idx != get_and_inc_netif_num(
                curr_netif)))
            {
                continue;
            }
            if (pcb->remote_port == tcphdr->src && pcb->local_port == tcphdr->dest &&
                compare_ip_addr(&pcb->remote_ip, curr_src_addr) && compare_ip_addr(
                    &pcb->local_ip,
                    curr_dst_addr))
            {
                /// We don't really care enough to move this PCB to the front of the list since we are not very likely to receive that many segments for connections in TIME-WAIT.
                Logf(true, ("tcp_input: packed for TIME_WAITing connection.\n"));
                // if (LWIP_HOOK_TCP_INPACKET_PCB(pcb,
                //                                tcphdr,
                //                                tcphdr_optlen,
                //                                tcphdr_opt1_len,
                //                                tcphdr_opt2,
                //                                p) == ERR_OK) {
                //     tcp_timewait_input(pcb);
                // }
                free_pkt_buf(p);
                return;
            }
        } /* Finally, if we still did not get a match, we check all PCBs that
           are LISTENing for incoming connections. */
        prev = nullptr;
        for (lpcb = tcp_listen_pcbs.listen_pcbs; lpcb != nullptr; lpcb = lpcb->next)
        {
            /* check if PCB is bound to specific netif */
            if ((lpcb->netif_idx != NETIF_NO_INDEX) && (lpcb->netif_idx !=
                get_and_inc_netif_num(curr_netif)))
            {
                prev = (struct TcpPcb *)lpcb;
                continue;
            }
            if (lpcb->local_port == tcphdr->dest)
            {
                if (is_ip_addr_any_type(lpcb->local_ip))
                {
                    /* found an ANY TYPE (IPv4/IPv6) match */
                    lpcb_any = lpcb;
                    lpcb_prev = prev;
                }
                else if (match_exact_ip_addr_pcb_vers((IpPcb*)lpcb, curr_dst_addr))
                {
                    if (compare_ip_addr(&lpcb->local_ip, curr_dst_addr))
                    {
                        /* found an exact match */
                        break;
                    }
                    else if (is_ip_addr_any(&lpcb->local_ip))
                    {
                        /* found an ANY-match */
                        lpcb_any = lpcb;
                        lpcb_prev = prev;
                    }
                }
            }
            prev = (struct TcpPcb *)lpcb;
        } /* first try specific local IP */
        if (lpcb == nullptr)
        {
            /* only pass to ANY if no specific local IP has been found */
            lpcb = lpcb_any;
            prev = lpcb_prev;
        }
        if (lpcb != nullptr)
        {
            /* Move this PCB to the front of the list so that subsequent
               lookups will be faster (we exploit locality in TCP segment
               arrivals). */
            if (prev != nullptr)
            {
                ((struct TcpPcbListen *)prev)->next = lpcb->next;
                /* our successor is the remainder of the listening list */
                lpcb->next = tcp_listen_pcbs.listen_pcbs;
                /* put this listening pcb at the head of the listening list */
                tcp_listen_pcbs.listen_pcbs = lpcb;
            }
            else
            {
            }
            Logf(true, ("tcp_input: packed for LISTENing connection.\n"));
            free_pkt_buf(p);
            return;
        }
    } // if ((pcb != nullptr) && LWIP_HOOK_TCP_INPACKET_PCB(pcb,
    //                                                    tcphdr,
    //                                                    tcphdr_optlen,
    //                                                    tcphdr_opt1_len,
    //                                                    tcphdr_opt2,
    //                                                    p) != ERR_OK) {
    //     free_pkt_buf(p);
    //     return;
    // }
    if (pcb != nullptr)
    {
        /* The incoming segment belongs to a connection. */
        /* Set up a tcp_seg structure. */
        inseg.next = nullptr;
        inseg.len = p->tot_len;
        inseg.p = p;
        inseg.tcphdr = tcphdr;
        recv_data = nullptr;
        recv_flags = 0;
        recv_acked = 0;
        if (flags & TCP_PSH)
        {
            p->push = true;
        } /* If there is data which was previously "refused" by upper layer */
        if (pcb->refused_data != nullptr)
        {
            if ((tcp_process_refused_data(pcb) == ERR_ABRT) || ((pcb->refused_data !=
                nullptr) && (tcplen > 0)))
            {
                /* pcb has been aborted or refused data is still refused and the new
                   segment contains data */
                if (pcb->rcv_ann_wnd == 0)
                {
                    /* this is a zero-window probe, we respond to it with current RCV.NXT
                    and drop the data segment */
                    tcp_send_empty_ack(pcb);
                }
                goto aborted;
            }
        }
        tcp_input_pcb = pcb;
        LwipStatus err = tcp_process(pcb);
        /* A return value of ERR_ABRT means that tcp_abort() was called
                  and that the pcb has been freed. If so, we don't do anything. */
        if (err != ERR_ABRT)
        {
            if (recv_flags & TF_RESET)
            {
                /* TF_RESET means that the connection was reset by the other
                   end. We then call the error callback to inform the
                   application that the connection is dead before we
                   deallocate the PCB. */
                // TCP_EVENT_ERR(pcb->state, pcb->errf, pcb->callback_arg, ERR_RST);
                tcp_pcb_remove(&tcp_active_pcbs, pcb);
                tcp_free(pcb);
            }
            else
            {
                err = STATUS_OK; /* If the application has registered a "sent" function to be
                   called when new send buffer space is available, we call it
                   now. */
                if (recv_acked > 0)
                {
                    /* recv_acked is uint32_t but the sent callback only takes a uint16_t,
                       so we might have to call it multiple times. */
                    uint32_t acked = recv_acked;
                    while (acked > 0)
                    {
                        uint16_t acked16 = (uint16_t)std::min(acked, 0xffffu);
                        acked -= acked16;
                        TCP_EVENT_SENT(pcb, (uint16_t)acked16, err);
                        if (err == ERR_ABRT)
                        {
                            goto aborted;
                        }
                    }
                    recv_acked = 0;
                }
                if (tcp_input_delayed_close(pcb))
                {
                    goto aborted;
                }
                while (recv_data != nullptr)
                {
                    struct PacketBuffer* rest = nullptr;
                    pbuf_split_64k(recv_data, &rest);
                    lwip_assert("pcb->refused_data == NULL",
                                pcb->refused_data == nullptr);
                    if (pcb->flags & TF_RXCLOSED)
                    {
                        /* received data although already closed -> abort (send RST) to
                           notify the remote host that not all data has been processed */
                        free_pkt_buf(recv_data);
                        if (rest != nullptr)
                        {
                            free_pkt_buf(rest);
                        }
                        tcp_abort(pcb);
                        goto aborted;
                    } /* Notify application that data has been received. */
                    TCP_EVENT_RECV(pcb, recv_data, ERR_OK, err);
                    if (err == ERR_ABRT)
                    {
                        if (rest != nullptr)
                        {
                            free_pkt_buf(rest);
                        }
                        goto aborted;
                    } /* If the upper layer can't receive this data, store it */
                    if (err != STATUS_OK)
                    {
                        if (rest != nullptr)
                        {
                            pbuf_cat(recv_data, rest);
                        }
                        pcb->refused_data = recv_data;
                        Logf(true,
                             ("tcp_input: keep incoming packet, because pcb is \"full\"\n"
                             ));
                        break;
                    }
                    else
                    {
                        /* Upper layer received the data, go on with the rest if > 64K */
                        recv_data = rest;
                    }
                } /* If a FIN segment was received, we call the callback
                   function with a NULL buffer to indicate EOF. */
                if (recv_flags & TF_GOT_FIN)
                {
                    if (pcb->refused_data != nullptr)
                    {
                        /* Delay this if we have refused data. */
                        pcb->refused_data->has_tcp_fin_flag = true;
                    }
                    else
                    {
                        /* correct rcv_wnd as the application won't call tcp_recved()
                           for the FIN's seqno */
                        if (pcb->rcv_wnd != TCP_WND_MAX(pcb))
                        {
                            pcb->rcv_wnd++;
                        }
                        TCP_EVENT_CLOSED(pcb, err);
                        if (err == ERR_ABRT)
                        {
                            goto aborted;
                        }
                    }
                }
                tcp_input_pcb = nullptr;
                if (tcp_input_delayed_close(pcb))
                {
                    goto aborted;
                } /* Try to send something out. */
                tcp_output(pcb);
            }
        } /* Jump target if pcb has been aborted in a callback (by calling tcp_abort()).
           Below this line, 'pcb' may not be dereferenced! */
    aborted: tcp_input_pcb = nullptr;
        recv_data = nullptr; /* give up our reference to inseg.p */
        if (inseg.p != nullptr)
        {
            free_pkt_buf(inseg.p);
            inseg.p = nullptr;
        }
    }
    else
    {
        /* If no matching PCB was found, send a TCP RST (reset) to the
           sender. */
        Logf(true, ("tcp_input: no PCB match found, resetting.\n"));
        if (!(tcph_flags(tcphdr) & TCP_RST))
        {
            tcp_rst(nullptr,
                    ackno,
                    seqno + tcplen,
                    curr_dst_addr,
                    curr_src_addr,
                    tcphdr->dest,
                    tcphdr->src);
        }
        free_pkt_buf(p);
    }
    lwip_assert("tcp_input: tcp_pcbs_sane()", tcp_pcbs_sane());
    return;
dropped: free_pkt_buf(p);
} /** Called from tcp_input to check for TF_CLOSED flag. This results in closing
 * and deallocating a pcb at the correct place to ensure noone references it
 * any more.
 * @returns 1 if the pcb has been closed and deallocated, 0 otherwise
 */
 int
tcp_input_delayed_close(struct TcpPcb* pcb)
{
    lwip_assert("tcp_input_delayed_close: invalid pcb", pcb != nullptr);
    if (recv_flags & TF_CLOSED)
    {
        /* The connection has been closed and we will deallocate the
            PCB. */
        if (!(pcb->flags & TF_RXCLOSED))
        {
            /* Connection closed although the application has only shut down the
                tx side: call the PCB's err callback and indicate the closure to
                ensure the application doesn't continue using the PCB. */
            // TCP_EVENT_ERR(pcb->state, pcb->errf, pcb->callback_arg, ERR_CLSD);
        }
        tcp_pcb_remove(&tcp_active_pcbs, pcb);
        tcp_free(pcb);
        return 1;
    }
    return 0;
} /**
 * Called by tcp_input() when a segment arrives for a listening
 * connection (from tcp_input()).
 *
 * @param pcb the tcp_pcb_listen for which a segment arrived
 *
 * @note the segment which arrived is saved in global variables, therefore only the pcb
 *       involved is passed as a parameter to this function
 */
 void
tcp_listen_input(struct TcpPcbListen* pcb)
{
     IpAddrInfo* curr_dst_addr = nullptr;
        IpAddrInfo* curr_src_addr = nullptr;
    if (flags & TCP_RST)
    {
        /* An incoming RST should be ignored. Return. */
        return;
    }
    lwip_assert("tcp_listen_input: invalid pcb", pcb != nullptr);
    /* In the LISTEN state, we check for incoming SYN segments,
        creates a new PCB, and responds with a SYN|ACK. */
    if (flags & TCP_ACK)
    {
        /* For incoming segments with the ACK flag set, respond with a
           RST. */
        Logf(true, ("tcp_listen_input: ACK in LISTEN, sending reset\n"));

        tcp_rst((const struct TcpPcb *)pcb,
                ackno,
                seqno + tcplen,
                curr_dst_addr,
                curr_src_addr,
                tcphdr->dest,
                tcphdr->src);
    }
    else if (flags & TCP_SYN)
    {
        Logf(true,
             "TCP connection request %d -> %d.\n", tcphdr->src, tcphdr->dest);
        if (pcb->accepts_pending >= pcb->backlog)
        {
            Logf(true,
                 "tcp_listen_input: listen backlog exceeded for port %d\n", tcphdr->dest
                 );
            return;
        }
        struct TcpPcb* npcb = tcp_alloc(pcb->prio);
        /* If a new PCB could not be created (probably due to lack of memory),
              we don't do anything, but rely on the sender will retransmit the
              SYN at a time when we have more memory available. */
        if (npcb == nullptr)
        {
            LwipStatus err;
            Logf(true, ("tcp_listen_input: could not allocate PCB\n"));
            // TCP_STATS_INC(tcp.memerr);
            TCP_EVENT_ACCEPT(pcb, NULL, pcb->callback_arg, ERR_MEM, err); /* err not useful here */
            return;
        }
        pcb->accepts_pending++;
        tcp_set_flags(npcb, TF_BACKLOGPEND); /* Set up the new PCB. */
        copy_ip_addr(&npcb->local_ip, curr_dst_addr);
        copy_ip_addr(&npcb->remote_ip, curr_src_addr);
        npcb->local_port = pcb->local_port;
        npcb->remote_port = tcphdr->src;
        npcb->state = SYN_RCVD;
        npcb->rcv_nxt = seqno + 1;
        npcb->rcv_ann_right_edge = npcb->rcv_nxt;
        uint32_t iss = tcp_next_iss(npcb);
        npcb->snd_wl2 = iss;
        npcb->snd_nxt = iss;
        npcb->lastack = iss;
        npcb->snd_lbb = iss;
        npcb->snd_wl1 = seqno - 1; /* initialise to seqno-1 to force window update */
        npcb->callback_arg = pcb->callback_arg;
        npcb->listener = pcb; /* inherit socket options */
        npcb->so_options = pcb->so_options & kSofInherited;
        npcb->netif_idx = pcb->netif_idx;
        /* Register the new PCB so that we can begin receiving segments
              for it. */
        // TCP_REG_ACTIVE(npcb); /* Parse any options in the SYN. */
        tcp_parseopt(npcb);
        npcb->snd_wnd = tcphdr->wnd;
        npcb->snd_wnd_max = npcb->snd_wnd;
        npcb->mss = tcp_eff_send_mss(npcb->mss, &npcb->local_ip, &npcb->remote_ip);
        if (tcp_ext_arg_invoke_callbacks_passive_open(pcb, npcb) != STATUS_OK)
        {
            tcp_abandon(npcb, 0);
            return;
        } /* Send a SYN|ACK together with the MSS option. */
        LwipStatus rc = tcp_enqueue_flags(npcb, TCP_SYN | TCP_ACK);
        if (rc != STATUS_OK)
        {
            tcp_abandon(npcb, 0);
            return;
        }
        tcp_output(npcb);
    }
} /**
 * Called by tcp_input() when a segment arrives for a connection in
 * TIME_WAIT.
 *
 * @param pcb the TcpProtoCtrlBlk for which a segment arrived
 *
 * @note the segment which arrived is saved in global variables, therefore only the pcb
 *       involved is passed as a parameter to this function
 */
 void
tcp_timewait_input(struct TcpPcb* pcb)
{
    IpAddrInfo* curr_dst_addr = nullptr;
    IpAddrInfo* curr_src_addr = nullptr;
    /* RFC 1337: in TIME_WAIT, ignore RST and ACK FINs + any 'acceptable' segments */
    /* RFC 793 3.9 Event Processing - Segment Arrives:
      * - first check sequence number - we skip that one in TIME_WAIT (always
      *   acceptable since we only send ACKs)
      * - second check the RST bit (... return) */
    if (flags & TCP_RST)
    {
        return;
    }
    lwip_assert("tcp_timewait_input: invalid pcb", pcb != nullptr);
    /* - fourth, check the SYN bit, */
    if (flags & TCP_SYN)
    {
        /* If an incoming segment is not acceptable, an acknowledgment
           should be sent in reply */
        if (TCP_SEQ_BETWEEN(seqno, pcb->rcv_nxt, pcb->rcv_nxt + pcb->rcv_wnd))
        {
            /* If the SYN is in the window it is an error, send a reset */
            tcp_rst(pcb,
                    ackno,
                    seqno + tcplen,
                    curr_dst_addr,
                    curr_src_addr,
                    tcphdr->dest,
                    tcphdr->src);
            return;
        }
    }
    else if (flags & TCP_FIN)
    {
        /* - eighth, check the FIN bit: Remain in the TIME-WAIT state.
             Restart the 2 MSL time-wait timeout.*/
        pcb->tmr = tcp_ticks;
    }
    if ((tcplen > 0))
    {
        /* Acknowledge data, FIN or out-of-window SYN */
        tcp_ack_now(pcb);
        tcp_output(pcb);
    }
} /**
 * Implements the TCP state machine. Called by tcp_input. In some
 * states tcp_receive() is called to receive data. The tcp_seg
 * argument will be freed by the caller (tcp_input()) unless the
 * recv_data pointer in the pcb is set.
 *
 * @param pcb the TcpProtoCtrlBlk for which a segment arrived
 *
 * @note the segment which arrived is saved in global variables, therefore only the pcb
 *       involved is passed as a parameter to this function
 */
 LwipStatus
tcp_process(struct TcpPcb* pcb)
{
    IpAddrInfo* curr_dst_addr = nullptr;
    IpAddrInfo* curr_src_addr = nullptr;
    uint8_t acceptable = 0;
    LwipStatus err = STATUS_OK;
    lwip_assert("tcp_process: invalid pcb", pcb != nullptr);
    /* Process incoming RST segments. */
    if (flags & TCP_RST)
    {
        /* First, determine if the reset is acceptable. */
        if (pcb->state == SYN_SENT)
        {
            /* "In the SYN-SENT state (a RST received in response to an initial SYN),
                the RST is acceptable if the ACK field acknowledges the SYN." */
            if (ackno == pcb->snd_nxt)
            {
                acceptable = 1;
            }
        }
        else
        {
            /* "In all states except SYN-SENT, all reset (RST) segments are validated
                by checking their SEQ-fields." */
            if (seqno == pcb->rcv_nxt)
            {
                acceptable = 1;
            }
            else if (TCP_SEQ_BETWEEN(seqno, pcb->rcv_nxt, pcb->rcv_nxt + pcb->rcv_wnd))
            {
                /* If the sequence number is inside the window, we send a challenge ACK
                   and wait for a re-send with matching sequence number.
                   This follows RFC 5961 section 3.2 and addresses CVE-2004-0230
                   (RST spoofing attack), which is present in RFC 793 RST handling. */
                tcp_ack_now(pcb);
            }
        }
        if (acceptable)
        {
            Logf(true, ("tcp_process: Connection RESET\n"));
            lwip_assert("tcp_input: pcb->state != CLOSED", pcb->state != CLOSED);
            recv_flags |= TF_RESET;
            tcp_clear_flags(pcb, TF_ACK_DELAY);
            return ERR_RST;
        }
        else
        {
            Logf(true,
                 "tcp_process: unacceptable reset seqno %d rcv_nxt %d\n", seqno, pcb->
                     rcv_nxt);
            Logf(true,
                 "tcp_process: unacceptable reset seqno %d rcv_nxt %d\n", seqno, pcb->
                     rcv_nxt);
            return STATUS_OK;
        }
    }
    if ((flags & TCP_SYN) && (pcb->state != SYN_SENT && pcb->state != SYN_RCVD))
    {
        /* Cope with new connection attempt after remote end crashed */
        tcp_ack_now(pcb);
        return STATUS_OK;
    }
    if ((pcb->flags & TF_RXCLOSED) == 0)
    {
        /* Update the PCB (in)activity timer unless rx is closed (see tcp_shutdown) */
        pcb->tmr = tcp_ticks;
    }
    pcb->keep_cnt_sent = 0;
    pcb->persist_probe = 0;
    tcp_parseopt(pcb); /* Do different things depending on the TCP state. */
    switch (pcb->state)
    {
    case SYN_SENT:
        Logf(true,
             "SYN-SENT: ackno %d pcb->snd_nxt %d unacked %d\n", ackno, pcb->snd_nxt,
                 lwip_ntohl(pcb->unacked->tcphdr->seqno));
        /* received SYN ACK with expected sequence number? */
        if ((flags & TCP_ACK) && (flags & TCP_SYN) && (ackno == pcb->lastack + 1))
        {
            pcb->rcv_nxt = seqno + 1;
            pcb->rcv_ann_right_edge = pcb->rcv_nxt;
            pcb->lastack = ackno;
            pcb->snd_wnd = tcphdr->wnd;
            pcb->snd_wnd_max = pcb->snd_wnd;
            pcb->snd_wl1 = seqno - 1; /* initialise to seqno - 1 to force window update */
            pcb->state = ESTABLISHED;
            pcb->mss = tcp_eff_send_mss(pcb->mss, &pcb->local_ip, &pcb->remote_ip);
            pcb->cwnd = lwip_tcp_calc_initial_cwnd(pcb->mss);
            Logf(true,
                 "tcp_process (SENT): cwnd %d ssthresh %d\n", pcb->cwnd,
                     pcb->ssthresh);
            lwip_assert("pcb->snd_queuelen > 0", (pcb->snd_queuelen > 0));
            --pcb->snd_queuelen;
            Logf(true,
                 "tcp_process: SYN-SENT --queuelen %d\n", pcb->
                     snd_queuelen);
            struct TcpSeg* rseg = pcb->unacked;
            if (rseg == nullptr)
            {
                /* might happen if tcp_output fails in tcp_rexmit_rto()
                   in which case the segment is on the unsent list */
                rseg = pcb->unsent;
                lwip_assert("no segment to free", rseg != nullptr);
                pcb->unsent = rseg->next;
            }
            else
            {
                pcb->unacked = rseg->next;
            }
            tcp_seg_free(rseg);
            /* If there's nothing left to acknowledge, stop the retransmit
                      timer, otherwise reset it to start again */
            if (pcb->unacked == nullptr)
            {
                pcb->rtime = -1;
            }
            else
            {
                pcb->rtime = 0;
                pcb->nrtx = 0;
            } /* Call the user specified function to call when successfully
         * connected. */
            TCP_EVENT_CONNECTED(pcb, STATUS_OK, err);
            if (err == ERR_ABRT)
            {
                return ERR_ABRT;
            }
            tcp_ack_now(pcb);
        } /* received ACK? possibly a half-open connection */ else if (flags & TCP_ACK)
        {
            /* send a RST to bring the other side in a non-synchronized state. */
            tcp_rst(pcb,
                    ackno,
                    seqno + tcplen,
                    curr_dst_addr,
                    curr_src_addr,
                    tcphdr->dest,
                    tcphdr->src);
            /* Resend SYN immediately (don't wait for rto timeout) to establish
                     connection faster, but do not send more SYNs than we otherwise would
                     have, or we might get caught in a loop on loopback interfaces. */
            if (pcb->nrtx < TCP_SYNMAXRTX)
            {
                pcb->rtime = 0;
                tcp_rexmit_rto(pcb);
            }
        }
        break;
    case SYN_RCVD:
        if (flags & TCP_ACK)
        {
            /* expected ACK number? */
            if (TCP_SEQ_BETWEEN(ackno, pcb->lastack + 1, pcb->snd_nxt))
            {
                pcb->state = ESTABLISHED;
                Logf(true,
                     "TCP connection established %d -> %d.\n", inseg.tcphdr->src, inseg
                                                                                   .tcphdr
                                                                                   ->dest
                     );
                if (pcb->listener == nullptr)
                {
                    /* listen pcb might be closed by now */
                    err = ERR_VAL;
                }
                else

                {
                    lwip_assert("pcb->listener->accept != NULL",
                                pcb->listener->accept_fn != nullptr);
                    tcp_backlog_accepted(pcb); /* Call the accept function. */
                    TCP_EVENT_ACCEPT(pcb->listener, pcb, pcb->callback_arg, STATUS_OK, err);
                }
                if (err != STATUS_OK)
                {
                    /* If the accept function returns with an error, we abort
                     * the connection. */ /* Already aborted? */
                    if (err != ERR_ABRT)
                    {
                        tcp_abort(pcb);
                    }
                    return ERR_ABRT;
                } /* If there was any data contained within this ACK,
           * we'd better pass it on to the application as well. */
                tcp_receive(pcb); /* Prevent ACK for SYN to generate a sent event */
                if (recv_acked != 0)
                {
                    recv_acked--;
                }
                pcb->cwnd = lwip_tcp_calc_initial_cwnd(pcb->mss);
                Logf(true,
                     "tcp_process (SYN_RCVD): cwnd %d ssthresh %d\n", pcb->
                         cwnd, pcb->ssthresh);
                if (recv_flags & TF_GOT_FIN)
                {
                    tcp_ack_now(pcb);
                    pcb->state = CLOSE_WAIT;
                }
            }
            else
            {
                /* incorrect ACK number, send RST */
                tcp_rst(pcb,
                        ackno,
                        seqno + tcplen,
                        curr_dst_addr,
                        curr_src_addr,
                        tcphdr->dest,
                        tcphdr->src);
            }
        }
        else if ((flags & TCP_SYN) && (seqno == pcb->rcv_nxt - 1))
        {
            /* Looks like another copy of the SYN - retransmit our SYN-ACK */
            tcp_rexmit(pcb);
        }
        break;
    case CLOSE_WAIT: /* FALLTHROUGH */ case ESTABLISHED:
        tcp_receive(pcb);
        if (recv_flags & TF_GOT_FIN)
        {
            /* passive close */
            tcp_ack_now(pcb);
            pcb->state = CLOSE_WAIT;
        }
        break;
    case FIN_WAIT_1:
        tcp_receive(pcb);
        if (recv_flags & TF_GOT_FIN)
        {
            if ((flags & TCP_ACK) && (ackno == pcb->snd_nxt) && pcb->unsent == nullptr)
            {
                Logf(true,
                     "TCP connection closed: FIN_WAIT_1 %d -> %d.\n", inseg.tcphdr->src,
                         inseg.tcphdr->dest);
                tcp_ack_now(pcb);
                tcp_pcb_purge(pcb);
                // TCP_RMV_ACTIVE(pcb);
                pcb->state = TIME_WAIT;
                reg_tcp_pcb(&tcp_tw_pcbs, pcb);
            }
            else
            {
                tcp_ack_now(pcb);
                pcb->state = CLOSING;
            }
        }
        else if ((flags & TCP_ACK) && (ackno == pcb->snd_nxt) && pcb->unsent == nullptr)
        {
            pcb->state = FIN_WAIT_2;
        }
        break;
    case FIN_WAIT_2:
        tcp_receive(pcb);
        if (recv_flags & TF_GOT_FIN)
        {
            Logf(true,
                 "TCP connection closed: FIN_WAIT_2 %d -> %d.\n", inseg.tcphdr->src,
                     inseg.tcphdr->dest);
            tcp_ack_now(pcb);
            tcp_pcb_purge(pcb);
            // TCP_RMV_ACTIVE(pcb);
            pcb->state = TIME_WAIT;
            reg_tcp_pcb(&tcp_tw_pcbs, pcb);
        }
        break;
    case CLOSING:
        tcp_receive(pcb);
        if ((flags & TCP_ACK) && ackno == pcb->snd_nxt && pcb->unsent == nullptr)
        {
            Logf(true,
                 "TCP connection closed: CLOSING %d -> %d.\n", inseg.tcphdr->src, inseg
                                                                                   .tcphdr
                                                                                   ->dest
                 );
            tcp_pcb_purge(pcb);
            // TCP_RMV_ACTIVE(pcb);
            pcb->state = TIME_WAIT;
            reg_tcp_pcb(&tcp_tw_pcbs, pcb);
        }
        break;
    case LAST_ACK:
        tcp_receive(pcb);
        if ((flags & TCP_ACK) && ackno == pcb->snd_nxt && pcb->unsent == nullptr)
        {
            Logf(true,
                 "TCP connection closed: LAST_ACK %d -> %d.\n", inseg.tcphdr->src, inseg
                                                                                    .tcphdr
                                                                                    ->dest
                 );
            /* bugfix #21699: don't set pcb->state to CLOSED here or we risk leaking segments */
            recv_flags |= TF_CLOSED;
        }
        break;
    default:
        break;
    }
    return STATUS_OK;
} /**
 * Insert segment into the list (segments covered with new one will be deleted)
 *
 * Called from tcp_receive()
 */
 void
tcp_oos_insert_segment(struct TcpSeg* cseg, struct TcpSeg* next)
{
    lwip_assert("tcp_oos_insert_segment: invalid cseg", cseg != nullptr);
    if (tcph_flags(cseg->tcphdr) & TCP_FIN)
    {
        /* received segment overlaps all following segments */
        tcp_segs_free(next);
        next = nullptr;
    }
    else
    {
        /* delete some following segments
           oos queue may have segments with FIN flag */
        while (next && TCP_SEQ_GEQ((seqno + cseg->len), (next->tcphdr->seqno + next->len))
        )
        {
            /* cseg with FIN already processed */
            if (tcph_flags(next->tcphdr) & TCP_FIN)
            {
                TCPH_SET_FLAG(cseg->tcphdr, TCP_FIN);
            }
            struct TcpSeg* old_seg = next;
            next = next->next;
            tcp_seg_free(old_seg);
        }
        if (next && TCP_SEQ_GT(seqno + cseg->len, next->tcphdr->seqno))
        {
            /* We need to trim the incoming segment. */
            cseg->len = (uint16_t)(next->tcphdr->seqno - seqno);
            pbuf_realloc(cseg->p);
        }
    }
    cseg->next = next;
} /** Remove segments from a list if the incoming ACK acknowledges them */
 struct TcpSeg*
tcp_free_acked_segments(struct TcpPcb* pcb,
                        struct TcpSeg* seg_list,
                        const char* dbg_list_name,
                        struct TcpSeg* dbg_other_seg_list)
{
    while (seg_list != nullptr && TCP_SEQ_LEQ(
        lwip_ntohl(seg_list->tcphdr->seqno) + tcp_tcplen(seg_list),
        ackno))
    {
        Logf(true,
             ("tcp_receive: removing %d:%d from pcb->%s\n",
                 lwip_ntohl(seg_list->tcphdr->seqno), lwip_ntohl(seg_list->tcphdr->seqno)
                 + tcp_tcplen(seg_list), dbg_list_name));
        struct TcpSeg* next = seg_list;
        seg_list = seg_list->next;
        uint16_t clen = pbuf_clen(next->p);
        Logf(true,
             "tcp_receive: queuelen %d ... ", pcb->snd_queuelen);
        lwip_assert("pcb->snd_queuelen >= pbuf_clen(next->p)",
                    (pcb->snd_queuelen >= clen));
        pcb->snd_queuelen = (uint16_t)(pcb->snd_queuelen - clen);
        recv_acked = (TcpWndSize)(recv_acked + next->len);
        tcp_seg_free(next);
        Logf(true,
             ("%d (after freeing %s)\n", pcb->snd_queuelen, dbg_list_name
             ));
        if (pcb->snd_queuelen != 0)
        {
            lwip_assert("tcp_receive: valid queue length",
                        seg_list != nullptr || dbg_other_seg_list != nullptr);
        }
    }
    return seg_list;
} /**
 * Called by tcp_process. Checks if the given segment is an ACK for outstanding
 * data, and if so frees the memory of the buffered data. Next, it places the
 * segment on any of the receive queues (pcb->recved or pcb->ooseq). If the segment
 * is buffered, the PacketBuffer is referenced by pbuf_ref so that it will not be freed until
 * it has been removed from the buffer.
 *
 * If the incoming segment constitutes an ACK for a segment that was used for RTT
 * estimation, the RTT is estimated here as well.
 *
 * Called from tcp_process().
 */
 void
tcp_receive(struct TcpPcb* pcb)
{
    int found_dupack = 0;
    lwip_assert("tcp_receive: invalid pcb", pcb != nullptr);
    lwip_assert("tcp_receive: wrong state", pcb->state >= ESTABLISHED);
    if (flags & TCP_ACK)
    {
        uint32_t right_wnd_edge = pcb->snd_wnd + pcb->snd_wl2; /* Update window. */
        if (tcp_seq_lt(pcb->snd_wl1, seqno) || (pcb->snd_wl1 == seqno &&
            tcp_seq_lt(pcb->snd_wl2, ackno)) || (pcb->snd_wl2 == ackno && (uint32_t)
            SND_WND_SCALE(pcb, tcphdr->wnd) > pcb->snd_wnd))
        {
            pcb->snd_wnd = SND_WND_SCALE(pcb, tcphdr->wnd);
            /* keep track of the biggest window announced by the remote host to calculate
                    the maximum segment size */
            if (pcb->snd_wnd_max < pcb->snd_wnd)
            {
                pcb->snd_wnd_max = pcb->snd_wnd;
            }
            pcb->snd_wl1 = seqno;
            pcb->snd_wl2 = ackno;
            Logf(true, "tcp_receive: window update %d\n", pcb->snd_wnd);
        } /* (From Stevens TCP/IP Illustrated Vol II, p970.) Its only a
     * duplicate ack if:
     * 1) It doesn't ACK new data
     * 2) length of received packet is zero (i.e. no payload)
     * 3) the advertised window hasn't changed
     * 4) There is outstanding unacknowledged data (retransmission timer running)
     * 5) The ACK is == biggest ACK sequence number so far seen (snd_una)
     *
     * If it passes all five, should process as a dupack:
     * a) dupacks < 3: do nothing
     * b) dupacks == 3: fast retransmit
     * c) dupacks > 3: increase cwnd
     *
     * If it only passes 1-3, should reset dupack counter (and add to
     * stats, which we don't do in lwIP)
     *
     * If it only passes 1, should reset dupack counter
     *
     */ /* Clause 1 */
        if (TCP_SEQ_LEQ(ackno, pcb->lastack))
        {
            /* Clause 2 */
            if (tcplen == 0)
            {
                /* Clause 3 */
                if (pcb->snd_wl2 + pcb->snd_wnd == right_wnd_edge)
                {
                    /* Clause 4 */
                    if (pcb->rtime >= 0)
                    {
                        /* Clause 5 */
                        if (pcb->lastack == ackno)
                        {
                            found_dupack = 1;
                            if ((uint8_t)(pcb->dupacks + 1) > pcb->dupacks)
                            {
                                ++pcb->dupacks;
                            }
                            if (pcb->dupacks > 3)
                            {
                                /* Inflate the congestion window */
                                tcp_wnd_inc(pcb->cwnd, pcb->mss);
                            }
                            if (pcb->dupacks >= 3)
                            {
                                /* Do fast retransmit (checked via TF_INFR, not via dupacks count) */
                                tcp_rexmit_fast(pcb);
                            }
                        }
                    }
                }
            } /* If Clause (1) or more is true, but not a duplicate ack, reset
       * count of consecutive duplicate acks */
            if (!found_dupack)
            {
                pcb->dupacks = 0;
            }
        }
        else if (TCP_SEQ_BETWEEN(ackno, pcb->lastack + 1, pcb->snd_nxt))
        {
            /* Reset the "IN Fast Retransmit" flag, since we are no longer
             in fast retransmit. Also reset the congestion window to the
             slow start threshold. */
            if (pcb->flags & TF_INFR)
            {
                tcp_clear_flags(pcb, TF_INFR);
                pcb->cwnd = pcb->ssthresh;
                pcb->bytes_acked = 0;
            } /* Reset the number of retransmissions. */
            pcb->nrtx = 0; /* Reset the retransmission time-out. */
            pcb->rto = (int16_t)((pcb->sa >> 3) + pcb->sv);
            /* Record how much data this ACK acks */
            TcpWndSize acked = (TcpWndSize)(ackno - pcb->lastack);
            /* Reset the fast retransmit variables. */
            pcb->dupacks = 0;
            pcb->lastack = ackno; /* Update the congestion control variables (cwnd and
         ssthresh). */
            if (pcb->state >= ESTABLISHED)
            {
                if (pcb->cwnd < pcb->ssthresh)
                {
                    /* limit to 1 SMSS segment during period following RTO */
                    const uint8_t num_seg = (pcb->flags & TF_RTO) ? 1 : 2;
                    /* RFC 3465, section 2.2 Slow Start */
                    const auto increase = std::min(acked, uint32_t(num_seg * pcb->mss));
                    tcp_wnd_inc(pcb->cwnd, increase);
                    Logf(true, "tcp_receive: slow start cwnd %d\n", pcb->cwnd);
                }
                else
                {
                    /* RFC 3465, section 2.1 Congestion Avoidance */
                    tcp_wnd_inc(pcb->bytes_acked, acked);
                    if (pcb->bytes_acked >= pcb->cwnd)
                    {
                        pcb->bytes_acked = (TcpWndSize)(pcb->bytes_acked - pcb->cwnd);
                        tcp_wnd_inc(pcb->cwnd, pcb->mss);
                    }
                    Logf(true,
                         "tcp_receive: congestion avoidance cwnd %d\n", pcb->cwnd);
                }
            }
            Logf(true,
                 "tcp_receive: ACK for %d, unacked->seqno %d:%d\n",
                 ackno,
                 pcb->unacked != nullptr ? lwip_ntohl(pcb->unacked->tcphdr->seqno) : 0,
                 pcb->unacked != nullptr
                     ? lwip_ntohl(pcb->unacked->tcphdr->seqno) + tcp_tcplen(pcb->unacked)
                     : 0);
            /* Remove segment from the unacknowledged list if the incoming
                    ACK acknowledges them. */
            pcb->unacked =
                tcp_free_acked_segments(pcb, pcb->unacked, "unacked", pcb->unsent);
            /* We go through the ->unsent list to see if any of the segments
                    on the list are acknowledged by the ACK. This may seem
                    strange since an "unsent" segment shouldn't be acked. The
                    rationale is that lwIP puts all outstanding segments on the
                    ->unsent list after a retransmission, so these segments may
                    in fact have been sent once. */
            pcb->unsent =
                tcp_free_acked_segments(pcb, pcb->unsent, "unsent", pcb->unacked);
            /* If there's nothing left to acknowledge, stop the retransmit
                    timer, otherwise reset it to start again */
            if (pcb->unacked == nullptr)
            {
                pcb->rtime = -1;
            }
            else
            {
                pcb->rtime = 0;
            }
            pcb->polltmr = 0;
            if (pcb->unsent == nullptr)
            {
                pcb->unsent_oversize = 0;
            }
            // if (ip_current_is_v6())
            // {
            //     /* Inform neighbor reachability of forward progress. */
            //     nd6_reachability_hint(ip6_current_src_addr());
            // }
            pcb->snd_buf = (TcpWndSize)(pcb->snd_buf + recv_acked);
            /* check if this ACK ends our retransmission of in-flight data */
            if (pcb->flags & TF_RTO)
            {
                /* RTO is done if
                    1) both queues are empty or
                    2) unacked is empty and unsent head contains data not part of RTO or
                    3) unacked head contains data not part of RTO */
                if (pcb->unacked == nullptr)
                {
                    if ((pcb->unsent == nullptr) || (TCP_SEQ_LEQ(
                        pcb->rto_end,
                        lwip_ntohl(pcb->unsent->tcphdr->seqno))))
                    {
                        tcp_clear_flags(pcb, TF_RTO);
                    }
                }
                else if (TCP_SEQ_LEQ(pcb->rto_end,
                                     lwip_ntohl(pcb->unacked->tcphdr->seqno)))
                {
                    tcp_clear_flags(pcb, TF_RTO);
                }
            } /* End of ACK for new data processing. */
        }
        else
        {
            /* Out of sequence ACK, didn't really ack anything */
            tcp_send_empty_ack(pcb);
        }
        Logf(true,
             "tcp_receive: pcb->rttest %d rtseq %d ackno %d\n", pcb->rttest, pcb->rtseq,
                 ackno); /* RTT estimation calculations. This is done by checking if the
       incoming segment acknowledges the segment we use to take a
       round-trip time measurement. */
        if (pcb->rttest && tcp_seq_lt(pcb->rtseq, ackno))
        {
            /* diff between this shouldn't exceed 32K since this are tcp timer ticks
               and a round-trip shouldn't be that long... */
            int16_t m = (int16_t)(tcp_ticks - pcb->rttest);
            Logf(true,
                "tcp_receive: experienced rtt %d ticks (%d msec).\n", m, (uint16_t)(m *
                     TCP_SLOW_INTERVAL));
            /* This is taken directly from VJs original code in his paper */
            m = (int16_t)(m - (pcb->sa >> 3));
            pcb->sa = (int16_t)(pcb->sa + m);
            if (m < 0)
            {
                m = (int16_t)- m;
            }
            m = (int16_t)(m - (pcb->sv >> 2));
            pcb->sv = (int16_t)(pcb->sv + m);
            pcb->rto = (int16_t)((pcb->sa >> 3) + pcb->sv);
            Logf(true,
                 "tcp_receive: RTO %d (%d milliseconds)\n", pcb->rto, (uint16_t)(pcb->rto
                     * TCP_SLOW_INTERVAL));
            pcb->rttest = 0;
        }
    } /* If the incoming segment contains data, we must process it
     further unless the pcb already received a FIN.
     (RFC 793, chapter 3.9, "SEGMENT ARRIVES" in states CLOSE-WAIT, CLOSING,
     LAST-ACK and TIME-WAIT: "Ignore the segment text.") */
    if ((tcplen > 0) && (pcb->state < CLOSE_WAIT))
    {
        /* This code basically does three things:

        +) If the incoming segment contains data that is the next
        in-sequence data, this data is passed to the application. This
        might involve trimming the first edge of the data. The rcv_nxt
        variable and the advertised window are adjusted.

        +) If the incoming segment has data that is above the next
        sequence number expected (->rcv_nxt), the segment is placed on
        the ->ooseq queue. This is done by finding the appropriate
        place in the ->ooseq queue (which is ordered by sequence
        number) and trim the segment in both ends if needed. An
        immediate ACK is sent to indicate that we received an
        out-of-sequence segment.

        +) Finally, we check if the first segment on the ->ooseq queue
        now is in sequence (i.e., if rcv_nxt >= ooseq->seqno). If
        rcv_nxt > ooseq->seqno, we must trim the first edge of the
        segment on ->ooseq before we adjust rcv_nxt. The data in the
        segments that are now on sequence are chained onto the
        incoming segment so that we only need to call the application
        once.
        */ /* First, we check if we must trim the first edge. We have to do
       this if the sequence number of the incoming segment is less
       than rcv_nxt, and the sequence number plus the length of the
       segment is larger than rcv_nxt. */ /*    if (tcp_seq_lt(seqno, pcb->rcv_nxt)) {
          if (tcp_seq_lt(pcb->rcv_nxt, seqno + tcplen)) {*/
        if (TCP_SEQ_BETWEEN(pcb->rcv_nxt, seqno + 1, seqno + tcplen - 1))
        {
            /* Trimming the first edge is done by pushing the payload
               pointer in the PacketBuffer downwards. This is somewhat tricky since
               we do not want to discard the full contents of the PacketBuffer up to
               the new starting point of the data since we have to keep the
               TCP header which is present in the first PacketBuffer in the chain.

               What is done is really quite a nasty hack: the first PacketBuffer in
               the PacketBuffer chain is pointed to by inseg.p. Since we need to be
               able to deallocate the whole PacketBuffer, we cannot change this
               inseg.p pointer to point to any of the later pbufs in the
               chain. Instead, we point the ->payload pointer in the first
               PacketBuffer to data in one of the later pbufs. We also set the
               inseg.data pointer to point to the right place. This way, the
               ->p pointer will still point to the first PacketBuffer, but the
               ->p->payload pointer will point to data in another PacketBuffer.

               After we are done with adjusting the PacketBuffer pointers we must
               adjust the ->data pointer in the seg and the segment
               length.*/
            struct PacketBuffer* p = inseg.p;
            uint32_t off32 = pcb->rcv_nxt - seqno;
            lwip_assert("inseg.p != NULL", inseg.p);
            lwip_assert("insane offset!", (off32 < 0xffff));
            uint16_t off = (uint16_t)off32;
            lwip_assert("PacketBuffer too short!", (((int32_t)inseg.p->tot_len) >= off));
            inseg.len -= off;
            uint16_t new_tot_len = (uint16_t)(inseg.p->tot_len - off);
            while (p->len < off)
            {
                off -= p->len;
                /* all pbufs up to and including this one have len==0, so tot_len is equal */
                p->tot_len = new_tot_len;
                p->len = 0;
                p = p->next;
            } /* cannot fail... */
            pbuf_remove_header(p, off);
            inseg.tcphdr->seqno = seqno = pcb->rcv_nxt;
        }
        else
        {
            if (tcp_seq_lt(seqno, pcb->rcv_nxt))
            {
                /* the whole segment is < rcv_nxt */
                /* must be a duplicate of a packet that has already been correctly handled */
                Logf(true, "tcp_receive: duplicate seqno %d\n", seqno);
                tcp_ack_now(pcb);
            }
        } /* The sequence number must be within the window (above rcv_nxt
       and below rcv_nxt + rcv_wnd) in order to be further
       processed. */
        if (TCP_SEQ_BETWEEN(seqno, pcb->rcv_nxt, pcb->rcv_nxt + pcb->rcv_wnd - 1))
        {
            if (pcb->rcv_nxt == seqno)
            {
                /* The incoming segment is the next in sequence. We check if
                   we have to trim the end of the segment and update rcv_nxt
                   and pass the data to the application. */
                tcplen = tcp_tcplen(&inseg);
                if (tcplen > pcb->rcv_wnd)
                {
                    Logf(true,
                         "tcp_receive: other end overran receive window"
                             "seqno %d len %d right edge %d\n", seqno, tcplen, pcb->
                             rcv_nxt + pcb->rcv_wnd);
                    if (tcph_flags(inseg.tcphdr) & TCP_FIN)
                    {
                        /* Must remove the FIN from the header as we're trimming
                         * that byte of sequence-space from the packet */
                        TCPH_FLAGS_SET(inseg.tcphdr,
                                       tcph_flags(inseg.tcphdr) & ~(unsigned int)TCP_FIN);
                    } /* Adjust length of segment to fit in the window. */
                    lwip_assert("window size > 0xFFFF", (pcb->rcv_wnd) <= 0xFFFF);
                    inseg.len = (uint16_t)pcb->rcv_wnd;
                    if (tcph_flags(inseg.tcphdr) & TCP_SYN)
                    {
                        inseg.len -= 1;
                    }
                    pbuf_realloc(inseg.p);
                    tcplen = tcp_tcplen(&inseg);
                    lwip_assert("tcp_receive: segment not trimmed correctly to rcv_wnd\n",
                                (seqno + tcplen) == (pcb->rcv_nxt + pcb->rcv_wnd));
                } /* Received in-sequence data, adjust ooseq data if:
           - FIN has been received or
           - inseq overlaps with ooseq */
                if (pcb->ooseq != nullptr)
                {
                    if (tcph_flags(inseg.tcphdr) & TCP_FIN)
                    {
                        Logf(true,
                             ("tcp_receive: received in-order FIN, binning ooseq queue\n"
                             )); /* Received in-order FIN means anything that was received
             * out of order must now have been received in-order, so
             * bin the ooseq queue */
                        while (pcb->ooseq != nullptr)
                        {
                            struct TcpSeg* old_ooseq = pcb->ooseq;
                            pcb->ooseq = pcb->ooseq->next;
                            tcp_seg_free(old_ooseq);
                        }
                    }
                    else
                    {
                        struct TcpSeg* next = pcb->ooseq;
                        /* Remove all segments on ooseq that are covered by inseg already.
                                    * FIN is copied from ooseq to inseg if present. */
                        while (next && TCP_SEQ_GEQ(seqno + tcplen,
                                                   next->tcphdr->seqno + next->len))
                        {
                            /* inseg cannot have FIN here (already processed above) */
                            if ((tcph_flags(next->tcphdr) & TCP_FIN) != 0 && (tcph_flags(
                                inseg.tcphdr) & TCP_SYN) == 0)
                            {
                                TCPH_SET_FLAG(inseg.tcphdr, TCP_FIN);
                                tcplen = tcp_tcplen(&inseg);
                            }
                            struct TcpSeg* tmp = next;
                            next = next->next;
                            tcp_seg_free(tmp);
                        } /* Now trim right side of inseg if it overlaps with the first
             * segment on ooseq */
                        if (next && TCP_SEQ_GT(seqno + tcplen, next->tcphdr->seqno))
                        {
                            /* inseg cannot have FIN here (already processed above) */
                            inseg.len = (uint16_t)(next->tcphdr->seqno - seqno);
                            if (tcph_flags(inseg.tcphdr) & TCP_SYN)
                            {
                                inseg.len -= 1;
                            }
                            pbuf_realloc(inseg.p);
                            tcplen = tcp_tcplen(&inseg);
                            lwip_assert(
                                "tcp_receive: segment not trimmed correctly to ooseq queue\n",
                                (seqno + tcplen) == next->tcphdr->seqno);
                        }
                        pcb->ooseq = next;
                    }
                }
                pcb->rcv_nxt = seqno + tcplen; /* Update the receiver's (our) window. */
                lwip_assert("tcp_receive: tcplen > rcv_wnd\n", pcb->rcv_wnd >= tcplen);
                pcb->rcv_wnd -= tcplen;
                tcp_update_rcv_ann_wnd(pcb);
                /* If there is data in the segment, we make preparations to
                          pass this up to the application. The ->recv_data variable
                          is used for holding the PacketBuffer that goes to the
                          application. The code for reassembling out-of-sequence data
                          chains its data on this PacketBuffer as well.

                          If the segment was a FIN, we set the TF_GOT_FIN flag that will
                          be used to indicate to the application that the remote side has
                          closed its end of the connection. */
                if (inseg.p->tot_len > 0)
                {
                    recv_data = inseg.p;
                    /* Since this PacketBuffer now is the responsibility of the
                                application, we delete our reference to it so that we won't
                                (mistakingly) deallocate it. */
                    inseg.p = nullptr;
                }
                if (tcph_flags(inseg.tcphdr) & TCP_FIN)
                {
                    Logf(true, ("tcp_receive: received FIN.\n"));
                    recv_flags |= TF_GOT_FIN;
                } /* We now check if we have segments on the ->ooseq queue that
           are now in sequence. */
                while (pcb->ooseq != nullptr && pcb->ooseq->tcphdr->seqno == pcb->rcv_nxt)
                {
                    struct TcpSeg* cseg = pcb->ooseq;
                    seqno = pcb->ooseq->tcphdr->seqno;
                    pcb->rcv_nxt += tcp_tcplen(cseg);
                    lwip_assert("tcp_receive: ooseq tcplen > rcv_wnd\n",
                                pcb->rcv_wnd >= tcp_tcplen(cseg));
                    pcb->rcv_wnd -= tcp_tcplen(cseg);
                    tcp_update_rcv_ann_wnd(pcb);
                    if (cseg->p->tot_len > 0)
                    {
                        /* Chain this PacketBuffer onto the PacketBuffer that we will pass to
                           the application. */
                        /* With window scaling, this can overflow recv_data->tot_len, but
                                      that's not a problem since we explicitly fix that before passing
                                      recv_data to the application. */
                        if (recv_data)
                        {
                            pbuf_cat(recv_data, cseg->p);
                        }
                        else
                        {
                            recv_data = cseg->p;
                        }
                        cseg->p = nullptr;
                    }
                    if (tcph_flags(cseg->tcphdr) & TCP_FIN)
                    {
                        Logf(true, ("tcp_receive: dequeued FIN.\n"));
                        recv_flags |= TF_GOT_FIN;
                        if (pcb->state == ESTABLISHED)
                        {
                            /* force passive close or we can move to active close */
                            pcb->state = CLOSE_WAIT;
                        }
                    }
                    pcb->ooseq = cseg->next;
                    tcp_seg_free(cseg);
                }
                if (pcb->flags & TF_SACK)
                {
                    if (pcb->ooseq != nullptr)
                    {
                        /* Some segments may have been removed from ooseq, let's remove all SACKs that
                           describe anything before the new beginning of that list. */
                        tcp_remove_sacks_lt(pcb, pcb->ooseq->tcphdr->seqno);
                    }
                    else if (tcp_sack_valid(pcb, 0))
                    {
                        /* ooseq has been cleared. Nothing to SACK */
                        memset(pcb->rcv_sacks, 0, sizeof(pcb->rcv_sacks));
                    }
                } /* Acknowledge the segment(s). */
                tcp_ack(pcb);
                if (tcp_sack_valid(pcb, 0))
                {
                    /* Normally the ACK for the data received could be piggy-backed on a data packet,
                       but lwIP currently does not support including SACKs in data packets. So we force
                       it to respond with an empty ACK packet (only if there is at least one SACK to be sent).
                       NOTE: tcp_send_empty_ack() on success clears the ACK flags (set by tcp_ack()) */
                    tcp_send_empty_ack(pcb);
                }
                // if (ip_current_is_v6())
                // {
                //     /* Inform neighbor reachability of forward progress. */
                //     nd6_reachability_hint(ip6_current_src_addr());
                // }
            }
            else
            {
                /* We get here if the incoming segment is out-of-sequence. */
                /* We queue the segment on the ->ooseq queue. */
                if (pcb->ooseq == nullptr)
                {
                    pcb->ooseq = tcp_seg_copy(&inseg);
                    if (pcb->flags & TF_SACK)
                    {
                        /* All the SACKs should be invalid, so we can simply store the most recent one: */
                        pcb->rcv_sacks[0].left = seqno;
                        pcb->rcv_sacks[0].right = seqno + inseg.len;
                    }
                }
                else
                {
                    /* If the queue is not empty, we walk through the queue and
                       try to find a place where the sequence number of the
                       incoming segment is between the sequence numbers of the
                       previous and the next segment on the ->ooseq queue. That is
                       the place where we put the incoming segment. If needed, we
                       trim the second edges of the previous and the incoming
                       segment so that it will fit into the sequence.

                       If the incoming segment has the same sequence number as a
                       segment on the ->ooseq queue, we discard the segment that
                       contains less data. */
                    /* This is the left edge of the lowest possible SACK range.
                                It may start before the newly received segment (possibly adjusted below). */
                    uint32_t sackbeg = tcp_seq_lt(seqno, pcb->ooseq->tcphdr->seqno)
                                           ? seqno
                                           : pcb->ooseq->tcphdr->seqno;
                    struct TcpSeg *next, *prev = nullptr;
                    for (next = pcb->ooseq; next != nullptr; next = next->next)
                    {
                        if (seqno == next->tcphdr->seqno)
                        {
                            /* The sequence number of the incoming segment is the
                               same as the sequence number of the segment on
                               ->ooseq. We check the lengths to see which one to
                               discard. */
                            if (inseg.len > next->len)
                            {
                                /* The incoming segment is larger than the old
                                   segment. We replace some segments with the new
                                   one. */
                                struct TcpSeg* cseg = tcp_seg_copy(&inseg);
                                if (cseg != nullptr)
                                {
                                    if (prev != nullptr)
                                    {
                                        prev->next = cseg;
                                    }
                                    else
                                    {
                                        pcb->ooseq = cseg;
                                    }
                                    tcp_oos_insert_segment(cseg, next);
                                }
                                break;
                            }
                            else
                            {
                                /* Either the lengths are the same or the incoming
                                   segment was smaller than the old one; in either
                                   case, we ditch the incoming segment. */
                                break;
                            }
                        }
                        else
                        {
                            if (prev == nullptr)
                            {
                                if (tcp_seq_lt(seqno, next->tcphdr->seqno))
                                {
                                    /* The sequence number of the incoming segment is lower
                                       than the sequence number of the first segment on the
                                       queue. We put the incoming segment first on the
                                       queue. */
                                    struct TcpSeg* cseg = tcp_seg_copy(&inseg);
                                    if (cseg != nullptr)
                                    {
                                        pcb->ooseq = cseg;
                                        tcp_oos_insert_segment(cseg, next);
                                    }
                                    break;
                                }
                            }
                            else
                            {
                                /*if (tcp_seq_lt(prev->tcphdr->seqno, seqno) &&
                                  tcp_seq_lt(seqno, next->tcphdr->seqno)) {*/
                                if (TCP_SEQ_BETWEEN(seqno,
                                                    prev->tcphdr->seqno + 1,
                                                    next->tcphdr->seqno - 1))
                                {
                                    /* The sequence number of the incoming segment is in
                                       between the sequence numbers of the previous and
                                       the next segment on ->ooseq. We trim trim the previous
                                       segment, delete next segments that included in received segment
                                       and trim received, if needed. */
                                    struct TcpSeg* cseg = tcp_seg_copy(&inseg);
                                    if (cseg != nullptr)
                                    {
                                        if (TCP_SEQ_GT(
                                            prev->tcphdr->seqno + prev->len,
                                            seqno))
                                        {
                                            /* We need to trim the prev segment. */
                                            prev->len = (uint16_t)(seqno - prev
                                                                           ->tcphdr->seqno
                                            );
                                            pbuf_realloc(prev->p);
                                        }
                                        prev->next = cseg;
                                        tcp_oos_insert_segment(cseg, next);
                                    }
                                    break;
                                }
                            } /* The new segment goes after the 'next' one. If there is a "hole" in sequence numbers
                 between 'prev' and the beginning of 'next', we want to move sackbeg. */
                            if (prev != nullptr && prev->tcphdr->seqno + prev->len != next
                                                                                      ->
                                                                                      tcphdr
                                                                                      ->
                                                                                      seqno
                            )
                            {
                                sackbeg = next->tcphdr->seqno;
                            } /* We don't use 'prev' below, so let's set it to current 'next'.
                 This way even if we break the loop below, 'prev' will be pointing
                 at the segment right in front of the newly added one. */
                            prev = next;
                            /* If the "next" segment is the last segment on the
                                            ooseq queue, we add the incoming segment to the end
                                            of the list. */
                            if (next->next == nullptr && TCP_SEQ_GT(
                                seqno,
                                next->tcphdr->seqno))
                            {
                                if (tcph_flags(next->tcphdr) & TCP_FIN)
                                {
                                    /* segment "next" already contains all data */
                                    break;
                                }
                                next->next = tcp_seg_copy(&inseg);
                                if (next->next != nullptr)
                                {
                                    if (TCP_SEQ_GT(next->tcphdr->seqno + next->len, seqno)
                                    )
                                    {
                                        /* We need to trim the last segment. */
                                        next->len = (uint16_t)(seqno - next->tcphdr->seqno
                                        );
                                        pbuf_realloc(next->p);
                                    } /* check if the remote side overruns our receive window */
                                    if (TCP_SEQ_GT((uint32_t)tcplen + seqno,
                                                   pcb->rcv_nxt + (uint32_t)pcb->rcv_wnd))
                                    {
                                        Logf(true,
                                             "tcp_receive: other end overran receive window"
                                                 "seqno %d len %d right edge %d\n", seqno,
                                                 tcplen, pcb->rcv_nxt + pcb->rcv_wnd);
                                        if (tcph_flags(next->next->tcphdr) & TCP_FIN)
                                        {
                                            /* Must remove the FIN from the header as we're trimming
                                             * that byte of sequence-space from the packet */
                                            TCPH_FLAGS_SET(
                                                next->next->tcphdr,
                                                tcph_flags(
                                                    next->next->tcphdr) & ~TCP_FIN);
                                        } /* Adjust length of segment to fit in the window. */
                                        next->next->len = (uint16_t)(pcb->rcv_nxt + pcb->
                                            rcv_wnd - seqno);
                                        pbuf_realloc(next->next->p);
                                        tcplen = tcp_tcplen(next->next);
                                        lwip_assert(
                                            "tcp_receive: segment not trimmed correctly to rcv_wnd\n",
                                            (seqno + tcplen) == (pcb->rcv_nxt + pcb->
                                                rcv_wnd));
                                    }
                                }
                                break;
                            }
                        }
                    }
                    if (pcb->flags & TF_SACK)
                    {
                        if (prev == nullptr)
                        {
                            /* The new segment is at the beginning. sackbeg should already be set properly.
                               We need to find the right edge. */
                            next = pcb->ooseq;
                        }
                        else if (prev->next != nullptr)
                        {
                            /* The new segment was added after 'prev'. If there is a "hole" between 'prev' and 'prev->next',
                               we need to move sackbeg. After that we should find the right edge. */
                            next = prev->next;
                            if (prev->tcphdr->seqno + prev->len != next->tcphdr->seqno)
                            {
                                sackbeg = next->tcphdr->seqno;
                            }
                        }
                        else
                        {
                            next = nullptr;
                        }
                        if (next != nullptr)
                        {
                            uint32_t sackend = next->tcphdr->seqno;
                            for (; (next != nullptr) && (sackend == next->tcphdr->seqno);
                                   next = next->next)
                            {
                                sackend += next->len;
                            }
                            tcp_add_sack(pcb, sackbeg, sackend);
                        }
                    }
                }
                {
                    /* Check that the data on ooseq doesn't exceed one of the limits
                       and throw away everything above that limit. */
                    // const uint32_t ooseq_max_blen = TCP_OOSEQ_BYTES_LIMIT(pcb);
                    uint32_t ooseq_blen = 0;
                    // const uint16_t ooseq_max_qlen = TCP_OOSEQ_PBUFS_LIMIT(pcb);
                    uint16_t ooseq_qlen = 0;
                    struct TcpSeg* prev = nullptr;
                    for (struct TcpSeg* next = pcb->ooseq; next != nullptr; prev = next,
                         next = next->next)
                    {
                        struct PacketBuffer* p = next->p;
                        int stop_here = 0;
                        ooseq_blen += p->tot_len;
                        // if (ooseq_blen > ooseq_max_blen)
                        // {
                        //     stop_here = 1;
                        // }
                        ooseq_qlen += pbuf_clen(p);
                        // if (ooseq_qlen > ooseq_max_qlen)
                        // {
                        //     stop_here = 1;
                        // }
                        if (stop_here)
                        {
                            if (pcb->flags & TF_SACK)
                            {
                                /* Let's remove all SACKs from next's seqno up. */
                                tcp_remove_sacks_gt(pcb, next->tcphdr->seqno);
                            } /* too much ooseq data, dump this and everything after it */
                            tcp_segs_free(next);
                            if (prev == nullptr)
                            {
                                /* first ooseq segment is too much, dump the whole queue */
                                pcb->ooseq = nullptr;
                            }
                            else
                            {
                                /* just dump 'next' and everything after it */
                                prev->next = nullptr;
                            }
                            break;
                        }
                    }
                } /* We send the ACK packet after we've (potentially) dealt with SACKs,
           so they can be included in the acknowledgment. */
                tcp_send_empty_ack(pcb);
            }
        }
        else
        {
            /* The incoming segment is not within the window. */
            tcp_send_empty_ack(pcb);
        }
    }
    else
    {
        /* Segments with length 0 is taken care of here. Segments that
           fall out of the window are ACKed. */
        if (!TCP_SEQ_BETWEEN(seqno, pcb->rcv_nxt, pcb->rcv_nxt + pcb->rcv_wnd - 1))
        {
            tcp_ack_now(pcb);
        }
    }
}

 uint8_t
tcp_get_next_optbyte(void)
{
    uint16_t optidx = tcp_optidx++;
    if ((tcphdr_opt2 == nullptr) || (optidx < tcphdr_opt1_len))
    {
        uint8_t* opts = (uint8_t *)tcphdr + TCP_HDR_LEN;
        return opts[optidx];
    }
    else
    {
        uint8_t idx = (uint8_t)(optidx - tcphdr_opt1_len);
        return tcphdr_opt2[idx];
    }
} /**
 * Parses the options contained in the incoming segment.
 *
 * Called from tcp_listen_input() and tcp_process().
 * Currently, only the MSS option is supported!
 *
 * @param pcb the TcpProtoCtrlBlk for which a segment arrived
 */
 void
tcp_parseopt(struct TcpPcb* pcb)
{
    uint8_t data;
    uint16_t mss;
    uint32_t tsval;
    lwip_assert("tcp_parseopt: invalid pcb", pcb != nullptr);
    /* Parse the TCP MSS option, if present. */
    if (tcphdr_optlen != 0)
    {
        for (tcp_optidx = 0; tcp_optidx < tcphdr_optlen;)
        {
            uint8_t opt = tcp_get_next_optbyte();
            switch (opt)
            {
            case LWIP_TCP_OPT_EOL: /* End of options. */ Logf(
                    true,
                    ("tcp_parseopt: EOL\n"));
                return;
            case LWIP_TCP_OPT_NOP: /* NOP option. */ Logf(true, ("tcp_parseopt: NOP\n"));
                break;
            case LWIP_TCP_OPT_MSS:
                Logf(true, ("tcp_parseopt: MSS\n"));
                if (tcp_get_next_optbyte() != LWIP_TCP_OPT_LEN_MSS || (tcp_optidx - 2 +
                    LWIP_TCP_OPT_LEN_MSS) > tcphdr_optlen)
                {
                    /* Bad length */
                    Logf(true, ("tcp_parseopt: bad length\n"));
                    return;
                } /* An MSS option with the right option length. */
                mss = (uint16_t)(tcp_get_next_optbyte() << 8);
                mss |= tcp_get_next_optbyte();
                /* Limit the mss to the configured TCP_MSS and prevent division by zero */
                pcb->mss = ((mss > TCP_MSS) || (mss == 0)) ? TCP_MSS : mss;
                break;
            case LWIP_TCP_OPT_WS:
                Logf(true, ("tcp_parseopt: WND_SCALE\n"));
                if (tcp_get_next_optbyte() != LWIP_TCP_OPT_LEN_WS || (tcp_optidx - 2 +
                    LWIP_TCP_OPT_LEN_WS) > tcphdr_optlen)
                {
                    /* Bad length */
                    Logf(true, ("tcp_parseopt: bad length\n"));
                    return;
                } /* An WND_SCALE option with the right option length. */
                data = tcp_get_next_optbyte();
                /* If syn was received with wnd scale option,
                            activate wnd scale opt, but only if this is not a retransmission */
                if ((flags & TCP_SYN) && !(pcb->flags & TF_WND_SCALE))
                {
                    pcb->snd_scale = data;
                    if (pcb->snd_scale > 14U)
                    {
                        pcb->snd_scale = 14U;
                    }
                    // fixme
                    pcb->rcv_scale = 0xff;
                    tcp_set_flags(pcb, TF_WND_SCALE);
                    /* window scaling is enabled, we can use the full receive window */
                    lwip_assert("window not at default value",
                                pcb->rcv_wnd == TCPWND_MIN16(TCP_WND));
                    lwip_assert("window not at default value",
                                pcb->rcv_ann_wnd == TCPWND_MIN16(TCP_WND));
                    pcb->rcv_wnd = pcb->rcv_ann_wnd = TCP_WND;
                }
                break;
            case LWIP_TCP_OPT_TS:
                Logf(true, ("tcp_parseopt: TS\n"));
                if (tcp_get_next_optbyte() != LWIP_TCP_OPT_LEN_TS || (tcp_optidx - 2 +
                    LWIP_TCP_OPT_LEN_TS) > tcphdr_optlen)
                {
                    /* Bad length */
                    Logf(true, ("tcp_parseopt: bad length\n"));
                    return;
                } /* TCP timestamp option with valid length */
                tsval = tcp_get_next_optbyte();
                tsval |= (tcp_get_next_optbyte() << 8);
                tsval |= (tcp_get_next_optbyte() << 16);
                tsval |= (tcp_get_next_optbyte() << 24);
                if (flags & TCP_SYN)
                {
                    pcb->ts_recent = lwip_ntohl(tsval);
                    /* Enable sending timestamps in every segment now that we know
                                  the remote host supports it. */
                    tcp_set_flags(pcb, TF_TIMESTAMP);
                }
                else if (TCP_SEQ_BETWEEN(pcb->ts_lastacksent, seqno, seqno + tcplen))
                {
                    pcb->ts_recent = lwip_ntohl(tsval);
                } /* Advance to next option (6 bytes already read) */
                tcp_optidx += LWIP_TCP_OPT_LEN_TS - 6;
                break;
            case LWIP_TCP_OPT_SACK_PERM:
                Logf(true, ("tcp_parseopt: SACK_PERM\n"));
                if (tcp_get_next_optbyte() != LWIP_TCP_OPT_LEN_SACK_PERM || (tcp_optidx -
                    2 + LWIP_TCP_OPT_LEN_SACK_PERM) > tcphdr_optlen)
                {
                    /* Bad length */
                    Logf(true, ("tcp_parseopt: bad length\n"));
                    return;
                } /* TCP SACK_PERM option with valid length */
                if (flags & TCP_SYN)
                {
                    /* We only set it if we receive it in a SYN (or SYN+ACK) packet */
                    tcp_set_flags(pcb, TF_SACK);
                }
                break;
            default:
                Logf(true, ("tcp_parseopt: other\n"));
                data = tcp_get_next_optbyte();
                if (data < 2)
                {
                    Logf(true, ("tcp_parseopt: bad length\n"));
                    /* If the length field is zero, the options are malformed
                                  and we don't process them further. */
                    return;
                } /* All other options have a length field, so that we easily
             can skip past them. */
                tcp_optidx += data - 2;
            }
        }
    }
}

void
tcp_trigger_input_pcb_close(void)
{
    recv_flags |= TF_CLOSED;
} /**
 * Called by tcp_receive() to add new SACK entry.
 *
 * The new SACK entry will be placed at the beginning of rcv_sacks[], as the newest one.
 * Existing SACK entries will be "pushed back", to preserve their order.
 * This is the behavior described in RFC 2018, section 4.
 *
 * @param pcb the TcpProtoCtrlBlk for which a segment arrived
 * @param left the left side of the SACK (the first sequence number)
 * @param right the right side of the SACK (the first sequence number past this SACK)
 */
 void
tcp_add_sack(struct TcpPcb* pcb, uint32_t left, uint32_t right)
{
    uint8_t i;
    uint8_t unused_idx;
    if ((pcb->flags & TF_SACK) == 0 || !tcp_seq_lt(left, right))
    {
        return;
    } /* First, let's remove all SACKs that are no longer needed (because they overlap with the newest one),
     while moving all other SACKs forward.
     We run this loop for all entries, until we find the first invalid one.
     There is no point checking after that. */
    for (i = unused_idx = 0; (i < LWIP_TCP_MAX_SACK_NUM) && tcp_sack_valid(pcb, i);
         ++i)
    {
        /* We only want to use SACK at [i] if it doesn't overlap with left:right range.
           It does not overlap if its right side is before the newly added SACK,
           or if its left side is after the newly added SACK.
           NOTE: The equality should not really happen, but it doesn't hurt. */
        if (TCP_SEQ_LEQ(pcb->rcv_sacks[i].right, left) || TCP_SEQ_LEQ(
            right,
            pcb->rcv_sacks[i].left))
        {
            if (unused_idx != i)
            {
                /* We don't need to copy if it's already in the right spot */
                pcb->rcv_sacks[unused_idx] = pcb->rcv_sacks[i];
            }
            ++unused_idx;
        }
    } /* Now 'unused_idx' is the index of the first invalid SACK entry,
     anywhere between 0 (no valid entries) and LWIP_TCP_MAX_SACK_NUM (all entries are valid).
     We want to clear this and all following SACKs.
     However, we will be adding another one in the front (and shifting everything else back).
     So let's just iterate from the back, and set each entry to the one to the left if it's valid,
     or to 0 if it is not. */
    for (i = LWIP_TCP_MAX_SACK_NUM - 1; i > 0; --i)
    {
        /* [i] is the index we are setting, and the value should be at index [i-1],
           or 0 if that index is unused (>= unused_idx). */
        if (i - 1 >= unused_idx)
        {
            /* [i-1] is unused. Let's clear [i]. */
            pcb->rcv_sacks[i].left = pcb->rcv_sacks[i].right = 0;
        }
        else
        {
            pcb->rcv_sacks[i] = pcb->rcv_sacks[i - 1];
        }
    } /* And now we can store the newest SACK */
    pcb->rcv_sacks[0].left = left;
    pcb->rcv_sacks[0].right = right;
} /**
 * Called to remove a range of SACKs.
 *
 * SACK entries will be removed or adjusted to not acknowledge any sequence
 * numbers that are less than 'seq' passed. It not only invalidates entries,
 * but also moves all entries that are still valid to the beginning.
 *
 * @param pcb the TcpProtoCtrlBlk to modify
 * @param seq the lowest sequence number to keep in SACK entries
 */
 void
tcp_remove_sacks_lt(struct TcpPcb* pcb, uint32_t seq)
{
    uint8_t i;
    uint8_t unused_idx;
    /* We run this loop for all entries, until we find the first invalid one.
        There is no point checking after that. */
    for (i = unused_idx = 0; (i < LWIP_TCP_MAX_SACK_NUM) && tcp_sack_valid(pcb, i);
         ++i)
    {
        /* We only want to use SACK at index [i] if its right side is > 'seq'. */
        if (TCP_SEQ_GT(pcb->rcv_sacks[i].right, seq))
        {
            if (unused_idx != i)
            {
                /* We only copy it if it's not in the right spot already. */
                pcb->rcv_sacks[unused_idx] = pcb->rcv_sacks[i];
            } /* NOTE: It is possible that its left side is < 'seq', in which case we should adjust it. */
            if (tcp_seq_lt(pcb->rcv_sacks[unused_idx].left, seq))
            {
                pcb->rcv_sacks[unused_idx].left = seq;
            }
            ++unused_idx;
        }
    } /* We also need to invalidate everything from 'unused_idx' till the end */
    for (i = unused_idx; i < LWIP_TCP_MAX_SACK_NUM; ++i)
    {
        pcb->rcv_sacks[i].left = pcb->rcv_sacks[i].right = 0;
    }
} /**
 * Called to remove a range of SACKs.
 *
 * SACK entries will be removed or adjusted to not acknowledge any sequence
 * numbers that are greater than (or equal to) 'seq' passed. It not only invalidates entries,
 * but also moves all entries that are still valid to the beginning.
 *
 * @param pcb the TcpProtoCtrlBlk to modify
 * @param seq the highest sequence number to keep in SACK entries
 */
 void
tcp_remove_sacks_gt(struct TcpPcb* pcb, uint32_t seq)
{
    uint8_t i;
    uint8_t unused_idx;
    /* We run this loop for all entries, until we find the first invalid one.
        There is no point checking after that. */
    for (i = unused_idx = 0; (i < LWIP_TCP_MAX_SACK_NUM) && tcp_sack_valid(pcb, i);
         ++i)
    {
        /* We only want to use SACK at index [i] if its left side is < 'seq'. */
        if (tcp_seq_lt(pcb->rcv_sacks[i].left, seq))
        {
            if (unused_idx != i)
            {
                /* We only copy it if it's not in the right spot already. */
                pcb->rcv_sacks[unused_idx] = pcb->rcv_sacks[i];
            } /* NOTE: It is possible that its right side is > 'seq', in which case we should adjust it. */
            if (TCP_SEQ_GT(pcb->rcv_sacks[unused_idx].right, seq))
            {
                pcb->rcv_sacks[unused_idx].right = seq;
            }
            ++unused_idx;
        }
    } /* We also need to invalidate everything from 'unused_idx' till the end */
    for (i = unused_idx; i < LWIP_TCP_MAX_SACK_NUM; ++i)
    {
        pcb->rcv_sacks[i].left = pcb->rcv_sacks[i].right = 0;
    }
}
