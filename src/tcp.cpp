/**
 * @file
 * Transmission Control Protocol for IP
 * See also @ref tcp_raw
 *
 * @defgroup tcp_raw TCP
 * @ingroup callbackstyle_api
 * Transmission Control Protocol for IP\n
 * @see @ref api
 *
 * Common functions for the TCP implementation, such as functions
 * for manipulating the data structures and the TCP timer functions. TCP functions
 * related to input and output is found in tcp_in.c and tcp_out.c respectively.\n
 *
 * TCP connection setup
 * --------------------
 * The functions used for setting up connections is similar to that of
 * the sequential API and of the BSD socket API. A new TCP connection
 * identifier (i.e., a protocol control block - PCB) is created with the
 * tcp_new() function. This PCB can then be either set to listen for new
 * incoming connections or be explicitly connected to another host.
 * - tcp_new()
 * - tcp_bind()
 * - tcp_listen() and tcp_listen_with_backlog()
 * - tcp_accept()
 * - tcp_connect()
 *
 * Sending TCP data
 * ----------------
 * TCP data is sent by enqueueing the data with a call to tcp_write() and
 * triggering to send by calling tcp_output(). When the data is successfully
 * transmitted to the remote host, the application will be notified with a
 * call to a specified callback function.
 * - tcp_write()
 * - tcp_output()
 * - tcp_sent()
 *
 * Receiving TCP data
 * ------------------
 * TCP data reception is callback based - an application specified
 * callback function is called when new data arrives. When the
 * application has taken the data, it has to call the tcp_recved()
 * function to indicate that TCP can advertise increase the receive
 * window.
 * - tcp_recv()
 * - tcp_recved()
 *
 * Application polling
 * -------------------
 * When a connection is idle (i.e., no data is either transmitted or
 * received), lwIP will repeatedly poll the application by calling a
 * specified callback function. This can be used either as a watchdog
 * timer for killing connections that have stayed idle for too long, or
 * as a method of waiting for memory to become available. For instance,
 * if a call to tcp_write() has failed because memory wasn't available,
 * the application may use the polling functionality to call tcp_write()
 * again when the connection has been idle for a while.
 * - tcp_poll()
 *
 * Closing and aborting connections
 * --------------------------------
 * - tcp_close()
 * - tcp_abort()
 * - tcp_err()
 *
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

#include <algorithm>
#include <cstring>
#include <def.h>
#include <ip6.h>
#include <ip6_addr.h>
#include <lwip_debug.h>
#include <nd6.h>
#include <opt.h>
#include <sys.h>
#include <tcp.h>
#include <tcp_priv.h>
#include <tcpip.h>


/* From http://www.iana.org/assignments/port-numbers:
   "The Dynamic and/or Private Ports are those from 49152 through 65535" */
constexpr auto TCP_LOCAL_PORT_RANGE_START = 0xc000;
constexpr auto TCP_LOCAL_PORT_RANGE_END = 0xffff;

inline bool tcp_ensure_local_port_range(const uint16_t port)
{
    return uint16_t(((port) & uint16_t(~TCP_LOCAL_PORT_RANGE_START)) + TCP_LOCAL_PORT_RANGE_START);
}

inline uint32_t tcp_keep_dur(TcpPcb* pcb) { return ((pcb)->keep_cnt * (pcb)->keep_intvl); }
inline uint32_t tcp_keep_intvl(TcpPcb* pcb) { return ((pcb)->keep_intvl); }


/* As initial send MSS, we use TCP_MSS but limit it to 536. */

constexpr auto INITIAL_MSS = 536;


static const char* const tcp_state_str[] = {
    "CLOSED",
    "LISTEN",
    "SYN_SENT",
    "SYN_RCVD",
    "ESTABLISHED",
    "FIN_WAIT_1",
    "FIN_WAIT_2",
    "CLOSE_WAIT",
    "CLOSING",
    "LAST_ACK",
    "TIME_WAIT"
};

/* last local TCP port */
static uint16_t tcp_port = TCP_LOCAL_PORT_RANGE_START;

/* Incremented every coarse grained timer shot (typically every 500 ms). */
uint32_t tcp_ticks;
static const uint8_t TCP_BACKOFF[13] =
    {1, 2, 3, 4, 5, 6, 7, 7, 7, 7, 7, 7, 7};
/* Times per slowtmr hits */
static const uint8_t TCP_PERSIST_BACKOFF[7] = {3, 6, 12, 24, 48, 96, 120};

/* The TCP PCB lists. */

/** List of all TCP PCBs bound but not yet (connected || listening) */
// struct TcpPcb* tcp_bound_pcbs;
/** List of all TCP PCBs in LISTEN state */
union tcp_listen_pcbs_t tcp_listen_pcbs;
/** List of all TCP PCBs that are in a state in which
 * they accept or send data. */
// struct TcpPcb *tcp_active_pcbs;
/** List of all TCP PCBs in TIME-WAIT state */
// struct TcpPcb* tcp_tw_pcbs;

/** An array with all (non-temporary) PCB lists, mainly used for smaller code size */
// struct TcpPcb** const tcp_pcb_lists[] = {
//     &tcp_listen_pcbs.pcbs, &tcp_bound_pcbs,
//     &tcp_active_pcbs, &tcp_tw_pcbs
// };

// uint8_t tcp_active_pcbs_changed;

/** Timer counter to handle calling slow-timer from tcp_tmr() */
// static uint8_t tcp_timer;
// static uint8_t tcp_timer_ctr;
static uint16_t tcp_new_port();

static LwipStatus tcp_close_shutdown_fin(struct TcpPcb* pcb);

static void tcp_ext_arg_invoke_callbacks_destroyed(TcpPcbExtArgs* ext_args);


/**
 * Initialize this module.
 */
void
tcp_init()
{
    tcp_port = tcp_ensure_local_port_range(lwip_rand());
}

/** Free a tcp pcb */
void
tcp_free(struct TcpPcb* pcb)
{
    lwip_assert("tcp_free: LISTEN", pcb->state != LISTEN);

    tcp_ext_arg_invoke_callbacks_destroyed(pcb->ext_args);

    // memp_free(MEMP_TCP_PCB, pcb);
    delete pcb;
}

/** Free a tcp listen pcb */
static void
tcp_free_listen(struct TcpPcb* pcb)
{
    lwip_assert("tcp_free_listen: !LISTEN", pcb->state != LISTEN);

    tcp_ext_arg_invoke_callbacks_destroyed(pcb->ext_args);

    // memp_free(MEMP_TCP_PCB_LISTEN, pcb);
    delete pcb;
}

/**
 * Called periodically to dispatch TCP timers.
 */
void
tcp_tmr()
{
    /* Call tcp_fasttmr() every 250 ms */
    tcp_fasttmr();

    // todo: fixme
    // if (++tcp_timer & 1)
    // {
    //     /* Call tcp_slowtmr() every 500 ms, i.e., every other timer
    //        tcp_tmr() is called. */
    //     tcp_slowtmr();
    // }
}

/** Called when a listen pcb is closed. Iterates one pcb list and removes the
 * closed listener pcb from pcb->listener if matching.
 */
static void
tcp_remove_listener(struct TcpPcb* list, struct TcpPcbListen* lpcb)
{
    lwip_assert("tcp_remove_listener: invalid listener", lpcb != nullptr);

    for (auto pcb = list; pcb != nullptr; pcb = pcb->next)
    {
        if (pcb->listener == lpcb)
        {
            pcb->listener = nullptr;
        }
    }
}


/** Called when a listen pcb is closed. Iterates all pcb lists and removes the
 * closed listener pcb from pcb->listener if matching.
 */
static void
tcp_listen_closed(struct TcpPcb* pcb)
{
    lwip_assert("pcb != NULL", pcb != nullptr);
    lwip_assert("pcb->state == LISTEN", pcb->state == LISTEN);
    for (size_t i = 1; i < LWIP_ARRAYSIZE(tcp_pcb_lists); i++)
    {
        tcp_remove_listener(*tcp_pcb_lists[i], (struct TcpPcbListen *)pcb);
    }
}

/** @ingroup tcp_raw
 * Delay accepting a connection in respect to the listen backlog:
 * the number of outstanding connections is increased until
 * tcp_backlog_accepted() is called.
 *
 * ATTENTION: the caller is responsible for calling tcp_backlog_accepted()
 * or else the backlog feature will get out of sync!
 *
 * @param pcb the connection pcb which is not fully accepted yet
 */
void
tcp_backlog_delayed(struct TcpPcb* pcb)
{
    lwip_assert("pcb != NULL", pcb != nullptr);

    if ((pcb->flags & TF_BACKLOGPEND) == 0)
    {
        if (pcb->listener != nullptr)
        {
            pcb->listener->accepts_pending++;
            lwip_assert("accepts_pending != 0", pcb->listener->accepts_pending != 0);
            tcp_set_flags(pcb, TF_BACKLOGPEND);
        }
    }
}

/** @ingroup tcp_raw
 * A delayed-accept a connection is accepted (or closed/aborted): decreases
 * the number of outstanding connections after calling tcp_backlog_delayed().
 *
 * ATTENTION: the caller is responsible for calling tcp_backlog_accepted()
 * or else the backlog feature will get out of sync!
 *
 * @param pcb the connection pcb which is now fully accepted (or closed/aborted)
 */
void
tcp_backlog_accepted(struct TcpPcb* pcb)
{
    lwip_assert("pcb != NULL", pcb != nullptr);

    if ((pcb->flags & TF_BACKLOGPEND) != 0)
    {
        if (pcb->listener != nullptr)
        {
            lwip_assert("accepts_pending != 0", pcb->listener->accepts_pending != 0);
            pcb->listener->accepts_pending--;
            tcp_clear_flags(pcb, TF_BACKLOGPEND);
        }
    }
}


/**
 * Closes the TX side of a connection held by the PCB.
 * For tcp_close(), a RST is sent if the application didn't receive all data
 * (tcp_recved() not called for all data passed to recv callback).
 *
 * Listening pcbs are freed and may not be referenced any more.
 * Connection pcbs are freed if not yet connected and may not be referenced
 * any more. If a connection is established (at least SYN received or in
 * a closing state), the connection is closed, and put in a closing state.
 * The pcb is then automatically freed in tcp_slowtmr(). It is therefore
 * unsafe to reference it.
 *
 * @param pcb the TcpProtoCtrlBlk to close
 * @return ERR_OK if connection has been closed
 *         another LwipStatus if closing failed and pcb is not freed
 */
static LwipStatus
tcp_close_shutdown(struct TcpPcb* pcb, uint8_t rst_on_unacked_data)
{
    lwip_assert("tcp_close_shutdown: invalid pcb", pcb != nullptr);

    if (rst_on_unacked_data && ((pcb->state == ESTABLISHED) || (pcb->state == CLOSE_WAIT)))
    {
        if ((pcb->refused_data != nullptr) || (pcb->rcv_wnd != TCP_WND_MAX(pcb)))
        {
            /* Not all data received by application, send RST to tell the remote
               side about this. */
            lwip_assert("pcb->flags & TF_RXCLOSED", pcb->flags & TF_RXCLOSED);

            /* don't call tcp_abort here: we must not deallocate the pcb since
               that might not be expected when calling tcp_close */
            tcp_rst(pcb, pcb->snd_nxt, pcb->rcv_nxt, &pcb->local_ip, &pcb->remote_ip,
                    pcb->local_port, pcb->remote_port);

            tcp_pcb_purge(pcb);
            remove_active_tcp_pcb(pcb);
            /* Deallocate the pcb since we already sent a RST for it */
            if (tcp_input_pcb == pcb)
            {
                /* prevent using a deallocated pcb: free it from tcp_input later */
                tcp_trigger_input_pcb_close();
            }
            else
            {
                tcp_free(pcb);
            }
            return STATUS_SUCCESS;
        }
    }

    /* - states which free the pcb are handled here,
       - states which send FIN and change state are handled in tcp_close_shutdown_fin() */
    switch (pcb->state)
    {
    case CLOSED:
        /* Closing a pcb in the CLOSED state might seem erroneous,
         * however, it is in this state once allocated and as yet unused
         * and the user needs some way to free it should the need arise.
         * Calling tcp_close() with a pcb that has already been closed, (i.e. twice)
         * or for a pcb that has been used and then entered the CLOSED state
         * is erroneous, but this should never happen as the pcb has in those cases
         * been freed, and so any remaining handles are bogus. */
        if (pcb->local_port != 0)
        {
            remove_tcp_pcb_from_list(&tcp_bound_pcbs, pcb);
        }
        tcp_free(pcb);
        break;
    case LISTEN:
        tcp_listen_closed(pcb);
        tcp_pcb_remove(&tcp_listen_pcbs.pcbs, pcb);
        tcp_free_listen(pcb);
        break;
    case SYN_SENT:
        TCP_PCB_REMOVE_ACTIVE(pcb);
        tcp_free(pcb);

        break;
    default:
        return tcp_close_shutdown_fin(pcb);
    }
    return STATUS_SUCCESS;
}

static LwipStatus
tcp_close_shutdown_fin(struct TcpPcb* pcb)
{
    LwipStatus err;
    lwip_assert("pcb != NULL", pcb != nullptr);

    switch (pcb->state)
    {
    case SYN_RCVD:
        err = tcp_send_fin(pcb);
        if (err == STATUS_SUCCESS)
        {
            tcp_backlog_accepted(pcb);

            pcb->state = FIN_WAIT_1;
        }
        break;
    case ESTABLISHED:
        err = tcp_send_fin(pcb);
        if (err == STATUS_SUCCESS)
        {
            pcb->state = FIN_WAIT_1;
        }
        break;
    case CLOSE_WAIT:
        err = tcp_send_fin(pcb);
        if (err == STATUS_SUCCESS)
        {
            pcb->state = LAST_ACK;
        }
        break;
    default:
        /* Has already been closed, do nothing. */
        return STATUS_SUCCESS;
    }

    if (err == STATUS_SUCCESS)
    {
        /* To ensure all data has been sent when tcp_close returns, we have
           to make sure tcp_output doesn't fail.
           Since we don't really have to ensure all data has been sent when tcp_close
           returns (unsent data is sent from tcp timer functions, also), we don't care
           for the return value of tcp_output for now. */
        tcp_output(pcb);
    }
    else if (err == ERR_MEM)
    {
        /* Mark this pcb for closing. Closing is retried from tcp_tmr. */
        tcp_set_flags(pcb, TF_CLOSEPEND);
        /* We have to return ERR_OK from here to indicate to the callers that this
           pcb should not be used any more as it will be freed soon via tcp_tmr.
           This is OK here since sending FIN does not guarantee a time frime for
           actually freeing the pcb, either (it is left in closure states for
           remote ACK or timeout) */
        return STATUS_SUCCESS;
    }
    return err;
}

/**
 * @ingroup tcp_raw
 * Closes the connection held by the PCB.
 *
 * Listening pcbs are freed and may not be referenced any more.
 * Connection pcbs are freed if not yet connected and may not be referenced
 * any more. If a connection is established (at least SYN received or in
 * a closing state), the connection is closed, and put in a closing state.
 * The pcb is then automatically freed in tcp_slowtmr(). It is therefore
 * unsafe to reference it (unless an error is returned).
 *
 * The function may return ERR_MEM if no memory
 * was available for closing the connection. If so, the application
 * should wait and try again either by using the acknowledgment
 * callback or the polling functionality. If the close succeeds, the
 * function returns ERR_OK.
 *
 * @param pcb the TcpProtoCtrlBlk to close
 * @return ERR_OK if connection has been closed
 *         another LwipStatus if closing failed and pcb is not freed
 */
LwipStatus
tcp_close(struct TcpPcb* pcb)
{

    Logf(true, ("tcp_close: closing in "));

    tcp_debug_print_state(pcb->state);

    if (pcb->state != LISTEN)
    {
        /* Set a flag not to receive any more data... */
        tcp_set_flags(pcb, TF_RXCLOSED);
    }
    /* ... and close */
    return tcp_close_shutdown(pcb, 1);
}

/**
 * @ingroup tcp_raw
 * Causes all or part of a full-duplex connection of this PCB to be shut down.
 * This doesn't deallocate the PCB unless shutting down both sides!
 * Shutting down both sides is the same as calling tcp_close, so if it succeds
 * (i.e. returns ER_OK), the PCB must not be referenced any more!
 *
 * @param pcb PCB to shutdown
 * @param shut_rx shut down receive side if this is != 0
 * @param shut_tx shut down send side if this is != 0
 * @return ERR_OK if shutdown succeeded (or the PCB has already been shut down)
 *         another LwipStatus on error.
 */
LwipStatus
tcp_shutdown(struct TcpPcb* pcb, int shut_rx, int shut_tx)
{



    if (pcb->state == LISTEN)
    {
        return ERR_CONN;
    }
    if (shut_rx != 0)
    {
        /* shut down the receive side: set a flag not to receive any more data... */
        tcp_set_flags(pcb, TF_RXCLOSED);
        if (shut_tx)
        {
            /* shutting down the tx AND rx side is the same as closing for the raw API */
            return tcp_close_shutdown(pcb, 1);
        }
        /* ... and free buffered data */
        if (pcb->refused_data != nullptr)
        {
            free_pkt_buf(pcb->refused_data);
            pcb->refused_data = nullptr;
        }
    }
    if (shut_tx)
    {
        /* This can't happen twice since if it succeeds, the pcb's state is changed.
           Only close in these states as the others directly deallocate the PCB */
        switch (pcb->state)
        {
        case SYN_RCVD:
        case ESTABLISHED:
        case CLOSE_WAIT:
            return tcp_close_shutdown(pcb, (uint8_t)shut_rx);
        default:
            /* Not (yet?) connected, cannot shutdown the TX side as that would bring us
              into CLOSED state, where the PCB is deallocated. */
            return ERR_CONN;
        }
    }
    return STATUS_SUCCESS;
}

/**
 * Abandons a connection and optionally sends a RST to the remote
 * host.  Deletes the local protocol control block. This is done when
 * a connection is killed because of shortage of memory.
 *
 * @param pcb the TcpProtoCtrlBlk to abort
 * @param reset boolean to indicate whether a reset should be sent
 */
void
tcp_abandon(struct TcpPcb* pcb, int reset)
{
    // pcb->state LISTEN not allowed here
    lwip_assert("don't call tcp_abort/tcp_abandon for listen-pcbs",
                pcb->state != LISTEN);

    // Figure out on which TCP PCB list we are, and remove us. If we
    //   are in an active state, call the receive function associated with
    //   the PCB with a NULL argument, and send an RST to the remote end.
    if (pcb->state == TIME_WAIT)
    {
        tcp_pcb_remove(&tcp_tw_pcbs, pcb);
        tcp_free(pcb);
    }
    else
    {
        auto send_rst = 0;
        uint16_t local_port = 0;
        uint32_t seqno = pcb->snd_nxt;
        uint32_t ackno = pcb->rcv_nxt;

        tcp_err_fn errf = pcb->errf;

        void* errf_arg = pcb->callback_arg;
        if (pcb->state == CLOSED)
        {
            if (pcb->local_port != 0)
            {
                /* bound, not yet opened */
                remove_tcp_pcb_from_list(&tcp_bound_pcbs, pcb);
            }
        }
        else
        {
            send_rst = reset;
            local_port = pcb->local_port;
            TCP_PCB_REMOVE_ACTIVE(pcb);
        }
        if (pcb->unacked != nullptr)
        {
            tcp_segs_free(pcb->unacked);
        }
        if (pcb->unsent != nullptr)
        {
            tcp_segs_free(pcb->unsent);
        }

        if (pcb->ooseq != nullptr)
        {
            tcp_segs_free(pcb->ooseq);
        }

        tcp_backlog_accepted(pcb);
        if (send_rst)
        {
            Logf(true, ("tcp_abandon: sending RST\n"));
            tcp_rst(pcb, seqno, ackno, &pcb->local_ip, &pcb->remote_ip, local_port, pcb->remote_port);
        }
        pcb->state;
        tcp_free(pcb);
        // TCP_EVENT_ERR(last_state, errf, errf_arg, ERR_ABRT);
    }
}

/**
 * @ingroup tcp_raw
 * Aborts the connection by sending a RST (reset) segment to the remote
 * host. The pcb is deallocated. This function never fails.
 *
 * ATTENTION: When calling this from one of the TCP callbacks, make
 * sure you always return ERR_ABRT (and never return ERR_ABRT otherwise
 * or you will risk accessing deallocated memory or memory leaks!
 *
 * @param pcb the tcp pcb to abort
 */
void
tcp_abort(struct TcpPcb* pcb)
{
    tcp_abandon(pcb, 1);
}

/**
 * @ingroup tcp_raw
 * Binds the connection to a local port number and IP address. If the
 * IP address is not given (i.e., ipaddr == IP_ANY_TYPE), the connection is
 * bound to all local IP addresses.
 * If another connection is bound to the same port, the function will
 * return ERR_USE, otherwise ERR_OK is returned.
 *
 * @param pcb the TcpProtoCtrlBlk to bind (no check is done whether this pcb is
 *        already bound!)
 * @param ipaddr the local ip address to bind to (use IPx_ADDR_ANY to bind
 *        to any local address
 * @param port the local port to bind to
 * @return ERR_USE if the port is already in use
 *         ERR_VAL if bind failed because the PCB is not in a valid state
 *         ERR_OK if bound
 */
LwipStatus
tcp_bind(struct TcpPcb* pcb, const IpAddrInfo* ipaddr, uint16_t port)
{
    auto max_pcb_list = NUM_TCP_PCB_LISTS;
    IpAddrInfo zoned_ipaddr{};

    /// Unless the REUSEADDR flag is set, we have to check the pcbs in TIME-WAIT state,
    /// also. We do not dump TIME_WAIT pcb's; they can still be matched by incoming
    /// packets using both local and remote IP addresses and ports to distinguish.
    if (ip_get_option(reinterpret_cast<IpPcb*>(pcb), SOF_REUSEADDR))
    {
        max_pcb_list = NUM_TCP_PCB_LISTS_NO_TIME_WAIT;
    }


    /* If the given IP address should have a zone but doesn't, assign one now.
      * This is legacy support: scope-aware callers should always provide properly
      * zoned source addresses. Do the zone selection before the address-in-use
      * check below; as such we have to make a temporary copy of the address. */
    if (is_ip_addr_v6(ipaddr) && ip6_addr_lacks_zone(&ipaddr->u_addr.ip6, IP6_UNICAST))
    {
        copy_ip_addr(&zoned_ipaddr, ipaddr);
        select_ip6_addr_zone((&zoned_ipaddr.u_addr.ip6), (&zoned_ipaddr.u_addr.ip6),);
        ipaddr = &zoned_ipaddr;
    }

    if (port == 0)
    {
        port = tcp_new_port();
        if (port == 0)
        {
            return ERR_BUF;
        }
    }
    else
    {
        /* Check if the address already is in use (on all lists) */
        for (int i = 0; i < max_pcb_list; i++)
        {
            for (struct TcpPcb* cpcb = *tcp_pcb_lists[i]; cpcb != nullptr; cpcb = cpcb->next)
            {
                if (cpcb->local_port == port)
                {
                    /* Omit checking for the same port if both pcbs have REUSEADDR set.
                       For LWIP_SO_REUSEADDR, the duplicate-check for a 5-tuple is done in
                       tcp_connect. */
                    if (!ip_get_option((IpPcb*)pcb, SOF_REUSEADDR) ||
                        !ip_get_option((IpPcb*)cpcb, SOF_REUSEADDR))

                    {
                        /* @todo: check accept_any_ip_version */
                        if ((is_ip_addr_v6(ipaddr) == is_ip_addr_v6(&cpcb->local_ip)) &&
                            (is_ip_addr_any(&cpcb->local_ip) ||
                                is_ip_addr_any(ipaddr) ||
                                compare_ip_addr(&cpcb->local_ip, ipaddr)))
                        {
                            return ERR_USE;
                        }
                    }
                }
            }
        }
    }

    if (!is_ip_addr_any(ipaddr)

        || (get_ip_addr_type(ipaddr) != get_ip_addr_type(&pcb->local_ip))

    )
    {
        set_ip_addr(&pcb->local_ip, ipaddr);
    }
    pcb->local_port = port;
    reg_tcp_pcb(&tcp_bound_pcbs, pcb);
    Logf(true, "tcp_bind: bind to port %d\n", port);
    return STATUS_SUCCESS;
}

/**
 * @ingroup tcp_raw
 * Binds the connection to a netif and IP address.
 * After calling this function, all packets received via this PCB
 * are guaranteed to have come in via the specified netif, and all
 * outgoing packets will go out via the specified netif.
 *
 * @param pcb the TcpProtoCtrlBlk to bind.
 * @param netif the netif to bind to. Can be NULL.
 */
void
tcp_bind_netif(struct TcpPcb* pcb, const NetworkInterface* netif)
{

    if (netif != nullptr)
    {
        pcb->netif_idx = get_and_inc_netif_num(netif);
    }
    else
    {
        pcb->netif_idx = NETIF_NO_INDEX;
    }
}


/**
 * Default accept callback if no accept callback is specified by the user.
 */
static LwipStatus
tcp_accept_null(void* arg, struct TcpPcb* pcb, LwipStatus err)
{
    lwip_assert("tcp_accept_null: invalid pcb", pcb != nullptr);

    tcp_abort(pcb);

    return ERR_ABRT;
}


/**
 * @ingroup tcp_raw
 * Set the state of the connection to be LISTEN, which means that it
 * is able to accept incoming connections. The protocol control block
 * is reallocated in order to consume less memory. Setting the
 * connection to LISTEN is an irreversible process.
 * When an incoming connection is accepted, the function specified with
 * the tcp_accept() function will be called. The pcb has to be bound
 * to a local port with the tcp_bind() function.
 *
 * The tcp_listen() function returns a new connection identifier, and
 * the one passed as an argument to the function will be
 * deallocated. The reason for this behavior is that less memory is
 * needed for a connection that is listening, so tcp_listen() will
 * reclaim the memory needed for the original connection and allocate a
 * new smaller memory block for the listening connection.
 *
 * tcp_listen() may return NULL if no memory was available for the
 * listening connection. If so, the memory associated with the pcb
 * passed as an argument to tcp_listen() will not be deallocated.
 *
 * The backlog limits the number of outstanding connections
 * in the listen queue to the value specified by the backlog argument.
 * To use it, your need to set TCP_LISTEN_BACKLOG=1 in your lwipopts.h.
 *
 * @param pcb the original TcpProtoCtrlBlk
 * @param backlog the incoming connections queue limit
 * @return TcpProtoCtrlBlk used for listening, consumes less memory.
 *
 * @note The original TcpProtoCtrlBlk is freed. This function therefore has to be
 *       called like this:
 *             tpcb = tcp_listen_with_backlog(tpcb, backlog);
 */
struct TcpPcb*
tcp_listen_with_backlog(struct TcpPcb* pcb, uint8_t backlog)
{

    return tcp_listen_with_backlog_and_err(pcb, backlog, nullptr);
}

/**
 * @ingroup tcp_raw
 * Set the state of the connection to be LISTEN, which means that it
 * is able to accept incoming connections. The protocol control block
 * is reallocated in order to consume less memory. Setting the
 * connection to LISTEN is an irreversible process.
 *
 * @param pcb the original TcpProtoCtrlBlk
 * @param backlog the incoming connections queue limit
 * @param err when NULL is returned, this contains the error reason
 * @return TcpProtoCtrlBlk used for listening, consumes less memory.
 *
 * @note The original TcpProtoCtrlBlk is freed. This function therefore has to be
 *       called like this:
 *             tpcb = tcp_listen_with_backlog_and_err(tpcb, backlog, &err);
 */
struct TcpPcb*
tcp_listen_with_backlog_and_err(struct TcpPcb* pcb, uint8_t backlog, LwipStatus* err)
{
    struct TcpPcbListen* lpcb = nullptr;
    LwipStatus res; /* already listening? */
    if (pcb->state == LISTEN)
    {
        lpcb = (struct TcpPcbListen *)pcb;
        res = ERR_ALREADY;
        goto done;
    }

    if (ip_get_option((IpPcb*)pcb, SOF_REUSEADDR))
    {
        /* Since SOF_REUSEADDR allows reusing a local address before the pcb's usage
           is declared (listen-/connection-pcb), we have to make sure now that
           this port is only used once for every local IP. */
        for (lpcb = tcp_listen_pcbs.listen_pcbs; lpcb != nullptr; lpcb = lpcb->next)
        {
            if ((lpcb->local_port == pcb->local_port) &&
                compare_ip_addr(&lpcb->local_ip, &pcb->local_ip))
            {
                /* this address/port is already used */
                lpcb = nullptr;
                res = ERR_USE;
                goto done;
            }
        }
    }

    // lpcb = (struct tcp_pcb_listen *)memp_malloc(MEMP_TCP_PCB_LISTEN);
    lpcb = new TcpPcbListen;
    if (lpcb == nullptr)
    {
        res = ERR_MEM;
        goto done;
    }
    lpcb->callback_arg = pcb->callback_arg;
    lpcb->local_port = pcb->local_port;
    lpcb->state = LISTEN;
    lpcb->prio = pcb->prio;
    lpcb->so_options = pcb->so_options;
    lpcb->netif_idx = NETIF_NO_INDEX;
    lpcb->ttl = pcb->ttl;
    lpcb->tos = pcb->tos;

    set_ip_addr_type(lpcb->remote_ip, pcb->local_ip.type);

    copy_ip_addr(&lpcb->local_ip, &pcb->local_ip);
    if (pcb->local_port != 0)
    {
        // tcp_remove_listener(&tcp_bound_pcbs, pcb);
    }

    /* copy over ext_args to listening pcb  */
    memcpy(&lpcb->ext_args, &pcb->ext_args, sizeof(pcb->ext_args));

    tcp_free(pcb);

    lpcb->accept_fn = tcp_accept_null;

    lpcb->accepts_pending = 0;
    tcp_backlog_set(reinterpret_cast<TcpPcb*>(lpcb), backlog);

    reg_tcp_pcb(&tcp_listen_pcbs.pcbs, reinterpret_cast<TcpPcb*>(lpcb));
    res = STATUS_SUCCESS;
done:
    if (err != nullptr)
    {
        *err = res;
    }
    return reinterpret_cast<struct TcpPcb *>(lpcb);
}

/**
 * Update the state that tracks the available window space to advertise.
 *
 * Returns how much extra window would be advertised if we sent an
 * update now.
 */
uint32_t
tcp_update_rcv_ann_wnd(struct TcpPcb* pcb)
{
    lwip_assert("tcp_update_rcv_ann_wnd: invalid pcb", pcb != nullptr);
    uint32_t new_right_edge = pcb->rcv_nxt + pcb->rcv_wnd;

    if (TCP_SEQ_GEQ(new_right_edge, pcb->rcv_ann_right_edge + std::min(uint16_t(TCP_WND / 2), pcb->mss)))
    {
        /* we can advertise more window */
        pcb->rcv_ann_wnd = pcb->rcv_wnd;
        return new_right_edge - pcb->rcv_ann_right_edge;
    }
    else
    {
        if (TCP_SEQ_GT(pcb->rcv_nxt, pcb->rcv_ann_right_edge))
        {
            /* Can happen due to other end sending out of advertised window,
             * but within actual available (but not yet advertised) window */
            pcb->rcv_ann_wnd = 0;
        }
        else
        {
            /* keep the right edge of window constant */
            uint32_t new_rcv_ann_wnd = pcb->rcv_ann_right_edge - pcb->rcv_nxt;

            pcb->rcv_ann_wnd = (TcpWndSize)new_rcv_ann_wnd;
        }
        return 0;
    }
}

/**
 * @ingroup tcp_raw
 * This function should be called by the application when it has
 * processed the data. The purpose is to advertise a larger window
 * when the data has been processed.
 *
 * @param pcb the TcpProtoCtrlBlk for which data is read
 * @param len the amount of bytes that have been read by the application
 */
void
tcp_recved(struct TcpPcb* pcb, uint16_t len)
{
    /* pcb->state LISTEN not allowed here */
    lwip_assert("don't call tcp_recved for listen-pcbs",
                pcb->state != LISTEN);

    TcpWndSize rcv_wnd = (TcpWndSize)(pcb->rcv_wnd + len);
    if ((rcv_wnd > TCP_WND_MAX(pcb)) || (rcv_wnd < pcb->rcv_wnd))
    {
        /* window got too big or TcpWndSizeT overflow */
        Logf(true, ("tcp_recved: window got too big or TcpWndSizeT overflow\n"));
        pcb->rcv_wnd = TCP_WND_MAX(pcb);
    }
    else
    {
        pcb->rcv_wnd = rcv_wnd;
    }

    uint32_t wnd_inflation = tcp_update_rcv_ann_wnd(pcb);

    /* If the change in the right edge of window is significant (default
     * watermark is TCP_WND/4), then send an explicit update now.
     * Otherwise wait for a packet to be sent in the normal course of
     * events (or more window to be available later) */
    if (wnd_inflation >= TCP_WND_UPDATE_THRESHOLD)
    {
        tcp_ack_now(pcb);
        tcp_output(pcb);
    }
    Logf(true,
         "tcp_recved: received %d bytes, wnd %d (%d).\n",
         len,
         pcb->rcv_wnd,
         uint16_t(TCP_WND_MAX(pcb) - pcb->rcv_wnd));
}

/**
 * Allocate a new local TCP port.
 *
 * @return a new (free) local TCP port number
 */
static uint16_t
tcp_new_port(void)
{
    uint16_t n = 0;
again:
    tcp_port++;
    if (tcp_port == TCP_LOCAL_PORT_RANGE_END)
    {
        tcp_port = TCP_LOCAL_PORT_RANGE_START;
    }
    /* Check all PCB lists. */
    for (uint8_t i = 0; i < NUM_TCP_PCB_LISTS; i++)
    {
        for (struct TcpPcb* pcb = *tcp_pcb_lists[i]; pcb != nullptr; pcb = pcb->next)
        {
            if (pcb->local_port == tcp_port)
            {
                n++;
                if (n > (TCP_LOCAL_PORT_RANGE_END - TCP_LOCAL_PORT_RANGE_START))
                {
                    return 0;
                }
                goto again;
            }
        }
    }
    return tcp_port;
}

/**
 * @ingroup tcp_raw
 * Connects to another host. The function given as the "connected"
 * argument will be called when the connection has been established.
 *  Sets up the pcb to connect to the remote host and sends the
 * initial SYN segment which opens the connection.
 *
 * The tcp_connect() function returns immediately; it does not wait for
 * the connection to be properly setup. Instead, it will call the
 * function specified as the fourth argument (the "connected" argument)
 * when the connection is established. If the connection could not be
 * properly established, either because the other host refused the
 * connection or because the other host didn't answer, the "err"
 * callback function of this pcb (registered with tcp_err, see below)
 * will be called.
 *
 * The tcp_connect() function can return ERR_MEM if no memory is
 * available for enqueueing the SYN segment. If the SYN indeed was
 * enqueued successfully, the tcp_connect() function returns ERR_OK.
 *
 * @param pcb the TcpProtoCtrlBlk used to establish the connection
 * @param ipaddr the remote ip address to connect to
 * @param port the remote tcp port to connect to
 * @param connected callback function to call when connected (on error,
                    the err calback will be called)
 * @return ERR_VAL if invalid arguments are given
 *         ERR_OK if connect request has been sent
 *         other LwipStatus values if connect request couldn't be sent
 */
LwipStatus tcp_connect(struct TcpPcb* pcb,
                       const IpAddrInfo* ipaddr,
                       const uint16_t port,
                       const tcp_connected_fn connected)
{
    NetworkInterface* netif = nullptr;
    Logf(true, "tcp_connect to port %d\n", port);
    set_ip_addr(&pcb->remote_ip, ipaddr);
    pcb->remote_port = port;

    if (pcb->netif_idx != NETIF_NO_INDEX)
    {
        // netif = get_netif_by_index(pcb->netif_idx);
    }
    else
    {
        /* check if we have a route to the remote host */
        netif = ip_route(&pcb->local_ip, &pcb->remote_ip,);
    }
    if (netif == nullptr)
    {
        /* Don't even try to send a SYN packet if we have no route since that will fail. */
        return STATUS_E_ROUTING;
    }

    /* check if local IP has been assigned to pcb, if not, get one */
    if (is_ip_addr_any(&pcb->local_ip))
    {
        const IpAddrInfo* local_ip = ip_netif_get_local_ip(netif, ipaddr,);
        if (local_ip == nullptr)
        {
            return STATUS_E_ROUTING;
        }
        copy_ip_addr(&pcb->local_ip, local_ip);
    }

    /* If the given IP address should have a zone but doesn't, assign one now.
     * Given that we already have the target netif, this is easy and cheap. */
    if (is_ip_addr_v6(&pcb->remote_ip) &&
        ip6_addr_lacks_zone((&pcb->remote_ip.u_addr.ip6), IP6_UNICAST))
    {
        assign_ip6_addr_zone((&pcb->remote_ip.u_addr.ip6), IP6_UNICAST, netif,);
    }
    const uint16_t old_local_port = pcb->local_port;
    if (pcb->local_port == 0)
    {
        pcb->local_port = tcp_new_port();
        if (pcb->local_port == 0)
        {
            return ERR_BUF;
        }
    }
    else
    {
        if (ip_get_option(reinterpret_cast<IpPcb*>(pcb), SOF_REUSEADDR) != 0u)
        {
            /* Don't check listen- and bound-PCBs, check active- and TIME-WAIT PCBs. */
            for (int i = 2; i < NUM_TCP_PCB_LISTS; i++)
            {
                for (struct TcpPcb* cpcb = *tcp_pcb_lists[i]; cpcb != nullptr; cpcb = cpcb->next)
                {
                    if ((cpcb->local_port == pcb->local_port) &&
                        (cpcb->remote_port == port) &&
                        compare_ip_addr(&cpcb->local_ip, &pcb->local_ip) &&
                        compare_ip_addr(&cpcb->remote_ip, ipaddr))
                    {
                        /* linux returns EISCONN here, but ERR_USE should be OK for us */
                        return ERR_USE;
                    }
                }
            }
        }
    }
    auto iss = tcp_next_iss(pcb);
    pcb->rcv_nxt = 0;
    pcb->snd_nxt = iss;
    pcb->lastack = iss - 1;
    pcb->snd_wl2 = iss - 1;
    pcb->snd_lbb = iss - 1;
    /* Start with a window that does not need scaling. When window scaling is
       enabled and used, the window is enlarged when both sides agree on scaling. */
    pcb->rcv_wnd = pcb->rcv_ann_wnd = TCPWND_MIN16(TCP_WND);
    pcb->rcv_ann_right_edge = pcb->rcv_nxt;
    pcb->snd_wnd = TCP_WND;
    /* As initial send MSS, we use TCP_MSS but limit it to 536.
       The send MSS is updated when an MSS option is received. */
    pcb->mss = INITIAL_MSS;

    pcb->mss = tcp_eff_send_mss_netif(pcb->mss, netif, &pcb->remote_ip);

    pcb->cwnd = 1;

    pcb->connected = connected;


    /* Send a SYN together with the MSS option. */
    LwipStatus ret = tcp_enqueue_flags(pcb, TCP_SYN);
    if (ret == STATUS_SUCCESS)
    {
        /* SYN segment was enqueued, changed the pcbs state now */
        pcb->state = SYN_SENT;
        if (old_local_port != 0)
        {
            // TCP_RMV(&tcp_bound_pcbs, pcb);
        }
        // TCP_REG_ACTIVE(pcb);


        tcp_output(pcb);
    }
    return ret;
}

/**
 * Called every 500 ms and implements the retransmission timer and the timer that
 * removes PCBs that have been in TIME-WAIT for enough time. It also increments
 * various timers such as the inactivity timer in each PCB.
 *
 * Automatically called from tcp_tmr().
 */
void
tcp_slowtmr(void)
{
    uint8_t pcb_remove; /* flag if a PCB should be removed */
    LwipStatus err = STATUS_SUCCESS;

    ++tcp_ticks;
    // ++tcp_timer_ctr;

tcp_slowtmr_start:
    /* Steps through all of the active PCBs. */
    struct TcpPcb* prev = nullptr;
    struct TcpPcb* pcb = tcp_active_pcbs;
    if (pcb == nullptr)
    {
        Logf(true, ("tcp_slowtmr: no active pcbs\n"));
    }
    while (pcb != nullptr)
    {
        Logf(true, ("tcp_slowtmr: processing active pcb\n"));
        lwip_assert("tcp_slowtmr: active pcb->state != CLOSED\n", pcb->state != CLOSED);
        lwip_assert("tcp_slowtmr: active pcb->state != LISTEN\n", pcb->state != LISTEN);
        lwip_assert("tcp_slowtmr: active pcb->state != TIME-WAIT\n", pcb->state != TIME_WAIT);
        // if (pcb->last_timer == tcp_timer_ctr)
        // {
        //     /* skip this pcb, we have already processed it */
        //     prev = pcb;
        //     pcb = pcb->next;
        //     continue;
        // }
        // pcb->last_timer = tcp_timer_ctr;

        pcb_remove = 0;
        uint8_t pcb_reset = 0;

        if (pcb->state == SYN_SENT && pcb->nrtx >= TCP_SYNMAXRTX)
        {
            ++pcb_remove;
            Logf(true, ("tcp_slowtmr: max SYN retries reached\n"));
        }
        else if (pcb->nrtx >= TCP_MAXRTX)
        {
            ++pcb_remove;
            Logf(true, ("tcp_slowtmr: max DATA retries reached\n"));
        }
        else
        {
            if (pcb->persist_backoff > 0)
            {
                lwip_assert("tcp_slowtimr: persist ticking with in-flight data", pcb->unacked == nullptr);
                lwip_assert("tcp_slowtimr: persist ticking with empty send buffer", pcb->unsent != nullptr);
                if (pcb->persist_probe >= TCP_MAXRTX)
                {
                    ++pcb_remove; /* max probes reached */
                }
                else
                {
                    uint8_t backoff_cnt = TCP_PERSIST_BACKOFF[pcb->persist_backoff - 1];
                    if (pcb->persist_cnt < backoff_cnt)
                    {
                        pcb->persist_cnt++;
                    }
                    if (pcb->persist_cnt >= backoff_cnt)
                    {
                        int next_slot = 1; /* increment timer to next slot */
                        /* If snd_wnd is zero, send 1 byte probes */
                        if (pcb->snd_wnd == 0)
                        {
                            if (tcp_zero_window_probe(pcb) != STATUS_SUCCESS)
                            {
                                next_slot = 0; /* try probe again with current slot */
                            }
                            /* snd_wnd not fully closed, split unsent head and fill window */
                        }
                        else
                        {
                            if (tcp_split_unsent_seg(pcb, (uint16_t)pcb->snd_wnd) == STATUS_SUCCESS)
                            {
                                if (tcp_output(pcb) == STATUS_SUCCESS)
                                {
                                    /* sending will cancel persist timer, else retry with current slot */
                                    next_slot = 0;
                                }
                            }
                        }
                        if (next_slot)
                        {
                            pcb->persist_cnt = 0;
                            if (pcb->persist_backoff < sizeof(TCP_PERSIST_BACKOFF))
                            {
                                pcb->persist_backoff++;
                            }
                        }
                    }
                }
            }
            else
            {
                /* Increase the retransmission timer if it is running */
                if ((pcb->rtime >= 0) && (pcb->rtime < 0x7FFF))
                {
                    ++pcb->rtime;
                }

                if (pcb->rtime >= pcb->rto)
                {
                    /* Time for a retransmission. */
                    // Logf(true, ("tcp_slowtmr: rtime %"S16_F
                    //          " pcb->rto %"S16_F"\n",
                    //          pcb->rtime, pcb->rto));
                    /* If prepare phase fails but we have unsent data but no unacked data,
                       still execute the backoff calculations below, as this means we somehow
                       failed to send segment. */
                    if ((tcp_rexmit_rto_prepare(pcb) == STATUS_SUCCESS) || ((pcb->unacked == nullptr) && (pcb->unsent != nullptr
                    )))
                    {
                        /* Double retransmission time-out unless we are trying to
                         * connect to somebody (i.e., we are in SYN_SENT). */
                        if (pcb->state != SYN_SENT)
                        {
                            const auto backoff_idx = std::min(pcb->nrtx, uint8_t(sizeof(TCP_BACKOFF) - 1));
                            int calc_rto = ((pcb->sa >> 3) + pcb->sv) << TCP_BACKOFF[backoff_idx];
                            pcb->rto = int16_t(std::min(calc_rto, 0x7FFF));
                        }

                        /* Reset the retransmission timer. */
                        pcb->rtime = 0;

                        /* Reduce congestion window and ssthresh. */
                        const auto eff_wnd = std::min(pcb->cwnd, pcb->snd_wnd);
                        pcb->ssthresh = eff_wnd >> 1;
                        if (pcb->ssthresh < (TcpWndSize)(pcb->mss << 1))
                        {
                            pcb->ssthresh = (TcpWndSize)(pcb->mss << 1);
                        }
                        pcb->cwnd = pcb->mss;
                        // Logf(true, ("tcp_slowtmr: cwnd %"TCPWNDSIZE_F
                        //          " ssthresh %d\n",
                        //          pcb->cwnd, pcb->ssthresh));
                        pcb->bytes_acked = 0;

                        /* The following needs to be called AFTER cwnd is set to one
                           mss - STJ */
                        tcp_rexmit_rto_commit(pcb);
                    }
                }
            }
        }
        /* Check if this PCB has stayed too long in FIN-WAIT-2 */
        if (pcb->state == FIN_WAIT_2)
        {
            /* If this PCB is in FIN_WAIT_2 because of SHUT_WR don't let it time out. */
            if (pcb->flags & TF_RXCLOSED)
            {
                /* PCB was fully closed (either through close() or SHUT_RDWR):
                   normal FIN-WAIT timeout handling. */
                if ((uint32_t)(tcp_ticks - pcb->tmr) >
                    TCP_FIN_WAIT_TIMEOUT / TCP_SLOW_INTERVAL)
                {
                    ++pcb_remove;
                    Logf(true, ("tcp_slowtmr: removing pcb stuck in FIN-WAIT-2\n"));
                }
            }
        }

        /* Check if KEEPALIVE should be sent */
        if (ip_get_option((IpPcb*)pcb, SOF_KEEPALIVE) &&
            ((pcb->state == ESTABLISHED) ||
                (pcb->state == CLOSE_WAIT)))
        {
            if (uint32_t(tcp_ticks - pcb->tmr) >
                (pcb->keep_idle + tcp_keep_dur(pcb)) / TCP_SLOW_INTERVAL)
            {
                Logf(true, ("tcp_slowtmr: KEEPALIVE timeout. Aborting connection to "));
                // ip_addr_debug_print_val(true, pcb->remote_ip);
                Logf(true, ("\n"));

                ++pcb_remove;
                ++pcb_reset;
            }
            else if (uint32_t(tcp_ticks - pcb->tmr) >
                (pcb->keep_idle + pcb->keep_cnt_sent * tcp_keep_intvl(pcb))
                / TCP_SLOW_INTERVAL)
            {
                err = tcp_keepalive(pcb);
                if (err == STATUS_SUCCESS)
                {
                    pcb->keep_cnt_sent++;
                }
            }
        }

        /* If this PCB has queued out of sequence data, but has been
           inactive for too long, will drop the data (it will eventually
           be retransmitted). */

        if (pcb->ooseq != nullptr &&
            (tcp_ticks - pcb->tmr >= (uint32_t)pcb->rto * TCP_OOSEQ_TIMEOUT))
        {
            // Logf(true, ("tcp_slowtmr: dropping OOSEQ queued data\n"));
            tcp_free_ooseq(pcb);
        }


        /* Check if this PCB has stayed too long in SYN-RCVD */
        if (pcb->state == SYN_RCVD)
        {
            if ((uint32_t)(tcp_ticks - pcb->tmr) >
                TCP_SYN_RCVD_TIMEOUT / TCP_SLOW_INTERVAL)
            {
                ++pcb_remove;
                Logf(true, ("tcp_slowtmr: removing pcb stuck in SYN-RCVD\n"));
            }
        }

        /* Check if this PCB has stayed too long in LAST-ACK */
        if (pcb->state == LAST_ACK)
        {
            if ((uint32_t)(tcp_ticks - pcb->tmr) > 2 * TCP_MSL / TCP_SLOW_INTERVAL)
            {
                ++pcb_remove;
                Logf(true, ("tcp_slowtmr: removing pcb stuck in LAST-ACK\n"));
            }
        }

        /* If the PCB should be removed, do it. */
        if (pcb_remove)
        {
            tcp_err_fn err_fn = pcb->errf;
            tcp_pcb_purge(pcb);
            /* Remove PCB from tcp_active_pcbs list. */
            if (prev != nullptr)
            {
                lwip_assert("tcp_slowtmr: middle tcp != tcp_active_pcbs", pcb != tcp_active_pcbs);
                prev->next = pcb->next;
            }
            else
            {
                /* This PCB was the first. */
                lwip_assert("tcp_slowtmr: first pcb == tcp_active_pcbs", tcp_active_pcbs == pcb);
                tcp_active_pcbs = pcb->next;
            }

            if (pcb_reset)
            {
                tcp_rst(pcb, pcb->snd_nxt, pcb->rcv_nxt, &pcb->local_ip, &pcb->remote_ip,
                        pcb->local_port, pcb->remote_port);
            }

            void* err_arg = pcb->callback_arg;
            enum TcpState last_state = pcb->state;
            struct TcpPcb* pcb2 = pcb;
            pcb = pcb->next;
            tcp_free(pcb2);

            tcp_active_pcbs_changed = 0;
            // TCP_EVENT_ERR(last_state, err_fn, err_arg, ERR_ABRT);
            if (tcp_active_pcbs_changed)
            {
                goto tcp_slowtmr_start;
            }
        }
        else
        {
            /* get the 'next' element now and work with 'prev' below (in case of abort) */
            prev = pcb;
            pcb = pcb->next;

            /* We check if we should poll the connection. */
            ++prev->polltmr;
            if (prev->polltmr >= prev->pollinterval)
            {
                prev->polltmr = 0;
                Logf(true, ("tcp_slowtmr: polling application\n"));
                tcp_active_pcbs_changed = 0;
                TCP_EVENT_POLL(prev, err);
                if (tcp_active_pcbs_changed)
                {
                    goto tcp_slowtmr_start;
                }
                /* if err == ERR_ABRT, 'prev' is already deallocated */
                if (err == STATUS_SUCCESS)
                {
                    tcp_output(prev);
                }
            }
        }
    }


    /* Steps through all of the TIME-WAIT PCBs. */
    prev = nullptr;
    pcb = tcp_tw_pcbs;
    while (pcb != nullptr)
    {
        lwip_assert("tcp_slowtmr: TIME-WAIT pcb->state == TIME-WAIT", pcb->state == TIME_WAIT);
        pcb_remove = 0;

        /* Check if this PCB has stayed long enough in TIME-WAIT */
        if ((uint32_t)(tcp_ticks - pcb->tmr) > 2 * TCP_MSL / TCP_SLOW_INTERVAL)
        {
            ++pcb_remove;
        }

        /* If the PCB should be removed, do it. */
        if (pcb_remove)
        {
            tcp_pcb_purge(pcb);
            /* Remove PCB from tcp_tw_pcbs list. */
            if (prev != nullptr)
            {
                lwip_assert("tcp_slowtmr: middle tcp != tcp_tw_pcbs", pcb != tcp_tw_pcbs);
                prev->next = pcb->next;
            }
            else
            {
                /* This PCB was the first. */
                lwip_assert("tcp_slowtmr: first pcb == tcp_tw_pcbs", tcp_tw_pcbs == pcb);
                tcp_tw_pcbs = pcb->next;
            }
            struct TcpPcb* pcb2 = pcb;
            pcb = pcb->next;
            tcp_free(pcb2);
        }
        else
        {
            prev = pcb;
            pcb = pcb->next;
        }
    }
}

/**
 * Is called every TCP_FAST_INTERVAL (250 ms) and process data previously
 * "refused" by upper layer (application) and sends delayed ACKs or pending FINs.
 *
 * Automatically called from tcp_tmr().
 */
void
tcp_fasttmr(void)
{
    // ++tcp_timer_ctr;

tcp_fasttmr_start:
    struct TcpPcb* pcb = tcp_active_pcbs;

    while (pcb != nullptr)
    {
        // if (pcb->last_timer != tcp_timer_ctr)
        // {
        //     pcb->last_timer = tcp_timer_ctr;
        //     /* send delayed ACKs */
        //     if (pcb->flags & TF_ACK_DELAY)
        //     {
        //         Logf(true, ("tcp_fasttmr: delayed ACK\n"));
        //         tcp_ack_now(pcb);
        //         tcp_output(pcb);
        //         tcp_clear_flags(pcb, TF_ACK_DELAY | TF_ACK_NOW);
        //     }
        //     /* send pending FIN */
        //     if (pcb->flags & TF_CLOSEPEND)
        //     {
        //         Logf(true, ("tcp_fasttmr: pending FIN\n"));
        //         tcp_clear_flags(pcb, TF_CLOSEPEND);
        //         tcp_close_shutdown_fin(pcb);
        //     }
        //
        //     struct TcpPcb* next = pcb->next;
        //
        //     /* If there is data which was previously "refused" by upper layer */
        //     if (pcb->refused_data != nullptr)
        //     {
        //         tcp_active_pcbs_changed = 0;
        //         tcp_process_refused_data(pcb);
        //         if (tcp_active_pcbs_changed)
        //         {
        //             /* application callback has changed the pcb list: restart the loop */
        //             goto tcp_fasttmr_start;
        //         }
        //     }
        //     pcb = next;
        // }
        // else
        // {
        //     pcb = pcb->next;
        // }
    }
}

/** Call tcp_output for all active pcbs that have TF_NAGLEMEMERR set */
void
tcp_txnow(void)
{
    for (struct TcpPcb* pcb = tcp_active_pcbs; pcb != nullptr; pcb = pcb->next)
    {
        if (pcb->flags & TF_NAGLEMEMERR)
        {
            tcp_output(pcb);
        }
    }
}

/** Pass pcb->refused_data to the recv callback */
LwipStatus
tcp_process_refused_data(struct TcpPcb* pcb)
{
    struct PacketBuffer* rest;


    while (pcb->refused_data != nullptr)

    {
        LwipStatus err;
        // uint8_t refused_flags = pcb->refused_data->flags;
        /* set pcb->refused_data to NULL in case the callback frees it and then
           closes the pcb */
        struct PacketBuffer* refused_data = pcb->refused_data;

        // pbuf_split_64k(refused_data, &rest);
        pcb->refused_data = rest;

        /* Notify again application with data previously received. */
        Logf(true, ("tcp_input: notify kept packet\n"));
        TCP_EVENT_RECV(pcb, refused_data, ERR_OK, err);
        if (err == STATUS_SUCCESS)
        {
            /* did refused_data include a FIN? */
            // if ((refused_flags & PBUF_FLAG_TCP_FIN)
            //
            //     && (rest == nullptr)
            //
            //
            //
            // )
            // {
            //     /* correct rcv_wnd as the application won't call tcp_recved()
            //        for the FIN's seqno */
            //     if (pcb->rcv_wnd != TCP_WND_MAX(pcb))
            //     {
            //         pcb->rcv_wnd++;
            //     }
            //     TCP_EVENT_CLOSED(pcb, err);
            //     if (err == ERR_ABRT)
            //     {
            //         return ERR_ABRT;
            //     }
            // }
        }
        else if (err == ERR_ABRT)
        {
            /* if err == ERR_ABRT, 'pcb' is already deallocated */
            /* Drop incoming packets because pcb is "full" (only if the incoming
               segment contains data). */
            Logf(true, ("tcp_input: drop incoming packets, because pcb is \"full\"\n"));
            return ERR_ABRT;
        }
        else
        {
            /* data is still refused, PacketBuffer is still valid (go on for ACK-only packets) */

            if (rest != nullptr)
            {
                // pbuf_cat(refused_data, rest);
            }

            pcb->refused_data = refused_data;
            return ERR_INPROGRESS;
        }
    }
    return STATUS_SUCCESS;
}

/**
 * Deallocates a list of TCP segments (tcp_seg structures).
 *
 * @param seg tcp_seg list of TCP segments to free
 */
void
tcp_segs_free(struct TcpSeg* seg)
{
    while (seg != nullptr)
    {
        struct TcpSeg* next = seg->next;
        tcp_seg_free(seg);
        seg = next;
    }
}

/**
 * Frees a TCP segment (tcp_seg structure).
 *
 * @param seg single tcp_seg to free
 */
void
tcp_seg_free(struct TcpSeg* seg)
{
    if (seg != nullptr)
    {
        if (seg->p != nullptr)
        {
            free_pkt_buf(seg->p);
#if true
      seg->p = nullptr;
#endif /* true */
        }
        // memp_free(MEMP_TCP_SEG, seg);
        delete seg;
    }
}

/**
 * @ingroup tcp
 * Sets the priority of a connection.
 *
 * @param pcb the TcpProtoCtrlBlk to manipulate
 * @param prio new priority
 */
void
tcp_setprio(struct TcpPcb* pcb, uint8_t prio)
{



    pcb->prio = prio;
}

/**
 * Returns a copy of the given TCP segment.
 * The PacketBuffer and data are not copied, only the pointers
 *
 * @param seg the old tcp_seg
 * @return a copy of seg
 */
struct TcpSeg*
tcp_seg_copy(struct TcpSeg* seg)
{
    lwip_assert("tcp_seg_copy: invalid seg", seg != nullptr);

    // cseg = (struct tcp_seg *)memp_malloc(MEMP_TCP_SEG);
    struct TcpSeg* cseg = new TcpSeg;
    if (cseg == nullptr)
    {
        return nullptr;
    }
    memcpy((uint8_t *)cseg, (const uint8_t *)seg, sizeof(struct TcpSeg));
    // pbuf_ref(cseg->p);
    return cseg;
}


/**
 * Default receive callback that is called if the user didn't register
 * a recv callback for the pcb.
 */
LwipStatus
tcp_recv_null(void* arg, struct TcpPcb* pcb, struct PacketBuffer* p, LwipStatus err)
{
    if (p != nullptr)
    {
        tcp_recved(pcb, p->tot_len);
        free_pkt_buf(p);
    }
    else if (err == STATUS_SUCCESS)
    {
        return tcp_close(pcb);
    }
    return STATUS_SUCCESS;
}

/* Kills the oldest active connection that has a lower priority than 'prio'.
 *
 * @param prio minimum priority
 */
static void
tcp_kill_prio(uint8_t prio)
{
    uint8_t mprio = std::min((uint8_t)TCP_PRIO_MAX, prio);

    /* We want to kill connections with a lower prio, so bail out if
     * supplied prio is 0 - there can never be a lower prio
     */
    if (mprio == 0)
    {
        return;
    }

    /* We only want kill connections with a lower prio, so decrement prio by one
     * and start searching for oldest connection with same or lower priority than mprio.
     * We want to find the connections with the lowest possible prio, and among
     * these the one with the longest inactivity time.
     */
    mprio--;

    uint32_t inactivity = 0;
    struct TcpPcb* inactive = nullptr;
    for (struct TcpPcb* pcb = tcp_active_pcbs; pcb != nullptr; pcb = pcb->next)
    {
        /* lower prio is always a kill candidate */
        if ((pcb->prio < mprio) ||
            /* longer inactivity is also a kill candidate */
            ((pcb->prio == mprio) && ((uint32_t)(tcp_ticks - pcb->tmr) >= inactivity)))
        {
            inactivity = tcp_ticks - pcb->tmr;
            inactive = pcb;
            mprio = pcb->prio;
        }
    }
    if (inactive != nullptr)
    {
        Logf(true,
             "tcp_kill_prio: killing oldest PCB %p (%d)\n",
             static_cast<void *>(inactive),
             inactivity);
        tcp_abort(inactive);
    }
}

/**
 * Kills the oldest connection that is in specific state.
 * Called from tcp_alloc() for LAST_ACK and CLOSING if no more connections are available.
 */
static void
tcp_kill_state(enum TcpState state)
{
    lwip_assert("invalid state", (state == CLOSING) || (state == LAST_ACK));

    uint32_t inactivity = 0;
    struct TcpPcb* inactive = nullptr;
    /* Go through the list of active pcbs and get the oldest pcb that is in state
       CLOSING/LAST_ACK. */
    for (struct TcpPcb* pcb = tcp_active_pcbs; pcb != nullptr; pcb = pcb->next)
    {
        if (pcb->state == state)
        {
            if ((uint32_t)(tcp_ticks - pcb->tmr) >= inactivity)
            {
                inactivity = tcp_ticks - pcb->tmr;
                inactive = pcb;
            }
        }
    }
    if (inactive != nullptr)
    {
        //    Logf(true, ("tcp_kill_closing: killing oldest %s PCB %p (%d)\n",
        //                            tcp_state_str[state], (void *)inactive, inactivity));
        /* Don't send a RST, since no data is lost. */
        tcp_abandon(inactive, 0);
    }
}

/**
 * Kills the oldest connection that is in TIME_WAIT state.
 * Called from tcp_alloc() if no more connections are available.
 */
static void
tcp_kill_timewait(void)
{
    uint32_t inactivity = 0;
    struct TcpPcb* inactive = nullptr;
    /* Go through the list of TIME_WAIT pcbs and get the oldest pcb. */
    for (struct TcpPcb* pcb = tcp_tw_pcbs; pcb != nullptr; pcb = pcb->next)
    {
        if ((uint32_t)(tcp_ticks - pcb->tmr) >= inactivity)
        {
            inactivity = tcp_ticks - pcb->tmr;
            inactive = pcb;
        }
    }
    if (inactive != nullptr)
    {
        //    Logf(true, ("tcp_kill_timewait: killing oldest TIME-WAIT PCB %p (%d)\n",
        //                            (void *)inactive, inactivity));
        tcp_abort(inactive);
    }
}

/* Called when allocating a pcb fails.
 * In this case, we want to handle all pcbs that want to close first: if we can
 * now send the FIN (which failed before), the pcb might be in a state that is
 * OK for us to now free it.
 */
static void
tcp_handle_closepend(void)
{
    struct TcpPcb* pcb = tcp_active_pcbs;

    while (pcb != nullptr)
    {
        struct TcpPcb* next = pcb->next;
        /* send pending FIN */
        if (pcb->flags & TF_CLOSEPEND)
        {
            Logf(true, ("tcp_handle_closepend: pending FIN\n"));
            tcp_clear_flags(pcb, TF_CLOSEPEND);
            tcp_close_shutdown_fin(pcb);
        }
        pcb = next;
    }
}

/**
 * Allocate a new TcpProtoCtrlBlk structure.
 *
 * @param prio priority for the new pcb
 * @return a new TcpProtoCtrlBlk that initially is in state CLOSED
 */
struct TcpPcb*
tcp_alloc(uint8_t prio)
{
    // pcb = (struct TcpProtoCtrlBlk *)memp_malloc(MEMP_TCP_PCB);
    struct TcpPcb* pcb = new TcpPcb;
    if (pcb == nullptr)
    {
        /* Try to send FIN for all pcbs stuck in TF_CLOSEPEND first */
        tcp_handle_closepend();

        /* Try killing oldest connection in TIME-WAIT. */
        Logf(true, ("tcp_alloc: killing off oldest TIME-WAIT connection\n"));
        tcp_kill_timewait();
        /* Try to allocate a TcpProtoCtrlBlk again. */
        // pcb = (struct TcpProtoCtrlBlk *)memp_malloc(MEMP_TCP_PCB);
        pcb = new TcpPcb;
        if (pcb == nullptr)
        {
            /* Try killing oldest connection in LAST-ACK (these wouldn't go to TIME-WAIT). */
            Logf(true, ("tcp_alloc: killing off oldest LAST-ACK connection\n"));
            tcp_kill_state(LAST_ACK);
            /* Try to allocate a TcpProtoCtrlBlk again. */
            // pcb = (struct TcpProtoCtrlBlk *)memp_malloc(MEMP_TCP_PCB);
            pcb = new TcpPcb;
            if (pcb == nullptr)
            {
                /* Try killing oldest connection in CLOSING. */
                Logf(true, ("tcp_alloc: killing off oldest CLOSING connection\n"));
                tcp_kill_state(CLOSING);
                /* Try to allocate a TcpProtoCtrlBlk again. */
                // pcb = (struct TcpProtoCtrlBlk *)memp_malloc(MEMP_TCP_PCB);
                pcb = new TcpPcb;
                if (pcb == nullptr)
                {
                    /* Try killing oldest active connection with lower priority than the new one. */
                    Logf(true, "tcp_alloc: killing oldest connection with prio lower than %d\n", prio);
                    tcp_kill_prio(prio);
                    /* Try to allocate a TcpProtoCtrlBlk again. */
                    // pcb = (struct TcpProtoCtrlBlk *)memp_malloc(MEMP_TCP_PCB);
                    pcb = new TcpPcb;
                    if (pcb != nullptr)
                    {
                        /* adjust err stats: memp_malloc failed multiple times before */
                        // MEMP_STATS_DEC(err, MEMP_TCP_PCB);
                    }
                }
                if (pcb != nullptr)
                {
                    /* adjust err stats: memp_malloc failed multiple times before */
                    // MEMP_STATS_DEC(err, MEMP_TCP_PCB);
                }
            }
            if (pcb != nullptr)
            {
                /* adjust err stats: memp_malloc failed multiple times before */
                // MEMP_STATS_DEC(err, MEMP_TCP_PCB);
            }
        }
        if (pcb != nullptr)
        {
            /* adjust err stats: memp_malloc failed above */
            // MEMP_STATS_DEC(err, MEMP_TCP_PCB);
        }
    }
    if (pcb != nullptr)
    {
        /* zero out the whole pcb, so there is no need to initialize members to zero */
        memset(pcb, 0, sizeof(struct TcpPcb));
        pcb->prio = prio;
        pcb->snd_buf = TCP_SND_BUF;
        /* Start with a window that does not need scaling. When window scaling is
           enabled and used, the window is enlarged when both sides agree on scaling. */
        pcb->rcv_wnd = pcb->rcv_ann_wnd = TCPWND_MIN16(TCP_WND);
        pcb->ttl = TCP_TTL;
        /* As initial send MSS, we use TCP_MSS but limit it to 536.
           The send MSS is updated when an MSS option is received. */
        pcb->mss = INITIAL_MSS;
        pcb->rto = 3000 / TCP_SLOW_INTERVAL;
        pcb->sv = 3000 / TCP_SLOW_INTERVAL;
        pcb->rtime = -1;
        pcb->cwnd = 1;
        pcb->tmr = tcp_ticks;
        // pcb->last_timer = tcp_timer_ctr;

        /* RFC 5681 recommends setting ssthresh abritrarily high and gives an example
        of using the largest advertised receive window.  We've seen complications with
        receiving TCPs that use window scaling and/or window auto-tuning where the
        initial advertised window is very small and then grows rapidly once the
        connection is established. To avoid these complications, we set ssthresh to the
        largest effective cwnd (amount of in-flight data) that the sender can have. */
        pcb->ssthresh = TCP_SND_BUF;


        pcb->recv = tcp_recv_null;


        /* Init KEEPALIVE timer */
        pcb->keep_idle = TCP_KEEPIDLE_DEFAULT;


        pcb->keep_intvl = TCP_KEEPINTVL_DEFAULT;
        pcb->keep_cnt = TCP_KEEPCNT_DEFAULT;
    }
    return pcb;
}

/**
 * @ingroup tcp_raw
 * Creates a new TCP protocol control block but doesn't place it on
 * any of the TCP PCB lists.
 * The pcb is not put on any list until binding using tcp_bind().
 * If memory is not available for creating the new pcb, NULL is returned.
 *
 * @internal: Maybe there should be a idle TCP PCB list where these
 * PCBs are put on. Port reservation using tcp_bind() is implemented but
 * allocated pcbs that are not bound can't be killed automatically if wanting
 * to allocate a pcb with higher prio (@see tcp_kill_prio())
 *
 * @return a new TcpProtoCtrlBlk that initially is in state CLOSED
 */
struct TcpPcb*
tcp_new()
{
    return tcp_alloc(TCP_PRIO_NORMAL);
}

/**
 * @ingroup tcp_raw
 * Creates a new TCP protocol control block but doesn't
 * place it on any of the TCP PCB lists.
 * The pcb is not put on any list until binding using tcp_bind().
 *
 * @param type IP address type, see @ref lwip_ip_addr_type definitions.
 * If you want to listen to IPv4 and IPv6 (dual-stack) connections,
 * supply @ref IPADDR_TYPE_ANY as argument and bind to @ref IP_ANY_TYPE.
 * @return a new TcpProtoCtrlBlk that initially is in state CLOSED
 */
struct TcpPcb* tcp_new_ip_type(IpAddrType type)
{
    auto pcb = tcp_alloc(TCP_PRIO_NORMAL);
    if (pcb != nullptr)
    {
        set_ip_addr_type(pcb->local_ip, type);
        set_ip_addr_type(pcb->remote_ip, type);
    }
    return pcb;
}

/**
 * @ingroup tcp_raw
 * Specifies the program specific state that should be passed to all
 * other callback functions. The "pcb" argument is the current TCP
 * connection control block, and the "arg" argument is the argument
 * that will be passed to the callbacks.
 *
 * @param pcb TcpProtoCtrlBlk to set the callback argument
 * @param arg void pointer argument to pass to callback functions
 */
void
tcp_arg(struct TcpPcb* pcb, void* arg)
{

    /* This function is allowed to be called for both listen pcbs and
       connection pcbs. */
    if (pcb != nullptr)
    {
        pcb->callback_arg = arg;
    }
}


/**
 * @ingroup tcp_raw
 * Sets the callback function that will be called when new data
 * arrives. The callback function will be passed a NULL PacketBuffer to
 * indicate that the remote host has closed the connection. If the
 * callback function returns ERR_OK or ERR_ABRT it must have
 * freed the PacketBuffer, otherwise it must not have freed it.
 *
 * @param pcb TcpProtoCtrlBlk to set the recv callback
 * @param recv callback function to call for this pcb when data is received
 */
void
tcp_recv(struct TcpPcb* pcb, tcp_recv_fn recv)
{

    if (pcb != nullptr)
    {
        lwip_assert("invalid socket state for recv callback", pcb->state != LISTEN);
        pcb->recv = recv;
    }
}

/**
 * @ingroup tcp_raw
 * Specifies the callback function that should be called when data has
 * successfully been received (i.e., acknowledged) by the remote
 * host. The len argument passed to the callback function gives the
 * amount bytes that was acknowledged by the last acknowledgment.
 *
 * @param pcb TcpProtoCtrlBlk to set the sent callback
 * @param sent callback function to call for this pcb when data is successfully sent
 */
void
tcp_sent(struct TcpPcb* pcb, tcp_sent_fn sent)
{

    if (pcb != nullptr)
    {
        lwip_assert("invalid socket state for sent callback", pcb->state != LISTEN);
        pcb->sent = sent;
    }
}

/**
 * @ingroup tcp_raw
 * Used to specify the function that should be called when a fatal error
 * has occurred on the connection.
 *
 * If a connection is aborted because of an error, the application is
 * alerted of this event by the err callback. Errors that might abort a
 * connection are when there is a shortage of memory. The callback
 * function to be called is set using the tcp_err() function.
 *
 * @note The corresponding pcb is already freed when this callback is called!
 *
 * @param pcb TcpProtoCtrlBlk to set the err callback
 * @param err callback function to call for this pcb when a fatal error
 *        has occurred on the connection
 */
void
tcp_err(struct TcpPcb* pcb, tcp_err_fn err)
{

    if (pcb != nullptr)
    {
        lwip_assert("invalid socket state for err callback", pcb->state != LISTEN);
        pcb->errf = err;
    }
}

/**
 * @ingroup tcp_raw
 * Used for specifying the function that should be called when a
 * LISTENing connection has been connected to another host.
 *
 * @param pcb TcpProtoCtrlBlk to set the accept callback
 * @param accept callback function to call for this pcb when LISTENing
 *        connection has been connected to another host
 */
void
tcp_accept(struct TcpPcb* pcb, tcp_accept_fn accept)
{

    if ((pcb != nullptr) && (pcb->state == LISTEN))
    {
        struct TcpPcbListen* lpcb = (struct TcpPcbListen *)pcb;
        lpcb->accept_fn = accept;
    }
}


/**
 * @ingroup tcp_raw
 * Specifies the polling interval and the callback function that should
 * be called to poll the application. The interval is specified in
 * number of TCP coarse grained timer shots, which typically occurs
 * twice a second. An interval of 10 means that the application would
 * be polled every 5 seconds.
 *
 * When a connection is idle (i.e., no data is either transmitted or
 * received), lwIP will repeatedly poll the application by calling a
 * specified callback function. This can be used either as a watchdog
 * timer for killing connections that have stayed idle for too long, or
 * as a method of waiting for memory to become available. For instance,
 * if a call to tcp_write() has failed because memory wasn't available,
 * the application may use the polling functionality to call tcp_write()
 * again when the connection has been idle for a while.
 */
void
tcp_poll(struct TcpPcb* pcb, tcp_poll_fn poll, uint8_t interval)
{



    lwip_assert("invalid socket state for poll", pcb->state != LISTEN);


    pcb->poll = poll;

    pcb->pollinterval = interval;
}

/**
 * Purges a TCP PCB. Removes any buffered data and frees the buffer memory
 * (pcb->ooseq, pcb->unsent and pcb->unacked are freed).
 *
 * @param pcb TcpProtoCtrlBlk to purge. The pcb itself is not deallocated!
 */
void
tcp_pcb_purge(struct TcpPcb* pcb)
{
    if (pcb->state != CLOSED &&
        pcb->state != TIME_WAIT &&
        pcb->state != LISTEN)
    {
        Logf(true, ("tcp_pcb_purge\n"));

        tcp_backlog_accepted(pcb);

        if (pcb->refused_data != nullptr)
        {
            Logf(true, ("tcp_pcb_purge: data left on ->refused_data\n"));
            free_pkt_buf(pcb->refused_data);
            pcb->refused_data = nullptr;
        }
        if (pcb->unsent != nullptr)
        {
            Logf(true, ("tcp_pcb_purge: not all data sent\n"));
        }
        if (pcb->unacked != nullptr)
        {
            Logf(true, ("tcp_pcb_purge: data left on ->unacked\n"));
        }

        if (pcb->ooseq != nullptr)
        {
            Logf(true, ("tcp_pcb_purge: data left on ->ooseq\n"));
            tcp_free_ooseq(pcb);
        }


        /* Stop the retransmission timer as it will expect data on unacked
           queue if it fires */
        pcb->rtime = -1;

        tcp_segs_free(pcb->unsent);
        tcp_segs_free(pcb->unacked);
        pcb->unacked = pcb->unsent = nullptr;

        pcb->unsent_oversize = 0;
    }
}

/**
 * Purges the PCB and removes it from a PCB list. Any delayed ACKs are sent first.
 *
 * @param pcblist PCB list to purge.
 * @param pcb TcpProtoCtrlBlk to purge. The pcb itself is NOT deallocated!
 */
void
tcp_pcb_remove(struct TcpPcb** pcblist, struct TcpPcb* pcb)
{
    lwip_assert("tcp_pcb_remove: invalid pcb", pcb != nullptr);
    lwip_assert("tcp_pcb_remove: invalid pcblist", pcblist != nullptr);

    // TCP_RMV(pcblist, pcb);

    tcp_pcb_purge(pcb);

    /* if there is an outstanding delayed ACKs, send it */
    if ((pcb->state != TIME_WAIT) &&
        (pcb->state != LISTEN) &&
        (pcb->flags & TF_ACK_DELAY))
    {
        tcp_ack_now(pcb);
        tcp_output(pcb);
    }

    if (pcb->state != LISTEN)
    {
        lwip_assert("unsent segments leaking", pcb->unsent == nullptr);
        lwip_assert("unacked segments leaking", pcb->unacked == nullptr);

        lwip_assert("ooseq segments leaking", pcb->ooseq == nullptr);
    }

    pcb->state = CLOSED;
    /* reset the local port to prevent the pcb from being 'bound' */
    pcb->local_port = 0;

    lwip_assert("tcp_pcb_remove: tcp_pcbs_sane()", tcp_pcbs_sane());
}

/**
 * Calculates a new initial sequence number for new connections.
 *
 * @return uint32_t pseudo random sequence number
 */
uint32_t
tcp_next_iss(struct TcpPcb* pcb)
{
    lwip_assert("tcp_next_iss: invalid pcb", pcb != nullptr);
    // return LWIP_HOOK_TCP_ISN(&pcb->local_ip, pcb->local_port, &pcb->remote_ip, pcb->remote_port);
    return 0;
}


/**
 * Calculates the effective send mss that can be used for a specific IP address
 * by calculating the minimum of TCP_MSS and the mtu (if set) of the target
 * netif (if not NULL).
 */
uint16_t
tcp_eff_send_mss_netif(uint16_t sendmss, NetworkInterface* outif, const IpAddrInfo* dest)
{
    uint16_t mtu;
    lwip_assert("tcp_eff_send_mss_netif: invalid dst_ip", dest != nullptr);


    if (is_ip_addr_v6(dest))

    {
        /* First look in destination cache, to see if there is a Path MTU. */
        mtu = nd6_get_destination_mtu((&dest->u_addr.ip6), outif);
    }

    else

    {
        if (outif == nullptr)
        {
            return sendmss;
        }
        mtu = outif->mtu;
    }


    if (mtu != 0)
    {
        uint16_t offset;

        if (is_ip_addr_v6(dest))

        {
            offset = IP6_HDR_LEN + TCP_HDR_LEN;
        }

        else


        {
            offset = IP4_HDR_LEN + TCP_HDR_LEN;
        }

        uint16_t mss_s = (mtu > offset) ? (uint16_t)(mtu - offset) : 0;
        /* RFC 1122, chap 4.2.2.6:
         * Eff.snd.MSS = min(SendMSS+20, MMS_S) - TCPhdrsize - IPoptionsize
         * We correct for TCP options in tcp_write(), and don't support IP options.
         */
        sendmss = std::min(sendmss, mss_s);
    }
    return sendmss;
}


/** Helper function for tcp_netif_ip_addr_changed() that iterates a pcb list */
static void
tcp_netif_ip_addr_changed_pcblist(const IpAddrInfo* old_addr, struct TcpPcb* pcb_list)
{
    struct TcpPcb* pcb = pcb_list;

    lwip_assert("tcp_netif_ip_addr_changed_pcblist: invalid old_addr", old_addr != nullptr);

    while (pcb != nullptr)
    {
        /* PCB bound to current local interface address? */
        if (compare_ip_addr(&pcb->local_ip, old_addr)

            /* connections to link-local addresses must persist (RFC3927 ch. 1.9) */
            && (!is_ip_addr_v4(pcb->local_ip) || !is_ip4_addr_link_local((&pcb->local_ip.u_addr.ip4)))

        )
        {
            /* this connection must be aborted */
            struct TcpPcb* next = pcb->next;
            Logf(true, "netif_set_ipaddr: aborting TCP pcb %p\n", pcb);
            tcp_abort(pcb);
            pcb = next;
        }
        else
        {
            pcb = pcb->next;
        }
    }
}

/** This function is called from netif.c when address is changed or netif is removed
 *
 * @param old_addr IP address of the netif before change
 * @param new_addr IP address of the netif after change or NULL if netif has been removed
 */
void
tcp_netif_ip_addr_changed(const IpAddrInfo* old_addr, const IpAddrInfo* new_addr)
{
    if (!is_ip_addr_any(old_addr))
    {
        tcp_netif_ip_addr_changed_pcblist(old_addr, tcp_active_pcbs);
        tcp_netif_ip_addr_changed_pcblist(old_addr, tcp_bound_pcbs);

        if (!is_ip_addr_any(new_addr))
        {
            /* PCB bound to current local interface address? */
            for (struct TcpPcbListen* lpcb = tcp_listen_pcbs.listen_pcbs; lpcb != nullptr; lpcb = lpcb->next)
            {
                /* PCB bound to current local interface address? */
                if (compare_ip_addr(&lpcb->local_ip, old_addr))
                {
                    /* The PCB is listening to the old ipaddr and
                      * is set to listen to the new one instead */
                    copy_ip_addr(&lpcb->local_ip, new_addr);
                }
            }
        }
    }
}

const char*
tcp_debug_state_str(enum TcpState s)
{
    return tcp_state_str[s];
}

LwipStatus
tcp_tcp_get_tcp_addrinfo(struct TcpPcb* pcb, int local, IpAddrInfo* addr, uint16_t* port)
{
    if (pcb)
    {
        if (local)
        {
            if (addr)
            {
                *addr = pcb->local_ip;
            }
            if (port)
            {
                *port = pcb->local_port;
            }
        }
        else
        {
            if (addr)
            {
                *addr = pcb->remote_ip;
            }
            if (port)
            {
                *port = pcb->remote_port;
            }
        }
        return STATUS_SUCCESS;
    }
    return ERR_VAL;
}


/* Free all ooseq pbufs (and possibly reset SACK state) */
void
tcp_free_ooseq(struct TcpPcb* pcb)
{
    if (pcb->ooseq)
    {
        tcp_segs_free(pcb->ooseq);
        pcb->ooseq = nullptr;

        memset(pcb->rcv_sacks, 0, sizeof(pcb->rcv_sacks));
    }
}


/**
 * @defgroup tcp_raw_extargs ext arguments
 * @ingroup tcp_raw
 * Additional data storage per tcp pcb\n
 * @see @ref tcp_raw
 *
 * When LWIP_TCP_PCB_NUM_EXT_ARGS is > 0, every tcp pcb (including listen pcb)
 * includes a number of additional argument entries in an array.
 *
 * To support memory management, in addition to a 'uint8_t *', callbacks can be
 * provided to manage transition from listening pcbs to connections and to
 * deallocate memory when a pcb is deallocated (see struct @ref tcp_ext_arg_callbacks).
 *
 * After allocating this index, use @ref tcp_ext_arg_set and @ref tcp_ext_arg_get
 * to store and load arguments from this index for a given pcb.
 */

static uint8_t tcp_ext_arg_id;

/**
 * @ingroup tcp_raw_extargs
 * Allocate an index to store data in ext_args member of struct TcpProtoCtrlBlk.
 * Returned value is an index in mentioned array.
 * The index is *global* over all pcbs!
 *
 * When @ref LWIP_TCP_PCB_NUM_EXT_ARGS is > 0, every tcp pcb (including listen pcb)
 * includes a number of additional argument entries in an array.
 *
 * To support memory management, in addition to a 'uint8_t *', callbacks can be
 * provided to manage transition from listening pcbs to connections and to
 * deallocate memory when a pcb is deallocated (see struct @ref tcp_ext_arg_callbacks).
 *
 * After allocating this index, use @ref tcp_ext_arg_set and @ref tcp_ext_arg_get
 * to store and load arguments from this index for a given pcb.
 *
 * @return a unique index into struct TcpProtoCtrlBlk.ext_args
 */
uint8_t
tcp_ext_arg_alloc_id()
{
    uint8_t result = tcp_ext_arg_id;
    tcp_ext_arg_id++;



    lwip_assert("Increase LWIP_TCP_PCB_NUM_EXT_ARGS in lwipopts.h", result < LWIP_TCP_PCB_NUM_EXT_ARGS);
    return result;
}


// void
// tcp_ext_arg_set_callbacks(struct TcpPcb* pcb, uint8_t id, const struct tcp_ext_arg_callbacks* const callbacks)
// {
//     lwip_assert("pcb != NULL", pcb != nullptr);
//     lwip_assert("id < LWIP_TCP_PCB_NUM_EXT_ARGS", id < LWIP_TCP_PCB_NUM_EXT_ARGS);
//     lwip_assert("callbacks != NULL", callbacks != nullptr);
//
//
//
//     pcb->ext_args[id].callbacks = callbacks;
// }

/**
 * @ingroup tcp_raw_extargs
 * Set data for a given index of ext_args on the specified pcb.
 *
 * @param pcb TcpProtoCtrlBlk for which to set the data
 * @param id ext_args index to set (allocated via @ref tcp_ext_arg_alloc_id)
 * @param arg data pointer to set
 */
void tcp_ext_arg_set(struct TcpPcb* pcb, uint8_t id, void* arg)
{
    lwip_assert("pcb != NULL", pcb != nullptr);
    lwip_assert("id < LWIP_TCP_PCB_NUM_EXT_ARGS", id < LWIP_TCP_PCB_NUM_EXT_ARGS);



    pcb->ext_args[id].data = arg;
}

/**
 * @ingroup tcp_raw_extargs
 * Set data for a given index of ext_args on the specified pcb.
 *
 * @param pcb TcpProtoCtrlBlk for which to set the data
 * @param id ext_args index to set (allocated via @ref tcp_ext_arg_alloc_id)
 * @return data pointer at the given index
 */
void* tcp_ext_arg_get(const struct TcpPcb* pcb, uint8_t id)
{
    lwip_assert("pcb != NULL", pcb != nullptr);
    lwip_assert("id < LWIP_TCP_PCB_NUM_EXT_ARGS", id < LWIP_TCP_PCB_NUM_EXT_ARGS);



    return pcb->ext_args[id].data;
}

/** This function calls the "destroy" callback for all ext_args once a pcb is
 * freed.
 */
static void
tcp_ext_arg_invoke_callbacks_destroyed(TcpPcbExtArgs* ext_args)
{
    lwip_assert("ext_args != NULL", ext_args != nullptr);

    for (auto i = 0; i < LWIP_TCP_PCB_NUM_EXT_ARGS; i++)
    {
        if (ext_args[i].callbacks != nullptr)
        {
            if (ext_args[i].callbacks->destroy != nullptr)
            {
                ext_args[i].callbacks->destroy(uint8_t(i), ext_args[i].data);
            }
        }
    }
}

/** This function calls the "passive_open" callback for all ext_args if a connection
 * is in the process of being accepted. This is called just after the SYN is
 * received and before a SYN/ACK is sent, to allow to modify the very first
 * segment sent even on passive open. Naturally, the "accepted" callback of the
 * pcb has not been called yet!
 */
LwipStatus
tcp_ext_arg_invoke_callbacks_passive_open(struct TcpPcbListen* lpcb, struct TcpPcb* cpcb)
{
    lwip_assert("lpcb != NULL", lpcb != nullptr);
    lwip_assert("cpcb != NULL", cpcb != nullptr);

    for (int i = 0; i < LWIP_TCP_PCB_NUM_EXT_ARGS; i++)
    {
        if (lpcb->ext_args[i].callbacks != nullptr)
        {
            if (lpcb->ext_args[i].callbacks->passive_open != nullptr)
            {
                LwipStatus err = lpcb->ext_args[i].callbacks->passive_open((uint8_t)i, lpcb, cpcb);
                if (err != STATUS_SUCCESS)
                {
                    return err;
                }
            }
        }
    }
    return STATUS_SUCCESS;
}

/**
 * Attempt to reclaim some memory from queued out-of-sequence TCP segments
 * if we run out of pool pbufs. It's better to give priority to new packets
 * if we're running out.
 *
 * This must be done in the correct thread context therefore this function
 * can only be used with NO_SYS=0 and through tcpip_callback.
 */

static
void
pbuf_free_ooseq(TcpPcb* tcp_active_pcbs)
{
    sys_prot_t lev;
    SYS_ARCH_PROTECT(lev);
    pbuf_free_ooseq_pending = 0;
    sys_arch_unprotect(lev);

    for (struct TcpPcb* pcb = tcp_active_pcbs; nullptr != pcb; pcb = pcb->next)
    {
        if (pcb->ooseq != nullptr)
        {
            // Free the ooseq pbufs of one PCB only
            Logf(true,
                 ("pbuf_free_ooseq: freeing out-of-sequence pbufs\n"));
            tcp_free_ooseq(pcb);
            return;
        }
    }
}

//
// Just a callback function for tcpip_callback() that calls pbuf_free_ooseq().
//
static void pbuf_free_ooseq_callback(void* arg)
{
    TcpPcb* pcbs = (TcpPcb*)arg;
    pbuf_free_ooseq(pcbs);
}

//
//
//
inline void pbuf_pool_free_ooseq_queue_call(sys_prot_t old_level)
{
    if (tcpip_try_callback(pbuf_free_ooseq_callback, nullptr) != STATUS_SUCCESS)
    {
        SYS_ARCH_PROTECT(old_level);
        pbuf_free_ooseq_pending = 0;
        sys_arch_unprotect(old_level);
    }
}

// volatile uint8_t pbuf_free_ooseq_pending;

/// Queue a call to pbuf_free_ooseq if not already queued.
void pbuf_pool_is_empty()
{
    sys_prot_t lev;
    SYS_ARCH_PROTECT(lev);
    const auto queued = pbuf_free_ooseq_pending;
    pbuf_free_ooseq_pending = 1;
    sys_arch_unprotect(lev);

    if (!queued)
    {
        /// queue a call to pbuf_free_ooseq if not already queued
        pbuf_pool_free_ooseq_queue_call(lev);
    }
}
