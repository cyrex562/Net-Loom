/**
 * @file
 * Network Point to Point Protocol over Serial file.
 *
 */ /*
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
 */
#include <ppp_opts.h>
#include <cstring>
#include <arch.h>
#include <lwip_status.h>
#include <packet_buffer.h>
#include <sys.h>
#include <network_interface.h>
#include <tcpip_priv.h>
#include <ip4.h> /* for ip4_input() */
#include <ppp_impl.h>
#include <pppos.h>
#include <vj.h>
#include <ppp.h>
/* Memory pool */
// LWIP_MEMPOOL_DECLARE(PPPOS_PCB, MEMP_NUM_PPPOS_INTERFACES, sizeof(pppos_pcb), "PPPOS_PCB")
/* callbacks called from PPP core */
static LwipStatus
pppos_write(PppPcb* ppp, uint8_t* ctx, struct PacketBuffer* p);
static LwipStatus
pppos_netif_output(PppPcb* ppp, uint8_t* ctx, struct PacketBuffer* pb, uint16_t protocol);
static void
pppos_connect(PppPcb* ppp, uint8_t* ctx);
static void
pppos_listen(PppPcb* ppp, uint8_t* ctx);
static void
pppos_disconnect(PppPcb* ppp, uint8_t* ctx);
static LwipStatus
pppos_destroy(PppPcb* ppp, uint8_t* ctx);
static void
pppos_send_config(PppPcb* ppp, uint8_t* ctx, uint32_t accm, int pcomp, int accomp);
static void
pppos_recv_config(PppPcb* ppp, uint8_t* ctx, uint32_t accm, int pcomp, int accomp);
/* Prototypes for procedures local to this file. */
static void
pppos_input_callback(void* arg);
static void
pppos_input_free_current_packet(pppos_pcb* pppos);
static void
pppos_input_drop(pppos_pcb* pppos);
static LwipStatus
pppos_output_append(pppos_pcb* pppos,
                    LwipStatus err,
                    struct PacketBuffer* nb,
                    uint8_t c,
                    uint8_t accm,
                    uint16_t* fcs);
static LwipStatus
pppos_output_last(pppos_pcb* pppos,
                  LwipStatus err,
                  struct PacketBuffer* nb,
                  uint16_t* fcs); /* Callbacks structure for PPP core */
// static const struct LinkCallbacks pppos_callbacks = {
//   pppos_connect,
//
//   pppos_listen,
//
//   pppos_disconnect,
//   pppos_destroy,
//   pppos_write,
//   pppos_netif_output,
//   pppos_send_config,
//   pppos_recv_config
// };
/* PPP's Asynchronous-Control-Character-Map.  The mask array is used
 * to select the specific bit for a character. */
#define ESCAPE_P(accm, c) ((accm)[(c) >> 3] & 1 << (c & 0x07))
/*
 * FCS lookup table as calculated by genfcstab.
 */
static const uint16_t fcstab[256] = {
    0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf, 0x8c48, 0x9dc1,
    0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7, 0x1081, 0x0108, 0x3393, 0x221a,
    0x56a5, 0x472c, 0x75b7, 0x643e, 0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64,
    0xf9ff, 0xe876, 0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
    0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5, 0x3183, 0x200a,
    0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c, 0xbdcb, 0xac42, 0x9ed9, 0x8f50,
    0xfbef, 0xea66, 0xd8fd, 0xc974, 0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9,
    0x2732, 0x36bb, 0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
    0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a, 0xdecd, 0xcf44,
    0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72, 0x6306, 0x728f, 0x4014, 0x519d,
    0x2522, 0x34ab, 0x0630, 0x17b9, 0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3,
    0x8a78, 0x9bf1, 0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
    0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70, 0x8408, 0x9581,
    0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7, 0x0840, 0x19c9, 0x2b52, 0x3adb,
    0x4e64, 0x5fed, 0x6d76, 0x7cff, 0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324,
    0xf1bf, 0xe036, 0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
    0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5, 0x2942, 0x38cb,
    0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd, 0xb58b, 0xa402, 0x9699, 0x8710,
    0xf3af, 0xe226, 0xd0bd, 0xc134, 0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e,
    0x5cf5, 0x4d7c, 0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
    0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb, 0xd68d, 0xc704,
    0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232, 0x5ac5, 0x4b4c, 0x79d7, 0x685e,
    0x1ce1, 0x0d68, 0x3ff3, 0x2e7a, 0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3,
    0x8238, 0x93b1, 0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
    0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330, 0x7bc7, 0x6a4e,
    0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};
#define PPP_FCS(fcs, c) (((fcs) >> 8) ^ fcstab[((fcs) ^ (c)) & 0xff])
#define PPPOS_DECL_PROTECT(lev) sys_prot_t lev
#define PPPOS_PROTECT(lev) SYS_ARCH_PROTECT(lev)
#define PPPOS_UNPROTECT(lev) SYS_ARCH_UNPROTECT(lev)

/*
 * Create a new PPP connection using the given serial I/O device.
 *
 * Return 0 on success, an error code on failure.
 */
PppPcb*
pppos_create(NetworkInterface* pppif,
             pppos_output_cb_fn output_cb,
             ppp_link_status_cb_fn link_status_cb,
             void* ctx_cb)
{
    pppos_pcb* pppos = new pppos_pcb;
    if (pppos == nullptr)
    {
        return nullptr;
    }
    PppPcb* ppp = init_ppp_pcb(pppif, pppos, link_status_cb, ctx_cb);
    if (ppp == nullptr)
    {
        // LWIP_MEMPOOL_FREE(PPPOS_PCB, pppos);
        delete pppos;
        return nullptr;
    }
    memset(pppos, 0, sizeof(pppos_pcb));
    pppos->ppp = ppp;
    pppos->output_cb = output_cb;
    return ppp;
} /* Called by PPP core */
static LwipStatus
pppos_write(PppPcb* ppp, uint8_t* ctx, struct PacketBuffer* p)
{
    pppos_pcb* pppos = (pppos_pcb *)ctx;
    uint16_t fcs_out; /* Grab an output buffer. Using PBUF_POOL here for tx is ok since the PacketBuffer
        gets freed by 'pppos_output_last' before this function returns and thus
        cannot starve rx. */
    // struct PacketBuffer* nb = pbuf_alloc();
    PacketBuffer pb{};
    if (nb == nullptr)
    {
        // PPPDEBUG(LOG_WARNING, ("pppos_write[%d]: alloc fail\n", ppp->netif->num));
        // LINK_STATS_INC(link.memerr);
        // LINK_STATS_INC(link.drop);
        // MIB2_STATS_NETIF_INC(ppp->netif, ifoutdiscards);
        free_pkt_buf(p);
        return ERR_MEM;
    } /* Set nb->tot_len to actual payload length */
    nb->tot_len = p->len;
    /* If the link has been idle, we'll send a fresh flag character to
      * flush any noise. */
    LwipStatus err = STATUS_SUCCESS;
    if ((sys_now() - pppos->last_xmit) >= PPP_MAXIDLEFLAG)
    {
        err = pppos_output_append(pppos, err, nb, PPP_FLAG, 0, nullptr);
    } /* Load output buffer. */
    fcs_out = PPP_INITFCS;
    uint8_t* s = (uint8_t*)p->payload;
    uint16_t n = p->len;
    while (n-- > 0)
    {
        err = pppos_output_append(pppos, err, nb, *s++, 1, &fcs_out);
    }
    err = pppos_output_last(pppos, err, nb, &fcs_out);
    if (err == STATUS_SUCCESS)
    {
        // PPPDEBUG(LOG_INFO, ("pppos_write[%d]: len=%d\n", ppp->netif->num, p->len));
    }
    else
    {
        // PPPDEBUG(LOG_WARNING, ("pppos_write[%d]: output failed len=%d\n", ppp->netif->num, p->len));
    }
    free_pkt_buf(p);
    return err;
} /* Called by PPP core */
static LwipStatus
pppos_netif_output(PppPcb* ppp, uint8_t* ctx, struct PacketBuffer* pb, uint16_t protocol)
{
    pppos_pcb* pppos = (pppos_pcb *)ctx;
    uint16_t fcs_out; /* Grab an output buffer. Using PBUF_POOL here for tx is ok since the PacketBuffer
        gets freed by 'pppos_output_last' before this function returns and thus
        cannot starve rx. */
    // struct PacketBuffer* nb = pbuf_alloc();
    PacketBuffer nb{};
    if (nb == nullptr)
    {
        // PPPDEBUG(LOG_WARNING, ("pppos_netif_output[%d]: alloc fail\n", ppp->netif->num));
        // LINK_STATS_INC(link.memerr);
        // LINK_STATS_INC(link.drop);
        // MIB2_STATS_NETIF_INC(ppp->netif, ifoutdiscards);
        return ERR_MEM;
    } /* Set nb->tot_len to actual payload length */
    nb->tot_len = pb->tot_len;
    /* If the link has been idle, we'll send a fresh flag character to
      * flush any noise. */
    LwipStatus err = STATUS_SUCCESS;
    if ((sys_now() - pppos->last_xmit) >= PPP_MAXIDLEFLAG)
    {
        err = pppos_output_append(pppos, err, nb, PPP_FLAG, 0, nullptr);
    }
    fcs_out = PPP_INITFCS;
    if (!pppos->accomp)
    {
        err = pppos_output_append(pppos, err, nb, PPP_ALLSTATIONS, 1, &fcs_out);
        err = pppos_output_append(pppos, err, nb, PPP_UI, 1, &fcs_out);
    }
    if (!pppos->pcomp || protocol > 0xFF)
    {
        err = pppos_output_append(pppos, err, nb, (protocol >> 8) & 0xFF, 1, &fcs_out);
    }
    err = pppos_output_append(pppos, err, nb, protocol & 0xFF, 1, &fcs_out);
    /* Load packet. */
    for (struct PacketBuffer* p = pb; p; p = p->next)
    {
        uint16_t n = p->len;
        uint8_t* s = (uint8_t*)p->payload;
        while (n-- > 0)
        {
            err = pppos_output_append(pppos, err, nb, *s++, 1, &fcs_out);
        }
    }
    err = pppos_output_last(pppos, err, nb, &fcs_out);
    if (err == STATUS_SUCCESS)
    {
        // PPPDEBUG(LOG_INFO, ("pppos_netif_output[%d]: proto=0x%x, len = %d\n", ppp->netif->num, protocol, pb->tot_len));
    }
    else
    {
        // PPPDEBUG(LOG_WARNING, ("pppos_netif_output[%d]: output failed proto=0x%x, len = %d\n", ppp->netif->num, protocol, pb->tot_len));
    }
    return err;
}

static void
pppos_connect(PppPcb* ppp, uint8_t* ctx)
{
    pppos_pcb* pppos = (pppos_pcb *)ctx;
    PPPOS_DECL_PROTECT(lev); /* input PacketBuffer left over from last session? */
    pppos_input_free_current_packet(pppos);
    /* reset PPPoS control block to its initial state */
    memset(&pppos->last_xmit, 0, sizeof(pppos_pcb) - offsetof(pppos_pcb, last_xmit)); /*
   * Default the in and out accm so that escape and flag characters
   * are always escaped.
   */
    pppos->in_accm[15] = 0x60; /* no need to protect since RX is not running */
    pppos->out_accm[15] = 0x60;
    PPPOS_PROTECT(lev);
    pppos->open = 1;
    PPPOS_UNPROTECT(lev); /*
   * Start the connection and handle incoming events (packet or timeout).
   */ // PPPDEBUG(LOG_INFO, ("pppos_connect: unit %d: connecting\n", ppp->netif->num));
    ppp_start(ppp); /* notify upper layers */
}

static void
pppos_listen(PppPcb* ppp, uint8_t* ctx)
{
    pppos_pcb* pppos = (pppos_pcb *)ctx;
    PPPOS_DECL_PROTECT(lev); /* input PacketBuffer left over from last session? */
    pppos_input_free_current_packet(pppos);
    /* reset PPPoS control block to its initial state */
    memset(&pppos->last_xmit, 0, sizeof(pppos_pcb) - offsetof(pppos_pcb, last_xmit)); /*
   * Default the in and out accm so that escape and flag characters
   * are always escaped.
   */
    pppos->in_accm[15] = 0x60; /* no need to protect since RX is not running */
    pppos->out_accm[15] = 0x60;
    PPPOS_PROTECT(lev);
    pppos->open = 1;
    PPPOS_UNPROTECT(lev); /*
   * Wait for something to happen.
   */ // PPPDEBUG(LOG_INFO, ("pppos_listen: unit %d: listening\n", ppp->netif->num));
    ppp_start(ppp); /* notify upper layers */
}

static void
pppos_disconnect(PppPcb* ppp, uint8_t* ctx)
{
    pppos_pcb* pppos = (pppos_pcb *)ctx;
    PPPOS_DECL_PROTECT(lev);
    PPPOS_PROTECT(lev);
    pppos->open = 0;
    PPPOS_UNPROTECT(lev); /* If PPP_INPROC_IRQ_SAFE is used we cannot call
   * pppos_input_free_current_packet() here because
   * rx IRQ might still call pppos_input().
   */
    ppp_link_end(ppp); /* notify upper layers */
}

static LwipStatus
pppos_destroy(PppPcb* ppp, uint8_t* ctx)
{
    pppos_pcb* pppos = (pppos_pcb *)ctx;
    pppos_input_free_current_packet(pppos);
    // LWIP_MEMPOOL_FREE(PPPOS_PCB, pppos);
    return STATUS_SUCCESS;
} /** PPPoS input helper struct, must be packed since it is stored
 * to PacketBuffer->payload, which might be unaligned. */
struct pppos_input_header
{
    PppPcb* ppp;
}; /** Pass received raw characters to PPPoS to be decoded.
 *
 * @param ppp PPP descriptor index, returned by pppos_create()
 * @param s received data
 * @param l length of received data
 */
void
pppos_input(PppPcb* ppp, uint8_t* s, int l)
{
    pppos_pcb* pppos = (pppos_pcb *)ppp->link_ctx_cb;
    PPPOS_DECL_PROTECT(lev);
    // PPPDEBUG(LOG_DEBUG, ("pppos_input[%d]: got %d bytes\n", ppp->netif->num, l));
    while (l-- > 0)
    {
        uint8_t cur_char = *s++;
        PPPOS_PROTECT(lev);
        /* ppp_input can disconnect the interface, we need to abort to prevent a memory
            * leak if there are remaining bytes because pppos_connect and pppos_listen
            * functions expect input buffer to be free. Furthermore there are no real
            * reason to continue reading bytes if we are disconnected.
            */
        if (!pppos->open)
        {
            PPPOS_UNPROTECT(lev);
            return;
        }
        uint8_t escaped = ESCAPE_P(pppos->in_accm, cur_char);
        PPPOS_UNPROTECT(lev); /* Handle special characters. */
        if (escaped)
        {
            /* Check for escape sequences. */
            /* XXX Note that this does not handle an escaped 0x5d character which
                  * would appear as an escape character.  Since this is an ASCII ']'
                  * and there is no reason that I know of to escape it, I won't complicate
                  * the code to handle this case. GLL */
            if (cur_char == PPP_ESCAPE)
            {
                pppos->in_escaped = 1; /* Check for the flag character. */
            }
            else if (cur_char == PPP_FLAG)
            {
                /* If this is just an extra flag character, ignore it. */
                if (pppos->in_state <= PDADDRESS)
                {
                }
                else if (pppos->in_state < PDDATA)
                {
                    // PPPDEBUG(LOG_WARNING,
                    //          ("pppos_input[%d]: Dropping incomplete packet %d\n", ppp
                    //                                                               ->netif
                    //                                                               ->num,
                    //              pppos->in_state));
                    // LINK_STATS_INC(link.lenerr);
                    pppos_input_drop(pppos); /* If the fcs is invalid, drop the packet. */
                }
                else if (pppos->in_fcs != PPP_GOODFCS)
                {
                    // PPPDEBUG(LOG_INFO,
                    //          ("pppos_input[%d]: Dropping bad fcs 0x%x proto=0x%x\n", ppp
                    //                                                                  ->
                    //                                                                  netif
                    //                                                                  ->num
                    //              , pppos->in_fcs, pppos->in_protocol));
                    /* Note: If you get lots of these, check for UART frame errors or try different baud rate */
                    // LINK_STATS_INC(link.chkerr);
                    pppos_input_drop(pppos);
                    /* Otherwise it's a good packet so pass it on. */
                }
                else
                {
                    if (pppos->in_tail->len > 2)
                    {
                        pppos->in_tail->len -= 2;
                        pppos->in_tail->tot_len = pppos->in_tail->len;
                        if (pppos->in_tail != pppos->in_head)
                        {
                            // pbuf_cat(pppos->in_head, pppos->in_tail);
                        }
                    }
                    else
                    {
                        pppos->in_tail->tot_len = pppos->in_tail->len;
                        if (pppos->in_tail != pppos->in_head)
                        {
                            // pbuf_cat(pppos->in_head, pppos->in_tail);
                        }
                        // pbuf_realloc(pppos->in_head);
                    } /* Dispatch the packet thereby consuming it. */
                    struct PacketBuffer* inp = pppos->in_head; /* Packet consumed, release our references. */
                    pppos->in_head = nullptr;
                    pppos->in_tail = nullptr;
                    /* hide the room for Ethernet forwarding header */
                    // pbuf_remove_header(inp,
                    //                    PBUF_LINK_ENCAPSULATION_HLEN + PBUF_LINK_HLEN);
                    if (tcpip_try_callback(pppos_input_callback, inp) != STATUS_SUCCESS)
                    {
                        // PPPDEBUG(LOG_ERR,
                        //          ("pppos_input[%d]: tcpip_callback() failed, dropping packet\n"
                        //              , ppp->netif->num));
                        free_pkt_buf(inp);
                        // LINK_STATS_INC(link.drop);
                        // MIB2_STATS_NETIF_INC(ppp->netif, ifindiscards);
                    }
                } /* Prepare for a new packet. */
                pppos->in_fcs = PPP_INITFCS;
                pppos->in_state = PDADDRESS;
                pppos->in_escaped = 0;
                /* Other characters are usually control characters that may have
                      * been inserted by the physical layer so here we just drop them. */
            }
            else
            {
                // PPPDEBUG(LOG_WARNING,
                //          ("pppos_input[%d]: Dropping ACCM char <%d>\n", ppp->netif->num,
                //              cur_char));
            } /* Process other characters. */
        }
        else
        {
            /* Unencode escaped characters. */
            if (pppos->in_escaped)
            {
                pppos->in_escaped = 0;
                cur_char ^= PPP_TRANS;
            } /* Process character relative to current state. */
            switch (pppos->in_state)
            {
            case PDIDLE: /* Idle state - waiting. */
                /* Drop the character if it's not 0xff
                          * we would have processed a flag character above. */ if (
                    cur_char != PPP_ALLSTATIONS)
                {
                    break;
                } /* no break */ /* Fall through */
            case PDSTART: /* Process start flag. */ /* Prepare for a new packet. */ pppos
                    ->in_fcs = PPP_INITFCS; /* no break */ /* Fall through */
            case PDADDRESS: /* Process address field. */ if (cur_char == PPP_ALLSTATIONS)
                {
                    pppos->in_state = PDCONTROL;
                    break;
                } /* no break */ /* Else assume compressed address and control fields so
           * fall through to get the protocol... */ /* Fall through */
            case PDCONTROL: /* Process control field. */
                /* If we don't get a valid control code, restart. */ if (cur_char ==
                    PPP_UI)
                {
                    pppos->in_state = PDPROTOCOL1;
                    break;
                } /* no break */ /* Fall through */
            case PDPROTOCOL1: /* Process protocol field 1. */
                /* If the lower bit is set, this is the end of the protocol
                          * field. */ if (cur_char & 1)
                {
                    pppos->in_protocol = cur_char;
                    pppos->in_state = PDDATA;
                }
                else
                {
                    pppos->in_protocol = (uint16_t)cur_char << 8;
                    pppos->in_state = PDPROTOCOL2;
                }
                break;
            case PDPROTOCOL2: /* Process protocol field 2. */ pppos->in_protocol |=
                    cur_char;
                pppos->in_state = PDDATA;
                break;
            case PDDATA: /* Process data byte. */
                /* Make space to receive processed data. */ if (pppos->in_tail == nullptr
                    || pppos->in_tail->len == PBUF_POOL_BUFSIZE)
                {
                    if (pppos->in_tail != nullptr)
                    {
                        pppos->in_tail->tot_len = pppos->in_tail->len;
                        if (pppos->in_tail != pppos->in_head)
                        {
                            // pbuf_cat(pppos->in_head, pppos->in_tail);
                            /* give up the in_tail reference now */
                            pppos->in_tail = nullptr;
                        }
                    } /* If we haven't started a packet, we need a packet header. */
                    uint16_t pbuf_alloc_len = 0;
                    /* If IP forwarding is enabled we are reserving PBUF_LINK_ENCAPSULATION_HLEN
                                * + PBUF_LINK_HLEN bytes so the packet is being allocated with enough header
                                * space to be forwarded (to Ethernet for example).
                                */
                    if (pppos->in_head == nullptr)
                    {
                        pbuf_alloc_len = PBUF_LINK_ENCAPSULATION_HLEN + PBUF_LINK_HLEN;
                    }
                    // struct PacketBuffer* next_pbuf = pbuf_alloc();
                    PacketBuffer next_pbuf{};
                    if (next_pbuf == nullptr)
                    {
                        /* No free buffers.  Drop the input packet and let the
                         * higher layers deal with it.  Continue processing
                         * the received PacketBuffer chain in case a new packet starts. */
                        // PPPDEBUG(LOG_ERR,
                        //          ("pppos_input[%d]: NO FREE PBUFS!\n", ppp->netif->num));
                        // LINK_STATS_INC(link.memerr);
                        pppos_input_drop(pppos);
                        pppos->in_state = PDSTART; /* Wait for flag sequence. */
                        break;
                    }
                    if (pppos->in_head == nullptr)
                    {
                        uint8_t* payload = ((uint8_t*)next_pbuf->payload) +
                            pbuf_alloc_len;
                        ((struct pppos_input_header*)payload)->ppp = ppp;
                        payload += sizeof(struct pppos_input_header);
                        next_pbuf->len += sizeof(struct pppos_input_header);
                        next_pbuf->len += sizeof(pppos->in_protocol);
                        *(payload++) = pppos->in_protocol >> 8;
                        *(payload) = pppos->in_protocol & 0xFF;
                        pppos->in_head = next_pbuf;
                    }
                    pppos->in_tail = next_pbuf;
                } /* Load character into buffer. */
                ((uint8_t*)pppos->in_tail->payload)[pppos->in_tail->len++] = cur_char;
                break;
            default:
                break;
            } /* update the frame check sequence number. */
            pppos->in_fcs = PPP_FCS(pppos->in_fcs, cur_char);
        }
    } /* while (l-- > 0), all bytes processed */
} /* PPPoS input callback using one input pointer
 */
static void
pppos_input_callback(void* arg)
{
    struct PacketBuffer* pb = (struct PacketBuffer*)arg;
    PppPcb* ppp = ((struct pppos_input_header*)pb->payload)->ppp;
    // if (pbuf_remove_header(pb, sizeof(struct pppos_input_header)))
    // {
    //     lwip_assert("pbuf_remove_header failed\n", false);
    //     goto drop;
    // } /* Dispatch the packet thereby consuming it. */
    Fsm* fsm = nullptr;
    ppp_input(ppp, pb, fsm);
    return;
drop:
    // LINK_STATS_INC(link.drop);
    // MIB2_STATS_NETIF_INC(ppp->netif, ifindiscards);
    free_pkt_buf(pb);
}

static void
pppos_send_config(PppPcb* ppp, uint8_t* ctx, uint32_t accm, int pcomp, int accomp)
{
    pppos_pcb* pppos = (pppos_pcb *)ctx;
    pppos->pcomp = pcomp;
    pppos->accomp = accomp; /* Load the ACCM bits for the 32 control codes. */
    for (int i = 0; i < 32 / 8; i++)
    {
        pppos->out_accm[i] = (uint8_t)((accm >> (8 * i)) & 0xFF);
    }
    // PPPDEBUG(LOG_INFO,
    //          ("pppos_send_config[%d]: out_accm=%X %X %X %X\n", pppos->ppp->netif->num,
    //              pppos->out_accm[0], pppos->out_accm[1], pppos->out_accm[2], pppos->
    //              out_accm[3]));
}

static void
pppos_recv_config(PppPcb* ppp, uint8_t* ctx, uint32_t accm, int pcomp, int accomp)
{
    pppos_pcb* pppos = (pppos_pcb *)ctx;
    PPPOS_DECL_PROTECT(lev);
    PPPOS_PROTECT(lev);
    for (int i = 0; i < 32 / 8; i++)
    {
        pppos->in_accm[i] = (uint8_t)(accm >> (i * 8));
    }
    PPPOS_UNPROTECT(lev);
    // PPPDEBUG(LOG_INFO,
    //          ("pppos_recv_config[%d]: in_accm=%X %X %X %X\n", pppos->ppp->netif->num,
    //              pppos->in_accm[0], pppos->in_accm[1], pppos->in_accm[2], pppos->in_accm[3
    //              ]));
} /*
 * Drop the input packet.
 */
static void
pppos_input_free_current_packet(pppos_pcb* pppos)
{
    if (pppos->in_head != nullptr)
    {
        if (pppos->in_tail && (pppos->in_tail != pppos->in_head))
        {
            free_pkt_buf(pppos->in_tail);
        }
        free_pkt_buf(pppos->in_head);
        pppos->in_head = nullptr;
    }
    pppos->in_tail = nullptr;
} /*
 * Drop the input packet and increase error counters.
 */
static void
pppos_input_drop(pppos_pcb* pppos)
{
    if (pppos->in_head != nullptr)
    {
        // PPPDEBUG(LOG_INFO,
        //          ("pppos_input_drop: PacketBuffer len=%d, addr %p\n", pppos->in_head->len,
        //              (void*)pppos->in_head));
    }
    pppos_input_free_current_packet(pppos);
    vj_uncompress_err(&pppos->ppp->vj_comp);
    // LINK_STATS_INC(link.drop);
    // MIB2_STATS_NETIF_INC(pppos->ppp->netif, ifindiscards);
} /*
 * pppos_output_append - append given character to end of given PacketBuffer.
 * If out_accm is not 0 and the character needs to be escaped, do so.
 * If PacketBuffer is full, send the PacketBuffer and reuse it.
 * Return the current PacketBuffer.
 */
static LwipStatus
pppos_output_append(pppos_pcb* pppos,
                    LwipStatus err,
                    struct PacketBuffer* nb,
                    uint8_t c,
                    uint8_t accm,
                    uint16_t* fcs)
{
    if (err != STATUS_SUCCESS)
    {
        return err;
    } /* Make sure there is room for the character and an escape code.
   * Sure we don't quite fill the buffer if the character doesn't
   * get escaped but is one character worth complicating this? */
    if ((PBUF_POOL_BUFSIZE - nb->len) < 2)
    {
        uint32_t l = pppos->output_cb(pppos->ppp,
                                      (uint8_t*)nb->payload,
                                      nb->len,
                                      pppos->ppp->ctx_cb);
        if (l != nb->len)
        {
            return ERR_IF;
        }
        nb->len = 0;
    } /* Update FCS before checking for special characters. */
    if (fcs)
    {
        *fcs = PPP_FCS(*fcs, c);
    } /* Copy to output buffer escaping special characters. */
    if (accm && ESCAPE_P(pppos->out_accm, c))
    {
        *((uint8_t*)nb->payload + nb->len++) = PPP_ESCAPE;
        *((uint8_t*)nb->payload + nb->len++) = c ^ PPP_TRANS;
    }
    else
    {
        *((uint8_t*)nb->payload + nb->len++) = c;
    }
    return STATUS_SUCCESS;
}

static LwipStatus
pppos_output_last(pppos_pcb* pppos,
                  LwipStatus err,
                  struct PacketBuffer* nb,
                  uint16_t* fcs)
{
    PppPcb* ppp = pppos->ppp; /* Add FCS and trailing flag. */
    err = pppos_output_append(pppos, err, nb, ~(*fcs) & 0xFF, 1, nullptr);
    err = pppos_output_append(pppos, err, nb, (~(*fcs) >> 8) & 0xFF, 1, nullptr);
    err = pppos_output_append(pppos, err, nb, PPP_FLAG, 0, nullptr);
    if (err != STATUS_SUCCESS)
    {
        goto failed;
    } /* Send remaining buffer if not empty */
    if (nb->len > 0)
    {
        uint32_t l = pppos->output_cb(ppp, (uint8_t*)nb->payload, nb->len, ppp->ctx_cb);
        if (l != nb->len)
        {
            err = ERR_IF;
            goto failed;
        }
    }
    pppos->last_xmit = sys_now();
    // MIB2_STATS_NETIF_ADD(ppp->netif, ifoutoctets, nb->tot_len);
    // MIB2_STATS_NETIF_INC(ppp->netif, ifoutucastpkts);
    // LINK_STATS_INC(link.xmit);
    free_pkt_buf(nb);
    return STATUS_SUCCESS;
failed: pppos->last_xmit = 0; /* prepend PPP_FLAG to next packet */
    // LINK_STATS_INC(link.err);
    // LINK_STATS_INC(link.drop);
    // MIB2_STATS_NETIF_INC(ppp->netif, ifoutdiscards);
    free_pkt_buf(nb);
    return err;
} //#endif /* PPP_SUPPORT && PPPOS_SUPPORT */
