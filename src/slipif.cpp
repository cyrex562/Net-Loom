/**
 * @file
 * SLIP Interface
 *
 */ /*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is built upon the file: src/arch/rtxc/sioslip.c
 *
 * Author: Magnus Ivarsson <magnus.ivarsson(at)volvo.com>
 *         Simon Goldschmidt
 */ /**
 * @defgroup slipif SLIP
 * @ingroup netifs
 *
 * This is an arch independent SLIP netif. The specific serial hooks must be
 * provided by another file. They are sio_open, sio_read/sio_tryread and sio_send
 *
 * Usage: This netif can be used in three ways:\n
 *        1) For NO_SYS==0, an RX thread can be used which blocks on sio_read()
 *           until data is received.\n
 *        2) In your main loop, call slipif_poll() to check for new RX bytes,
 *           completed packets are fed into netif->input().\n
 *        3) Call slipif_received_byte[s]() from your serial RX ISR and
 *           slipif_process_rxqueue() from your main loop. ISR level decodes
 *           packets and puts completed packets on a queue which is fed into
 *           the stack from the main loop (needs SYS_LIGHTWEIGHT_PROT for
 *           pbuf_alloc to work on ISR level!).
 *
 */
#include <slipif.h>
#include <opt.h>
#include <def.h>
#include <packet_buffer.h>
//#include <snmp.h>
#include <sys.h>
#include <sio.h>
#include <lwip_debug.h>
#define SLIP_END     0xC0 /* 0300: start and end of every packet */
#define SLIP_ESC     0xDB /* 0333: escape start (one byte escaped data follows) */
#define SLIP_ESC_END 0xDC /* 0334: following escape: original byte is 0xC0 (END) */
#define SLIP_ESC_ESC 0xDD /* 0335: following escape: original byte is 0xDB (ESC) */
/** Maximum packet size that is received by this netif */
constexpr auto SLIP_MAX_SIZE = 1500;

enum SlipifRecvState
{
    SLIP_RECV_NORMAL,
    SLIP_RECV_ESCAPE
};

struct SlipifPriv
{
    SioFd sd;
    /* q is the whole PacketBuffer chain for a packet, p is the current PacketBuffer in the chain */
    // struct PacketBuffer *p, *q;
    uint8_t state;
    uint16_t i, recved;
    // struct PacketBuffer* rxpackets;
}; /**
 * Send a PacketBuffer doing the necessary SLIP encapsulation
 *
 * Uses the serial layer's sio_send()
 *
 * @param netif the lwip network interface structure for this slipif
 * @param p the PacketBuffer chain packet to send
 * @return always returns ERR_OK since the serial layer does not provide return values
 */
static LwipStatus
slipif_output(NetworkInterface* netif, struct PacketBuffer* p)
{
    lwip_assert("netif != NULL", (netif != nullptr));
    lwip_assert("netif->state != NULL", (netif->state != nullptr));
    lwip_assert("p != NULL", (p != nullptr));
    //  Logf(true, ("slipif_output: sending %d bytes\n", p->tot_len));
    struct SlipifPriv* priv = (struct SlipifPriv *)netif->state;
    /* Send PacketBuffer out on the serial I/O device. */
    /* Start with packet delimiter. */
    sio_send(SLIP_END, priv->sd);
    for (struct PacketBuffer* q = p; q != nullptr; q = q->next)
    {
        for (uint16_t i = 0; i < q->len; i++)
        {
            uint8_t c = ((uint8_t *)q->payload)[i];
            switch (c)
            {
            case SLIP_END: /* need to escape this byte (0xC0 -> 0xDB, 0xDC) */ sio_send(
                    SLIP_ESC,
                    priv->sd);
                sio_send(SLIP_ESC_END, priv->sd);
                break;
            case SLIP_ESC: /* need to escape this byte (0xDB -> 0xDB, 0xDD) */ sio_send(
                    SLIP_ESC,
                    priv->sd);
                sio_send(SLIP_ESC_ESC, priv->sd);
                break;
            default: /* normal byte - no need for escaping */ sio_send(c, priv->sd);
                break;
            }
        }
    } /* End with packet delimiter. */
    sio_send(SLIP_END, priv->sd);
    return STATUS_SUCCESS;
} /**
 * Send a PacketBuffer doing the necessary SLIP encapsulation
 *
 * Uses the serial layer's sio_send()
 *
 * @param netif the lwip network interface structure for this slipif
 * @param p the PacketBuffer chain packet to send
 * @param ipaddr the ip address to send the packet to (not used for slipif)
 * @return always returns ERR_OK since the serial layer does not provide return values
 */
static LwipStatus
slipif_output_v4(NetworkInterface* netif, struct PacketBuffer* p, const Ip4Addr* ipaddr)
{
    return slipif_output(netif, p);
} /**
 * Send a PacketBuffer doing the necessary SLIP encapsulation
 *
 * Uses the serial layer's sio_send()
 *
 * @param netif the lwip network interface structure for this slipif
 * @param p the PacketBuffer chain packet to send
 * @param ipaddr the ip address to send the packet to (not used for slipif)
 * @return always returns ERR_OK since the serial layer does not provide return values
 */
static LwipStatus
slipif_output_v6(NetworkInterface* netif, struct PacketBuffer* p, const Ip6Addr* ipaddr)
{
    return slipif_output(netif, p);
} /**
 * Handle the incoming SLIP stream character by character
 *
 * @param netif the lwip network interface structure for this slipif
 * @param c received character (multiple calls to this function will
 *        return a complete packet, NULL is returned before - used for polling)
 * @return The IP packet when SLIP_END is received
 */
static struct PacketBuffer*
slipif_rxbyte(NetworkInterface* netif, uint8_t c)
{
    lwip_assert("netif != NULL", (netif != nullptr));
    lwip_assert("netif->state != NULL", (netif->state != nullptr));
    struct SlipifPriv* priv = (struct SlipifPriv *)netif->state;
    switch (priv->state)
    {
    case SLIP_RECV_NORMAL:
        switch (c)
        {
        case SLIP_END:
            if (priv->recved > 0)
            {
                /* Received whole packet. */
                /* Trim the PacketBuffer to the size of the received packet. */
                // pbuf_realloc(priv->q); // LINK_STATS_INC(link.recv);
                //            Logf(true, ("slipif: Got packet (%d bytes)\n", priv->recved));
                struct PacketBuffer* t = priv->q;
                priv->pkt_buf = priv->q = nullptr;
                priv->i = priv->recved = 0;
                return t;
            }
            return nullptr;
        case SLIP_ESC:
            priv->state = SLIP_RECV_ESCAPE;
            return nullptr;
        default:
            break;
        } /* end switch (c) */
        break;
    case SLIP_RECV_ESCAPE: /* un-escape END or ESC bytes, leave other bytes
         (although that would be a protocol error) */ switch (c)
        {
        case SLIP_ESC_END:
            c = SLIP_END;
            break;
        case SLIP_ESC_ESC:
            c = SLIP_ESC;
            break;
        default:
            break;
        }
        priv->state = SLIP_RECV_NORMAL;
        break;
    default:
        break;
    } /* end switch (priv->state) */
    /* byte received, packet not yet completely received */
    if (priv->pkt_buf == nullptr)
    {
        /* allocate a new PacketBuffer */
        Logf(true, ("slipif_input: alloc\n"));
        // priv->p = pbuf_alloc();
        if (priv->pkt_buf == nullptr)
        {
            Logf(true, ("slipif_input: no new PacketBuffer! (DROP)\n"));
            /* don't process any further since we got no PacketBuffer to receive to */
            return nullptr;
        }
        if (priv->q != nullptr)
        {
            /* 'chain' the PacketBuffer to the existing chain */
            // pbuf_cat(priv->q, priv->p);
        }
        else
        {
            /* p is the first PacketBuffer in the chain */
            priv->q = priv->pkt_buf;
        }
    } /* this automatically drops bytes if > SLIP_MAX_SIZE */
    if ((priv->pkt_buf != nullptr) && (priv->recved <= SLIP_MAX_SIZE))
    {
        ((uint8_t *)priv->pkt_buf->payload)[priv->i] = c;
        priv->recved++;
        priv->i++;
        if (priv->i >= priv->pkt_buf->len)
        {
            /* on to the next PacketBuffer */
            priv->i = 0;
            if (priv->pkt_buf->next != nullptr && priv->pkt_buf->next->len > 0)
            {
                /* p is a chain, on to the next in the chain */
                priv->pkt_buf = priv->pkt_buf->next;
            }
            else
            {
                /* p is a single PacketBuffer, set it to NULL so next time a new
                 * PacketBuffer is allocated */
                priv->pkt_buf = nullptr;
            }
        }
    }
    return nullptr;
} /** Like slipif_rxbyte, but passes completed packets to netif->input
 *
 * @param netif The lwip network interface structure for this slipif
 * @param c received character
 */
static void
slipif_rxbyte_input(NetworkInterface* netif, uint8_t c)
{
    struct PacketBuffer* p = slipif_rxbyte(netif, c);
    if (p != nullptr)
    {
        if (netif->input(p, netif) != STATUS_SUCCESS)
        {
            free_pkt_buf(p);
        }
    }
} /**
 * The SLIP input thread.
 *
 * Feed the IP layer with incoming packets
 *
 * @param nf the lwip network interface structure for this slipif
 */
static void
slipif_loop_thread(uint8_t* nf)
{
    uint8_t c;
    NetworkInterface* netif = (NetworkInterface*)nf;
    struct SlipifPriv* priv = (struct SlipifPriv *)netif->state;
    while (true)
    {
        if (sio_read(priv->sd, &c, 1) > 0)
        {
            slipif_rxbyte_input(netif, c);
        }
    }
} /**
 * @ingroup slipif
 * SLIP netif initialization
 *
 * Call the arch specific sio_open and remember
 * the opened device in the state field of the netif.
 *
 * @param netif the lwip network interface structure for this slipif
 * @return ERR_OK if serial line could be opened,
 *         ERR_MEM if no memory could be allocated,
 *         ERR_IF is serial line couldn't be opened
 *
 * @note If netif->state is interpreted as an uint8_t serial port number.
 *
 */
LwipStatus
slipif_init(NetworkInterface* netif)
{
    lwip_assert("slipif needs an input callback", netif->input != nullptr);
    /* netif->state contains serial port number */
    uint8_t sio_num = (uint8_t)netif->state;
    //  Logf(true, ("slipif_init: netif->num=%d\n", (uint16_t)sio_num));
    /* Allocate private data */
    struct SlipifPriv* priv = new struct SlipifPriv;
    if (!priv)
    {
        return ERR_MEM;
    }
    netif->name[0] = 's';
    netif->name[1] = 'l';
    netif->output = slipif_output_v4;
    netif->output_ip6 = slipif_output_v6;
    netif->mtu = SLIP_MAX_SIZE; /* Try to open the serial port. */
    priv->sd = sio_open(sio_num);
    if (!priv->sd)
    {
        /* Opening the serial port failed. */
        delete priv;
        return ERR_IF;
    } /* Initialize private data */
    priv->pkt_buf = nullptr;
    priv->q = nullptr;
    priv->state = SLIP_RECV_NORMAL;
    priv->i = 0;
    priv->recved = 0;
    priv->rxpackets = nullptr;
    netif->state = priv;
    /* initialize the snmp variables and counters inside the NetworkInterface*/
    // MIB2_INIT_NETIF(netif, snmp_ifType_slip, SLIP_SIO_SPEED(priv->sd));
    /* Create a thread to poll the serial line. */ // fixme:
    // sys_thread_new(SLIPIF_THREAD_NAME, slipif_loop_thread, netif,
    //                SLIPIF_THREAD_STACKSIZE, SLIPIF_THREAD_PRIO),;
    return STATUS_SUCCESS;
} /**
 * @ingroup slipif
 * Polls the serial device and feeds the IP layer with incoming packets.
 *
 * @param netif The lwip network interface structure for this slipif
 */
void
slipif_poll(NetworkInterface* netif)
{
    uint8_t c;
    lwip_assert("netif != NULL", (netif != nullptr));
    lwip_assert("netif->state != NULL", (netif->state != nullptr));
    struct SlipifPriv* priv = (struct SlipifPriv *)netif->state;
    while (sio_tryread(priv->sd, &c, 1) > 0)
    {
        slipif_rxbyte_input(netif, c);
    }
} /**
 * @ingroup slipif
 * Feeds the IP layer with incoming packets that were receive
 *
 * @param netif The lwip network interface structure for this slipif
 */
void
slipif_process_rxqueue(NetworkInterface* netif)
{
    lwip_assert("netif != NULL", (netif != nullptr));
    lwip_assert("netif->state != NULL", (netif->state != nullptr));
    struct SlipifPriv* priv = (struct SlipifPriv *)netif->state; // SYS_ARCH_PROTECT(old_level);
    while (priv->rxpackets != nullptr)
    {
        struct PacketBuffer* p = priv->rxpackets; /* dequeue packet */
        struct PacketBuffer* q = p;
        while ((q->len != q->tot_len) && (q->next != nullptr))
        {
            q = q->next;
        }
        priv->rxpackets = q->next;
        q->next = nullptr; // SYS_ARCH_UNPROTECT(old_level);
        if (netif->input(p, netif) != STATUS_SUCCESS)
        {
            free_pkt_buf(p);
        } // SYS_ARCH_PROTECT(old_level);
        while (priv->rxpackets != nullptr)
        {
            struct PacketBuffer* p = priv->rxpackets; /* dequeue packet */
            struct PacketBuffer* q = p;
            while ((q->len != q->tot_len) && (q->next != nullptr))
            {
                q = q->next;
            }
            priv->rxpackets = q->next;
            q->next = nullptr; // sys_arch_unprotect(old_level);
            if (netif->input(p, netif) != STATUS_SUCCESS)
            {
                free_pkt_buf(p);
            } // SYS_ARCH_PROTECT(old_level);
        } // sys_arch_unprotect(old_level);
    }
} /** Like slipif_rxbyte, but queues completed packets.
 *
 * @param netif The lwip network interface structure for this slipif
 * @param data Received serial byte
 */
static void
slipif_rxbyte_enqueue(NetworkInterface* netif, uint8_t data)
{
    struct SlipifPriv* priv = (struct SlipifPriv *)netif->state;
    sys_prot_t old_level;
    struct PacketBuffer* p = slipif_rxbyte(netif, data);
    if (p != nullptr)
    {
        SYS_ARCH_PROTECT(old_level);
        if (priv->rxpackets != nullptr)
        {
            /* queue multiple pbufs */
            struct PacketBuffer* q = p;
            while (q->next != nullptr)
            {
                q = q->next;
            }
            q->next = p;
        }
        else
        {
            priv->rxpackets = p;
        }
        SYS_ARCH_UNPROTECT(old_level);
    }
} /**
 * @ingroup slipif
 * Process a received byte, completed packets are put on a queue that is
 * fed into IP through slipif_process_rxqueue().
 *
 * This function can be called from ISR if SYS_LIGHTWEIGHT_PROT is enabled.
 *
 * @param netif The lwip network interface structure for this slipif
 * @param data received character
 */
void
slipif_received_byte(NetworkInterface* netif, uint8_t data)
{
    lwip_assert("netif != NULL", (netif != nullptr));
    lwip_assert("netif->state != NULL", (netif->state != nullptr));
    slipif_rxbyte_enqueue(netif, data);
} /**
 * @ingroup slipif
 * Process multiple received byte, completed packets are put on a queue that is
 * fed into IP through slipif_process_rxqueue().
 *
 * This function can be called from ISR if SYS_LIGHTWEIGHT_PROT is enabled.
 *
 * @param netif The lwip network interface structure for this slipif
 * @param data received character
 * @param len Number of received characters
 */
void
slipif_received_bytes(NetworkInterface* netif, uint8_t* data, uint8_t len)
{
    uint8_t* rxdata = data;
    lwip_assert("netif != NULL", (netif != nullptr));
    lwip_assert("netif->state != NULL", (netif->state != nullptr));
    for (uint8_t i = 0; i < len; i++, rxdata++)
    {
        slipif_rxbyte_enqueue(netif, *rxdata);
    }
}
