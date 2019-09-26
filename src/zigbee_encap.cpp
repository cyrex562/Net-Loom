/**
 * @file
 *
 * @defgroup zepif ZEP - ZigBee Encapsulation Protocol
 * @ingroup netifs
 * A netif implementing the ZigBee Encapsulation Protocol (ZEP).
 * This is used to tunnel 6LowPAN over UDP.
 *
 * Usage (there must be a default netif before!):
 * @code{.c}
 *   netif_add(&zep_netif, NULL, NULL, NULL, NULL, zepif_init, tcpip_6lowpan_input);
 *   netif_create_ip6_linklocal_address(&zep_netif, 1);
 *   netif_set_up(&zep_netif);
 *   netif_set_link_up(&zep_netif);
 * @endcode
 */

#include <cstdint>
#include <cstring>
#include "lowpan6.h"
#include "timeouts.h"
#include "udp.h"
#include "zepif.h"


// static bool zep_lowpan_timer_running;

/* Helper function that calls the 6LoWPAN timer and reschedules itself */
static bool
zep_lowpan_timer(bool zep_lowpan_timer_running)
{
    lowpan6_tmr();
    if (zep_lowpan_timer_running)
    {
        // sys_timeout(LOWPAN6_TIMER_INTERVAL, zep_lowpan_timer, arg);
        // todo: schedule zep_lowpan_timer
    }
}

/* Pass received pbufs into 6LowPAN netif */
static bool
zepif_udp_recv(UdpPcb& pcb,
               PacketContainer& p,
               const IpAddrInfo& addr,
               uint16_t port,
               NetworkInterface& netif,
               NetworkInterface& netif_lowpan6)
{
    // auto netif_lowpan6 = static_cast<NetworkInterface*>(arg);
    // lwip_assert("arg != NULL", arg != nullptr);
    // lwip_assert("pcb != NULL", pcb != nullptr);

    /* Parse and hide the ZEP header */
    if (p.data.size() < sizeof(struct ZepHdr))
    {
        /* need the ZepHdr in one piece */
        goto err_return;
    }

    auto zep = reinterpret_cast<struct ZepHdr *>(p.data.data());
    if (zep->prot_id[0] != 'E')
    {
        return false;
    }
    if (zep->prot_id[1] != 'X')
    {
        return false;
    }
    if (zep->prot_version != 2)
    {
        /* we only support this version for now */
        return false;
    }
    if (zep->type != 1)
    {
        return false;
    }
    if (zep->crc_mode != 1)
    {
        return false;
    }
    if (zep->len != p.data.size() - sizeof(struct ZepHdr))
    {
        return false;
    }
    /* everything seems to be OK, hide the ZEP header */
    // if (pbuf_remove_header(p, sizeof(struct ZepHdr)))
    // {
    //     goto err_return;
    // }
    /* TODO Check CRC? */
    /* remove CRC trailer */
    // pbuf_realloc(p);

    /* Call into 6LoWPAN code. */
    // auto err = netif_lowpan6.input(p, netif_lowpan6);
    //
    // if (err == STATUS_SUCCESS)
    // {
    //     return;
    // }
    // todo: pass code to netif_lowpan6 input function.
err_return:
    //free_pkt_buf(p);
    return true;
}

/* Send 6LoWPAN TX packets as UDP broadcast */
static bool
zepif_linkoutput(NetworkInterface& netif,
                 PacketContainer& p,
                 ZepifState& state,
                 UdpPcb& udp_pcb,
                 NetworkInterface& netif_lowpan6)
{
    // lwip_assert("invalid netif", netif != nullptr);
    // lwip_assert("invalid pbuf", p != nullptr);
    if (p.data.size() > ZEP_MAX_DATA_LEN) { return ERR_VAL; }
    // lwip_assert("TODO: support chained pbufs", p->next == nullptr);
    // struct ZepifState* state = static_cast<struct ZepifState *>(netif->state);
    // lwip_assert("state->pcb != NULL", state->pcb != nullptr);
    // struct PacketBuffer* q = pbuf_alloc();
    PacketContainer q{};
    //   if (q == nullptr) {
    //   return ERR_MEM;
    // }
    ZepHdr zep{};

    // auto zep = (struct ZepHdr *)q.bytes.data();
    // memset(zep, 0, sizeof(struct ZepHdr));
    zep.prot_id[0] = 'E';
    zep.prot_id[1] = 'X';
    zep.prot_version = 2;
    zep.type = 1; /* Data */
    zep.channel_id = 0; /* whatever */
    zep.device_id = ns_htons(1); /* whatever */
    zep.crc_mode = 1;
    zep.unknown_1 = 0xff;
    zep.seq_num = lwip_htonl(state.seqno);
    state.seqno++;
    zep.len = p.data.size();
    std::copy(&zep, (&zep) + sizeof(ZepHdr), q.data);
    std::copy(p.data.begin(), p.data.end(), q.data.begin() + sizeof(ZepHdr));
    IpAddrInfo empty{};
    if (!zepif_udp_recv(udp_pcb, q, empty, 0, netif, netif_lowpan6)) { return false; }
    auto err = udp_sendto(udp_pcb,
                          q,
                          state.init.zep_dst_ip_addr,
                          state.init.zep_dst_udp_port);
    return err;
}



/**
 * @ingroup zepif
 * Set up a raw 6LowPAN netif and surround it with input- and output
 * functions for ZEP
 */
NsStatus
zepif_init(NetworkInterface* netif)
{
    auto init_state = static_cast<struct ZepifInit*>(netif->state);
    auto state = new ZepifState;

    lwip_assert("zepif needs an input callback", netif->input != nullptr);

    if (state == nullptr)
    {
        return STATUS_E_MEM;
    }
    memset(state, 0, sizeof(struct ZepifState));
    if (init_state != nullptr)
    {
        memcpy(&state->init, init_state, sizeof(struct ZepifInit));
    }
    if (state->init.zep_src_udp_port == 0)
    {
        state->init.zep_src_udp_port = zepif_default_udp_port;
    }
    if (state->init.zep_dst_udp_port == 0)
    {
        state->init.zep_dst_udp_port = zepif_default_udp_port;
    }

    if (state->init.zep_dst_ip_addr == nullptr)
    {
        /* With IPv4 enabled, default to broadcasting packets if no address is set */
        state->init.zep_dst_ip_addr->u_addr.ip4.word = IP4_ADDR_BCAST_U32;
    }


    netif->state = nullptr;

  NsStatus err = lowpan6_if_init(netif);
  lwip_assert("lowpan6_if_init set a state", netif->state == nullptr);
  if (err == STATUS_SUCCESS) {
    netif->state = state;
    netif->hwaddr_len = 6;
    if (init_state != nullptr) {
      memcpy(netif->hwaddr, init_state->addr, 6);
    } else {
        for (uint8_t i = 0; i < 6; i++) {
        netif->hwaddr[i] = i;
      }
      netif->hwaddr[0] &= 0xfc;
    }
    err = udp_bind(state->pcb, state->init.zep_src_ip_addr, state->init.zep_src_udp_port);
    if (err != STATUS_SUCCESS)
    {
        goto err_ret;
    }
    if (state->init.zep_netif != nullptr)
    {
        udp_bind_netif(state->pcb, state->init.zep_netif);
    }
    lwip_assert("udp_bind(lowpan6_broadcast_pcb) failed", err == STATUS_SUCCESS);
    ip4_set_ip_option(&state->pcb->so_options, SOF_BROADCAST);
    udp_recv(state->pcb, zepif_udp_recv, netif);

    err = lowpan6_if_init(netif);
    lwip_assert("lowpan6_if_init set a state", netif->state == nullptr);
    if (err == STATUS_SUCCESS)
    {
        netif->state = state;
        netif->hwaddr_len = 6;
        if (init_state != nullptr)
        {
            memcpy(netif->hwaddr, init_state->addr, 6);
        }
        else
        {
            for (uint8_t i = 0; i < 6; i++)
            {
                netif->hwaddr[i] = i;
            }
            netif->hwaddr[0] &= 0xfc;
        }
        netif->linkoutput = zepif_linkoutput;

        if (!zep_lowpan_timer_running)
        {
            sys_timeout(LOWPAN6_TIMER_INTERVAL, zep_lowpan_timer, nullptr);
            zep_lowpan_timer_running = true;
        }

        return STATUS_SUCCESS;
    }
  }

err_ret:
    if (state->pcb != nullptr)
    {
        udp_remove(state->pcb);
    }
    delete state;
    return err;
}
