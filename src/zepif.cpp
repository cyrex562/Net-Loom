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

#include "zepif.h"
#include "lowpan6.h"
#include "udp.h"
#include "timeouts.h"
#include <cstring>
#include <lowpan6.cpp>

constexpr auto kZepMaxDataLen = 127;

#ifdef PACK_STRUCT_USE_INCLUDES
#  include "bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct zep_hdr {
  PACK_STRUCT_FLD_8(uint8_t prot_id[2]);
  PACK_STRUCT_FLD_8(uint8_t prot_version);
  PACK_STRUCT_FLD_8(uint8_t type);
  PACK_STRUCT_FLD_8(uint8_t channel_id);
  PACK_STRUCT_FIELD(uint16_t device_id);
  PACK_STRUCT_FLD_8(uint8_t crc_mode);
  PACK_STRUCT_FLD_8(uint8_t unknown_1);
  PACK_STRUCT_FIELD(uint32_t timestamp[2]);
  PACK_STRUCT_FIELD(uint32_t seq_num);
  PACK_STRUCT_FLD_8(uint8_t unknown_2[10]);
  PACK_STRUCT_FLD_8(uint8_t len);
} PACK_STRUCT_STRUCT;

struct ZepifState
{
    struct ZepifInit init;
    struct udp_pcb* pcb;
    uint32_t seqno;
};

static uint8_t zep_lowpan_timer_running;

/* Helper function that calls the 6LoWPAN timer and reschedules itself */
static void
zep_lowpan_timer(void* arg)
{
    lowpan6_tmr();
    if (zep_lowpan_timer_running)
    {
        sys_timeout(kLowpan6TmrInterval, zep_lowpan_timer, arg);
    }
}

/* Pass received pbufs into 6LowPAN netif */
static void
zepif_udp_recv(void* arg, struct udp_pcb* pcb, struct pbuf* p,
               const ip_addr_t* addr, uint16_t port)
{
    auto netif_lowpan6 = static_cast<struct netif *>(arg);

    LWIP_ASSERT("arg != NULL", arg != NULL);
    LWIP_ASSERT("pcb != NULL", pcb != NULL);
    if (p == nullptr)
    {
        return;
    }

    /* Parse and hide the ZEP header */
    if (p->len < sizeof(struct ZepHdr))
    {
        /* need the zep_hdr in one piece */
        goto err_return;
    }
    auto zep = static_cast<struct ZepHdr *>(p->payload);
    if (zep->prot_id[0] != 'E')
    {
        goto err_return;
    }
    if (zep->prot_id[1] != 'X')
    {
        goto err_return;
    }
    if (zep->prot_version != 2)
    {
        /* we only support this version for now */
        goto err_return;
    }
    if (zep->type != 1)
    {
        goto err_return;
    }
    if (zep->crc_mode != 1)
    {
        goto err_return;
    }
    if (zep->len != p->tot_len - sizeof(struct ZepHdr))
    {
        goto err_return;
    }
    /* everything seems to be OK, hide the ZEP header */
    if (pbuf_remove_header(p, sizeof(struct ZepHdr)))
    {
        goto err_return;
    }
    /* TODO Check CRC? */
    /* remove CRC trailer */
    pbuf_realloc(p, p->tot_len - 2);

    /* Call into 6LoWPAN code. */
    auto err = netif_lowpan6->input(p, netif_lowpan6);
    if (err == ERR_OK)
    {
        return;
    }
err_return:
    pbuf_free(p);
}

/* Send 6LoWPAN TX packets as UDP broadcast */
static err_t
zepif_linkoutput(struct netif* netif, struct pbuf* p)
{
    struct pbuf* q;

    LWIP_ASSERT("invalid netif", netif != NULL);
    LWIP_ASSERT("invalid pbuf", p != NULL);

    if (p->tot_len > kZepMaxDataLen)
    {
        return ERR_VAL;
    }
    LWIP_ASSERT("TODO: support chained pbufs", p->next == NULL);

    struct ZepifState* state = static_cast<struct ZepifState *>(netif->state);
    LWIP_ASSERT("state->pcb != NULL", state->pcb != NULL);

  q = pbuf_alloc(PBUF_TRANSPORT, sizeof(struct zep_hdr) + p->tot_len, PBUF_RAM);
  if (q == NULL) {
    return ERR_MEM;
  }
  zep = (struct zep_hdr *)q->payload;
  memset(zep, 0, sizeof(struct zep_hdr));
  zep->prot_id[0] = 'E';
  zep->prot_id[1] = 'X';
  zep->prot_version = 2;
  zep->type = 1; /* Data */
  zep->channel_id = 0; /* whatever */
  zep->device_id = lwip_htons(1); /* whatever */
  zep->crc_mode = 1;
  zep->unknown_1 = 0xff;
  zep->seq_num = lwip_htonl(state->seqno);
  state->seqno++;
  zep->len = (uint8_t)p->tot_len;

    auto err = pbuf_take_at(q, p->payload, p->tot_len, sizeof(struct ZepHdr));
    if (err == ERR_OK)
    {
        zepif_udp_recv(netif, state->pcb, pbuf_clone(PBUF_RAW, PBUF_RAM, q), nullptr, 0);
        err = udp_sendto(state->pcb, q, state->init.zep_dst_ip_addr, state->init.zep_dst_udp_port);
    }
    pbuf_free(q);

    return err;
}

int zepif_default_udp_port = 9999;

/**
 * @ingroup zepif
 * Set up a raw 6LowPAN netif and surround it with input- and output
 * functions for ZEP
 */
err_t
zepif_init(struct netif* netif)
{
    err_t err;
    auto init_state = static_cast<struct ZepifInit*>(netif->state);
    auto state = static_cast<struct ZepifState *>(mem_malloc(sizeof(struct ZepifState)));

    LWIP_ASSERT("zepif needs an input callback", netif->input != NULL);

    if (state == nullptr)
    {
        return ERR_MEM;
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
#if LWIP_IPV4
    if (state->init.zep_dst_ip_addr == nullptr)
    {
        /* With IPv4 enabled, default to broadcasting packets if no address is set */
        state->init.zep_dst_ip_addr = IP_ADDR_BROADCAST;
    }
#endif /* LWIP_IPV4 */

    netif->state = nullptr;

  err = lowpan6_if_init(netif);
  LWIP_ASSERT("lowpan6_if_init set a state", netif->state == NULL);
  if (err == ERR_OK) {
    netif->state = state;
    netif->hwaddr_len = 6;
    if (init_state != NULL) {
      memcpy(netif->hwaddr, init_state->addr, 6);
    } else {
      uint8_t i;
      for (i = 0; i < 6; i++) {
        netif->hwaddr[i] = i;
      }
      netif->hwaddr[0] &= 0xfc;
    }
    err = udp_bind(state->pcb, state->init.zep_src_ip_addr, state->init.zep_src_udp_port);
    if (err != ERR_OK)
    {
        goto err_ret;
    }
    if (state->init.zep_netif != nullptr)
    {
        udp_bind_netif(state->pcb, state->init.zep_netif);
    }
    LWIP_ASSERT("udp_bind(lowpan6_broadcast_pcb) failed", err == ERR_OK);
    ip_set_option(state->pcb, SOF_BROADCAST);
    udp_recv(state->pcb, zepif_udp_recv, netif);

    err = lowpan6_if_init(netif);
    LWIP_ASSERT("lowpan6_if_init set a state", netif->state == NULL);
    if (err == ERR_OK)
    {
        netif->state = state;
        netif->hwaddr_len = 6;
        if (init_state != nullptr)
        {
            memcpy(netif->hwaddr, init_state->addr, 6);
        }
        else
        {
            uint8_t i;
            for (i = 0; i < 6; i++)
            {
                netif->hwaddr[i] = i;
            }
            netif->hwaddr[0] &= 0xfc;
        }
        netif->linkoutput = zepif_linkoutput;

        if (!zep_lowpan_timer_running)
        {
            sys_timeout(kLowpan6TmrInterval, zep_lowpan_timer, nullptr);
            zep_lowpan_timer_running = 1;
        }

        return ERR_OK;
    }

err_ret:
    if (state->pcb != nullptr)
    {
        udp_remove(state->pcb);
    }
    mem_free(state);
    return err;
}
