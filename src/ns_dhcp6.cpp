/**
 * @file
 *
 * @defgroup dhcp6 DHCPv6
 * @ingroup ip6
 * DHCPv6 client: IPv6 address autoconfiguration as per
 * RFC 3315 (stateful DHCPv6) and
 * RFC 3736 (stateless DHCPv6).
 *
 * For now, only stateless DHCPv6 is implemented!
 *
 * TODO:
 * - enable/disable API to not always start when RA is received
 * - stateful DHCPv6 (for now, only stateless DHCPv6 for DNS and NTP servers works)
 * - create Client Identifier?
 * - only start requests if a valid local address is available on the netif
 * - only start information requests if required (not for every RA)
 *
 * dhcp6_enable_stateful() enables stateful DHCPv6 for a netif (stateless disabled)\n
 * dhcp6_enable_stateless() enables stateless DHCPv6 for a netif (stateful disabled)\n
 * dhcp6_disable() disable DHCPv6 for a netif
 *
 * When enabled, requests are only issued after receipt of RA with the
 * corresponding bits set.
 */


#include "dhcp6.h"
#include "ns_config.h"
#include "dhcp6_def.h"
#include "ns_udp.h"
#include "ns_dns.h"
#include "ns_debug.h"
#include "ns_ip.h"
#include <cstring>
#include <tuple>

#include "spdlog/spdlog.h"


/**
 *
 */
bool dhcp6_bind(Dhcp6Context& ctx, IpAddrInfo& addr, uint16_t port)
{
    // not implemented
    return false;
}


/**
 * Ensure DHCP PCB is allocated and bound
 *
 */
bool
dhcp6_inc_pcb_refcount(Dhcp6Context& ctx, size_t& ref_cnt, NetworkInterface& netif)
{
    if (ref_cnt == 0) {
        ctx.socket_options |= SOF_BROADCAST;
        /* set up local and remote port for the pcb -> listen on all interfaces on all
         * src/dest IPs */
        auto addr_any = ip_addr_create_ip4_any();
        if (!dhcp6_bind(ctx, addr_any, DHCP6_CLIENT_PORT)) { return false; }
        bool ok;
        Dhcp6ClientServerMessage msg;
        std::tie(ok, msg) = dhcp6_recv(ctx, addr_any, DHCP6_CLIENT_PORT, netif);
        if (!ok) {
            return false;
        }
    }
    ref_cnt++;
    return true;
}


/**
 * Free DHCP PCB if the last netif stops using it
 *
 */
void
dhcp6_dec_pcb_refcount(Dhcp6Context& ctx)
{
    ns_assert("dhcp6_pcb_refcount(): refcount error", (ctx.ref_cnt > 0));
    ctx.ref_cnt--;
    if (ctx.ref_cnt == 0) {
        // todo: if ref_cnt is 0, 'free'/clean-up ctx
        // udp_remove(dhcp6_pcb);
        // dhcp6_pcb = nullptr;
    }
}


/**
 * Set a statically allocated Dhcp6 to work with.
 * Using this prevents dhcp6_start to allocate it using mem_malloc.
 *
 * @param netif the netif for which to set the struct dhcp
 * @param ctx (uninitialised) dhcp6 struct allocated by the application
 */
void
dhcp6_set_struct(NetworkInterface& netif, Dhcp6Context& ctx)
{
    // lwip_assert("netif already has a Dhcp6 set",
    //             get_netif_dhcp6_ctx(netif) == nullptr);
    /* clear data structure */
    // memset(ctx, 0, sizeof(struct Dhcp6Context));
    /* dhcp6_set_state(&dhcp, DHCP6_STATE_OFF); */
    // netif->client_data[LWIP_NETIF_CLIENT_DATA_INDEX_DHCP6] = ctx;
    dhcp6_set_state(ctx, DHCP6_STATE_OFF);
}


/**
 * Removes a Dhcp6 from a netif.
 *
 * ATTENTION: Only use this when not using dhcp6_set_struct() to allocate the
 *            Dhcp6 since the memory is passed back to the heap.
 *
 * @param netif the netif from which to remove the struct dhcp
 */
void dhcp6_cleanup(NetworkInterface& netif, Dhcp6Context& ctx)
{
    // lwip_assert("netif != NULL", netif != nullptr);
    // if (get_netif_dhcp6_ctx(netif) != nullptr)
    // {
    //     delete get_netif_dhcp6_ctx(netif);
    //     netif->client_data[LWIP_NETIF_CLIENT_DATA_INDEX_DHCP6] = nullptr;
    // }

}


/**
 *
 */
// Dhcp6Context
// dhcp6_get_struct(NetworkInterface& netif)
// {
//     struct Dhcp6Context* dhcp6 = get_netif_dhcp6_ctx(netif);
//     if (dhcp6 == nullptr) {
//         Logf(true, "%s: mallocing new DHCPv6 client\n", dbg_requester);
//         dhcp6 = new struct Dhcp6Context;
//         if (dhcp6 == nullptr) {
//             Logf(true, "%s: could not allocate dhcp6\n", dbg_requester);
//             return nullptr;
//         } /* clear data structure, this implies DHCP6_STATE_OFF */
//         memset(dhcp6,
//                0,
//                sizeof(struct Dhcp6Context)); /* store this dhcp6 client in the netif */
//         netif->client_data[LWIP_NETIF_CLIENT_DATA_INDEX_DHCP6] = dhcp6;
//     }
//     else {
//         /* already has DHCP6 client attached */
//         Logf(true, ("%s: using existing DHCPv6 client\n", dbg_requester));
//     }
//     if (!dhcp6->pcb_allocated) {
//         if (dhcp6_inc_pcb_refcount(, , ) != STATUS_SUCCESS) {
//             /* ensure DHCP6 PCB is allocated */
//             delete dhcp6;
//             netif->client_data[LWIP_NETIF_CLIENT_DATA_INDEX_DHCP6] = nullptr;
//             return nullptr;
//         }
//         Logf(true, ("%s: allocated dhcp6", dbg_requester));
//         dhcp6->pcb_allocated = 1;
//     }
//     return dhcp6;
// }


/*
 * Set the DHCPv6 state
 * If the state changed, reset the number of tries.
 */
void
dhcp6_set_state(Dhcp6Context& ctx, uint8_t new_state)
{
    spdlog::info("DHCPv6: {} -> {}", ctx.state, new_state);
    if (new_state != ctx.state) {
        ctx.state = new_state;
        ctx.tries = 0;
        ctx.request_timeout = 0;
    }
}


/**
 *
 */
bool
dhcp6_stateless_enabled(Dhcp6Context& ctx)
{
    if ((ctx.state == DHCP6_STATE_STATELESS_IDLE) || (ctx.state ==
        DHCP6_STATE_REQUESTING_CONFIG)) { return true; }
    return false;
}


/*int
dhcp6_stateful_enabled(Dhcp6 *dhcp6)
{
  if (dhcp6->state == DHCP6_STATE_OFF) {
    return 0;
  }
  if (dhcp6_stateless_enabled(dhcp6)) {
    return 0;
  }
  return 1;
}*/

/**
 * @ingroup dhcp6
 * Enable stateful DHCPv6 on this netif
 * Requests are sent on receipt of an RA message with the
 * ND6_RA_FLAG_MANAGED_ADDR_CONFIG flag set.
 *
 * A Dhcp6 will be allocated for this netif if not
 * set via @ref dhcp6_set_struct before.
 *
 * @todo: stateful DHCPv6 not supported, yet
 */
bool
dhcp6_enable_stateful(NetworkInterface& netif) { return false; }

/**
 * @ingroup dhcp6
 * Enable stateless DHCPv6 on this netif Requests are sent on receipt of an RA message
 * with the ND6_RA_FLAG_OTHER_CONFIG flag set. A Dhcp6 will be allocated for this netif
 * if not set via @ref dhcp6_set_struct before.
 */
bool
dhcp6_enable_stateless(NetworkInterface& netif, Dhcp6Context& ctx)
{
    // Logf(true | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp6_enable_stateless(netif=%p) %c%c%d\n", (void *)netif, netif->name[0], netif->name[1], (uint16_t)netif->num));
    // struct Dhcp6Context* dhcp6 = dhcp6_get_struct(netif);
    // if (dhcp6 == nullptr)
    // {
    //     return ERR_MEM;
    // }
    if (dhcp6_stateless_enabled(ctx)) {
        spdlog::info("dhcp6_enable_stateless(): stateless DHCPv6 already enabled");
        return true;
    }
    if (ctx.state != DHCP6_STATE_OFF) {
        /* stateful running */ /* @todo: stop stateful once it is implemented */
        spdlog::info(
            "dhcp6_enable_stateless(): switching from stateful to stateless DHCPv6");
    }
    spdlog::info("dhcp6_enable_stateless(): stateless DHCPv6 enabled");
    dhcp6_set_state(ctx, DHCP6_STATE_STATELESS_IDLE);
    return true;
}


/**
 * Disable stateful or stateless DHCPv6 on this netif Requests are sent on receipt of an
 * RA message with the ND6_RA_FLAG_OTHER_CONFIG flag set.
 */
void
dhcp6_disable(NetworkInterface& netif, Dhcp6Context& ctx)
{
    if (ctx.state != DHCP6_STATE_OFF) {
        spdlog::info("dhcp6_disable(): DHCPv6 disabled (old state: {}})\n",
                     dhcp6_stateless_enabled(ctx) ? "stateless" : "stateful");
        dhcp6_set_state(ctx, DHCP6_STATE_OFF);
        if (ctx.pcb_allocated != 0) {
            dhcp6_dec_pcb_refcount(ctx);
            /* free DHCPv6 PCB if not needed any more */
            ctx.pcb_allocated = 0;
        }
    }
}

/**
 * Create a DHCPv6 request, fill in common headers
 *
 * @param netif the netif under DHCPv6 control
 * @param dhcp6 dhcp6 control struct
 * @param message_type message type of the request
 * @param opt_len_alloc option length to allocate
 * @param options_out_len option length on exit
 * @return a PacketBuffer for the message
 */
Dhcp6ClientServerMessage
dhcp6_create_msg(Dhcp6Context& dhcp6, Dhcp6MessageType message_type)
{
    /* @todo: limit new xid for certain message types? */
    /* reuse transaction identifier in retransmissions */
    if (dhcp6.tries == 0)
    {
        dhcp6.xid = lwip_rand() & 0xFFFFFF;
    }

    // cast Dhcp6Message p_out.pay
    Dhcp6ClientServerMessage msg{};

    msg.msg_type = message_type;
    msg.transaction_id[0] = uint8_t(dhcp6.xid >> 16);
    msg.transaction_id[1] = uint8_t(dhcp6.xid >> 8);
    msg.transaction_id[2] = uint8_t(dhcp6.xid);
    return msg;
}

/**
 *
 */
size_t
dhcp6_option_short(size_t& options_out_len,
                   std::vector<uint8_t>& options,
                   uint16_t value)
{
    options[options_out_len++] = uint8_t((value & 0xff00U) >> 8);
    options[options_out_len++] = uint8_t(value & 0x00ffU);
    return options_out_len;
}


/**
 *
 */
size_t
dhcp6_option_optionrequest(size_t options_out_len,
                           std::vector<uint8_t>& options,
                           std::vector<uint16_t>& req_options,
                           size_t num_req_options)
{
    // lwip_assert(
    //     "dhcp6_option_optionrequest: options_out_len + sizeof(struct dhcp6_msg) + addlen <= max_len",
    //     sizeof(struct Dhcp6ClientServerMessage) + options_out_len + 4U + (2U *
    //         num_req_options) <= max_len);
    auto ret = dhcp6_option_short(options_out_len, options, DHCP6_OPTION_ORO);
    ret = dhcp6_option_short(ret, options, 2 * num_req_options);
    for (size_t i = 0; i < num_req_options; i++) {
        ret = dhcp6_option_short(ret, options, req_options[i]);
    }
    return ret;
}


/* All options are added, shrink the PacketBuffer to the required size */
bool
dhcp6_msg_finalize(size_t options_out_len, PacketContainer& p_out)
{
  /* shrink the PacketBuffer to the actual content length */
  //pbuf_realloc(p_out);
    return false;
}


void
dhcp6_information_request(NetworkInterface& netif, Dhcp6Context& ctx)
{
    const uint16_t requested_options[] = {
            DHCP6_OPTION_DNS_SERVERS,
            DHCP6_OPTION_DOMAIN_LIST,
            DHCP6_OPTION_SNTP_SERVERS
        };
    uint16_t options_out_len;
    spdlog::info("dhcp6_information_request()");

    /* create and initialize the DHCP message header */
    Dhcp6ClientServerMessage msg = dhcp6_create_msg(ctx, DHCP6_INFO_REQUEST);

    // const auto options = reinterpret_cast<uint8_t *>(msg_out + 1);



    spdlog::info("dhcp6_information_request: making request");

    options_out_len = dhcp6_option_optionrequest(options_out_len,
                                                 msg.options,
                                                 requested_options,
                                                 LWIP_ARRAYSIZE(requested_options));
    // LWIP_HOOK_DHCP6_APPEND_OPTIONS(netif,
    //                                dhcp6,
    //                                DHCP6_STATE_REQUESTING_CONFIG,
    //                                msg_out,
    //                                DHCP6_INFOREQUEST,
    //                                options_out_len,
    //                                msg->len);
    dhcp6_msg_finalize(options_out_len, msg);
    const auto err = udp_sendto_if(dhcp6_pcb,
                                   msg,
                                   &dhcp6_All_DHCP6_Relay_Agents_and_Servers,
                                   DHCP6_SERVER_PORT,
                                   netif);
    free_pkt_buf(msg);
    Logf(true, "dhcp6_information_request: INFOREQUESTING -> %d\n", err);
    dhcp6_set_state(dhcp6, DHCP6_STATE_REQUESTING_CONFIG);
    if (dhcp6->tries < 255) { dhcp6->tries++; }
    const auto msecs = uint16_t((dhcp6->tries < 6 ? 1 << dhcp6->tries : 60) * 1000);
    dhcp6->request_timeout =
        uint16_t((msecs + DHCP6_TIMER_MSECS - 1) / DHCP6_TIMER_MSECS);
    Logf(true, "dhcp6_information_request(): set request timeout %d msecs\n", msecs);
}



NsStatus
dhcp6_request_config(NetworkInterface*netif, Dhcp6Context *dhcp6)
{
  /* stateless mode enabled and no request running? */
  if (dhcp6->state == DHCP6_STATE_STATELESS_IDLE) {
    /* send Information-request and wait for answer; setup receive timeout */
    dhcp6_information_request(netif, dhcp6);
  }

  return STATUS_SUCCESS;
}


///
///
///
void
dhcp6_abort_config_request(Dhcp6Context *dhcp6)
{
  if (dhcp6->state == DHCP6_STATE_REQUESTING_CONFIG) {
    /* abort running request */
    dhcp6_set_state(dhcp6, DHCP6_STATE_STATELESS_IDLE);
  }
}


/// Handle a REPLY to INFOREQUEST
/// This parses DNS and NTP server addresses from the reply.
void
dhcp6_handle_config_reply(NetworkInterface* netif, struct PacketContainer* p_msg_in)
{
    Dhcp6Context* dhcp6 = get_netif_dhcp6_ctx(netif);

    if (dhcp6_option_given(dhcp6, DHCP6_OPTION_IDX_DNS_SERVER)) {
        IpAddrInfo dns_addr{};
        const auto op_start = dhcp6_get_option_start(dhcp6, DHCP6_OPTION_IDX_DNS_SERVER);
        const auto op_len = dhcp6_get_option_length(dhcp6, DHCP6_OPTION_IDX_DNS_SERVER);
        uint16_t idx;
        uint8_t n;

        memset(&dns_addr, 0, sizeof(dns_addr));
        const auto dns_addr6 = &dns_addr.u_addr.ip6;
        for (n = 0, idx = op_start; (idx < op_start + op_len) && (n < LWIP_DHCP6_PROVIDE_DNS_SERVERS);
             n++, idx += sizeof(Ip6Addr)) {
            const auto copied = pbuf_copy_partial(p_msg_in, (uint8_t*)dns_addr6, sizeof(Ip6Addr), idx);
            if (copied != sizeof(Ip6Addr)) {
                /* PacketBuffer length mismatch */
                return;
            }
            assign_ip6_addr_zone(dns_addr6, IP6_UNKNOWN, netif,);
            /* @todo: do we need a different offset than DHCP(v4)? */
            dns_setserver(&dns_addr, );
        }
    }
    /* @ todo: parse and set Domain Search List */


    if (dhcp6_option_given(dhcp6, DHCP6_OPTION_IDX_NTP_SERVER)) {
        IpAddrInfo ntp_server_addrs[LWIP_DHCP6_MAX_NTP_SERVERS];
        const auto op_start = dhcp6_get_option_start(dhcp6, DHCP6_OPTION_IDX_NTP_SERVER);
        const auto op_len = dhcp6_get_option_length(dhcp6, DHCP6_OPTION_IDX_NTP_SERVER);
        uint16_t idx;
        uint8_t n;

        for (n = 0, idx = op_start; (idx < op_start + op_len) && (n < LWIP_DHCP6_MAX_NTP_SERVERS);
             n++, idx += sizeof(Ip6Addr)) {
            const auto ntp_addr6 = &ntp_server_addrs[n].u_addr.ip6;

            ip6_addr_zero(&ntp_server_addrs[n].u_addr.ip6);
            &ntp_server_addrs[n].type = IP_ADDR_TYPE_V6;

            const auto copied = pbuf_copy_partial(p_msg_in, (uint8_t*)ntp_addr6, sizeof(Ip6Addr), idx);
            if (copied != sizeof(Ip6Addr)) {
                /* PacketBuffer length mismatch */
                return;
            }
            assign_ip6_addr_zone(ntp_addr6, IP6_UNKNOWN, netif,);
        }
    }
}


/** This function is called from nd6 module when an RA messsage is received
 * It triggers DHCPv6 requests (if enabled).
 */
void dhcp6_nd6_ra_trigger(NetworkInterface* netif,
                          uint8_t managed_addr_config,
                          uint8_t other_config)
{
    ns_assert("netif != NULL", netif != nullptr);
    struct Dhcp6Context* dhcp6 = get_netif_dhcp6_ctx(netif);

  if (dhcp6 != nullptr) {
    if (dhcp6_stateless_enabled(dhcp6)) {
      if (other_config) {
        dhcp6_request_config(netif, dhcp6);
      } else {
        dhcp6_abort_config_request(dhcp6);
      }
    }
  }

}

/**
 * Parse the DHCPv6 message and extract the DHCPv6 options.
 *
 * Extract the DHCPv6 options (offset + length) so that we can later easily
 * check for them or extract the contents.
 */
NsStatus dhcp6_parse_reply(struct PacketContainer* p, struct Dhcp6Context* dhcp6)
{
    auto msg_in = reinterpret_cast<struct Dhcp6ClientServerMessage *>(p->payload); /* parse options */
    const auto options_idx = sizeof(struct Dhcp6ClientServerMessage);
    /* parse options to the end of the received packet */
    const auto offset_max = p->tot_len;
    auto offset = options_idx; /* at least 4 byte to read? */
    while ((offset + 4 <= offset_max))
    {
        uint8_t op_len_buf[4];
        const auto val_offset = offset + 4;
        if (val_offset < offset)
        {
            /* overflow */
            return ERR_BUF;
        } /* copy option + length, might be split accross pbufs */
        // auto* op_len = static_cast<uint8_t *>(pbuf_get_contiguous(p, op_len_buf, 4, offset));
        if (op_len == nullptr)
        {
            /* failed to get option and length */
            return ERR_VAL;
        }
        const uint16_t op = (op_len[0] << 8) | op_len[1];
        const size_t len = (op_len[2] << 8) | op_len[3];
        offset = val_offset + len;
        if (offset < val_offset)
        {
            /* overflow */
            return ERR_BUF;
        }
        switch (op)
        {
        case (DHCP6_OPTION_CLIENTID): dhcp6_got_option(dhcp6, DHCP6_OPTION_IDX_CLI_ID);
            dhcp6_set_option(dhcp6, DHCP6_OPTION_IDX_CLI_ID, val_offset, len);
            break;
        case (DHCP6_OPTION_SERVERID): dhcp6_got_option(dhcp6, DHCP6_OPTION_IDX_SERVER_ID);
            dhcp6_set_option(dhcp6, DHCP6_OPTION_IDX_SERVER_ID, val_offset, len);
            break;

      case (DHCP6_OPTION_DNS_SERVERS):
        dhcp6_got_option(dhcp6, DHCP6_OPTION_IDX_DNS_SERVER);
        dhcp6_set_option(dhcp6, DHCP6_OPTION_IDX_DNS_SERVER, val_offset, len);
        break;
      case (DHCP6_OPTION_DOMAIN_LIST):
        dhcp6_got_option(dhcp6, DHCP6_OPTION_IDX_DOMAIN_LIST);
        dhcp6_set_option(dhcp6, DHCP6_OPTION_IDX_DOMAIN_LIST, val_offset, len);
        break;


      case (DHCP6_OPTION_SNTP_SERVERS):
        dhcp6_got_option(dhcp6, DHCP6_OPTION_IDX_NTP_SERVER);
        dhcp6_set_option(dhcp6, DHCP6_OPTION_IDX_NTP_SERVER, val_offset, len);
        break;

        default:
            // Logf(true, ("skipping option %d in options\n", op));
            // LWIP_HOOK_DHCP6_PARSE_OPTION(ip_current_netif(),
            //                              dhcp6,
            //                              dhcp6->state,
            //                              msg_in,
            //                              msg_in->msgtype,
            //                              op,
            //                              len,
            //                              q,
            //                              val_offset);
            break;
        }
    }
    return STATUS_SUCCESS;
}


std::tuple<bool, Dhcp6ClientServerMessage>
dhcp6_recv(Dhcp6Context& ctx, IpAddrInfo& addr, uint16_t port, NetworkInterface& netif)
{
    Dhcp6ClientServerMessage parsed_message{};
    Dhcp6ClientServerMessage reply_message{};
    // auto dhcp6 = get_netif_dhcp6_ctx(netif);
    auto reply_msg = reinterpret_cast<Dhcp6ClientServerMessage *>(p->payload
    ); /* Caught DHCPv6 message from netif that does not have DHCPv6 enabled? -> not interested */
    if ((ctx == nullptr) || (ctx.pcb_allocated == 0)) { goto free_pbuf_and_return; } //
    if (!(addr.type == IP_ADDR_TYPE_V6)) {
        printf("invalid server address type\n");
        goto free_pbuf_and_return;
    }
    // Logf(true | LWIP_DBG_TRACE,
    //      ("dhcp6_recv(PacketBuffer = %p) from DHCPv6 server %s port %d\n", (void *)p
    //          , ipaddr_ntoa(addr), port));
    // Logf(true | LWIP_DBG_TRACE, ("PacketBuffer->len = %d\n", p->len));
    // Logf(true | LWIP_DBG_TRACE,
    //      ("PacketBuffer->tot_len = %d\n", p->tot_len));
    // /* prevent warnings about unused arguments */
    // ;
    // ;
    // ;
    if (p->len < sizeof(struct Dhcp6ClientServerMessage)) {
        Logf(true, ("DHCPv6 reply message or PacketBuffer too short\n"));
        goto free_pbuf_and_return;
    } /* match transaction ID against what we expected */
    uint32_t xid = reply_msg->transaction_id[0] << 16;
    xid |= reply_msg->transaction_id[1] << 8;
    xid |= reply_msg->transaction_id[2];
    if (xid != ctx.xid) {
        // Logf(true | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
        //      ("transaction id mismatch reply_msg->xid(%x)!= dhcp6->xid(%x)\n",
        //          xid, dhcp6->xid));
        goto free_pbuf_and_return;
    } /* option fields could be unfold? */
    if (dhcp6_parse_reply(p, ctx) != STATUS_SUCCESS) {
        Logf(true, ("problem unfolding DHCPv6 message - too short on memory?\n"));
        goto free_pbuf_and_return;
    } /* read DHCP message type */
    uint8_t msg_type = reply_msg->msgtype; /* message type is DHCP6 REPLY? */
    if (msg_type == DHCP6_REPLY) {
        Logf(true, ("DHCP6_REPLY received\n"));

        /* in info-requesting state? */
        if (ctx.state == DHCP6_STATE_REQUESTING_CONFIG) {
            dhcp6_set_state(ctx, DHCP6_STATE_STATELESS_IDLE);
            dhcp6_handle_config_reply(netif, p);
        }
        else {
            /* @todo: handle reply in other states? */
        }
    }
    else {
        /* @todo: handle other message types */
    }
free_pbuf_and_return: free_pkt_buf(p);
}

/**
 * A DHCPv6 request has timed out.
 *
 * The timer that was started with the DHCPv6 request has
 * timed out, indicating no response was received in time.
 */
void
dhcp6_timeout(NetworkInterface*netif, struct Dhcp6Context *dhcp6)
{
  Logf(true, ("dhcp6_timeout()\n"));

  // ;
  // ;


  /* back-off period has passed, or server selection timed out */
  if (dhcp6->state == DHCP6_STATE_REQUESTING_CONFIG) {
    Logf(true, ("dhcp6_timeout(): retrying information request\n"));
    dhcp6_information_request(netif, dhcp6);
  }

}

/**
 * DHCPv6 timeout handling (this function must be called every 500ms,
 * see @ref DHCP6_TIMER_MSECS).
 *
 * A DHCPv6 server is expected to respond within a short period of time.
 * This timer checks whether an outstanding DHCPv6 request is timed out.
 */
void
dhcp6_tmr(void)
{
  NetworkInterface*netif;
  /* loop through netif's */
  for ((netif) = netif_list; (netif) != nullptr; (netif) = (netif)->next) {
    struct Dhcp6Context *dhcp6 = get_netif_dhcp6_ctx(netif);
    /* only act on DHCPv6 configured interfaces */
    if (dhcp6 != nullptr) {
      /* timer is active (non zero), and is about to trigger now */
      if (dhcp6->request_timeout > 1) {
        dhcp6->request_timeout--;
      } else if (dhcp6->request_timeout == 1) {
        dhcp6->request_timeout--;
        /* { dhcp6->request_timeout == 0 } */
        Logf(true, ("dhcp6_tmr(): request timeout\n"));
        /* this client's request timeout triggered */
        dhcp6_timeout(netif, dhcp6);
      }
    }
  }
}


void dhcp6_set_ntp_servers(uint8_t num_ntp_servers, const IpAddrInfo* ntp_server_addrs)
{

}




//
// END OF FILE
//