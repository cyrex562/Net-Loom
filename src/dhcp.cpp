///
/// file: dhcp.cpp
///

#define NOMINMAX
#include "dhcp.h"
#include "dhcp_context.h"
#include "opt.h"
#include "udp.h"
#include "ip_addr.h"
#include "network_interface.h"
#include "def.h"
#include "autoip.h"
#include "dns.h"
#include "etharp.h"
#include "iana.h"
#include "ip.h"
#include <cstring>
#include <algorithm>


///
///  Ensure DHCP PCB is allocated and bound
///
static LwipStatus dhcp_inc_pcb_refcount()
{
    if (dhcp_pcb_refcount == 0) {
        // allocate UDP PCB
        dhcp_pcb = udp_new();
        if (dhcp_pcb == nullptr) {
            return ERR_MEM;
        }
        // todo: this is setting the first field of the DHCP_PCB struct to SOF_BROADCAST; probably a bug.
        set_ip4_option((uint8_t*)dhcp_pcb, SOF_BROADCAST);
        // set up local and remote port for the pcb -> listen on all interfaces on all src/dest IPs
        auto any_addr = create_ip_addr_any();
        udp_bind(dhcp_pcb, &any_addr, LWIP_IANA_PORT_DHCP_CLIENT);
        udp_connect(dhcp_pcb, &any_addr, LWIP_IANA_PORT_DHCP_SERVER);
        udp_recv(dhcp_pcb, dhcp_recv, nullptr);
    }
    dhcp_pcb_refcount++;
    return STATUS_SUCCESS;
}


///
/// Free DHCP PCB if the last netif stops using it
///
static void dhcp_dec_pcb_refcount(void)
{
    // lwip_assert("dhcp_pcb_refcount(): refcount error", (dhcp_pcb_refcount > 0));
    dhcp_pcb_refcount--;
    if (dhcp_pcb_refcount == 0) {
        udp_remove(dhcp_pcb);
        dhcp_pcb = nullptr;
    }
}

/**
 * Back-off the DHCP client (because of a received NAK response).
 *
 * Back-off the DHCP client because of a received NAK. Receiving a
 * NAK means the client asked for something non-sensible, for
 * example when it tries to renew a lease obtained on another network.
 *
 * We clear any existing set IP address and restart DHCP negotiation
 * afresh (as per RFC2131 3.2.3).
 *
 * @param netif the netif under DHCP control
 */
static void dhcp_handle_nak(NetworkInterface * netif)
{
    // DhcpContext* dhcp = get_netif_dhcp_ctx(netif);
    auto dhcp = netif->dhcp_ctx;
    // Logf(true | LWIP_DBG_TRACE,
    //      ("dhcp_handle_nak(netif=%p) %c%c%d\n", (void *)netif, netif->name[0], netif
    //          ->name[1], (uint16_t)netif->num));
    /* Change to a defined state - set this before assigning the address
        to ensure the callback can use dhcp_supplied_address() */
    dhcp_set_state(&dhcp, DHCP_STATE_BACKING_OFF);
    /* remove IP address from interface (must no longer be used, as per RFC2131) */
    set_netif_addr(netif, nullptr, nullptr, nullptr);
    /* We can immediately restart discovery */
    dhcp_discover(netif);
}

///
/// Checks if the offered IP address is already in use.
///
/// It does so by sending an ARP request for the offered address and
/// entering CHECKING state. If no ARP reply is received within a small
/// interval, the address is assumed to be free for use by us.
///
/// netif: the netif under DHCP control
///
static void
dhcp_check(NetworkInterface * netif)
{
    // DhcpContext* dhcp = get_netif_dhcp_ctx(netif);
    auto dhcp = netif->dhcp_ctx;
    Logf(true,
         "dhcp_check(netif=%p) %c%c\n",
         netif,
         netif->name[0],
         netif->name[1]);
    dhcp_set_state(&dhcp, DHCP_STATE_CHECKING);
    /* create an ARP query for the offered IP address, expecting that no host
       responds, as the IP address should not be in use. */
    LwipStatus result = etharp_query(netif, &dhcp.offered_ip_addr, nullptr);
    if (result != STATUS_SUCCESS) {
        Logf(true, "dhcp_check: could not perform ARP query\n");
    }
    if (dhcp.tries < 255) {
        dhcp.tries++;
    }
    uint16_t msecs = 500;
    dhcp->request_timeout = (uint16_t)((msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS);
    Logf(true, "dhcp_check(): set request timeout %d msecs\n", msecs);
}


//
// Remember the configuration offered by a DHCP server.
//
// param netif: the netif under DHCP control
//
static void dhcp_handle_offer(NetworkInterface * netif, DhcpMsg * msg_in, DhcpContext* dhcp_ctx)
{
    auto dhcp = get_netif_dhcp_ctx(netif);
    Logf(true,
         "dhcp_handle_offer(netif=%p) %c%c%%d\n",
         static_cast<void*>(netif),
         netif->name[0],
         netif->name[1],
         uint16_t(netif->number)); /* obtain the server address */
    if (dhcp_option_given(dhcp_ctx->dhcp_options, DHCP_OPTION_IDX_SERVER_ID)) {
        dhcp->request_timeout = 0; /* stop timer */
        set_ip_addr_ip4_u32(&dhcp->server_ip_addr,
                            lwip_htonl(
                            dhcp_get_option_value(dhcp_ctx->dhcp_options, DHCP_OPTION_IDX_SERVER_ID)));
        Logf(true,
             "dhcp_handle_offer(): server 0x%08%d\n", get_ip4_addr_u32(
             &dhcp->server_ip_addr.u_addr.ip4)); /* remember offered address */
        copy_ip4_addr(&dhcp->offered_ip_addr, &msg_in->yiaddr);
        Logf(true,
             "dhcp_handle_offer(): offer for 0x%08%d\n", get_ip4_addr_u32(
             &dhcp->offered_ip_addr));
        dhcp_select(netif);
    } else {
        Logf(true,
             "dhcp_handle_offer(netif=%p) did not get server ID!\n", (void*)netif);
    }
}

/**
 * Select a DHCP server offer out of all offers.
 *
 * Simply select the first offer received.
 *
 * @param netif the netif under DHCP control
 * @return lwIP specific error (see error.h)
 */
static LwipStatus dhcp_select(NetworkInterface * netif)
{
    LwipStatus result;
    uint16_t options_out_len;
    auto dhcp = get_netif_dhcp_ctx(netif);
    Logf(true,
         "dhcp_select(netif=%p) %c%c%d\n",
         netif,
         netif->name[0],
         netif->name[1],
         uint16_t(netif->number));
    dhcp_set_state(dhcp, DHCP_STATE_REQUESTING);
    /* create and initialize the DHCP message header */
    struct PacketBuffer* p_out = dhcp_create_msg(netif,
                                                 dhcp,
                                                 DHCP_REQUEST,
                                                 &options_out_len);
    if (p_out != nullptr) {
        auto msg_out = reinterpret_cast<DhcpMsg*>(p_out->payload);
        options_out_len = dhcp_option(options_out_len,
                                      msg_out->options,
                                      DHCP_OPTION_MAX_MSG_SIZE,
                                      DHCP_OPTION_MAX_MSG_SIZE_LEN);
        options_out_len = dhcp_option_short(options_out_len,
                                            msg_out->options,
                                            DHCP_MAX_MSG_LEN(netif));
        /* MUST request the offered IP address */
        options_out_len = dhcp_option(options_out_len,
                                      msg_out->options,
                                      DHCP_OPTION_REQUESTED_IP,
                                      4);
        options_out_len = dhcp_option_long(options_out_len,
                                           msg_out->options,
                                           lwip_ntohl(
                                           get_ip4_addr_u32(&dhcp->offered_ip_addr)));
        options_out_len = dhcp_option(options_out_len,
                                      msg_out->options,
                                      DHCP_OPTION_SERVER_ID,
                                      4);
        options_out_len = dhcp_option_long(options_out_len,
                                           msg_out->options,
                                           lwip_ntohl(get_ip4_addr_u32(
                                           &dhcp->server_ip_addr.u_addr.ip4)));
        options_out_len = dhcp_option(options_out_len,
                                      msg_out->options,
                                      DHCP_OPTION_PARAMETER_REQUEST_LIST,
                                      LWIP_ARRAYSIZE(dhcp_discover_request_options));
        for (uint8_t i = 0; i < LWIP_ARRAYSIZE(dhcp_discover_request_options); i++) {
            options_out_len = dhcp_option_byte(options_out_len,
                                               msg_out->options,
                                               dhcp_discover_request_options[i]);
        }
        options_out_len = dhcp_option_hostname(options_out_len, msg_out->options, netif);
        LWIP_HOOK_DHCP_APPEND_OPTIONS(netif,
                                      dhcp,
                                      DHCP_STATE_REQUESTING,
                                      msg_out,
                                      DHCP_REQUEST,
                                      &options_out_len);
        dhcp_option_trailer(options_out_len, msg_out->options, p_out);
        /* send broadcast to any DHCP server */
        auto ip_bcast = create_ip_addr_ip4_bcast();
        auto ip_any = create_ip_addr_ip4_any();
        result = udp_sendto_if_src(dhcp_pcb,
                                   p_out,
                                   &ip_bcast,
                                   LWIP_IANA_PORT_DHCP_SERVER,
                                   netif,
                                   &ip_any);
        free_pkt_buf(p_out);
        Logf(true, "dhcp_select: REQUESTING\n");
    } else {
        Logf(true, "dhcp_select: could not allocate DHCP request\n");
        result = ERR_MEM;
    }

    if (dhcp->tries < MAX_TRIES) {
        dhcp->tries++;
    }

    auto msecs = uint16_t((dhcp->tries < 6 ? 1 << dhcp->tries : 60) * MILLIS_PER_SEC);
    dhcp->request_timeout = uint16_t((msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS);
    Logf(true, "dhcp_select(): set request timeout %d msecs\n", msecs);
    return result;
}

/**
 * The DHCP timer that checks for lease renewal/rebind timeouts.
 * Must be called once a minute (see @ref DHCP_COARSE_TIMER_SECS).
 */
void
dhcp_coarse_tmr(void)
{
    NetworkInterface* netif;
    Logf(true, "dhcp_coarse_tmr()\n");
    /* iterate through all network interfaces */
    for ((netif) = netif_list; (netif) != nullptr; (netif) = (netif)->next)
    {
        /* only act on DHCP configured interfaces */
        DhcpContext* dhcp = get_netif_dhcp_ctx(netif);
        if (dhcp != nullptr && dhcp->state != DHCP_STATE_OFF) {
            /* compare lease time to expire timeout */
            if (dhcp->t0_timeout && ++dhcp->lease_used == dhcp->t0_timeout) {
                Logf(true, "dhcp_coarse_tmr(): t0 timeout\n");
                /* this clients' lease time has expired */
                dhcp_release_and_stop(netif);
                dhcp_start(netif);
                /* timer is active (non zero), and triggers (zeroes) now? */
            } else if (dhcp->t2_rebind_time && dhcp->t2_rebind_time-- == 1) {
                Logf(true, "dhcp_coarse_tmr(): t2 timeout\n");
                /* this clients' rebind timeout triggered */
                dhcp_t2_timeout(netif);
                /* timer is active (non zero), and triggers (zeroes) now */
            } else if (dhcp->t1_renew_time && dhcp->t1_renew_time-- == 1) {
                Logf(true, "dhcp_coarse_tmr(): t1 timeout\n");
                /* this clients' renewal timeout triggered */
                dhcp_t1_timeout(netif);
            }
        }
    }
}

/**
 * DHCP transaction timeout handling (this function must be called every 500ms,
 * see @ref DHCP_FINE_TIMER_MSECS).
 *
 * A DHCP server is expected to respond within a short period of time.
 * This timer checks whether an outstanding DHCP request is timed out.
 */
void
dhcp_fine_tmr(void)
{
    NetworkInterface* netif;
    /* loop through netif's */
    for ((netif) = netif_list; (netif) != nullptr; (netif) = (netif)->next)
    {
        DhcpContext* dhcp = get_netif_dhcp_ctx(netif);
        /* only act on DHCP configured interfaces */
        if (dhcp != nullptr) {
            /* timer is active (non zero), and is about to trigger now */
            if (dhcp->request_timeout > 1) {
                dhcp->request_timeout--;
            } else if (dhcp->request_timeout == 1) {
                dhcp->request_timeout--;
                /* { dhcp->request_timeout == 0 } */
                Logf(true, "dhcp_fine_tmr(): request timeout\n");
                /* this client's request timeout triggered */
                dhcp_timeout(netif);
            }
        }
    }
}

/**
 * A DHCP negotiation transaction, or ARP request, has timed out.
 *
 * The timer that was started with the DHCP or ARP request has
 * timed out, indicating no response was received in time.
 *
 * @param netif the netif under DHCP control
 */
static void
dhcp_timeout(NetworkInterface * netif)
{
    DhcpContext* dhcp = get_netif_dhcp_ctx(netif);

    Logf(true, "dhcp_timeout()\n");
    /* back-off period has passed, or server selection timed out */
    if (dhcp->state == DHCP_STATE_BACKING_OFF || dhcp->state == DHCP_STATE_SELECTING) {
        Logf(true, "dhcp_timeout(): restarting discovery\n");
        dhcp_discover(netif);
        /* receiving the requested lease timed out */
    } else if (dhcp->state == DHCP_STATE_REQUESTING) {
        Logf(true, "dhcp_timeout(): REQUESTING, DHCP request timed out\n");
        if (dhcp->tries <= 5) {
            dhcp_select(netif);
        } else {
            Logf(true, "dhcp_timeout(): REQUESTING, releasing, restarting\n");
            dhcp_release_and_stop(netif);
            dhcp_start(netif);
        }

        /* received no ARP reply for the offered address (which is good) */
    } else if (dhcp->state == DHCP_STATE_CHECKING) {
        Logf(true, "dhcp_timeout(): CHECKING, ARP request timed out\n");
        if (dhcp->tries <= 1) {
            dhcp_check(netif);
            /* no ARP replies on the offered address,
               looks like the IP address is indeed free */
        } else {
            /* bind the interface to the offered address */
            dhcp_bind(netif);
        }

    } else if (dhcp->state == DHCP_STATE_REBOOTING) {
        if (dhcp->tries < kRebootTries) {
            dhcp_reboot(netif);
        } else {
            dhcp_discover(netif);
        }
    }
}

/**
 * The renewal period has timed out.
 *
 * @param netif the netif under DHCP control
 */
static void
dhcp_t1_timeout(NetworkInterface * netif)
{
    DhcpContext* dhcp = get_netif_dhcp_ctx(netif);

    Logf(true, "dhcp_t1_timeout()\n");
    if (dhcp->state == DHCP_STATE_REQUESTING || dhcp->state == DHCP_STATE_BOUND ||
        dhcp->state == DHCP_STATE_RENEWING) {
        /* just retry to renew - note that the rebind timer (t2) will
         * eventually time-out if renew tries fail. */
        Logf(true,
            "dhcp_t1_timeout(): must renew\n");
        /* This slightly different to RFC2131: DHCPREQUEST will be sent from state
           DHCP_STATE_RENEWING, not DHCP_STATE_BOUND */
        dhcp_renew(netif);
        /* Calculate next timeout */
        if ((dhcp->t2_timeout - dhcp->lease_used) / 2 >= (60 + DHCP_COARSE_TIMER_SECS / 2) / DHCP_COARSE_TIMER_SECS) {
            dhcp->t1_renew_time = (uint16_t)((dhcp->t2_timeout - dhcp->lease_used) / 2);
        }
    }
}

/**
 * The rebind period has timed out.
 *
 * @param netif the netif under DHCP control
 */
static void
dhcp_t2_timeout(NetworkInterface * netif)
{
    DhcpContext* dhcp = get_netif_dhcp_ctx(netif);

    Logf(true, "dhcp_t2_timeout()\n");
    if (dhcp->state == DHCP_STATE_REQUESTING || dhcp->state == DHCP_STATE_BOUND ||
        dhcp->state == DHCP_STATE_RENEWING || dhcp->state == DHCP_STATE_REBINDING) {
        /* just retry to rebind */
        Logf(true,
            "dhcp_t2_timeout(): must rebind\n");
        /* This slightly different to RFC2131: DHCPREQUEST will be sent from state
           DHCP_STATE_REBINDING, not DHCP_STATE_BOUND */
        dhcp_rebind(netif);
        /* Calculate next timeout */
        if ((dhcp->t0_timeout - dhcp->lease_used) / 2 >= (60 + DHCP_COARSE_TIMER_SECS / 2) / DHCP_COARSE_TIMER_SECS) {
            dhcp->t2_rebind_time = (uint16_t)((dhcp->t0_timeout - dhcp->lease_used) / 2);
        }
    }
}

/**
 * Handle a DHCP ACK packet
 *
 * @param netif the netif under DHCP control
 */
static void
dhcp_handle_ack(NetworkInterface * netif, DhcpMsg * msg_in)
{
    DhcpContext* dhcp = get_netif_dhcp_ctx(netif);

    uint8_t n;

    Ip4Addr ntp_server_addrs[LWIP_DHCP_MAX_NTP_SERVERS];


    /* clear options we might not get from the ACK */
    zero_ip4_addr(&dhcp->offered_sn_mask);
    zero_ip4_addr(&dhcp->offered_gw_addr);

    zero_ip4_addr(&dhcp->offered_si_addr);


    /* lease time given? */
    if (dhcp_option_given(dhcp->dhcp_options, DHCP_OPTION_IDX_LEASE_TIME)) {
        /* remember offered lease time */
        dhcp->offered_t0_lease = dhcp_get_option_value(dhcp->dhcp_options, DHCP_OPTION_IDX_LEASE_TIME);
    }
    /* renewal period given? */
    if (dhcp_option_given(dhcp->dhcp_options, DHCP_OPTION_IDX_T1)) {
        /* remember given renewal period */
        dhcp->offered_t1_renew = dhcp_get_option_value(dhcp->dhcp_options, DHCP_OPTION_IDX_T1);
    } else {
        /* calculate safe periods for renewal */
        dhcp->offered_t1_renew = dhcp->offered_t0_lease / 2;
    }

    /* renewal period given? */
    if (dhcp_option_given(dhcp->dhcp_options, DHCP_OPTION_IDX_T2)) {
        /* remember given rebind period */
        dhcp->offered_t2_rebind = dhcp_get_option_value(dhcp->dhcp_options, DHCP_OPTION_IDX_T2);
    } else {
        /* calculate safe periods for rebinding (offered_t0_lease * 0.875 -> 87.5%)*/
        dhcp->offered_t2_rebind = dhcp->offered_t0_lease * 7U / 8U;
    }

    /* (y)our internet address */
    copy_ip4_addr(&dhcp->offered_ip_addr, &msg_in->yiaddr);


    /* copy boot server address,
       boot file name copied in dhcp_parse_reply if not overloaded */
    copy_ip4_addr(&dhcp->offered_si_addr, &msg_in->siaddr);


    /* subnet mask given? */
    if (dhcp_option_given(dhcp->dhcp_options, DHCP_OPTION_IDX_SUBNET_MASK)) {
        /* remember given subnet mask */
        set_ip4_addr_u32(&dhcp->offered_sn_mask, lwip_htonl(dhcp_get_option_value(dhcp->dhcp_options, DHCP_OPTION_IDX_SUBNET_MASK)));
        dhcp->subnet_mask_given = 1;
    } else {
        dhcp->subnet_mask_given = 0;
    }

    /* gateway router */
    if (dhcp_option_given(dhcp->dhcp_options, DHCP_OPTION_IDX_ROUTER)) {
        set_ip4_addr_u32(&dhcp->offered_gw_addr, lwip_htonl(dhcp_get_option_value(dhcp->dhcp_options, DHCP_OPTION_IDX_ROUTER)));
    }


    /* NTP servers */
    for (n = 0; n < LWIP_DHCP_MAX_NTP_SERVERS && dhcp_option_given(dhcp->dhcp_options, DHCP_OPTION_IDX_NTP_SERVER + n); n++) {
        set_ip4_addr_u32(&ntp_server_addrs[n], lwip_htonl(dhcp_get_option_value(dhcp->dhcp_options, DHCP_OPTION_IDX_NTP_SERVER + n)));
    }
    dhcp_set_ntp_servers(n, ntp_server_addrs);



    /* DNS servers */
    for (n = 0; n < 0xff && dhcp_option_given(dhcp->dhcp_options, DHCP_OPTION_IDX_DNS_SERVER + n); n++) {
        IpAddrInfo dns_addr{};
        set_ip4_addr_u32(&dns_addr.u_addr.ip4,
                         lwip_htonl(
                         dhcp_get_option_value(dhcp->dhcp_options, DHCP_OPTION_IDX_DNS_SERVER + n)));
        dns_setserver(n, &dns_addr);
    }

}

///
/// Set a statically allocated DhcpContext to work with.
/// Using this prevents dhcp_start to allocate it using mem_malloc.
///
/// netif: the netif for which to set the struct dhcp
/// dhcp: (uninitialised) dhcp struct allocated by the application
///
void dhcp_set_struct(NetworkInterface * netif, DhcpContext * dhcp)
{
    /* clear data structure */
    memset(dhcp, 0, sizeof(DhcpContext)); /* dhcp_set_state(&dhcp, DHCP_STATE_OFF); */
    netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_DHCP, dhcp);
}

///
/// Removes a struct dhcp from a netif.
///
/// ATTENTION: Only use this when not using dhcp_set_struct() to allocate the
///            struct dhcp since the memory is passed back to the heap.
///
/// netif: the netif from which to remove the struct dhcp
///
void dhcp_cleanup(NetworkInterface * netif)
{
    auto data = get_netif_dhcp_ctx(netif);
    if (data != nullptr) {
        netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_DHCP, nullptr);
    }
}

///
/// Start DHCP negotiation for a network interface.
///
/// If no DHCP client instance was attached to this interface,
/// a new client is created first. If a DHCP client instance
/// was already present, it restarts negotiation.
///
/// netif: The lwIP network interface
///
/// returns: lwIP error code
/// * ERR_OK: No error
/// * ERR_MEM: Out of memory
///
LwipStatus
dhcp_start(NetworkInterface * netif)
{
    DhcpContext* dhcp = get_netif_dhcp_ctx(netif);
    Logf(true, "dhcp_start(netif=%p) %c%c%d\n", (void*)netif, netif->name[0], netif->name[1], (uint16_t)netif->number);

    /* check MTU of the netif */
    if (netif->mtu < kDhcpMaxMsgLenMinRequired) {
        Logf(true, "dhcp_start(): Cannot use this netif with DHCP: MTU is too small\n");
        return ERR_MEM;
    }

    /* no DHCP client attached yet? */
    if (dhcp == nullptr) {
        Logf(true, "dhcp_start(): mallocing new DHCP client\n");
        dhcp = new DhcpContext;
        if (dhcp == nullptr) {
            Logf(true, "dhcp_start(): could not allocate dhcp\n");
            return ERR_MEM;
        }

        /* store this dhcp client in the netif */
        netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_DHCP, dhcp);
        Logf(true, "dhcp_start(): allocated dhcp");
        /* already has DHCP client attached */
    } else {
        Logf(true, "dhcp_start(): restarting DHCP configuration\n");

        if (dhcp->pcb_allocated != 0) {
            dhcp_dec_pcb_refcount(); /* free DHCP PCB if not needed any more */
        }
        /* dhcp is cleared below, no need to reset flag*/
    }

    /* clear data structure */
    memset(dhcp, 0, sizeof(DhcpContext));
    /* dhcp_set_state(&dhcp, DHCP_STATE_OFF); */

    Logf(true, "dhcp_start(): starting DHCP configuration\n");

    if (dhcp_inc_pcb_refcount() != STATUS_SUCCESS) { /* ensure DHCP PCB is allocated */
        return ERR_MEM;
    }
    dhcp->pcb_allocated = 1;

    if (!is_netif_link_up(netif)) {
        /* set state INIT and wait for dhcp_network_changed() to call dhcp_discover() */
        dhcp_set_state(dhcp, DHCP_STATE_INIT);
        return STATUS_SUCCESS;
    }

    /* (re)start the DHCP negotiation */
    LwipStatus result = dhcp_discover(netif);
    if (result != STATUS_SUCCESS) {
        /* free resources allocated above */
        dhcp_release_and_stop(netif);
        return ERR_MEM;
    }
    return result;
}

/**
 * @ingroup dhcp4
 * Inform a DHCP server of our manual configuration.
 *
 * This informs DHCP servers of our fixed IP address configuration
 * by sending an INFORM message. It does not involve DHCP address
 * configuration, it is just here to be nice to the network.
 *
 * @param netif The lwIP network interface
 */
void
dhcp_inform(NetworkInterface * netif)
{
    DhcpContext dhcp;
    uint16_t options_out_len;



    if (dhcp_inc_pcb_refcount() != STATUS_SUCCESS) { /* ensure DHCP PCB is allocated */
        return;
    }

    memset(&dhcp, 0, sizeof(DhcpContext));
    dhcp_set_state(&dhcp, DHCP_STATE_INFORMING);

    /* create and initialize the DHCP message header */
    struct PacketBuffer* p_out = dhcp_create_msg(netif, &dhcp, DHCP_INFORM, &options_out_len);
    if (p_out != nullptr) {
        auto* msg_out = (DhcpMsg*)p_out->payload;
        options_out_len = dhcp_option(options_out_len, msg_out->options, DHCP_OPTION_MAX_MSG_SIZE, DHCP_OPTION_MAX_MSG_SIZE_LEN);
        options_out_len = dhcp_option_short(options_out_len, msg_out->options, DHCP_MAX_MSG_LEN(netif));

        LWIP_HOOK_DHCP_APPEND_OPTIONS(netif, &dhcp, DHCP_STATE_INFORMING, msg_out, DHCP_INFORM, &options_out_len);
        dhcp_option_trailer(options_out_len, msg_out->options, p_out);

        Logf(true, "dhcp_inform: INFORMING\n");

        auto bcast_addr = create_ip_addr_ip4_bcast();
        udp_sendto_if(dhcp_pcb, p_out, &bcast_addr, LWIP_IANA_PORT_DHCP_SERVER, netif);

        free_pkt_buf(p_out);
    } else {
        Logf(true, "dhcp_inform: could not allocate DHCP request\n");
    }

    dhcp_dec_pcb_refcount(); /* delete DHCP PCB if not needed any more */
}

/** Handle a possible change in the network configuration.
 *
 * This enters the REBOOTING state to verify that the currently bound
 * address is still valid.
 */
void
dhcp_network_changed(NetworkInterface * netif)
{
    DhcpContext* dhcp = get_netif_dhcp_ctx(netif);

    if (!dhcp) {
        return;
    }
    switch (dhcp->state) {
        case DHCP_STATE_REBINDING:
        case DHCP_STATE_RENEWING:
        case DHCP_STATE_BOUND:
        case DHCP_STATE_REBOOTING:
            dhcp->tries = 0;
            dhcp_reboot(netif);
            break;
        case DHCP_STATE_OFF:
            /* stay off */
            break;
        default:
            lwip_assert("invalid dhcp->state", dhcp->state <= DHCP_STATE_BACKING_OFF);
            /* INIT/REQUESTING/CHECKING/BACKING_OFF restart with new 'rid' because the
               state changes, SELECTING: continue with current 'rid' as we stay in the
               same state */

            if (dhcp->autoip_coop_state == DHCP_AUTOIP_COOP_STATE_ON) {
                autoip_stop(netif);
                dhcp->autoip_coop_state = DHCP_AUTOIP_COOP_STATE_OFF;
            }

            /* ensure we start with short timeouts, even if already discovering */
            dhcp->tries = 0;
            dhcp_discover(netif);
            break;
    }
}


/**
 * Match an ARP reply with the offered IP address:
 * check whether the offered IP address is not in use using ARP
 *
 * @param netif the network interface on which the reply was received
 * @param addr The IP address we received a reply from
 */
bool
dhcp_arp_reply(NetworkInterface& netif, const Ip4Addr& addr)
{
    DhcpContext* dhcp = get_netif_dhcp_ctx(netif);
    Logf(true, "dhcp_arp_reply()\n");
    /* is a DHCP client doing an ARP check? */
    if (dhcp != nullptr && dhcp->state == DHCP_STATE_CHECKING) {
        Logf(true, "dhcp_arp_reply(): CHECKING, arp reply for 0x%08x\n",
             get_ip4_addr_u32(addr));
        /* did a host respond with the address we
           were offered by the DHCP server? */
        if (is_ip4_addr_equal(addr, &dhcp->offered_ip_addr)) {
            /* we will not accept the offered address */
            Logf(true,
                "dhcp_arp_reply(): arp reply matched with offered address, declining\n");
            dhcp_decline(netif);
        }
    }
}

/**
 * Decline an offered lease.
 *
 * Tell the DHCP server we do not accept the offered address.
 * One reason to decline the lease is when we find out the address
 * is already in use by another host (through ARP).
 *
 * @param netif the netif under DHCP control
 */
static LwipStatus
dhcp_decline(NetworkInterface * netif)
{
    DhcpContext* dhcp = get_netif_dhcp_ctx(netif);
    LwipStatus result;
    uint16_t options_out_len;

    Logf(true, "dhcp_decline()\n");
    dhcp_set_state(dhcp, DHCP_STATE_BACKING_OFF);
    /* create and initialize the DHCP message header */
    struct PacketBuffer* p_out = dhcp_create_msg(netif, dhcp, DHCP_DECLINE, &options_out_len);
    if (p_out != nullptr) {
        auto* msg_out = (DhcpMsg*)p_out->payload;
        options_out_len = dhcp_option(options_out_len, msg_out->options, DHCP_OPTION_REQUESTED_IP, 4);
        options_out_len = dhcp_option_long(options_out_len, msg_out->options, lwip_ntohl(get_ip4_addr_u32(&dhcp->offered_ip_addr)));

        LWIP_HOOK_DHCP_APPEND_OPTIONS(netif, dhcp, DHCP_STATE_BACKING_OFF, msg_out, DHCP_DECLINE, &options_out_len);
        dhcp_option_trailer(options_out_len, msg_out->options, p_out);

        /* per section 4.4.4, broadcast DECLINE messages */
        IpAddrInfo bcast_addr = create_ip_addr_ip4_bcast();
        IpAddrInfo any_addr = create_ip_addr_ip4_any();
        result = udp_sendto_if_src(dhcp_pcb, p_out, &bcast_addr, LWIP_IANA_PORT_DHCP_SERVER, netif, &any_addr);
        free_pkt_buf(p_out);
        Logf(true, "dhcp_decline: BACKING OFF\n");
    } else {
        Logf(true,
            "dhcp_decline: could not allocate DHCP request\n");
        result = ERR_MEM;
    }
    if (dhcp->tries < 255) {
        dhcp->tries++;
    }
    uint16_t msecs = 10 * 1000;
    dhcp->request_timeout = (uint16_t)((msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS);
    Logf(true, "dhcp_decline(): set request timeout %d msecs\n", msecs);
    return result;
}



/**
 * Start the DHCP process, discover a DHCP server.
 *
 * @param netif the netif under DHCP control
 */
static LwipStatus
dhcp_discover(NetworkInterface * netif)
{
    DhcpContext* dhcp = get_netif_dhcp_ctx(netif);
    LwipStatus result = STATUS_SUCCESS;
    uint16_t options_out_len;

    Logf(true, "dhcp_discover()\n");

    ip4_addr_set_any(&dhcp->offered_ip_addr);
    dhcp_set_state(dhcp, DHCP_STATE_SELECTING);
    /* create and initialize the DHCP message header */
    struct PacketBuffer* p_out = dhcp_create_msg(netif, dhcp, DHCP_DISCOVER, &options_out_len);
    if (p_out != nullptr) {
        auto* msg_out = (DhcpMsg*)p_out->payload;
        Logf(true, "dhcp_discover: making request\n");

        options_out_len = dhcp_option(options_out_len, msg_out->options, DHCP_OPTION_MAX_MSG_SIZE, DHCP_OPTION_MAX_MSG_SIZE_LEN);
        options_out_len = dhcp_option_short(options_out_len, msg_out->options, DHCP_MAX_MSG_LEN(netif));

        options_out_len = dhcp_option(options_out_len, msg_out->options, DHCP_OPTION_PARAMETER_REQUEST_LIST, LWIP_ARRAYSIZE(dhcp_discover_request_options));
        for (uint8_t i = 0; i < LWIP_ARRAYSIZE(dhcp_discover_request_options); i++) {
            options_out_len = dhcp_option_byte(options_out_len, msg_out->options, dhcp_discover_request_options[i]);
        }
        LWIP_HOOK_DHCP_APPEND_OPTIONS(netif, dhcp, DHCP_STATE_SELECTING, msg_out, DHCP_DISCOVER, &options_out_len);
        dhcp_option_trailer(options_out_len, msg_out->options, p_out);

        Logf(true, "dhcp_discover: sendto(DISCOVER, IP_ADDR_BROADCAST, LWIP_IANA_PORT_DHCP_SERVER)\n");
        IpAddrInfo bcast_addr = create_ip_addr_ip4_bcast();
        IpAddrInfo any_addr = create_ip_addr_ip4_any();
        udp_sendto_if_src(dhcp_pcb, p_out, &bcast_addr, LWIP_IANA_PORT_DHCP_SERVER, netif, &any_addr);
        Logf(true, "dhcp_discover: deleting()ing\n");
        free_pkt_buf(p_out);
        Logf(true, "dhcp_discover: SELECTING\n");
    } else {
        Logf(true, "dhcp_discover: could not allocate DHCP request\n");
    }
    if (dhcp->tries < 255) {
        dhcp->tries++;
    }

    if (dhcp->tries >= LWIP_DHCP_AUTOIP_COOP_TRIES && dhcp->autoip_coop_state == DHCP_AUTOIP_COOP_STATE_OFF) {
        dhcp->autoip_coop_state = DHCP_AUTOIP_COOP_STATE_ON;
        autoip_start(netif);
    }
    auto msecs = (uint16_t)((dhcp->tries < 6 ? 1 << dhcp->tries : 60) * 1000);
    dhcp->request_timeout = (uint16_t)((msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS);
    Logf(true, "dhcp_discover(): set request timeout %d msecs\n", msecs);
    return result;
}


/**
 * Bind the interface to the offered IP address.
 *
 * @param netif network interface to bind to the offered address
 */
static void
dhcp_bind(NetworkInterface * netif)
{
    uint32_t timeout;
    Ip4Addr sn_mask, gw_addr;

    DhcpContext* dhcp = get_netif_dhcp_ctx(netif);

    Logf(true, "dhcp_bind(netif=%p) %c%c%d\n", (void*)netif, netif->name[0], netif->name[1], (uint16_t)netif->number);

    /* reset time used of lease */
    dhcp->lease_used = 0;

    if (dhcp->offered_t0_lease != 0xffffffffUL) {
        /* set renewal period timer */
        Logf(true, "dhcp_bind(): t0 renewal timer %d secs\n", dhcp->offered_t0_lease);
        timeout = (dhcp->offered_t0_lease + DHCP_COARSE_TIMER_SECS / 2) / DHCP_COARSE_TIMER_SECS;
        if (timeout > 0xffff) {
            timeout = 0xffff;
        }
        dhcp->t0_timeout = (uint16_t)timeout;
        if (dhcp->t0_timeout == 0) {
            dhcp->t0_timeout = 1;
        }
        Logf(true, "dhcp_bind(): set request timeout %d msecs\n", dhcp->offered_t0_lease * 1000);
    }

    /* temporary DHCP lease? */
    if (dhcp->offered_t1_renew != 0xffffffffUL) {
        /* set renewal period timer */
        Logf(true, "dhcp_bind(): t1 renewal timer %d secs\n", dhcp->offered_t1_renew);
        timeout = (dhcp->offered_t1_renew + DHCP_COARSE_TIMER_SECS / 2) / DHCP_COARSE_TIMER_SECS;
        if (timeout > 0xffff) {
            timeout = 0xffff;
        }
        dhcp->t1_timeout = (uint16_t)timeout;
        if (dhcp->t1_timeout == 0) {
            dhcp->t1_timeout = 1;
        }
        Logf(true, "dhcp_bind(): set request timeout %d msecs\n", dhcp->offered_t1_renew * 1000);
        dhcp->t1_renew_time = dhcp->t1_timeout;
    }
    /* set renewal period timer */
    if (dhcp->offered_t2_rebind != 0xffffffffUL) {
        Logf(true, "dhcp_bind(): t2 rebind timer %d secs\n", dhcp->offered_t2_rebind);
        timeout = (dhcp->offered_t2_rebind + DHCP_COARSE_TIMER_SECS / 2) / DHCP_COARSE_TIMER_SECS;
        if (timeout > 0xffff) {
            timeout = 0xffff;
        }
        dhcp->t2_timeout = (uint16_t)timeout;
        if (dhcp->t2_timeout == 0) {
            dhcp->t2_timeout = 1;
        }
        Logf(true, "dhcp_bind(): set request timeout %d msecs\n", dhcp->offered_t2_rebind * 1000);
        dhcp->t2_rebind_time = dhcp->t2_timeout;
    }

    /* If we have sub 1 minute lease, t2 and t1 will kick in at the same time. */
    if (dhcp->t1_timeout >= dhcp->t2_timeout && dhcp->t2_timeout > 0) {
        dhcp->t1_timeout = 0;
    }

    if (dhcp->subnet_mask_given) {
        /* copy offered network mask */
        copy_ip4_addr(&sn_mask, &dhcp->offered_sn_mask);
    } else {
        /* subnet mask not given, choose a safe subnet mask given the network class */
        uint8_t first_octet = ip4_addr1(&dhcp->offered_ip_addr);
        if (first_octet <= 127) {
            set_ip4_addr_u32(&sn_mask, pp_htonl(0xff000000UL));
        } else if (first_octet >= 192) {
            set_ip4_addr_u32(&sn_mask, pp_htonl(0xffffff00UL));
        } else {
            set_ip4_addr_u32(&sn_mask, pp_htonl(0xffff0000UL));
        }
    }

    copy_ip4_addr(&gw_addr, &dhcp->offered_gw_addr);
    /* gateway address not given? */
    if (ip4_addr_isany_val(gw_addr)) {
        /* copy network address */
        get_ip4_addr_net(&gw_addr, &dhcp->offered_ip_addr, &sn_mask);
        /* use first host address on network as gateway */
        set_ip4_addr_u32(&gw_addr, get_ip4_addr_u32(&gw_addr) | pp_htonl(0x00000001UL));
    }


    if (dhcp->autoip_coop_state == DHCP_AUTOIP_COOP_STATE_ON) {
        autoip_stop(netif);
        dhcp->autoip_coop_state = DHCP_AUTOIP_COOP_STATE_OFF;
    }


    Logf(true, "dhcp_bind(): IP: 0x%08x SN: 0x%08x GW: 0x%08x\n",
         get_ip4_addr_u32(&dhcp->offered_ip_addr), get_ip4_addr_u32(&sn_mask), get_ip4_addr_u32(&gw_addr));
    /* netif is now bound to DHCP leased address - set this before assigning the address
       to ensure the callback can use dhcp_supplied_address() */
    dhcp_set_state(dhcp, DHCP_STATE_BOUND);

    set_netif_addr(netif, &dhcp->offered_ip_addr, &sn_mask, &gw_addr);
    /* interface is used by routing now that an address is set */
}

/**
 * @ingroup dhcp4
 * Renew an existing DHCP lease at the involved DHCP server.
 *
 * @param netif network interface which must renew its lease
 */
LwipStatus
dhcp_renew(NetworkInterface * netif)
{
    DhcpContext* dhcp = get_netif_dhcp_ctx(netif);
    LwipStatus result;
    uint16_t options_out_len;


    Logf(true, "dhcp_renew()\n");
    dhcp_set_state(dhcp, DHCP_STATE_RENEWING);

    /* create and initialize the DHCP message header */
    struct PacketBuffer* p_out = dhcp_create_msg(netif, dhcp, DHCP_REQUEST, &options_out_len);
    if (p_out != nullptr) {
        auto* msg_out = (DhcpMsg*)p_out->payload;
        options_out_len = dhcp_option(options_out_len, msg_out->options, DHCP_OPTION_MAX_MSG_SIZE, DHCP_OPTION_MAX_MSG_SIZE_LEN);
        options_out_len = dhcp_option_short(options_out_len, msg_out->options, DHCP_MAX_MSG_LEN(netif));

        options_out_len = dhcp_option(options_out_len, msg_out->options, DHCP_OPTION_PARAMETER_REQUEST_LIST, LWIP_ARRAYSIZE(dhcp_discover_request_options));
        for (uint8_t i = 0; i < LWIP_ARRAYSIZE(dhcp_discover_request_options); i++) {
            options_out_len = dhcp_option_byte(options_out_len, msg_out->options, dhcp_discover_request_options[i]);
        }


        options_out_len = dhcp_option_hostname(options_out_len, msg_out->options, netif);


        LWIP_HOOK_DHCP_APPEND_OPTIONS(netif, dhcp, DHCP_STATE_RENEWING, msg_out, DHCP_REQUEST, &options_out_len);
        dhcp_option_trailer(options_out_len, msg_out->options, p_out);

        result = udp_sendto_if(dhcp_pcb, p_out, &dhcp->server_ip_addr, LWIP_IANA_PORT_DHCP_SERVER, netif);
        free_pkt_buf(p_out);

        Logf(true, "dhcp_renew: RENEWING\n");
    } else {
        Logf(true, "dhcp_renew: could not allocate DHCP request\n");
        result = ERR_MEM;
    }
    if (dhcp->tries < 255) {
        dhcp->tries++;
    }
    /* back-off on retries, but to a maximum of 20 seconds */
    auto msecs = (uint16_t)(dhcp->tries < 10 ? dhcp->tries * 2000 : 20 * 1000);
    dhcp->request_timeout = (uint16_t)((msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS);
    Logf(true, "dhcp_renew(): set request timeout %d msecs\n", msecs);
    return result;
}

/**
 * Rebind with a DHCP server for an existing DHCP lease.
 *
 * @param netif network interface which must rebind with a DHCP server
 */
static LwipStatus
dhcp_rebind(NetworkInterface * netif)
{
    DhcpContext* dhcp = get_netif_dhcp_ctx(netif);
    LwipStatus result;
    uint16_t options_out_len;

    Logf(true, "dhcp_rebind()\n");
    dhcp_set_state(dhcp, DHCP_STATE_REBINDING);

    /* create and initialize the DHCP message header */
    struct PacketBuffer* p_out = dhcp_create_msg(netif, dhcp, DHCP_REQUEST, &options_out_len);
    if (p_out != nullptr) {
        auto* msg_out = (DhcpMsg*)p_out->payload;
        options_out_len = dhcp_option(options_out_len, msg_out->options, DHCP_OPTION_MAX_MSG_SIZE, DHCP_OPTION_MAX_MSG_SIZE_LEN);
        options_out_len = dhcp_option_short(options_out_len, msg_out->options, DHCP_MAX_MSG_LEN(netif));

        options_out_len = dhcp_option(options_out_len, msg_out->options, DHCP_OPTION_PARAMETER_REQUEST_LIST, LWIP_ARRAYSIZE(dhcp_discover_request_options));
        for (uint8_t i = 0; i < LWIP_ARRAYSIZE(dhcp_discover_request_options); i++) {
            options_out_len = dhcp_option_byte(options_out_len, msg_out->options, dhcp_discover_request_options[i]);
        }


        options_out_len = dhcp_option_hostname(options_out_len, msg_out->options, netif);


        LWIP_HOOK_DHCP_APPEND_OPTIONS(netif, dhcp, DHCP_STATE_REBINDING, msg_out, DHCP_DISCOVER, &options_out_len);
        dhcp_option_trailer(options_out_len, msg_out->options, p_out);

        /* broadcast to server */
        IpAddrInfo bcast_addr = create_ip_addr_ip4_bcast();
        result = udp_sendto_if(dhcp_pcb, p_out, &bcast_addr, LWIP_IANA_PORT_DHCP_SERVER, netif);
        free_pkt_buf(p_out);
        Logf(true, "dhcp_rebind: REBINDING\n");
    } else {
        Logf(true, "dhcp_rebind: could not allocate DHCP request\n");
        result = ERR_MEM;
    }
    if (dhcp->tries < 255) {
        dhcp->tries++;
    }
    auto msecs = (uint16_t)(dhcp->tries < 10 ? dhcp->tries * 1000 : 10 * 1000);
    dhcp->request_timeout = (uint16_t)((msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS);
    Logf(true, "dhcp_rebind(): set request timeout %d msecs\n", msecs);
    return result;
}

/**
 * Enter REBOOTING state to verify an existing lease
 *
 * @param netif network interface which must reboot
 */
static LwipStatus
dhcp_reboot(NetworkInterface * netif)
{
    DhcpContext* dhcp = get_netif_dhcp_ctx(netif);
    LwipStatus result;
    uint16_t options_out_len;

    Logf(true, "dhcp_reboot()\n");
    dhcp_set_state(dhcp, DHCP_STATE_REBOOTING);

    /* create and initialize the DHCP message header */
    struct PacketBuffer* p_out = dhcp_create_msg(netif, dhcp, DHCP_REQUEST, &options_out_len);
    if (p_out != nullptr) {
        auto* msg_out = (DhcpMsg*)p_out->payload;
        options_out_len = dhcp_option(options_out_len, msg_out->options, DHCP_OPTION_MAX_MSG_SIZE, DHCP_OPTION_MAX_MSG_SIZE_LEN);
        options_out_len = dhcp_option_short(options_out_len, msg_out->options, kDhcpMaxMsgLenMinRequired);

        options_out_len = dhcp_option(options_out_len, msg_out->options, DHCP_OPTION_REQUESTED_IP, 4);
        options_out_len = dhcp_option_long(options_out_len, msg_out->options, lwip_ntohl(get_ip4_addr_u32(&dhcp->offered_ip_addr)));

        options_out_len = dhcp_option(options_out_len, msg_out->options, DHCP_OPTION_PARAMETER_REQUEST_LIST, LWIP_ARRAYSIZE(dhcp_discover_request_options));
        for (uint8_t i = 0; i < LWIP_ARRAYSIZE(dhcp_discover_request_options); i++) {
            options_out_len = dhcp_option_byte(options_out_len, msg_out->options, dhcp_discover_request_options[i]);
        }


        options_out_len = dhcp_option_hostname(options_out_len, msg_out->options, netif);


        LWIP_HOOK_DHCP_APPEND_OPTIONS(netif, dhcp, DHCP_STATE_REBOOTING, msg_out, DHCP_REQUEST, &options_out_len);
        dhcp_option_trailer(options_out_len, msg_out->options, p_out);

        /* broadcast to server */
        IpAddrInfo bcast_addr = create_ip_addr_ip4_bcast();
        result = udp_sendto_if(dhcp_pcb, p_out, &bcast_addr, LWIP_IANA_PORT_DHCP_SERVER, netif);
        free_pkt_buf(p_out);
        Logf(true, "dhcp_reboot: REBOOTING\n");
    } else {
        Logf(true, "dhcp_reboot: could not allocate DHCP request\n");
        result = ERR_MEM;
    }
    if (dhcp->tries < 255) {
        dhcp->tries++;
    }
    uint16_t msecs = (uint16_t)(dhcp->tries < 10 ? dhcp->tries * 1000 : 10 * 1000);
    dhcp->request_timeout = (uint16_t)((msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS);
    Logf(true, "dhcp_reboot(): set request timeout %d msecs\n", msecs);
    return result;
}

/**
 * @ingroup dhcp4
 * Release a DHCP lease and stop DHCP statemachine (and AUTOIP if LWIP_DHCP_AUTOIP_COOP).
 *
 * @param netif network interface
 */
void
dhcp_release_and_stop(NetworkInterface * netif)
{
    DhcpContext* dhcp = get_netif_dhcp_ctx(netif);
    IpAddrInfo server_ip_addr;


    Logf(true, "dhcp_release_and_stop()\n");
    if (dhcp == nullptr) {
        return;
    }

    /* already off? -> nothing to do */
    if (dhcp->state == DHCP_STATE_OFF) {
        return;
    }

    copy_ip_addr(&server_ip_addr, &dhcp->server_ip_addr);

    /* clean old DHCP offer */
    zero_ip_addr(&dhcp->server_ip_addr);
    zero_ip4_addr(&dhcp->offered_ip_addr);
    zero_ip4_addr(&dhcp->offered_sn_mask);
    zero_ip4_addr(&dhcp->offered_gw_addr);

    zero_ip4_addr(&dhcp->offered_si_addr);

    dhcp->offered_t0_lease = dhcp->offered_t1_renew = dhcp->offered_t2_rebind = 0;
    dhcp->t1_renew_time = dhcp->t2_rebind_time = dhcp->lease_used = dhcp->t0_timeout = 0;

    /* send release message when current IP was assigned via DHCP */
    if (dhcp_supplied_address(netif)) {
        uint16_t options_out_len;
        struct PacketBuffer* p_out = dhcp_create_msg(netif, dhcp, DHCP_RELEASE, &options_out_len);
        if (p_out != nullptr) {
            auto* msg_out = (DhcpMsg*)p_out->payload;
            options_out_len = dhcp_option(options_out_len, msg_out->options, DHCP_OPTION_SERVER_ID, 4);
            options_out_len = dhcp_option_long(options_out_len, msg_out->options, lwip_ntohl(get_ip4_addr_u32(&server_ip_addr.u_addr.ip4)));

            LWIP_HOOK_DHCP_APPEND_OPTIONS(netif, dhcp, dhcp->state, msg_out, DHCP_RELEASE, &options_out_len);
            dhcp_option_trailer(options_out_len, msg_out->options, p_out);

            udp_sendto_if(dhcp_pcb, p_out, &server_ip_addr, LWIP_IANA_PORT_DHCP_SERVER, netif);
            free_pkt_buf(p_out);
            Logf(true, "dhcp_release: RELEASED, DHCP_STATE_OFF\n");
        } else {
            /* sending release failed, but that's not a problem since the correct behaviour of dhcp does not rely on release */
            Logf(true, "dhcp_release: could not allocate DHCP request\n");
        }
    }

    /* remove IP address from interface (prevents routing from selecting this interface) */
    Ip4Addr any_addr = make_ip4_addr_any();
    set_netif_addr(netif, &any_addr, &any_addr, &any_addr);

    if (dhcp->autoip_coop_state == DHCP_AUTOIP_COOP_STATE_ON) {
        autoip_stop(netif);
        dhcp->autoip_coop_state = DHCP_AUTOIP_COOP_STATE_OFF;
    }


    dhcp_set_state(dhcp, DHCP_STATE_OFF);

    if (dhcp->pcb_allocated != 0) {
        dhcp_dec_pcb_refcount(); /* free DHCP PCB if not needed any more */
        dhcp->pcb_allocated = 0;
    }
}

/**
 * @ingroup dhcp4
 * This function calls dhcp_release_and_stop() internally.
 * @deprecated Use dhcp_release_and_stop() instead.
 */
LwipStatus
dhcp_release(NetworkInterface * netif)
{
    dhcp_release_and_stop(netif);
    return STATUS_SUCCESS;
}

/**
 * @ingroup dhcp4
 * This function calls dhcp_release_and_stop() internally.
 * @deprecated Use dhcp_release_and_stop() instead.
 */
void
dhcp_stop(NetworkInterface * netif)
{
    dhcp_release_and_stop(netif);
}

/*
 * Set the DHCP state of a DHCP client.
 *
 * If the state changed, reset the number of tries.
 */
static void
dhcp_set_state(DhcpContext * dhcp, uint8_t new_state)
{
    if (new_state != dhcp->state) {
        dhcp->state = new_state;
        dhcp->tries = 0;
        dhcp->request_timeout = 0;
    }
}

/*
 * Concatenate an option type and length field to the outgoing
 * DHCP message.
 *
 */
static uint16_t
dhcp_option(uint16_t options_out_len, uint8_t * options, uint8_t option_type, uint8_t option_len)
{
    lwip_assert("dhcp_option: options_out_len + 2 + option_len <= DHCP_OPTIONS_LEN", options_out_len + 2U + option_len <= DHCP_OPTIONS_LEN);
    options[options_out_len++] = option_type;
    options[options_out_len++] = option_len;
    return options_out_len;
}
/*
 * Concatenate a single byte to the outgoing DHCP message.
 *
 */
static uint16_t
dhcp_option_byte(uint16_t options_out_len, uint8_t * options, uint8_t value)
{
    lwip_assert("dhcp_option_byte: options_out_len < DHCP_OPTIONS_LEN", options_out_len < DHCP_OPTIONS_LEN);
    options[options_out_len++] = value;
    return options_out_len;
}

static uint16_t
dhcp_option_short(uint16_t options_out_len, uint8_t * options, uint16_t value)
{
    lwip_assert("dhcp_option_short: options_out_len + 2 <= DHCP_OPTIONS_LEN", options_out_len + 2U <= DHCP_OPTIONS_LEN);
    options[options_out_len++] = (uint8_t)((value & 0xff00U) >> 8);
    options[options_out_len++] = (uint8_t)(value & 0x00ffU);
    return options_out_len;
}

static uint16_t
dhcp_option_long(uint16_t options_out_len, uint8_t * options, uint32_t value)
{
    lwip_assert("dhcp_option_long: options_out_len + 4 <= DHCP_OPTIONS_LEN", options_out_len + 4U <= DHCP_OPTIONS_LEN);
    options[options_out_len++] = (uint8_t)((value & 0xff000000UL) >> 24);
    options[options_out_len++] = (uint8_t)((value & 0x00ff0000UL) >> 16);
    options[options_out_len++] = (uint8_t)((value & 0x0000ff00UL) >> 8);
    options[options_out_len++] = (uint8_t)(value & 0x000000ffUL);
    return options_out_len;
}

static uint16_t
dhcp_option_hostname(uint16_t options_out_len, uint8_t * options, NetworkInterface * netif)
{
    if (netif->hostname != nullptr) {
        size_t namelen = strlen(netif->hostname);
        if (namelen > 0) {
            const char* p = netif->hostname;
            /* Shrink len to available bytes (need 2 bytes for OPTION_HOSTNAME
               and 1 byte for trailer) */
            size_t available = DHCP_OPTIONS_LEN - options_out_len - 3;
            lwip_assert("DHCP: hostname is too long!", namelen <= available);
            size_t len = std::min(namelen, available);
            lwip_assert("DHCP: hostname is too long!", len <= 0xFF);
            options_out_len = dhcp_option(options_out_len, options, DHCP_OPTION_HOSTNAME, (uint8_t)len);
            while (len--) {
                options_out_len = dhcp_option_byte(options_out_len, options, *p++);
            }
        }
    }
    return options_out_len;
}


/**
 * Extract the DHCP message and the DHCP options.
 *
 * Extract the DHCP message and the DHCP options, each into a contiguous
 * piece of memory. As a DHCP message is variable sized by its options,
 * and also allows overriding some fields for options, the easy approach
 * is to first unfold the options into a contiguous piece of memory, and
 * use that further on.
 *
 */
static LwipStatus
dhcp_parse_reply(struct PacketBuffer* p, DhcpContext * dhcp)
{
    auto parse_file_as_options = 0;
    auto parse_sname_as_options = 0;
    auto file_overloaded = 0;

    /* clear received options */
    dhcp_clear_all_options(dhcp->dhcp_options, 0xff);
    /* check that beginning of dhcp_msg (up to and including chaddr) is in first PacketBuffer */
    if (p->len < DHCP_SNAME_OFS) {
        return ERR_BUF;
    }
    auto msg_in = reinterpret_cast<DhcpMsg*>(p->payload);

    /* clear boot file name */
    dhcp->boot_file_name[0] = 0;

    /* parse options */

    /* start with options field */
    uint16_t options_idx = DHCP_OPTIONS_OFS;
    /* parse options to the end of the received packet */
    auto options_idx_max = p->tot_len;
again:
    auto q = p;
    while (q != nullptr && options_idx >= q->len) {
        options_idx = uint16_t(options_idx - q->len);
        options_idx_max = uint16_t(options_idx_max - q->len);
        q = q->next;
    }
    if (q == nullptr) {
        return ERR_BUF;
    }
    auto offset = options_idx;
    auto offset_max = options_idx_max;
    auto options = static_cast<uint8_t*>(q->payload);
    /* at least 1 byte to read and no end marker, then at least 3 bytes to read? */
    while (q != nullptr && offset < offset_max && options[offset] != DHCP_OPTION_END) {
        const auto op = options[offset];
        size_t len;
        size_t decode_len = 0;
        auto decode_idx = -1;
        auto val_offset = uint16_t(offset + 2);
        if (val_offset < offset) {
            /* overflow */
            return ERR_BUF;
        }
        /* len byte might be in the next PacketBuffer */
        if (offset + 1 < q->len) {
            len = options[offset + 1];
        } else {
            len = q->next != nullptr ? ((uint8_t*)q->next->payload)[0] : 0;
        }
        /* Logf(true, ("msg_offset=%d, q->len=%"U16_F, msg_offset, q->len)); */
        decode_len = len;
        size_t other_len = 0;
        switch (op) {
            /* case(DHCP_OPTION_END): handled above */
            case DHCP_OPTION_PAD:
                /* special option: no len encoded */
                decode_len = len = 0;
                /* will be increased below */
                break;
            case DHCP_OPTION_SUBNET_MASK:

                decode_idx = DHCP_OPTION_IDX_SUBNET_MASK;
                break;
            case DHCP_OPTION_ROUTER:
                decode_len = 4; /* only copy the first given router */

                decode_idx = DHCP_OPTION_IDX_ROUTER;
                break;

            case DHCP_OPTION_DNS_SERVER:
                /* special case: there might be more than one server */

                /* limit number of DNS servers */
                other_len = 4 * DNS_MAX_SERVERS;
                decode_len = std::min(len, other_len);

                decode_idx = DHCP_OPTION_IDX_DNS_SERVER;
                break;

            case DHCP_OPTION_LEASE_TIME:

                decode_idx = DHCP_OPTION_IDX_LEASE_TIME;
                break;

            case DHCP_OPTION_NTP:
                /* special case: there might be more than one server */

                /* limit number of NTP servers */
                other_len = 4 * LWIP_DHCP_MAX_NTP_SERVERS;
                decode_len = std::min(len, other_len);

                decode_idx = DHCP_OPTION_IDX_NTP_SERVER;
                break;

            case DHCP_OPTION_OVERLOAD:

                /* decode overload only in options, not in file/sname: invalid packet */

                decode_idx = DHCP_OPTION_IDX_OVERLOAD;
                break;
            case DHCP_OPTION_MESSAGE_TYPE:

                decode_idx = DHCP_OPTION_IDX_MSG_TYPE;
                break;
            case DHCP_OPTION_SERVER_ID:

                decode_idx = DHCP_OPTION_IDX_SERVER_ID;
                break;
            case DHCP_OPTION_T1:

                decode_idx = DHCP_OPTION_IDX_T1;
                break;
            case DHCP_OPTION_T2:

                decode_idx = DHCP_OPTION_IDX_T2;
                break;
            default:
                decode_len = 0;
                Logf(true, "skipping option %d in options\n", op);
                // LWIP_HOOK_DHCP_PARSE_OPTION(ip_current_netif(), dhcp, dhcp->state, msg_in,
                //                             dhcp_option_given(dhcp, DHCP_OPTION_IDX_MSG_TYPE) ? (uint8_t)dhcp_get_option_value(dhcp, DHCP_OPTION_IDX_MSG_TYPE) : 0,
                //                             op, len, q, val_offset);
                break;
        }
        if (op == DHCP_OPTION_PAD) {
            offset++;
        } else {
            if (offset + len + 2 > 0xFFFF) {
                /* overflow */
                return ERR_BUF;
            }
            offset = uint16_t(offset + len + 2);
            if (decode_len > 0) {
                uint32_t value = 0;
            decode_next:
                lwip_assert("check decode_idx", decode_idx >= 0 && decode_idx < DHCP_OPTION_IDX_MAX);
                if (!dhcp_option_given(dhcp->dhcp_options, decode_idx)) {
                    const uint16_t copy_len = (std::min)(decode_len, (size_t)4);
                    if (pbuf_copy_partial(q, reinterpret_cast<uint8_t*>(&value), copy_len, val_offset) != copy_len) {
                        return ERR_BUF;
                    }
                    if (decode_len > 4) {
                        dhcp_got_option(dhcp->dhcp_options, decode_idx);
                        dhcp_set_option_value(dhcp->dhcp_options, decode_idx, lwip_htonl(value));
                        decode_len = uint8_t(decode_len - 4);
                        const auto next_val_offset = uint16_t(val_offset + 4);
                        if (next_val_offset < val_offset) {
                            /* overflow */
                            return ERR_BUF;
                        }
                        val_offset = next_val_offset;
                        decode_idx++;
                        goto decode_next;
                    } else if (decode_len == 4) {
                        value = lwip_ntohl(value);
                    } else {

                        value = reinterpret_cast<uint8_t*>(& value)[0];
                    }
                    dhcp_got_option(dhcp->dhcp_options, decode_idx);
                    dhcp_set_option_value(dhcp->dhcp_options, decode_idx, value);
                }
            }
        }
        if (offset >= q->len) {
            offset = uint16_t(offset - q->len);
            offset_max = uint16_t(offset_max - q->len);
            if (offset < offset_max) {
                q = q->next;

                options = static_cast<uint8_t*>(q->payload);
            } else {
                /* We've run out of bytes, probably no end marker. Don't proceed. */
                return ERR_BUF;
            }
        }
    }
    /* is this an overloaded message? */
    if (dhcp_option_given(dhcp->dhcp_options, DHCP_OPTION_IDX_OVERLOAD)) {
        uint32_t overload = dhcp_get_option_value(dhcp->dhcp_options, DHCP_OPTION_IDX_OVERLOAD);
        dhcp_clear_option(dhcp->dhcp_options, DHCP_OPTION_IDX_OVERLOAD);
        if (overload == DHCP_OVERLOAD_FILE) {
            parse_file_as_options = 1;
            Logf(true, "overloaded file field\n");
        } else if (overload == DHCP_OVERLOAD_SNAME) {
            parse_sname_as_options = 1;
            Logf(true, "overloaded sname field\n");
        } else if (overload == DHCP_OVERLOAD_SNAME_FILE) {
            parse_sname_as_options = 1;
            parse_file_as_options = 1;
            Logf(true, "overloaded sname and file field\n");
        } else {
            Logf(true, "invalid overload option: %d\n", overload);
        }
    }
    if (parse_file_as_options) {
        /* if both are overloaded, parse file first and then sname (RFC 2131 ch. 4.1) */
        parse_file_as_options = 0;
        options_idx = DHCP_FILE_OFS;
        options_idx_max = DHCP_FILE_OFS + DHCP_FILE_LEN;

        file_overloaded = 1;

        goto again;
    } else if (parse_sname_as_options) {
        parse_sname_as_options = 0;
        options_idx = DHCP_SNAME_OFS;
        options_idx_max = DHCP_SNAME_OFS + DHCP_SNAME_LEN;
        goto again;
    }

    if (!file_overloaded) {
        /* only do this for ACK messages */
        if (dhcp_option_given(dhcp->dhcp_options, DHCP_OPTION_IDX_MSG_TYPE) &&
            dhcp_get_option_value(dhcp->dhcp_options, DHCP_OPTION_IDX_MSG_TYPE) == DHCP_ACK)
        {
            {
            /* copy bootp file name, don't care for sname (server hostname) */
            if (pbuf_copy_partial(p, reinterpret_cast<uint8_t*>(dhcp->boot_file_name), DHCP_FILE_LEN - 1, DHCP_FILE_OFS) != DHCP_FILE_LEN - 1) {
                return ERR_BUF;
            }
            }
        } /* make sure the string is really NULL-terminated */
        dhcp->boot_file_name[DHCP_FILE_LEN - 1] = 0;
    }

    return STATUS_SUCCESS;
}

/**
 * If an incoming DHCP message is in response to us, then trigger the state machine
 */
static void
dhcp_recv(void* arg, UdpPcb& pcb, PacketBuffer& p, const IpAddrInfo& addr, uint16_t port, NetworkInterface
          & netif)
{
    // todo: replace ip_current_input_netif();
    // NetworkInterface* netif;
    // NetworkInterface* netif = ip_current_input_netif();
    auto dhcp = get_netif_dhcp_ctx(netif);
    auto reply_msg = reinterpret_cast<DhcpMsg*>(p->payload);

    /* Caught DHCP message from netif that does not have DHCP enabled? -> not interested */
    if (dhcp == nullptr || dhcp->pcb_allocated == 0) {
        goto free_pbuf_and_return;
    }

    lwip_assert("invalid server address type", is_ip_addr_v4(addr));

    Logf(true, "PacketBuffer->len = %d\n", p->len);
    Logf(true, "PacketBuffer->tot_len = %d\n", p->tot_len);
    /* prevent warnings about unused arguments */

    if (p->len < kDhcpMinReplyLen) {
        Logf(true, "DHCP reply message or PacketBuffer too short\n");
        goto free_pbuf_and_return;
    }

    if (reply_msg->op != DHCP_BOOTREPLY) {
        Logf(true, "not a DHCP reply message, but type %d\n", reply_msg->op);
        goto free_pbuf_and_return;
    }
    /* iterate through hardware address and match against DHCP message */
    for (uint8_t i = 0; i < netif->hwaddr_len && i < std::min(DHCP_CHADDR_LEN, NETIF_MAX_HWADDR_LEN); i++) {
        if (netif->hwaddr[i] != reply_msg->chaddr[i]) {
            Logf(true,
                "netif->hwaddr[%d]==%02x != reply_msg->chaddr[%d]==%02x\n",
                 i, netif->hwaddr[i], i, reply_msg->chaddr[i]);
            goto free_pbuf_and_return;
        }
    }
    /* match transaction ID against what we expected */
    if (lwip_ntohl(reply_msg->xid) != dhcp->xid) {
        Logf(true,
            "transaction id mismatch reply_msg->xid(%x)!=dhcp->xid(%x)\n", lwip_ntohl(reply_msg->xid), dhcp->xid);
        goto free_pbuf_and_return;
    }
    /* option fields could be unfold? */
    if (dhcp_parse_reply(p, dhcp) != STATUS_SUCCESS) {
        Logf(true,
            "problem unfolding DHCP message - too short on memory?\n");
        goto free_pbuf_and_return;
    }

    Logf(true, "searching DHCP_OPTION_MESSAGE_TYPE\n");
    /* obtain pointer to DHCP message type */
    if (!dhcp_option_given(dhcp->dhcp_options, DHCP_OPTION_IDX_MSG_TYPE)) {
        Logf(true, "DHCP_OPTION_MESSAGE_TYPE option not found\n");
        goto free_pbuf_and_return;
    }

    auto* msg_in = (DhcpMsg*)p->payload;
    /* read DHCP message type */
    uint8_t msg_type = (uint8_t)dhcp_get_option_value(dhcp->dhcp_options, DHCP_OPTION_IDX_MSG_TYPE);
    /* message type is DHCP ACK? */
    if (msg_type == DHCP_ACK) {
        Logf(true, "DHCP_ACK received\n");
        /* in requesting state? */
        if (dhcp->state == DHCP_STATE_REQUESTING) {
            dhcp_handle_ack(netif, msg_in);

            if ((netif->flags & NETIF_FLAG_ETH_ARP) != 0) {
                /* check if the acknowledged lease address is already in use */
                dhcp_check(netif);
            } else {
                /* bind interface to the acknowledged lease address */
                dhcp_bind(netif);
            }

        }
        /* already bound to the given lease address? */
        else if (dhcp->state == DHCP_STATE_REBOOTING || dhcp->state == DHCP_STATE_REBINDING ||
            dhcp->state == DHCP_STATE_RENEWING) {
            dhcp_handle_ack(netif, msg_in);
            dhcp_bind(netif);
        }
    }
    /* received a DHCP_NAK in appropriate state? */
    else if (msg_type == DHCP_NAK &&
        (dhcp->state == DHCP_STATE_REBOOTING || dhcp->state == DHCP_STATE_REQUESTING ||
             dhcp->state == DHCP_STATE_REBINDING || dhcp->state == DHCP_STATE_RENEWING)) {
        Logf(true, "DHCP_NAK received\n");
        dhcp_handle_nak(netif);
    }
    /* received a DHCP_OFFER in DHCP_STATE_SELECTING state? */
    else if (msg_type == DHCP_OFFER && dhcp->state == DHCP_STATE_SELECTING) {
        Logf(true, "DHCP_OFFER received in DHCP_STATE_SELECTING state\n");
        /* remember offered lease */
        dhcp_handle_offer(netif, msg_in,dhcp);
    }

free_pbuf_and_return:
    free_pkt_buf(p);
}

/**
 * Create a DHCP request, fill in common headers
 *
 * @param netif the netif under DHCP control
 * @param dhcp dhcp control struct
 * @param message_type message type of the request
 */
static struct PacketBuffer*
dhcp_create_msg(NetworkInterface * netif, DhcpContext * dhcp, uint8_t message_type, uint16_t * options_out_len)
{
    /** default global transaction identifier starting value (easy to match
     *  with a packet analyser). We simply increment for each new request.
     *  Predefine DHCP_GLOBAL_XID to a better value or a function call to generate one
     *  at runtime, any supporting function prototypes can be defined in DHCP_GLOBAL_XID_HEADER */

    static uint32_t xid;

    // struct PacketBuffer* p_out = pbuf_alloc();
    PacketBuffer pbuf{};
    if (p_out == nullptr) {
        Logf(true,
            "dhcp_create_msg(): could not allocate PacketBuffer\n");
        return nullptr;
    }
    lwip_assert("dhcp_create_msg: check that first PacketBuffer can hold DhcpMsg",
        p_out->len >= sizeof(DhcpMsg));

    /* DHCP_REQUEST should reuse 'xid' from DHCPOFFER */
    if ((message_type != DHCP_REQUEST) || dhcp->state == DHCP_STATE_REBOOTING) {
        /* reuse transaction identifier in retransmissions */
        if (dhcp->tries == 0) {

            xid = lwip_rand();

        }
        dhcp->xid = xid;
    }
    Logf(true,
         "transaction id xid(%x)\n", xid);

    auto* msg_out = reinterpret_cast<DhcpMsg*>(p_out->payload);
    memset(msg_out, 0, sizeof(DhcpMsg));

    msg_out->op = DHCP_BOOTREQUEST;
    /* @todo: make link layer independent */
    msg_out->htype = LWIP_IANA_HWTYPE_ETHERNET;
    msg_out->hlen = netif->hwaddr_len;
    msg_out->xid = lwip_htonl(dhcp->xid);
    /* we don't need the broadcast flag since we can receive unicast traffic
       before being fully configured! */
       /* set ciaddr to netif->ip_addr based on message_type and state */
    if ((message_type == DHCP_INFORM) || (message_type == DHCP_DECLINE) || (message_type == DHCP_RELEASE) ||
        ((message_type == DHCP_REQUEST) && /* DHCP_STATE_BOUND not used for sending! */
        (dhcp->state == DHCP_STATE_RENEWING || dhcp->state == DHCP_STATE_REBINDING))) {
        // *netif_ip4_addr(netif)
        Ip4Addr netif_ip4_addr{};
        copy_ip4_addr(&msg_out->ciaddr, &netif_ip4_addr);
    }
    for (uint16_t i = 0; i < std::min(DHCP_CHADDR_LEN, NETIF_MAX_HWADDR_LEN); i++) {
        /* copy netif hardware address (padded with zeroes through memset already) */
        msg_out->chaddr[i] = netif->hwaddr[i];
    }
    msg_out->cookie = pp_htonl(DHCP_MAGIC_COOKIE);
    /* Add option MESSAGE_TYPE */
    auto options_out_len_loc = dhcp_option(0, msg_out->options, DHCP_OPTION_MESSAGE_TYPE, DHCP_OPTION_MESSAGE_TYPE_LEN);
    options_out_len_loc = dhcp_option_byte(options_out_len_loc, msg_out->options, message_type);
    if (options_out_len) {
        *options_out_len = options_out_len_loc;
    }
    return p_out;
}

/**
 * Add a DHCP message trailer
 *
 * Adds the END option to the DHCP message, and if
 * necessary, up to three padding bytes.
 */
static void
dhcp_option_trailer(uint16_t options_out_len, uint8_t * options, struct PacketBuffer* p_out)
{
    options[options_out_len++] = DHCP_OPTION_END;
    /* packet is too small, or not 4 byte aligned? */
    while (((options_out_len < DHCP_MIN_OPTIONS_LEN) || (options_out_len & 3)) &&
        (options_out_len < DHCP_OPTIONS_LEN)) {
        /* add a fill/padding byte */
        options[options_out_len++] = 0;
    }
    /* shrink the PacketBuffer to the actual content length */
    pbuf_realloc(p_out);
}

/** check if DHCP supplied netif->ip_addr
 *
 * @param netif the netif to check
 * @return 1 if DHCP supplied netif->ip_addr (states BOUND or RENEWING),
 *         0 otherwise
 */
uint8_t
dhcp_supplied_address(const NetworkInterface * netif)
{
    if (netif != nullptr && get_netif_dhcp_ctx(netif) != nullptr) {
        DhcpContext* dhcp = get_netif_dhcp_ctx(netif);
        return dhcp->state == DHCP_STATE_BOUND || dhcp->state == DHCP_STATE_RENEWING ||
            dhcp->state == DHCP_STATE_REBINDING;
    }
    return 0;
}
