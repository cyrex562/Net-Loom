///
/// file: dhcp6.h
///
#pragma once
#include "netloom_status.h"
#include "network_interface.h"
#include "dhcp6_def.h"
#include <cstdint>


void
dhcp6_set_struct(NetworkInterface& netif, Dhcp6Context& ctx);

/**
 *
 */
inline Dhcp6Context
get_netif_dhcp6_ctx(NetworkInterface& netif) { return netif.dhcp6_ctx; }


/**
 *
 */
inline bool
dhcp6_option_given(Dhcp6Context& dhcp6, const size_t idx)
{
    return dhcp6.dhcp6_rx_options[idx].option_given != 0;
}


/**
 *
 */
inline bool
dhcp6_got_option(Dhcp6Context& dhcp6, const size_t idx)
{
    return (dhcp6.dhcp6_rx_options[idx].option_given = 1);
}


/**
 *
 */
inline bool
dhcp6_clear_option(Dhcp6Context& dhcp6, const size_t idx)
{
    return (dhcp6.dhcp6_rx_options[idx].option_given = 0);
}


/**
 *
 */
inline size_t
dhcp6_get_option_start(Dhcp6Context& dhcp6, size_t idx)
{
    return (dhcp6.dhcp6_rx_options[idx].val_start);
}


/**
 *
 */
inline size_t
dhcp6_get_option_length(Dhcp6Context& dhcp6, size_t idx)
{
    return (dhcp6.dhcp6_rx_options[idx].val_length);
}


/**
 *
 */
inline void
dhcp6_set_option(Dhcp6Context& dhcp,
                 const size_t idx,
                 const size_t start,
                 const size_t len)
{
    dhcp.dhcp6_rx_options[idx].val_start = (start);
    dhcp.dhcp6_rx_options[idx].val_length = (len);
}


void
dhcp6_cleanup(NetworkInterface& netif, Dhcp6Context& ctx);


bool
dhcp6_enable_stateful(NetworkInterface& netif);


bool
dhcp6_enable_stateless(NetworkInterface& netif, Dhcp6Context& ctx);


void
dhcp6_disable(NetworkInterface& netif, Dhcp6Context& ctx);


void
dhcp6_tmr();


void
dhcp6_nd6_ra_trigger(NetworkInterface* netif,
                     uint8_t managed_addr_config,
                     uint8_t other_config);

/** This function must exist, in other to add offered NTP servers to
 * the NTP (or SNTP) engine.
 * See LWIP_DHCP6_MAX_NTP_SERVERS */
void
dhcp6_set_ntp_servers(uint8_t num_ntp_servers, const IpAddrInfo* ntp_server_addrs);


/* receive, unfold, parse and free incoming messages */
std::tuple<bool, Dhcp6ClientServerMessage>
dhcp6_recv(Dhcp6Context& ctx, IpAddrInfo& addr, uint16_t port, NetworkInterface& netif);


bool
dhcp6_inc_pcb_refcount(Dhcp6Context& ctx, size_t& ref_cnt, NetworkInterface& netif);


void
dhcp6_dec_pcb_refcount(Dhcp6Context& ctx);


void
dhcp6_set_state(Dhcp6Context& ctx, uint8_t new_state);


bool
dhcp6_stateless_enabled(Dhcp6Context& ctx);


Dhcp6ClientServerMessage
dhcp6_create_msg(Dhcp6Context& dhcp6, Dhcp6MessageType message_type);


size_t
dhcp6_option_short(size_t& options_out_len,
                   std::vector<uint8_t>& options,
                   uint16_t value);


size_t
dhcp6_option_optionrequest(size_t options_out_len,
                           std::vector<uint8_t>& options,
                           std::vector<uint16_t>& req_options,
                           size_t num_req_options);


bool
dhcp6_msg_finalize(size_t options_out_len, PacketContainer& p_out);


void
dhcp6_information_request(NetworkInterface& netif, Dhcp6Context& ctx);


NsStatus
dhcp6_request_config(NetworkInterface* netif, Dhcp6Context* dhcp6);


void
dhcp6_abort_config_request(Dhcp6Context* dhcp6);


void
dhcp6_handle_config_reply(NetworkInterface* netif, struct PacketContainer* p_msg_in);


NsStatus
dhcp6_parse_reply(struct PacketContainer* p, struct Dhcp6Context* dhcp6);


void
dhcp6_recv(void* arg,
           struct UdpPcb* pcb,
           struct PacketContainer* p,
           const IpAddrInfo* addr,
           uint16_t port,
           NetworkInterface* netif);


void
dhcp6_timeout(NetworkInterface* netif, struct Dhcp6Context* dhcp6);


void
dhcp6_tmr();


bool
dhcp6_bind(Dhcp6Context& ctx, IpAddrInfo& addr, uint16_t port);


//
// END OF FILE
//
