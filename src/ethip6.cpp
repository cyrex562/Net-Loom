/**
 * @file
 *
 * Ethernet output for IPv6. Uses ND tables for link-layer addressing.
 */

/*
 * Copyright (c) 2010 Inico Technologies Ltd.
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
 * Author: Ivan Delamer <delamer@inicotech.com>
 *
 *
 * Please coordinate changes and requests with Ivan Delamer
 * <delamer@inicotech.com>
 */

#include <ethip6.h>
#include <ethernet.h>
#include <ieee.h>
#include <ip6_addr.h>
#include <nd6.h>
#include <network_interface.h>
#include <packet_buffer.h>
#include <mac_address.h>

#include <cstring>


///
/// Resolve and fill-in Ethernet address header for outgoing IPv6 packet.
///
/// For IPv6 multicast, corresponding Ethernet addresses
/// are selected and the packet is transmitted on the link.
///
/// For unicast addresses, ask the ND6 module what to do. It will either let us
/// send the the packet right away, or queue the packet for later itself, unless
/// an error occurs.
///
/// @todo anycast addresses
///
/// @param net_ifc The lwIP network interface which the IP packet will be sent on.
/// @param pkt_buf The PacketBuffer(s) containing the IP packet to be sent.
/// @param ip6_addr The IP address of the packet destination.
///
/// @return
/// - ERR_OK or the return value of @ref nd6_get_next_hop_addr_or_queue.
///
LwipStatus ethip6_output(NetworkInterface& net_ifc, PacketBuffer& pkt_buf, const Ip6Addr& ip6_addr)
{
    MacAddress dest{};
    const uint8_t* hwaddr;
    // The destination IP address must be properly zoned from here on down.
    // multicast destination IP address?
    if (is_ip6_addr_mcast(ip6_addr))
    {
        // Hash IP multicast address to MAC address
        dest.bytes[0] = 0x33;
        dest.bytes[1] = 0x33;
        dest.bytes[2] = reinterpret_cast<const uint8_t *>(ip6_addr.word[3])[0];
        dest.bytes[3] = reinterpret_cast<const uint8_t *>(ip6_addr.word[3])[1];
        dest.bytes[4] = reinterpret_cast<const uint8_t *>(ip6_addr.word[3])[2];
        dest.bytes[5] = reinterpret_cast<const uint8_t *>(ip6_addr.word[3])[3];


        const auto i = 0;

        return send_ethernet_pkt(net_ifc,
                               pkt_buf,
                               net_ifc.mac_address,
                               dest,
                               ETHTYPE_IPV6);
    } 
    // We have a unicast destination IP address */ /* @todo anycast? */
    /* Ask ND6 what to do with the packet. */
    const auto result = nd6_get_next_hop_addr_or_queue(net_ifc, pkt_buf, ip6_addr, &hwaddr);
    if (result != STATUS_SUCCESS)
    {
        return result;
    } /* If no hardware address is returned, nd6 has queued the packet for later. */
    if (hwaddr == nullptr)
    {
        return STATUS_SUCCESS;
    } /* Send out the packet using the returned hardware address. */
    memcpy(dest.bytes, hwaddr, 6);
    return send_ethernet_pkt(net_ifc,
                           pkt_buf,
                           reinterpret_cast<const struct MacAddress*>(net_ifc->hwaddr),
                           &dest,
                           ETHTYPE_IPV6);
}

//
// END OF FILE
//
