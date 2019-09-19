/**
 * @file tcp_udp.h
 * routines common between tcp and udp protocols, such as port management.
 */
#pragma once
#include <tuple>
#include <cstdint>
#include <vector>
#include "ns_config.h"



struct NetworkPort
{
    uint16_t port;
    // todo: refcount
    // todo: c, m, a, times
};


/**
 *
 */
inline bool
port_in_list(std::vector<NetworkPort>& ports, const uint16_t port)
{
    for (auto& p : ports) { if (port == p.port) { return true; } }
    return false;
}


/**
 *
 */
inline uint16_t
ensure_local_port_range(const uint16_t port)
{
    return uint16_t(
        (port & uint16_t(~LOCAL_PORT_RANGE_START)) + LOCAL_PORT_RANGE_START);
}


/**
 *
 */
inline std::tuple<bool, uint16_t>
reserve_port(std::vector<NetworkPort> used_ports)
{
    // todo: get ports from elsewhere
    // todo: also check system for occupied ports.
    auto found = false;
    const uint16_t port = LOCAL_PORT_RANGE_START;
    while (port <= LOCAL_PORT_RANGE_END) {
        if (!port_in_list(used_ports, port)) {
            found = true;
            break;
        }
    }

    NetworkPort net_port;
    net_port.port = port;

    used_ports.push_back(net_port);
    return std::make_tuple(found, port);
}

//
// END OF FILE
//