#pragma once
#include "network_interface.h"
#include "host_mapping.h"
#include "routing_table.h"


struct NetworkStack
{
    // network interfaces
    std::vector<NetworkInterface> interfaces;
    // hosts mappings
    std::vector<HostMapping> hosts;
    // routing tables
    std::vector<RoutingTable> routing_tables;
};
