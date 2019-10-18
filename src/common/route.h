#pragma once
#include "network_interface.h"
#include "network.h"


struct Route
{
    Network network;
    IpAddress next_hop;
    NetworkInterface next_hop_interface;
    int metric{};
    int priority{};
};
