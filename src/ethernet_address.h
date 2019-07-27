///
/// file: ethernet_address.h
///

#pragma once
#include "ethernet.h"

constexpr auto ETH_ADDR_LEN = 6;

struct EthernetAddress
{
    uint8_t addr[ETH_ADDR_LEN];
}; 

//
// END OF FILE
//