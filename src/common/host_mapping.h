#pragma once
#include <string>
#include <vector>
#include "ip_addr.h"


struct HostMapping
{
    std::vector<std::string> names;
    IpAddrInfo address;
};
