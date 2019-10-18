#pragma once
#include "ip_addr.h"


struct Network
{
    IpAddress address;
    IpAddress mask;
};
