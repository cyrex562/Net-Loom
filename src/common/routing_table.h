#pragma once
#include <string>
#include <vector>
#include "route.h"


struct RoutingTable
{
    std::string id;
    // todo: store routes by priority
    std::vector<Route> routes;
};
