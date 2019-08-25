#pragma once
#include <xstring>

#ifndef WIN32
struct pcapifh_linkstate
{
    uint8_t empty;
};
#else

#include "Packet32.h"

struct pcapifh_linkstate
{
    LPADAPTER lpAdapter;
    PPACKET_OID_DATA ppacket_oid_data;
};
#endif


enum PcapIfHlpLinkEvent
{
    PCAPIF_LINKEVENT_UNKNOWN,
    PCAPIF_LINKEVENT_UP,
    PCAPIF_LINKEVENT_DOWN
};


std::tuple<bool, pcapifh_linkstate>
pcapifh_linkstate_init(std::string& adapter_name);

PcapIfHlpLinkEvent
pcapifh_linkstate_get(pcapifh_linkstate& state);

void
pcapifh_linkstate_close(pcapifh_linkstate& state);

//
// END OF FILE
//