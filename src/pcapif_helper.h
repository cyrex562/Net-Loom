#pragma once
#include <cstdint>


#ifdef _MSC_VER
struct pcapifh_linkstate
{
    uint8_t empty;
};
#else

      struct pcapifh_linkstate {
  LPADAPTER        lpAdapter;
  PPACKET_OID_DATA ppacket_oid_data;
};
#endif


enum pcapifh_link_event
{
    PCAPIF_LINKEVENT_UNKNOWN,
    PCAPIF_LINKEVENT_UP,
    PCAPIF_LINKEVENT_DOWN
};


struct pcapifh_linkstate*
pcapifh_linkstate_init(char* adapter_name);

enum pcapifh_link_event
pcapifh_linkstate_get(struct pcapifh_linkstate* state);

void
pcapifh_linkstate_close(struct pcapifh_linkstate* state);

//
// END OF FILE
//