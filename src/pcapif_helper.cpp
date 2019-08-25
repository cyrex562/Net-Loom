/**
 * pcapif_helper.c - This file is part of lwIP pcapif and provides helper functions
 * for managing the link state.
 */

#include "pcapif_helper.h"
#include "arch.h"
#include <cstdlib>
#include <cstdio>
#include <string>


#ifdef WIN32

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "Windows.h"
#include "ntddndis.h"


/**
 *
 */
std::tuple<bool, pcapifh_linkstate>
pcapifh_linkstate_init(std::string& adapter_name)
{
    pcapifh_linkstate state{};
    state.ppacket_oid_data = PPACKET_OID_DATA(
        malloc(sizeof(PACKET_OID_DATA) + sizeof(NDIS_MEDIA_STATE)));
    if (state.ppacket_oid_data == nullptr)
    {
        return std::make_tuple(false, state);
    }
    state.lpAdapter = PacketOpenAdapter(PCHAR(adapter_name.c_str()));
    if ((state.lpAdapter == nullptr) || (state.lpAdapter->hFile == INVALID_HANDLE_VALUE))
    {
        /* failed to open adapter */
        return std::make_tuple(false, state);
    }
    return std::make_tuple(true, state);
}


/**
 *
 */
PcapIfHlpLinkEvent
pcapifh_linkstate_get(pcapifh_linkstate& state)
{
    auto ret = PCAPIF_LINKEVENT_UNKNOWN;
    state.ppacket_oid_data->Oid = OID_GEN_MEDIA_CONNECT_STATUS;
    state.ppacket_oid_data->Length = sizeof(NDIS_MEDIA_STATE);
    if (PacketRequest(state.lpAdapter, FALSE, state.ppacket_oid_data) != 0U)
    {
        const auto ndis_media_state = (*PNDIS_MEDIA_STATE(state.ppacket_oid_data->Data));
        if (ndis_media_state == NdisMediaStateConnected)
        {
            ret = PCAPIF_LINKEVENT_UP;
        }
        else
        {
            ret = PCAPIF_LINKEVENT_DOWN;
        }
    }
    return ret;
}


/**
 *
 */
void
pcapifh_linkstate_close(pcapifh_linkstate& state)
{
    if (state.lpAdapter != nullptr)
    {
        PacketCloseAdapter(state.lpAdapter);
    }
    if (state.ppacket_oid_data != nullptr)
    {
        free(state.ppacket_oid_data);
    }
}

#else /* WIN32 */

/* @todo: add linux/unix implementation? */


struct pcapifh_linkstate* pcapifh_linkstate_init(char *adapter_name)
{
  ;
  return NULL;
}

enum pcapifh_link_event pcapifh_linkstate_get(struct pcapifh_linkstate* state)
{
  ;
  return PCAPIF_LINKEVENT_UP;
}
void pcapifh_linkstate_close(struct pcapifh_linkstate* state)
{
  ;
}

#endif /* WIN32 */