//
// file: tcpip_priv.h
//
#pragma once
#include "tcpip.h"
#include "netloom_sys.h"
#include "timeouts.h"

struct PacketContainer;
NsStatus tcpip_send_msg_wait_sem(TcpipCallbackFn fn, uint8_t* apimsg, Semaphore* sem);

struct TcpipApiCallData
{
    uint8_t dummy; /* avoid empty struct :-( */
};

typedef NsStatus (*tcpip_api_call_fn)(struct TcpipApiCallData* call);
NsStatus tcpip_api_call(tcpip_api_call_fn fn, struct TcpipApiCallData* call);

enum tcpip_msg_type
{
    TCPIP_MSG_INPKT,
    TCPIP_MSG_TIMEOUT,
    TCPIP_MSG_UNTIMEOUT,
    TCPIP_MSG_CALLBACK,
    TCPIP_MSG_CALLBACK_STATIC
};

struct tcpip_msg
{
    enum tcpip_msg_type type;

    union
    {
        struct
        {
            struct PacketContainer* p;
            NetworkInterface* netif;
            NetifInputFn input_fn;
        } inp;

        struct
        {
            TcpipCallbackFn function;
            uint8_t* ctx;
        } cb;

        struct
        {
            uint32_t msecs;
            SysTimeoutHandler h;
            uint8_t* arg;
        } tmo;
    } msg;
};

//
// END OF FILE
//