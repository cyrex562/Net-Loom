#pragma once

#include "ppp_opts.h"
#include "ppp.h"
#include "pppos.h"
#include "sys.h"
#include "netif.h"
#include "tcpip_priv.h"
#include "ppp.h"
#include "pppos.h"

struct PppApiMsgMsg
{
    PppPcb* ppp;

    union
    {
        struct
        {
            ppp_notify_phase_cb_fn notify_phase_cb;
        } setnotifyphasecb;

        struct
        {
            struct NetIfc* pppif;
            pppos_output_cb_fn output_cb;
            ppp_link_status_cb_fn link_status_cb;
            void* ctx_cb;
        } serialcreate;

        struct
        {
            struct NetIfc* pppif;
            struct NetIfc* ethif;
            const char* service_name;
            const char* concentrator_name;
            ppp_link_status_cb_fn link_status_cb;
            void* ctx_cb;
        } ethernetcreate;

        struct
        {
            struct NetIfc* pppif;
            struct NetIfc* netif;
            IpAddr ipaddr;
            uint16_t port;
            const uint8_t* secret;
            uint8_t secret_len;
            ppp_link_status_cb_fn link_status_cb;
            void* ctx_cb;
        } l2tpcreate;

        struct
        {
            uint16_t holdoff;
        } connect;

        struct
        {
            uint8_t nocarrier;
        } close;

        struct
        {
            uint8_t cmd;
            void* arg;
        } ioctl;
    } msg;
};

struct pppapi_msg
{
    struct tcpip_api_call_data call;
    struct PppApiMsgMsg msg;
};

/* API for application */
LwipError pppapi_set_default(PppPcb *pcb);

LwipError pppapi_set_notify_phase_callback(PppPcb *pcb, ppp_notify_phase_cb_fn notify_phase_cb);

PppPcb *pppapi_pppos_create(struct NetIfc *pppif, pppos_output_cb_fn output_cb, ppp_link_status_cb_fn link_status_cb, void *ctx_cb);

PppPcb *pppapi_pppoe_create(struct NetIfc *pppif, struct NetIfc *ethif, const char *service_name,
                                const char *concentrator_name, ppp_link_status_cb_fn link_status_cb,
                                void *ctx_cb);

PppPcb *pppapi_pppol2tp_create(struct NetIfc *pppif, struct NetIfc *netif, IpAddr *ipaddr, uint16_t port,
                            const uint8_t *secret, uint8_t secret_len,
                            ppp_link_status_cb_fn link_status_cb, void *ctx_cb);

LwipError pppapi_connect(PppPcb *pcb, uint16_t holdoff);

LwipError pppapi_listen(PppPcb *pcb);

LwipError pppapi_close(PppPcb *pcb, uint8_t nocarrier);

LwipError pppapi_free(PppPcb *pcb);

LwipError pppapi_ioctl(PppPcb *pcb, uint8_t cmd, void *arg);

//
// END OF FILE
//
