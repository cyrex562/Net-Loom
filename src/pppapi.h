#pragma once

#include <ppp_opts.h>
#include <ppp.h>
#include <pppos.h>
#include <sys.h>
#include <network_interface.h>
#include <tcpip_priv.h>
#include <ppp.h>
#include <pppos.h>

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
            NetworkInterface* pppif;
            pppos_output_cb_fn output_cb;
            ppp_link_status_cb_fn link_status_cb;
            void* ctx_cb;
        } serialcreate;

        struct
        {
            NetworkInterface* pppif;
            NetworkInterface* ethif;
            const char* service_name;
            const char* concentrator_name;
            ppp_link_status_cb_fn link_status_cb;
            void* ctx_cb;
        } ethernetcreate;

        struct
        {
            NetworkInterface* pppif;
            NetworkInterface* netif;
            IpAddrInfo ipaddr;
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
    struct TcpipApiCallData call;
    struct PppApiMsgMsg msg;
};

/* API for application */
LwipStatus pppapi_set_default(PppPcb *pcb);

LwipStatus pppapi_set_notify_phase_callback(PppPcb *pcb, ppp_notify_phase_cb_fn notify_phase_cb);

PppPcb *pppapi_pppos_create(NetworkInterface*pppif, pppos_output_cb_fn output_cb, ppp_link_status_cb_fn link_status_cb, uint8_t *ctx_cb);

PppPcb *pppapi_pppoe_create(NetworkInterface*pppif, NetworkInterface*ethif, const char *service_name,
                                const char *concentrator_name, ppp_link_status_cb_fn link_status_cb,
                                uint8_t *ctx_cb);

PppPcb *pppapi_pppol2tp_create(NetworkInterface*pppif, NetworkInterface*netif, IpAddrInfo *ipaddr, uint16_t port,
                            const uint8_t *secret, uint8_t secret_len,
                            ppp_link_status_cb_fn link_status_cb, uint8_t *ctx_cb);

LwipStatus pppapi_connect(PppPcb *pcb, uint16_t holdoff);

LwipStatus pppapi_listen(PppPcb *pcb);

LwipStatus pppapi_close(PppPcb *pcb, uint8_t nocarrier);

LwipStatus pppapi_free(PppPcb *pcb);

LwipStatus pppapi_ioctl(PppPcb *pcb, uint8_t cmd, uint8_t *arg);

//
// END OF FILE
//
