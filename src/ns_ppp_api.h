#pragma once

#include "ns_ppp_config.h"
#include "ns_ppp.h"
#include "ns_pppos.h"
#include "ns_sys.h"
#include "ns_network_interface.h"
#include "ns_tcpip_priv.h"
#include "ns_ppp.h"
#include "ns_pppos.h"

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
NsStatus pppapi_set_default(PppPcb *pcb);

NsStatus pppapi_set_notify_phase_callback(PppPcb *pcb, ppp_notify_phase_cb_fn notify_phase_cb);

PppPcb *pppapi_pppos_create(NetworkInterface*pppif, pppos_output_cb_fn output_cb, ppp_link_status_cb_fn link_status_cb, uint8_t *ctx_cb);

PppPcb *pppapi_pppoe_create(NetworkInterface*pppif, NetworkInterface*ethif, const char *service_name,
                                const char *concentrator_name, ppp_link_status_cb_fn link_status_cb,
                                uint8_t *ctx_cb);

PppPcb *pppapi_pppol2tp_create(NetworkInterface*pppif, NetworkInterface*netif, IpAddrInfo *ipaddr, uint16_t port,
                            const uint8_t *secret, uint8_t secret_len,
                            ppp_link_status_cb_fn link_status_cb, uint8_t *ctx_cb);

NsStatus pppapi_connect(PppPcb *pcb, uint16_t holdoff);

NsStatus pppapi_listen(PppPcb *pcb);

NsStatus pppapi_close(PppPcb *pcb, uint8_t nocarrier);

NsStatus pppapi_free(PppPcb *pcb);

NsStatus pppapi_ioctl(PppPcb *pcb, uint8_t cmd, uint8_t *arg);

//
// END OF FILE
//
