/**
 * @file
 * Point To Point Protocol Sequential API module
 *
 */

/*
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 */

#include <ppp_opts.h>
#include <pppapi.h>
#include <tcpip_priv.h>
#include <pppoe.h>
#include <pppol2tp.h>
#include <pppos.h>
#include <lwip_status.h>

#define API_VAR_DECLARE(x, y) x y
#define API_VAR_REF(x) x

#define PPPAPI_VAR_REF(name)               API_VAR_REF(name)
#define PPPAPI_VAR_DECLARE(name)           API_VAR_DECLARE(struct pppapi_msg, name)
#define PPPAPI_VAR_ALLOC(name)             API_VAR_ALLOC_POOL(struct pppapi_msg, PPPAPI_MSG, name, ERR_MEM)
#define PPPAPI_VAR_ALLOC_RETURN_NULL(name) API_VAR_ALLOC_POOL(struct pppapi_msg, PPPAPI_MSG, name, NULL)
#define PPPAPI_VAR_FREE(name)              API_VAR_FREE_POOL(PPPAPI_MSG, name)

/**
 * Call ppp_set_default() inside the tcpip_thread context.
 */
static LwipStatus
pppapi_do_ppp_set_default(struct TcpipApiCallData *m)
{
  /* cast through void* to silence alignment warnings. 
   * We know it works because the structs have been instantiated as struct pppapi_msg */
  struct pppapi_msg *msg = (struct pppapi_msg *)(void*)m;
  
  ppp_set_default(msg->msg.ppp);
  return ERR_OK;
}

/**
 * Call ppp_set_default() in a thread-safe way by running that function inside the
 * tcpip_thread context.
 */
LwipStatus pppapi_set_default(PppPcb* pcb)
{
    struct pppapi_msg* msg = new pppapi_msg;
    msg->msg.ppp = pcb;
    const auto err = tcpip_api_call(pppapi_do_ppp_set_default, &msg->call);
    delete msg;
    return err;
}

/**
 * Call ppp_set_notify_phase_callback() inside the tcpip_thread context.
 */
static LwipStatus
pppapi_do_ppp_set_notify_phase_callback(struct TcpipApiCallData *m)
{
  /* cast through void* to silence alignment warnings. 
   * We know it works because the structs have been instantiated as struct pppapi_msg */
   struct pppapi_msg *msg = (struct pppapi_msg *)(void*)m;

  ppp_set_notify_phase_callback(msg->msg.ppp, msg->msg.msg.setnotifyphasecb.notify_phase_cb);
  return ERR_OK;
}

/**
 * Call ppp_set_notify_phase_callback() in a thread-safe way by running that function inside the
 * tcpip_thread context.
 */
LwipStatus pppapi_set_notify_phase_callback(PppPcb* pcb,
                                            ppp_notify_phase_cb_fn notify_phase_cb)
{
    struct pppapi_msg* msg = new pppapi_msg;
    // API_VAR_ALLOC_POOL(struct pppapi_msg, PPPAPI_MSG, msg, ERR_MEM);
    msg->msg.ppp = pcb;
    msg->msg.msg.setnotifyphasecb.notify_phase_cb = notify_phase_cb;
    LwipStatus err = tcpip_api_call(pppapi_do_ppp_set_notify_phase_callback, &msg->call);
    delete msg;
    return err;
}


/**
 * Call pppos_create() inside the tcpip_thread context.
 */
static LwipStatus pppapi_do_pppos_create(struct TcpipApiCallData* m)
{
    /* cast through void* to silence alignment warnings. 
     * We know it works because the structs have been instantiated as struct pppapi_msg */
    auto* msg = static_cast<struct pppapi_msg *>(static_cast<void*>(m));
    msg->msg.ppp = pppos_create(msg->msg.msg.serialcreate.pppif,
                                msg->msg.msg.serialcreate.output_cb,
                                msg->msg.msg.serialcreate.link_status_cb,
                                msg->msg.msg.serialcreate.ctx_cb);
    return ERR_OK;
}

/**
 * Call pppos_create() in a thread-safe way by running that function inside the
 * tcpip_thread context.
 */
PppPcb* pppapi_pppos_create(NetworkInterface* pppif,
                            pppos_output_cb_fn output_cb,
                            ppp_link_status_cb_fn link_status_cb,
                            uint8_t* ctx_cb)
{
    auto msg = new pppapi_msg; // PPPAPI_VAR_ALLOC_RETURN_NULL(msg);
    msg->msg.ppp = nullptr;
    msg->msg.msg.serialcreate.pppif = pppif;
    msg->msg.msg.serialcreate.output_cb = output_cb;
    msg->msg.msg.serialcreate.link_status_cb = link_status_cb;
    msg->msg.msg.serialcreate.ctx_cb = ctx_cb;
    tcpip_api_call(pppapi_do_pppos_create, &msg->call);
    const auto result = msg->msg.ppp;
    delete msg;
    return result;
}



/**
 * Call pppoe_create() inside the tcpip_thread context.
 */
static LwipStatus
pppapi_do_pppoe_create(struct TcpipApiCallData *m)
{
  /* cast through void* to silence alignment warnings. 
   * We know it works because the structs have been instantiated as struct pppapi_msg */
  struct pppapi_msg *msg = (struct pppapi_msg *)(void*)m;

  msg->msg.ppp = pppoe_create(msg->msg.msg.ethernetcreate.pppif, msg->msg.msg.ethernetcreate.ethif,
                              msg->msg.msg.ethernetcreate.service_name, msg->msg.msg.ethernetcreate.concentrator_name,
                              msg->msg.msg.ethernetcreate.link_status_cb, msg->msg.msg.ethernetcreate.ctx_cb);
  return ERR_OK;
}



/**
 * Call pppoe_create() in a thread-safe way by running that function inside the
 * tcpip_thread context.
 */
PppPcb* pppapi_pppoe_create(NetworkInterface* pppif,
                            NetworkInterface* ethif,
                            const char* service_name,
                            const char* concentrator_name,
                            ppp_link_status_cb_fn link_status_cb,
                            uint8_t* ctx_cb)
{
    PppPcb* result;
    struct pppapi_msg* msg;
    // API_VAR_ALLOC_POOL(struct pppapi_msg, PPPAPI_MSG, msg, NULL);
    msg = new pppapi_msg;
    msg->msg.ppp = nullptr;
    msg->msg.msg.ethernetcreate.pppif = pppif;
    msg->msg.msg.ethernetcreate.ethif = ethif;
    msg->msg.msg.ethernetcreate.service_name = service_name;
    msg->msg.msg.ethernetcreate.concentrator_name = concentrator_name;
    msg->msg.msg.ethernetcreate.link_status_cb = link_status_cb;
    msg->msg.msg.ethernetcreate.ctx_cb = ctx_cb;
    tcpip_api_call(pppapi_do_pppoe_create, &msg->call);
    result = msg->msg.ppp; // API_VAR_FREE_POOL(PPPAPI_MSG, msg);
    delete msg;
    return result;
}



/**
 * Call pppol2tp_create() inside the tcpip_thread context.
 */
static LwipStatus pppapi_do_pppol2tp_create(struct TcpipApiCallData* m)
{
    /* cast through void* to silence alignment warnings. 
     * We know it works because the structs have been instantiated as struct pppapi_msg */
    auto* msg = static_cast<struct pppapi_msg *>(static_cast<void*>(m));
    msg->msg.ppp = CreatePppol2tpSession(msg->msg.msg.l2tpcreate.pppif,
                                         msg->msg.msg.l2tpcreate.netif,
                                         &msg->msg.msg.l2tpcreate.ipaddr,
                                         msg->msg.msg.l2tpcreate.port,
                                         msg->msg.msg.l2tpcreate.secret,
                                         msg->msg.msg.l2tpcreate.secret_len,
                                         msg->msg.msg.l2tpcreate.link_status_cb,
                                         msg->msg.msg.l2tpcreate.ctx_cb);
    return ERR_OK;
}

/**
 * Call pppol2tp_create() in a thread-safe way by running that function inside the
 * tcpip_thread context.
 */
PppPcb*
pppapi_pppol2tp_create(NetworkInterface*pppif, NetworkInterface*netif, IpAddr *ipaddr, uint16_t port,
                        const uint8_t *secret, uint8_t secret_len,
                        ppp_link_status_cb_fn link_status_cb, uint8_t *ctx_cb)
{
  PppPcb* result;
  struct pppapi_msg* msg = new pppapi_msg;

  msg->msg.ppp = nullptr;
  msg->msg.msg.l2tpcreate.pppif = pppif;
  msg->msg.msg.l2tpcreate.netif = netif;
  msg->msg.msg.l2tpcreate.ipaddr = *ipaddr;
  msg->msg.msg.l2tpcreate.port = port;

  msg->msg.msg.l2tpcreate.secret = secret;
  msg->msg.msg.l2tpcreate.secret_len = secret_len;

  msg->msg.msg.l2tpcreate.link_status_cb = link_status_cb;
  msg->msg.msg.l2tpcreate.ctx_cb = ctx_cb;
  tcpip_api_call(pppapi_do_pppol2tp_create, &msg->call);
  result = msg->msg.ppp;
  delete msg;
  return result;
}



/**
 * Call ppp_connect() inside the tcpip_thread context.
 */
static LwipStatus
pppapi_do_ppp_connect(struct TcpipApiCallData *m)
{
  /* cast through void* to silence alignment warnings. 
   * We know it works because the structs have been instantiated as struct pppapi_msg */
  struct pppapi_msg *msg = (struct pppapi_msg *)(void*)m;

  return ppp_connect(msg->msg.ppp, msg->msg.msg.connect.holdoff);
}

/**
 * Call ppp_connect() in a thread-safe way by running that function inside the
 * tcpip_thread context.
 */
LwipStatus pppapi_connect(PppPcb* pcb, uint16_t holdoff)
{
    auto msg = new pppapi_msg;
    msg->msg.ppp = pcb;
    msg->msg.msg.connect.holdoff = holdoff;
    LwipStatus err = tcpip_api_call(pppapi_do_ppp_connect, &msg->call);
    delete msg;
    return err;
}


#if PPP_SERVER
/**
 * Call ppp_listen() inside the tcpip_thread context.
 */
static LwipStatus
pppapi_do_ppp_listen(struct TcpipApiCallData *m)
{
  /* cast through void* to silence alignment warnings. 
   * We know it works because the structs have been instantiated as struct pppapi_msg */
  struct pppapi_msg *msg = (struct pppapi_msg *)(void*)m;

  return ppp_listen(msg->msg.ppp);
}

/**
 * Call ppp_listen() in a thread-safe way by running that function inside the
 * tcpip_thread context.
 */
LwipStatus
pppapi_listen(PppPcb *pcb)
{
  LwipStatus err;
  PPPAPI_VAR_DECLARE(msg);
  PPPAPI_VAR_ALLOC(msg);

  PPPAPI_VAR_REF(msg).msg.ppp = pcb;
  err = tcpip_api_call(pppapi_do_ppp_listen, &PPPAPI_VAR_REF(msg).call);
  PPPAPI_VAR_FREE(msg);
  return err;
}
#endif /* PPP_SERVER */


/**
 * Call ppp_close() inside the tcpip_thread context.
 */
static LwipStatus
pppapi_do_ppp_close(struct TcpipApiCallData *m)
{
  /* cast through void* to silence alignment warnings. 
   * We know it works because the structs have been instantiated as struct pppapi_msg */
  struct pppapi_msg *msg = (struct pppapi_msg *)(void*)m;

  return ppp_close(msg->msg.ppp, msg->msg.msg.close.nocarrier);
}

/**
 * Call ppp_close() in a thread-safe way by running that function inside the
 * tcpip_thread context.
 */
LwipStatus
pppapi_close(PppPcb *pcb, uint8_t nocarrier)
{
  LwipStatus err;
  PPPAPI_VAR_DECLARE(msg);
  PPPAPI_VAR_ALLOC(msg);

  PPPAPI_VAR_REF(msg).msg.ppp = pcb;
  PPPAPI_VAR_REF(msg).msg.msg.close.nocarrier = nocarrier;
  err = tcpip_api_call(pppapi_do_ppp_close, &PPPAPI_VAR_REF(msg).call);
  PPPAPI_VAR_FREE(msg);
  return err;
}


/**
 * Call ppp_free() inside the tcpip_thread context.
 */
static LwipStatus
pppapi_do_ppp_free(struct TcpipApiCallData *m)
{
  /* cast through void* to silence alignment warnings. 
   * We know it works because the structs have been instantiated as struct pppapi_msg */
  struct pppapi_msg *msg = (struct pppapi_msg *)(void*)m;

  return ppp_free(msg->msg.ppp);
}

/**
 * Call ppp_free() in a thread-safe way by running that function inside the
 * tcpip_thread context.
 */
LwipStatus
pppapi_free(PppPcb *pcb)
{
  LwipStatus err;
  PPPAPI_VAR_DECLARE(msg);
  PPPAPI_VAR_ALLOC(msg);

  PPPAPI_VAR_REF(msg).msg.ppp = pcb;
  err = tcpip_api_call(pppapi_do_ppp_free, &PPPAPI_VAR_REF(msg).call);
  PPPAPI_VAR_FREE(msg);
  return err;
}


/**
 * Call ppp_ioctl() inside the tcpip_thread context.
 */
static LwipStatus
pppapi_do_ppp_ioctl(struct TcpipApiCallData *m)
{
  /* cast through void* to silence alignment warnings. 
   * We know it works because the structs have been instantiated as struct pppapi_msg */
  struct pppapi_msg *msg = (struct pppapi_msg *)(void*)m;

  return ppp_ioctl(msg->msg.ppp, msg->msg.msg.ioctl.cmd, msg->msg.msg.ioctl.arg);
}

/**
 * Call ppp_ioctl() in a thread-safe way by running that function inside the
 * tcpip_thread context.
 */
LwipStatus
pppapi_ioctl(PppPcb *pcb, uint8_t cmd, uint8_t *arg)
{
  LwipStatus err;
  PPPAPI_VAR_DECLARE(msg);
  PPPAPI_VAR_ALLOC(msg);

  PPPAPI_VAR_REF(msg).msg.ppp = pcb;
  PPPAPI_VAR_REF(msg).msg.msg.ioctl.cmd = cmd;
  PPPAPI_VAR_REF(msg).msg.msg.ioctl.arg = arg;
  err = tcpip_api_call(pppapi_do_ppp_ioctl, &PPPAPI_VAR_REF(msg).call);
  PPPAPI_VAR_FREE(msg);
  return err;
}

