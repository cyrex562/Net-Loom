//
// file: tcpip
//
#pragma once

#include <opt.h>
#include <lwip_error.h>
#include <timeouts.h>
#include <netif.h>

/** The global semaphore to lock the stack. */
extern Mutex lock_tcpip_core;

/** Lock lwIP core mutex (needs @ref LWIP_TCPIP_CORE_LOCKING 1) */
#define LOCK_TCPIP_CORE()     sys_mutex_lock(&lock_tcpip_core)
/** Unlock lwIP core mutex (needs @ref LWIP_TCPIP_CORE_LOCKING 1) */
#define UNLOCK_TCPIP_CORE()   sys_mutex_unlock(&lock_tcpip_core)



struct PacketBuffer;
struct NetIfc;

/** Function prototype for the init_done function passed to tcpip_init */
using tcpip_init_done_fn = void (*)(uint8_t*);
/** Function prototype for functions passed to tcpip_callback() */
using tcpip_callback_fn = void (*)(uint8_t*);

/* Forward declarations */
struct tcpip_callback_msg;

void   tcpip_init(tcpip_init_done_fn tcpip_init_done, uint8_t *arg);

LwipStatus  tcpip_inpkt(struct PacketBuffer *p, NetIfc*inp, NetifInputFn input_fn);
LwipStatus  tcpip_input(struct PacketBuffer *p, NetIfc*inp);

LwipStatus  tcpip_try_callback(tcpip_callback_fn function, uint8_t *ctx);
LwipStatus  tcpip_callback(tcpip_callback_fn function, uint8_t *ctx);


struct tcpip_callback_msg* tcpip_callbackmsg_new(tcpip_callback_fn function, uint8_t *ctx);
void   tcpip_callbackmsg_delete(struct tcpip_callback_msg* msg);
LwipStatus  tcpip_callbackmsg_trycallback(struct tcpip_callback_msg* msg);
LwipStatus  tcpip_callbackmsg_trycallback_fromisr(struct tcpip_callback_msg* msg);

/* free pbufs or heap memory from another context without blocking */
LwipStatus  pbuf_free_callback(struct PacketBuffer *p);
LwipStatus  mem_free_callback(uint8_t *m);


LwipStatus  tcpip_timeout(uint32_t msecs, SysTimeoutHandler h, uint8_t *arg);
LwipStatus  tcpip_untimeout(SysTimeoutHandler h, uint8_t *arg);


int tcpip_thread_poll_one(void);

//
// END OF FILE
//