//
// file: tcpip
//
#pragma once

#include "netloom_config.h"
#include "netloom_status.h"
#include "timeouts.h"
#include "network_interface.h"

/** The global semaphore to lock the stack. */
extern Mutex lock_tcpip_core;

/** Lock lwIP core mutex (needs @ref LWIP_TCPIP_CORE_LOCKING 1) */
#define LOCK_TCPIP_CORE()     sys_mutex_lock(&lock_tcpip_core)
/** Unlock lwIP core mutex (needs @ref LWIP_TCPIP_CORE_LOCKING 1) */
#define UNLOCK_TCPIP_CORE()   sys_mutex_unlock(&lock_tcpip_core)



struct PacketContainer;
struct NetworkInterface;

/** Function prototype for the init_done function passed to tcpip_init */
using TcpipInitDoneFn = void (*)(void*);
/** Function prototype for functions passed to tcpip_callback() */
using TcpipCallbackFn = void (*)(void*);

/* Forward declarations */
struct tcpip_callback_msg;

void   tcpip_init(TcpipInitDoneFn tcpip_init_done, void* arg);


bool
tcpip_inpkt(PacketContainer& pkt, NetworkInterface& ifc);
NsStatus  tcpip_input(struct PacketContainer *p, NetworkInterface*inp);

NsStatus  tcpip_try_callback(TcpipCallbackFn function, void* ctx);
NsStatus  tcpip_callback(TcpipCallbackFn function, void* ctx);


struct tcpip_callback_msg* tcpip_callbackmsg_new(TcpipCallbackFn function, uint8_t *ctx);
void   tcpip_callbackmsg_delete(struct tcpip_callback_msg* msg);
NsStatus  tcpip_callbackmsg_trycallback(struct tcpip_callback_msg* msg);
NsStatus  tcpip_callbackmsg_trycallback_fromisr(struct tcpip_callback_msg* msg);

/* free pbufs or heap memory from another context without blocking */
NsStatus  pbuf_free_callback(struct PacketContainer *p);
NsStatus  mem_free_callback(uint8_t *m);


NsStatus  tcpip_timeout(uint32_t msecs, SysTimeoutHandler h, void* arg);
NsStatus  tcpip_untimeout(SysTimeoutHandler h, void* arg);


int tcpip_thread_poll_one(void);

//
// END OF FILE
//