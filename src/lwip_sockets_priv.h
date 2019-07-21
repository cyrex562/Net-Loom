/**
 * @file
 * Sockets API internal implementations (do not use in application code)
 */

/*
 * Copyright (c) 2017 Joel Cunningham, Garmin International, Inc. <joel.cunningham@garmin.com>
 * All rights reserved.
 *
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
 * Author: Joel Cunningham <joel.cunningham@me.com>
 *
 */
#include <opt.h>
#include <lwip_error.h>
#include <lwip_sockets.h>
#include <sys.h>

#define NUM_SOCKETS MEMP_NUM_NETCONN

/** This is overridable for the rare case where more than 255 threads
 * select on the same socket...
 */
#define SELWAIT_T uint8_t

union lwip_sock_lastdata {
  struct netbuf *netbuf;
  struct PacketBuffer *pbuf;
};

/** Contains all internal pointers and states used for a socket */
struct lwip_sock {
  /** sockets currently are built on netconns, each socket has one NetconnDesc */
  struct NetconnDesc *conn;
  /** data that was left from the previous read */
  union lwip_sock_lastdata lastdata;

  /** number of times data was received, set by event_callback(),
      tested by the receive and select functions */
  int16_t rcvevent;
  /** number of times data was ACKed (free send buffer), set by event_callback(),
      tested by select */
  uint16_t sendevent;
  /** error happened for this socket, set by event_callback(), tested by select */
  uint16_t errevent;
  /** counter of how many threads are waiting for this socket using select */
  SELWAIT_T select_waiting;


  /* counter of how many threads are using a struct lwip_sock (not the 'int') */
  uint8_t fd_used;
  /* status of pending close/delete actions */
  uint8_t fd_free_pending;
#define LWIP_SOCK_FD_FREE_TCP  1
#define LWIP_SOCK_FD_FREE_FREE 2
};

#define set_errno(err) do { if (err) { errno = (err); } } while(0)

struct lwip_sock* lwip_socket_dbg_get_socket(int fd);

#define SELECT_SEM_T        Semaphore*
#define SELECT_SEM_PTR(sem) (sem)


/** Description for a task waiting in select */
struct lwip_select_cb {
  /** Pointer to the next waiting task */
  struct lwip_select_cb *next;
  /** Pointer to the previous waiting task */
  struct lwip_select_cb *prev;

  /** readset passed to select */
  LwipFdSet *readset;
  /** writeset passed to select */
  LwipFdSet *writeset;
  /** unimplemented: exceptset passed to select */

  /** fds passed to poll; NULL if select */
  struct LwipPolllfd *poll_fds;
  /** nfds passed to poll; 0 if select */
  LwipNfds poll_nfds;

  /** don't signal the same semaphore twice: set to 1 when signalled */
  int sem_signalled;
  /** semaphore to wake up a task waiting for select */
  SELECT_SEM_T sem;
};

