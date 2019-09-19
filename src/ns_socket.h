/**
 * @file
 * Socket API (to be used from non-TCPIP threads)
 */

/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
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
 * Author: Adam Dunkels <adam@sics.se>
 *
 */


#pragma once

#include "ns_sys.h"
#include "ns_config.h"


#define SELECT_SEM_T        Semaphore*
#define SELECT_SEM_PTR(sem) (sem)


/* If your port already typedef's sa_family_t, define SA_FAMILY_T_DEFINED
   to prevent this code from redefining it. */

typedef uint8_t LwipSaFamily;

/* If your port already typedef's LwipInPort, define IN_PORT_T_DEFINED
   to prevent this code from redefining it. */

typedef uint16_t LwipInPort;


constexpr auto SIN_ZERO_LEN = 8;

/* members are in network byte order */
// struct LwipSockaddrSockaddrIn
// {
//     uint8_t _sin_len;
//     LwipSaFamily _sin_family;
//     LwipInPort _sin_port;
//     LwipInAddrStruct __sin_addr;
//     char _sin_zero[SIN_ZERO_LEN];
// };


// struct LwipSockaddrIn6
// {
//     uint8_t _sin6_len; /* length of this structure    */
//     LwipSaFamily _sin6_family; /* AF_INET6                    */
//     LwipInPort _sin6_port; /* Transport layer port #      */
//     uint32_t _sin6_flowinfo; /* IPv6 flow information       */
//     LwipIn6Addr _sin6_addr; /* IPv6 address                */
//     uint32_t _sin6_scope_id; /* Set of interfaces for scope */
// };


struct LwipSockaddr
{
    uint8_t _sa_len;
    LwipSaFamily _sa_family;
    char _sa_data[14];
};

struct LwipSockaddrStorage
{
    uint8_t s2_len;
    LwipSaFamily ss_family;
    char s2_data1[2];
    uint32_t s2_data2[3];
    uint32_t s2_data3[3];
};

/* If your port already typedef's LwipSocklen, define SOCKLEN_T_DEFINED
   to prevent this code from redefining it. */
typedef uint32_t LwipSocklen;


constexpr auto LWIP_IOV_MAX = 0xFFFF;

struct LwipIovec
{
    void* iov_base;
    size_t iov_len;
};

struct LwipMsgHdr
{
    void* msg_name;
    LwipSocklen msg_namelen;
    struct LwipIovec* msg_iov;
    int msg_iovlen;
    void* msg_control;
    LwipSocklen msg_controllen;
    int msg_flags;
};

/* struct LwipMsgHdr->msg_flags bit field values */
constexpr auto LWIP_MSG_TRUNC = 0x04;
constexpr auto LWIP_MSG_CTRUNC = 0x08;

/* RFC 3542, Section 20: Ancillary Data */
struct LwipCmsgHdr
{
    LwipSocklen cmsg_len; /* number of bytes, including header */
    int cmsg_level; /* originating protocol */
    int cmsg_type; /* protocol-specific type */
};

/* Data section follows header and possible padding, typically referred to as
      unsigned char cmsg_data[]; */

/* cmsg header/data alignment. NOTE: we align to native word size (double word
size on 16-bit arch) so structures are not placed at an unaligned address.
16-bit arch needs double word to ensure 32-bit alignment because LwipSocklen
could be 32 bits. If we ever have cmsg data with a 64-bit variable, alignment
will need to increase long long */
#define LWIP_ALIGN_H(size) (((size) + sizeof(long) - 1U) & ~(sizeof(long)-1U))
#define LWIP_ALIGN_D(size) LWIP_ALIGN_H(size)

#define LWIP_CMSG_FIRSTHDR(mhdr) \
          ((mhdr)->msg_controllen >= sizeof(struct LwipCmsgHdr) ? \
           (struct LwipCmsgHdr *)(mhdr)->msg_control : \
           (struct LwipCmsgHdr *)NULL)

#define LWIP_CMSG_NXTHDR(mhdr, cmsg) \
        (((cmsg) == NULL) ? LWIP_CMSG_FIRSTHDR(mhdr) : \
         (((uint8_t *)(cmsg) + LWIP_ALIGN_H((cmsg)->cmsg_len) \
                            + LWIP_ALIGN_D(sizeof(struct LwipCmsgHdr)) > \
           (uint8_t *)((mhdr)->msg_control) + (mhdr)->msg_controllen) ? \
          (struct LwipCmsgHdr *)NULL : \
          (struct LwipCmsgHdr *)((void*)((uint8_t *)(cmsg) + \
                                      LWIP_ALIGN_H((cmsg)->cmsg_len)))))

#define LWIP_CMSG_DATA(cmsg) ((void*)((uint8_t *)(cmsg) + \
                         LWIP_ALIGN_D(sizeof(struct LwipCmsgHdr))))

#define LWIP_CMSG_SPACE(length) (LWIP_ALIGN_D(sizeof(struct LwipCmsgHdr)) + \
                            LWIP_ALIGN_H(length))

#define LWIP_CMSG_LEN(length) (LWIP_ALIGN_D(sizeof(struct LwipCmsgHdr)) + \
                           length)

/* Set socket options argument */
constexpr auto IFC_NAME_SZ = 0xff;

struct LwipIfreq
{
    char ifr_name[IFC_NAME_SZ]; /* Interface name */
};

/* Socket protocol types (TCP/UDP/RAW) */
enum SockProtoType
{
    LWIP_SOCK_STREAM =1,
    LWIP_SOCK_DGRAM =2,
    LWIP_SOCK_RAW =3,
};


/*
 * Option flags per-socket. These must match the SOF_ flags in ip.h (checked in init.c)
 */
#define LWIP_SO_REUSEADDR   0x0004 /* Allow local address reuse */
#define LWIP_SO_KEEPALIVE   0x0008 /* keep connections alive */
#define LWIP_SO_BROADCAST   0x0020 /* permit to send and to receive broadcast messages (see IP_SOF_BROADCAST option) */


/*
 * Additional options, not kept in so_options.
 */
#define LWIP_SO_DEBUG        0x0001 /* Unimplemented: turn on debugging info recording */
#define LWIP_SO_ACCEPTCONN   0x0002 /* socket has had listen() */
#define LWIP_SO_DONTROUTE    0x0010 /* Unimplemented: just use interface addresses */
#define LWIP_SO_USELOOPBACK  0x0040 /* Unimplemented: bypass hardware when possible */
#define LWIP_SO_LINGER       0x0080 /* LwipLinger on close if data present */
#define LWIP_SO_DONTLINGER   ((int)(~SO_LINGER))
#define LWIP_SO_OOBINLINE    0x0100 /* Unimplemented: leave received OOB data in line */
#define LWIP_SO_REUSEPORT    0x0200 /* Unimplemented: allow local address & port reuse */
#define LWIP_SO_SNDBUF       0x1001 /* Unimplemented: send buffer size */
#define LWIP_SO_RCVBUF       0x1002 /* receive buffer size */
#define LWIP_SO_SNDLOWAT     0x1003 /* Unimplemented: send low-water mark */
#define LWIP_SO_RCVLOWAT     0x1004 /* Unimplemented: receive low-water mark */
#define LWIP_SO_SaNDTIMEO     0x1005 /* send timeout */
#define LWIP_SO_RCVTIMEO     0x1006 /* receive timeout */
#define LWIP_SO_ERROR        0x1007 /* get error status and clear */
#define LWIP_SO_TYPE         0x1008 /* get socket type */
#define LWIP_SO_CONTIMEO     0x1009 /* Unimplemented: connect timeout */
#define LWIP_SO_NO_CHECK     0x100a /* don't create UDP checksum */
#define LWIP_SO_BINDTODEVICE 0x100b /* bind to device */

/*
 * Structure used for manipulating LwipLinger option.
 */
struct LwipLinger
{
    int l_onoff; /* option on/off */
    int l_linger; /* LwipLinger time in seconds */
};

/*
 * Level number for (get/set)sockopt() to apply to socket itself.
 */
#define  LWIP_SOL_SOCKET  0xfff    /* options for socket level */


#define LWIP_AF_UNSPEC       0
#define LWIP_AF_INET         2
#define LWIP_AF_INET6        10
#define LWIP_PF_INET         LWIP_AF_INET
#define LWIP_PF_INET6        LWIP_AF_INET6
#define LWIP_PF_UNSPEC       LWIP_AF_UNSPEC

#define LWIP_IPPROTO_IP      0
#define LWIP_IPPROTO_ICMP    1
#define LWIP_IPPROTO_TCP     6
#define LWIP_IPPROTO_UDP     17

#define LWIP_IPPROTO_IPV6    41
#define LWIP_IPPROTO_ICMPV6  58
#define LWIP_IPPROTO_UDPLITE 136
#define LWIP_IPPROTO_RAW     255

/* Flags we can use with send and recv. */
#define LWIP_MSG_PEEK       0x01    /* Peeks at an incoming message */
#define LWIP_MSG_WAITALL    0x02    /* Unimplemented: Requests that the function block until the full amount of data requested can be returned */
#define LWIP_MSG_OOB        0x04    /* Unimplemented: Requests out-of-band data. The significance and semantics of out-of-band data are protocol-specific */
#define LWIP_MSG_DONTWAIT   0x08    /* Nonblocking i/o for this operation only */
#define LWIP_MSG_MORE       0x10    /* Sender will send more */
#define LWIP_MSG_NOSIGNAL   0x20    /* Uninmplemented: Requests not to send the SIGPIPE signal if an attempt to send is made on a stream-oriented socket that is no longer connected. */


/*
 * Options for level IPPROTO_IP
 */
#define LWIP_IP_TOS             1
#define LWIP_IP_TTL             2
#define LWIP_IP_PKTINFO         8

/*
 * Options for level IPPROTO_TCP
 */
#define LWIP_TCP_NODELAY    0x01    /* don't delay send to coalesce packets */
#define LWIP_TCP_KEEPALIVE  0x02    /* send KEEPALIVE probes when idle for pcb->keep_idle milliseconds */
#define LWIP_TCP_KEEPIDLE   0x03    /* set pcb->keep_idle  - Same as TCP_KEEPALIVE, but use seconds for get/setsockopt */
#define LWIP_TCP_KEEPINTVL  0x04    /* set pcb->keep_intvl - Use seconds for get/setsockopt */
#define LWIP_TCP_KEEPCNT    0x05    /* set pcb->keep_cnt   - Use number of probes sent for get/setsockopt */


/*
 * Options for level IPPROTO_IPV6
 */
#define LWIP_IPV6_CHECKSUM       7  /* RFC3542: calculate and insert the ICMPv6 checksum for raw sockets. */
#define LWIP_IPV6_V6ONLY         27 /* RFC3493: boolean control to restrict AF_INET6 sockets to IPv6 communications only. */


/*
 * Options for level IPPROTO_UDPLITE
 */
#define LWIP_UDPLITE_SEND_CSCOV 0x01 /* sender checksum coverage */
#define LWIP_UDPLITE_RECV_CSCOV 0x02 /* minimal receiver checksum coverage */


/*
 * Options and types for UDP multicast traffic handling
 */
#define LWIP_IP_MULTICAST_TTL   5
#define LWIP_IP_MULTICAST_IF    6
#define LWIP_IP_MULTICAST_LOOP  7


/*
 * Options and types related to multicast membership
 */
#define LWIP_IP_ADD_MEMBERSHIP  3
#define LWIP_IP_DROP_MEMBERSHIP 4

// struct LwipIpMreq
// {
//     struct LwipInAddrStruct imr_multiaddr; /* IP multicast address of group */
//     struct LwipInAddrStruct imr_interface; /* local IP address of interface */
// };


// struct LwipInPktInfo
// {
//     unsigned int ipi_ifindex; /* Interface index */
//     struct LwipInAddrStruct ipi_addr; /* Destination (from header) address */
// };


/*
 * Options and types related to IPv6 multicast membership
 */
constexpr auto LWIP_IPV6_JOIN_GROUP = 12;
#define LWIP_IPV6_ADD_MEMBERSHIP  LWIP_IPV6_JOIN_GROUP
constexpr auto LWIP_IPV6_LEAVE_GROUP = 13;
#define LWIP_IPV6_DROP_MEMBERSHIP LWIP_IPV6_LEAVE_GROUP

// struct LwipIpv6Mreq
// {
//     struct LwipIn6Addr ipv6_mr_multiaddr; /*  IPv6 multicast addr */
//     unsigned int ipv6_mr_interface; /*  interface index, or 0 */
// };


/*
 * The Type of Service provides an indication of the abstract
 * parameters of the quality of service desired.  These parameters are
 * to be used to guide the selection of the actual service parameters
 * when transmitting a datagram through a particular network.  Several
 * networks offer service precedence, which somehow treats high
 * precedence traffic as more important than other traffic (generally
 * by accepting only traffic above a certain precedence at time of high
 * load).  The major choice is a three way tradeoff between low-delay,
 * high-reliability, and high-throughput.
 * The use of the Delay, Throughput, and Reliability indications may
 * increase the cost (in some sense) of the service.  In many networks
 * better performance for one of these parameters is coupled with worse
 * performance on another.  Except for very unusual cases at most two
 * of these three indications should be set.
 */
#define LWIP_IPTOS_TOS_MASK          0x1E
#define LWIP_IPTOS_TOS(tos)          ((tos) & LWIP_IPTOS_TOS_MASK)
#define LWIP_IPTOS_LOWDELAY          0x10
#define LWIP_IPTOS_THROUGHPUT        0x08
#define LWIP_IPTOS_RELIABILITY       0x04
#define LWIP_IPTOS_LOWCOST           0x02
#define LWIP_IPTOS_MINCOST           LWIP_IPTOS_LOWCOST

/*
 * The Network Control precedence designation is intended to be used
 * within a network only.  The actual use and control of that
 * designation is up to each network. The Internetwork Control
 * designation is intended for use by gateway control originators only.
 * If the actual use of these precedence designations is of concern to
 * a particular network, it is the responsibility of that network to
 * control the access to, and use of, those precedence designations.
 */
#define LWIP_IPTOS_PREC_MASK                 0xe0
#define LWIP_IPTOS_PREC(tos)                ((tos) & LWIP_IPTOS_PREC_MASK)
#define LWIP_IPTOS_PREC_NETCONTROL           0xe0
#define LWIP_IPTOS_PREC_INTERNETCONTROL      0xc0
#define LWIP_IPTOS_PREC_CRITIC_ECP           0xa0
#define LWIP_IPTOS_PREC_FLASHOVERRIDE        0x80
#define LWIP_IPTOS_PREC_FLASH                0x60
#define LWIP_IPTOS_PREC_IMMEDIATE            0x40
#define LWIP_IPTOS_PREC_PRIORITY             0x20
#define LWIP_IPTOS_PREC_ROUTINE              0x00


/*
 * Commands for ioctlsocket(),  taken from the BSD file fcntl.h.
 * lwip_ioctl only supports FIONREAD and FIONBIO, for now
 *
 * Ioctl's have the command encoded in the lower word,
 * and the size of any in or out parameters in the upper
 * word.  The high 2 bits of the upper word are used
 * to encode the in/out status of the parameter; for now
 * we restrict parameters to at most 128 bytes.
 */

#define LWIP_IOCPARM_MASK    0x7fU           /* parameters must be < 128 bytes */
#define LWIP_IOC_VOID        0x20000000UL    /* no parameters */
#define LWIP_IOC_OUT         0x40000000UL    /* copy out parameters */
#define LWIP_IOC_IN          0x80000000UL    /* copy in parameters */
#define LWIP_IOC_INOUT       (LWIP_IOC_IN|LWIP_IOC_OUT)
/* 0x20000000 distinguishes new &
   old ioctl's */
#define LWIP_IO(x,y)        ((long)(LWIP_IOC_VOID|((x)<<8)|(y)))

#define LWIP_IOR(x,y,t)     ((long)(LWIP_IOC_OUT|((sizeof(t)&LWIP_IOCPARM_MASK)<<16)|((x)<<8)|(y)))

#define LWIP_IOW(x,y,t)     ((long)(LWIP_IOC_IN|((sizeof(t)&LWIP_IOCPARM_MASK)<<16)|((x)<<8)|(y)))

#define LWIP_FIONREAD    LWIP_IOR('f', 127, unsigned long) /* get # bytes to read */

#define LWIP_FIONBIO     LWIP_IOW('f', 126, unsigned long) /* set/clear non-blocking i/o */


/* Socket I/O Controls: unimplemented */
#define LWIP_SIOCSHIWAT  LWIP_IOW('s',  0, unsigned long)  /* set high watermark */
#define LWIP_SIOCGHIWAT  LWIP_IOR('s',  1, unsigned long)  /* get high watermark */
#define LWIP_SIOCSLOWAT  LWIP_IOW('s',  2, unsigned long)  /* set low watermark */
#define LWIP_SIOCGLOWAT  LWIP_IOR('s',  3, unsigned long)  /* get low watermark */
#define LWIP_SIOCATMARK  LWIP_IOR('s',  7, unsigned long)  /* at oob mark? */


/* commands for fnctl */
#define LWIP_F_GETFL 3
#define LWIP_F_SETFL 4

/* File status flags and file access modes for fnctl,
   these are bits in an int. */

#define LWIP_O_NONBLOCK  1 /* nonblocking I/O */

#define LWIP_O_NDELAY    LWIP_O_NONBLOCK /* same as O_NONBLOCK, for compatibility */
#define LWIP_O_RDONLY    2

#define LWIP_O_WRONLY    4


#define LWIP_O_RDWR      (O_RDONLY|O_WRONLY)

#define LWIP_SHUT_RD   0
#define LWIP_SHUT_WR   1
#define LWIP_SHUT_RDWR 2


/* Make FD_SETSIZE match NUM_SOCKETS in socket.c */
#define LWIP_FD_SETSIZE    MEMP_NUM_NETCONN
#define LWIP_SELECT_MAXNFDS (LWIP_FD_SETSIZE + LWIP_SOCKET_OFFSET)
#define LWIP_FDSETSAFESET(n, code) do { \
  if (((n) - LWIP_SOCKET_OFFSET < MEMP_NUM_NETCONN) && (((int)(n) - LWIP_SOCKET_OFFSET) >= 0)) { \
  code; }} while(0)
#define LWIP_FDSETSAFEGET(n, code) (((n) - LWIP_SOCKET_OFFSET < MEMP_NUM_NETCONN) && (((int)(n) - LWIP_SOCKET_OFFSET) >= 0) ?\
  (code) : 0)
#define LWIP_FD_SET(n, p)  LWIP_FDSETSAFESET(n, (p)->fd_bits[((n)-LWIP_SOCKET_OFFSET)/8] = (uint8_t)((p)->fd_bits[((n)-LWIP_SOCKET_OFFSET)/8] |  (1 << (((n)-LWIP_SOCKET_OFFSET) & 7))))
#define LWIP_FD_CLR(n, p)  LWIP_FDSETSAFESET(n, (p)->fd_bits[((n)-LWIP_SOCKET_OFFSET)/8] = (uint8_t)((p)->fd_bits[((n)-LWIP_SOCKET_OFFSET)/8] & ~(1 << (((n)-LWIP_SOCKET_OFFSET) & 7))))
#define LWIP_FD_ISSET(n,p) LWIP_FDSETSAFEGET(n, (p)->fd_bits[((n)-LWIP_SOCKET_OFFSET)/8] &   (1 << (((n)-LWIP_SOCKET_OFFSET) & 7)))
#define LWIP_FD_ZERO(p)    memset((void*)(p), 0, sizeof(*(p)))

struct LwipFdSet
{
    unsigned char fd_bits[(LWIP_FD_SETSIZE + 7) / 8];
};

#define LWIP_POLLIN     0x1
#define LWIP_POLLOUT    0x2
#define LWIP_POLLERR    0x4
#define LWIP_POLLNVAL   0x8
#define LWIP_POLLRDNORM 0x10
#define LWIP_POLLRDBAND 0x20
#define LWIP_POLLPRI    0x40
#define LWIP_POLLWRNORM 0x80
#define LWIP_POLLWRBAND 0x100
#define LWIP_POLLHUP    0x200

using LwipNfds = unsigned int;

struct LwipPolllfd
{
    int fd;
    short events;
    short revents;
};

/** LWIP_TIMEVAL_PRIVATE: if you want to use the struct timeval provided
 * by your system, set this to 0 and include <sys/time.h> in cc.h */
constexpr auto LWIP_TIMEVAL_PRIVATE = 1;

struct LwipTimeval
{
    long tv_sec; /* seconds */
    long tv_usec; /* and microseconds */
};



#define NUM_SOCKETS MEMP_NUM_NETCONN

/** This is overridable for the rare case where more than 255 threads
 * select on the same socket...
 */
#define SELWAIT_T uint8_t

union lwip_sock_lastdata {
  struct netbuf *netbuf;
  struct PacketContainer *pbuf;
};

/** Contains all internal pointers and states used for a socket */
struct lwip_sock
{
    /** sockets currently are built on netconns, each socket has one NetconnDesc */
    struct NetconnDesc* conn; /** data that was left from the previous read */
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
    uint8_t fd_used; /* status of pending close/delete actions */
    uint8_t fd_free_pending;
#define LWIP_SOCK_FD_FREE_TCP  1
#define LWIP_SOCK_FD_FREE_FREE 2
};

#define set_errno(err) do { if (err) { errno = (err); } } while(0)

struct lwip_sock* lwip_socket_dbg_get_socket(int fd);




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




#define lwip_socket_init() /* Compatibility define, no init needed. */
// void lwip_socket_thread_init(void); /* LWIP_NETCONN_SEM_PER_THREAD==1: initialize thread-local semaphore */
// void lwip_socket_thread_cleanup(void); /* LWIP_NETCONN_SEM_PER_THREAD==1: destroy thread-local semaphore */

// int lwip_accept(int s, struct LwipSockaddr* addr, LwipSocklen* addrlen);
// int lwip_bind(int s, const struct LwipSockaddr* name, LwipSocklen namelen);
// int lwip_shutdown(int s, int how);
// int lwip_getpeername(int s, struct LwipSockaddr* name, LwipSocklen* namelen);
// int lwip_getsockname(int s, struct LwipSockaddr* name, LwipSocklen* namelen);
// int lwip_getsockopt(int s, int level, int optname, void* optval, LwipSocklen* optlen);
// int lwip_setsockopt(int s, int level, int optname, const void* optval, LwipSocklen optlen);
// int lwip_close(int s);
// int lwip_connect(int s, const struct LwipSockaddr* name, LwipSocklen namelen);
// int lwip_listen(int s, int backlog);
// ssize_t lwip_recv(int s, void* mem, size_t len, int flags);
// ssize_t lwip_read(int s, void* mem, size_t len);
// ssize_t lwip_readv(int s, const struct LwipIovec* iov, int iovcnt);
// ssize_t lwip_recvfrom(int s, void* mem, size_t len, int flags,
//                       struct LwipSockaddr* from, LwipSocklen* fromlen);
// ssize_t lwip_recvmsg(int s, struct LwipMsgHdr* message, int flags);
// ssize_t lwip_send(int s, const void* dataptr, size_t size, int flags);
// ssize_t lwip_sendmsg(int s, const struct LwipMsgHdr* message, int flags);
// ssize_t lwip_sendto(int s, const void* dataptr, size_t size, int flags,
//                     const struct LwipSockaddr* to, LwipSocklen tolen);
// int lwip_socket(int domain, int type, int protocol);
// ssize_t lwip_write(int s, const void* dataptr, size_t size);
// ssize_t lwip_writev(int s, const struct LwipIovec* iov, int iovcnt);
//
// int lwip_select(int maxfdp1, LwipFdSet* readset, LwipFdSet* writeset, LwipFdSet* exceptset,
//                 struct timeval* timeout);
//
// #
// int lwip_poll(struct LwipPolllfd* fds, LwipNfds nfds, int timeout);
//
// int lwip_ioctl(int s, long cmd, void* argp);
// int lwip_fcntl(int s, int cmd, int val);
// const char* lwip_inet_ntop(int af, const void* src, char* dst, LwipSocklen size);
// int lwip_inet_pton(int af, const char* src, void* dst);

