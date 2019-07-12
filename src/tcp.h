#pragma once
#include "lwip_error.h"
#include "icmp.h"
#include "ip.h"
#include "opt.h"
#include "packet_buffer.h"
#include "tcpbase.h"
#include <cstdint>

/* Length of the TCP header, excluding options. */
constexpr auto kTcpHdrLen = 20;
constexpr auto kTcpSndQueueLenOvflw = (0xffffU - 3);

/* Fields are (of course) in network byte order.
* Some fields are converted to host byte order in tcp_input().
*/
struct TcpHdr
{
    uint16_t src;
    uint16_t dest;
    uint32_t seqno;
    uint32_t ackno;
    uint16_t _hdrlen_rsvd_flags;
    uint16_t wnd;
    uint16_t chksum;
    uint16_t urgp;
}; 


/* TCP header flags bits */
constexpr auto TCP_FIN = 0x01U;
constexpr auto TCP_SYN = 0x02U;
constexpr auto kTcpRst = 0x04U;
constexpr auto kTcpPsh = 0x08U;
constexpr auto kTcpAck = 0x10U;
constexpr auto kTcpUrg = 0x20U;
constexpr auto kTcpEce = 0x40U;
constexpr auto kTcpCwr = 0x80U; /* Valid TCP header flags */
constexpr auto TCP_FLAGS = 0x3fU;
constexpr auto kTcpMaxOptionBytes = 40;

inline size_t TcphHdrlen(TcpHdr* phdr) {
    return lwip_ntohs(phdr->_hdrlen_rsvd_flags) >> 12;
}

inline size_t TcphHdrlenBytes(TcpHdr* phdr) {
    return TcphHdrlen(phdr) << 2;
}



#define TCPH_FLAGS(phdr)  ((uint8_t)((lwip_ntohs((phdr)->_hdrlen_rsvd_flags) & TCP_FLAGS)))
#define TCPH_HDRLEN_SET(phdr, len) (phdr)->_hdrlen_rsvd_flags = lwip_htons(((len) << 12) | TCPH_FLAGS(phdr))
#define TCPH_FLAGS_SET(phdr, flags) (phdr)->_hdrlen_rsvd_flags = (((phdr)->_hdrlen_rsvd_flags & PpHtons(~TCP_FLAGS)) | lwip_htons(flags))
#define TCPH_HDRLEN_FLAGS_SET(phdr, len, flags) (phdr)->_hdrlen_rsvd_flags = (uint16_t)(lwip_htons((uint16_t)((len) << 12) | (flags)))
#define TCPH_SET_FLAG(phdr, flags) (phdr)->_hdrlen_rsvd_flags = ((phdr)->_hdrlen_rsvd_flags | lwip_htons(flags))
#define TCPH_UNSET_FLAG(phdr, flags) (phdr)->_hdrlen_rsvd_flags = ((phdr)->_hdrlen_rsvd_flags & ~lwip_htons(flags))
#ifdef __cplusplus
extern "C" {
#endif
    struct TcpProtoCtrlBlk;
    struct tcp_pcb_listen;
    /** Function prototype for tcp accept callback functions. Called when a new
        * connection can be accepted on a listening pcb.
        *
        * @param arg Additional argument to pass to the callback function (@see tcp_arg())
        * @param newpcb The new connection pcb
        * @param err An error code if there has been an error accepting.
        *            Only return ERR_ABRT if you have called tcp_abort from within the
        *            callback function!
        */
    typedef LwipError(*tcp_accept_fn)(void* arg, struct TcpProtoCtrlBlk* newpcb, LwipError err);
    /** Function prototype for tcp receive callback functions. Called when data has
        * been received.
        *
        * @param arg Additional argument to pass to the callback function (@see tcp_arg())
        * @param tpcb The connection pcb which received data
        * @param p The received data (or NULL when the connection has been closed!)
        * @param err An error code if there has been an error receiving
        *            Only return ERR_ABRT if you have called tcp_abort from within the
        *            callback function!
        */
    typedef LwipError(*tcp_recv_fn)(void* arg, struct TcpProtoCtrlBlk* tpcb, struct PacketBuffer* p, LwipError err);
    /** Function prototype for tcp sent callback functions. Called when sent data has
        * been acknowledged by the remote side. Use it to free corresponding resources.
        * This also means that the pcb has now space available to send new data.
        *
        * @param arg Additional argument to pass to the callback function (@see tcp_arg())
        * @param tpcb The connection pcb for which data has been acknowledged
        * @param len The amount of bytes acknowledged
        * @return ERR_OK: try to send some data by calling tcp_output
        *            Only return ERR_ABRT if you have called tcp_abort from within the
        *            callback function!
        */
    typedef LwipError(*tcp_sent_fn)(void* arg, struct TcpProtoCtrlBlk* tpcb, uint16_t len);
    /** Function prototype for tcp poll callback functions. Called periodically as
        * specified by @see tcp_poll.
        *
        * @param arg Additional argument to pass to the callback function (@see tcp_arg())
        * @param tpcb tcp pcb
        * @return ERR_OK: try to send some data by calling tcp_output
        *            Only return ERR_ABRT if you have called tcp_abort from within the
        *            callback function!
        */
    typedef LwipError(*tcp_poll_fn)(void* arg, struct TcpProtoCtrlBlk* tpcb);
    /** Function prototype for tcp error callback functions. Called when the pcb
        * receives a RST or is unexpectedly closed for any other reason.
        *
        * @note The corresponding pcb is already freed when this callback is called!
        *
        * @param arg Additional argument to pass to the callback function (@see tcp_arg())
        * @param err Error code to indicate why the pcb has been closed
        *            ERR_ABRT: aborted through tcp_abort or by a TCP timer
        *            ERR_RST: the connection was reset by the remote host
        */
    typedef void (*tcp_err_fn)(void* arg, LwipError err);
    /** Function prototype for tcp connected callback functions. Called when a pcb
        * is connected to the remote side after initiating a connection attempt by
        * calling tcp_connect().
        *
        * @param arg Additional argument to pass to the callback function (@see tcp_arg())
        * @param tpcb The connection pcb which is connected
        * @param err An unused error code, always ERR_OK currently ;-) @todo!
        *            Only return ERR_ABRT if you have called tcp_abort from within the
        *            callback function!
        *
        * @note When a connection attempt fails, the error callback is currently called!
        */
    typedef LwipError(*tcp_connected_fn)(void* arg, struct TcpProtoCtrlBlk* tpcb, LwipError err);
#define RCV_WND_SCALE(pcb, wnd) (((wnd) >> (pcb)->rcv_scale))
#define SND_WND_SCALE(pcb, wnd) (((wnd) << (pcb)->snd_scale))
#define TCPWND16(x)             ((uint16_t)LWIP_MIN((x), 0xFFFF))
#define TCP_WND_MAX(pcb)        ((TcpWndSizeT)(((pcb)->flags & TF_WND_SCALE) ? TCP_WND : TCPWND16(TCP_WND)))
    /* Increments a TcpWndSizeT and holds at max value rather than rollover */
#define TCP_WND_INC(wnd, inc)   do { \
                                  if ((TcpWndSizeT)(wnd + inc) >= wnd) { \
                                    wnd = (TcpWndSizeT)(wnd + inc); \
                                  } else { \
                                    wnd = (TcpWndSizeT)-1; \
                                  } \
                                } while(0)
#define TF_ACK_DELAY   0x01U   /* Delayed ACK. */
#define TF_ACK_NOW     0x02U   /* Immediate ACK. */
#define TF_INFR        0x04U   /* In fast recovery. */
#define TF_CLOSEPEND   0x08U   /* If this is set, tcp_close failed to enqueue the FIN (retried in tcp_tmr) */
#define TF_RXCLOSED    0x10U   /* rx closed by tcp_shutdown */
#define TF_FIN         0x20U   /* Connection was closed locally (FIN segment enqueued). */
#define TF_NODELAY     0x40U   /* Disable Nagle algorithm */
#define TF_NAGLEMEMERR 0x80U   /* nagle enabled, memerr, try to output to prevent delayed ACK to happen */
#define TF_WND_SCALE   0x0100U /* Window Scale option enabled */
#define TF_BACKLOGPEND 0x0200U /* If this is set, a connection pcb has increased the backlog on its listener */
#define TF_TIMESTAMP   0x0400U   /* Timestamp option enabled */
#define TF_RTO         0x0800U /* RTO timer has fired, in-flight data moved to unsent and being retransmitted */
#define TF_SACK        0x1000U /* Selective ACKs enabled */

/** SACK ranges to include in ACK packets.
 * SACK entry is invalid if left==right. */
    struct TcpSackRange
    {
        /** Left edge of the SACK: the first acknowledged sequence number. */
        uint32_t left;
        /** Right edge of the SACK: the last acknowledged sequence number +1 (so first NOT acknowledged). */
        uint32_t right;
    }; /** Function prototype for deallocation of arguments. Called *just before* the
         * pcb is freed, so don't expect to be able to do anything with this pcb!
         *
         * @param id ext arg id (allocated via @ref tcp_ext_arg_alloc_id)
         * @param data pointer to the data (set via @ref tcp_ext_arg_set before)
         */
    typedef void (*tcp_extarg_callback_pcb_destroyed_fn)(uint8_t id, void* data);
    /** Function prototype to transition arguments from a listening pcb to an accepted pcb
        *
        * @param id ext arg id (allocated via @ref tcp_ext_arg_alloc_id)
        * @param lpcb the listening pcb accepting a connection
        * @param cpcb the newly allocated connection pcb
        * @return ERR_OK if OK, any error if connection should be dropped
        */
    typedef LwipError(*tcp_extarg_callback_passive_open_fn)(uint8_t id,
        struct tcp_pcb_listen* lpcb,
        struct TcpProtoCtrlBlk* cpcb);

    /** A table of callback functions that is invoked for ext arguments */
    struct tcp_ext_arg_callbacks
    {
        /** @ref tcp_extarg_callback_pcb_destroyed_fn */
        tcp_extarg_callback_pcb_destroyed_fn destroy;
        /** @ref tcp_extarg_callback_passive_open_fn */
        tcp_extarg_callback_passive_open_fn passive_open;
    };

    constexpr auto kLwipTcpPcbNumExtArgIdInvalid = 0xFF;

    /* This is the structure for ext args in tcp pcbs (used as array) */
    struct TcpPcbExtArgs
    {
        struct tcp_ext_arg_callbacks* callbacks;
        void* data;
    };

    typedef uint16_t TcpFlags;
    constexpr auto TCP_ALLFLAGS = 0xffffU;
    struct tcp_pcb_listen; /** the TCP protocol control block for listening pcbs */
    struct tcp_pcb_listen
    {
        /** Common members of all PCB types */
        IpAddr local_ip; /* Bound netif index */
        uint8_t netif_idx; /* Socket options */
        uint8_t so_options; /* Type Of Service */
        uint8_t tos; /* Time To Live */
        uint8_t ttl;
        struct netif_hint netif_hints; /** Protocol specific PCB members */
        tcp_pcb_listen* next; /* for the linked list */
        void* callback_arg;
        struct TcpPcbExtArgs ext_args[LWIP_TCP_PCB_NUM_EXT_ARGS];
        enum TcpState state; /* TCP state */
        uint8_t prio; /* ports are in host byte order */
        uint16_t local_port; /* Function to call when a listener has been connected. */
        tcp_accept_fn accept_fn;
        uint8_t backlog;
        uint8_t accepts_pending;
    };


  
struct TcpProtoCtrlBlk
{
    /** common PCB members */
    IpAddr local_ip; /* Bound netif index */
    uint8_t netif_idx; /* Socket options */
    uint8_t so_options; /* Type Of Service */
    uint8_t tos; /* Time To Live */
    uint8_t ttl;
    struct netif_hint netif_hints; /** protocol specific PCB members */
    tcp_pcb_listen* next; /* for the linked list */
    void* callback_arg;
    struct TcpPcbExtArgs ext_args[LWIP_TCP_PCB_NUM_EXT_ARGS];
    enum TcpState state; /* TCP state */
    uint8_t prio; /* ports are in host byte order */
    uint16_t local_port; /* ports are in host byte order */
    uint16_t remote_port;
    TcpFlags flags; /* the rest of the fields are in host byte order
           as we have to do some math with them */ /* Timers */
    uint8_t polltmr, pollinterval;
    uint8_t last_timer;
    uint32_t tmr; /* receiver variables */
    uint32_t rcv_nxt; /* next seqno expected */
    TcpWndSizeT rcv_wnd; /* receiver window available */
    TcpWndSizeT rcv_ann_wnd; /* receiver window to announce */
    uint32_t rcv_ann_right_edge; /* announced right edge of window */
    /* SACK ranges to include in ACK packets (entry is invalid if left==right) */
    struct TcpSackRange rcv_sacks[LWIP_TCP_MAX_SACK_NUM];
/* Retransmission timer. */
    int16_t rtime;
    uint16_t mss; /* maximum segment size */
    /* RTT (round trip time) estimation variables */
    uint32_t rttest; /* RTT estimate in 500ms ticks */
    uint32_t rtseq; /* sequence number being timed */
    int16_t sa, sv;
    /* @see "Congestion Avoidance and Control" by Van Jacobson and Karels */
    int16_t rto; /* retransmission time-out (in ticks of TCP_SLOW_INTERVAL) */
    uint8_t nrtx; /* number of retransmissions */ /* fast retransmit/recovery */
    uint8_t dupacks;
    uint32_t lastack; /* Highest acknowledged seqno. */
    /* congestion avoidance/control variables */
    TcpWndSizeT cwnd;
    TcpWndSizeT ssthresh; /* first byte following last rto byte */
    uint32_t rto_end; /* sender variables */
    uint32_t snd_nxt; /* next new seqno to be sent */
    uint32_t snd_wl1, snd_wl2; /* Sequence and acknowledgement numbers of last
                             window update. */
    uint32_t snd_lbb; /* Sequence number of next byte to be buffered. */
    TcpWndSizeT snd_wnd; /* sender window */
    TcpWndSizeT snd_wnd_max;
    /* the maximum sender window announced by the remote host */
    TcpWndSizeT snd_buf; /* Available buffer space for sending (in bytes). */
    uint16_t snd_queuelen; /* Number of pbufs currently in the send buffer. */
    /* Extra bytes available at the end of the last pbuf in unsent. */
    uint16_t unsent_oversize;
    TcpWndSizeT bytes_acked; /* These are ordered by sequence number: */
    struct tcp_seg* unsent; /* Unsent (queued) segments. */
    struct tcp_seg* unacked; /* Sent but unacknowledged segments. */
    struct tcp_seg* ooseq; /* Received out of sequence segments. */
    struct PacketBuffer* refused_data;
    /* Data previously received but not yet taken by upper layer */
    struct tcp_pcb_listen* listener;
    /* Function to be called when more send buffer space is available. */
    tcp_sent_fn sent; /* Function to be called when (in-sequence) data has arrived. */
    tcp_recv_fn recv; /* Function to be called when a connection has been set up. */
    tcp_connected_fn connected; /* Function which is called periodically. */
    tcp_poll_fn poll; /* Function to be called whenever a fatal error occurs. */
    tcp_err_fn errf;
    uint32_t ts_lastacksent;
    uint32_t ts_recent; /* idle time before KEEPALIVE is sent */
    uint32_t keep_idle;
    uint32_t keep_intvl;
    uint32_t keep_cnt; /* Persist timer counter */
    uint8_t persist_cnt; /* Persist timer back-off */
    uint8_t persist_backoff; /* Number of persist probes */
    uint8_t persist_probe; /* KEEPALIVE counter */
    uint8_t keep_cnt_sent;
    uint8_t snd_scale;
    uint8_t rcv_scale;
};

inline bool LwipTcpSackValid(TcpProtoCtrlBlk* pcb, const size_t idx) {
    return pcb->rcv_sacks[idx].left != pcb->rcv_sacks[idx].right;
}

enum LwipEvent
{
    LWIP_EVENT_ACCEPT,
    LWIP_EVENT_SENT,
    LWIP_EVENT_RECV,
    LWIP_EVENT_CONNECTED,
    LWIP_EVENT_POLL,
    LWIP_EVENT_ERR
};

// LwipError lwip_tcp_event(void* arg,
//                      struct TcpProtoCtrlBlk* pcb,
//                      enum LwipEvent,
//                      struct pbuf* p,
//                      uint16_t size,
//                      LwipError err);
    
    
    /* Application program's interface: */
struct TcpProtoCtrlBlk* tcp_new(void);
struct TcpProtoCtrlBlk* tcp_new_ip_type(uint8_t type);
void tcp_arg(struct TcpProtoCtrlBlk* pcb, void* arg);
void tcp_recv(struct TcpProtoCtrlBlk* pcb, tcp_recv_fn recv);
void tcp_sent(struct TcpProtoCtrlBlk* pcb, tcp_sent_fn sent);
void tcp_err(struct TcpProtoCtrlBlk* pcb, tcp_err_fn err);
void tcp_accept(struct TcpProtoCtrlBlk* pcb, tcp_accept_fn accept);
void tcp_poll(struct TcpProtoCtrlBlk* pcb, tcp_poll_fn poll, uint8_t interval);

inline void tcp_set_flags(TcpProtoCtrlBlk* pcb, const uint16_t set_flags)
{
    (pcb)->flags = TcpFlags((pcb)->flags | (set_flags));
}

inline void tcp_clear_flags(TcpProtoCtrlBlk* pcb, const uint16_t clr_flags)
{
    (pcb)->flags = TcpFlags((pcb)->flags & TcpFlags(~(clr_flags) & TCP_ALLFLAGS));
}

inline bool tcp_is_flag_set(TcpProtoCtrlBlk* pcb, const uint16_t flag)
{
    return (((pcb)->flags & (flag)) != 0);
}

inline uint32_t tcp_mss(TcpProtoCtrlBlk* pcb)
{
    return (((pcb)->flags & TF_TIMESTAMP) ? ((pcb)->mss - 12) : (pcb)->mss);
}

/** @ingroup tcp_raw */
#define          tcp_sndbuf(pcb)          (TCPWND16((pcb)->snd_buf))
/** @ingroup tcp_raw */
#define          tcp_sndqueuelen(pcb)     ((pcb)->snd_queuelen)
/** @ingroup tcp_raw */
#define          tcp_nagle_disable(pcb)   tcp_set_flags(pcb, TF_NODELAY)
/** @ingroup tcp_raw */
#define          tcp_nagle_enable(pcb)    tcp_clear_flags(pcb, TF_NODELAY)
/** @ingroup tcp_raw */
#define          tcp_nagle_disabled(pcb)  tcp_is_flag_set(pcb, TF_NODELAY)

inline uint32_t tcp_backlog_set(TcpProtoCtrlBlk* pcb, uint32_t new_backlog)
{
    reinterpret_cast<struct tcp_pcb_listen *>(pcb)->backlog = ((new_backlog)
                                                                   ? (new_backlog)
                                                                   : 1);
}


void tcp_backlog_delayed(struct TcpProtoCtrlBlk* pcb);


void tcp_backlog_accepted(struct TcpProtoCtrlBlk* pcb);


void tcp_recved(struct TcpProtoCtrlBlk* pcb, uint16_t len);
LwipError tcp_bind(struct TcpProtoCtrlBlk* pcb, const IpAddr* ipaddr, uint16_t port);
void tcp_bind_netif(struct TcpProtoCtrlBlk* pcb, const struct NetIfc* netif);
LwipError tcp_connect(struct TcpProtoCtrlBlk* pcb,
                  const IpAddr* ipaddr,
                  uint16_t port,
                  tcp_connected_fn connected);
struct TcpProtoCtrlBlk* tcp_listen_with_backlog_and_err(struct TcpProtoCtrlBlk* pcb,
                                                uint8_t backlog,
                                                LwipError* err);
struct TcpProtoCtrlBlk* tcp_listen_with_backlog(struct TcpProtoCtrlBlk* pcb, uint8_t backlog);
/** @ingroup tcp_raw */
#define          tcp_listen(pcb) tcp_listen_with_backlog(pcb, TCP_DEFAULT_LISTEN_BACKLOG)
void tcp_abort(struct TcpProtoCtrlBlk* pcb);
LwipError tcp_close(struct TcpProtoCtrlBlk* pcb);
LwipError tcp_shutdown(struct TcpProtoCtrlBlk* pcb, int shut_rx, int shut_tx);
LwipError tcp_write(struct TcpProtoCtrlBlk* pcb, const void* dataptr, uint16_t len, uint8_t apiflags);
void tcp_setprio(struct TcpProtoCtrlBlk* pcb, uint8_t prio);
LwipError tcp_output(struct TcpProtoCtrlBlk* pcb);
LwipError tcp_tcp_get_tcp_addrinfo(struct TcpProtoCtrlBlk* pcb,
                               int local,
                               IpAddr* addr,
                               uint16_t* port);
#define tcp_dbg_get_tcp_state(pcb) ((pcb)->state)
/* for compatibility with older implementation */
#define tcp_new_ip6() tcp_new_ip_type(IPADDR_TYPE_V6)
uint8_t tcp_ext_arg_alloc_id(void);
void tcp_ext_arg_set_callbacks(struct TcpProtoCtrlBlk* pcb,
                               uint8_t id,
                               const struct tcp_ext_arg_callbacks* const callbacks);
void tcp_ext_arg_set(struct TcpProtoCtrlBlk* pcb, uint8_t id, void* arg);
void* tcp_ext_arg_get(const struct TcpProtoCtrlBlk* pcb, uint8_t id);
#ifdef __cplusplus
}
#endif
