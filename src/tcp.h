#pragma once
#define NOMINMAX
#include <algorithm>
#include <cstdint>
#include <icmp.h>
#include <ip.h>
#include <lwip_status.h>
#include <opt.h>
#include <tcpbase.h>
/* Length of the TCP header, excluding options. */
constexpr auto TCP_HDR_LEN = 20;
constexpr auto TCP_SND_QUEUE_LEN_OVFLW = (0xffffU - 3);

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
}; /* TCP header flags bits */
enum TcpFlags : uint8_t
{
    TCP_FIN = 0x01U,
    TCP_SYN = 0x02U,
    TCP_RST = 0x04U,
    TCP_PSH = 0x08U,
    TCP_ACK = 0x10U,
    TCP_URG = 0x20U,
    TCP_ECE = 0x40U,
    TCP_CWR = 0x80U,
    /* Valid TCP header flags */
};

constexpr uint16_t TCP_FLAGS = 0x3fU;
constexpr auto MAX_TCP_OPT_BYTES = 40; ///
///
///
inline size_t
get_tcp_hdr_len(TcpHdr* tcp_hdr, const bool get_bytes = false)
{
    if (get_bytes)
    {
        return (lwip_ntohs(tcp_hdr->_hdrlen_rsvd_flags) >> 12) << 2;
    }
    return lwip_ntohs(tcp_hdr->_hdrlen_rsvd_flags) >> 12;
} ///
///
///
inline uint8_t
tcph_flags(TcpHdr* phdr)
{
    return uint8_t((lwip_ntohs((phdr)->_hdrlen_rsvd_flags) & TCP_FLAGS));
} ///
///
///
inline void
TCPH_HDRLEN_SET(TcpHdr* phdr, const size_t len)
{
    (phdr)->_hdrlen_rsvd_flags = lwip_htons(((len) << 12) | tcph_flags(phdr));
}

inline void
set_tcp_hdr_flags(TcpHdr* phdr, const uint8_t flags)
{
    (phdr)->_hdrlen_rsvd_flags = (((phdr)->_hdrlen_rsvd_flags & pp_htons(~TCP_FLAGS)) |
        lwip_htons(flags));
}

inline void
TCPH_HDRLEN_FLAGS_SET(TcpHdr* phdr, const size_t len, const uint8_t flags)
{
    (phdr)->_hdrlen_rsvd_flags = uint16_t(lwip_htons(uint16_t((len) << 12) | (flags)));
}

inline void
TCPH_SET_FLAG(TcpHdr* phdr, uint8_t flags)
{
    (phdr)->_hdrlen_rsvd_flags = ((phdr)->_hdrlen_rsvd_flags | lwip_htons(flags));
}

inline void
TCPH_UNSET_FLAG(TcpHdr* phdr, uint8_t flags)
{
    (phdr)->_hdrlen_rsvd_flags = ((phdr)->_hdrlen_rsvd_flags & ~lwip_htons(flags));
}

struct TcpPcb;
struct TcpPcbListen;
/** Function prototype for tcp accept callback functions. Called when a new
      * connection can be accepted on a listening pcb.
      *
      * @param arg Additional argument to pass to the callback function (@see tcp_arg())
      * @param newpcb The new connection pcb
      * @param err An error code if there has been an error accepting.
      *            Only return ERR_ABRT if you have called tcp_abort from within the
      *            callback function!
      */
typedef LwipStatus
(*tcp_accept_fn)(void* arg, struct TcpPcb* newpcb, LwipStatus err);
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
typedef LwipStatus
(*tcp_recv_fn)(void* arg, struct TcpPcb* tpcb, struct PacketBuffer* p, LwipStatus err);
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
typedef LwipStatus
(*tcp_sent_fn)(void* arg, struct TcpPcb* tpcb, uint16_t len);
/** Function prototype for tcp poll callback functions. Called periodically as
      * specified by @see tcp_poll.
      *
      * @param arg Additional argument to pass to the callback function (@see tcp_arg())
      * @param tpcb tcp pcb
      * @return ERR_OK: try to send some data by calling tcp_output
      *            Only return ERR_ABRT if you have called tcp_abort from within the
      *            callback function!
      */
typedef LwipStatus
(*tcp_poll_fn)(void* arg, struct TcpPcb* tpcb);
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
typedef void
(*tcp_err_fn)(void* arg, LwipStatus err);
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
typedef LwipStatus
(*tcp_connected_fn)(void* arg, struct TcpPcb* tpcb, LwipStatus err);
#define SND_WND_SCALE(pcb, wnd) (((wnd) << (pcb)->snd_scale))

constexpr uint16_t MAX_TCP_WND16 = 0xFFFF;


inline uint16_t
TCPWND16(const uint16_t x)
{
    return (std::min)(x, MAX_TCP_WND16);
}

/// Increments a TcpWndSizeT and holds at max value rather than rollover
inline void
tcp_wnd_inc(TcpWndSize wnd, const unsigned inc)
{
    if (TcpWndSize(wnd + inc) >= wnd)
    {
        wnd = TcpWndSize(wnd + inc);
    }
    else
    {
        wnd = TcpWndSize(-1);
    }
}

constexpr auto TF_ACK_DELAY = 0x01U; /* Delayed ACK. */
constexpr auto TF_ACK_NOW = 0x02U; /* Immediate ACK. */
constexpr auto TF_INFR = 0x04U; /* In fast recovery. */
constexpr auto TF_CLOSEPEND = 0x08U;
/* If this is set, tcp_close failed to enqueue the FIN (retried in tcp_tmr) */
constexpr auto TF_RXCLOSED = 0x10U; /* rx closed by tcp_shutdown */
constexpr auto TF_FIN = 0x20U; /* Connection was closed locally (FIN segment enqueued). */
constexpr auto TF_NODELAY = 0x40U; /* Disable Nagle algorithm */
constexpr auto TF_NAGLEMEMERR = 0x80U;
/* nagle enabled, memerr, try to output to prevent delayed ACK to happen */
constexpr auto TF_WND_SCALE = 0x0100U; /* Window Scale option enabled */
constexpr auto TF_BACKLOGPEND = 0x0200U;
/* If this is set, a connection pcb has increased the backlog on its listener */
constexpr auto TF_TIMESTAMP = 0x0400U; /* Timestamp option enabled */
constexpr auto TF_RTO = 0x0800U;
/* RTO timer has fired, in-flight data moved to unsent and being retransmitted */
constexpr auto TF_SACK = 0x1000U; /* Selective ACKs enabled */
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
typedef void
(*tcp_extarg_callback_pcb_destroyed_fn)(uint8_t id, void* data);
/** Function prototype to transition arguments from a listening pcb to an accepted pcb
       *
       * @param id ext arg id (allocated via @ref tcp_ext_arg_alloc_id)
       * @param lpcb the listening pcb accepting a connection
       * @param cpcb the newly allocated connection pcb
       * @return ERR_OK if OK, any error if connection should be dropped
       */
typedef LwipStatus
(*tcp_extarg_callback_passive_open_fn)(uint8_t id,
                                       struct TcpPcbListen* lpcb,
                                       struct TcpPcb* cpcb);

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
}; // typedef uint16_t TcpFlags;
constexpr auto TCP_ALLFLAGS = 0xffffU;
struct TcpPcbListen; /** the TCP protocol control block for listening pcbs */
struct TcpPcbListen
{
    /** Common members of all PCB types */
    IpAddrInfo local_ip; /* Bound netif index */
    IpAddrInfo remote_ip;
    uint8_t netif_idx; /* Socket options */
    uint8_t so_options; /* Type Of Service */
    uint8_t tos; /* Time To Live */
    uint8_t ttl;
    NetworkInterface* netif_hints; /** Protocol specific PCB members */
    TcpPcbListen* next; /* for the linked list */
    void* callback_arg;
    TcpPcbExtArgs ext_args[LWIP_TCP_PCB_NUM_EXT_ARGS];
    enum TcpState state; /* TCP state */
    uint8_t prio; /* ports are in host byte order */
    uint16_t local_port; /* Function to call when a listener has been connected. */
    tcp_accept_fn accept_fn;
    uint8_t backlog;
    uint8_t accepts_pending;
};

struct TcpSeg;
struct NetIfcHint;

struct TcpPcb
{
    /** common PCB members */
    IpAddrInfo local_ip; /* Bound netif index */
    IpAddrInfo remote_ip;
    int netif_idx; /* Socket options */
    uint8_t so_options; /* Type Of Service */
    uint8_t tos; /* Time To Live */
    uint8_t ttl;
    NetIfcHint* netif_hints; /** protocol specific PCB members */
    TcpPcb* next; /* for the linked list */
    void* callback_arg;
    TcpPcbExtArgs ext_args[LWIP_TCP_PCB_NUM_EXT_ARGS];
    TcpState state; /* TCP state */
    uint8_t prio; /* ports are in host byte order */
    uint16_t local_port; /* ports are in host byte order */
    uint16_t remote_port;
    TcpFlags flags; /* the rest of the fields are in host byte order
               as we have to do some math with them */ /* Timers */
    uint8_t polltmr;

    uint8_t pollinterval;

    uint8_t last_timer;
    uint32_t tmr; /* receiver variables */
    uint32_t rcv_nxt; /* next seqno expected */
    TcpWndSize rcv_wnd; /* receiver window available */
    TcpWndSize rcv_ann_wnd; /* receiver window to announce */
    uint32_t rcv_ann_right_edge; /* announced right edge of window */
    /* SACK ranges to include in ACK packets (entry is invalid if left==right) */
    TcpSackRange rcv_sacks[LWIP_TCP_MAX_SACK_NUM]; /* Retransmission timer. */
    int16_t rtime;
    uint16_t mss; /* maximum segment size */
    /* RTT (round trip time) estimation variables */
    uint32_t rttest; /* RTT estimate in 500ms ticks */
    uint32_t rtseq; /* sequence number being timed */
    int16_t sa;

    int16_t sv; /* @see "Congestion Avoidance and Control" by Van Jacobson and Karels */
    int16_t rto; /* retransmission time-out (in ticks of TCP_SLOW_INTERVAL) */
    uint8_t nrtx; /* number of retransmissions */ /* fast retransmit/recovery */
    uint8_t dupacks;
    uint32_t lastack; /* Highest acknowledged seqno. */
    /* congestion avoidance/control variables */
    TcpWndSize cwnd;
    TcpWndSize ssthresh; /* first byte following last rto byte */
    uint32_t rto_end; /* sender variables */
    uint32_t snd_nxt; /* next new seqno to be sent */
    uint32_t snd_wl1;

    uint32_t snd_wl2;

    uint32_t snd_lbb; /* Sequence number of next byte to be buffered. */
    TcpWndSize snd_wnd; /* sender window */
    TcpWndSize snd_wnd_max; /* the maximum sender window announced by the remote host */
    TcpWndSize snd_buf; /* Available buffer space for sending (in bytes). */
    uint16_t snd_queuelen; /* Number of pbufs currently in the send buffer. */
    /* Extra bytes available at the end of the last pbuf in unsent. */
    size_t unsent_oversize;
    size_t bytes_acked; /* These are ordered by sequence number: */
    TcpSeg* unsent; /* Unsent (queued) segments. */
    TcpSeg* unacked; /* Sent but unacknowledged segments. */
    TcpSeg* ooseq; /* Received out of sequence segments. */
    PacketBuffer* refused_data;
    /* Data previously received but not yet taken by upper layer */
    TcpPcbListen* listener;
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

inline TcpWndSize
TCP_WND_MAX(TcpPcb* pcb)
{
    return TcpWndSize(((pcb)->flags & TF_WND_SCALE) ? TCP_WND : TCPWND16(TCP_WND));
}

inline unsigned int
RCV_WND_SCALE(TcpPcb* pcb, const unsigned int wnd)
{
    return wnd >> pcb->rcv_scale;
}

inline bool
tcp_sack_valid(const TcpPcb* pcb, const size_t idx)
{
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
}; // LwipStatus lwip_tcp_event(void* arg,
//                      struct TcpProtoCtrlBlk* pcb,
//                      enum LwipEvent,
//                      PacketBuffer* p,
//                      uint16_t size,
//                      LwipStatus err);
/* Application program's interface: */
struct TcpPcb*
tcp_new(void);
struct TcpPcb*
tcp_new_ip_type(IpAddrType type);
void
tcp_arg(struct TcpPcb* pcb, void* arg);
void
tcp_recv(struct TcpPcb* pcb, tcp_recv_fn recv);
void
tcp_sent(struct TcpPcb* pcb, tcp_sent_fn sent);
void
tcp_err(struct TcpPcb* pcb, tcp_err_fn err);
void
tcp_accept(struct TcpPcb* pcb, tcp_accept_fn accept);
void
tcp_poll(struct TcpPcb* pcb, tcp_poll_fn poll, uint8_t interval);

inline void
tcp_set_flags(TcpPcb* pcb, const uint16_t set_flags)
{
    (pcb)->flags = TcpFlags((pcb)->flags | (set_flags));
}

inline void
tcp_clear_flags(TcpPcb* pcb, const uint16_t clr_flags)
{
    (pcb)->flags = TcpFlags((pcb)->flags & TcpFlags(~(clr_flags) & TCP_ALLFLAGS));
}

inline bool
tcp_is_flag_set(TcpPcb* pcb, const uint16_t flag)
{
    return (((pcb)->flags & (flag)) != 0);
}

inline uint32_t
tcp_mss(TcpPcb* pcb)
{
    return (((pcb)->flags & TF_TIMESTAMP) ? ((pcb)->mss - 12) : (pcb)->mss);
} /** @ingroup tcp_raw */
#define          tcp_sndbuf(pcb)          (TCPWND16((pcb)->snd_buf))
/** @ingroup tcp_raw */
#define          tcp_sndqueuelen(pcb)     ((pcb)->snd_queuelen)
/** @ingroup tcp_raw */
#define          tcp_nagle_disable(pcb)   tcp_set_flags(pcb, TF_NODELAY)
/** @ingroup tcp_raw */
#define          tcp_nagle_enable(pcb)    tcp_clear_flags(pcb, TF_NODELAY)
/** @ingroup tcp_raw */
#define          tcp_nagle_disabled(pcb)  tcp_is_flag_set(pcb, TF_NODELAY)

inline uint32_t
tcp_backlog_set(TcpPcb* pcb, uint32_t new_backlog)
{
    return reinterpret_cast<struct TcpPcbListen*>(pcb)->backlog = ((new_backlog)
                                                                ? (new_backlog)
                                                                : 1);
}

void
tcp_backlog_delayed(struct TcpPcb* pcb);
void
tcp_backlog_accepted(struct TcpPcb* pcb);
void
tcp_recved(struct TcpPcb* pcb, uint16_t len);
LwipStatus
tcp_bind(struct TcpPcb* pcb, const IpAddrInfo* ipaddr, uint16_t port);
void
tcp_bind_netif(struct TcpPcb* pcb, const NetworkInterface** netif);
LwipStatus
tcp_connect(struct TcpPcb* pcb,
            const IpAddrInfo* ipaddr,
            uint16_t port,
            tcp_connected_fn connected);
struct TcpPcb*
tcp_listen_with_backlog_and_err(struct TcpPcb* pcb, uint8_t backlog, LwipStatus* err);
struct TcpPcb*
tcp_listen_with_backlog(struct TcpPcb* pcb, uint8_t backlog); /** @ingroup tcp_raw */
#define          tcp_listen(pcb) tcp_listen_with_backlog(pcb, TCP_DEFAULT_LISTEN_BACKLOG)
void
tcp_abort(struct TcpPcb* pcb);
LwipStatus
tcp_close(struct TcpPcb* pcb);
LwipStatus
tcp_shutdown(struct TcpPcb* pcb, int shut_rx, int shut_tx);
LwipStatus
tcp_write(struct TcpPcb* pcb, const void* dataptr, size_t len, uint8_t apiflags);
void
tcp_setprio(struct TcpPcb* pcb, uint8_t prio);
LwipStatus
tcp_output(struct TcpPcb* pcb);
LwipStatus
tcp_tcp_get_tcp_addrinfo(struct TcpPcb* pcb, int local, IpAddrInfo* addr, uint16_t* port);
#define tcp_dbg_get_tcp_state(pcb) ((pcb)->state)
/* for compatibility with older implementation */
#define tcp_new_ip6() tcp_new_ip_type(IPADDR_TYPE_V6)
uint8_t
tcp_ext_arg_alloc_id(void);
void
tcp_ext_arg_set_callbacks(struct TcpPcb* pcb,
                          uint8_t id,
                          const struct tcp_ext_arg_callbacks* const callbacks);
void
tcp_ext_arg_set(struct TcpPcb* pcb, uint8_t id, void* arg);
void*
tcp_ext_arg_get(const struct TcpPcb* pcb, uint8_t id);
void
pbuf_free_ooseq(TcpPcb* tcp_active_pcbs);

void pbuf_pool_is_empty(void);

//
// END OF FILE
//