//
// file: opt.h
//

#pragma once
#define NOMINMAX
#include <algorithm>


constexpr auto MEM_SIZE = 1600;

constexpr auto MEMP_NUM_PBUF = 16;

constexpr auto MEMP_NUM_RAW_PCB = 4;

constexpr auto MEMP_NUM_UDP_PCB = 4;

constexpr auto MEMP_NUM_TCP_PCB = 5;

constexpr auto MEMP_NUM_TCP_PCB_LISTEN = 8;

constexpr auto MEMP_NUM_TCP_SEG = 16;

constexpr auto MEMP_NUM_ALTCP_PCB = MEMP_NUM_TCP_PCB;

constexpr auto MEMP_NUM_REASSDATA = 5;

constexpr auto MEMP_NUM_FRAG_PBUF = 15;

constexpr auto MEMP_NUM_ARP_QUEUE = 30;

constexpr auto MEMP_NUM_IGMP_GROUP = 8;

constexpr auto MEMP_NUM_SYS_TIMEOUT = 10;

constexpr auto MEMP_NUM_NETBUF = 2;

constexpr auto MEMP_NUM_NETCONN = 4;

constexpr auto MEMP_NUM_SELECT_CB = 4;

constexpr auto MEMP_NUM_TCPIP_MSG_API = 8;

constexpr auto MEMP_NUM_TCPIP_MSG_INPKT = 8;

constexpr auto MEMP_NUM_NETDB = 1;

constexpr auto MEMP_NUM_LOCALHOSTLIST = 1;

constexpr auto PBUF_POOL_SIZE = 16;

constexpr auto MEMP_NUM_API_MSG = MEMP_NUM_TCPIP_MSG_API;

constexpr auto MEMP_NUM_DNS_API_MSG = MEMP_NUM_TCPIP_MSG_API;

constexpr auto MEMP_NUM_SOCKET_SETGETSOCKOPT_DATA = MEMP_NUM_TCPIP_MSG_API;

constexpr auto MEMP_NUM_NETIFAPI_MSG = MEMP_NUM_TCPIP_MSG_API;

constexpr auto ARP_TABLE_SIZE = 10;

constexpr auto ARP_MAXAGE = 300;

constexpr auto ARP_QUEUE_LEN = 3;

constexpr auto ETH_PAD_SIZE = 0;

constexpr auto IP_REASS_MAXAGE = 15;

constexpr auto IP_REASS_MAX_PBUFS = 10;

constexpr auto IP_DEFAULT_TTL = 255;

constexpr auto ICMP_TTL = IP_DEFAULT_TTL;


constexpr auto RAW_TTL = IP_DEFAULT_TTL;

constexpr auto DNS_MAX_SERVERS = 2;

constexpr auto LWIP_DHCP_MAX_NTP_SERVERS = 1;
constexpr auto LWIP_DHCP_MAX_DNS_SERVERS = DNS_MAX_SERVERS;
constexpr auto LWIP_DHCP_AUTOIP_COOP_TRIES = 9;
constexpr auto DNS_TABLE_SIZE = 4;
constexpr auto DNS_MAX_NAME_LENGTH = 256;

constexpr auto DNS_MAX_RETRIES = 4;
constexpr auto LWIP_DNS_SECURE_NO_MULTIPLE_OUTSTANDING = 2;
constexpr auto LWIP_DNS_SECURE_RAND_SRC_PORT = 4;

constexpr auto UDP_TTL = IP_DEFAULT_TTL;

constexpr auto TCP_TTL = IP_DEFAULT_TTL;

constexpr auto TCP_MSS = 536;

constexpr auto TCP_WND = (4 * TCP_MSS);

constexpr auto TCP_MAXRTX = 12;

constexpr auto TCP_SYNMAXRTX = 6;
constexpr auto LWIP_TCP_MAX_SACK_NUM = 4;


constexpr auto TCP_SND_BUF = (2 * TCP_MSS);

constexpr auto TCP_SND_QUEUELEN = ((4 * (TCP_SND_BUF) + (TCP_MSS - 1)) / (TCP_MSS));
constexpr auto TCP_SNDLOWAT = (std::min)((std::max)(((TCP_SND_BUF) / 2), (2 * TCP_MSS) + 1), (TCP_SND_BUF) - 1);
constexpr auto TCP_SNDQUEUELOWAT = (std::max)(((TCP_SND_QUEUELEN) / 2), 5);
constexpr auto TCP_OOSEQ_MAX_BYTES = 0;

constexpr auto TCP_DEFAULT_LISTEN_BACKLOG = 0xff;
constexpr auto TCP_OVERSIZE = TCP_MSS;
constexpr auto TCP_WND_UPDATE_THRESHOLD = (std::min)((TCP_WND / 4), (TCP_MSS * 4));

constexpr auto LWIP_TCP_PCB_NUM_EXT_ARGS = 1;
constexpr auto PBUF_LINK_HLEN = (14 + ETH_PAD_SIZE);
constexpr auto PBUF_LINK_ENCAPSULATION_HLEN = 0;
constexpr auto PBUF_POOL_BUFSIZE = (TCP_MSS + 40 + PBUF_LINK_ENCAPSULATION_HLEN + PBUF_LINK_HLEN);

using LWIP_PBUF_REF_T = unsigned int;
constexpr auto LWIP_NUM_NETIF_CLIENT_DATA = 1;
constexpr auto LWIP_LOOPBACK_MAX_PBUFS = 0;
constexpr auto TCPIP_THREAD_NAME = "tcpip_thread";
constexpr auto TCPIP_THREAD_PRIO = 1;
constexpr auto TCPIP_MBOX_SIZE = 0;

constexpr auto SLIPIF_THREAD_NAME = "slipif_loop";
constexpr auto DEFAULT_THREAD_NAME = "lwIP";
constexpr auto RECV_BUFSIZE_DEFAULT = INT_MAX;
constexpr auto LWIP_TCP_CLOSE_TIMEOUT_MS_DEFAULT = 20000;
constexpr auto LWIP_IPV6_NUM_ADDRESSES = 3;

constexpr auto LWIP_ICMP6_DATASIZE = 8;
constexpr auto LWIP_ICMP6_HL = 255;
constexpr auto MEMP_NUM_MLD6_GROUP = 4;
constexpr auto MEMP_NUM_ND6_QUEUE = 20;
constexpr auto LWIP_ND6_NUM_NEIGHBORS = 10;
constexpr auto LWIP_ND6_NUM_DESTINATIONS = 10;
constexpr auto LWIP_ND6_NUM_PREFIXES = 5;
constexpr auto LWIP_ND6_NUM_ROUTERS = 3;
constexpr auto LWIP_ND6_MAX_MULTICAST_SOLICIT = 3;
constexpr auto LWIP_ND6_MAX_UNICAST_SOLICIT = 3;
constexpr auto LWIP_ND6_MAX_ANYCAST_DELAY_TIME = 1000;
constexpr auto LWIP_ND6_REACHABLE_TIME = 30000;
constexpr auto LWIP_ND6_RETRANS_TIMER = 1000;
constexpr auto LWIP_ND6_DELAY_FIRST_PROBE_TIME = 5000;
constexpr auto LWIP_ND6_TCP_REACHABILITY_HINTS = 1;
constexpr auto LWIP_ND6_RDNSS_MAX_DNS_SERVERS = 0;
constexpr auto LWIP_DHCP6_MAX_NTP_SERVERS = 1;

constexpr auto LWIP_DHCP6_MAX_DNS_SERVERS = DNS_MAX_SERVERS;

/* From http://www.iana.org/assignments/port-numbers:
   "The Dynamic and/or Private Ports are those from 49152 through 65535" */
constexpr auto LOCAL_PORT_RANGE_START = 0xc000;
constexpr auto LOCAL_PORT_RANGE_END = 0xffff;




//
// END OF FILE
//
