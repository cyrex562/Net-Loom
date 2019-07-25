#pragma once
#include <netif.h>
#include <packet_buffer.h>
#include <ip4.h>


//
// IGMP constants
//
constexpr auto IGMP_TTL = 1;
constexpr auto IGMP_MIN_LEN = 8;
constexpr auto ROUTER_ALERT = 0x9404U;
constexpr auto ROUTER_ALERT_LEN = 4;


//
// IGMP message types, including version number.
//
enum IgmpMsgType
{
    IGMP_MEMB_QUERY = 0x11,
    // Membership query         
    IGMP_V1_MEMB_REPORT = 0x12,
    // Ver. 1 membership report 
    IGMP_V2_MEMB_REPORT = 0x16,
    // Ver. 2 membership report 
    IGMP_LEAVE_GROUP = 0x17,
    // Leave-group message      
};


//
// Group  membership states
//
enum IgmpGroupMembershipState
{
    IGMP_GROUP_NON_MEMBER = 0,
    IGMP_GROUP_DELAYING_MEMBER = 1,
    IGMP_GROUP_IDLE_MEMBER = 2,
};


//
// IGMP packet format.
//
struct IgmpMsg
{
    uint8_t igmp_msgtype;
    uint8_t igmp_maxresp;
    uint16_t igmp_checksum;
    Ip4Addr igmp_group_address;
};

// IGMP timer
// Milliseconds
constexpr auto IGMP_TMR_INTERVAL = 100;
constexpr auto IGMP_V1_DELAYING_MEMBER_TMR = (1000 / IGMP_TMR_INTERVAL);
constexpr auto IGMP_JOIN_DELAYING_MEMBER_TMR = (500 / IGMP_TMR_INTERVAL);

// Compatibility defines (don't use for new code)
constexpr auto IGMP_DEL_MAC_FILTER = NETIF_DEL_MAC_FILTER;
constexpr auto IGMP_ADD_MAC_FILTER = NETIF_ADD_MAC_FILTER;



/*  Prototypes */
void   init_igmp_module(void);
LwipStatus  igmp_start(NetworkInterface*netif);
LwipStatus  igmp_stop(NetworkInterface*netif);
void   igmp_report_groups(NetworkInterface*netif);
// struct IgmpGroup *igmp_lookfor_group(NetworkInterface*ifp, const Ip4Addr *addr);
void   igmp_input(struct PacketBuffer *p, NetworkInterface*inp, const Ip4Addr *dest);
LwipStatus  igmp_joingroup(const Ip4Addr *ifaddr, const Ip4Addr *groupaddr);
LwipStatus  igmp_joingroup_netif(NetworkInterface*netif, const Ip4Addr *groupaddr);
LwipStatus  igmp_leavegroup(const Ip4Addr *ifaddr, const Ip4Addr *groupaddr);
LwipStatus  igmp_leavegroup_netif(NetworkInterface*netif, const Ip4Addr *groupaddr);
void   igmp_tmr(void);


//
// END OF FILE
//