#pragma once
#include "netif.h"
#include "packet_buffer.h"
#include "ip4.h"


//
// IGMP constants
//
constexpr auto kIgmpTtl = 1;
constexpr auto kIgmpMinlen = 8;
constexpr auto kRouterAlert = 0x9404U;
constexpr auto kRouterAlertlen = 4;


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

//
// igmp group structure - there is
// a list of groups for each interface
// these should really be linked from the interface, but
// if we keep them separate we will not affect the lwip original code
// too much
//
// There will be a group for the all systems group address but this
// will not run the state machine as it is used to kick off reports
// from all the other groups
//
struct IgmpGroup {
  /** next link */
  struct IgmpGroup *next;
  /** multicast address */
  Ip4Addr         group_address;
  /** signifies we were the last person to report */
  uint8_t               last_reporter_flag;
  /** current state of the group */
  uint8_t               group_state;
  /** timer for reporting, negative is OFF */
  uint16_t              timer;
  /** counter of simultaneous uses */
  uint8_t               use;
};

/*  Prototypes */
void   init_igmp_module(void);
LwipStatus  igmp_start(NetIfc*netif);
LwipStatus  igmp_stop(NetIfc*netif);
void   igmp_report_groups(NetIfc*netif);
struct IgmpGroup *igmp_lookfor_group(NetIfc*ifp, const Ip4Addr *addr);
void   igmp_input(struct PacketBuffer *p, NetIfc*inp, const Ip4Addr *dest);
LwipStatus  igmp_joingroup(const Ip4Addr *ifaddr, const Ip4Addr *groupaddr);
LwipStatus  igmp_joingroup_netif(NetIfc*netif, const Ip4Addr *groupaddr);
LwipStatus  igmp_leavegroup(const Ip4Addr *ifaddr, const Ip4Addr *groupaddr);
LwipStatus  igmp_leavegroup_netif(NetIfc*netif, const Ip4Addr *groupaddr);
void   igmp_tmr(void);

/** @ingroup igmp 
 * Get list head of IGMP groups for netif.
 * Note: The allsystems group IP is contained in the list as first entry.
 * @see @ref netif_set_igmp_mac_filter()
 */
inline IgmpGroup* netif_igmp_data(NetIfc* netif)
{
    return static_cast<IgmpGroup *>(netif->client_data[LWIP_NETIF_CLIENT_DATA_INDEX_IGMP]
    );
}

//
// END OF FILE
//