/**
 * @file
 * Multicast listener discovery
 *
 * @defgroup mld6 MLD6
 * @ingroup ip6
 * Multicast listener discovery for IPv6. Aims to be compliant with RFC 2710.
 * No support for MLDv2.\n
 * Note: The allnodes (ff01::1, ff02::1) group is assumed be received by your 
 * netif since it must always be received for correct IPv6 operation (e.g. SLAAC).
 * Ensure the netif filters are configured accordingly!\n
 * The netif flags also need NETIF_FLAG_MLD6 flag set to enable MLD6 on a
 * netif ("netif->flags |= NETIF_FLAG_MLD6;").\n
 * To be called from TCPIP thread.
 */

/*
 * Copyright (c) 2010 Inico Technologies Ltd.
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
 * Author: Ivan Delamer <delamer@inicotech.com>
 *
 *
 * Please coordinate changes and requests with Ivan Delamer
 * <delamer@inicotech.com>
 */

/* Based on igmp.c implementation of igmp v2 protocol */

#include "netloom_config.h"
#include "mld6.h"
#include "mld6.h"
#include "icmp6.h"
#include "ip6.h"
#include "ip6_addr.h"
#include "ip.h"
#include "inet_chksum.h"
#include "packet.h"
#include "network_interface.h"
#include <cstring>


/*
 * MLD constants
 */
#define MLD6_HL                           1
#define MLD6_JOIN_DELAYING_MEMBER_TMR_MS  (500)

#define MLD6_GROUP_NON_MEMBER             0
#define MLD6_GROUP_DELAYING_MEMBER        1
#define MLD6_GROUP_IDLE_MEMBER            2

/* Forward declarations. */
static struct MldGroup *mld6_new_group(NetworkInterface*ifp, const Ip6Addr *addr);
static NsStatus mld6_remove_group(NetworkInterface*netif, struct MldGroup *group);
static void mld6_delayed_report(struct MldGroup *group, uint16_t maxresp);
static void mld6_send(NetworkInterface*netif, struct MldGroup *group, uint8_t type);


/**
 * Stop MLD processing on interface
 *
 * @param netif network interface on which stop MLD processing
 */
NsStatus
mld6_stop(NetworkInterface*netif)
{
  struct MldGroup *group = ((MldGroup *)netif_get_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_MLD6));

  netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_MLD6, nullptr);

  while (group != nullptr) {
    struct MldGroup *next = group->next; /* avoid use-after-free below */

    /* disable the group at the MAC level */
    if (netif->mld_mac_filter != nullptr) {
      netif->mld_mac_filter(netif, &(group->group_address), NETIF_DEL_MAC_FILTER);
    }

    /* free group */
    delete group;

    /* move to "next" */
    group = next;
  }
  return STATUS_SUCCESS;
}

/**
 * Report MLD memberships for this interface
 *
 * @param netif network interface on which report MLD memberships
 */
void
mld6_report_groups(NetworkInterface*netif)
{
  struct MldGroup *group = ((MldGroup *)netif_get_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_MLD6));

  while (group != nullptr) {
    mld6_delayed_report(group, MLD6_JOIN_DELAYING_MEMBER_TMR_MS);
    group = group->next;
  }
}

/**
 * Search for a group that is joined on a netif
 *
 * @param ifp the network interface for which to look
 * @param addr the group ipv6 address to search for
 * @return a MldGroup* if the group has been found,
 *         NULL if the group wasn't found.
 */
struct MldGroup *
mld6_lookfor_group(NetworkInterface*ifp, const Ip6Addr *addr)
{
  struct MldGroup *group = ((MldGroup *)netif_get_client_data(ifp, LWIP_NETIF_CLIENT_DATA_INDEX_MLD6));

  while (group != nullptr) {
    if (ip6_addr_equal(&(group->group_address), addr)) {
      return group;
    }
    group = group->next;
  }

  return nullptr;
}


/**
 * create a new group
 *
 * @param ifp the network interface for which to create
 * @param addr the new group ipv6
 * @return a MldGroup*,
 *         NULL on memory error.
 */
static struct MldGroup *
mld6_new_group(NetworkInterface*ifp, const Ip6Addr *addr)
{
    // group = (MldGroup *)memp_malloc(MEMP_MLD6_GROUP);
    struct MldGroup* group = new MldGroup;
  if (group != nullptr) {
    set_ip6_addr(&(group->group_address), addr);
    group->timer              = 0; /* Not running */
    group->group_state        = MLD6_GROUP_IDLE_MEMBER;
    group->last_reporter_flag = 0;
    group->use                = 0;
    group->next               = ((MldGroup *)netif_get_client_data(ifp, LWIP_NETIF_CLIENT_DATA_INDEX_MLD6));

    netif_set_client_data(ifp, LWIP_NETIF_CLIENT_DATA_INDEX_MLD6, group);
  }

  return group;
}

/**
 * Remove a group from the mld_group_list, but do not free it yet
 *
 * @param group the group to remove
 * @return ERR_OK if group was removed from the list, an LwipStatus otherwise
 */
static NsStatus
mld6_remove_group(NetworkInterface*netif, struct MldGroup *group)
{
  NsStatus err = STATUS_SUCCESS;

  /* Is it the first group? */
  if (((MldGroup *)netif_get_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_MLD6)) == group) {
    netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_MLD6, group->next);
  } else {
    /* look for group further down the list */
    struct MldGroup *tmpGroup;
    for (tmpGroup = ((MldGroup *)netif_get_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_MLD6)); tmpGroup != nullptr; tmpGroup = tmpGroup->next) {
      if (tmpGroup->next == group) {
        tmpGroup->next = group->next;
        break;
      }
    }
    /* Group not find group */
    if (tmpGroup == nullptr) {
      err = STATUS_E_INVALID_ARG;
    }
  }

  return err;
}


/**
 * Process an input MLD message. Called by icmp6_input.
 *
 * @param pkt_buf the mld packet, p->payload pointing to the icmpv6 header
 * @param in_netif the netif on which this packet was received
 */
void mld6_input(struct PacketContainer* pkt_buf, NetworkInterface* in_netif)
{
    struct MldGroup* group;
    Ip6Addr* curr_dst_addr = nullptr; /* Check that mld header fits in packet. */
    if (pkt_buf->len < sizeof(struct MldHeader))
    {
        /* @todo debug message */
        free_pkt_buf(pkt_buf);
        return;
    }
    struct MldHeader* mld_hdr = (struct MldHeader *)pkt_buf->payload;
    switch (mld_hdr->type)
    {
    case ICMP6_TYPE_MLQ: /* Multicast listener query. */ /* Is it a general query? */ if (
            ip6_addr_isallnodes_linklocal(curr_dst_addr) && ip6_addr_is_any(
                &(mld_hdr->multicast_address)))
        {
            /* Report all groups, except all nodes group, and if-local groups. */
            group = ((MldGroup *)netif_get_client_data(in_netif, LWIP_NETIF_CLIENT_DATA_INDEX_MLD6));
            while (group != nullptr)
            {
                if ((!(ip6_addr_is_multicast_if_local(&(group->group_address)))) && (!(
                    ip6_addr_isallnodes_linklocal(&(group->group_address)))))
                {
                    mld6_delayed_report(group, mld_hdr->max_resp_delay);
                }
                group = group->next;
            }
        }
        else
        {
            /* Have we joined this group?
             * We use IP6 destination address to have a memory aligned copy.
             * mld_hdr->multicast_address should be the same. */
            group = mld6_lookfor_group(in_netif, curr_dst_addr);
            if (group != nullptr)
            {
                /* Schedule a report. */
                mld6_delayed_report(group, mld_hdr->max_resp_delay);
            }
        }
        break; /* ICMP6_TYPE_MLQ */
    case ICMP6_TYPE_MLR: /* Multicast listener report. */ /* Have we joined this group?
     * We use IP6 destination address to have a memory aligned copy.
     * mld_hdr->multicast_address should be the same. */ group = mld6_lookfor_group(
            in_netif,
            curr_dst_addr);
        if (group != nullptr)
        {
            /* If we are waiting to report, cancel it. */
            if (group->group_state == MLD6_GROUP_DELAYING_MEMBER)
            {
                group->timer = 0; /* stopped */
                group->group_state = MLD6_GROUP_IDLE_MEMBER;
                group->last_reporter_flag = 0;
            }
        }
        break; /* ICMP6_TYPE_MLR */
    case ICMP6_TYPE_MLD: /* Multicast listener done. */
        /* Do nothing, router will query us. */ break; /* ICMP6_TYPE_MLD */
    default:
        break;
    }
    free_pkt_buf(pkt_buf);
}

/**
 * @ingroup mld6
 * Join a group on one or all network interfaces.
 *
 * If the group is to be joined on all interfaces, the given group address must
 * not have a zone set (i.e., it must have its zone index set to kIp6NoZone).
 * If the group is to be joined on one particular interface, the given group
 * address may or may not have a zone set.
 *
 * @param srcaddr ipv6 address (zoned) of the network interface which should
 *                join a new group. If IP6_ADDR_ANY6, join on all netifs
 * @param groupaddr the ipv6 address of the group to join (possibly but not
 *                  necessarily zoned)
 * @return ERR_OK if group was joined on the netif(s), an LwipStatus otherwise
 */
NsStatus
mld6_joingroup(const Ip6Addr *srcaddr, const Ip6Addr *groupaddr)
{
  NsStatus         err = ERR_VAL; /* no matching interface */
  NetworkInterface*netif;

 

  /* loop through netif's */
  for ((netif) = netif_list; (netif) != nullptr; (netif) = (netif)->next) {
    /* Should we join this interface ? */
    if (ip6_addr_is_any(srcaddr) ||
        get_netif_ip6_addr_idx(netif, srcaddr) >= 0) {
      err = mld6_joingroup_netif(netif, groupaddr);
      if (err != STATUS_SUCCESS) {
        return err;
      }
    }
  }

  return err;
}

/**
 * @ingroup mld6
 * Join a group on a network interface.
 *
 * @param netif the network interface which should join a new group.
 * @param groupaddr the ipv6 address of the group to join (possibly but not
 *                  necessarily zoned)
 * @return ERR_OK if group was joined on the netif, an LwipStatus otherwise
 */
NsStatus
mld6_joingroup_netif(NetworkInterface*netif, const Ip6Addr *groupaddr)
{
    Ip6Addr ip6addr;

  /* If the address has a particular scope but no zone set, use the netif to
   * set one now. Within the mld6 module, all addresses are properly zoned. */
  if (ip6_addr_lacks_zone(groupaddr, IP6_MULTICAST)) {
    set_ip6_addr(&ip6addr, groupaddr);
    assign_ip6_addr_zone(&ip6addr, IP6_MULTICAST, netif,);
    groupaddr = &ip6addr;
  }
  // IP6_ADDR_ZONECHECK_NETIF(groupaddr, netif);


 

  /* find group or create a new one if not found */
  struct MldGroup* group = mld6_lookfor_group(netif, groupaddr);

  if (group == nullptr) {
    /* Joining a new group. Create a new group entry. */
    group = mld6_new_group(netif, groupaddr);
    if (group == nullptr) {
      return STATUS_E_MEM;
    }

    /* Activate this address on the MAC layer. */
    if (netif->mld_mac_filter != nullptr) {
      netif->mld_mac_filter(netif, groupaddr, NETIF_ADD_MAC_FILTER);
    }

    /* Report our membership. */
    // MLD6_STATS_INC(mld6.tx_report);
    mld6_send(netif, group, ICMP6_TYPE_MLR);
    mld6_delayed_report(group, MLD6_JOIN_DELAYING_MEMBER_TMR_MS);
  }

  /* Increment group use */
  group->use++;
  return STATUS_SUCCESS;
}

/**
 * @ingroup mld6
 * Leave a group on a network interface.
 *
 * Zoning of address follows the same rules as @ref mld6_joingroup.
 *
 * @param srcaddr ipv6 address (zoned) of the network interface which should
 *                leave the group. If IP6_ADDR_ANY6, leave on all netifs
 * @param groupaddr the ipv6 address of the group to leave (possibly, but not
 *                  necessarily zoned)
 * @return ERR_OK if group was left on the netif(s), an LwipStatus otherwise
 */
NsStatus
mld6_leavegroup(const Ip6Addr *srcaddr, const Ip6Addr *groupaddr)
{
  NsStatus         err = ERR_VAL; /* no matching interface */
  NetworkInterface*netif;

 

  /* loop through netif's */
  for ((netif) = netif_list; (netif) != nullptr; (netif) = (netif)->next) {
    /* Should we leave this interface ? */
    if (ip6_addr_is_any(srcaddr) ||
        get_netif_ip6_addr_idx(netif, srcaddr) >= 0) {
      NsStatus res = mld6_leavegroup_netif(netif, groupaddr);
      if (err != STATUS_SUCCESS) {
        /* Store this result if we have not yet gotten a success */
        err = res;
      }
    }
  }

  return err;
}

/**
 * @ingroup mld6
 * Leave a group on a network interface.
 *
 * @param netif the network interface which should leave the group.
 * @param groupaddr the ipv6 address of the group to leave (possibly, but not
 *                  necessarily zoned)
 * @return ERR_OK if group was left on the netif, an LwipStatus otherwise
 */
NsStatus
mld6_leavegroup_netif(NetworkInterface*netif, const Ip6Addr *groupaddr)
{
    Ip6Addr ip6addr;

  if (ip6_addr_lacks_zone(groupaddr, IP6_MULTICAST)) {
    set_ip6_addr(&ip6addr, groupaddr);
    assign_ip6_addr_zone(&ip6addr, IP6_MULTICAST, netif,);
    groupaddr = &ip6addr;
  }
  // IP6_ADDR_ZONECHECK_NETIF(groupaddr, netif);


 

  /* find group */
  struct MldGroup* group = mld6_lookfor_group(netif, groupaddr);

  if (group != nullptr) {
    /* Leave if there is no other use of the group */
    if (group->use <= 1) {
      /* Remove the group from the list */
      mld6_remove_group(netif, group);

      /* If we are the last reporter for this group */
      if (group->last_reporter_flag) {
        // MLD6_STATS_INC(mld6.tx_leave);
        mld6_send(netif, group, ICMP6_TYPE_MLD);
      }

      /* Disable the group at the MAC level */
      if (netif->mld_mac_filter != nullptr) {
        netif->mld_mac_filter(netif, groupaddr, NETIF_DEL_MAC_FILTER);
      }

      /* free group struct */
      // memp_free(MEMP_MLD6_GROUP, group);
        delete group;
    } else {
      /* Decrement group use */
      group->use--;
    }

    /* Left group */
    return STATUS_SUCCESS;
  }

  /* Group not found */
  return ERR_VAL;
}


/**
 * Periodic timer for mld processing. Must be called every
 * MLD6_TMR_INTERVAL milliseconds (100).
 *
 * When a delaying member expires, a membership report is sent.
 */
void
mld6_tmr(void)
{
  NetworkInterface*netif;

  for ((netif) = netif_list; (netif) != nullptr; (netif) = (netif)->next) {
    struct MldGroup *group = ((MldGroup *)netif_get_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_MLD6));

    while (group != nullptr) {
      if (group->timer > 0) {
        group->timer--;
        if (group->timer == 0) {
          /* If the state is MLD6_GROUP_DELAYING_MEMBER then we send a report for this group */
          if (group->group_state == MLD6_GROUP_DELAYING_MEMBER) {
            // MLD6_STATS_INC(mld6.tx_report);
            mld6_send(netif, group, ICMP6_TYPE_MLR);
            group->group_state = MLD6_GROUP_IDLE_MEMBER;
          }
        }
      }
      group = group->next;
    }
  }
}

/**
 * Schedule a delayed membership report for a group
 *
 * @param group the mld_group for which "delaying" membership report
 *              should be sent
 * @param maxresp_in the max resp delay provided in the query
 */
static void
mld6_delayed_report(struct MldGroup *group, uint16_t maxresp_in)
{
  /* Convert maxresp from milliseconds to tmr ticks */
  uint16_t maxresp = maxresp_in / MLD6_TMR_INTERVAL;
  if (maxresp == 0) {
    maxresp = 1;
  }


  /* Randomize maxresp. (if lwip_rand is supported) */
  maxresp = (uint16_t)(lwip_rand() % maxresp);
  if (maxresp == 0) {
    maxresp = 1;
  }


  /* Apply timer value if no report has been scheduled already. */
  if ((group->group_state == MLD6_GROUP_IDLE_MEMBER) ||
     ((group->group_state == MLD6_GROUP_DELAYING_MEMBER) &&
      ((group->timer == 0) || (maxresp < group->timer)))) {
    group->timer = maxresp;
    group->group_state = MLD6_GROUP_DELAYING_MEMBER;
  }
}

/**
 * Send a MLD message (report or done).
 *
 * An IPv6 hop-by-hop options header with a router alert option
 * is prepended.
 *
 * @param group the group to report or quit
 * @param type ICMP6_TYPE_MLR (report) or ICMP6_TYPE_MLD (done)
 */
static void
mld6_send(NetworkInterface*netif, struct MldGroup *group, uint8_t type)
{
    const Ip6Addr *src_addr;

  /* Allocate a packet. Size is MLD header + IPv6 Hop-by-hop options header. */
  // struct PacketBuffer* p =
  //     pbuf_alloc();
    PacketContainer p = init_pkt_buf()
  if (p == nullptr) {
    // MLD6_STATS_INC(mld6.memerr);
    return;
  }

  /* Move to make room for Hop-by-hop options header. */
  // if (pbuf_remove_header(p, MLD6_HBH_HLEN)) {
  //   free_pkt_buf(p);
  //   // MLD6_STATS_INC(mld6.lenerr);
  //   return;
  // }

  /* Select our source address. */
  if (!ip6_addr_is_valid(get_netif_ip6_addr_state(netif, 0))) {
    /* This is a special case, when we are performing duplicate address detection.
     * We must join the multicast group, but we don't have a valid address yet. */
    src_addr = nullptr;
  } else {
    /* Use link-local address as source address. */
    src_addr = get_netif_ip6_addr(netif, 0);
  }

  /* MLD message header pointer. */
  struct MldHeader* mld_hdr = (struct MldHeader *)p->payload;

  /* Set fields. */
  mld_hdr->type = type;
  mld_hdr->code = 0;
  mld_hdr->chksum = 0;
  mld_hdr->max_resp_delay = 0;
  mld_hdr->reserved = 0;
  ip6_addr_copy_to_packed((Ip6Addr*)&mld_hdr->multicast_address, &group->group_address);

  // IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_ICMP6) {
  //   mld_hdr->chksum = ip6_chksum_pseudo(p, IP6_NEXTH_ICMP6, p->len,
  //     src_addr, &(group->group_address));
  // }


  /* Add hop-by-hop headers options: router alert with MLD value. */
  ip6_options_add_hbh_ra(p, IP6_NEXTH_ICMP6, IP6_ROUTER_ALERT_VALUE_MLD);

  if (type == ICMP6_TYPE_MLR) {
    /* Remember we were the last to report */
    group->last_reporter_flag = 1;
  }

  /* Send the packet out. */
  // MLD6_STATS_INC(mld6.xmit);
  ip6_output_if(p, (ip6_addr_is_any(src_addr)) ? nullptr : src_addr, &(group->group_address), MLD6_HL, 0, IP6_NEXTH_HOPBYHOP, netif);
  free_pkt_buf(p);
}

