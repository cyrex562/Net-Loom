
#include "netloom_config.h"
#include "igmp.h"
#include "ns_def.h"
#include "ip.h"
#include "inet_chksum.h"
#include "network_interface.h"

static struct IgmpGroup* igmp_lookup_group(NetworkInterface* ifp, const Ip4Addr* addr);
static NsStatus igmp_remove_group(NetworkInterface* netif, struct IgmpGroup* group);
static void igmp_timeout(NetworkInterface* netif, struct IgmpGroup* group);
static void igmp_start_timer(struct IgmpGroup* group, uint8_t max_time);
static void igmp_delaying_member(struct IgmpGroup* group, uint8_t maxresp);
static NsStatus igmp_ip_output_if(struct PacketContainer* p,
                                   const Ip4Addr* src,
                                   const Ip4Addr* dest,
                                   NetworkInterface* netif);
static void igmp_send(NetworkInterface* netif, struct IgmpGroup* group, uint8_t type);
static Ip4Addr allsystems;
static Ip4Addr allrouters;

/**
 * Initialize the IGMP module
 */
void init_igmp_module(void)
{
    Logf(true, ("igmp_init: initializing\n"));
    make_ip4_addr_host_from_bytes(&allsystems, 224, 0, 0, 1);
    make_ip4_addr_host_from_bytes(&allrouters, 224, 0, 0, 2);
}

/**
 * Start IGMP processing on interface
 *
 * @param netif network interface on which start IGMP processing
 */
NsStatus igmp_start(NetworkInterface& netif)
{
    // Logf(true, ("igmp_start: starting IGMP processing on if %p\n", (uint8_t *)netif));
    struct IgmpGroup* group = igmp_lookup_group(netif, &allsystems);
    if (group != nullptr)
    {
        group->group_state = IGMP_GROUP_IDLE_MEMBER;
        group->use++; /* Allow the igmp messages at the MAC level */
        if (netif->igmp_mac_filter != nullptr)
        {
            Logf(true, ("igmp_start: igmp_mac_filter(ADD "));
            // ip4_addr_debug_print_val(true, allsystems);
            // Logf(true, (") on if %p\n", (uint8_t *)netif));
            netif->igmp_mac_filter(netif, &allsystems, NETIF_ADD_MAC_FILTER);
        }
        return STATUS_SUCCESS;
    }
    return STATUS_E_MEM;
}

/**
 * Stop IGMP processing on interface
 *
 * @param netif network interface on which stop IGMP processing
 */
NsStatus igmp_stop(NetworkInterface& netif)
{
    // IgmpGroup* group = netif_igmp_data(netif);
    auto group = netif->igmp_group;
    // netif->client_data[LWIP_NETIF_CLIENT_DATA_INDEX_IGMP] = nullptr;
    while (group != nullptr)
    {
        struct IgmpGroup* next = group->next; /* avoid use-after-free below */
        /* disable the group at the MAC level */
        if (netif->igmp_mac_filter != nullptr)
        {
            Logf(true, ("igmp_stop: igmp_mac_filter(DEL "));
            // ip4_addr_debug_print_val(true, group->group_address);
            // Logf(true, (") on if %p\n", (uint8_t *)netif));
            netif->igmp_mac_filter(netif, &(group->group_address), NETIF_DEL_MAC_FILTER);
        } /* free group */ // memp_free(MEMP_IGMP_GROUP, group);
        delete group; /* move to "next" */
        group = next;
    }
    return STATUS_SUCCESS;
}

/**
 * Report IGMP memberships for this interface
 *
 * @param netif network interface on which report IGMP memberships
 */
void igmp_report_groups(NetworkInterface& netif)
{
    struct IgmpGroup* group = get_netif_igmp_group(netif,);
    // Logf(true, ("igmp_report_groups: sending IGMP reports on if %p\n", (uint8_t *)netif));
    /* Skip the first group in the list, it is always the allsystems group added in igmp_start() */
    if (group != nullptr)
    {
        group = group->next;
    }
    while (group != nullptr)
    {
        igmp_delaying_member(group, IGMP_JOIN_DELAYING_MEMBER_TMR);
        group = group->next;
    }
}



/**
 * Search for a specific igmp group and create a new one if not found-
 *
 * @param ifp the network interface for which to look
 * @param addr the group ip address to search
 * @return a struct igmp_group*,
 *         NULL on memory error.
 */
static struct IgmpGroup* igmp_lookup_group(NetworkInterface* ifp, const Ip4Addr* addr)
{
    auto list_head = get_netif_igmp_group(ifp,);
    /* Search if the group already exists */
    auto group = find_igmp_grp(ifp, addr);
    if (group != nullptr)
    {
        /* Group already exists. */
        return group;
    } /* Group doesn't exist yet, create a new one */
    // group = (struct IgmpGroup *)memp_malloc(MEMP_IGMP_GROUP);
    group = new IgmpGroup;
    if (group != nullptr)
    {
        (&(group->group_address) = addr);
        group->timer = 0; /* Not running */
        group->group_state = IGMP_GROUP_NON_MEMBER;
        group->last_reporter_flag = 0;
        group->use = 0; /* Ensure allsystems group is always first in list */
        if (list_head == nullptr)
        {
            /* this is the first entry in linked list */
            ns_assert("igmp_lookup_group: first group must be allsystems",
                        ((addr.u32 == &allsystems.u32) != 0));
            group->next = nullptr;
            ifp->client_data[LWIP_NETIF_CLIENT_DATA_INDEX_IGMP] = group;
        }
        else
        {
            /* append _after_ first entry */
            ns_assert(
                "igmp_lookup_group: all except first group must not be allsystems",
                ((addr.u32 == &allsystems.u32) == 0));
            group->next = list_head->next;
            list_head->next = group;
        }
    }
    Logf(true,
         ("igmp_lookup_group: %sallocated a new group with address ", (
             group ? "" : "impossible to ")));
    // ip4_addr_debug_print(true, addr)
    // ;
    // Logf(true, (" on if %p\n", (uint8_t *)ifp));
    return group;
}

/**
 * Remove a group from netif's igmp group list, but don't free it yet
 *
 * @param group the group to remove from the netif's igmp group list
 * @return ERR_OK if group was removed from the list, an LwipStatus otherwise
 */
static NsStatus igmp_remove_group(NetworkInterface* netif, struct IgmpGroup* group)
{
    NsStatus err = STATUS_SUCCESS;
    struct IgmpGroup* tmp_group;
    /* Skip the first group in the list, it is always the allsystems group added in igmp_start() */
    for (tmp_group = get_netif_igmp_group(netif,); tmp_group != nullptr; tmp_group = tmp_group->
         next)
    {
        if (tmp_group->next == group)
        {
            tmp_group->next = group->next;
            break;
        }
    } /* Group not found in netif's igmp group list */
    if (tmp_group == nullptr)
    {
        err = STATUS_E_INVALID_ARG;
    }
    return err;
}

/**
 * Called from ip_input() if a new IGMP packet is received.
 *
 * @param pkt_buf received igmp packet, p->payload pointing to the igmp header
 * @param netif network interface on which the packet was received
 * @param daddr destination ip address of the igmp packet
 */
void
igmp_input(PacketContainer& pkt_buf, NetworkInterface& netif, const Ip4Addr& daddr)
{
    /* Note that the length CAN be greater than 8 but only 8 are used - All are included in the checksum */
  if (pkt_buf->len < IGMP_MIN_LEN) {
    free_pkt_buf(pkt_buf);

    Logf(true, ("igmp_input: length error\n"));
    return;
  }

  Logf(true, ("igmp_input: message from "));
  // ip4_addr_debug_print_val(true, ip4_current_header()->src);
  Logf(true, (" to address "));
  // ip4_addr_debug_print_val(true, ip4_current_header()->dest);
  // Logf(true, (" on if %p\n", (uint8_t *)inp));

  /* Now calculate and check the checksum */
  struct IgmpMsg* igmp = (struct IgmpMsg *)pkt_buf->payload;
  if (inet_chksum((uint8_t*)igmp, pkt_buf->len)) {
    free_pkt_buf(pkt_buf);

    Logf(true, ("igmp_input: checksum error\n"));
    return;
  }

  /* Packet is ok so find an existing group */
  struct IgmpGroup* group = find_igmp_grp(netif, daddr); /* use the destination IP address of incoming packet */

  /* If group can be found or create... */
  if (!group) {
    free_pkt_buf(pkt_buf);

    Logf(true, ("igmp_input: IGMP frame not for us\n"));
    return;
  }

  /* NOW ACT ON THE INCOMING MESSAGE TYPE... */
  switch (igmp->igmp_msgtype) {
    case IGMP_MEMB_QUERY:
      /* IGMP_MEMB_QUERY to the "all systems" address ? */
      if (((daddr.u32 == &allsystems.u32)) && (reinterpret_cast<Ip4Addr*>(&igmp->igmp_group_address.u32 == IP4_ADDR_ANY_U32))) {
        /* THIS IS THE GENERAL QUERY */
        // Logf(true, ("igmp_input: General IGMP_MEMB_QUERY on \"ALL SYSTEMS\" address (224.0.0.1) [igmp_maxresp=%i]\n", (int)(igmp->igmp_maxresp)));

        if (igmp->igmp_maxresp == 0) {

          Logf(true, ("igmp_input: got an all hosts query with time== 0 - this is V1 and not implemented - treat as v2\n"));
          igmp->igmp_maxresp = IGMP_V1_DELAYING_MEMBER_TMR;
        } else {

        }

        struct IgmpGroup* groupref = get_netif_igmp_group(netif,);

        /* Do not send messages on the all systems group address! */
        /* Skip the first group in the list, it is always the allsystems group added in igmp_start() */
        if (groupref != nullptr) {
          groupref = groupref->next;
        }

        while (groupref) {
          igmp_delaying_member(groupref, igmp->igmp_maxresp);
          groupref = groupref->next;
        }
      } else {
        /* IGMP_MEMB_QUERY to a specific group ? */
        if (!(reinterpret_cast<Ip4Addr*>(&igmp->igmp_group_address.u32 == IP4_ADDR_ANY_U32))) {
          // Logf(true, ("igmp_input: IGMP_MEMB_QUERY to a specific group "));
          // ip4_addr_debug_print_val(true, igmp->igmp_group_address);
          if ((daddr.u32 == &allsystems.u32)) {
            Ip4Addr groupaddr;
            // Logf(true, (" using \"ALL SYSTEMS\" address (224.0.0.1) [igmp_maxresp=%i]\n", (int)(igmp->igmp_maxresp)));
            /* we first need to re-look for the group since we used dest last time */
            (&groupaddr = reinterpret_cast<Ip4Addr*>(&igmp->igmp_group_address));
            group = find_igmp_grp(netif, &groupaddr);
          } else {
            // Logf(true, (" with the group address as destination [igmp_maxresp=%i]\n", (int)(igmp->igmp_maxresp)));
          }

          if (group != nullptr) {

            igmp_delaying_member(group, igmp->igmp_maxresp);
          } else {
          }
        } else {
        }
      }
      break;
    case IGMP_V2_MEMB_REPORT:
      Logf(true, ("igmp_input: IGMP_V2_MEMB_REPORT\n"));
      if (group->group_state == IGMP_GROUP_DELAYING_MEMBER) {
        /* This is on a specific group we have already looked up */
        group->timer = 0; /* stopped */
        group->group_state = IGMP_GROUP_IDLE_MEMBER;
        group->last_reporter_flag = 0;
      }
      break;
    default:
      // Logf(true, ("igmp_input: unexpected msg %d in state %d on group %p on if %p\n",
      //                          igmp->igmp_msgtype, group->group_state, (uint8_t *)&group, (uint8_t *)inp));
      break;
  }

  free_pkt_buf(pkt_buf);
}

/**
 * @ingroup igmp
 * Join a group on one network interface.
 *
 * @param ifc_addr ip address of the network interface which should join a new group
 * @param grp_addr the ip address of the group which to join
 * @return ERR_OK if group was joined on the netif(s), an LwipStatus otherwise
 */
NsStatus
igmp_joingroup(const Ip4Addr& ifc_addr, const Ip4Addr& grp_addr)
{
  NsStatus err = ERR_VAL; /* no matching interface */
  NetworkInterface*netif;



  /* make sure it is multicast address */
  //
  //

  /* loop through netif's */
  for ((netif) = netif_list; (netif) != nullptr; (netif) = (netif)->next) {
    /* Should we join this interface ? */
    if ((netif->flags & NETIF_FLAG_IGMP) && (((ifc_addr.u32 == IP4_ADDR_ANY_U32) || (get_netif_ip4_addr(netif,).u32 == ifc_addr.u32)))) {
      err = igmp_joingroup_netif(netif, grp_addr);
      if (err != STATUS_SUCCESS) {
        /* Return an error even if some network interfaces are joined */
        /** @todo undo any other netif already joined */
        return err;
      }
    }
  }

  return err;
}

/**
 * @ingroup igmp
 * Join a group on one network interface.
 *
 * @param netif the network interface which should join a new group
 * @param groupaddr the ip address of the group which to join
 * @return ERR_OK if group was joined on the netif, an LwipStatus otherwise
 */
NsStatus
igmp_joingroup_netif(NetworkInterface& netif, const Ip4Addr& groupaddr)
{
    /* make sure it is multicast address */
  //
  //

  /* make sure it is an igmp-enabled netif */
  //

  /* find group or create a new one if not found */
  struct IgmpGroup* group = igmp_lookup_group(netif, groupaddr);

  if (group != nullptr) {
    /* This should create a new group, check the state to make sure */
    if (group->group_state != IGMP_GROUP_NON_MEMBER) {
      Logf(true, ("igmp_joingroup_netif: join to group not in state IGMP_GROUP_NON_MEMBER\n"));
    } else {
      /* OK - it was new group */
      Logf(true, ("igmp_joingroup_netif: join to new group: "));
      // ip4_addr_debug_print(true, groupaddr);
      Logf(true, ("\n"));

      /* If first use of the group, allow the group at the MAC level */
      if ((group->use == 0) && (netif->igmp_mac_filter != nullptr)) {
        Logf(true, ("igmp_joingroup_netif: igmp_mac_filter(ADD "));
        // ip4_addr_debug_print(true, groupaddr);
        // Logf(true, (") on if %p\n", (uint8_t *)netif));
        netif->igmp_mac_filter(netif, groupaddr, NETIF_ADD_MAC_FILTER);
      }

      igmp_send(netif, group, IGMP_V2_MEMB_REPORT);

      igmp_start_timer(group, IGMP_JOIN_DELAYING_MEMBER_TMR);

      /* Need to work out where this timer comes from */
      group->group_state = IGMP_GROUP_DELAYING_MEMBER;
    }
    /* Increment group use */
    group->use++;
    /* Join on this interface */
    return STATUS_SUCCESS;
  } else {
    Logf(true, ("igmp_joingroup_netif: Not enough memory to join to group\n"));
    return STATUS_E_MEM;
  }
}

/**
 * @ingroup igmp
 * Leave a group on one network interface.
 *
 * @param ifaddr ip address of the network interface which should leave a group
 * @param groupaddr the ip address of the group which to leave
 * @return ERR_OK if group was left on the netif(s), an LwipStatus otherwise
 */
NsStatus
igmp_leavegroup(const Ip4Addr& ifaddr, const Ip4Addr& groupaddr)
{
  NsStatus err = ERR_VAL; /* no matching interface */
  NetworkInterface*netif;



  /* make sure it is multicast address */
  //
  //

  /* loop through netif's */
  for ((netif) = netif_list; (netif) != nullptr; (netif) = (netif)->next) {
    /* Should we leave this interface ? */
    if ((netif->flags & NETIF_FLAG_IGMP) && (((ifaddr.u32 == IP4_ADDR_ANY_U32) || (get_netif_ip4_addr(netif,).u32 == ifaddr.u32)))) {
      NsStatus res = igmp_leavegroup_netif(netif, groupaddr);
      if (err != STATUS_SUCCESS) {
        /* Store this result if we have not yet gotten a success */
        err = res;
      }
    }
  }

  return err;
}

/**
 * @ingroup igmp
 * Leave a group on one network interface.
 *
 * @param netif the network interface which should leave a group
 * @param groupaddr the ip address of the group which to leave
 * @return ERR_OK if group was left on the netif, an LwipStatus otherwise
 */
NsStatus
igmp_leavegroup_netif(NetworkInterface& netif, const Ip4Addr& groupaddr)
{
    /* make sure it is multicast address */
  //
  //

  /* make sure it is an igmp-enabled netif */
  //

  /* find group */
  struct IgmpGroup* group = find_igmp_grp(netif, groupaddr);

  if (group != nullptr) {
    /* Only send a leave if the flag is set according to the state diagram */
    Logf(true, ("igmp_leavegroup_netif: Leaving group: "));
    // ip4_addr_debug_print(true, groupaddr);
    Logf(true, ("\n"));

    /* If there is no other use of the group */
    if (group->use <= 1) {
      /* Remove the group from the list */
      igmp_remove_group(netif, group);

      /* If we are the last reporter for this group */
      if (group->last_reporter_flag) {
        Logf(true, ("igmp_leavegroup_netif: sending leaving group\n"));
        igmp_send(netif, group, IGMP_LEAVE_GROUP);
      }

      /* Disable the group at the MAC level */
      if (netif->igmp_mac_filter != nullptr) {
        Logf(true, ("igmp_leavegroup_netif: igmp_mac_filter(DEL "));
        // ip4_addr_debug_print(true, groupaddr);
        // Logf(true, (") on if %p\n", (uint8_t *)netif));
        netif->igmp_mac_filter(netif, groupaddr, NETIF_DEL_MAC_FILTER);
      }

      /* Free group struct */
      delete group;
    } else {
      /* Decrement group use */
      group->use--;
    }
    return STATUS_SUCCESS;
  } else {
    Logf(true, ("igmp_leavegroup_netif: not member of group\n"));
    return ERR_VAL;
  }
}

/**
 * The igmp timer function (both for NO_SYS=1 and =0)
 * Should be called every IGMP_TMR_INTERVAL milliseconds (100 ms is default).
 */
void
igmp_tmr(void)
{
  NetworkInterface*netif;

  for ((netif) = netif_list; (netif) != nullptr; (netif) = (netif)->next) {
    struct IgmpGroup *group = get_netif_igmp_group(netif,);

    while (group != nullptr) {
      if (group->timer > 0) {
        group->timer--;
        if (group->timer == 0) {
          igmp_timeout(netif, group);
        }
      }
      group = group->next;
    }
  }
}

/**
 * Called if a timeout for one group is reached.
 * Sends a report for this group.
 *
 * @param group an igmp_group for which a timeout is reached
 */
static void
igmp_timeout(NetworkInterface*netif, struct IgmpGroup *group)
{
  /* If the state is IGMP_GROUP_DELAYING_MEMBER then we send a report for this group
     (unless it is the allsystems group) */
  if ((group->group_state == IGMP_GROUP_DELAYING_MEMBER) &&
      (!((&(group->group_address).u32 &allsystems.u32)))) {
    Logf(true, ("igmp_timeout: report membership for group with address "));
    // ip4_addr_debug_print_val(true, group->group_address);
    // Logf(true, (" on if %p\n", (uint8_t *)netif));

    group->group_state = IGMP_GROUP_IDLE_MEMBER;

    igmp_send(netif, group, IGMP_V2_MEMB_REPORT);
  }
}

/**
 * Start a timer for an igmp group
 *
 * @param group the igmp_group for which to start a timer
 * @param max_time the time in multiples of IGMP_TMR_INTERVAL (decrease with
 *        every call to igmp_tmr())
 */
static void
igmp_start_timer(struct IgmpGroup *group, uint8_t max_time)
{
#ifdef lwip_rand
  group->timer = (uint16_t)(max_time > 2 ? (lwip_rand() % max_time) : 1);
#else /* lwip_rand */
  /* ATTENTION: use this only if absolutely necessary! */
  group->timer = max_time / 2;
#endif /* lwip_rand */

  if (group->timer == 0) {
    group->timer = 1;
  }
}

/**
 * Delaying membership report for a group if necessary
 *
 * @param group the igmp_group for which "delaying" membership report
 * @param maxresp query delay
 */
static void
igmp_delaying_member(struct IgmpGroup *group, uint8_t maxresp)
{
  if ((group->group_state == IGMP_GROUP_IDLE_MEMBER) ||
      ((group->group_state == IGMP_GROUP_DELAYING_MEMBER) &&
       ((group->timer == 0) || (maxresp < group->timer)))) {
    igmp_start_timer(group, maxresp);
    group->group_state = IGMP_GROUP_DELAYING_MEMBER;
  }
}


/**
 * Sends an IP packet on a network interface. This function constructs the IP header
 * and calculates the IP header checksum. If the source IP address is NULL,
 * the IP address of the outgoing network interface is filled in as source address.
 *
 * @param p the packet to send (p->payload points to the data, e.g. next
            protocol header; if dest == LWIP_IP_HDRINCL, p already includes an
            IP header and p->payload points to that IP header)
 * @param src the source IP address to send from (if src == IP4_ADDR_ANY, the
 *         IP  address of the netif used to send is used as source address)
 * @param dest the destination IP address to send the packet to
 * @param netif the netif on which to send this packet
 * @return ERR_OK if the packet was sent OK
 *         ERR_BUF if p doesn't have enough space for IP/LINK headers
 *         returns errors returned by netif->output
 */
static NsStatus
igmp_ip_output_if(struct PacketContainer *p, const Ip4Addr *src, const Ip4Addr *dest, NetworkInterface*netif)
{
  /* This is the "router alert" option */
  uint16_t ra[2];
  ra[0] = pp_htons(ROUTER_ALERT);
  ra[1] = 0x0000; /* Router shall examine packet */
  return ip4_output_if_opt(p, src, dest, IGMP_TTL, 0, IP_PROTO_IGMP, netif, (uint8_t*)ra, ROUTER_ALERT_LEN);
}

/**
 * Send an igmp packet to a specific group.
 *
 * @param group the group to which to send the packet
 * @param type the type of igmp packet to send
 */
static void
igmp_send(NetworkInterface*netif, struct IgmpGroup *group, uint8_t type)
{
  struct PacketContainer     *p    = nullptr;
  struct IgmpMsg *igmp = nullptr;
  Ip4Addr   src  = IP4_ADDR_ANY_U32;
  Ip4Addr  *dest = nullptr;

  /* IP header + "router alert" option + IGMP header */
  // p = pbuf_alloc();

  if (p) {
    igmp = reinterpret_cast<struct IgmpMsg *>(p->payload);
    ns_assert("igmp_send: check that first PacketBuffer can hold struct igmp_msg",
                (p->len >= sizeof(struct IgmpMsg)));
    (&src = get_netif_ip4_addr(netif,));

    if (type == IGMP_V2_MEMB_REPORT) {
      dest = &(group->group_address);
      (reinterpret_cast<Ip4Addr*>(&igmp->igmp_group_address) = &group->group_address);
      group->last_reporter_flag = 1; /* Remember we were the last to report */
    } else {
      if (type == IGMP_LEAVE_GROUP) {
        dest = &allrouters;
        (reinterpret_cast<Ip4Addr*>(&igmp->igmp_group_address) = &group->group_address);
      }
    }

    if ((type == IGMP_V2_MEMB_REPORT) || (type == IGMP_LEAVE_GROUP)) {
      igmp->igmp_msgtype  = type;
      igmp->igmp_maxresp  = 0;
      igmp->igmp_checksum = 0;
      igmp->igmp_checksum = inet_chksum(reinterpret_cast<uint8_t*>(igmp), IGMP_MIN_LEN);

      igmp_ip_output_if(p, &src, dest, netif);
    }

    free_pkt_buf(p);
  } else {
    Logf(true, ("igmp_send: not enough memory for igmp_send\n"));
  }
}
