/**
 * @file
 * DNS - host name to IP address resolver.
 *
 * @defgroup dns DNS
 * @ingroup callbackstyle_api
 *
 * Implements a DNS host name to IP address resolver.
 *
 * The lwIP DNS resolver functions are used to lookup a host name and
 * map it to a numerical IP address. It maintains a list of resolved
 * hostnames that can be queried with the dns_lookup() function.
 * New hostnames can be resolved using the dns_query() function.
 *
 * The lwIP version of the resolver also adds a non-blocking version of
 * gethostbyname() that will work with a raw API application. This function
 * checks for an IP address string first and converts it if it is valid.
 * gethostbyname() then does a dns_lookup() to see if the name is
 * already in the table. If so, the IP is returned. If not, a query is
 * issued and the function returns with a ERR_INPROGRESS status. The app
 * using the dns client must then go into a waiting state.
 *
 * Once a hostname has been resolved (or found to be non-existent),
 * the resolver code calls a specified callback function (which
 * must be implemented by the module that uses the resolver).
 *
 * Multicast DNS queries are supported for names ending on ".local".
 * However, only "One-Shot Multicast DNS Queries" are supported (RFC 6762
 * chapter 5.1), this is not a fully compliant implementation of continuous
 * mDNS querying!
 *
 * All functions must be called from TCPIP thread.
 *
 * @see DNS_MAX_SERVERS
 * @see LWIP_DHCP_MAX_DNS_SERVERS
 * @see @ref netconn_common for thread-safe access.
 */

/*
 * Port to lwIP from uIP
 * by Jim Pettinato April 2007
 *
 * security fixes and more by Simon Goldschmidt
 *
 * uIP version Copyright (c) 2002-2003, Adam Dunkels.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*-----------------------------------------------------------------------------
 * RFC 1035 - Domain names - implementation and specification
 * RFC 2181 - Clarifications to the DNS Specification
 *----------------------------------------------------------------------------*/

/** @todo: define good default values (rfc compliance) */
/** @todo: improve answer parsing, more checkings... */
/** @todo: check RFC1035 - 7.3. Processing responses */
/** @todo: one-shot mDNS: dual-stack fallback to another IP version */

/*-----------------------------------------------------------------------------
 * Includes
 *----------------------------------------------------------------------------*/

#include "ns_dns.h"
#include "ns_config.h"
#include "ns_def.h"
#include "ns_udp.h"
#include "ns_debug.h"
#include "ns_ip_addr.h"
#include "ns_ip6_addr.h"
#include "ns_ip4_addr.h"
#include "ns_ip6.h"
#include "ns_ip.h"
#include "ns_tcp_udp.h"
#include "spdlog/spdlog.h"
#include <cstring>
#include <cctype>




/**
 * Initialize the resolver: set up the UDP pcb and configure the default server
 * (if DNS_SERVER_ADDRESS is set).
 */
std::tuple<bool, std::vector<DnsPcb>, std::vector<DnsServer>, std::vector<
               LocalHostListEntry>>
dns_init(std::vector<NetworkInterface>& netifs,
         std::vector<NetworkPort>& ports,
         DnsServer& default_dns_server,
         std::vector<LocalHostListEntry>& initial_local_hosts)
{
    std::vector<DnsPcb> dns_pcbs;
    std::vector<DnsServer> servers;

    /* initialize default DNS server address */
    // IpAddrInfo dnsserver{}; // DNS_SERVER_ADDRESS(&dnsserver);
    dns_setserver(default_dns_server, servers);
    ns_assert("sanity check SIZEOF_DNS_QUERY",
                sizeof(struct DnsQuery) == DNS_QUERY_LEN);
    ns_assert("sanity check SIZEOF_DNS_ANSWER",
                sizeof(struct DnsAnswer) <= SIZEOF_DNS_ANSWER_ASSERT);
    Logf(true, ("dns_init: initializing\n"));
    /* if dns client not yet initialized... */
    if (dns_pcbs.empty()) {
        DnsPcb new_pcb = dns_new_ip_type(IP_ADDR_TYPE_ANY);
        dns_pcbs.push_back(new_pcb);
        /* initialize DNS table not needed (initialized to zero since it is a global
         * variable) */
        /* initialize DNS client */
        IpAddrInfo any_addr = ip_addr_create_any();
        dns_bind(netifs,
                 ports,
                 dns_pcbs,
                 new_pcb,
                 any_addr,
                 0);
        // udp_recv(dns_pcbs[0], dns_recv, nullptr);
    }
    auto local_host_list = dns_init_local(initial_local_hosts);
    return std::make_tuple(true, dns_pcbs, servers, local_host_list);
}


/**
 * @ingroup dns
 * Initialize one of the DNS servers.
 *
 * @param index the index of the DNS server to set must be < DNS_MAX_SERVERS
 * @param dnsserver IP address of the DNS server to set
 * @param servers
 */
bool
dns_setserver(DnsServer& dnsserver, std::vector<DnsServer>& servers)
{
    servers.push_back(dnsserver);
    return true;
}


/**
 * @ingroup dns
 * Obtain one of the currently configured DNS server.
 *
 * @param server_id the index of the DNS server
 * @param servers
 * @return IP address of the indexed DNS server or "ip_addr_any" if the DNS
 *         server has not been configured.
 */
// TODO: rewrite
std::tuple<bool, DnsServer>
dns_getserver(const uint32_t server_id, std::vector<DnsServer>& servers)
{
    for (auto& server : servers) {
        if (server.id == server_id) {
            return std::make_tuple(true, server);
        }
    }

    DnsServer empty{};

    return std::make_tuple(false, empty);
}

/**
 * The DNS resolver client timer - handle retries and timeouts and should
 * be called every DNS_TMR_INTERVAL milliseconds (every second by default).
 */
void dns_tmr()
{
    Logf(true, ("dns_tmr: dns_check_entries\n"));
    dns_check_entries();
}


std::vector<LocalHostListEntry>
dns_init_local(std::vector<LocalHostListEntry>& init_entries)
{
    std::vector<LocalHostListEntry> local_host_list;

    if (!init_entries.empty()) {
        for (auto& ie : init_entries) {
            local_host_list.push_back(ie);
        }
    }

    return local_host_list;
}


/**
 * Scans the local host-list for a hostname.
 *
 * @param hostname Hostname to look for in the local host-list
 * @param entries
 * @param addr the first IP address for the hostname in the local host-list or
 *         IPADDR_NONE if not found.
 * @param dns_addrtype - LWIP_DNS_ADDRTYPE_IPV4_IPV6: try to resolve IPv4 (ATTENTION: no fallback here!)
 *                     - LWIP_DNS_ADDRTYPE_IPV6_IPV4: try to resolve IPv6 (ATTENTION: no fallback here!)
 *                     - LWIP_DNS_ADDRTYPE_IPV4: try to resolve IPv4 only
 *                     - LWIP_DNS_ADDRTYPE_IPV6: try to resolve IPv6 only
 * @return ERR_OK if found, ERR_ARG if not found
 */
std::tuple<bool, IpAddrInfo>
dns_local_lookup(const std::string& hostname, const std::vector<LocalHostListEntry>& entries)
{
    for (auto& e : entries) {
        if (e.name == hostname) {
            return std::make_tuple(true, e.addr);
        }
    }

    IpAddrInfo empty{};
    return std::make_tuple(false, empty);
}


/**
 * Remove all entries from the local host-list for a specific hostname
 * and/or IP address
 *
 * @param hostname hostname for which entries shall be removed from the local
 *                 host-list
 * @param address address for which entries shall be removed from the local host-list
 * @param local_host_list
 * @return the number of removed entries
 */
uint32_t
dns_local_remove_host(std::string& hostname,
                      const IpAddrInfo& address,
                      std::vector<LocalHostListEntry>& local_host_list)
{
    uint32_t removed_cnt = 0;
    auto host = local_host_list.begin();
    while (host != local_host_list.end()) {
        if (host->name == hostname) {
            host = local_host_list.erase(host);
            removed_cnt++;
        }
        else if (ip_addr_eq(address, host->addr)) {
            host = local_host_list.erase(host);
            removed_cnt++;
        }
        else { ++host; }
    }
    return removed_cnt;
}

/**
 * Add a hostname/IP address pair to the local host-list.
 * Duplicates are not checked.
 *
 * @param hostname hostname of the new entry
 * @param address IP address of the new entry
 * @param local_hosts
 * @return ERR_OK if succeeded or ERR_MEM on memory error
 */
bool
dns_local_addhost(std::string& hostname,
                  IpAddrInfo& address,
                  std::vector<LocalHostListEntry>& local_hosts)
{
    LocalHostListEntry entry{};
    entry.name = hostname;
    entry.addr = address;
    local_hosts.push_back(entry);
    return true;
}


/**
 * Look up a hostname in the array of known hostnames.
 *
 * @note This function only looks in the internal array of known
 * hostnames, it does not send out a query for the hostname if none
 * was found. The function dns_enqueue() can be used to send a query
 * for a hostname.
 *
 * @param hostname the hostname to look up
 * @param address the hostname's IP address, as uint32_t (instead of IpAddr to
 *         better check for failure: != IPADDR_NONE) or IPADDR_NONE if the hostname
 *         was not found in the cached dns_table.
 * @param dns_entries
 * @param dns_addrtype
 * @return ERR_OK if found, ERR_ARG if not found
 */
std::tuple<bool, DnsTableEntry>
dns_lookup(std::string& hostname,
           IpAddrInfo& address,
           std::vector<DnsTableEntry>& dns_entries)
{
    for (auto& de : dns_entries) {
        if (de.hostname == hostname) { return std::make_tuple(true, de); }
        if (ip_addr_eq(address, de.address)) { return std::make_tuple(true, de); }
    }
    DnsTableEntry empty{};
    return std::make_tuple(false, empty);
}

/**
 * Compare the "dotted" name "query" with the encoded name "response"
 * to make sure an answer from the DNS server matches the current dns_table
 * entry (otherwise, answers might arrive late for hostname not on the list
 * any more).
 *
 * For now, this function compares case-insensitive to cope with all kinds of
 * servers. This also means that "dns 0x20 bit encoding" must be checked
 * externally, if we want to implement it.
 * Currently, the request is sent exactly as passed in by he user request.
 *
 * @param query hostname (not encoded) from the dns_table
 * @param pkt PacketBuffer containing the encoded hostname in the DNS response
 * @param start_offset offset into p where the name starts
 * @return 0xFFFF: names differ, other: names equal -> offset behind name
 *
 * todo: re-write
 */
uint16_t
dns_compare_name(std::string& query, PacketContainer& pkt, size_t start_offset)
{
    int n;
    size_t response_offset = start_offset;
    auto q = query.begin();
    do {
        n = get_pbuf_byte_at(pkt, response_offset);
        if ((n < 0) || (response_offset == 0xFFFF)) {
            /* error or overflow */
            return 0xFFFF;
        }
        response_offset++;
        /** @see RFC 1035 - 4.1.4. Message compression */
        if ((n & 0xc0) == 0xc0) {
            /* Compressed name: cannot be equal since we don't send them */
            return 0xFFFF;
        }
        /* Not compressed name */

        while (n > 0) {
            const auto c = get_pbuf_byte_at(pkt, response_offset);
            if (tolower((*q)) != tolower(static_cast<char>(c))) { return 0xFFFF; }
            if (response_offset == 0xFFFF) {
                /* would overflow */
                return 0xFFFF;
            }
            response_offset++;
            ++q;
            --n;
        }
        ++q;
        n = get_pbuf_byte_at(pkt, response_offset);
        if (n < 0) { return 0xFFFF; }
    }
    while (n != 0);
    if (response_offset == 0xFFFF) {
        /* would overflow */
        return 0xFFFF;
    }
    return (uint16_t)(response_offset + 1);
}

/**
 * Walk through a compact encoded DNS name and return the end of the name.
 *
 * @param p PacketBuffer containing the name
 * @param query_index start index into p pointing to encoded DNS name in the DNS server response
 * @return index to end of the name
 */
uint16_t
dns_skip_name(PacketContainer& p, uint16_t query_index)
{
    int n;
    uint16_t offset = query_index;
    do {
        n = get_pbuf_byte_at(p, offset++);
        if ((n < 0) || (offset == 0)) { return 0xFFFF; }
        /** @see RFC 1035 - 4.1.4. Message compression */
        if ((n & 0xc0) == 0xc0) {
            /* Compressed name: since we only want to skip it (not check it), stop here */
            break;
        }
        /* Not compressed name */
        if (offset + n >= p.data.size()) { return 0xFFFF; }
        offset = (uint16_t)(offset + n);
        n = get_pbuf_byte_at(p, offset);
        if (n < 0) { return 0xFFFF; }
    }
    while (n != 0);
    if (offset == 0xFFFF) { return 0xFFFF; }
    return (uint16_t)(offset + 1);
}

/**
 * Send a DNS query packet.
 *
 * @param idx the DNS table entry index for which to send a request
 * @param dns_entries
 * @param servers
 * @return ERR_OK if packet is sent; an LwipStatus indicating the problem otherwise
 */
bool
dns_send(const uint8_t idx,
         std::vector<DnsTableEntry>& dns_entries,
         std::vector<DnsServer>& servers)
{
    DnsHdr hdr;
    DnsQuery qry;
    uint8_t n;
    auto entry = dns_entries[idx];
    if (ip_addr_is_any(servers[entry.server_idx]) && !entry.is_mdns)
    {
        /* DNS server not valid anymore, e.g. PPP netif has been shut down */
        /* call specified callback function if provided */
        dns_call_found(idx, nullptr); /* flush this entry */
        entry->state = DNS_STATE_UNUSED;
        return STATUS_SUCCESS;
    } /* if here, we have either a new query or a retry on a previous query to process */
    // auto pbuf = pbuf_alloc();
    PacketContainer pbuf{};
    if (pbuf != nullptr)
    {
        const IpAddrInfo* dst;
        uint16_t dst_port; /* fill dns header */
        memset(&hdr, 0, DNS_HDR_LEN);
        hdr.id = ns_htons(entry->txid);
        hdr.flags1 = DNS_FLAG1_RD;
        hdr.numquestions = pp_htons(1);
        pbuf_take(pbuf, reinterpret_cast<uint8_t*>(&hdr), DNS_HDR_LEN);
        const char* hostname = entry->name;
        --hostname; /* convert hostname into suitable query format. */
        uint16_t query_idx = DNS_HDR_LEN;
        do
        {
            ++hostname;
            auto hostname_part = hostname;
            for (n = 0; *hostname != '.' && *hostname != 0; ++hostname)
            {
                ++n;
            }
            auto copy_len = static_cast<uint16_t>(hostname - hostname_part);
            if (query_idx + n + 1 > 0xFFFF)
            {
                /* uint16_t overflow */
                goto overflow_return;
            }
            pbuf_put_at(pbuf, query_idx, n);
            pbuf_take_at(pbuf,
                         (uint8_t*)hostname_part,
                         static_cast<uint16_t>(query_idx + 1));
            query_idx = static_cast<uint16_t>(query_idx + n + 1);
        }
        while (*hostname != 0);
        pbuf_put_at(pbuf, query_idx, 0);
        query_idx++; /* fill dns query */
        if (lwip_dns_addrtype_is_ipv6(entry->reqaddrtype))
        {
            qry.type = pp_htons(DNS_RRTYPE_AAAA);
        }
        else
        {
            qry.type = pp_htons(DNS_RRTYPE_A);
        }
        qry.cls = pp_htons(DNS_RRCLASS_IN);
        pbuf_take_at(pbuf, (uint8_t*)&qry, query_idx);
        uint8_t pcb_idx = entry->pcb_idx; /* send dns packet */ // Logf(true,
        //      ("sending DNS request ID %d for name \"%s\" to server %d\r\n", entry->txid,
        //          entry->name, entry->server_idx));
        if (entry->is_mdns)
        {
            dst_port = DNS_MQUERY_PORT;
            if (lwip_dns_addrtype_is_ipv6(entry->reqaddrtype))
            {
                dst = &dns_mquery_v6group;
            }
            else
            {
                dst = &dns_mquery_v4group;
            }
        }
        else
        {
            dst_port = DNS_SERVER_PORT;
            dst = &dns_servers[entry->server_idx];
        }
        err = udp_sendto(dns_pcbs[pcb_idx], pbuf, dst, dst_port); /* free PacketBuffer */
        free_pkt_buf(pbuf);
    }
    else
    {
        err = STATUS_E_MEM;
    }
    return err;
overflow_return: free_pkt_buf(pbuf);
    return ERR_VAL;
}

UdpPcb* dns_alloc_random_port(void)
{
    NsStatus err;
    UdpPcb* pcb = udp_new_ip_type(IP_ADDR_TYPE_ANY);
    if (pcb == nullptr)
    {
        /* out of memory, have to reuse an existing pcb */
        return nullptr;
    }
    do
    {
        auto port = static_cast<uint16_t>(lwip_rand());
        if (dns_port_allowed(port))
        {
            IpAddrInfo any_addr = ip_addr_create_any();
            err = udp_bind(pcb, &any_addr, port);
        }
        else
        {
            /* this port is not allowed, try again */
            err = ERR_USE;
        }
    }
    while (err == ERR_USE);
    if (err != STATUS_SUCCESS)
    {
        udp_remove(pcb);
        return nullptr;
    }
    // udp_recv(pcb, dns_recv, nullptr);
    return pcb;
}

/**
 * dns_alloc_pcb() - allocates a new pcb (or reuses an existing one) to be used
 * for sending a request
 *
 * @return an index into dns_pcbs
 */
uint8_t
dns_alloc_pcb(void)
{
  uint8_t i;
  uint8_t idx;

  for (i = 0; i < DNS_MAX_SOURCE_PORTS; i++) {
    if (dns_pcbs[i] == nullptr) {
      break;
    }
  }
  if (i < DNS_MAX_SOURCE_PORTS) {
    dns_pcbs[i] = dns_alloc_random_port();
    if (dns_pcbs[i] != nullptr) {
      /* succeeded */
      dns_last_pcb_idx = i;
      return i;
    }
  }
  /* if we come here, creating a new UDP pcb failed, so we have to use
     an already existing one (so overflow is no issue) */
  for (i = 0, idx = (uint8_t)(dns_last_pcb_idx + 1); i < DNS_MAX_SOURCE_PORTS; i++, idx++) {
    if (idx >= DNS_MAX_SOURCE_PORTS) {
      idx = 0;
    }
    if (dns_pcbs[idx] != nullptr) {
      dns_last_pcb_idx = idx;
      return idx;
    }
  }
  return DNS_MAX_SOURCE_PORTS;
}


/**
 * dns_call_found() - call the found callback and check if there are duplicate
 * entries for the given hostname. If there are any, their found callback will
 * be called and they will be removed.
 *
 * @param idx dns table index of the entry that is resolved or removed
 * @param addr IP address for the hostname (or NULL on error or memory shortage)
 */
void
dns_call_found(uint8_t idx, IpAddrInfo *addr)
{
    if (addr != nullptr) {
    /* check that address type matches the request and adapt the table entry */
    if ((*addr.type == IP_ADDR_TYPE_V6)) {
      // lwip_assert("invalid response", LWIP_DNS_ADDRTYPE_IS_IPV6(dns_table[idx].reqaddrtype));
      dns_table[idx].reqaddrtype = LWIP_DNS_ADDRTYPE_IPV6;
    } else {
      // lwip_assert("invalid response", !LWIP_DNS_ADDRTYPE_IS_IPV6(dns_table[idx].reqaddrtype));
      dns_table[idx].reqaddrtype = LWIP_DNS_ADDRTYPE_IPV4;
    }
  }


  // fixme:
  // for (i = 0; i < DNS_MAX_REQUESTS; i++) {
  //   if (dns_requests[i].found && (dns_requests[i].dns_table_idx == idx)) {
  //     (*dns_requests[i].found)(dns_table[idx].name, addr, dns_requests[i].arg);
  //     /* flush this entry */
  //     dns_requests[i].found = nullptr;
  //   }
  // }

  /* close the pcb used unless other request are using it */
  for (uint8_t i = 0; i < DNS_MAX_REQUESTS; i++) {
    if (i == idx) {
      continue; /* only check other requests */
    }
    if (dns_table[i].state == DNS_STATE_ASKING) {
      if (dns_table[i].pcb_idx == dns_table[idx].pcb_idx) {
        /* another request is still using the same pcb */
        dns_table[idx].pcb_idx = DNS_MAX_SOURCE_PORTS;
        break;
      }
    }
  }
  if (dns_table[idx].pcb_idx < DNS_MAX_SOURCE_PORTS) {
    /* if we come here, the pcb is not used any more and can be removed */
    udp_remove(dns_pcbs[dns_table[idx].pcb_idx]);
    dns_pcbs[dns_table[idx].pcb_idx] = nullptr;
    dns_table[idx].pcb_idx = DNS_MAX_SOURCE_PORTS;
  }

}

/* Create a query transmission ID that is unique for all outstanding queries */
uint16_t
dns_create_txid(void)
{
again:
  uint16_t txid = (uint16_t)lwip_rand();

  /* check whether the ID is unique */
  for (uint8_t i = 0; i < DNS_TABLE_SIZE; i++) {
    if ((dns_table[i].state == DNS_STATE_ASKING) &&
        (dns_table[i].txid == txid)) {
      /* ID already used by another pending query */
      goto again;
    }
  }

  return txid;
}

/**
 * Check whether there are other backup DNS servers available to try
 */
uint8_t
dns_backupserver_available(struct DnsTableEntry *pentry)
{
  uint8_t ret = 0;

  if (pentry) {
    if ((pentry->server_idx + 1 < DNS_MAX_SERVERS) && !ip_addr_isany_val(dns_servers[pentry->server_idx + 1])) {
      ret = 1;
    }
  }

  return ret;
}

/**
 * dns_check_entry() - see if entry has not yet been queried and, if so, sends out a query.
 * Check an entry in the dns_table:
 * - send out query for new entries
 * - retry old pending entries on timeout (also with different servers)
 * - remove completed entries from the table if their TTL has expired
 *
 * @param i index of the dns_table entry to check
 */
void
dns_check_entry(uint8_t i)
{
  NsStatus err;
  struct DnsTableEntry *entry = &dns_table[i];

  ns_assert("array index out of bounds", i < DNS_TABLE_SIZE);

  switch (entry->state) {
    case DNS_STATE_NEW:
      /* initialize new entry */
      entry->txid = dns_create_txid();
      entry->state = DNS_STATE_ASKING;
      entry->server_idx = 0;
      entry->tmr = 1;
      entry->retries = 0;

      /* send DNS packet for this entry */
      err = dns_send(i,,);
      if (err != STATUS_SUCCESS) {
        Logf(true,
                    ("dns_send returned error: %s\n", status_to_string(err).c_str()));
      }
      break;
    case DNS_STATE_ASKING:
      if (--entry->tmr == 0) {
        if (++entry->retries == DNS_MAX_RETRIES) {
          if (dns_backupserver_available(entry)

              && !entry->is_mdns

             ) {
            /* change of server */
            entry->server_idx++;
            entry->tmr = 1;
            entry->retries = 0;
          } else {
            Logf(true, ("dns_check_entry: \"%s\": timeout\n", entry->hostname));
            /* call specified callback function if provided */
            dns_call_found(i, nullptr);
            /* flush this entry */
            entry->state = DNS_STATE_UNUSED;
            break;
          }
        } else {
          /* wait longer for the next retry */
          entry->tmr = entry->retries;
        }

        /* send DNS packet for this entry */
        err = dns_send(i,,);
        if (err != STATUS_SUCCESS) {
          Logf(true,
                      ("dns_send returned error: %s\n", status_to_string(err).c_str()));
        }
      }
      break;
    case DNS_STATE_DONE:
      /* if the time to live is nul */
      if ((entry->ttl == 0) || (--entry->ttl == 0)) {
        Logf(true, ("dns_check_entry: \"%s\": flush\n", entry->hostname));
        /* flush this entry, there cannot be any related pending entries in this state */
        entry->state = DNS_STATE_UNUSED;
      }
      break;
    case DNS_STATE_UNUSED:
      /* nothing to do */
      break;
    default:
      ns_assert("unknown dns_table entry state:", false);
      break;
  }
}

/**
 * Call dns_check_entry for each entry in dns_table - check all entries.
 */
void
dns_check_entries(void)
{
    for (uint8_t i = 0; i < DNS_TABLE_SIZE; ++i) {
    dns_check_entry(i);
  }
}

/**
 * Save TTL and call dns_call_found for correct response.
 */
static void
dns_correct_response(uint8_t idx, uint32_t ttl)
{
  struct DnsTableEntry *entry = &dns_table[idx];

  entry->state = DNS_STATE_DONE;

  Logf(true, ("dns_recv: \"%s\": response = ", entry->hostname));
  // ip_addr_debug_print_val(true, entry->ipaddr);
  Logf(true, ("\n"));

  /* read the answer resource record's TTL, and maximize it if needed */
  entry->ttl = ttl;
  if (entry->ttl > DNS_MAX_TTL) {
    entry->ttl = DNS_MAX_TTL;
  }
  dns_call_found(idx, &entry->address);

  if (entry->ttl == 0) {
    /* RFC 883, page 29: "Zero values are
       interpreted to mean that the RR can only be used for the
       transaction in progress, and should not be cached."
       -> flush this entry now */
    /* entry reused during callback? */
    if (entry->state == DNS_STATE_DONE) {
      entry->state = DNS_STATE_UNUSED;
    }
  }
}

/**
 * Receive input function for DNS response packets arriving for the dns UDP pcb.
 */
void dns_recv(void* arg,
                     UdpPcb* pcb,
                     struct PacketContainer* p,
                     const IpAddrInfo* addr,
                     uint16_t port,
                     NetworkInterface* netif)
{
    struct DnsHdr hdr;
    struct DnsAnswer ans;
    struct DnsQuery qry; /* is the dns message big enough ? */
    if (p->tot_len < (DNS_HDR_LEN + DNS_QUERY_LEN))
    {
        Logf(true, ("dns_recv: PacketBuffer too small\n"));
        /* free PacketBuffer and return */
        goto ignore_packet;
    } /* copy dns payload inside static buffer for processing */
    if (pbuf_copy_partial(p, (uint8_t*)&hdr, DNS_HDR_LEN, 0) == DNS_HDR_LEN)
    {
        /* Match the ID in the DNS header with the name table. */
        uint16_t txid = ns_htons(hdr.id);
        for (uint8_t i = 0; i < DNS_TABLE_SIZE; i++)
        {
            struct DnsTableEntry* entry = &dns_table[i];
            if ((entry->state == DNS_STATE_ASKING) && (entry->txid == txid))
            {
                /* We only care about the question(s) and the answers. The authrr
                   and the extrarr are simply discarded. */
                uint16_t nquestions = ns_htons(hdr.numquestions);
                uint16_t nanswers = ns_htons(hdr.numanswers);
                /* Check for correct response. */
                if ((hdr.flags1 & DNS_FLAG1_RESPONSE) == 0)
                {
                    Logf(true, ("dns_recv: \"%s\": not a response\n", entry->hostname));
                    goto ignore_packet; /* ignore this packet */
                }
                if (nquestions != 1)
                {
                    Logf(true,
                         ("dns_recv: \"%s\": response not match to query\n", entry->hostname
                         ));
                    goto ignore_packet; /* ignore this packet */
                }

        if (!entry->is_mdns)

                {
                    /* Check whether response comes from the same network address to which the
                       question was sent. (RFC 5452) */
                    if (!ip_addr_eq(addr, &dns_servers[entry->server_idx]))
                    {
                        goto ignore_packet; /* ignore this packet */
                    }
                } /* Check if the name in the "question" part match with the name in the entry and
           skip it if equal. */
                uint16_t res_idx = dns_compare_name(entry->hostname, p, DNS_HDR_LEN);
                if (res_idx == 0xFFFF)
                {
                    Logf(true,
                         ("dns_recv: \"%s\": response not match to query\n", entry->hostname
                         ));
                    goto ignore_packet; /* ignore this packet */
                } /* check if "question" part matches the request */
                if (pbuf_copy_partial(p, (uint8_t*)&qry, DNS_QUERY_LEN, res_idx) !=
                    DNS_QUERY_LEN)
                {
                    goto ignore_packet; /* ignore this packet */
                }
                if ((qry.cls != pp_htons(DNS_RRCLASS_IN)) || (
                    lwip_dns_addrtype_is_ipv6(entry->reqaddrtype) && (qry.type !=
                        pp_htons(DNS_RRTYPE_AAAA))) || (!
                    lwip_dns_addrtype_is_ipv6(entry->reqaddrtype) && (qry.type != pp_htons(
                        DNS_RRTYPE_A))))
                {
                    Logf(true,
                         ("dns_recv: \"%s\": response not match to query\n", entry->hostname
                         ));
                    goto ignore_packet; /* ignore this packet */
                } /* skip the rest of the "question" part */
                if (res_idx + DNS_QUERY_LEN > 0xFFFF)
                {
                    goto ignore_packet;
                }
                res_idx = (uint16_t)(res_idx + DNS_QUERY_LEN);
                /* Check for error. If so, call callback to inform. */
                if (hdr.flags2 & DNS_FLAG2_ERR_MASK)
                {
                    Logf(true, ("dns_recv: \"%s\": error in flags\n", entry->hostname));
                    /* if there is another backup DNS server to try
                              * then don't stop the DNS request
                              */
                    if (dns_backupserver_available(entry))
                    {
                        /* avoid retrying the same server */
                        entry->retries = DNS_MAX_RETRIES - 1;
                        entry->tmr = 1; /* contact next available server for this entry */
                        dns_check_entry(i);
                        goto ignore_packet;
                    }
                }
                else
                {
                    while ((nanswers > 0) && (res_idx < p->tot_len))
                    {
                        /* skip answer resource record's host name */
                        res_idx = dns_skip_name(p, res_idx);
                        if (res_idx == 0xFFFF)
                        {
                            goto ignore_packet; /* ignore this packet */
                        } /* Check for IP address type and Internet class. Others are discarded. */
                        if (pbuf_copy_partial(p, (uint8_t*)&ans, SIZEOF_DNS_ANSWER, res_idx) !=
                            SIZEOF_DNS_ANSWER)
                        {
                            goto ignore_packet; /* ignore this packet */
                        }
                        if (res_idx + SIZEOF_DNS_ANSWER > 0xFFFF)
                        {
                            goto ignore_packet;
                        }
                        res_idx = (uint16_t)(res_idx + SIZEOF_DNS_ANSWER);
                        if (ans.cls == pp_htons(DNS_RRCLASS_IN))
                        {
                            if ((ans.type == pp_htons(DNS_RRTYPE_A)) && (ans.len ==
                                pp_htons(sizeof(Ip4Addr))))
                            {
                                if (!lwip_dns_addrtype_is_ipv6(entry->reqaddrtype))
                                {
                                    Ip4Addr ip4addr;
                                    /* read the IP address after answer resource record's header */
                                    if (pbuf_copy_partial(
                                        p,
                                        (uint8_t*)&ip4addr,
                                        sizeof(Ip4Addr),
                                        res_idx) != sizeof(Ip4Addr))
                                    {
                                        goto ignore_packet; /* ignore this packet */
                                    }
                                    copy_ip4_addr_to_ip_addr(&dns_table[i].ipaddr, &ip4addr);
                                    free_pkt_buf(p); /* handle correct response */
                                    dns_correct_response(i, ns_ntohl(ans.ttl));
                                    return;
                                }
                            }
                            if ((ans.type == pp_htons(DNS_RRTYPE_AAAA)) && (ans.len ==
                                pp_htons(sizeof(Ip6Addr))))
                            {
                                if (lwip_dns_addrtype_is_ipv6(entry->reqaddrtype))
                                {
                                    Ip6Addr ip6addr{};
                                    /* read the IP address after answer resource record's header */
                                    if (pbuf_copy_partial(
                                        p,
                                        (uint8_t*)&ip6addr,
                                        sizeof(Ip6Addr),
                                        res_idx) != sizeof(Ip6Addr))
                                    {
                                        goto ignore_packet; /* ignore this packet */
                                    } /* @todo: scope ip6addr? Might be required for link-local addresses at least? */
                                    dns_table[i].ipaddr.ip6.addr = ip6addr;

                                    free_pkt_buf(p); /* handle correct response */
                                    dns_correct_response(i, ns_ntohl(ans.ttl));
                                    return;
                                }
                            }
                        } /* skip this answer */
                        if ((int)(res_idx + ns_htons(ans.len)) > 0xFFFF)
                        {
                            goto ignore_packet; /* ignore this packet */
                        }
                        res_idx = (uint16_t)(res_idx + ns_htons(ans.len));
                        --nanswers;
                    }
                    if ((entry->reqaddrtype == LWIP_DNS_ADDRTYPE_IPV4_IPV6) || (entry->
                        reqaddrtype == LWIP_DNS_ADDRTYPE_IPV6_IPV4))
                    {
                        if (entry->reqaddrtype == LWIP_DNS_ADDRTYPE_IPV4_IPV6)
                        {
                            /* IPv4 failed, try IPv6 */
                            dns_table[i].reqaddrtype = LWIP_DNS_ADDRTYPE_IPV6;
                        }
                        else
                        {
                            /* IPv6 failed, try IPv4 */
                            dns_table[i].reqaddrtype = LWIP_DNS_ADDRTYPE_IPV4;
                        }
                        free_pkt_buf(p);
                        dns_table[i].state = DNS_STATE_NEW;
                        dns_check_entry(i);
                        return;
                    }
                    Logf(true,
                         ("dns_recv: \"%s\": error in response\n", entry->hostname));
                } /* call callback to indicate error, clean up memory and return */
                free_pkt_buf(p);
                dns_call_found(i, nullptr);
                dns_table[i].state = DNS_STATE_UNUSED;
                return;
            }
        }
    }
ignore_packet: /* deallocate memory and return */ free_pkt_buf(p);
}

/**
 * Queues a new hostname to resolve and sends out a DNS query for that hostname
 *
 * @param name the hostname that is to be queried
 * @param dns_addrtype
 * @param is_mdns
 * @param dns_table
 * @return LwipStatus return code.
 */
NsStatus
dns_enqueue(std::string& name,
            uint8_t dns_addrtype,
            const bool is_mdns,
            std::vector<DnsTableEntry>& dns_table,
            std::vector<DnsRequestEntry>& dns_requests)
{
    uint8_t i;
    struct DnsTableEntry* entry = nullptr;
    uint8_t r; /* check for duplicate entries */
    for (i = 0; i < DNS_TABLE_SIZE; i++)
    {
        if ((dns_table[i].state == DNS_STATE_ASKING) && (name == dns_table[i].hostname))
        {
            if (dns_table[i].reqaddrtype != dns_addrtype)
            {
                /* requested address types don't match
                   this can lead to 2 concurrent requests, but mixing the address types
                   for the same host should not be that common */
                continue;
            }

            DnsRequestEntry entry{};
            entry.dns_table_idx = i;
            entry.addr_type = dns_addrtype;
            dns_requests.push_back(entry);
            return STATUS_E_INPROGRESS
            
        }
    } /* no duplicate entries found */ /* search an unused entry, or the oldest one */
    uint8_t lseq = 0;
    uint8_t lseqi = DNS_TABLE_SIZE;
    for (i = 0; i < DNS_TABLE_SIZE; ++i)
    {
        entry = &dns_table[i]; /* is it an unused entry ? */
        if (entry->state == DNS_STATE_UNUSED)
        {
            break;
        } /* check if this is the oldest completed entry */
        if (entry->state == DNS_STATE_DONE)
        {
            uint8_t age = (uint8_t)(dns_seqno - entry->seqno);
            if (age > lseq)
            {
                lseq = age;
                lseqi = i;
            }
        }
    } /* if we don't have found an unused entry, use the oldest completed one */
    if (i == DNS_TABLE_SIZE)
    {
        if ((lseqi >= DNS_TABLE_SIZE) || (dns_table[lseqi].state != DNS_STATE_DONE))
        {
            /* no entry can be used now, table is full */
            Logf(true, ("dns_enqueue: \"%s\": DNS entries table is full\n", name));
            return STATUS_E_MEM;
        }
        else
        {
            /* use the oldest completed one */
            i = lseqi;
            entry = &dns_table[i];
        }
    } /* find a free request entry */
    struct DnsRequestEntry* req = nullptr;
    for (r = 0; r < DNS_MAX_REQUESTS; r++)
    {
        if (dns_requests[r].found == nullptr)
        {
            req = &dns_requests[r];
            break;
        }
    }
    if (req == nullptr)
    {
        /* no request entry can be used now, table is full */
        Logf(true,
             ("dns_enqueue: \"%s\": DNS request entries table is full\n", name));
        return STATUS_E_MEM;
    }
    req->dns_table_idx = i; /* use this entry */ /* fill the entry */
    entry->state = DNS_STATE_NEW;
    entry->seqno = dns_seqno;
    lwip_dns_set_addrtype(entry->reqaddrtype, dns_addrtype);
    lwip_dns_set_addrtype(req->addr_type, dns_addrtype);
    req->found = found;
    req->arg = callback_arg;
    const size_t dns_name_len_sz = DNS_MAX_NAME_LENGTH - 1;
    const size_t namelen = std::min(hostnamelen, dns_name_len_sz);
    memcpy(entry->hostname, name, namelen);
    entry->hostname[namelen] = 0;
    entry->pcb_idx = dns_alloc_pcb();
    if (entry->pcb_idx >= DNS_MAX_SOURCE_PORTS)
    {
        /* failed to get a UDP pcb */
        Logf(true, ("dns_enqueue: \"%s\": failed to allocate a pcb\n", name));
        entry->state = DNS_STATE_UNUSED;
        req->found = nullptr;
        return STATUS_E_MEM;
    }

    entry->is_mdns = is_mdns;
    dns_seqno++; /* force to send query without waiting timer */
    dns_check_entry(i); /* dns query is enqueued */
    return STATUS_E_INPROGRESS;
}

/**
 * @ingroup dns
 * Resolve a hostname (string) into an IP address.
 * NON-BLOCKING callback version for use with raw API!!!
 *
 * Returns immediately with one of LwipStatus return codes:
 * - ERR_OK if hostname is a valid IP address string or the host
 *   name is already in the local names table.
 * - ERR_INPROGRESS enqueue a request to be sent to the DNS server
 *   for resolution if no errors are present.
 * - ERR_ARG: dns client not initialized or invalid hostname
 *
 * @param hostname the hostname that is to be queried
 * @param addr pointer to a IpAddr where to store the address if it is already
 *             cached in the dns_table (only valid if ERR_OK is returned!)
 * @param found a callback function to be called on success, failure or timeout (only if
 *              ERR_INPROGRESS is returned!)
 * @param callback_arg argument to pass to the callback function
 * @return a LwipStatus return code.
 */
NsStatus
dns_gethostbyname(const char *hostname, IpAddrInfo *addr, dns_found_callback found,
                  uint8_t *callback_arg)
{
  return dns_gethostbyname_addrtype(hostname, addr, found, callback_arg, LWIP_DNS_ADDRTYPE_DEFAULT);
}

/**
 * @ingroup dns
 * Like dns_gethostbyname, but returned address type can be controlled:
 * @param hostname the hostname that is to be queried
 * @param addr pointer to a IpAddr where to store the address if it is already
 *             cached in the dns_table (only valid if ERR_OK is returned!)
 * @param found a callback function to be called on success, failure or timeout (only if
 *              ERR_INPROGRESS is returned!)
 * @param callback_arg argument to pass to the callback function
 * @param dns_addrtype - LWIP_DNS_ADDRTYPE_IPV4_IPV6: try to resolve IPv4 first, try IPv6 if IPv4 fails only
 *                     - LWIP_DNS_ADDRTYPE_IPV6_IPV4: try to resolve IPv6 first, try IPv4 if IPv6 fails only
 *                     - LWIP_DNS_ADDRTYPE_IPV4: try to resolve IPv4 only
 *                     - LWIP_DNS_ADDRTYPE_IPV6: try to resolve IPv6 only
 */
NsStatus dns_gethostbyname_addrtype(std::string& hostname,
                                      IpAddrInfo& addr,
                                      uint8_t dns_addrtype)
{
    if ((addr == nullptr) || (!hostname) || (!hostname[0]))
    {
        return STATUS_E_INVALID_ARG;
    }
    if (dns_pcbs[0] == nullptr)
    {
        return STATUS_E_INVALID_ARG;
    }
    size_t hostnamelen = strlen(hostname);
    if (hostnamelen >= DNS_MAX_NAME_LENGTH)
    {
        Logf(true, ("dns_gethostbyname: name too long to resolve"));
        return STATUS_E_INVALID_ARG;
    }
    if (strcmp(hostname, "localhost") == 0)
    {
        ip_addr_set_loopback(addr, lwip_dns_addrtype_is_ipv6(dns_addrtype));
        return STATUS_SUCCESS;
    } /* host name already in octet notation? set ip addr and return ERR_OK */
    if (ip_addr_aton(hostname, addr))
    {
        if ((addr.type == IP_ADDR_TYPE_V6 && (dns_addrtype != LWIP_DNS_ADDRTYPE_IPV4)) || (
            addr.type == IP_ADDR_TYPE_V4 && (dns_addrtype != LWIP_DNS_ADDRTYPE_IPV6)))
        {
            return STATUS_SUCCESS;
        }
    }
    // already have this address cached?
    if (dns_lookup(hostname, addr,) == STATUS_SUCCESS)
    {
        return STATUS_SUCCESS;
    }
    if ((dns_addrtype == LWIP_DNS_ADDRTYPE_IPV4_IPV6) || (dns_addrtype ==
        LWIP_DNS_ADDRTYPE_IPV6_IPV4))
    {
        /* fallback to 2nd IP type and try again to lookup */
        uint8_t fallback;
        if (dns_addrtype == LWIP_DNS_ADDRTYPE_IPV4_IPV6)
        {
            fallback = LWIP_DNS_ADDRTYPE_IPV6;
        }
        else
        {
            fallback = LWIP_DNS_ADDRTYPE_IPV4;
        }
        if (dns_lookup(hostname, addr,) == STATUS_SUCCESS)
        {
            return STATUS_SUCCESS;
        }
    }
    bool is_mdns = false;
    if (strstr(hostname, ".local") == &hostname[hostnamelen] - 6)
    {
        is_mdns = true;
    }
    else
    {
        is_mdns = false;
    }
    if (!is_mdns)
    {
        /* prevent calling found callback if no server is set, return error instead */
        if (ip_addr_isany_val(dns_servers[0]))
        {
            return ERR_VAL;
        }
    } /* queue query with specified callback */
    return dns_enqueue(hostname,
                       dns_addrtype,
                       is_mdns, , dns_addrtype);
}


/**
 * Bind a DNS PCB
 * @param netifs
 * @param ports
 * @param dns_pcbs
 * @param pcb UDP PCB to be bound with a local address ipaddr and port.
 * @param ip_addr
 * @param ipaddr local IP address to bind with. Use IP_ANY_TYPE to
 * bind to all local interfaces.
 * @param port local UDP port to bind with. Use 0 to automatically bind
 * to a random port between UDP_LOCAL_PORT_RANGE_START and
 * UDP_LOCAL_PORT_RANGE_END.
 *
 * ipaddr & port are expected to be in the same byte order as in the pcb.
 *
 * @return lwIP error code.
 * - ERR_OK. Successful. No error occurred.
 * - ERR_USE. The specified ipaddr and port are already bound to by
 * another UDP PCB.
 *
 * @see udp_disconnect()
 */
bool
dns_bind(std::vector<NetworkInterface>& netifs,
         std::vector<NetworkPort>& ports,
         std::vector<DnsPcb>& dns_pcbs,
         DnsPcb& pcb,
         IpAddrInfo& ip_addr,
         uint16_t port)
{
    IpAddrInfo zoned_ipaddr{};
    bool ok;
    bool rebind = false;

    /* Don't propagate NULL pointer (IPv4 ANY) to subsequent functions */
    // Logf(true | LWIP_DBG_TRACE, ("udp_bind(ipaddr = "));
    // ip_addr_debug_print(true | LWIP_DBG_TRACE, ipaddr);
    // Logf(true | LWIP_DBG_TRACE, ", port = %d)\n", port);
    /* Check for double bind and rebind of the same pcb */
    for (auto& ipcb : dns_pcbs) {
        if (pcb.id == ipcb.id) {
            rebind = true;
            break;
        }
    }

    /*
     * If the given IP address should have a zone but doesn't, assign one now.
     * This is legacy support: scope-aware callers should always provide properly
     * zoned source addresses. Do the zone selection before the address-in-use
     * check below; as such we have to make a temporary copy of the address.
     */
    if ((ip_addr.type == IP_ADDR_TYPE_V6) && ip6_addr_lacks_zone((ip_addr.u_addr.ip6), IP6_UNKNOWN)
    ) {
        zoned_ipaddr = ip_addr;
        select_ip6_addr_zone(zoned_ipaddr.u_addr.ip6, zoned_ipaddr.u_addr.ip6, netifs);
        ip_addr = zoned_ipaddr;
    }

    /* no port specified? */
    if (port == 0) {
        std::tie(ok, port) = reserve_port(ports);
        if (!ok) {
            /* no more ports available in local range */
            spdlog::error("udp_bind: out of free UDP ports\n");
            return false;
        }
    }
    else {
        for (auto& ipcb : dns_pcbs) {
            if (pcb.id != ipcb.id) {
                /* By default, we don't allow to bind to a port that any other udp
                   PCB is already bound to, unless *all* PCBs with that port have tha
                   REUSEADDR flag set. */

                if (pcb.sock_opts & SOF_REUSEADDR == 0 || ipcb.sock_opts & SOF_REUSEADDR == 0) {
                    if (ipcb.local_port == port && (ip_addr_eq(ipcb.local_ip, ip_addr) || ip_addr_is_any(ip_addr) || ip_addr_is_any(ipcb.local_ip))) {
                        spdlog::error("udp_bind: local port {} already bound by another pcb\n",
                             port);
                        return false;
                    }
                }
            }
        }
    }
    pcb.local_ip = ip_addr;
    pcb.local_port = port;
    // mib2_udp_bind(pcb); /* pcb not active yet? */
    if (rebind == 0)
    {
        /* place the PCB on the active list if not already there */
        // pcb->next = udp_pcbs;
        // udp_pcbs = pcb;
    }
    // Logf(true | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("udp_bind: bound to "));
    // ip_addr_debug_print_val(true | LWIP_DBG_TRACE | LWIP_DBG_STATE, pcb->local_ip);
    // Logf(true | LWIP_DBG_TRACE | LWIP_DBG_STATE, (", port %d)\n", pcb->local_port));
    return true;
}


//
// END OF FILE
//