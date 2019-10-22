#!/bin/sh
FAILED=0
IFS=";"
FILES="../../src/auto_ip/auto_ip.cpp;../../src/auto_ip/auto_ip.h;../../src/auto_ip/auto_ip_state.h;../../src/bridge/bridge_if.cpp;../../src/bridge/bridge_if.h;../../src/bridge/bridge_if_fdb.cpp;../../src/common/ieee_802_15_4.h;../../src/common/init.cpp;../../src/common/init.h;../../src/common/ip4_addr.cpp;../../src/common/ip4_addr.h;../../src/common/ip6_addr.cpp;../../src/common/ip6_addr.h;../../src/common/ip_addr.h;../../src/common/mac_address.h;../../src/common/netbuf.h;../../src/common/netdb.h;../../src/common/netif_api.h;../../src/common/netloom_arch.h;../../src/common/netloom_config.h;../../src/common/netloom_debug.h;../../src/common/netloom_iana.h;../../src/common/netloom_ieee.h;../../src/common/netloom_socket.h;../../src/common/netloom_status.h;../../src/common/netloom_sys.cpp;../../src/common/netloom_sys.h;../../src/common/netloom_util.h;../../src/common/network_flow.h;../../src/common/network_interface.cpp;../../src/common/network_interface.h;../../src/common/network_stack.h;../../src/common/network_workflow.h;../../src/common/packet.cpp;../../src/common/packet.h;../../src/common/timeouts.cpp;../../src/common/timeouts.h;../../src/dhcp/dhcp.cpp;../../src/dhcp/dhcp.h;../../src/dhcp/dhcp6.cpp;../../src/dhcp/dhcp6.h;../../src/dhcp/dhcp6_context.h;../../src/dhcp/dhcp6_def.h;../../src/dhcp/dhcp_context.h;../../src/dns/dns.cpp;../../src/dns/dns.h;../../src/dns/dns_workflow.h;../../src/ethernet/eth_arp.cpp;../../src/ethernet/eth_arp.h;../../src/ethernet/eth_ip6.cpp;../../src/ethernet/eth_ip6.h;../../src/ethernet/ethernet.cpp;../../src/ethernet/ethernet.h;../../src/icmp/icmp.cpp;../../src/icmp/icmp.h;../../src/icmp/icmp6.cpp;../../src/icmp/icmp6.h;../../src/igmp/igmp.cpp;../../src/igmp/igmp.h;../../src/igmp/igmp_grp.h;../../src/ip/inet_chksum.cpp;../../src/ip/inet_chksum.h;../../src/ip/ip.cpp;../../src/ip/ip.h;../../src/ip/ip4.cpp;../../src/ip/ip4.h;../../src/ip/ip4_frag.cpp;../../src/ip/ip4_frag.h;../../src/ip/ip6.cpp;../../src/ip/ip6.h;../../src/ip/ip6_frag.cpp;../../src/ip/ip6_frag.h;../../src/ip/mld6.cpp;../../src/ip/mld6.h;../../src/ip/mld6_group.h;../../src/ip/nd6.cpp;../../src/ip/nd6.h;../../src/ip/nd6_priv.h;../../src/ipcp/ipcp.cpp;../../src/ipcp/ipcp.h;../../src/ipcp/ipcp_defs.h;../../src/ipcp/ipv6cp.cpp;../../src/ipcp/ipv6cp.h;../../src/lowpan/lowpan6.cpp;../../src/lowpan/lowpan6.h;../../src/lowpan/lowpan6_ble.cpp;../../src/lowpan/lowpan6_ble.h;../../src/lowpan/lowpan6_common.cpp;../../src/lowpan/lowpan6_common.h;../../src/lowpan/lowpan6_opts.h;../../src/main.cpp;../../src/pcap/pcap_if.cpp;../../src/pcap/pcap_if.h;../../src/ppp/eui64.cpp;../../src/ppp/eui64.h;../../src/ppp/ppp.cpp;../../src/ppp/ppp.h;../../src/ppp/ppp_api.cpp;../../src/ppp/ppp_api.h;../../src/ppp/ppp_auth.cpp;../../src/ppp/ppp_auth.h;../../src/ppp/ppp_ccp.cpp;../../src/ppp/ppp_ccp.h;../../src/ppp/ppp_ccp_options.h;../../src/ppp/ppp_chap_md5.cpp;../../src/ppp/ppp_chap_md5.h;../../src/ppp/ppp_chap_ms.cpp;../../src/ppp/ppp_chap_ms.h;../../src/ppp/ppp_chap_new.cpp;../../src/ppp/ppp_chap_new.h;../../src/ppp/ppp_config.h;../../src/ppp/ppp_crypt.cpp;../../src/ppp/ppp_crypt.h;../../src/ppp/ppp_debug.h;../../src/ppp/ppp_def.h;../../src/ppp/ppp_demand.cpp;../../src/ppp/ppp_demand.h;../../src/ppp/ppp_eap.cpp;../../src/ppp/ppp_eap.h;../../src/ppp/ppp_eap_state.h;../../src/ppp/ppp_ecp.cpp;../../src/ppp/ppp_ecp.h;../../src/ppp/ppp_fsm.cpp;../../src/ppp/ppp_fsm.h;../../src/ppp/ppp_fsm_def.h;../../src/ppp/ppp_lcp.cpp;../../src/ppp/ppp_lcp.h;../../src/ppp/ppp_lcp_options.h;../../src/ppp/ppp_magic.cpp;../../src/ppp/ppp_magic.h;../../src/ppp/ppp_mppe.cpp;../../src/ppp/ppp_mppe.h;../../src/ppp/ppp_mppe_def.h;../../src/ppp/ppp_multilink.cpp;../../src/ppp/ppp_upap.cpp;../../src/ppp/ppp_upap.h;../../src/ppp/ppp_upap_state.h;../../src/ppp/pppoe.cpp;../../src/ppp/pppoe.h;../../src/ppp/pppol2tp.cpp;../../src/ppp/pppol2tp.h;../../src/ppp/pppos.cpp;../../src/ppp/pppos.h;../../src/raw/raw_if.cpp;../../src/raw/raw_if.h;../../src/serial/sio.cpp;../../src/serial/sio.h;../../src/serial/slip_if.cpp;../../src/serial/slip_if.h;../../src/tcp/tcp.cpp;../../src/tcp/tcp.h;../../src/tcp/tcp_in.cpp;../../src/tcp/tcp_in.h;../../src/tcp/tcp_out.cpp;../../src/tcp/tcp_priv.h;../../src/tcp/tcp_udp.h;../../src/tcp/tcpbase.h;../../src/tcp/tcpip.h;../../src/tcp/tcpip_priv.h;../../src/tcp/vj_comp.cpp;../../src/tcp/vj_comp.h;../../src/udp/udp.cpp;../../src/udp/udp.h;../../src/zigbee/zigbee_encap.cpp;../../src/zigbee/zigbee_encap.h"
IDS=$(echo -en "\n\b")
for FILE in $FILES
do
	clang-format -style=file -output-replacements-xml "$FILE" | grep "<replacement " >/dev/null &&
    {
      echo "$FILE is not correctly formatted"
	  FAILED=1
	}
done
if [ "$FAILED" -eq "1" ] ; then exit 1 ; fi
