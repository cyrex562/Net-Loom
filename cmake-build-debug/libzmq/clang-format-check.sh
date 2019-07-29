#!/bin/sh
FAILED=0
IFS=";"
FILES="../../src/ND6.CPP;../../src/arc4.cpp;../../src/arc4.h;../../src/arch.h;../../src/auth.cpp;../../src/auth.h;../../src/autoip.cpp;../../src/autoip.h;../../src/bridgeif.cpp;../../src/bridgeif.h;../../src/bridgeif_fdb.cpp;../../src/ccp.cpp;../../src/ccp.h;../../src/chap_md5.cpp;../../src/chap_md5.h;../../src/chap_ms.cpp;../../src/chap_ms.h;../../src/chap_new.cpp;../../src/chap_new.h;../../src/def.cpp;../../src/def.h;../../src/demand.cpp;../../src/demand.h;../../src/des.cpp;../../src/des.h;../../src/dhcp.cpp;../../src/dhcp.h;../../src/dhcp6.cpp;../../src/dhcp6.h;../../src/dns.cpp;../../src/dns.h;../../src/eap.cpp;../../src/eap.h;../../src/eap_state.h;../../src/ecp.cpp;../../src/ecp.h;../../src/etharp.cpp;../../src/etharp.h;../../src/ethernet.cpp;../../src/ethernet.h;../../src/ethip6.cpp;../../src/ethip6.h;../../src/eui64.cpp;../../src/eui64.h;../../src/fsm.cpp;../../src/fsm.h;../../src/iana.h;../../src/icmp.cpp;../../src/icmp.h;../../src/icmp6.cpp;../../src/icmp6.h;../../src/ieee.h;../../src/ieee802154.h;../../src/igmp.cpp;../../src/igmp.h;../../src/igmp_grp.h;../../src/inet_chksum.cpp;../../src/inet_chksum.h;../../src/init.cpp;../../src/init.h;../../src/ip.cpp;../../src/ip.h;../../src/ip4.cpp;../../src/ip4.h;../../src/ip4_addr.cpp;../../src/ip4_addr.h;../../src/ip4_frag.cpp;../../src/ip4_frag.h;../../src/ip6.cpp;../../src/ip6.h;../../src/ip6_addr.cpp;../../src/ip6_addr.h;../../src/ip6_frag.cpp;../../src/ip6_frag.h;../../src/ip_addr.h;../../src/ipcp.cpp;../../src/ipcp.h;../../src/ipcp_defs.h;../../src/ipv6cp.cpp;../../src/ipv6cp.h;../../src/lcp.cpp;../../src/lcp.h;../../src/lowpan6.cpp;../../src/lowpan6.h;../../src/lowpan6_ble.cpp;../../src/lowpan6_ble.h;../../src/lowpan6_common.cpp;../../src/lowpan6_common.h;../../src/lowpan6_opts.h;../../src/lwip_debug.h;../../src/lwip_sockets.h;../../src/lwip_status.h;../../src/lwipopts.h;../../src/mac_address.h;../../src/magic.cpp;../../src/magic.h;../../src/md4.cpp;../../src/md4.h;../../src/md5.cpp;../../src/md5.h;../../src/mld6.cpp;../../src/mld6.h;../../src/mppe.cpp;../../src/mppe.h;../../src/multilink.cpp;../../src/nd6.h;../../src/nd6_priv.h;../../src/netbuf.h;../../src/netdb.h;../../src/netifapi.h;../../src/network_interface.cpp;../../src/network_interface.h;../../src/opt.h;../../src/packet_buffer.cpp;../../src/packet_buffer.h;../../src/pcapif.cpp;../../src/pcapif.h;../../src/pcapif_helper.cpp;../../src/pcapif_helper.h;../../src/perf.h;../../src/ppp.cpp;../../src/ppp.h;../../src/ppp_defs.h;../../src/ppp_impl.h;../../src/ppp_opts.h;../../src/pppapi.cpp;../../src/pppapi.h;../../src/pppcrypt.cpp;../../src/pppcrypt.h;../../src/pppdebug.h;../../src/pppoe.cpp;../../src/pppoe.h;../../src/pppol2tp.cpp;../../src/pppol2tp.h;../../src/pppos.cpp;../../src/pppos.h;../../src/protent.h;../../src/raw.cpp;../../src/raw.h;../../src/raw_priv.h;../../src/sha1.cpp;../../src/sha1.h;../../src/sio.cpp;../../src/sio.h;../../src/slipif.cpp;../../src/slipif.h;../../src/sys.cpp;../../src/sys.h;../../src/tcp.cpp;../../src/tcp.h;../../src/tcp_in.cpp;../../src/tcp_in.h;../../src/tcp_out.cpp;../../src/tcp_priv.h;../../src/tcpbase.h;../../src/tcpip.h;../../src/tcpip_priv.h;../../src/timeouts.cpp;../../src/timeouts.h;../../src/udp.cpp;../../src/udp.h;../../src/upap.cpp;../../src/upap.h;../../src/utils.cpp;../../src/vj.cpp;../../src/vj.h;../../src/zepif.cpp;../../src/zepif.h"
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