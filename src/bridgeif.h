#pragma once

#include <ethernet.h>
#include <lwip_status.h>
struct NetworkInterface;
typedef uint64_t BridgeIfcPortMask;

constexpr auto BRIDGE_FLOOD = BridgeIfcPortMask(-1);
constexpr auto kBridgeIfcMaxPorts = 7;
constexpr auto kBridgeIfcDebug = true;
constexpr auto kBridgeIfcFdbDebug = true;
constexpr auto kBridgeIfcFwDebug = true;

struct BridgeInterface;

struct BridgeIfcPort
{
    // BridgeInterface bridge;
    NetworkInterface port_netif;
    uint32_t port_num;
};

struct BridgeFdbEntry
{
    bool used;
    BridgeIfcPortMask dst_ports;
    uint8_t port;
    uint64_t ts;
    MacAddress addr;
    bool dynamic;
};

struct BridgeInterface
{
    NetworkInterface netif;
    struct MacAddress mac_address;
    std::vector<BridgeIfcPort> ports;
    std::vector<BridgeFdbEntry> fdbs;
};

/**
 * Initialisation data for @ref bridgeif_init.
 * An instance of this type must be passed as parameter 'state' to @ref netif_add
 * when the bridge is added.
 */
struct BridgeIfcInitData {
  /** MAC address of the bridge (cannot use the netif's addresses) */
  struct MacAddress MacAddress;
  /** Maximum number of ports in the bridge (ports are stored in an array, this
      influences memory allocated for netif->state of the bridge netif). */
  uint8_t            max_ports;
  /** Maximum number of dynamic/learning entries in the bridge's forwarding database.
      In the default implementation, this controls memory consumption only. */
  uint16_t           max_fdb_dynamic_entries;
  /** Maximum number of static forwarding entries. Influences memory consumption! */
  uint16_t           max_fdb_static_entries;
} ;

/** @ingroup bridgeif
 * Use this for constant initialization of a bridgeif_initdat_t
 * (MacAddress must be passed as make_eth_addr_from_bytes())
 */
//#define BRIDGEIF_INITDATA1(max_ports, max_fdb_dynamic_entries, max_fdb_static_entries, MacAddress) {MacAddress, max_ports, max_fdb_dynamic_entries, max_fdb_static_entries}
/** @ingroup bridgeif
 * Use this for constant initialization of a bridgeif_initdat_t
 * (each byte of MacAddress must be passed)
 */
//#define BRIDGEIF_INITDATA2(max_ports, max_fdb_dynamic_entries, max_fdb_static_entries, e0, e1, e2, e3, e4, e5) {{e0, e1, e2, e3, e4, e5}, max_ports, max_fdb_dynamic_entries, max_fdb_static_entries}

LwipStatus bridgeif_init(NetworkInterface*netif);
LwipStatus bridgeif_add_port(NetworkInterface*bridgeif, NetworkInterface*portif);


bool
bridgeif_fdb_add(const MacAddress& addr,
                 BridgeIfcPortMask ports,
                 BridgeInterface
                 & bridge_ifc);


bool
remove_bridgeif_fdb(BridgeInterface& bridge_ifc, const MacAddress& addr);

/* FDB interface, can be replaced by own implementation */
bool bridgeif_fdb_update_src(void* fdb_ptr, struct MacAddress* src_addr, uint8_t port_idx);
BridgeIfcPortMask bridgeif_fdb_get_dst_ports(BridgeInterface& fdb_ptr, MacAddress& dst_addr);

// BridgeIfcFdb* bridgeif_fdb_init(uint16_t max_fdb_entries);

static LwipStatus bridgeif_tcpip_input(struct PacketBuffer* p, NetworkInterface* netif);

//
// END OF FILE
//
