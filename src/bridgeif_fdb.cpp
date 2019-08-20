#include <bridgeif.h>
#include <cstring>
#include <sys.h>

// constexpr auto BRIDGE_IF_AGE_TIMER_MS = 1000;
constexpr auto BRIDGE_FDB_TIMEOUT_SEC = (60*5) /* 5 minutes FDB timeout */;


/**
 * @ingroup bridgeif_fdb
 * A real simple and slow implementation of an auto-learning forwarding database that
 * remembers known src mac addresses to know which port to send frames destined for that
 * mac address.
 *
 * ATTENTION: This is meant as an example only, in real-world use, you should
 * provide a better implementation :-)
 */
bool
bridgeif_fdb_update_src(std::vector<BridgeFdbEntry>& fdb,
                        MacAddress& src_addr,
                        uint64_t port_idx)
{
    int i;
    for (auto& e : fdb)
    {
        if (e.used && e.ts)
        {
            if (memcmp(&e.addr, &src_addr, sizeof(struct MacAddress)) == 0)
            {
                e.ts = BRIDGE_FDB_TIMEOUT_SEC;
                e.port = port_idx;
                return true;
            }
        }
    }
    BridgeFdbEntry entry{};
    entry.ts = BRIDGE_FDB_TIMEOUT_SEC;
    entry.port = port_idx;
    entry.used = true;
    fdb.push_back(entry);
    return true;
}

/**
 * Walk our list of auto-learnt fdb entries and return a port to forward or BR_FLOOD if unknown
 */
BridgeIfcPortMask bridgeif_fdb_get_dst_ports(std::vector<BridgeFdbEntry>& entries, MacAddress& dst_addr)
{
    for (auto& entry : entries)
    {
        if(cmp_mac_address(entry.addr, dst_addr))
        {
            return BridgeIfcPortMask(uint64_t(1 << entry.port));
        }
    }

    return BRIDGE_FLOOD;
}


/**
 * Aging implementation of our simple fdb
 */
bool bridgeif_fdb_age_one_second(std::vector<BridgeFdbEntry>& entries)
{
    for (auto& entry : entries)
    {
        entry.ts--;
        // todo: check timestamps against limits in time elapsed.
        if (entry.ts == 0)
        {
            entry.used = false;
        }
    }

    return true;
}


/**
 * Timer callback for fdb aging, called once per second
 */
bool
bridgeif_age_tmr(std::vector<BridgeFdbEntry>& entries)
{
    return bridgeif_fdb_age_one_second(entries);
}


//
// END OF FILE
//