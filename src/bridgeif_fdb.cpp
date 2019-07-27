#include <bridgeif.h>
#include <cstring>
#include <lwip_debug.h>
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
bool bridgeif_fdb_update_src(void* fdb_ptr, struct EthernetAddress* src_addr, uint8_t port_idx)
{
    int i;
    const auto fdb = static_cast<BridgeIfcFdb *>(fdb_ptr);
    for (i = 0; i < fdb->max_fdb_entries; i++)
    {
        auto e = &fdb->fdb[i];
        if (e->used && e->ts)
        {
            if (!memcmp(&e->addr, src_addr, sizeof(struct EthernetAddress)))
            {
                // Logf(BRIDGEIF_FDB_DEBUG,
                //             ("br: update src %02x:%02x:%02x:%02x:%02x:%02x (from %d) @ idx %d\n"
                //                 , src_addr->addr[0], src_addr->addr[1], src_addr->addr[2],
                //                 src_addr->addr[3], src_addr->addr[4], src_addr->addr[5],
                //                 port_idx, i));
                e->ts = BRIDGE_FDB_TIMEOUT_SEC;
                e->port = port_idx;
                return true;
            }
        }
    } /* not found, allocate new entry from free */
    for (i = 0; i < fdb->max_fdb_entries; i++)
    {
        auto e = &fdb->fdb[i];
        if (!e->used || !e->ts)
        {
            if (!e->used || !e->ts)
            {
                // Logf(BRIDGEIF_FDB_DEBUG,
                //             ("br: create src %02x:%02x:%02x:%02x:%02x:%02x (from %d) @ idx %d\n"
                //                 , src_addr->addr[0], src_addr->addr[1], src_addr->addr[2],
                //                 src_addr->addr[3], src_addr->addr[4], src_addr->addr[5],
                //                 port_idx, i));
                memcpy(&e->addr, src_addr, sizeof(struct EthernetAddress));
                e->ts = BRIDGE_FDB_TIMEOUT_SEC;
                e->port = port_idx;
                e->used = 1;
                return true;
            }
        }
    }

    return false;
}

/**
 * @ingroup bridgeif_fdb
 * Walk our list of auto-learnt fdb entries and return a port to forward or BR_FLOOD if unknown
 */
BridgeIfcPortMask bridgeif_fdb_get_dst_ports(void* fdb_ptr, struct EthernetAddress* dst_addr)
{
    const auto fdb = static_cast<BridgeIfcFdb *>(fdb_ptr);
    for (auto i = 0; i < fdb->max_fdb_entries; i++)
    {
        auto e = &fdb->fdb[i];
        if (e->used && e->ts)
        {
            if (!memcmp(&e->addr, dst_addr, sizeof(struct EthernetAddress)))
            {
                const auto ret = BridgeIfcPortMask(uint64_t(1 << e->port));
                return ret;
            }
        }
    }
    return BRIDGE_FLOOD;
}


//
// @ingroup bridgeif_fdb
// Aging implementation of our simple fdb
//
bool bridgeif_fdb_age_one_second(void* fdb_ptr)
{
    const auto fdb = static_cast<BridgeIfcFdb *>(fdb_ptr);
    const auto lev = sys_arch_protect_int();
    for (auto i = 0; i < fdb->max_fdb_entries; i++)
    {
        auto e = &fdb->fdb[i];
        if (e->used && e->ts)
        {
            if (e->used && e->ts)
            {
                if (--e->ts == 0)
                {
                    e->used = 0;
                }
            }
        }
    }
    sys_arch_unprotect(lev);
    return true;
}

/** Timer callback for fdb aging, called once per second */
void bridgeif_age_tmr(void* arg)
{
    const auto fdb = static_cast<BridgeIfcFdb *>(arg);
    lwip_assert("invalid arg", arg != nullptr);
    bridgeif_fdb_age_one_second(fdb);
    // sys_timeout_debug(BRIDGE_IF_AGE_TIMER_MS, bridgeif_age_tmr, arg, "bridgeif_age_tmr");
}

/**
 * @ingroup bridgeif_fdb
 * Init our simple fdb list
 */
BridgeIfcFdb* bridgeif_fdb_init(const uint16_t max_fdb_entries)
{
    const auto alloc_len_sizet = sizeof(BridgeIfcFdb) + (max_fdb_entries * sizeof(
        BridgeIfDfDbEntry));
    const auto alloc_len = size_t(alloc_len_sizet);
    lwip_assert("alloc_len == alloc_len_sizet", alloc_len == alloc_len_sizet);
    Logf(kBridgeIfcDebug,
         "bridgeif_fdb_init: allocating %d bytes for private FDB data\n",
         int(alloc_len));
    const auto fdb = new BridgeIfcFdb;
    if (fdb == nullptr)
    {
        return nullptr;
    }
    fdb->max_fdb_entries = max_fdb_entries;
    fdb->fdb = reinterpret_cast<BridgeIfDfDbEntry *>(fdb + 1);
    // sys_timeout_debug(BRIDGE_IF_AGE_TIMER_MS, bridgeif_age_tmr, fdb, "bridgeif_age_tmr");
    return fdb;
}

//
// END OF FILE
//