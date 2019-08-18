#pragma once
#include <arch.h>
#include <opt.h>

/**
 * @defgroup debugging_levels LWIP_DBG_MIN_LEVEL and LWIP_DBG_TYPES_ON values
 * @ingroup lwip_opts_debugmsg
 * @{
 */ /** @name Debug level (LWIP_DBG_MIN_LEVEL)
 * @{
 */
enum LwipDebugLevel
{
    /** Debug level: ALL messages*/
    LWIP_DBG_LEVEL_ALL = 0x00,
    /** Debug level: Warnings. bad checksums, dropped packets, ... */
    LWIP_DBG_LEVEL_WARNING =0x01,
    /** Debug level: Serious. memory allocation failures, ... */
    LWIP_DBG_LEVEL_SERIOUS =0x02,
    /** Debug level: Severe */
    LWIP_DBG_LEVEL_SEVERE = 0x03
};

constexpr auto kLwipDbgMaskLevel = 0x03; /* compatibility define only */
constexpr auto kLwipDbgLevelOff = LWIP_DBG_LEVEL_ALL;

/** @name Enable/disable debug messages completely (LWIP_DBG_TYPES_ON)
* @{
*/ /** flag for Logf to enable that debug message */
constexpr auto LWIP_DBG_ON = 0x80U;
/** flag for Logf to disable that debug message */
constexpr auto LWIP_DBG_OFF = 0x00U; 
/**
 * @}
 */ /** @name Debug message types (LWIP_DBG_TYPES_ON)
 * @{
 */ /** flag for Logf indicating a tracing message (to follow program flow) */
enum LwipDebugMsgType
{
    LWIP_DBG_TRACE = 0x40U,
    /** flag for Logf indicating a state debug message (to follow module states) */
    LWIP_DBG_STATE = 0x20U,
    /** flag for Logf indicating newly added code, not thoroughly tested yet */
    LWIP_DBG_FRESH = 0x10U,
    /** flag for Logf to halt after printing this debug message */
    LWIP_DBG_HALT = 0x08U
};

inline void lwip_assert(const char* msg, const bool assertion)
{
    if (!assertion)
    {
        LWIP_PLATFORM_ASSERT(msg);
    }
}

inline void LWIP_PLATFORM_ERROR(char* msg)
{
    LWIP_PLATFORM_ASSERT(msg);
}

// TODO: add log level and filter
inline void Logf(const bool debug, const char* message, ...)
{

    va_list args;
    va_start(args, message);
    vprintf(message, args);
    va_end(args);

    // if (((debug) & LWIP_DBG_ON) && ((debug) & LWIP_DBG_TYPES_ON) && (int16_t(
    //     (debug) & kLwipDbgMaskLevel) >= LWIP_DBG_MIN_LEVEL))
    // {
    //     LwipPlatformDiag(message);
    //     if ((debug) & LWIP_DBG_HALT)
    //     {
    //         while (true);
    //     }
    // }
}
