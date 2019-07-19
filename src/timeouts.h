
//
// file: timeouts.h
//

#pragma once
#include "opt.h"
#include "lwip_error.h"
#include "sys.h"

/** Returned by sys_timeouts_sleeptime() to indicate there is no timer, so we
 * can sleep forever.
 */
constexpr auto SYS_TIMEOUTS_SLEEPTIME_INFINITE = 0xFFFFFFFF;

/** Function prototype for a stack-internal timer function that has to be
 * called at a defined interval */
typedef void (* cyclic_timer_handler)(void);

// This struct contains information about a stack-internal timer function that has to be called at a defined interval
struct CyclicTimer
{
    uint32_t interval_ms;
    cyclic_timer_handler handler;
    const char* handler_name;
};

// This array contains all stack-internal cyclic timers. To get the number of timers, use lwip_num_cyclic_timers
// TODO: eliminate globl
extern const struct CyclicTimer lwip_cyclic_timers[];

/** Array size of lwip_cyclic_timers[] */
extern const int NUM_CYCLIC_TIMERS;


/** Function prototype for a timeout callback function. Register such a function
 * using sys_timeout().
 *
 * @param arg Additional argument to pass to the function - set up by sys_timeout()
 */
typedef void (* sys_timeout_handler)(void *arg);

struct SysTimeoutContext
{
    struct SysTimeoutContext* next;
    uint32_t time;
    sys_timeout_handler h;
    void* arg;
    const char* handler_name;
};


void sys_timeouts_init(void);

void sys_timeout_debug(uint32_t msecs, sys_timeout_handler handler, void *arg, const char* handler_name);
#define sys_timeout(msecs, handler, arg) sys_timeout_debug(msecs, handler, arg, #handler)


void sys_untimeout(sys_timeout_handler handler, void *arg);
void sys_restart_timeouts(void);
void sys_check_timeouts(void);
uint32_t sys_timeouts_sleeptime(void);

struct SysTimeoutContext** sys_timeouts_get_next_timeout(void);
void lwip_cyclic_timer(void *arg);

//
// END OF FILE
//