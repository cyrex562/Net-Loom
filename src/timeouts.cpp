
#include <opt.h>
#include <autoip.h>
#include <def.h>
#include <dhcp6.h>
#include <dns.h>
#include <etharp.h>
#include <igmp.h>
#include <ip4_frag.h>
#include <ip6_frag.h>
#include <mld6.h>
#include <nd6.h>
#include <packet_buffer.h>
#include <sys.h>
#include <tcp_priv.h>
#include <tcpip_priv.h>
#include <timeouts.h>
#include <lwip_debug.h>
#include "dhcp.h"
#define HANDLER(x) x, #x

constexpr auto LWIP_MAX_TIMEOUT = 0x7fffffff;

/* Check if timer's expiry time is greater than time and care about uint32_t wraparounds */
#define TIME_LESS_THAN(t, compare_to) ( (((uint32_t)((t)-(compare_to))) > LWIP_MAX_TIMEOUT) ? 1 : 0 )

/** This array contains all stack-internal cyclic timers. To get the number of
 * timers, use LWIP_ARRAYSIZE() */
const struct CyclicTimer lwip_cyclic_timers[] = {

    /* The TCP timer is a special case: it does not have to run always and
       is triggered to start from TCP using tcp_timer_needed() */
    {TCP_TMR_INTERVAL, HANDLER(tcp_tmr)},
    {IP_TMR_INTERVAL, HANDLER(ip_reass_tmr)},
    {kArpTmrInterval, HANDLER(etharp_tmr)},
    {DHCP_COARSE_TIMER_MSECS, HANDLER(dhcp_coarse_tmr)},
    {DHCP_FINE_TIMER_MSECS, HANDLER(dhcp_fine_tmr)},
    {kAutoipTmrInterval, HANDLER(autoip_tmr)},
    {IGMP_TMR_INTERVAL, HANDLER(igmp_tmr)},
    {DNS_TMR_INTERVAL, HANDLER(dns_tmr)},
    {ND6_TMR_INTERVAL, HANDLER(nd6_tmr)},
    {IP6_REASS_TMR_INTERVAL, HANDLER(ip6_reass_tmr)},
    {MLD6_TMR_INTERVAL, HANDLER(mld6_tmr)},
    {DHCP6_TIMER_MSECS, HANDLER(dhcp6_tmr)},

};
const int NUM_CYCLIC_TIMERS = LWIP_ARRAYSIZE(lwip_cyclic_timers);

/** The one and only timeout list */
static struct SysTimeoutContext *next_timeout;

static uint32_t current_timeout_due_time;

/** global variable that shows if the tcp timer is currently scheduled or not */
static int tcpip_tcp_timer_active;


/**
 * Create a one-shot timer (aka timeout). Timeouts are processed in the
 * following cases:
 * - while waiting for a message using sys_timeouts_mbox_fetch()
 * - by calling sys_check_timeouts() (NO_SYS==1 only)
 *
 * @param msecs time in milliseconds after that the timer should expire
 * @param handler callback function to call when msecs have elapsed
 * @param arg argument to pass to the callback function
 */
void sys_timeout(uint32_t msecs, SysTimeoutHandler handler, void* arg)
{
    lwip_assert("Timeout time too long, max is LWIP_UINT32_MAX/4 msecs",
                msecs <= (kLwipUint32Max / 4));
    uint32_t next_timeout_time = uint32_t(sys_now() + msecs);
    /* overflow handled by TIME_LESS_THAN macro */
    // fixme: handler_name missing
    // sys_timeout_abs(next_timeout_time, handler, arg, handler_name);
}

/**
 * Timer callback function that calls tcp_tmr() and reschedules itself.
 *
 * @param arg unused argument
 */
static void
tcpip_tcp_timer(void* arg)
{


  /* call TCP timer handler */
  tcp_tmr();
  /* timer still needed? */
  if (tcp_active_pcbs || tcp_tw_pcbs) {
    /* restart timer */
    sys_timeout(TCP_TMR_INTERVAL, tcpip_tcp_timer, nullptr);
  } else {
    /* disable timer */
    tcpip_tcp_timer_active = 0;
  }
}

/**
 * Called from TCP_REG when registering a new PCB:
 * the reason is to have the TCP timer only running when
 * there are active (or time-wait) PCBs.
 */
void
tcp_timer_needed(void)
{
  LWIP_ASSERT_CORE_LOCKED();

  /* timer is off but needed again? */
  if (!tcpip_tcp_timer_active && (tcp_active_pcbs || tcp_tw_pcbs)) {
    /* enable and start timer */
    tcpip_tcp_timer_active = 1;
    sys_timeout(TCP_TMR_INTERVAL, tcpip_tcp_timer, nullptr);
  }
}


static void

sys_timeout_abs(uint32_t abs_time, SysTimeoutHandler handler, void* arg, const char *handler_name)

{
  struct SysTimeoutContext *timeout, *t;

  // timeout = (struct sys_timeo *)memp_malloc(MEMP_SYS_TIMEOUT);
  timeout = new SysTimeoutContext;
  if (timeout == nullptr) {
    lwip_assert("sys_timeout: timeout != NULL, pool MEMP_SYS_TIMEOUT is empty", timeout != nullptr);
    return;
  }

  timeout->next = nullptr;
  timeout->h = handler;
  timeout->arg = arg;
  timeout->time = abs_time;


  timeout->handler_name = handler_name;
  Logf(TIMERS_DEBUG, ("sys_timeout: %p abs_time=%d handler=%s arg=%p\n",
                             (void *)timeout, abs_time, handler_name, (void *)arg));


  if (next_timeout == nullptr) {
    next_timeout = timeout;
    return;
  }
  if (TIME_LESS_THAN(timeout->time, next_timeout->time)) {
    timeout->next = next_timeout;
    next_timeout = timeout;
  } else {
    for (t = next_timeout; t != nullptr; t = t->next) {
      if ((t->next == nullptr) || TIME_LESS_THAN(timeout->time, t->next->time)) {
        timeout->next = t->next;
        t->next = timeout;
        break;
      }
    }
  }
}

/**
 * Timer callback function that calls cyclic->handler() and reschedules itself.
 *
 * @param arg unused argument
 */

static
void
lwip_cyclic_timer(void* arg)
{
  uint32_t now;
  uint32_t next_timeout_time;
  const struct CyclicTimer *cyclic = (const struct CyclicTimer *)arg;

  Logf(TIMERS_DEBUG, ("tcpip: %s()\n", cyclic->handler_name));

  cyclic->handler();

  now = sys_now();
  next_timeout_time = (uint32_t)(current_timeout_due_time + cyclic->interval_ms);  /* overflow handled by TIME_LESS_THAN macro */ 
  if (TIME_LESS_THAN(next_timeout_time, now)) {
    /* timer would immediately expire again -> "overload" -> restart without any correction */

    sys_timeout_abs((uint32_t)(now + cyclic->interval_ms), lwip_cyclic_timer, (void*)arg, cyclic->handler_name);


  } else {
    /* correct cyclic interval with handler execution delay and sys_check_timeouts jitter */

    sys_timeout_abs(next_timeout_time, lwip_cyclic_timer, (void*)arg, cyclic->handler_name);

  }
}

/** Initialize this module */
void sys_timeouts_init(void)
{
    size_t i; /* tcp_tmr() at index 0 is started on demand */
    for (i = (LWIP_TCP ? 1 : 0); i < LWIP_ARRAYSIZE(lwip_cyclic_timers); i++)
    {
        /* we have to cast via size_t to get rid of const warning
          (this is OK as cyclic_timer() casts back to const* */
        sys_timeout(lwip_cyclic_timers[i].interval_ms,
                    lwip_cyclic_timer,
                    (void*)&lwip_cyclic_timers[i]);
    }
}



/**
 * Go through timeout list (for this task only) and remove the first matching
 * entry (subsequent entries remain untouched), even though the timeout has not
 * triggered yet.
 *
 * @param handler callback function that would be called by the timeout
 * @param arg callback argument that would be passed to handler
*/
void
sys_untimeout(SysTimeoutHandler handler, void* arg)
{
  struct SysTimeoutContext *prev_t, *t;

  LWIP_ASSERT_CORE_LOCKED();

  if (next_timeout == nullptr) {
    return;
  }

  for (t = next_timeout, prev_t = nullptr; t != nullptr; prev_t = t, t = t->next) {
    if ((t->h == handler) && (t->arg == arg)) {
      /* We have a match */
      /* Unlink from previous in list */
      if (prev_t == nullptr) {
        next_timeout = t->next;
      } else {
        prev_t->next = t->next;
      }
      // memp_free(MEMP_SYS_TIMEOUT, t);
      delete t;
      return;
    }
  }
  return;
}

/**
 * @ingroup lwip_nosys
 * Handle timeouts for NO_SYS==1 (i.e. without using
 * tcpip_thread/sys_timeouts_mbox_fetch(). Uses sys_now() to call timeout
 * handler functions when timeouts expire.
 *
 * Must be called periodically from your main loop.
 */
void
sys_check_timeouts(void)
{
  uint32_t now;

  LWIP_ASSERT_CORE_LOCKED();

  /* Process only timers expired at the start of the function. */
  now = sys_now();

  do {
      SysTimeoutHandler handler;
    void *arg;

    PBUF_CHECK_FREE_OOSEQ();

    struct SysTimeoutContext* tmptimeout = next_timeout;
    if (tmptimeout == nullptr) {
      return;
    }

    if (TIME_LESS_THAN(now, tmptimeout->time)) {
      return;
    }

    /* Timeout has expired */
    next_timeout = tmptimeout->next;
    handler = tmptimeout->h;
    arg = tmptimeout->arg;
    current_timeout_due_time = tmptimeout->time;

    if (handler != nullptr) {
      Logf(TIMERS_DEBUG, ("sct calling h=%s t=%d arg=%p\n",
                                 tmptimeout->handler_name, sys_now() - tmptimeout->time, arg));
    }

    // memp_free(MEMP_SYS_TIMEOUT, tmptimeout);
    delete tmptimeout;
    if (handler != nullptr) {
      handler(arg);
    }
    LWIP_TCPIP_THREAD_ALIVE();

    /* Repeat until all expired timers have been called */
  } while (1);
}

/** Rebase the timeout times to the current time.
 * This is necessary if sys_check_timeouts() hasn't been called for a long
 * time (e.g. while saving energy) to prevent all timer functions of that
 * period being called.
 */
void
sys_restart_timeouts(void)
{
  uint32_t now;
  uint32_t base;
  struct SysTimeoutContext *t;

  if (next_timeout == nullptr) {
    return;
  }

  now = sys_now();
  base = next_timeout->time;

  for (t = next_timeout; t != nullptr; t = t->next) {
    t->time = (t->time - base) + now;
  }
}

/** Return the time left before the next timeout is due. If no timeouts are
 * enqueued, returns 0xffffffff
 */
uint32_t
sys_timeouts_sleeptime(void)
{
  uint32_t now;

  LWIP_ASSERT_CORE_LOCKED();

  if (next_timeout == nullptr) {
    return SYS_TIMEOUTS_SLEEPTIME_INFINITE;
  }
  now = sys_now();
  if (TIME_LESS_THAN(next_timeout->time, now)) {
    return 0;
  } else {
    uint32_t ret = (uint32_t)(next_timeout->time - now);
    lwip_assert("invalid sleeptime", ret <= LWIP_MAX_TIMEOUT);
    return ret;
  }
}


