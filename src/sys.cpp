/**
 * @file
 * lwIP Operating System abstraction
 *
 */

/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

/**
 * @defgroup sys_layer Porting (system abstraction layer)
 * @ingroup lwip
 *
 * @defgroup sys_os OS abstraction layer
 * @ingroup sys_layer
 * No need to implement functions in this section in NO_SYS mode.
 * The OS-specific code should be implemented in sys_arch.h
 * and sys_arch.c of your port.
 * 
 * The operating system emulation layer provides a common interface
 * between the lwIP code and the underlying operating system kernel. The
 * general idea is that porting lwIP to new architectures requires only
 * small changes to a few header files and a new sys_arch
 * implementation. It is also possible to do a sys_arch implementation
 * that does not rely on any underlying operating system.
 * 
 * The sys_arch provides semaphores, mailboxes and mutexes to lwIP. For the full
 * lwIP functionality, multiple threads support can be implemented in the
 * sys_arch, but this is not required for the basic lwIP
 * functionality. Timer scheduling is implemented in lwIP, but can be implemented
 * by the sys_arch port (LWIP_TIMERS_CUSTOM==1).
 * 
 * In addition to the source file providing the functionality of sys_arch,
 * the OS emulation layer must provide several header files defining
 * macros used throughout lwip.  The files required and the macros they
 * must define are listed below the sys_arch description.
 * 
 * Since lwIP 1.4.0, semaphore, mutexes and mailbox functions are prototyped in a way that
 * allows both using pointers or actual OS structures to be used. This way, memory
 * required for such types can be either allocated in place (globally or on the
 * stack) or on the heap (allocated internally in the "*_new()" functions).
 * 
 * Note:
 * -----
 * Be careful with using mem_malloc() in sys_arch. When malloc() refers to
 * mem_malloc() you can run into a circular function call problem. In mem.c
 * mem_init() tries to allocate a semaphore using mem_malloc, which of course
 * can't be performed when sys_arch uses mem_malloc.
 *
 * @defgroup sys_sem Semaphores
 * @ingroup sys_os
 * Semaphores can be either counting or binary - lwIP works with both
 * kinds.
 * Semaphores are represented by the type "sys_sem_t" which is typedef'd
 * in the sys_arch.h file. Mailboxes are equivalently represented by the
 * type "sys_mbox_t". Mutexes are represented by the type "sys_mutex_t".
 * lwIP does not place any restrictions on how these types are represented
 * internally.
 *
 * @defgroup sys_mutex Mutexes
 * @ingroup sys_os
 * Mutexes are recommended to correctly handle priority inversion,
 * especially if you use LWIP_CORE_LOCKING .
 *
 * @defgroup sys_mbox Mailboxes
 * @ingroup sys_os
 * Mailboxes should be implemented as a queue which allows multiple messages
 * to be posted (implementing as a rendez-vous point where only one message can be
 * posted at a time can have a highly negative impact on performance). A message
 * in a mailbox is just a pointer, nothing more. 
 *
 * @defgroup sys_time Time
 * @ingroup sys_layer
 *
 * @defgroup sys_prot Critical sections
 * @ingroup sys_layer
 * Used to protect short regions of code against concurrent access.
 * - Your system is a bare-metal system (probably with an RTOS)
 *   and interrupts are under your control:
 *   Implement this as LockInterrupts() / UnlockInterrupts()
 * - Your system uses an RTOS with deferred interrupt handling from a
 *   worker thread: Implement as a global mutex or lock/unlock scheduler
 * - Your system uses a high-level OS with e.g. POSIX signals:
 *   Implement as a global mutex
 *
 * @defgroup sys_misc Misc
 * @ingroup sys_os
 */

#include "opt.h"
#include "opt.h"
#include "arch.h"
#include "lwip_debug.h"
#include "sys.h"
#include "tcpip.h"
#include <windows.h>
#include <cstdio> 
#include <cstdlib>
#include <ctime>


/* Most of the functions defined in sys.h must be implemented in the
 * architecture-dependent file sys_arch.c */

/**
 * Sleep for some ms. Timeouts are NOT processed while sleeping.
 *
 * @param ms number of milliseconds to sleep
 */
void
sys_msleep(uint32_t ms)
{
  if (ms > 0) {
    Semaphore delaysem;
    LwipStatus err = sys_sem_new(&delaysem, 0);
    if (err == ERR_OK) {
      sys_arch_sem_wait(&delaysem, ms);
      sys_sem_free(&delaysem);
    }
  }
}




/* These functions are used from NO_SYS also, for precise timer triggering */
static LARGE_INTEGER freq, sys_start_time;
#define SYS_INITIALIZED() (freq.QuadPart != 0)

static uint32_t netconn_sem_tls_index;

static HCRYPTPROV hcrypt;

uint32_t
sys_win_rand(void)
{
  uint32_t ret;
  if (CryptGenRandom(hcrypt, sizeof(ret), (uint8_t*)&ret)) {
    return ret;
  }
  lwip_assert("CryptGenRandom failed", 0);
  return 0;
}

static void
sys_win_rand_init(void)
{
  if (!CryptAcquireContext(&hcrypt, nullptr, nullptr, PROV_RSA_FULL, 0)) {
    auto err = GetLastError();
    LwipPlatformDiag(
        "CryptAcquireContext failed with error %d, trying to create NEWKEYSET",
        err);
    if(!CryptAcquireContext(&hcrypt, nullptr, nullptr, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
      char errbuf[128];
      err = GetLastError();
      snprintf(errbuf, sizeof(errbuf), "CryptAcquireContext failed with error %d", (int)err);
  
      lwip_assert(errbuf, 0);
    }
  }
}

static void
sys_init_timing(void)
{
  QueryPerformanceFrequency(&freq);
  QueryPerformanceCounter(&sys_start_time);
}

static LONGLONG
sys_get_ms_longlong(void)
{
  LONGLONG ret;
  LARGE_INTEGER now;

  QueryPerformanceCounter(&now);
  ret = now.QuadPart-sys_start_time.QuadPart;
  return (uint32_t)(((ret)*1000)/freq.QuadPart);
}

uint32_t
sys_jiffies(void)
{
  return (uint32_t)sys_get_ms_longlong();
}

uint32_t
sys_now(void)
{
  return (uint32_t)sys_get_ms_longlong();
}

CRITICAL_SECTION critSec;
#if LWIP_WIN32_SYS_ARCH_ENABLE_PROTECT_COUNTER
static int protection_depth;
#endif

static void
InitSysArchProtect(void)
{
  InitializeCriticalSection(&critSec);
}

sys_prot_t
sys_arch_protect_int(void)
{
  EnterCriticalSection(&critSec);
  return 0;
}

void sys_arch_unprotect(sys_prot_t pval)
{
    LeaveCriticalSection(&critSec);
}

/** This checks that SYS_ARCH_PROTECT() hasn't been called by protecting
 * and then checking the level
 */
static void
sys_arch_check_not_protected(void)
{
  sys_arch_protect_int();
  LWIP_ASSERT("SYS_ARCH_PROTECT before scheduling", protection_depth == 1);
  sys_arch_unprotect(0);
}



static void
msvc_sys_init(void)
{
  sys_win_rand_init();
  sys_init_timing();
  InitSysArchProtect();
  netconn_sem_tls_index = TlsAlloc();
  lwip_assert("TlsAlloc failed", netconn_sem_tls_index != TLS_OUT_OF_INDEXES);
}

void
sys_init(void)
{
  msvc_sys_init();
}



struct threadlist {
  lwip_thread_fn function;
  void *arg;
  DWORD id;
  struct threadlist *next;
};

static struct threadlist *lwip_win32_threads = nullptr;

LwipStatus
sys_sem_new(Semaphore *sem, uint8_t count)
{
  HANDLE new_sem = nullptr;

  lwip_assert("sem != NULL", sem != nullptr);

  new_sem = CreateSemaphore(nullptr, count, 100000, nullptr);
  lwip_assert("Error creating semaphore", new_sem != nullptr);
  if(new_sem != nullptr) {
    if (SYS_INITIALIZED()) {
      SYS_ARCH_LOCKED(SYS_STATS_INC_USED(sem));
    } else {
      SYS_STATS_INC_USED(sem);
    }

    sem->sem = new_sem;
    return ERR_OK;
  }
   
  /* failed to allocate memory... */
  if (SYS_INITIALIZED()) {
    SYS_ARCH_LOCKED(SYS_STATS_INC(sem.err));
  } else {
    SYS_STATS_INC(sem.err);
  }
  sem->sem = nullptr;
  return ERR_MEM;
}

void
sys_sem_free(Semaphore *sem)
{
  /* parameter check */
  lwip_assert("sem != NULL", sem != nullptr);
  lwip_assert("sem->sem != NULL", sem->sem != nullptr);
  lwip_assert("sem->sem != INVALID_HANDLE_VALUE", sem->sem != INVALID_HANDLE_VALUE);
  CloseHandle(sem->sem);

  SYS_ARCH_LOCKED(SYS_STATS_DEC(sem.used));

  sem->sem = nullptr;
}

uint32_t
sys_arch_sem_wait(Semaphore *sem, uint32_t timeout)
{
  DWORD ret;
  LONGLONG starttime, endtime;
  lwip_assert("sem != NULL", sem != nullptr);
  lwip_assert("sem->sem != NULL", sem->sem != nullptr);
  lwip_assert("sem->sem != INVALID_HANDLE_VALUE", sem->sem != INVALID_HANDLE_VALUE);
  if (!timeout) {
    /* wait infinite */
    starttime = sys_get_ms_longlong();
    ret = WaitForSingleObject(sem->sem, INFINITE);
    lwip_assert("Error waiting for semaphore", ret == WAIT_OBJECT_0);
    endtime = sys_get_ms_longlong();
    /* return the time we waited for the sem */
    return (uint32_t)(endtime - starttime);
  } else {
    starttime = sys_get_ms_longlong();
    ret = WaitForSingleObject(sem->sem, timeout);
    lwip_assert("Error waiting for semaphore", (ret == WAIT_OBJECT_0) || (ret == WAIT_TIMEOUT));
    if (ret == WAIT_OBJECT_0) {
      endtime = sys_get_ms_longlong();
      /* return the time we waited for the sem */
      return (uint32_t)(endtime - starttime);
    } else {
      /* timeout */
      return SYS_ARCH_TIMEOUT;
    }
  }
}

void
sys_sem_signal(Semaphore *sem)
{
  BOOL ret;
  sys_arch_check_not_protected();
  lwip_assert("sem != NULL", sem != nullptr);
  lwip_assert("sem->sem != NULL", sem->sem != nullptr);
  lwip_assert("sem->sem != INVALID_HANDLE_VALUE", sem->sem != INVALID_HANDLE_VALUE);
  ret = ReleaseSemaphore(sem->sem, 1, nullptr);
  lwip_assert("Error releasing semaphore", ret != 0);
  ;
}

LwipStatus
sys_mutex_new(Mutex *mutex)
{
  HANDLE new_mut = nullptr;

  lwip_assert("mutex != NULL", mutex != nullptr);

  new_mut = CreateMutex(nullptr, FALSE, nullptr);
  lwip_assert("Error creating mutex", new_mut != nullptr);
  if (new_mut != nullptr) {
    SYS_ARCH_LOCKED(SYS_STATS_INC_USED(mutex));

    lwip_assert("sys_mutex_new() counter overflow", lwip_stats.sys.mutex.used != 0);

    mutex->mut = new_mut;
    return ERR_OK;
  }
   
  /* failed to allocate memory... */
  SYS_ARCH_LOCKED(SYS_STATS_INC(mutex.err));
  mutex->mut = nullptr;
  return ERR_MEM;
}

void
sys_mutex_free(Mutex *mutex)
{
  /* parameter check */
  lwip_assert("mutex != NULL", mutex != nullptr);
  lwip_assert("mutex->mut != NULL", mutex->mut != nullptr);
  lwip_assert("mutex->mut != INVALID_HANDLE_VALUE", mutex->mut != INVALID_HANDLE_VALUE);
  CloseHandle(mutex->mut);

  SYS_ARCH_LOCKED(SYS_STATS_DEC(mutex.used));

  lwip_assert("sys_mutex_free() closed more than created", lwip_stats.sys.mutex.used != (uint16_t)-1);

  mutex->mut = nullptr;
}

void sys_mutex_lock(Mutex *mutex)
{
  DWORD ret;
  lwip_assert("mutex != NULL", mutex != nullptr);
  lwip_assert("mutex->mut != NULL", mutex->mut != nullptr);
  lwip_assert("mutex->mut != INVALID_HANDLE_VALUE", mutex->mut != INVALID_HANDLE_VALUE);
  /* wait infinite */
  ret = WaitForSingleObject(mutex->mut, INFINITE);
  lwip_assert("Error waiting for mutex", ret == WAIT_OBJECT_0);
  ;
}

void
sys_mutex_unlock(Mutex *mutex)
{
  sys_arch_check_not_protected();
  lwip_assert("mutex != NULL", mutex != nullptr);
  lwip_assert("mutex->mut != NULL", mutex->mut != nullptr);
  lwip_assert("mutex->mut != INVALID_HANDLE_VALUE", mutex->mut != INVALID_HANDLE_VALUE);
  /* wait infinite */
  if (!ReleaseMutex(mutex->mut)) {
    lwip_assert("Error releasing mutex", 0);
  }
}


#ifdef _MSC_VER
const DWORD MS_VC_EXCEPTION=0x406D1388;
#pragma pack(push,8)
typedef struct tagTHREADNAME_INFO
{
  DWORD dwType; /* Must be 0x1000. */
  LPCSTR szName; /* Pointer to name (in user addr space). */
  DWORD dwThreadID; /* Thread ID (-1=caller thread). */
  DWORD dwFlags; /* Reserved for future use, must be zero. */
} THREADNAME_INFO;
#pragma pack(pop)

static void
SetThreadName(DWORD dwThreadID, const char* threadName)
{
  THREADNAME_INFO info;
  info.dwType = 0x1000;
  info.szName = threadName;
  info.dwThreadID = dwThreadID;
  info.dwFlags = 0;

  __try {
    RaiseException(MS_VC_EXCEPTION, 0, sizeof(info)/sizeof(ULONG_PTR), (ULONG_PTR*)&info);
  }
  __except(EXCEPTION_EXECUTE_HANDLER) {
  }
}
#else /* _MSC_VER */
static void
SetThreadName(DWORD dwThreadID, const char* threadName)
{
  ;
  ;
}
#endif /* _MSC_VER */

static void
sys_thread_function(void* arg)
{
  struct threadlist* t = (struct threadlist*)arg;

  sys_arch_netconn_sem_alloc();

  t->function(t->arg);

  sys_arch_netconn_sem_free();

}

sys_thread_t
sys_thread_new(const char *name, lwip_thread_fn function, void *arg, int stacksize, int prio)
{
  struct threadlist *new_thread;
  HANDLE h;
  sys_prot_t lev;

  new_thread = (struct threadlist*)malloc(sizeof(struct threadlist));
  lwip_assert("new_thread != NULL", new_thread != nullptr);
  if (new_thread != nullptr) {
    new_thread->function = function;
    new_thread->arg = arg;
    SYS_ARCH_PROTECT(lev);
    new_thread->next = lwip_win32_threads;
    lwip_win32_threads = new_thread;

    h = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)sys_thread_function, new_thread, 0, &(new_thread->id));
    lwip_assert("h != 0", h != nullptr);
    lwip_assert("h != -1", h != INVALID_HANDLE_VALUE);
    SetThreadName(new_thread->id, name);

    SYS_ARCH_UNPROTECT(lev);
    return new_thread->id;
  }
  return 0;
}


static DWORD lwip_core_lock_holder_thread_id;

void
sys_lock_tcpip_core(void)
{
  sys_mutex_lock(&lock_tcpip_core);
  lwip_core_lock_holder_thread_id = GetCurrentThreadId();
}

void
sys_unlock_tcpip_core(void)
{
  lwip_core_lock_holder_thread_id = 0;
  sys_mutex_unlock(&lock_tcpip_core);
}


static DWORD lwip_tcpip_thread_id;

void
sys_mark_tcpip_thread(void)
{
  lwip_tcpip_thread_id = GetCurrentThreadId();
}

void
sys_check_core_locking(void)
{
  /* Embedded systems should check we are NOT in an interrupt context here */

  if (lwip_tcpip_thread_id != 0) {
    DWORD current_thread_id = GetCurrentThreadId();


    lwip_assert("Function called without core lock", current_thread_id == lwip_core_lock_holder_thread_id);

    ; /* for LWIP_NOASSERT */
  }
}


LwipStatus
sys_mbox_new(sys_mbox_t *mbox, int size)
{
  lwip_assert("mbox != NULL", mbox != nullptr);
  ;

  mbox->sem = CreateSemaphore(nullptr, 0, MAX_QUEUE_ENTRIES, nullptr);
  lwip_assert("Error creating semaphore", mbox->sem != nullptr);
  if (mbox->sem == nullptr) {
    SYS_ARCH_LOCKED(SYS_STATS_INC(mbox.err));
    return ERR_MEM;
  }
  memset(&mbox->q_mem, 0, sizeof(uint32_t)*MAX_QUEUE_ENTRIES);
  mbox->head = 0;
  mbox->tail = 0;
  SYS_ARCH_LOCKED(SYS_STATS_INC_USED(mbox));

  lwip_assert("sys_mbox_new() counter overflow", lwip_stats.sys.mbox.used != 0);

  return ERR_OK;
}

void
sys_mbox_free(sys_mbox_t *mbox)
{
  /* parameter check */
  lwip_assert("mbox != NULL", mbox != nullptr);
  lwip_assert("mbox->sem != NULL", mbox->sem != nullptr);
  lwip_assert("mbox->sem != INVALID_HANDLE_VALUE", mbox->sem != INVALID_HANDLE_VALUE);

  CloseHandle(mbox->sem);

  SYS_STATS_DEC(mbox.used);

  lwip_assert( "sys_mbox_free() ", lwip_stats.sys.mbox.used != (uint16_t)-1);

  mbox->sem = nullptr;
}

void
sys_mbox_post(sys_mbox_t *q, void *msg)
{
  BOOL ret;
  sys_prot_t lev;
  sys_arch_check_not_protected();

  /* parameter check */
  lwip_assert("q != SYS_MBOX_NULL", q != nullptr);
  lwip_assert("q->sem != NULL", q->sem != nullptr);
  lwip_assert("q->sem != INVALID_HANDLE_VALUE", q->sem != INVALID_HANDLE_VALUE);

  SYS_ARCH_PROTECT(lev);
  q->q_mem[q->head] = msg;
  q->head++;
  if (q->head >= MAX_QUEUE_ENTRIES)
  {
      q->head = 0;
  }
  lwip_assert("mbox is full!", q->head != q->tail);
  ret = ReleaseSemaphore(q->sem, 1, nullptr);
  lwip_assert("Error releasing sem", ret != 0);
  

  SYS_ARCH_UNPROTECT(lev);
  }

  LwipStatus
  sys_mbox_trypost(sys_mbox_t *q, void *msg)
  {
      uint32_t new_head;
      BOOL ret;
      sys_prot_t lev;
      sys_arch_check_not_protected();

      /* parameter check */
      lwip_assert("q != SYS_MBOX_NULL", q != nullptr);
      lwip_assert("q->sem != NULL", q->sem != nullptr);
      lwip_assert("q->sem != INVALID_HANDLE_VALUE", q->sem != INVALID_HANDLE_VALUE);

      SYS_ARCH_PROTECT(lev);

      new_head = q->head + 1;
      if (new_head >= MAX_QUEUE_ENTRIES)
      {
          new_head = 0;
      }
      if (new_head == q->tail)
      {
          SYS_ARCH_UNPROTECT(lev);
          return ERR_MEM;
      }

      q->q_mem[q->head] = msg;
      q->head = new_head;
      lwip_assert("mbox is full!", q->head != q->tail);
      ret = ReleaseSemaphore(q->sem, 1, nullptr);
      lwip_assert("Error releasing sem", ret != 0);
      sys_prot_t lev;

      sys_arch_unprotect(lev);
      return ERR_OK;
      }

      LwipStatus
      sys_mbox_trypost_fromisr(sys_mbox_t *q, void *msg)
      {
          return sys_mbox_trypost(q, msg);
      }

      uint32_t
      sys_arch_mbox_fetch(sys_mbox_t *q, void **msg, uint32_t timeout)
      {
          DWORD ret;
          LONGLONG starttime, endtime;
          sys_prot_t lev;

          /* parameter check */
          lwip_assert("q != SYS_MBOX_NULL", q != nullptr);
          lwip_assert("q->sem != NULL", q->sem != nullptr);
          lwip_assert("q->sem != INVALID_HANDLE_VALUE", q->sem != INVALID_HANDLE_VALUE);

          if (timeout == 0)
          {
              timeout = INFINITE;
          }
          starttime = sys_get_ms_longlong();
          ret = WaitForSingleObject(q->sem, timeout);
          if (ret == WAIT_OBJECT_0)
          {
              SYS_ARCH_PROTECT(lev);
              if (msg != nullptr)
              {
                  *msg  = q->q_mem[q->tail];
              }

              q->tail++;
              if (q->tail >= MAX_QUEUE_ENTRIES)
              {
                  q->tail = 0;
              }
              SYS_ARCH_UNPROTECT(lev);
              endtime = sys_get_ms_longlong();
              return (uint32_t)(endtime - starttime);
          } else
          {
              lwip_assert("Error waiting for sem", ret == WAIT_TIMEOUT);
              if (msg != nullptr)
              {
                  *msg  = nullptr;
              }

              return SYS_ARCH_TIMEOUT;
          }
          }

          uint32_t
          sys_arch_mbox_tryfetch(sys_mbox_t *q, void **msg)
          {
              DWORD ret;
              sys_prot_t lev;

              /* parameter check */
              lwip_assert("q != SYS_MBOX_NULL", q != nullptr);
              lwip_assert("q->sem != NULL", q->sem != nullptr);
              lwip_assert("q->sem != INVALID_HANDLE_VALUE", q->sem != INVALID_HANDLE_VALUE);

              ret = WaitForSingleObject(q->sem, 0);
              if (ret == WAIT_OBJECT_0)
              {
                  SYS_ARCH_PROTECT(lev);
                  if (msg != nullptr)
                  {
                      *msg  = q->q_mem[q->tail];
                  }

                  q->tail++;
                  if (q->tail >= MAX_QUEUE_ENTRIES)
                  {
                      q->tail = 0;
                  }
                  SYS_ARCH_UNPROTECT(lev);
                  return 0;
              } else
              {
                  lwip_assert("Error waiting for sem", ret == WAIT_TIMEOUT);
                  if (msg != nullptr)
                  {
                      *msg  = nullptr;
                  }

                  return SYS_ARCH_TIMEOUT;
              }
              }


Semaphore*
sys_arch_netconn_sem_get(void)
{
  LPVOID tls_data = TlsGetValue(netconn_sem_tls_index);
  return (Semaphore*)tls_data;
}

void
sys_arch_netconn_sem_alloc(void)
{
  Semaphore *sem;
  LwipStatus err;
  BOOL done;

  sem = (Semaphore*)malloc(sizeof(Semaphore));
  LWIP_ASSERT("failed to allocate memory for TLS semaphore", sem != nullptr);
  err = sys_sem_new(sem, 0);
  LWIP_ASSERT("failed to initialise TLS semaphore", err == ERR_OK);
  done = TlsSetValue(netconn_sem_tls_index, sem);
  ;
  LWIP_ASSERT("failed to initialise TLS semaphore storage", done == TRUE);
}

void
sys_arch_netconn_sem_free(void)
{
  LPVOID tls_data = TlsGetValue(netconn_sem_tls_index);
  if (tls_data != nullptr) {
    BOOL done;
    free(tls_data);
    done = TlsSetValue(netconn_sem_tls_index, nullptr);
    ;
    LWIP_ASSERT("failed to de-init TLS semaphore storage", done == TRUE);
  }
}




              /* get keyboard state to terminate the debug app on any kbhit event using win32 API */
              int
              lwip_win32_keypressed(void)
              {
                  INPUT_RECORD rec;
                  DWORD num = 0;
                  HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
                  BOOL ret = PeekConsoleInput(h, &rec, 1, &num);
                  if (ret && num)
                  {
                      ReadConsoleInput(h, &rec, 1, &num);
                      if (rec.EventType == KEY_EVENT)
                      {
                          if (rec.Event.KeyEvent.bKeyDown)
                          {
                              /* not a special key? */
                              if (rec.Event.KeyEvent.uChar.AsciiChar != 0)
                              {
                                  return 1;
                              }
                          }
                      }
                  }
                  return 0;
              }

#include <cstdarg>

              /* This is an example implementation for LWIP_PLATFORM_DIAG:
 * format a string and pass it to your output function.
 */
              void
              lwip_win32_platform_diag(const char *format, ...)
              {
                  va_list ap;
                  /* get the varargs */
                  va_start(ap, format);
                  /* print via varargs; to use another output function, you could use
     vsnprintf here */
                  vprintf(format, ap);
                  va_end(ap);
              }
