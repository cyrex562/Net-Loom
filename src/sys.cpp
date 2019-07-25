
#include "opt.h"
#include "arch.h"
#include "lwip_debug.h"
#include "sys.h"
#include "tcpip.h"
#define NOMINMAX
#include <windows.h>
#include <cstdio> 
#include <cstdlib>
#include <ctime>
#include <chrono>
#include <cstdarg>


static uint64_t freq;
static uint64_t sys_start_time;
static uint32_t netconn_sem_tls_index;
static HCRYPTPROV hcrypt;
CRITICAL_SECTION critSec;
static int protection_depth;

/* Most of the functions defined in sys.h must be implemented in the
 * architecture-dependent file sys_arch.c */

/**
 * Sleep for some ms. Timeouts are NOT processed while sleeping.
 *
 * @param ms number of milliseconds to sleep
 */
void
sys_msleep(const uint32_t ms)
{
  if (ms > 0) {
    Semaphore delaysem{};
    LwipStatus err = sys_sem_new(&delaysem, 0);
    if (err == ERR_OK) {
      sys_arch_sem_wait(&delaysem, ms);
      sys_sem_free(&delaysem);
    }
  }
}




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

//
//
//
uint32_t sys_win_rand()
{
    uint32_t ret;
    if (CryptGenRandom(hcrypt, sizeof(ret), reinterpret_cast<uint8_t*>(&ret)) != 0)
    {
        return ret;
    }
    lwip_assert("CryptGenRandom failed", false);
    return 0;
}

//
//
//
static void sys_win_rand_init()
{
    if (!CryptAcquireContext(&hcrypt, nullptr, nullptr, PROV_RSA_FULL, 0))
    {
        auto err = GetLastError();
        LwipPlatformDiag(
            "CryptAcquireContext failed with error %d, trying to create NEWKEYSET",
            err);
        if (!CryptAcquireContext(&hcrypt,
                                 nullptr,
                                 nullptr,
                                 PROV_RSA_FULL,
                                 CRYPT_NEWKEYSET))
        {
            char errbuf[128];
            err = GetLastError();
            snprintf(errbuf,
                     sizeof(errbuf),
                     "CryptAcquireContext failed with error %d",
                     static_cast<int>(err));
            lwip_assert(errbuf, 0);
        }
    }
}

//
//
//
static void sys_init_timing()
{
    // QueryPerformanceFrequency(&freq);
    // QueryPerformanceCounter(&sys_start_time);
}

static uint64_t
sys_get_time_ns(void)
{
    std::chrono::time_point time_now = std::chrono::high_resolution_clock::now();
    uint64_t now = time_now.time_since_epoch().count();
    return now;
}

uint64_t
sys_jiffies(void)
{
  return sys_get_time_ns();
}

uint64_t
sys_now(void)
{
  return sys_get_time_ns();
}


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
    LeaveCriticalSection(&crit_sec);
}

// This checks that SYS_ARCH_PROTECT() hasn't been called by protecting and then checking the level
static void sys_arch_check_not_protected(void)
{
    sys_arch_protect_int();

    sys_arch_unprotect(0);
}


static void
msvc_sys_init()
{
    sys_win_rand_init();
    sys_init_timing();
    InitSysArchProtect();
    netconn_sem_tls_index = TlsAlloc();
    lwip_assert("TlsAlloc failed", netconn_sem_tls_index != TLS_OUT_OF_INDEXES);
}


void
sys_init()
{
    msvc_sys_init();
}



// replace global
// static struct ThreadList *lwip_win32_threads = nullptr;

LwipStatus
sys_sem_new(Semaphore* sem, uint8_t count)
{
    HANDLE new_sem = nullptr;

    lwip_assert("sem != NULL", sem != nullptr);

    new_sem = CreateSemaphore(nullptr, count, 100000, nullptr);
    lwip_assert("Error creating semaphore", new_sem != nullptr);
    if (new_sem != nullptr)
    {
        if (sys_initialized())
        {
            do
            {
                sys_prot_t lev;
                SYS_ARCH_PROTECT(lev);
                sys_arch_unprotect(lev);
            }
            while (0);
        }
        else
        {
        }

        sem->sem = new_sem;
        return ERR_OK;
    }

    /* failed to allocate memory... */
    if (sys_initialized())
    {
        do
        {
            sys_prot_t lev;
            SYS_ARCH_PROTECT(lev);
            sys_arch_unprotect(lev);
        }
        while (0);
    }
    else
    {
    }
    sem->sem = nullptr;
    return ERR_MEM;
}

void
sys_sem_free(Semaphore* sem)
{
    /* parameter check */
    lwip_assert("sem != NULL", sem != nullptr);
    lwip_assert("sem->sem != NULL", sem->sem != nullptr);
    lwip_assert("sem->sem != INVALID_HANDLE_VALUE", sem->sem != INVALID_HANDLE_VALUE);
    CloseHandle(sem->sem);

    do
    {
        sys_prot_t lev;
        SYS_ARCH_PROTECT(lev);
        sys_arch_unprotect(lev);
    }
    while (0);

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
    starttime = sys_get_time_ns();
    ret = WaitForSingleObject(sem->sem, INFINITE);
    lwip_assert("Error waiting for semaphore", ret == WAIT_OBJECT_0);
    endtime = sys_get_time_ns();
    /* return the time we waited for the sem */
    return (uint32_t)(endtime - starttime);
  } else {
    starttime = sys_get_time_ns();
    ret = WaitForSingleObject(sem->sem, timeout);
    lwip_assert("Error waiting for semaphore", (ret == WAIT_OBJECT_0) || (ret == WAIT_TIMEOUT));
    if (ret == WAIT_OBJECT_0) {
      endtime = sys_get_time_ns();
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
    sys_arch_check_not_protected();
  lwip_assert("sem != NULL", sem != nullptr);
  lwip_assert("sem->sem != NULL", sem->sem != nullptr);
  lwip_assert("sem->sem != INVALID_HANDLE_VALUE", sem->sem != INVALID_HANDLE_VALUE);
  BOOL ret = ReleaseSemaphore(sem->sem, 1, nullptr);
  lwip_assert("Error releasing semaphore", ret != 0);
  ;
}

LwipStatus
sys_mutex_new(Mutex* mutex)
{
    HANDLE new_mut = nullptr;

    lwip_assert("mutex != NULL", mutex != nullptr);

    new_mut = CreateMutex(nullptr, FALSE, nullptr);
    lwip_assert("Error creating mutex", new_mut != nullptr);
    if (new_mut != nullptr)
    {
        do
        {
            sys_prot_t lev;
            SYS_ARCH_PROTECT(lev);
            sys_arch_unprotect(lev);
        }
        while (0);


        mutex->mut = new_mut;
        return ERR_OK;
    }

    /* failed to allocate memory... */
    do
    {
        sys_prot_t lev;
        SYS_ARCH_PROTECT(lev);
        sys_arch_unprotect(lev);
    }
    while (0);
    mutex->mut = nullptr;
    return ERR_MEM;
}

void
sys_mutex_free(Mutex* mutex)
{
    /* parameter check */
    lwip_assert("mutex != NULL", mutex != nullptr);
    lwip_assert("mutex->mut != NULL", mutex->mut != nullptr);
    lwip_assert("mutex->mut != INVALID_HANDLE_VALUE", mutex->mut != INVALID_HANDLE_VALUE);
    CloseHandle(mutex->mut);

    do
    {
        sys_prot_t lev;
        SYS_ARCH_PROTECT(lev);
        sys_arch_unprotect(lev);
    }
    while (0);


    mutex->mut = nullptr;
}

void sys_mutex_lock(Mutex* mutex)
{
    lwip_assert("mutex != NULL", mutex != nullptr);
    lwip_assert("mutex->mut != NULL", mutex->mut != nullptr);
    lwip_assert("mutex->mut != INVALID_HANDLE_VALUE", mutex->mut != INVALID_HANDLE_VALUE);
    /* wait infinite */
    DWORD ret = WaitForSingleObject(mutex->mut, INFINITE);
    lwip_assert("Error waiting for mutex", ret == WAIT_OBJECT_0);;
}

void
sys_mutex_unlock(Mutex* mutex)
{
    sys_arch_check_not_protected();
    lwip_assert("mutex != NULL", mutex != nullptr);
    lwip_assert("mutex->mut != NULL", mutex->mut != nullptr);
    lwip_assert("mutex->mut != INVALID_HANDLE_VALUE", mutex->mut != INVALID_HANDLE_VALUE);
    /* wait infinite */
    if (!ReleaseMutex(mutex->mut))
    {
        lwip_assert("Error releasing mutex", 0);
    }
}



const DWORD MS_VC_EXCEPTION=0x406D1388;

struct THREADNAME_INFO
{
    uint32_t dwType; /* Must be 0x1000. */
    const char* szName; /* Pointer to name (in user addr space). */
    uint32_t dwThreadID; /* Thread ID (-1=caller thread). */
    uint32_t dwFlags; /* Reserved for future use, must be zero. */
};


static void
SetThreadName(DWORD dwThreadID, const char* thread_name)
{
    THREADNAME_INFO info;
    info.dwType = 0x1000;
    info.szName = thread_name;
    info.dwThreadID = dwThreadID;
    info.dwFlags = 0;

    __try
    {
        RaiseException(MS_VC_EXCEPTION, 0, sizeof(info) / sizeof(ULONG_PTR), (ULONG_PTR*)&info);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}


//
//
//
static void
sys_thread_function(void* arg)
{
  struct ThreadList* t = (struct ThreadList*)arg;

  sys_arch_netconn_sem_alloc();

  t->function(t->arg);

  sys_arch_netconn_sem_free();

}


sys_thread_t
sys_thread_new(const char* name, LwipThreadFn function, void* arg, int stacksize, int prio, ThreadList* thread_list)
{
    sys_prot_t lev;

    struct ThreadList* new_thread = new ThreadList;
    lwip_assert("new_thread != NULL", new_thread != nullptr);
    if (new_thread != nullptr)
    {
        new_thread->function = function;
        new_thread->arg = arg;
        SYS_ARCH_PROTECT(lev);
        new_thread->next = thread_list;
        // lwip_win32_threads = new_thread;

        HANDLE h = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)sys_thread_function, new_thread, 0,
                                LPDWORD(&(new_thread->id)));
        lwip_assert("h != 0", h != nullptr);
        lwip_assert("h != -1", h != INVALID_HANDLE_VALUE);
        SetThreadName(new_thread->id, name);

        SYS_ARCH_UNPROTECT(lev);
        return new_thread->id;
    }
    return 0;
}


//
//
//
void sys_lock_tcpip_core()
{
    sys_mutex_lock(&lock_tcpip_core);
    lwip_core_lock_holder_thread_id = GetCurrentThreadId();
}

//
//
//
void sys_unlock_tcpip_core()
{
    lwip_core_lock_holder_thread_id = 0;
    sys_mutex_unlock(&lock_tcpip_core);
}


// static DWORD lwip_tcpip_thread_id;

uint32_t
sys_mark_tcpip_thread(void)
{
    auto lwip_tcpip_thread_id = GetCurrentThreadId();
    return lwip_tcpip_thread_id;
}

uint32_t
sys_check_core_locking(uint32_t lwip_tcpip_thread_id)
{
    /* Embedded systems should check we are NOT in an interrupt context here */

    if (lwip_tcpip_thread_id != 0)
    {
        uint32_t current_thread_id = GetCurrentThreadId();

        lwip_assert("Function called without core lock", current_thread_id == lwip_core_lock_holder_thread_id);;
        /* for LWIP_NOASSERT */
        return current_thread_id;
    }

    return 0;
}


LwipStatus
sys_new_mailbox(Mailbox* mbox, size_t size)
{
    lwip_assert("mbox != NULL", mbox != nullptr);;

    mbox->sem = CreateSemaphore(nullptr, 0, MAX_QUEUE_ENTRIES, nullptr);
    lwip_assert("Error creating semaphore", mbox->sem != nullptr);
    if (mbox->sem == nullptr)
    {
        sys_prot_t lev;
        SYS_ARCH_PROTECT(lev);
        sys_arch_unprotect(lev);

        return ERR_MEM;
    }
    memset(&mbox->q_mem, 0, sizeof(uint32_t) * MAX_QUEUE_ENTRIES);
    mbox->head = 0;
    mbox->tail = 0;

    sys_prot_t lev;
    SYS_ARCH_PROTECT(lev);
    sys_arch_unprotect(lev);


    return ERR_OK;
}

void
sys_free_mailbox(Mailbox* mbox)
{
    /* parameter check */
    lwip_assert("mbox != NULL", mbox != nullptr);
    lwip_assert("mbox->sem != NULL", mbox->sem != nullptr);
    lwip_assert("mbox->sem != INVALID_HANDLE_VALUE", mbox->sem != INVALID_HANDLE_VALUE);

    CloseHandle(mbox->sem);

    mbox->sem = nullptr;
}

void
sys_mbox_post(Mailbox* mbox, void* msg)
{
    sys_prot_t lev;
    sys_arch_check_not_protected();

    /* parameter check */
    lwip_assert("q != SYS_MBOX_NULL", mbox != nullptr);
    lwip_assert("q->sem != NULL", mbox->sem != nullptr);
    lwip_assert("q->sem != INVALID_HANDLE_VALUE", mbox->sem != INVALID_HANDLE_VALUE);

    SYS_ARCH_PROTECT(lev);
    mbox->q_mem[mbox->head] = msg;
    mbox->head++;
    if (mbox->head >= MAX_QUEUE_ENTRIES)
    {
        mbox->head = 0;
    }
    lwip_assert("mbox is full!", mbox->head != mbox->tail);
    const auto ret = ReleaseSemaphore(mbox->sem, 1, nullptr);
    lwip_assert("Error releasing sem", ret != 0);

    sys_arch_unprotect(lev);
}

LwipStatus
sys_mbox_trypost(Mailbox* q, void* msg)
{
    sys_prot_t lev;
    sys_arch_check_not_protected();

    /* parameter check */
    lwip_assert("q != SYS_MBOX_NULL", q != nullptr);
    lwip_assert("q->sem != NULL", q->sem != nullptr);
    lwip_assert("q->sem != INVALID_HANDLE_VALUE", q->sem != INVALID_HANDLE_VALUE);

    SYS_ARCH_PROTECT(lev);

    uint32_t new_head = q->head + 1;
    if (new_head >= MAX_QUEUE_ENTRIES)
    {
        new_head = 0;
    }
    if (new_head == q->tail)
    {
        sys_arch_unprotect(lev);
        return ERR_MEM;
    }

    q->q_mem[q->head] = msg;
    q->head = new_head;
    lwip_assert("mbox is full!", q->head != q->tail);
    const auto ret = ReleaseSemaphore(q->sem, 1, nullptr);
    lwip_assert("Error releasing sem", ret != 0);

    sys_arch_unprotect(lev);
    return ERR_OK;
}

LwipStatus
sys_mbox_trypost_fromisr(Mailbox* q, void* msg)
{
    return sys_mbox_trypost(q, msg);
}

uint32_t
sys_arch_mbox_fetch(Mailbox* q, void** msg, uint32_t timeout)
{
    sys_prot_t lev;

    /* parameter check */
    lwip_assert("q != SYS_MBOX_NULL", q != nullptr);
    lwip_assert("q->sem != NULL", q->sem != nullptr);
    lwip_assert("q->sem != INVALID_HANDLE_VALUE", q->sem != INVALID_HANDLE_VALUE);

    if (timeout == 0)
    {
        timeout = INFINITE;
    }
    uint64_t starttime = sys_get_time_ns();
    DWORD ret = WaitForSingleObject(q->sem, timeout);
    if (ret == WAIT_OBJECT_0)
    {
        SYS_ARCH_PROTECT(lev);
        if (msg != nullptr)
        {
            *msg = q->q_mem[q->tail];
        }

        q->tail++;
        if (q->tail >= MAX_QUEUE_ENTRIES)
        {
            q->tail = 0;
        }
        sys_arch_unprotect(lev);
        uint64_t endtime = sys_get_time_ns();
        return (uint32_t)(endtime - starttime);
    }
    else
    {
        lwip_assert("Error waiting for sem", ret == WAIT_TIMEOUT);
        if (msg != nullptr)
        {
            *msg = nullptr;
        }

        return SYS_ARCH_TIMEOUT;
    }
}

uint32_t
sys_arch_mbox_tryfetch(Mailbox* q, void** msg)
{
    sys_prot_t lev;

    /* parameter check */
    lwip_assert("q != SYS_MBOX_NULL", q != nullptr);
    lwip_assert("q->sem != NULL", q->sem != nullptr);
    lwip_assert("q->sem != INVALID_HANDLE_VALUE", q->sem != INVALID_HANDLE_VALUE);

    DWORD ret = WaitForSingleObject(q->sem, 0);
    if (ret == WAIT_OBJECT_0)
    {
        SYS_ARCH_PROTECT(lev);
        if (msg != nullptr)
        {
            *msg = q->q_mem[q->tail];
        }

        q->tail++;
        if (q->tail >= MAX_QUEUE_ENTRIES)
        {
            q->tail = 0;
        }
        SYS_ARCH_UNPROTECT(lev);
        return 0;
    }
    else
    {
        lwip_assert("Error waiting for sem", ret == WAIT_TIMEOUT);
        if (msg != nullptr)
        {
            *msg = nullptr;
        }

        return SYS_ARCH_TIMEOUT;
    }
}


//
//
//
Semaphore* sys_arch_netconn_sem_get()
{
    LPVOID tls_data = TlsGetValue(netconn_sem_tls_index);
    return (Semaphore*)tls_data;
}

//
//
//
void sys_arch_netconn_sem_alloc()
{
    Semaphore* sem = (Semaphore*)malloc(sizeof(Semaphore));
    LwipStatus err = sys_sem_new(sem, 0);
    BOOL done = TlsSetValue(netconn_sem_tls_index, sem);;
}

void
sys_arch_netconn_sem_free(void)
{
    LPVOID tls_data = TlsGetValue(netconn_sem_tls_index);
    if (tls_data != nullptr)
    {
        free(tls_data);
        BOOL done = TlsSetValue(netconn_sem_tls_index, nullptr);;
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


/* This is an example implementation for LWIP_PLATFORM_DIAG:
* format a string and pass it to your output function.
*/
void
lwip_win32_platform_diag(const char* format, ...)
{
    va_list ap;
    /* get the varargs */
    va_start(ap, format);
    /* print via varargs; to use another output function, you could use
vsnprintf here */
    vprintf(format, ap);
    va_end(ap);
}
