//
// file: sys.cpp
//

#include "arch.h"
#include "lwip_debug.h"
#include "sys.h"
#include "tcpip.h"
#include <windows.h>
#include <cstdio> 
#include <cstdlib>
#include <ctime>
#include <cstdarg>

static LARGE_INTEGER freq; 
static LARGE_INTEGER sys_start_time;
static uint32_t netconn_sem_tls_index;
static HCRYPTPROV hcrypt;
static DWORD lwip_core_lock_holder_thread_id;
CRITICAL_SECTION crit_sec;
static int protection_depth;
const DWORD MS_VC_EXCEPTION=0x406D1388;

//
// Sleep for some ms. Timeouts are NOT processed while sleeping.
//
// ms: number of milliseconds to sleep
//
void sys_msleep(const uint32_t ms)
{
    if (ms > 0)
    {
        Semaphore delaysem{};
        const auto err = sys_sem_new(&delaysem, 0);
        if (err == ERR_OK)
        {
            sys_arch_sem_wait(&delaysem, ms);
            sys_sem_free(&delaysem);
        }
    }
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
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&sys_start_time);
}

//
//
//
static LONGLONG sys_get_ms_longlong()
{
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    const auto ret = now.QuadPart - sys_start_time.QuadPart;
    return uint32_t(((ret) * 1000) / freq.QuadPart);
}

//
//
//
uint32_t sys_jiffies()
{
    return uint32_t(sys_get_ms_longlong());
}

//
//
//
uint32_t sys_now(void)
{
    return uint32_t(sys_get_ms_longlong());
}





static void
InitSysArchProtect(void)
{
  InitializeCriticalSection(&crit_sec);
}

sys_prot_t
sys_arch_protect_int(void)
{
  EnterCriticalSection(&crit_sec);
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
    // lwip_assert("SYS_ARCH_PROTECT before scheduling", protection_depth == 1);
    sys_arch_unprotect(0);
}

static void msvc_sys_init(void)
{
    sys_win_rand_init();
    sys_init_timing();
    InitSysArchProtect();
    netconn_sem_tls_index = TlsAlloc();
    lwip_assert("TlsAlloc failed", netconn_sem_tls_index != TLS_OUT_OF_INDEXES);
}

void sys_init(void)
{
    msvc_sys_init();
}

struct threadlist
{
    lwip_thread_fn function;
    void* arg;
    DWORD id;
    struct threadlist* next;
};

static struct threadlist *lwip_win32_threads = nullptr;

//
//
//
LwipStatus sys_sem_new(Semaphore* sem, const uint8_t count)
{
    HANDLE new_sem = nullptr;
    lwip_assert("sem != NULL", sem != nullptr);
    new_sem = CreateSemaphore(nullptr, count, 100000, nullptr);
    lwip_assert("Error creating semaphore", new_sem != nullptr);
    if (new_sem != nullptr)
    {
        if ((freq.QuadPart != 0))
        {
            sys_prot_t lev;
            SYS_ARCH_PROTECT(lev);
            sys_arch_unprotect(lev);
        }
        else
        {
        }
        sem->sem = new_sem;
        return ERR_OK;
    } /* failed to allocate memory... */
    if ((freq.QuadPart != 0))
    {
        sys_prot_t lev;
        SYS_ARCH_PROTECT(lev);
        sys_arch_unprotect(lev);
    }
    else
    {
    }
    sem->sem = nullptr;
    return ERR_MEM;
}

//
//
//
void sys_sem_free(Semaphore* sem)
{
    /* parameter check */
    lwip_assert("sem != NULL", sem != nullptr);
    lwip_assert("sem->sem != NULL", sem->sem != nullptr);
    lwip_assert("sem->sem != INVALID_HANDLE_VALUE", sem->sem != INVALID_HANDLE_VALUE);
    CloseHandle(sem->sem);
    sys_prot_t lev;
    SYS_ARCH_PROTECT(lev);
    sys_arch_unprotect(lev);
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

//
//
//
void sys_sem_signal(Semaphore* sem)
{
    sys_arch_check_not_protected();
    lwip_assert("sem != NULL", sem != nullptr);
    lwip_assert("sem->sem != NULL", sem->sem != nullptr);
    lwip_assert("sem->sem != INVALID_HANDLE_VALUE", sem->sem != INVALID_HANDLE_VALUE);
    auto ret = ReleaseSemaphore(sem->sem, 1, nullptr);
    lwip_assert("Error releasing semaphore", ret != 0);;
}

//
//
//
LwipStatus sys_mutex_new(Mutex* mutex)
{
    HANDLE new_mut = nullptr;
    lwip_assert("mutex != NULL", mutex != nullptr);
    new_mut = CreateMutex(nullptr, FALSE, nullptr);
    lwip_assert("Error creating mutex", new_mut != nullptr);
    if (new_mut != nullptr)
    {
        sys_prot_t lev;
        SYS_ARCH_PROTECT(lev);
        sys_arch_unprotect(lev);
        mutex->mut = new_mut;
        return ERR_OK;
    }
    sys_prot_t lev;
    SYS_ARCH_PROTECT(lev);
    sys_arch_unprotect(lev);
    mutex->mut = nullptr;
    return ERR_MEM;
}

//
//
//
void sys_mutex_free(Mutex* mutex)
{
    /* parameter check */
    lwip_assert("mutex != NULL", mutex != nullptr);
    lwip_assert("mutex->mut != NULL", mutex->mut != nullptr);
    lwip_assert("mutex->mut != INVALID_HANDLE_VALUE", mutex->mut != INVALID_HANDLE_VALUE);
    CloseHandle(mutex->mut);
    sys_prot_t lev;
    SYS_ARCH_PROTECT(lev);
    sys_arch_unprotect(lev);
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





typedef struct tagTHREADNAME_INFO
{
  DWORD dwType; /* Must be 0x1000. */
  LPCSTR szName; /* Pointer to name (in user addr space). */
  DWORD dwThreadID; /* Thread ID (-1=caller thread). */
  DWORD dwFlags; /* Reserved for future use, must be zero. */
} THREADNAME_INFO;


//
//
//
static void SetThreadName(const DWORD dw_thread_id, const char* thread_name)
{
    THREADNAME_INFO info;
    info.dwType = 0x1000;
    info.szName = thread_name;
    info.dwThreadID = dw_thread_id;
    info.dwFlags = 0;
    __try
    {
        RaiseException(MS_VC_EXCEPTION,
                       0,
                       sizeof(info) / sizeof(ULONG_PTR),
                       (ULONG_PTR*)&info);
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
    auto* t = static_cast<struct threadlist*>(arg);

  sys_arch_netconn_sem_alloc();

  t->function(t->arg);

  sys_arch_netconn_sem_free();

}


//
//
//
sys_thread_t sys_thread_new(const char* name,
                            const lwip_thread_fn function,
                            void* arg,
                            int stacksize,
                            int prio)
{
    sys_prot_t lev;
    const auto new_thread = new threadlist;
    lwip_assert("new_thread != NULL", new_thread != nullptr);
    if (new_thread != nullptr)
    {
        new_thread->function = function;
        new_thread->arg = arg;
        SYS_ARCH_PROTECT(lev);
        new_thread->next = lwip_win32_threads;
        lwip_win32_threads = new_thread;
        const auto h = CreateThread(nullptr,
                                0,
                                LPTHREAD_START_ROUTINE(sys_thread_function),
                                new_thread,
                                0,
                                &(new_thread->id));
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


static DWORD lwip_tcpip_thread_id;


//
//
//
void sys_mark_tcpip_thread()
{
    lwip_tcpip_thread_id = GetCurrentThreadId();
}


//
//
//
void sys_check_core_locking()
{
    /* Embedded systems should check we are NOT in an interrupt context here */
    if (lwip_tcpip_thread_id != 0)
    {
        const auto current_thread_id = GetCurrentThreadId();
        lwip_assert("Function called without core lock",
                    current_thread_id == lwip_core_lock_holder_thread_id);;
    }
}


//
//
//
LwipStatus sys_mbox_new(Mailbox* mbox, size_t size)
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


//
//
//
void sys_mbox_free(Mailbox* mbox)
{
    /* parameter check */
    lwip_assert("mbox != NULL", mbox != nullptr);
    lwip_assert("mbox->sem != NULL", mbox->sem != nullptr);
    lwip_assert("mbox->sem != INVALID_HANDLE_VALUE", mbox->sem != INVALID_HANDLE_VALUE);
    CloseHandle(mbox->sem);
    mbox->sem = nullptr;
}


//
//
//
void sys_mbox_post(Mailbox* mbox, void* msg)
{
    sys_prot_t lev;
    sys_arch_check_not_protected(); /* parameter check */
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
    const auto ret = ReleaseSemaphore(mbox->sem, 1, nullptr) != 0;
    lwip_assert("Error releasing sem", ret != 0);
    sys_arch_unprotect(lev);
}


//
//
//
LwipStatus sys_mbox_trypost(Mailbox* mbox, void* msg)
{
    sys_prot_t lev;
    sys_arch_check_not_protected(); /* parameter check */
    lwip_assert("q != SYS_MBOX_NULL", mbox != nullptr);
    lwip_assert("q->sem != NULL", mbox->sem != nullptr);
    lwip_assert("q->sem != INVALID_HANDLE_VALUE", mbox->sem != INVALID_HANDLE_VALUE);
    SYS_ARCH_PROTECT(lev);
    auto new_head = mbox->head + 1;
    if (new_head >= MAX_QUEUE_ENTRIES)
    {
        new_head = 0;
    }
    if (new_head == mbox->tail)
    {
        sys_arch_unprotect(lev);
        return ERR_MEM;
    }
    mbox->q_mem[mbox->head] = msg;
    mbox->head = new_head;
    lwip_assert("mbox is full!", mbox->head != mbox->tail);
    const auto ret = ReleaseSemaphore(mbox->sem, 1, nullptr);
    lwip_assert("Error releasing sem", ret != 0);
    sys_arch_unprotect(lev);
    return ERR_OK;
}

//
//
//
LwipStatus sys_mbox_trypost_fromisr(Mailbox* mbox, void* msg)
{
    return sys_mbox_trypost(mbox, msg);
}

//
//
//
uint32_t sys_arch_mbox_fetch(Mailbox* mbox, void** msg, uint32_t timeout)
{
    sys_prot_t lev; /* parameter check */
    lwip_assert("q != SYS_MBOX_NULL", mbox != nullptr);
    lwip_assert("q->sem != NULL", mbox->sem != nullptr);
    lwip_assert("q->sem != INVALID_HANDLE_VALUE", mbox->sem != INVALID_HANDLE_VALUE);
    if (timeout == 0)
    {
        timeout = INFINITE;
    }
    const auto starttime = sys_get_ms_longlong();
    const auto ret = WaitForSingleObject(mbox->sem, timeout);
    if (ret == WAIT_OBJECT_0)
    {
        SYS_ARCH_PROTECT(lev);
        if (msg != nullptr)
        {
            *msg = mbox->q_mem[mbox->tail];
        }
        mbox->tail++;
        if (mbox->tail >= MAX_QUEUE_ENTRIES)
        {
            mbox->tail = 0;
        }
        SYS_ARCH_UNPROTECT(lev);
        const auto endtime = sys_get_ms_longlong();
        return uint32_t(endtime - starttime);
    }
    lwip_assert("Error waiting for sem", ret == WAIT_TIMEOUT);
    if (msg != nullptr)
    {
        *msg = nullptr;
    }
    return SYS_ARCH_TIMEOUT;
}

//
//
//
uint32_t sys_arch_mbox_tryfetch(Mailbox* mbox, void** msg)
{
    sys_prot_t lev; /* parameter check */
    lwip_assert("q != SYS_MBOX_NULL", mbox != nullptr);
    lwip_assert("q->sem != NULL", mbox->sem != nullptr);
    lwip_assert("q->sem != INVALID_HANDLE_VALUE", mbox->sem != INVALID_HANDLE_VALUE);
    const auto ret = WaitForSingleObject(mbox->sem, 0);
    if (ret == WAIT_OBJECT_0)
    {
        SYS_ARCH_PROTECT(lev);
        if (msg != nullptr)
        {
            *msg = mbox->q_mem[mbox->tail];
        }
        mbox->tail++;
        if (mbox->tail >= MAX_QUEUE_ENTRIES)
        {
            mbox->tail = 0;
        }
        SYS_ARCH_UNPROTECT(lev);
        return 0;
    }
    lwip_assert("Error waiting for sem", ret == WAIT_TIMEOUT);
    if (msg != nullptr)
    {
        *msg = nullptr;
    }
    return SYS_ARCH_TIMEOUT;
}

//
//
//
Semaphore* sys_arch_netconn_sem_get()
{
    const auto tls_data = TlsGetValue(netconn_sem_tls_index);
    return static_cast<Semaphore*>(tls_data);
}

//
//
//
void sys_arch_netconn_sem_alloc()
{
    const auto sem = new Semaphore;
    lwip_assert("failed to allocate memory for TLS semaphore", sem != nullptr);
    const auto err = sys_sem_new(sem, 0);
    lwip_assert("failed to initialise TLS semaphore", err == ERR_OK);
    const auto done = TlsSetValue(netconn_sem_tls_index, sem);;
    lwip_assert("failed to initialise TLS semaphore storage", done == TRUE);
}

//
//
//
void sys_arch_netconn_sem_free()
{
    const auto tls_data = TlsGetValue(netconn_sem_tls_index);
    if (tls_data != nullptr)
    {
        free(tls_data);
        const auto done = TlsSetValue(netconn_sem_tls_index, nullptr);;
        lwip_assert("failed to de-init TLS semaphore storage", done == TRUE);
    }
} // get keyboard state to terminate the debug app on any kbhit event using win32 API
int lwip_win32_keypressed(void)
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
