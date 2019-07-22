//
// file: sys.h
//

#pragma once

#include <cstdint>

#include "lwip_error.h"


using sys_prot_t = int;

// DWORD (thread id) is used for sys_thread_t but we won't include windows.h
using sys_thread_t = uint32_t;

// Return code for timeouts from sys_arch_mbox_fetch and sys_arch_sem_wait
constexpr auto SYS_ARCH_TIMEOUT = 0xffffffffUL;

constexpr auto MAX_QUEUE_ENTRIES = 100;


/** Function prototype for thread functions */
using lwip_thread_fn = void (*)(void*);


struct Mailbox
{
    void* sem;
    std::array<void*, MAX_QUEUE_ENTRIES>q_mem;
    uint32_t head;
    uint32_t tail;
};

struct ThreadList
{
    lwip_thread_fn function;
    void* arg;
    uint32_t id;
    struct ThreadList* next;
};

/* HANDLE is used for Semaphore but we won't include windows.h */
struct Semaphore
{
    void* sem;
};

// HANDLE is used for sys_mutex_t but we won't include windows.h
struct Mutex
{
    void* mut;
};




/** sys_mbox_tryfetch() returns SYS_MBOX_EMPTY if appropriate.
 * For now we use the same magic value, but we allow this to change in future.
 */
// #define SYS_MBOX_EMPTY SYS_ARCH_TIMEOUT



/* Function prototypes for functions to be implemented by platform ports
   (in sys_arch.c) */

/* Mutex functions: */

/** Define LWIP_COMPAT_MUTEX if the port has no mutexes and binary semaphores
    should be used instead */

extern uint64_t freq;

inline bool sys_initialized(){return (freq != 0);}

/**
 * @ingroup sys_mutex
 * Create a new mutex.
 * Note that mutexes are expected to not be taken recursively by the lwIP code,
 * so both implementation types (recursive or non-recursive) should work.
 * The mutex is allocated to the memory that 'mutex'
 * points to (which can be both a pointer or the actual OS structure).
 * If the mutex has been created, ERR_OK should be returned. Returning any
 * other error will provide a hint what went wrong, but except for assertions,
 * no real error handling is implemented.
 * 
 * @param mutex pointer to the mutex to create
 * @return ERR_OK if successful, another LwipStatus otherwise
 */
LwipStatus sys_mutex_new(Mutex *mutex);
/**
 * @ingroup sys_mutex
 * Blocks the thread until the mutex can be grabbed.
 * @param mutex the mutex to lock
 */
void sys_mutex_lock(Mutex *mutex);
/**
 * @ingroup sys_mutex
 * Releases the mutex previously locked through 'sys_mutex_lock()'.
 * @param mutex the mutex to unlock
 */
void sys_mutex_unlock(Mutex *mutex);
/**
 * @ingroup sys_mutex
 * Deallocates a mutex.
 * @param mutex the mutex to delete
 */
void sys_mutex_free(Mutex *mutex);


/* Semaphore functions: */

/**
 * @ingroup sys_sem
 * Create a new semaphore
 * Creates a new semaphore. The semaphore is allocated to the memory that 'sem'
 * points to (which can be both a pointer or the actual OS structure).
 * The "count" argument specifies the initial state of the semaphore (which is
 * either 0 or 1).
 * If the semaphore has been created, ERR_OK should be returned. Returning any
 * other error will provide a hint what went wrong, but except for assertions,
 * no real error handling is implemented.
 *
 * @param sem pointer to the semaphore to create
 * @param count initial count of the semaphore
 * @return ERR_OK if successful, another LwipStatus otherwise
 */
LwipStatus sys_sem_new(Semaphore *sem, uint8_t count);
/**
 * @ingroup sys_sem
 * Signals a semaphore
 * @param sem the semaphore to signal
 */
void sys_sem_signal(Semaphore *sem);
/**
 * @ingroup sys_sem
 *  Blocks the thread while waiting for the semaphore to be signaled. If the
 * "timeout" argument is non-zero, the thread should only be blocked for the
 * specified time (measured in milliseconds). If the "timeout" argument is zero,
 * the thread should be blocked until the semaphore is signalled.
 * 
 * The return value is SYS_ARCH_TIMEOUT if the semaphore wasn't signaled within
 * the specified time or any other value if it was signaled (with or without
 * waiting).
 * Notice that lwIP implements a function with a similar name,
 * sys_sem_wait(), that uses the sys_arch_sem_wait() function.
 * 
 * @param sem the semaphore to wait for
 * @param timeout timeout in milliseconds to wait (0 = wait forever)
 * @return SYS_ARCH_TIMEOUT on timeout, any other value on success
 */
uint32_t sys_arch_sem_wait(Semaphore *sem, uint32_t timeout);
/**
 * @ingroup sys_sem
 * Deallocates a semaphore.
 * @param sem semaphore to delete
 */
void sys_sem_free(Semaphore *sem);
/** Wait for a semaphore - forever/no timeout */


/**
 * Same as sys_sem_set_invalid() but taking a value, not a pointer
 */



// Deallocates a mailbox. If there are messages still present in the
// mailbox when the mailbox is deallocated, it is an indication of a
// programming error in lwIP and the developer should be notified.
// 
// mbox: mbox to delete
//
void sys_mbox_free(Mailbox *mbox);


// @ingroup sys_misc
// The only thread function:
// Starts a new thread named "name" with priority "prio" that will begin its
// execution in the function "thread()". The "arg" argument will be passed as an
// argument to the thread() function. The stack size to used for this thread is
// the "stacksize" parameter. The id of the new thread is returned. Both the id
// and the priority are system dependent.
// ATTENTION: although this function returns a value, it MUST NOT FAIL (ports have to assert this!)
// 
// name: human-readable name for the thread (used for debugging purposes)
// thread: thread-function
// arg: parameter passed to 'thread'
// stacksize: stack size in bytes for the new thread (may be ignored by ports)
// prio: priority of the new thread (may be ignored by ports) */
sys_thread_t sys_thread_new(const char* name,
                            lwip_thread_fn function,
                            void* arg,
                            int stacksize,
                            int prio);

/**
 * @ingroup sys_misc
 * Sleep for specified number of ms
 */
void sys_msleep(uint32_t ms); /* only has a (close to) 1 ms resolution. */


/* Mailbox functions. */


/**
 * @ingroup sys_mbox
 * Post a message to an mbox - may not fail
 * -> blocks if full, only to be used from tasks NOT from ISR!
 * 
 * @param mbox mbox to posts the message
 * @param msg message to post (ATTENTION: can be NULL)
 */
void sys_mbox_post(Mailbox *mbox, void *msg);
/**
 * @ingroup sys_mbox
 * Try to post a message to an mbox - may fail if full.
 * Can be used from ISR (if the sys arch layer allows this).
 * Returns ERR_MEM if it is full, else, ERR_OK if the "msg" is posted.
 * 
 * @param mbox mbox to posts the message
 * @param msg message to post (ATTENTION: can be NULL)
 */
LwipStatus sys_mbox_trypost(Mailbox *mbox, void *msg);
/**
 * @ingroup sys_mbox
 * Try to post a message to an mbox - may fail if full.
 * To be be used from ISR.
 * Returns ERR_MEM if it is full, else, ERR_OK if the "msg" is posted.
 * 
 * @param mbox mbox to posts the message
 * @param msg message to post (ATTENTION: can be NULL)
 */
LwipStatus sys_mbox_trypost_fromisr(Mailbox *mbox, void *msg);
/**
 * @ingroup sys_mbox
 * Blocks the thread until a message arrives in the mailbox, but does
 * not block the thread longer than "timeout" milliseconds (similar to
 * the sys_arch_sem_wait() function). If "timeout" is 0, the thread should
 * be blocked until a message arrives. The "msg" argument is a result
 * parameter that is set by the function (i.e., by doing "*msg =
 * ptr"). The "msg" parameter maybe NULL to indicate that the message
 * should be dropped.
 * The return values are the same as for the sys_arch_sem_wait() function:
 * SYS_ARCH_TIMEOUT if there was a timeout, any other value if a messages
 * is received.
 * 
 * Note that a function with a similar name, sys_mbox_fetch(), is
 * implemented by lwIP. 
 * 
 * @param mbox mbox to get a message from
 * @param msg pointer where the message is stored
 * @param timeout maximum time (in milliseconds) to wait for a message (0 = wait forever)
 * @return SYS_ARCH_TIMEOUT on timeout, any other value if a message has been received
 */
uint32_t sys_arch_mbox_fetch(Mailbox *mbox, void **msg, uint32_t timeout);

/**
 * @ingroup sys_mbox
 * This is similar to sys_arch_mbox_fetch, however if a message is not
 * present in the mailbox, it immediately returns with the code
 * SYS_MBOX_EMPTY. On success 0 is returned.
 * To allow for efficient implementations, this can be defined as a
 * function-like macro in sys_arch.h instead of a normal function. For
 * example, a naive implementation could be:
 * \#define sys_arch_mbox_tryfetch(mbox,msg) sys_arch_mbox_fetch(mbox,msg,1)
 * although this would introduce unnecessary delays.
 * 
 * @param mbox mbox to get a message from
 * @param msg pointer where the message is stored
 * @return 0 (milliseconds) if a message has been received
 *         or SYS_MBOX_EMPTY if the mailbox is empty
 */
uint32_t sys_arch_mbox_tryfetch(Mailbox *mbox, void **msg);

/**
 * For now, we map straight to sys_arch implementation.
 */
inline void sys_mbox_tryfetch(Mailbox* mbox, void** msg)
{
    sys_arch_mbox_tryfetch(mbox, msg);
}
/**
 * @ingroup sys_mbox
 * Deallocates a mailbox. If there are messages still present in the
 * mailbox when the mailbox is deallocated, it is an indication of a
 * programming error in lwIP and the developer should be notified.
 * 
 * @param mbox mbox to delete
 */
void sys_free_mailbox(Mailbox *mbox);

/**
 * @ingroup sys_misc
 * The only thread function:
 * Starts a new thread named "name" with priority "prio" that will begin its
 * execution in the function "thread()". The "arg" argument will be passed as an
 * argument to the thread() function. The stack size to used for this thread is
 * the "stacksize" parameter. The id of the new thread is returned. Both the id
 * and the priority are system dependent.
 * ATTENTION: although this function returns a value, it MUST NOT FAIL (ports have to assert this!)
 * 
 * @param name human-readable name for the thread (used for debugging purposes)
 * @param thread thread-function
 * @param arg parameter passed to 'thread'
 * @param stacksize stack size in bytes for the new thread (may be ignored by ports)
 * @param prio priority of the new thread (may be ignored by ports) */
sys_thread_t sys_thread_new(const char *name, lwip_thread_fn thread, void *arg, int stacksize, int prio, ThreadList* thread_list);

/**
 * @ingroup sys_misc
 * sys_init() must be called before anything else.
 * Initialize the sys_arch layer.
 */
void sys_init();
/**
 * Ticks/jiffies since power up.
 */
uint64_t sys_jiffies();


/**
 * @ingroup sys_time
 * Returns the current time in milliseconds,
 * may be the same as sys_jiffies or at least based on it.
 * Don't care for wraparound, this is only used for time diffs.
 * Not implementing this function means you cannot use some modules (e.g. TCP
 * timestamps, internal timeouts for NO_SYS==1).
 */
uint64_t sys_now();

/* Critical Region Protection */
/* These functions must be implemented in the sys_arch.c file.
   In some implementations they can provide a more light-weight protection
   mechanism than using semaphores. Otherwise semaphores can be used for
   implementation */

/** SYS_LIGHTWEIGHT_PROT
 * define SYS_LIGHTWEIGHT_PROT in lwipopts.h if you want inter-task protection
 * for certain critical regions during buffer allocation, deallocation and memory
 * allocation and deallocation.
 */

/**
 * @ingroup sys_prot
 * SYS_ARCH_DECL_PROTECT
 * declare a protection variable. This macro will default to defining a variable of
 * type sys_prot_t. If a particular port needs a different implementation, then
 * this macro may be defined in sys_arch.h.
 */
// #define SYS_ARCH_DECL_PROTECT(lev) sys_prot_t lev

   sys_prot_t sys_arch_protect_int(); 
/**
 * @ingroup sys_prot
 * SYS_ARCH_PROTECT
 * Perform a "fast" protect. This could be implemented by
 * disabling interrupts for an embedded system or by using a semaphore or
 * mutex. The implementation should allow calling SYS_ARCH_PROTECT when
 * already protected. The old protection level is returned in the variable
 * "lev". This macro will default to calling the sys_arch_protect() function
 * which should be implemented in sys_arch.c. If a particular port needs a
 * different implementation, then this macro may be defined in sys_arch.h
 */
inline void SYS_ARCH_PROTECT(sys_prot_t& lev){ lev = sys_arch_protect_int();}
/**
 * @ingroup sys_prot
 * SYS_ARCH_UNPROTECT
 * Perform a "fast" set of the protection level to "lev". This could be
 * implemented by setting the interrupt level to "lev" within the MACRO or by
 * using a semaphore or mutex.  This macro will default to calling the
 * sys_arch_unprotect() function which should be implemented in
 * sys_arch.c. If a particular port needs a different implementation, then
 * this macro may be defined in sys_arch.h
 */
#define SYS_ARCH_UNPROTECT(lev) sys_arch_unprotect(lev)

void sys_arch_unprotect(sys_prot_t pval);


/*
 * Macros to set/get and increase/decrease variables in a thread-safe way.
 * Use these for accessing variable that are used from more than one thread.
 */


// #define SYS_ARCH_INC(var, val) do { \
//                                 sys_prot_t old_level; \
//                                 SYS_ARCH_PROTECT(old_level); \
//                                 var += val; \
//                                 SYS_ARCH_UNPROTECT(old_level); \
//                               } while(0)



// #define SYS_ARCH_DEC(var, val) do { \
//                                 sys_prot_t lev; \
//                                 SYS_ARCH_PROTECT(old_level); \
//                                 var -= val; \
//                                 SYS_ARCH_UNPROTECT(old_level); \
//                               } while(0)



// #define SYS_ARCH_GET(var, ret) do { \
//                                 sys_prot_t lev; \
//                                 SYS_ARCH_PROTECT(old_level); \
//                                 ret = var; \
//                                 SYS_ARCH_UNPROTECT(old_level); \
//                               } while(0)

#define SYS_ARCH_SET(var, val) do { \
                               sys_prot_t lev); \
                                SYS_ARCH_PROTECT(old_level); \
                                (var) = val; \
                                SYS_ARCH_UNPROTECT(old_level); \
                              } while(0)



#define SYS_ARCH_LOCKED(code) do { \
                                sys_prot_t lev; \
                                SYS_ARCH_PROTECT(old_level); \
                                code; \
                                SYS_ARCH_UNPROTECT(old_level); \
                              } while(0)



inline bool sys_sem_valid_val(Semaphore sema)
{
    return sema.sem != nullptr && sema.sem != reinterpret_cast<void*>(-1);
}

inline bool sys_sem_valid(Semaphore* sema)
{
    return sema != nullptr && sys_sem_valid_val(*sema);
}

inline void sys_sem_set_invalid(Semaphore* sema){ ((sema)->sem = nullptr);}

inline void sys_sem_set_invalid_val(Semaphore sem) {sys_sem_set_invalid(&(sem));}

inline bool sys_mutex_valid_val(Mutex mutex)
{
    return (((mutex).mut != nullptr) && ((mutex).mut != (void*)-1));
}

inline bool sys_mutex_valid(Mutex* mutex)
{
    return (((mutex) != nullptr) && sys_mutex_valid_val(*(mutex)));
}

inline void sys_mutex_set_invalid(Mutex* mutex)
{
    ((mutex)->mut = nullptr);
}

inline bool sys_mbox_valid_val(const Mailbox mbox)
{
    return mbox.sem != nullptr && mbox.sem != reinterpret_cast<void*>(-1);/**/
}

inline bool sys_mbox_valid(Mailbox* mbox)
{
    return ((mbox != nullptr) && sys_mbox_valid_val(*(mbox)));
}

inline void sys_mbox_set_invalid(Mailbox* mbox){ ((mbox)->sem = nullptr);}


/**
 * @ingroup sys_mbox
 * Creates an empty mailbox for maximum "size" elements. Elements stored
 * in mailboxes are pointers. You have to define macros "_MBOX_SIZE"
 * in your lwipopts.h, or ignore this parameter in your implementation
 * and use a default size.
 * If the mailbox has been created, ERR_OK should be returned. Returning any
 * other error will provide a hint what went wrong, but except for assertions,
 * no real error handling is implemented.
 * 
 * @param mbox pointer to the mbox to create
 * @param size (minimum) number of messages in this mbox
 * @return ERR_OK if successful, another LwipStatus otherwise
 */
LwipStatus sys_new_mailbox(Mailbox *mbox, size_t size);

Semaphore* sys_arch_netconn_sem_get(void);
void sys_arch_netconn_sem_alloc(void);
void sys_arch_netconn_sem_free(void);
#define LWIP_NETCONN_THREAD_SEM_GET()   sys_arch_netconn_sem_get()
#define LWIP_NETCONN_THREAD_SEM_ALLOC() sys_arch_netconn_sem_alloc()
#define LWIP_NETCONN_THREAD_SEM_FREE()  sys_arch_netconn_sem_free()

Semaphore* sys_arch_netconn_sem_get();
void sys_arch_netconn_sem_alloc();
void sys_arch_netconn_sem_free();
int lwip_win32_keypressed();



