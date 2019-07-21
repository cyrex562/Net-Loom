/**
 * @file
 * Support for different processor and compiler architectures
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
#pragma once

#include <cstdint>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <cstdint>

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 1234
#endif

#ifndef BIG_ENDIAN
#define BIG_ENDIAN 4321
#endif

/**
 * @defgroup compiler_abstraction Compiler/platform abstraction
 * @ingroup sys_layer
 * All defines related to this section must not be placed in lwipopts.h,
 * but in cc.h!
 * If the compiler does not provide memset() this file must include a
 * definition of it, or include a file which defines it.
 * These options cannot be \#defined in lwipopts.h since they are not options
 * of lwIP itself, but options of the lwIP port to your system.
 * @{
 */

/** Define the byte order of the system.
 * Needed for conversion of network data to host byte order.
 * Allowed values: LITTLE_ENDIAN and BIG_ENDIAN
 */
#define BYTE_ORDER LITTLE_ENDIAN

/** Define random number generator function of your system */
inline uint32_t LwipRand() {
    return uint32_t(rand());
}


/** Platform specific diagnostic output.\n
 * Note the default implementation pulls in printf, which may
 * in turn pull in a lot of standard libary code. In resource-constrained 
 * systems, this should be defined to something less resource-consuming.
 */
// #define LWIP_PLATFORM_DIAG(x) do {printf x;} while(0)

inline void LwipPlatformDiag(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

/** Platform specific assertion handling.\n
 * Note the default implementation pulls in printf, fflush and abort, which may
 * in turn pull in a lot of standard libary code. In resource-constrained 
 * systems, this should be defined to something less resource-consuming.
 */
// #define LWIP_PLATFORM_ASSERT(x) do {printf("Assertion \"%s\" failed at line %d in %s\n", \
//                                     x, __LINE__, __FILE__); fflush(NULL); abort();} while(0)
#define LWIP_PLATFORM_ASSERT(x)


/** Define this to 1 in cc.h of your port if you do not want to
 * include stddef.h header to get size_t. You need to typedef size_t
 * by yourself in this case.
 */


/** Define this to 1 in cc.h of your port if your compiler does not provide
 * the stdint.h header. You need to typedef the generic types listed in
 * arch.h yourself in this case (uint8_t, uint16_t...).
 */
// #ifndef LWIP_NO_STDINT_H
// #define LWIP_NO_STDINT_H 0
// #endif

// /* Define generic types used in lwIP */
// #if !LWIP_NO_STDINT_H
// /* stdint.h is C99 which should also provide support for 64-bit integers */
// #if !defined(LWIP_HAVE_INT64) && defined(UINT64_MAX)
// #define LWIP_HAVE_INT64 1
// #endif
// typedef uint8_t   uint8_t;
// typedef int8_t    int8_t;
// typedef uint16_t  uint16_t;
// typedef int16_t   int16_t;
// typedef uint32_t  uint32_t;
// typedef int32_t   s32_t;
// #if LWIP_HAVE_INT64
// typedef uint64_t  u64_t;
// typedef int64_t   s64_t;
// #endif
// typedef uintptr_t uintptr_t;
// #endif

/** Define this to 1 in cc.h of your port if your compiler does not provide
 * the inttypes.h header. You need to define the format strings listed in
 * arch.h yourself in this case (X8_F, U16_F...).
 */

/* Define (sn)printf formatters for these lwIP types */


/** Define this to 1 in cc.h of your port if your compiler does not provide
 * the limits.h header. You need to define the type limits yourself in this case
 * (e.g. INT_MAX, SSIZE_MAX).
 */




/* Do we need to define ssize_t? This is a compatibility hack:
 * Unfortunately, this type seems to be unavailable on some systems (even if
 * sys/types or unistd.h are available).
 * Being like that, we define it to 'int' if SSIZE_MAX is not defined.
 */

typedef int64_t ssize_t;
constexpr int64_t SSIZE_MAX = INT64_MAX;


/* some maximum values needed in lwip code */
constexpr auto kLwipUint32Max = 0xffffffff;

// #define LWIP_MEM_ALIGN_BUFFER(size) (((size) + MEM_ALIGNMENT - 1U))
inline size_t LwipMemAlignBuffer(const size_t size)
{
    return size + MEM_ALIGNMENT - 1U;
}


/** Define this to 1 in cc.h of your port if your compiler does not provide
 * the ctype.h header. If ctype.h is available, a few character functions
 * are mapped to the appropriate functions (lwip_islower, lwip_isdigit...), if
 * not, a private implementation is provided.
 */

/** Allocates a memory buffer of specified size that is of sufficient size to align
 * its start address using LWIP_MEM_ALIGN.
 * You can declare your own version here e.g. to enforce alignment without adding
 * trailing padding bytes (see LWIP_MEM_ALIGN_BUFFER) or your own section placement
 * requirements.\n
 * e.g. if you use gcc and need 32 bit alignment:\n
 * \#define LWIP_DECLARE_MEMORY_ALIGNED(variable_name, size) uint8_t variable_name[size] \_\_attribute\_\_((aligned(4)))\n
 * or more portable:\n
 * \#define LWIP_DECLARE_MEMORY_ALIGNED(variable_name, size) uint32_t variable_name[(size + sizeof(uint32_t) - 1) / sizeof(uint32_t)]
 */

// #define LWIP_DECLARE_MEMORY_ALIGNED(variable_name, size) uint8_t variable_name[LWIP_MEM_ALIGN_BUFFER(size)]

inline uint8_t* LwipDeclareMemoryAligned(const size_t size)
{
    return new uint8_t[LwipMemAlignBuffer(size)];
}



/** Calculate memory size for an aligned buffer - returns the next highest
 * multiple of MEM_ALIGNMENT (e.g. LWIP_MEM_ALIGN_SIZE(3) and
 * LWIP_MEM_ALIGN_SIZE(4) will both yield 4 for MEM_ALIGNMENT == 4).
 */

// #define LWIP_MEM_ALIGN_SIZE(size) (((size) + MEM_ALIGNMENT - 1U) & ~(MEM_ALIGNMENT-1U))
inline size_t LWIP_MEM_ALIGN_SIZE(const size_t size)
{
    return (size + MEM_ALIGNMENT - 1U) & ~(MEM_ALIGNMENT - 1U);
}


/** Calculate safe memory size for an aligned buffer when using an unaligned
 * type as storage. This includes a safety-margin on (MEM_ALIGNMENT - 1) at the
 * start (e.g. if buffer is uint8_t[] and actual data will be uint32_t*)
 */


/** Align a memory pointer to the alignment defined by MEM_ALIGNMENT
 * so that ADDR % MEM_ALIGNMENT == 0
 */

// #define LWIP_MEM_ALIGN(addr) ((uint8_t *)(((uintptr_t)(addr) + MEM_ALIGNMENT - 1) & ~(uintptr_t)(MEM_ALIGNMENT-1)))
// inline void LWIP_MEM_ALIGN(void* addr)
// {
//     ((void*)(((addr)+MEM_ALIGNMENT - 1) & ~(uint_ptr_t)
// }

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

