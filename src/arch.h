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

#include "cc.h"

#include <cctype>

#include <climits>
#include <cstdint>

#include <cstdio>

#include <cstdlib>


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
#define LWIP_RAND() ((uint32_t)rand())

/** Platform specific diagnostic output.\n
 * Note the default implementation pulls in printf, which may
 * in turn pull in a lot of standard libary code. In resource-constrained 
 * systems, this should be defined to something less resource-consuming.
 */
#define LWIP_PLATFORM_DIAG(x) do {printf x;} while(0)


/** Platform specific assertion handling.\n
 * Note the default implementation pulls in printf, fflush and abort, which may
 * in turn pull in a lot of standard libary code. In resource-constrained 
 * systems, this should be defined to something less resource-consuming.
 */
#define LWIP_PLATFORM_ASSERT(x) do {printf("Assertion \"%s\" failed at line %d in %s\n", \
                                    x, __LINE__, __FILE__); fflush(NULL); abort();} while(0)

#define LWIP_UINT32_MAX 0xffffffff

#define LWIP_ISDIGIT(c)           isdigit((unsigned char)(c))
#define LWIP_ISXDIGIT(c)          isxdigit((unsigned char)(c))
#define LWIP_ISLOWER(c)           islower((unsigned char)(c))
#define LWIP_ISSPACE(c)           isspace((unsigned char)(c))
#define LWIP_ISUPPER(c)           isupper((unsigned char)(c))
#define LWIP_TOLOWER(c)           tolower((unsigned char)(c))
#define LWIP_TOUPPER(c)           toupper((unsigned char)(c))
#define LWIP_CONST_CAST(target_type, val) ((target_type)((ptrdiff_t)val))

/** Get rid of alignment cast warnings (GCC -Wcast-align) */
#define LWIP_ALIGNMENT_CAST(target_type, val) LWIP_CONST_CAST(target_type, val)

/** Get rid of warnings related to pointer-to-numeric and vice-versa casts,
 * e.g. "conversion from 'uint8_t' to 'void *' of greater size"
 */
#define LWIP_PTR_NUMERIC_CAST(target_type, val) LWIP_CONST_CAST(target_type, val)

/** Avoid warnings/errors related to implicitly casting away packed attributes by doing a explicit cast */
#define LWIP_PACKED_CAST(target_type, val) LWIP_CONST_CAST(target_type, val)

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
#define LWIP_DECLARE_MEMORY_ALIGNED(variable_name, size) uint8_t variable_name[LWIP_MEM_ALIGN_BUFFER(size)]

/** Calculate memory size for an aligned buffer - returns the next highest
 * multiple of MEM_ALIGNMENT (e.g. LWIP_MEM_ALIGN_SIZE(3) and
 * LWIP_MEM_ALIGN_SIZE(4) will both yield 4 for MEM_ALIGNMENT == 4).
 */
#define LWIP_MEM_ALIGN_SIZE(size) (((size) + MEM_ALIGNMENT - 1U) & ~(MEM_ALIGNMENT-1U))

/** Calculate safe memory size for an aligned buffer when using an unaligned
 * type as storage. This includes a safety-margin on (MEM_ALIGNMENT - 1) at the
 * start (e.g. if buffer is uint8_t[] and actual data will be uint32_t*)
 */
#define LWIP_MEM_ALIGN_BUFFER(size) (((size) + MEM_ALIGNMENT - 1U))

/** Align a memory pointer to the alignment defined by MEM_ALIGNMENT
 * so that ADDR % MEM_ALIGNMENT == 0
 */
#define LWIP_MEM_ALIGN(addr) ((void *)(((mem_ptr_t)(addr) + MEM_ALIGNMENT - 1) & ~(mem_ptr_t)(MEM_ALIGNMENT-1)))


