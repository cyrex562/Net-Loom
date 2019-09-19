/*
 * eui64.h - EUI64 routines for IPv6CP.
 *
 * Copyright (c) 1999 Tommi Komulainen.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name(s) of the authors of this software must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Tommi Komulainen
 *     <Tommi.Komulainen@iki.fi>".
 *
 * THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * $Id: eui64.h,v 1.6 2002/12/04 23:03:32 paulus Exp $
*/
#pragma once

#include "magic.h"
#include "ns_def.h"
#include <cstdint>
#include <cstring>


/*
 * @todo:
 *
 * Maybe this should be done by processing struct LwipIn6Addr directly...
 */
union Eui64
{
    uint8_t e8[8];
    uint16_t e16[4];
    uint32_t e32[2];
};


inline bool
eui64_iszero(Eui64 e)
{
    return (((e).e32[0] | (e).e32[1]) == 0);
}


inline bool
eui64_equals(Eui64 e, Eui64 o)
{
    return (((e).e32[0] == (o).e32[0]) &&
        ((e).e32[1] == (o).e32[1]));
}


inline void
eui64_zero(Eui64& e)
{
    (e).e32[0] = (e).e32[1] = 0;
}


inline void
eui64_copy(Eui64* s, Eui64* d)
{
    memcpy(d, s, sizeof(Eui64));
}


inline void
eui64_magic(Eui64& e)
{
    (e).e32[0] = magic();
    (e).e32[1] = magic();
    (e).e8[0] &= ~2;
}


inline void
eui64_magic_nz(Eui64& x)
{
    do {
        eui64_magic(x);
    }
    while (eui64_iszero(x));
}


inline void
eui64_magic_ne(Eui64& x, Eui64& y)
{
    do {
        eui64_magic(x);
    }
    while (eui64_equals(x, y));
}


inline void
eui64_get(Eui64* ll, Eui64* cp)
{
    eui64_copy((cp), (ll));
    (cp) += sizeof(Eui64);
}


inline void
eui64_put(Eui64* ll, Eui64* cp)
{
    eui64_copy((ll), (cp));
    (cp) += sizeof(Eui64);
}


inline void
eui64_set32(Eui64& e, uint32_t l)
{
    (e).e32[0] = 0;
    (e).e32[1] = pp_htonl(l);
}


inline void
eui64_setlo32(Eui64& e, uint32_t l)
{
    eui64_set32(e, l);
}


char* eui64_ntoa(Eui64); /* Returns ascii representation of id */

//
// END OF FILE
//
