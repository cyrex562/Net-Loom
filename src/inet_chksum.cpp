/**
 * @file
 * Internet checksum functions.\n
 *
 * These are some reference implementations of the checksum algorithm, with the
 * aim of being simple, correct and fully portable. Checksumming is the
 * first thing you would want to optimize for your platform. If you create
 * your own version, link it in and in your cc.h put:
 *
 * \#define lwip_standard_checksum your_checksum_routine
 *
 * Or you can select from the implementations below by defining
 * lwip_standard_checksum_ALGORITHM to 1, 2 or 3.
 */ /*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
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
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */
#include "opt.h"
#include "def.h"
#include "inet_chksum.h"
#include "ip_addr.h"
#include "lwip_debug.h"
#include <cstring>

// uint16_t lwip_standard_chksum(const void *dataptr, int len);
uint16_t lwip_standard_checksum(const void* dataptr,
                                const size_t len,
                                const int checksum_algorithm)
{
    if (checksum_algorithm == 1)
    {
        return lwip_standard_chksum_1(dataptr, len);
        // ReSharper disable once CppIfCanBeReplacedByConstexprIf
    }
    else if (checksum_algorithm == 2)
    {
        return lwip_standard_chksum_2(dataptr, len);
    }
    else
    {
        return lwip_standard_chksum_3(dataptr, len);
    }
} /**
 * lwip checksum
 *
 * @param dataptr points to start of data to be summed at any boundary
 * @param len length of data to be summed
 * @return host order (!) lwip checksum (non-inverted Internet sum)
 *
 * @note accumulator size limits summable length to 64k
 * @note host endianess is irrelevant (p3 RFC1071)
 */
uint16_t lwip_standard_chksum_1(const void* dataptr, int len)
{
    uint32_t acc;
    uint16_t src;
    const uint8_t* octetptr;
    acc = 0; /* dataptr may be at odd or even addresses */
    octetptr = (const uint8_t *)dataptr;
    while (len > 1)
    {
        /* declare first octet as most significant
           thus assume network order, ignoring host order */
        src = (*octetptr) << 8;
        octetptr++; /* declare second octet as least significant */
        src |= (*octetptr);
        octetptr++;
        acc += src;
        len -= 2;
    }
    if (len > 0)
    {
        /* accumulate remaining octet */
        src = (*octetptr) << 8;
        acc += src;
    } /* add deferred carry bits */
    acc = (acc >> 16) + (acc & 0x0000ffffUL);
    if ((acc & 0xffff0000UL) != 0)
    {
        acc = (acc >> 16) + (acc & 0x0000ffffUL);
    } /* This maybe a little confusing: reorder sum using lwip_htons()
     instead of lwip_ntohs() since it has a little less call overhead.
     The caller must invert bits for Internet sum ! */
    return lwip_htons((uint16_t)acc);
}


/*
 * Curt McDowell
 * Broadcom Corp.
 * csm@broadcom.com
 *
 * IP checksum two bytes at a time with support for
 * unaligned buffer.
 * Works for len up to and including 0x20000.
 * by Curt McDowell, Broadcom Corp. 12/08/2005
 *
 * @param dataptr points to start of data to be summed at any boundary
 * @param len length of data to be summed
 * @return host order (!) lwip checksum (non-inverted Internet sum)
 */
uint16_t lwip_standard_chksum_2(const void* dataptr, const size_t len)
{
    const auto* pb = static_cast<const uint8_t *>(dataptr);
    uint16_t t = 0;
    uint32_t sum = 0;
    auto local_len = len;
    const auto odd = size_t(uintptr_t(pb) & 1); /* Get aligned to uint16_t */
    if (odd && local_len > 0)
    {
        reinterpret_cast<uint8_t *>(&t)[1] = *pb++;
        local_len--;
    } 
    /* Add the bulk of the data */
    const auto* ps = static_cast<const uint16_t *>(static_cast<const void *>(pb));
    while (local_len > 1)
    {
        sum += *ps++;
        local_len -= 2;
    } 
    /* Consume left-over byte, if any */
    if (local_len > 0)
    {
        reinterpret_cast<uint8_t *>(&t)[0] = *reinterpret_cast<const uint8_t *>(ps);
    } 
    /* Add end bytes */
    sum += t; /* Fold 32-bit sum to 16 bits
     calling this twice is probably faster than if statements... */
    sum = FOLD_U32T(sum);
    sum = FOLD_U32T(sum); /* Swap if alignment was odd */
    if (odd)
    {
        sum = SWAP_BYTES_IN_WORD(sum);
    }
    return uint16_t(sum);
}



/**
 * An optimized checksum routine. Basically, it uses loop-unrolling on
 * the checksum loop, treating the head and tail bytes specially, whereas
 * the inner loop acts on 8 bytes at a time.
 *
 * @arg start of buffer to be checksummed. May be an odd byte address.
 * @len number of bytes in the buffer to be checksummed.
 * @return host order (!) lwip checksum (non-inverted Internet sum)
 *
 * by Curt McDowell, Broadcom Corp. December 8th, 2005
 */
uint16_t lwip_standard_chksum_3(const void* dataptr, const size_t len)
{
    const auto* pb = static_cast<const uint8_t *>(dataptr);
    uint16_t t = 0;
    uint32_t sum = 0;
    size_t local_len = len; 
    
    /* starts at odd byte address? */
    int odd = uintptr_t(pb) & 1;
    if (odd && local_len > 0)
    {
        ((uint8_t *)&t)[1] = *pb++;
        local_len--;
    }
    const uint16_t* ps = (const uint16_t *)(const void *)pb;
    if (((uintptr_t)ps & 3) && local_len > 1)
    {
        sum += *ps++;
        local_len -= 2;
    }
    const uint32_t* pl = (const uint32_t *)(const void *)ps;
    while (local_len > 7)
    {
        uint32_t tmp = sum + *pl++; /* ping */
        if (tmp < sum)
        {
            tmp++; /* add back carry */
        }
        sum = tmp + *pl++; /* pong */
        if (sum < tmp)
        {
            sum++; /* add back carry */
        }
        local_len -= 8;
    } /* make room in upper bits */
    sum = FOLD_U32T(sum);
    ps = (const uint16_t *)pl; /* 16-bit aligned word remaining? */
    while (len > 1)
    {
        sum += *ps++;
        local_len -= 2;
    } /* dangling tail byte remaining? */
    if (local_len > 0)
    {
        /* include odd byte */
        ((uint8_t *)&t)[0] = *(const uint8_t *)ps;
    }
    sum += t; /* add end bytes */ /* Fold 32-bit sum to 16 bits
     calling this twice is probably faster than if statements... */
    sum = FOLD_U32T(sum);
    sum = FOLD_U32T(sum);
    if (odd)
    {
        sum = SWAP_BYTES_IN_WORD(sum);
    }
    return (uint16_t)sum;
} 



/** Parts of the pseudo checksum which are common to IPv4 and IPv6 */
static uint16_t inet_cksum_pseudo_base(struct PacketBuffer* p,
                                       uint8_t proto,
                                       size_t proto_len,
                                       uint32_t acc)
{
    struct PacketBuffer* q;
    int swapped = 0; /* iterate through all PacketBuffer in chain */
    for (q = p; q != nullptr; q = q->next)
    {
        // Logf(INET_DEBUG,
        //      ("inet_chksum_pseudo(): checksumming PacketBuffer %p (has next %p) \n", (void
        //          *)q, (void *)q->next));
        acc += lwip_standard_checksum(q->payload, q->len);
        /*Logf(INET_DEBUG, ("inet_chksum_pseudo(): unwrapped lwip_standard_checksum()=%"X32_F"
            * \n", acc));*/
        /* just executing this next line is probably faster that the if statement
              needed to check whether we really need to execute it, and does no harm */
        acc = FOLD_U32T(acc);
        if (q->len % 2 != 0)
        {
            swapped = !swapped;
            acc = SWAP_BYTES_IN_WORD(acc);
        } /*Logf(INET_DEBUG, ("inet_chksum_pseudo(): wrapped lwip_standard_checksum()=%"X32_F"
     * \n", acc));*/
    }
    if (swapped)
    {
        acc = SWAP_BYTES_IN_WORD(acc);
    }
    acc += (uint32_t)lwip_htons((uint16_t)proto);
    acc += (uint32_t)lwip_htons(proto_len); /* Fold 32-bit sum to 16 bits
     calling this twice is probably faster than if statements... */
    acc = FOLD_U32T(acc);
    acc = FOLD_U32T(acc); //  Logf(INET_DEBUG, ("inet_chksum_pseudo(): PacketBuffer chain
    //  lwip_standard_checksum()=%"X32_F"\n", acc));
    return (uint16_t)~(acc & 0xffffUL);
} /* inet_chksum_pseudo:
 *
 * Calculates the IPv4 pseudo Internet checksum used by TCP and UDP for a
 * PacketBuffer chain. IP addresses are expected to be in network byte order.
 *
 * @param p chain of pbufs over that a checksum should be calculated (ip data
 * part)
 * @param src source ip address (used for checksum of pseudo header)
 * @param dst destination ip address (used for checksum of pseudo header)
 * @param proto ip protocol (used for checksum of pseudo header)
 * @param proto_len length of the ip data part (used for checksum of pseudo
 * header)
 * @return checksum (as uint16_t) to be saved directly in the protocol header
 */
uint16_t inet_chksum_pseudo(struct PacketBuffer* p,
                            uint8_t proto,
                            uint16_t proto_len,
                            const Ip4Addr* src,
                            const Ip4Addr* dest)
{
    uint32_t addr = get_ip4_addr(src);
    uint32_t acc = (addr & 0xffffUL);
    acc = static_cast<uint32_t>(acc + ((addr >> 16) & 0xffffUL));
    addr = get_ip4_addr(dest);
    acc = (uint32_t)(acc + (addr & 0xffffUL));
    acc = (uint32_t)(acc + ((addr >> 16) & 0xffffUL)); /* fold down to 16 bits */
    acc = FOLD_U32T(acc);
    acc = FOLD_U32T(acc);
    return inet_cksum_pseudo_base(p, proto, proto_len, acc);
} /**
 * Calculates the checksum with IPv6 pseudo header used by TCP and UDP for a
 * PacketBuffer chain. IPv6 addresses are expected to be in network byte order.
 *
 * @param p chain of pbufs over that a checksum should be calculated (ip data
 * part)
 * @param proto ipv6 protocol/next header (used for checksum of pseudo header)
 * @param proto_len length of the ipv6 payload (used for checksum of pseudo
 * header)
 * @param src source ipv6 address (used for checksum of pseudo header)
 * @param dest destination ipv6 address (used for checksum of pseudo header)
 * @return checksum (as uint16_t) to be saved directly in the protocol header
 */
uint16_t ip6_chksum_pseudo(struct PacketBuffer* p,
                           uint8_t proto,
                           uint16_t proto_len,
                           const Ip6Addr* src,
                           const Ip6Addr* dest)
{
    uint32_t acc = 0;
    uint32_t addr;
    uint8_t addr_part;
    for (addr_part = 0; addr_part < 4; addr_part++)
    {
        addr = src->addr[addr_part];
        acc = (uint32_t)(acc + (addr & 0xffffUL));
        acc = (uint32_t)(acc + ((addr >> 16) & 0xffffUL));
        addr = dest->addr[addr_part];
        acc = (uint32_t)(acc + (addr & 0xffffUL));
        acc = (uint32_t)(acc + ((addr >> 16) & 0xffffUL));
    } /* fold down to 16 bits */
    acc = FOLD_U32T(acc);
    acc = FOLD_U32T(acc);
    return inet_cksum_pseudo_base(p, proto, proto_len, acc);
} /* ip_chksum_pseudo:
 *
 * Calculates the IPv4 or IPv6 pseudo Internet checksum used by TCP and UDP for
 * a PacketBuffer chain. IP addresses are expected to be in network byte order.
 *
 * @param p chain of pbufs over that a checksum should be calculated (ip data
 * part)
 * @param src source ip address (used for checksum of pseudo header)
 * @param dst destination ip address (used for checksum of pseudo header)
 * @param proto ip protocol (used for checksum of pseudo header)
 * @param proto_len length of the ip data part (used for checksum of pseudo
 * header)
 * @return checksum (as uint16_t) to be saved directly in the protocol header
 */
uint16_t ip_chksum_pseudo(struct PacketBuffer* p,
                          uint8_t proto,
                          uint16_t proto_len,
                          const IpAddr* src,
                          const IpAddr* dest)
{
  if (is_ipaddr_v6(dest)) {
      return ip6_chksum_pseudo(p,
                               proto,
                               proto_len,
                               convert_ip_addr_to_ip6_addr(src),
                               convert_ip_addr_to_ip6_addr(dest));
  }
  else
    {
        return inet_chksum_pseudo(p,
                                  proto,
                                  proto_len,
                                  convert_ip_addr_to_ip4_addr(src),
                                  convert_ip_addr_to_ip4_addr(dest));
    }

} /** Parts of the pseudo checksum which are common to IPv4 and IPv6 */
static uint16_t inet_cksum_pseudo_partial_base(struct PacketBuffer* p,
                                               uint8_t proto,
                                               uint16_t proto_len,
                                               uint16_t chksum_len,
                                               uint32_t acc)
{
    struct PacketBuffer* q;
    int swapped = 0;
    uint16_t chklen; /* iterate through all PacketBuffer in chain */
    for (q = p; (q != nullptr) && (chksum_len > 0); q = q->next)
    {
        // Logf(INET_DEBUG,
        //      ("inet_chksum_pseudo(): checksumming PacketBuffer %p (has next %p) \n", (void
        //          *)q, (void *)q->next));
        chklen = q->len;
        if (chklen > chksum_len)
        {
            chklen = chksum_len;
        }
        acc += lwip_standard_checksum(q->payload, chklen);
        chksum_len = (uint16_t)(chksum_len - chklen);
        lwip_assert("delete me", chksum_len < 0x7fff);
        /*Logf(INET_DEBUG, ("inet_chksum_pseudo(): unwrapped lwip_standard_checksum()=%"X32_F"
            * \n", acc));*/ /* fold the upper bit down */
        acc = FOLD_U32T(acc);
        if (q->len % 2 != 0)
        {
            swapped = !swapped;
            acc = SWAP_BYTES_IN_WORD(acc);
        } /*Logf(INET_DEBUG, ("inet_chksum_pseudo(): wrapped lwip_standard_checksum()=%"X32_F"
     * \n", acc));*/
    }
    if (swapped)
    {
        acc = SWAP_BYTES_IN_WORD(acc);
    }
    acc += (uint32_t)lwip_htons((uint16_t)proto);
    acc += (uint32_t)lwip_htons(proto_len); /* Fold 32-bit sum to 16 bits
     calling this twice is probably faster than if statements... */
    acc = FOLD_U32T(acc);
    acc = FOLD_U32T(acc); //  Logf(INET_DEBUG, ("inet_chksum_pseudo(): PacketBuffer chain
    //  lwip_standard_checksum()=%"X32_F"\n", acc));
    return (uint16_t)~(acc & 0xffffUL);
}

/* inet_chksum_pseudo_partial:
 *
 * Calculates the IPv4 pseudo Internet checksum used by TCP and UDP for a
 * PacketBuffer chain. IP addresses are expected to be in network byte order.
 *
 * @param p chain of pbufs over that a checksum should be calculated (ip data
 * part)
 * @param src source ip address (used for checksum of pseudo header)
 * @param dst destination ip address (used for checksum of pseudo header)
 * @param proto ip protocol (used for checksum of pseudo header)
 * @param proto_len length of the ip data part (used for checksum of pseudo
 * header)
 * @return checksum (as uint16_t) to be saved directly in the protocol header
 */
uint16_t inet_chksum_pseudo_partial(struct PacketBuffer* p,
                                    uint8_t proto,
                                    uint16_t proto_len,
                                    uint16_t chksum_len,
                                    const Ip4Addr* src,
                                    const Ip4Addr* dest)
{
    uint32_t acc;
    uint32_t addr;
    addr = get_ip4_addr(src);
    acc = (addr & 0xffffUL);
    acc = (uint32_t)(acc + ((addr >> 16) & 0xffffUL));
    addr = get_ip4_addr(dest);
    acc = (uint32_t)(acc + (addr & 0xffffUL));
    acc = (uint32_t)(acc + ((addr >> 16) & 0xffffUL)); /* fold down to 16 bits */
    acc = FOLD_U32T(acc);
    acc = FOLD_U32T(acc);
    return inet_cksum_pseudo_partial_base(p, proto, proto_len, chksum_len, acc);
}

/**
 * Calculates the checksum with IPv6 pseudo header used by TCP and UDP for a
 * PacketBuffer chain. IPv6 addresses are expected to be in network byte order.
 * Will only compute for a portion of the payload.
 *
 * @param p chain of pbufs over that a checksum should be calculated (ip data
 * part)
 * @param proto ipv6 protocol/next header (used for checksum of pseudo header)
 * @param proto_len length of the ipv6 payload (used for checksum of pseudo
 * header)
 * @param chksum_len number of payload bytes used to compute chksum
 * @param src source ipv6 address (used for checksum of pseudo header)
 * @param dest destination ipv6 address (used for checksum of pseudo header)
 * @return checksum (as uint16_t) to be saved directly in the protocol header
 */
uint16_t ip6_chksum_pseudo_partial(struct PacketBuffer *p, uint8_t proto,
                                   uint16_t proto_len, uint16_t chksum_len,
                                   const Ip6Addr *src, const Ip6Addr *dest) {
  uint32_t acc = 0;
  uint32_t addr;
  uint8_t addr_part;

  for (addr_part = 0; addr_part < 4; addr_part++) {
    addr = src->addr[addr_part];
    acc = (uint32_t)(acc + (addr & 0xffffUL));
    acc = (uint32_t)(acc + ((addr >> 16) & 0xffffUL));
    addr = dest->addr[addr_part];
    acc = (uint32_t)(acc + (addr & 0xffffUL));
    acc = (uint32_t)(acc + ((addr >> 16) & 0xffffUL));
  }
  /* fold down to 16 bits */
  acc = FOLD_U32T(acc);
  acc = FOLD_U32T(acc);

  return inet_cksum_pseudo_partial_base(p, proto, proto_len, chksum_len, acc);
}

/* ip_chksum_pseudo_partial:
 *
 * Calculates the IPv4 or IPv6 pseudo Internet checksum used by TCP and UDP for
 * a PacketBuffer chain.
 *
 * @param p chain of pbufs over that a checksum should be calculated (ip data
 * part)
 * @param src source ip address (used for checksum of pseudo header)
 * @param dst destination ip address (used for checksum of pseudo header)
 * @param proto ip protocol (used for checksum of pseudo header)
 * @param proto_len length of the ip data part (used for checksum of pseudo
 * header)
 * @return checksum (as uint16_t) to be saved directly in the protocol header
 */
uint16_t ip_chksum_pseudo_partial(struct PacketBuffer* p,
                                  uint8_t proto,
                                  uint16_t proto_len,
                                  uint16_t chksum_len,
                                  const IpAddr* src,
                                  const IpAddr* dest)
{
    if (is_ipaddr_v6(dest))
    {
        return ip6_chksum_pseudo_partial(p,
                                         proto,
                                         proto_len,
                                         chksum_len,
                                         &src->u_addr.ip6,
                                         &dest->u_addr.ip6);
    }
    return inet_chksum_pseudo_partial(p,
                                      proto,
                                      proto_len,
                                      chksum_len,
                                      convert_ip_addr_to_ip4_addr(src),
                                      convert_ip_addr_to_ip4_addr(dest));
} 


/* inet_chksum:
 *
 * Calculates the Internet checksum over a portion of memory. Used primarily for
 * IP and ICMP.
 *
 * @param dataptr start of the buffer to calculate the checksum (no alignment
 * needed)
 * @param len length of the buffer to calculate the checksum
 * @return checksum (as uint16_t) to be saved directly in the protocol header
 */
uint16_t inet_chksum(const void* dataptr, uint16_t len)
{
    return (uint16_t)~(unsigned int)lwip_standard_checksum(dataptr, len);
} /**
 * Calculate a checksum over a chain of pbufs (without pseudo-header, much like
 * inet_chksum only pbufs are used).
 *
 * @param p PacketBuffer chain over that the checksum should be calculated
 * @return checksum (as uint16_t) to be saved directly in the protocol header
 */
uint16_t inet_chksum_pbuf(struct PacketBuffer* p)
{
    bool swapped = false;
    uint32_t acc = 0;
    for (struct PacketBuffer* q = p; q != nullptr; q = q->next)
    {
        acc += lwip_standard_checksum(q->payload, q->len);
        acc = FOLD_U32T(acc);
        if (q->len % 2 != 0)
        {
            swapped = !swapped;
            acc = SWAP_BYTES_IN_WORD(acc);
        }
    }
    if (swapped)
    {
        acc = SWAP_BYTES_IN_WORD(acc);
    }
    return uint16_t(~(acc & 0xffffUL));
} 



/* These are some implementations for lwip_standard_checksum_COPY, which copies data
 * like MEMCPY but generates a checksum at the same time. Since this is a
 * performance-sensitive function, you might want to create your own version
 * in assembly targeted at your hardware by defining it in lwipopts.h:
 *   #define lwip_standard_checksum_COPY(dst, src, len) your_chksum_copy(dst, src, len)
 */

/** Safe but slow: first call MEMCPY, then call lwip_standard_checksum.
 * For architectures with big caches, data might still be in cache when
 * generating the checksum after copying.
 */
uint16_t lwip_standard_checksum_copy(void* dst, const void* src, uint16_t len)
{
    MEMCPY(dst, src, len);
    return lwip_standard_checksum(dst, len);
}

