///
/// file: inet_checksum.cpp
/// 

#include "opt.h"
#include "def.h"
#include "inet_chksum.h"
#include "ip_addr.h"
#include "lwip_debug.h"
#include <cstring>


///
///
///
uint16_t lwip_standard_checksum(const uint8_t* dataptr,
                                const size_t len,
                                const int checksum_algorithm)
{
    if (checksum_algorithm == 1)
    {
        return lwip_standard_chksum_1(dataptr, len);
        // ReSharper disable once CppIfCanBeReplacedByConstexprIf
    }
    if (checksum_algorithm == 2)
    {
        return lwip_standard_chksum_2(dataptr, len);
    }
    return lwip_standard_chksum_3(dataptr, len);
} 

///
/// lwip checksum
///
/// @param dataptr points to start of data to be summed at any boundary
/// @param len length of data to be summed
/// @return host order (!) lwip checksum (non-inverted Internet sum)
///
/// @note accumulator size limits summable length to 64k
/// @note host endianess is irrelevant (p3 RFC1071)
///
uint16_t lwip_standard_chksum_1(const void* dataptr, int len)
{
    uint16_t src;
    uint32_t acc = 0; /* dataptr may be at odd or even addresses */
    const auto* octetptr = static_cast<const uint8_t *>(dataptr);
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


///
/// Curt McDowell
/// Broadcom Corp.
/// csm@broadcom.com
///
/// IP checksum two bytes at a time with support for
/// unaligned buffer.
/// Works for len up to and including 0x20000.
/// by Curt McDowell, Broadcom Corp. 12/08/2005
///
/// @param dataptr points to start of data to be summed at any boundary
/// @param len length of data to be summed
/// @return host order (!) lwip checksum (non-inverted Internet sum)
///
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
    const auto* ps = reinterpret_cast<const uint16_t *>(static_cast<const uint8_t *>(pb));
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
    sum = fold_u32(sum);
    sum = fold_u32(sum); /* Swap if alignment was odd */
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
    const uint16_t* ps = (const uint16_t *)(const uint8_t *)pb;
    if (((uintptr_t)ps & 3) && local_len > 1)
    {
        sum += *ps++;
        local_len -= 2;
    }
    const uint32_t* pl = (const uint32_t *)(const uint8_t *)ps;
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
    sum = fold_u32(sum);
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
    sum = fold_u32(sum);
    sum = fold_u32(sum);
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
    int swapped = 0; /* iterate through all PacketBuffer in chain */
    for (struct PacketBuffer* q = p; q != nullptr; q = q->next)
    {
        // Logf(INET_DEBUG,
        //      ("inet_chksum_pseudo(): checksumming PacketBuffer %p (has next %p) \n", (void
        //          *)q, (uint8_t *)q->next));
        acc += lwip_standard_checksum(q->payload, q->len);
        /*Logf(INET_DEBUG, ("inet_chksum_pseudo(): unwrapped lwip_standard_checksum()=%x
            * \n", acc));*/
        /* just executing this next line is probably faster that the if statement
              needed to check whether we really need to execute it, and does no harm */
        acc = fold_u32(acc);
        if (q->len % 2 != 0)
        {
            swapped = !swapped;
            acc = SWAP_BYTES_IN_WORD(acc);
        } /*Logf(INET_DEBUG, ("inet_chksum_pseudo(): wrapped lwip_standard_checksum()=%x
     * \n", acc));*/
    }
    if (swapped)
    {
        acc = SWAP_BYTES_IN_WORD(acc);
    }
    acc += (uint32_t)lwip_htons((uint16_t)proto);
    acc += (uint32_t)lwip_htons(proto_len); /* Fold 32-bit sum to 16 bits
     calling this twice is probably faster than if statements... */
    acc = fold_u32(acc);
    acc = fold_u32(acc); //  Logf(INET_DEBUG, ("inet_chksum_pseudo(): PacketBuffer chain
    //  lwip_standard_checksum()=%x\n", acc));
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
uint16_t inet_chksum_pseudo(PacketBuffer& p,
                            uint8_t proto,
                            uint16_t proto_len,
                            const Ip4Addr& src,
                            const Ip4Addr& dest)
{
    uint32_t addr = get_ip4_addr_u32(src);
    uint32_t acc = (addr & 0xffffUL);
    acc = static_cast<uint32_t>(acc + ((addr >> 16) & 0xffffUL));
    addr = get_ip4_addr_u32(dest);
    acc = (uint32_t)(acc + (addr & 0xffffUL));
    acc = (uint32_t)(acc + ((addr >> 16) & 0xffffUL)); /* fold down to 16 bits */
    acc = fold_u32(acc);
    acc = fold_u32(acc);
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
uint16_t ip6_chksum_pseudo(struct PacketBuffer& p,
                           uint8_t proto,
                           size_t proto_len,
                           const Ip6Addr& src,
                           const Ip6Addr& dest)
{
    uint32_t acc = 0;
    for (uint8_t addr_part = 0; addr_part < 4; addr_part++)
    {
        uint32_t addr = src->word[addr_part];
        acc = (uint32_t)(acc + (addr & 0xffffUL));
        acc = (uint32_t)(acc + ((addr >> 16) & 0xffffUL));
        addr = dest->word[addr_part];
        acc = (uint32_t)(acc + (addr & 0xffffUL));
        acc = (uint32_t)(acc + ((addr >> 16) & 0xffffUL));
    } /* fold down to 16 bits */
    acc = fold_u32(acc);
    acc = fold_u32(acc);
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
uint16_t ip_chksum_pseudo(PacketBuffer& p,
                          uint8_t proto,
                          uint16_t proto_len,
                          const IpAddrInfo& src,
                          const IpAddrInfo& dest)
{
  if (is_ip_addr_v6(dest)) {
      return ip6_chksum_pseudo(p,
                               proto,
                               proto_len,
                               src.u_addr.ip6.addr,
                               dest.u_addr.ip6.addr);
  }
  else
    {
        return inet_chksum_pseudo(p,
                                  proto,
                                  proto_len,
                                  src.u_addr.ip4.address,
                                  dest.u_addr.ip4.address);
    }

} /** Parts of the pseudo checksum which are common to IPv4 and IPv6 */
static uint16_t inet_cksum_pseudo_partial_base(struct PacketBuffer* p,
                                               uint8_t proto,
                                               uint16_t proto_len,
                                               uint16_t chksum_len,
                                               uint32_t acc)
{
    int swapped = 0;
    for (struct PacketBuffer* q = p; (q != nullptr) && (chksum_len > 0); q = q->next)
    {
        // Logf(INET_DEBUG,
        //      ("inet_chksum_pseudo(): checksumming PacketBuffer %p (has next %p) \n", (void
        //          *)q, (uint8_t *)q->next));
        uint16_t chklen = q->len;
        if (chklen > chksum_len)
        {
            chklen = chksum_len;
        }
        acc += lwip_standard_checksum(q->payload, chklen);
        chksum_len = (uint16_t)(chksum_len - chklen);
        lwip_assert("delete me", chksum_len < 0x7fff);
        /*Logf(INET_DEBUG, ("inet_chksum_pseudo(): unwrapped lwip_standard_checksum()=%x
            * \n", acc));*/ /* fold the upper bit down */
        acc = fold_u32(acc);
        if (q->len % 2 != 0)
        {
            swapped = !swapped;
            acc = SWAP_BYTES_IN_WORD(acc);
        } /*Logf(INET_DEBUG, ("inet_chksum_pseudo(): wrapped lwip_standard_checksum()=%x
     * \n", acc));*/
    }
    if (swapped)
    {
        acc = SWAP_BYTES_IN_WORD(acc);
    }
    acc += (uint32_t)lwip_htons((uint16_t)proto);
    acc += (uint32_t)lwip_htons(proto_len); /* Fold 32-bit sum to 16 bits
     calling this twice is probably faster than if statements... */
    acc = fold_u32(acc);
    acc = fold_u32(acc); //  Logf(INET_DEBUG, ("inet_chksum_pseudo(): PacketBuffer chain
    //  lwip_standard_checksum()=%x\n", acc));
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
uint16_t inet_chksum_pseudo_partial(PacketBuffer& p,
                                    uint8_t proto,
                                    uint16_t proto_len,
                                    uint16_t chksum_len,
                                    const Ip4Addr& src,
                                    const Ip4Addr& dest)
{
    uint32_t addr = get_ip4_addr_u32(src);
    uint32_t acc = (addr & 0xffffUL);
    acc = (uint32_t)(acc + ((addr >> 16) & 0xffffUL));
    addr = get_ip4_addr_u32(dest);
    acc = (uint32_t)(acc + (addr & 0xffffUL));
    acc = (uint32_t)(acc + ((addr >> 16) & 0xffffUL)); /* fold down to 16 bits */
    acc = fold_u32(acc);
    acc = fold_u32(acc);
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
uint16_t ip6_chksum_pseudo_partial(PacketBuffer& p,
                                   uint8_t proto,
                                   size_t proto_len,
                                   size_t chksum_len,
                                   const Ip6Addr& src,
                                   const Ip6Addr& dest) {
  uint32_t acc = 0;
  for (uint8_t addr_part = 0; addr_part < 4; addr_part++) {
    uint32_t addr = src->word[addr_part];
    acc = (uint32_t)(acc + (addr & 0xffffUL));
    acc = (uint32_t)(acc + ((addr >> 16) & 0xffffUL));
    addr = dest->word[addr_part];
    acc = (uint32_t)(acc + (addr & 0xffffUL));
    acc = (uint32_t)(acc + ((addr >> 16) & 0xffffUL));
  }
  /* fold down to 16 bits */
  acc = fold_u32(acc);
  acc = fold_u32(acc);

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
uint16_t
ip_chksum_pseudo_partial(PacketBuffer& p,
                         uint8_t proto,
                         size_t proto_len,
                         size_t chksum_len,
                         const IpAddrInfo& src,
                         const IpAddrInfo& dest)
{
    if (is_ip_addr_v6(dest))
    {
        return ip6_chksum_pseudo_partial(p,
                                         proto,
                                         proto_len,
                                         chksum_len,
                                         src.u_addr.ip6.addr,
                                         dest.u_addr.ip6.addr);
    }
    return inet_chksum_pseudo_partial(p,
                                      proto,
                                      proto_len,
                                      chksum_len,
                                      src.u_addr.ip4.address,
                                      dest.u_addr.ip4.address);
} 

///
/// inet_chksum:
///
/// Calculates the Internet checksum over a portion of memory. Used primarily for
/// IP and ICMP.
///
/// @param dataptr start of the buffer to calculate the checksum (no alignment
/// needed)
/// @param len length of the buffer to calculate the checksum
/// @return checksum (as uint16_t) to be saved directly in the protocol header
///
uint16_t inet_chksum(const uint8_t* dataptr, size_t len)
{
    return uint16_t(~static_cast<unsigned int>(lwip_standard_checksum(dataptr, len)));
} 


///
/// Calculate a checksum over a chain of pbufs (without pseudo-header, much like
/// inet_chksum only pbufs are used).
///
/// @param p PacketBuffer chain over that the checksum should be calculated
/// @return checksum (as uint16_t) to be saved directly in the protocol header
///
uint16_t inet_chksum_pbuf(struct PacketBuffer* p)
{
    auto swapped = false;
    uint32_t acc = 0;
    for (auto q = p; q != nullptr; q = q->next)
    {
        acc += lwip_standard_checksum(q->payload, q->len);
        acc = fold_u32(acc);
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

///
/// Safe but slow: first call memcpy, then call lwip_standard_checksum.
/// For architectures with big caches, data might still be in cache when
/// generating the checksum after copying.
///
uint16_t lwip_standard_checksum_copy(uint8_t* dst, uint8_t* src, uint16_t len)
{
    memcpy(dst, src, len);
    return lwip_standard_checksum(dst, len);
}

//
// END OF FILE
//