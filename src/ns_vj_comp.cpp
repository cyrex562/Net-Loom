#include "ns_vj_comp.h"
#include "ns_debug.h"
#include <pppoe.cpp>
#include <cstring>

void
vj_compress_init(VjCompress* comp)
{
    auto tstate = comp->tstate;
    comp->max_slot_index = MAX_SLOTS - 1;
    comp->compress_slot = 0; /* Disable slot ID compression by default. */
    for (uint8_t i = MAX_SLOTS - 1; i > 0; --i)
    {
        tstate[i].cs_id = i;
        tstate[i].cs_next = &tstate[i - 1];
    }
    tstate[0].cs_next = &tstate[MAX_SLOTS - 1];
    tstate[0].cs_id = 0;
    comp->last_cs = &tstate[0];
    comp->last_recv = 255;
    comp->last_xmit = 255;
    comp->flags = VJF_TOSS;
} // ENCODE encodes a number that is known to be non-zero.  ENCODEZ
// checks for zero (since zero has to be encoded in the long, 3 byte
// form).
//
inline void
Encode(const uint16_t n, uint8_t* cp)
{
    if (uint16_t(n) >= 256)
    {
        *cp++ = 0;
        cp[1] = uint8_t(n);
        cp[0] = uint8_t((n) >> 8);
        cp += 2;
    }
    else
    {
        *cp++ = uint8_t(n);
    }
}

inline void
Encodez(const uint16_t n, uint8_t* cp)
{
    if (uint16_t(n) >= 256 || uint16_t(n) == 0)
    {
        *cp++ = 0;
        cp[1] = uint8_t(n);
        cp[0] = uint8_t((n) >> 8);
        cp += 2;
    }
    else
    {
        *cp++ = uint8_t(n);
    }
}

inline void
DecodeLong(uint32_t f, uint8_t* cp)
{
    if (*cp == 0)
    {
        auto tmp_ = ns_ntohl(f) + ((cp[1] << 8) | cp[2]);
        (f) = lwip_htonl(tmp_);
        cp += 3;
    }
    else
    {
        auto tmp_ = ns_ntohl(f) + uint32_t(*cp++);
        (f) = lwip_htonl(tmp_);
    }
}

inline void
DecodeShort(uint16_t f, uint8_t* cp)
{
    if (*cp == 0)
    {
        uint16_t tmp_ = ns_ntohs(f) + ((uint16_t(cp[1]) << 8) | cp[2]);
        (f) = ns_htons(tmp_);
        cp += 3;
    }
    else
    {
        uint16_t tmp_ = ns_ntohs(f) + uint16_t(*cp++);
        (f) = ns_htons(tmp_);
    }
}

inline uint16_t
DECODEU(uint16_t f, uint8_t* cp)
{
    if (*cp == 0)
    {
        f = ns_htons(uint16_t(cp[1]) << 8 | cp[2]);
        cp += 3;
    }
    else
    {
        (f) = ns_htons(uint16_t(*cp++));
    }
} /// Helper structures for unaligned *uint32_t and *uint16_t accesses
struct vj_uint32_t
{
    uint32_t v;
};

struct vj_u16_t
{
    uint16_t v;
}; ///
/// vj_compress_tcp - Attempt to do Van Jacobson header compression on a
/// packet.  This assumes that nb and comp are not null and that the first
/// buffer of the chain contains a valid IP header.
/// Return the VJ type code indicating whether or not the packet was
/// compressed.
///
uint8_t
vj_compress_tcp(VjCompress& vj_comp, PacketContainer& pkt_buf)
{
    struct PacketContainer* np = *pkt_buf;
    struct Ip4Hdr& ip = (struct Ip4Hdr *)np->payload;
    Cstate* cs = vj_comp->last_cs->cs_next;
    uint16_t ilen = get_ip4_hdr_hdr_len(ip);
    TcpHdr* oth;
    uint16_t deltaS, deltaA = 0;
    uint32_t deltaL;
    uint32_t changes = 0;
    uint8_t new_seq[16];
    uint8_t* cp = new_seq; /*
   * Check that the packet is IP proto TCP.
   */
    if (get_ip4_hdr_proto(ip) != IP_PROTO_TCP)
    {
        return (TYPE_IP);
    } /*
   * Bail if this is an IP fragment or if the TCP packet isn't
   * `compressible' (i.e., ACK isn't set or some other control bit is
   * set).
   */
    if ((get_ip4_hdr_offset(ip) & pp_htons(0x3fff)) || np->tot_len < 40)
    {
        return (TYPE_IP);
    }
    TcpHdr* th = (TcpHdr *)&((struct vj_uint32_t*)ip)[ilen];
    if ((tcph_flags(th) & (TCP_SYN | TCP_FIN | TCP_RST | TCP_ACK)) != TCP_ACK)
    {
        return (TYPE_IP);
    } /* Check that the TCP/IP headers are contained in the first buffer. */
    uint16_t hlen = ilen + get_tcp_hdr_len(th);
    hlen <<= 2;
    if (np->len < hlen)
    {
        return (TYPE_IP);
    } /* TCP stack requires that we don't change the packet payload, therefore we copy
   * the whole packet before compression. */
    np = pbuf_clone(*pkt_buf);
    if (!np)
    {
        return (TYPE_IP);
    }
    *pkt_buf = np;
    ip = (struct Ip4Hdr *)np->payload; /*
   * Packet is compressible -- we're going to send either a
   * COMPRESSED_TCP or UNCOMPRESSED_TCP packet.  Either way we need
   * to locate (or create) the connection state.  Special case the
   * most recently used connection since it's most likely to be used
   * again & we don't have to do any reordering if it's used.
   */ // vjs_packets +=1;
    if (!(&ip->src.u32 == &cs->vjcs_u.csu_ip.src.u32) || !
        (&ip->dest.u32 == &cs->vjcs_u.csu_ip.dest.u32) || (*(struct vj_uint32_t*)th).v
        != (((struct vj_uint32_t*)&cs->vjcs_u.csu_ip)[get_ip4_hdr_hdr_len(
            &cs->vjcs_u.csu_ip)]).v)
    {
        Cstate* lastcs = vj_comp->last_cs;
        do
        {
            Cstate* lcs = cs;
            cs = cs->cs_next; // INCR(vjs_searches);
            if ((&ip->src.u32 == &cs->vjcs_u.csu_ip.src.u32) &&
                (&ip->dest.u32 == &cs->vjcs_u.csu_ip.dest.u32) && (*(struct vj_uint32_t*
                )th).v == (((struct vj_uint32_t*)&cs->vjcs_u.csu_ip)[get_ip4_hdr_hdr_len(
                    &cs->vjcs_u.csu_ip)]).v)
            {
                goto found;
            }
        }
        while (cs != lastcs); /*
     * Check that the packet is IP proto TCP.
     */
        if (get_ip4_hdr_proto(ip) != IP_PROTO_TCP)
        {
            return (TYPE_IP);
        } /*
     * Bail if this is an IP fragment or if the TCP packet isn't
     * `compressible' (i.e., ACK isn't set or some other control bit is
     * set).
     */
        if ((get_ip4_hdr_offset(ip) & pp_htons(0x3fff)) || np->tot_len < 40)
        {
            return (TYPE_IP);
        }
        auto th = reinterpret_cast<struct TcpHdr *>(&reinterpret_cast<struct vj_uint32_t*>
            (ip)[ilen]);
        if ((tcph_flags(th) & (TCP_SYN | TCP_FIN | TCP_RST | TCP_ACK)) != TCP_ACK)
        {
            return (TYPE_IP);
        } /* Check that the TCP/IP headers are contained in the first buffer. */
        uint16_t hlen = ilen + get_tcp_hdr_len(th);
        hlen <<= 2;
        if (np->len < hlen)
        {
            // PPPDEBUG(LOG_INFO, ("vj_compress_tcp: header len %d spans buffers\n", hlen));
            return (TYPE_IP);
        } /* TCP stack requires that we don't change the packet payload, therefore we copy
     * the whole packet before compression. */
        np = pbuf_clone( *pkt_buf);
        if (!np)
        {
            return (TYPE_IP);
        }
        *pkt_buf = np;
        ip = reinterpret_cast<struct Ip4Hdr *>(np->payload); /*
     * Packet is compressible -- we're going to send either a
     * COMPRESSED_TCP or UNCOMPRESSED_TCP packet.  Either way we need
     * to locate (or create) the connection state.  Special case the
     * most recently used connection since it's most likely to be used
     * again & we don't have to do any reordering if it's used.
     */ // INCR(vjs_packets);
        if (!(&ip->src.u32 == &cs->vjcs_u.csu_ip.src.u32) || !
            (&ip->dest.u32 == &cs->vjcs_u.csu_ip.dest.u32) || (*(struct vj_uint32_t*)th)
            .v != (((struct vj_uint32_t*)&cs->vjcs_u.csu_ip)[get_ip4_hdr_hdr_len(
                &cs->vjcs_u.csu_ip)]).v)
        {
            /*
             * Wasn't the first -- search for it.
             *
             * States are kept in a circularly linked list with
             * last_cs pointing to the end of the list.  The
             * list is kept in lru order by moving a state to the
             * head of the list whenever it is referenced.  Since
             * the list is short and, empirically, the connection
             * we want is almost always near the front, we locate
             * states via linear search.  If we don't find a state
             * for the datagram, the oldest state is (re-)used.
             */
            Cstate* lcs;
            Cstate* lastcs = vj_comp->last_cs;
            do
            {
                lcs = cs;
                cs = cs->cs_next; // INCR(vjs_searches);
                if ((&ip->src.u32 == &cs->vjcs_u.csu_ip.src.u32) &&
                    (&ip->dest.u32 == &cs->vjcs_u.csu_ip.dest.u32) && (*(struct
                        vj_uint32_t*)th).v == (((struct vj_uint32_t*)&cs->vjcs_u.csu_ip)[
                        get_ip4_hdr_hdr_len(&cs->vjcs_u.csu_ip)]).v)
                {
                    goto found;
                }
            }
            while (cs != lastcs); /*
         * Didn't find it -- re-use oldest cstate.  Send an
         * uncompressed packet that tells the other side what
         * connection number we're using for this conversation.
         * Note that since the state list is circular, the oldest
         * state points to the newest and we only need to set
         * last_cs to update the lru linkage.
         */ // INCR(vjs_misses);
            vj_comp->last_cs = lcs;
            goto uncompressed;
        found: /*
         * Found it -- move to the front on the connection list.
         */ if (cs == lastcs)
            {
                vj_comp->last_cs = lcs;
            }
            else
            {
                lcs->cs_next = cs->cs_next;
                cs->cs_next = lastcs->cs_next;
                lastcs->cs_next = cs;
            }
        }
        struct TcpHdr* oth = (struct TcpHdr *)&((struct vj_uint32_t*)&cs->vjcs_u.csu_ip)[
            ilen];
        uint16_t deltaS = ilen; /*
     * Make sure that only what we expect to change changed. The first
     * line of the `if' checks the IP protocol version, header length &
     * type of service.  The 2nd line checks the "Don't fragment" bit.
     * The 3rd line checks the time-to-live and protocol (the protocol
     * check is unnecessary but costless).  The 4th line checks the TCP
     * header length.  The 5th line checks IP options, if any.  The 6th
     * line checks TCP options, if any.  If any of these things are
     * different between the previous & current datagram, we send the
     * current datagram `uncompressed'.
     */
        if ((((struct vj_u16_t*)ip)[0]).v != (((struct vj_u16_t*)&cs->vjcs_u.csu_ip)[0]).v
            || (((struct vj_u16_t*)ip)[3]).v != (((struct vj_u16_t*)&cs->vjcs_u.csu_ip)[3]
            ).v || (((struct vj_u16_t*)ip)[4]).v != (((struct vj_u16_t*)&cs->vjcs_u.csu_ip
            )[4]).v || get_tcp_hdr_len(th) != get_tcp_hdr_len(oth) || (deltaS > 5 && BCMP(
                ip + 1,
                &cs->vjcs_u.csu_ip + 1,
                (deltaS - 5) << 2)) || (get_tcp_hdr_len(th) > 5 && BCMP(
                th + 1,
                oth + 1,
                (get_tcp_hdr_len(th) - 5) << 2)))
        {
            goto uncompressed;
        } /*
     * Figure out which of the changing fields changed.  The
     * receiver expects changes in the order: urgent, window,
     * ack, seq (the order minimizes the number of temporaries
     * needed in this section of code).
     */
        if (tcph_flags(th) & TCP_URG)
        {
            deltaS = lwip_ntohs(th->urgp); // Encodez(deltaS);
            // changes |= NEW_U;
        }
        else if (th->urgp != oth->urgp)
        {
            /* argh! URG not set but urp changed -- a sensible
             * implementation should never do this but RFC793
             * doesn't prohibit the change so we have to deal
             * with it. */
            goto uncompressed;
        }
        if ((deltaS = (uint16_t)(lwip_ntohs(th->wnd) - lwip_ntohs(oth->wnd))) != 0)
        {
            Encode(deltaS, cp); // changes |= NEW_W;
        } // if ((delta_l = lwip_ntohl(th->ackno) - lwip_ntohl(oth->ackno)) != 0)
        // {
        //     if (delta_l > 0xffff)
        //     {
        //         goto uncompressed;
        //     }
        //     deltaA = (uint16_t)delta_l;
        //     Encode(deltaA, cp);
        //     changes |= NEW_A;
        // }
        // if ((delta_l = lwip_ntohl(th->seqno) - lwip_ntohl(oth->seqno)) != 0)
        // {
        //     if (delta_l > 0xffff)
        //     {
        //         goto uncompressed;
        //     }
        //     deltaS = (uint16_t)delta_l;
        //     Encode(deltaS, cp);
        //     changes |= NEW_S;
        // }
        switch (changes)
        {
        case 0: /*
         * Nothing changed. If this packet contains data and the
         * last one didn't, this is probably a data packet following
         * an ack (normal on an interactive connection) and we send
         * it compressed.  Otherwise it's probably a retransmit,
         * retransmitted ack or window probe.  Send it uncompressed
         * in case the other side missed the compressed version.
         */ if (get_ip4_hdr_len(ip) != get_ip4_hdr_len(&cs->vjcs_u.csu_ip) && lwip_ntohs(
                get_ip4_hdr_len(&cs->vjcs_u.csu_ip)) == hlen)
            {
                break;
            } /* no break */ /* fall through */ // case SPECIAL_I: case SPECIAL_D: /*
            //  * actual changes match one of our special case encodings --
            //  * send packet uncompressed.
            //  */ goto uncompressed;
            // case NEW_S | NEW_A:
            //     if (deltaS == deltaA && deltaS == lwip_ntohs(get_ip4_hdr_len(&cs->vjcs_u.csu_ip)) -
            //         hlen)
            //     {
            //         /* special case for echoed terminal traffic */
            //         changes = SPECIAL_I;
            //         cp = new_seq;
            //     }
            //     break;
            // case NEW_S:
            //     if (deltaS == lwip_ntohs(get_ip4_hdr_len(&cs->vjcs_u.csu_ip)) - hlen)
            //     {
            //         /* special case for data xfer */
            //         changes = SPECIAL_D;
            //         cp = new_seq;
            //     }
            //     break;
        default:
            break;
        }
        deltaS = (uint16_t)(lwip_ntohs(get_ip4_hdr_id(ip)) - lwip_ntohs(
            get_ip4_hdr_id(&cs->vjcs_u.csu_ip)));
        if (deltaS != 1)
        {
            // Encodez(deltaS);
            // changes |= NEW_I;
        }
        if (tcph_flags(th) & TCP_PSH)
        {
            // changes |= TCP_PUSH_BIT;
        } /*
     * Grab the cksum before we overwrite it below.  Then update our
     * state with this packet's header.
     */
        deltaA = lwip_ntohs(th->chksum);
        memcpy(&cs->vjcs_u.csu_ip, ip, hlen); /*
     * We want to use the original packet as our compressed packet.
     * (cp - new_seq) is the number of bytes we need for compressed
     * sequence numbers.  In addition we need one byte for the change
     * mask, one for the connection id and two for the tcp checksum.
     * So, (cp - new_seq) + 4 bytes of header are needed.  hlen is how
     * many bytes of the original packet to toss so subtract the two to
     * get the new packet size.
     */
        deltaS = (uint16_t)(cp - new_seq);
        if (!vj_comp->compress_slot || vj_comp->last_xmit != cs->cs_id)
        {
            vj_comp->last_xmit = cs->cs_id;
            hlen -= deltaS + 4;
            // if (pbuf_remove_header(np, hlen))
            // {
            //     /* Can we cope with this failing?  Just assert for now */
            //     lwip_assert("pbuf_remove_header failed\n", false);
            // }
            cp = (uint8_t*)np->payload; // *cp++ = (uint8_t)(changes | NEW_C);
            *cp++ = cs->cs_id;
        }
        cp = (uint8_t*)np->payload;
        *cp++ = (uint8_t)changes;
    }
    *cp++ = (uint8_t)(deltaA >> 8);
    *cp++ = (uint8_t)deltaA;
    memcpy(cp, new_seq, deltaS); // INCR(vjs_compressed);
    return (TYPE_COMPRESSED_TCP);
uncompressed: memcpy(&cs->vjcs_u.csu_ip, ip, hlen);
    set_ip4_hdr_proto(ip, cs->cs_id);
    vj_comp->last_xmit = cs->cs_id;
    return (TYPE_UNCOMPRESSED_TCP);
} ///
/// Called when we may have missed a packet.
///
void
vj_uncompress_err(struct VjCompress* comp)
{
    comp->flags |= VJF_TOSS; // INCR(vjs_errorin);
} ///
/// "Uncompress" a packet of type TYPE_UNCOMPRESSED_TCP.
/// Return 0 on success, -1 on failure.
///
int
vj_uncompress_uncomp(struct PacketContainer* nb, struct VjCompress* comp)
{
    struct Ip4Hdr& ip = (struct Ip4Hdr *)nb->payload;
    uint32_t hlen = get_ip4_hdr_hdr_len(ip) << 2;
    if (get_ip4_hdr_proto(ip) >= MAX_SLOTS || hlen + sizeof(struct TcpHdr) > nb->len || (
            hlen += get_tcp_hdr_len((struct TcpHdr *)&((char *)ip)[hlen], true)) > nb->len
        ||
        hlen > MAX_HDR)
    {
        // PPPDEBUG(LOG_INFO,
        //          ("vj_uncompress_uncomp: bad cid=%d, hlen=%d buflen=%d\n",
        //              get_ip4_hdr_proto(ip), hlen, nb->len));
        vj_uncompress_err(comp);
        return -1;
    }
    Cstate* cs = &comp->rstate[comp->last_recv = get_ip4_hdr_proto(ip)];
    comp->flags &= ~ VJF_TOSS;
    set_ip4_hdr_proto(ip, IP_PROTO_TCP);
    /* copy from/to bigger buffers checked above instead of cs->vjcs_u.csu_ip and ip
                            just to help static code analysis to see this is correct ;-) */
    memcpy(&cs->vjcs_u.csu_hdr, nb->payload, hlen);
    cs->cs_hlen = (uint16_t)hlen; // INCR(vjs_uncompressedin);
    return 0;
} ///
/// Uncompress a packet of type TYPE_COMPRESSED_TCP.
/// The packet is composed of a buffer chain and the first buffer
/// must contain an accurate chain length.
/// The first buffer must include the entire compressed TCP/IP header.
/// This procedure replaces the compressed header with the uncompressed
/// header and returns the length of the VJ header.
///
int
vj_uncompress_tcp(struct PacketContainer** nb, struct VjCompress* comp)
{
    struct vj_u16_t* bp;
    struct PacketContainer* n0 = *nb;
    uint32_t tmp;
    uint8_t* cp = (uint8_t*)n0->payload;
    uint32_t changes = *cp++;
    if (changes & NEW_C)
    {
        /*
         * Make sure the state index is in range, then grab the state.
         * If we have a good state index, clear the 'discard' flag.
         */
        if (*cp >= MAX_SLOTS)
        {
            // PPPDEBUG(LOG_INFO, ("vj_uncompress_tcp: bad cid=%d\n", *cp));
            return -1;
        }
        comp->flags &= ~ VJF_TOSS;
        comp->last_recv = *cp++;
    }
    else
    {
        /*
         * this packet has an implicit state index.  If we've
         * had a line error since the last time we got an
         * explicit state index, we have to toss the packet.
         */
        if (comp->flags & VJF_TOSS)
        {
            // PPPDEBUG(LOG_INFO, ("vj_uncompress_tcp: tossing\n"));
            // INCR(vjs_tossed);
            return (-1);
        }
    }
    struct Cstate* cs = &comp->rstate[comp->last_recv];
    uint32_t hlen = get_ip4_hdr_hdr_len(&cs->vjcs_u.csu_ip) << 2;
    struct TcpHdr* th = (struct TcpHdr *)&((uint8_t*)&cs->vjcs_u.csu_ip)[hlen];
    th->chksum = ns_htons((*cp << 8) | cp[1]);
    cp += 2;
    if (changes & TCP_PUSH_BIT)
    {
        TCPH_SET_FLAG(th, TCP_PSH);
    }
    else
    {
        TCPH_UNSET_FLAG(th, TCP_PSH);
    }
    switch (changes & SPECIALS_MASK)
    {
    case SPECIAL_I:
        {
            uint32_t i = ns_ntohs(get_ip4_hdr_len(&cs->vjcs_u.csu_ip)) - cs->cs_hlen;
            /* some compilers can't nest inline assembler.. */
            tmp = ns_ntohl(th->ackno) + i;
            th->ackno = lwip_htonl(tmp);
            tmp = ns_ntohl(th->seqno) + i;
            th->seqno = lwip_htonl(tmp);
        }
        break;
    case SPECIAL_D: /* some compilers can't nest inline assembler.. */ tmp =
            ns_ntohl(th->seqno) + ns_ntohs(get_ip4_hdr_len(&cs->vjcs_u.csu_ip)) - cs->
            cs_hlen;
        th->seqno = lwip_htonl(tmp);
        break;
    default:
        if (changes & NEW_U)
        {
            TCPH_SET_FLAG(th, TCP_URG); // DECODEU(th->urgp);
        }
        else
        {
            TCPH_UNSET_FLAG(th, TCP_URG);
        }
        if (changes & NEW_W)
        {
            // DecodeShort(th->wnd);
        }
        if (changes & NEW_A)
        {
            // DecodeLong(th->ackno);
        }
        if (changes & NEW_S)
        {
            // DecodeLong(th->seqno);
        }
        break;
    }
    if (changes & NEW_I)
    {
        // DecodeShort(cs->vjcs_u.csu_ip._id);
    }
    else
    {
        set_ip4_hdr_id(&cs->vjcs_u.csu_ip,
                       ns_ntohs(get_ip4_hdr_id(&cs->vjcs_u.csu_ip)) + 1);
        set_ip4_hdr_id(&cs->vjcs_u.csu_ip,
                       ns_htons(get_ip4_hdr_id(&cs->vjcs_u.csu_ip)));
    }
    if (changes & NEW_I)
    {
        // DecodeShort(cs->vjcs_u.csu_ip._id);
    }
    else
    {
        set_ip4_hdr_id(&cs->vjcs_u.csu_ip,
                       ns_ntohs(get_ip4_hdr_id(&cs->vjcs_u.csu_ip)) + 1);
        set_ip4_hdr_id(&cs->vjcs_u.csu_ip,
                       ns_htons(get_ip4_hdr_id(&cs->vjcs_u.csu_ip)));
    } /*
 * At this point, cp points to the first byte of data in the
 * packet.  Fill in the IP total length and update the IP
 * header checksum.
 */
    auto vjlen = (uint16_t)(cp - (uint8_t*)n0->payload);
    if (n0->len < vjlen)
    {
        /*
         * At this point, cp points to the first byte of data in the
         * packet.  Fill in the IP total length and update the IP
         * header checksum.
         */
        uint32_t vjlen = uint16_t(cp - static_cast<uint8_t*>(n0->payload));
        if (n0->len < vjlen)
        {
            /*
             * We must have dropped some characters (crc should detect
             * this but the old slip framing won't)
             */
            // PPPDEBUG(LOG_INFO, ("vj_uncompress_tcp: head buffer %d too short %d\n",
            // n0->len, vjlen));
            goto bad;
        }
#if BYTE_ORDER == LITTLE_ENDIAN
        tmp = n0->tot_len - vjlen + cs->cs_hlen;
        set_ip4_hdr_len(&cs->vjcs_u.csu_ip, ns_htons((uint16_t)tmp));
#else
  set_ip4_hdr_len(&cs->vjcs_u.csu_ip, lwip_htons(n0->tot_len - vjlen + cs->cs_hlen));
#endif
        /* recompute the ip header checksum */
        bp = reinterpret_cast<struct vj_u16_t*>(&cs->vjcs_u.csu_ip);
        set_ip4_hdr_checksum(&cs->vjcs_u.csu_ip, 0);
        for (tmp = 0; hlen > 0; hlen -= 2)
        {
            tmp += (*bp++).v;
        }
        tmp = (tmp & 0xffff) + (tmp >> 16);
        tmp = (tmp & 0xffff) + (tmp >> 16);
        set_ip4_hdr_checksum(&cs->vjcs_u.csu_ip, (uint16_t)(~tmp));
        /* Remove the compressed header and prepend the uncompressed header. */
        // if (pbuf_remove_header(n0, vjlen))
        // {
        //     /* Can we cope with this failing?  Just assert for now */
        //     lwip_assert("pbuf_remove_header failed\n", false);
        //     goto bad;
        // } //     if (LWIP_MEM_ALIGN(n0->payload) != n0->payload)
        //     {
        //         PacketBuffer* np;
        //
        // #if IP_FORWARD
        //     /* If IP forwarding is enabled we are using a PBUF_LINK packet type so
        //      * the packet is being allocated with enough header space to be
        //      * forwarded (to Ethernet for example).
        //      */
        //     np = pbuf_alloc(PBUF_LINK, n0->len + cs->cs_hlen, PBUF_POOL);
        // #else /* IP_FORWARD */
        //         np = pbuf_alloc(PBUF_RAW, n0->len + cs->cs_hlen, PBUF_POOL);
        // #endif /* IP_FORWARD */
        //         if (!np)
        //         {
        //             PPPDEBUG(LOG_WARNING, ("vj_uncompress_tcp: realign failed\n"));
        //             goto bad;
        //         }
        //
        //         if (pbuf_remove_header(np, cs->cs_hlen))
        //         {
        //             /* Can we cope with this failing?  Just assert for now */
        //             lwip_assert("pbuf_remove_header failed\n", 0);
        //             goto bad;
        //         }
        //
        //         pbuf_take(np, n0->payload, n0->len);
        //
        //         if (n0->next)
        //         {
        //             pbuf_chain(np, n0->next);
        //             pbuf_dechain(n0);
        //         }
        //         free_pkt_buf(n0);
        //         n0 = np;
        //     }
        // if (pbuf_add_header(n0, cs->cs_hlen))
        // {
        //     lwip_assert("vj_uncompress_tcp: cs->cs_hlen <= PBUF_POOL_BUFSIZE",
        //                 cs->cs_hlen <= PBUF_POOL_BUFSIZE);
        //     // np = pbuf_alloc(PBUF_RAW, cs->cs_hlen, PBUF_POOL);
        //     struct PacketBuffer* np = new PacketBuffer;
        //     if (!np)
        //     {
        //         // PPPDEBUG(LOG_WARNING, ("vj_uncompress_tcp: prepend failed\n"));
        //         goto bad;
        //     }
        //     pbuf_cat(np, n0);
        //     n0 = np;
        // }
        ns_assert("n0->len >= cs->cs_hlen", n0->len >= cs->cs_hlen);
        memcpy(n0->payload, &cs->vjcs_u.csu_ip, cs->cs_hlen);
        *nb = n0;
        return vjlen;
    bad: vj_uncompress_err(comp);
        return (-1);
    }
}
