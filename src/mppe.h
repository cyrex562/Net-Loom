//
// file: mppe.h
//
#pragma once
#include <pppcrypt.h>
#include <lwip_status.h>
#include <packet_buffer.h>
#include "lcp.h"
constexpr auto MPPE_PAD = 4 /* MPPE growth per frame */;
constexpr auto MPPE_MAX_KEY_LEN = 16 /* largest key length (128-bit) */;
constexpr auto MPPE_CCOUNT_SPACE = 0x1000; /* The size of the ccount space */
constexpr auto MPPE_OVERHEAD_LEN = 2; /* MPPE overhead/packet */
constexpr auto SANITY_MAX = 1600; /* Max bogon factor we will tolerate */

/* option bits for CcpOptions.mppe */
enum MppeOptions
{
    MPPE_OPT_NONE = 0,
    MPPE_OPT_40 =0x01,
    /* 40 bit */
    MPPE_OPT_128 =0x02,
    /* 128 bit */
    MPPE_OPT_STATEFUL =0x04,
    /* stateful mode */
    /* unsupported opts */
    MPPE_OPT_56 =0x08,
    /* 56 bit */
    MPPE_OPT_MPPC =0x10,
    /* MPPC compression */
    MPPE_OPT_D =0x20,
    /* Unknown */
    MPPE_OPT_UNSUPPORTED =(MPPE_OPT_56 | MPPE_OPT_MPPC | MPPE_OPT_D),
    MPPE_OPT_UNKNOWN =0x40,
    /* Bits !defined in RFC 3078 were set */
};


/*
 * This is not nice ... the alternative is a bitfield struct though.
 * And unfortunately, we cannot share the same bits for the option
 * names above since C and H are the same bit.  We could do a u_int32
 * but then we have to do a lwip_htonl() all the time and/or we still need
 * to know which octet is which.
 */
enum MppeBits
{
    MPPE_C_BIT =0x01,
    /* MPPC */
    MPPE_D_BIT =0x10,
    /* Obsolete, usage unknown */
    MPPE_L_BIT =0x20,
    /* 40-bit */
    MPPE_S_BIT =0x40,
    /* 128-bit */
    MPPE_M_BIT =0x80,
    /* 56-bit, not supported */
    MPPE_H_BIT =0x01,
    /* Stateless (in a different byte) */
};


/* Does not include H bit; used for least significant octet only. */
constexpr auto MPPE_ALL_BITS = (MPPE_D_BIT|MPPE_L_BIT|MPPE_S_BIT|MPPE_M_BIT|MPPE_H_BIT);


/* Shared MPPE padding between MSCHAP and MPPE */
constexpr auto SHA1_PAD_SIZE = 40;

static const uint8_t MPPE_SHA1_PAD1[SHA1_PAD_SIZE] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t MPPE_SHA1_PAD2[SHA1_PAD_SIZE] = {
  0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
  0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
  0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
  0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2
};

/*
 * State for an MPPE (de)compressor.
 */
struct PppMppeState
{
    lwip_arc4_context arc4;
    uint8_t master_key[MPPE_MAX_KEY_LEN];
    uint8_t session_key[MPPE_MAX_KEY_LEN];
    uint8_t keylen; /* key length in bytes */ /* NB: 128-bit == 16, 40-bit == 8!
     * If we want to support 56-bit, the unit has to change to bits
     */
    uint8_t bits; /* MPPE control bits */
    uint16_t ccount; /* 12-bit coherency count (seqno)  */
    uint16_t sanity_errors; /* take down LCP if too many */
    unsigned int stateful :1; /* stateful mode flag */
    unsigned int discard :1; /* stateful mode packet loss flag */
};



/* Build a CI from mppe opts (see RFC 3078) */
inline void mppe_opts_to_ci(const MppeOptions opts, uint8_t* ci)
{
    auto ptr = ci; /* uint8_t[4] */ /* H bit */
    if (opts & MPPE_OPT_STATEFUL)
    {
        *ptr++ = 0x0;
    }
    else
    {
        *ptr++ = MPPE_H_BIT;
    }
    *ptr++ = 0;
    *ptr++ = 0; /* S,L bits */
    *ptr = 0;
    if (opts & MPPE_OPT_128)
    {
        *ptr |= MPPE_S_BIT;
    }
    if (opts & MPPE_OPT_40)
    {
        *ptr |= MPPE_L_BIT; /* M,D,C bits not supported */
    }
}

/* The reverse of the above */
inline uint8_t MPPE_CI_TO_OPTS(const uint8_t* ci, uint8_t opts)
{
    const uint8_t* ptr = ci; /* uint8_t[4] */
    opts = 0; /* H bit */
    if (!(ptr[0] & MPPE_H_BIT))
        opts |= MPPE_OPT_STATEFUL; /* S,L bits */
    if (ptr[3] & MPPE_S_BIT)
    {
        opts |= MPPE_OPT_128;
    }
    if (ptr[3] & MPPE_L_BIT)
        opts |= MPPE_OPT_40; /* M,D,C bits */
    if (ptr[3] & MPPE_M_BIT)
    {
        opts |= MPPE_OPT_56;
    }
    if (ptr[3] & MPPE_D_BIT)
        opts |= MPPE_OPT_D;
    if (ptr[3] & MPPE_C_BIT)
        opts |= MPPE_OPT_MPPC; /* Other bits */
    if (ptr[0] & ~MPPE_H_BIT)
        opts |= MPPE_OPT_UNKNOWN;
    if (ptr[1] || ptr[2])
    {
        opts |= MPPE_OPT_UNKNOWN;
    }
    if (ptr[3] & ~MPPE_ALL_BITS)
    {
        opts |= MPPE_OPT_UNKNOWN;
    }
}


inline bool
close_on_bad_mppe_state(PppPcb& ppp_pcb, PppMppeState& state)
{
    if (state.sanity_errors > SANITY_MAX) {
        std::string msg = "too many MPPE errors";
        return lcp_close(ppp_pcb, msg);
    }
    return true;
}

void mppe_set_key(PppPcb *pcb, PppMppeState *state, uint8_t *key);

bool
mppe_init(PppPcb& pcb, PppMppeState& state, uint8_t options);
void mppe_comp_reset(PppPcb *pcb, PppMppeState *state);
LwipStatus mppe_compress(PppPcb& pcb, PppMppeState& state, ::PacketBuffer& pb, uint16_t protocol);
void mppe_decomp_reset(PppPcb *pcb, PppMppeState *state);

bool
mppe_decompress(PppPcb& ppp_pcb, PppMppeState& ppp_mppe_state, PacketBuffer& pkt_buf);

//
// END OF FILE
//