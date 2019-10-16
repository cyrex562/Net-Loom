#pragma once

#include <mbedtls/arc4.h>
#include <cstdint>
#include <vector>

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

/* MPPE growth per frame */
constexpr auto MPPE_PAD = 4;
/* largest key length (128-bit) */
constexpr auto MPPE_MAX_KEY_LEN = 16;
/* The size of the ccount space */
constexpr auto MPPE_CCOUNT_SPACE = 0x1000;
/* MPPE overhead/packet */
constexpr auto MPPE_OVERHEAD_LEN = 2;
/* Max bogon factor we will tolerate */
constexpr auto SANITY_MAX = 1600;
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

/**
 * State for an MPPE (de)compressor.
 */
struct PppMppeState
{
    mbedtls_arc4_context arc4;
    std::vector<uint8_t> master_key;
    std::vector<uint8_t> session_key;
    uint8_t bits; /* MPPE control bits */
    size_t ccount; /* 12-bit coherency count (seqno)  */
    size_t sanity_errors; /* take down LCP if too many */
    bool stateful; /* stateful mode flag */
    bool discard; /* stateful mode packet loss flag */
};


/**
 *
 */
struct MppeOpts
{
    bool opt_40;
    bool opt_128;
    bool stateful;
    bool opt_56;
    bool opt_mppc;
    bool opt_d;
    bool unknown;
};


inline bool
mppe_has_options(MppeOpts opts)
{
    if (opts.opt_40 | opts.opt_128 | opts.stateful | opts.opt_56 | opts.opt_mppc |
        opts.opt_d | opts.unknown) { return true; }
    return false;
}

//
// END OF FILE
//
