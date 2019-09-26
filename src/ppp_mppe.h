//
// file: mppe.h
//
#pragma once
#include "pppcrypt.h"
#include "packet.h"
#include "ppp_lcp.h"
#include "mppe_def.h"






inline bool
cmp_ppp_mppe_state(PppMppeState& state1, PppMppeState& state2)
{
    if (!cmp_arc4_ctx(state1.arc4, state2.arc4))
    {
        return false;
    }
    if (state1.master_key != state2.master_key)
    {
        return false;
    }
    if (state1.session_key != state2.session_key)
    {
        return false;
    }
    if (state1.bits != state2.bits)
    {
        return false;
    }
    if (state1.ccount != state2.ccount)
    {
        return false;
    }
    if (state1.sanity_errors != state2.sanity_errors)
    {
        return false;
    }
    if (state1.stateful != state2.stateful)
    {
        return false;
    }
    if (state1.discard != state2.discard)
    {
        return false;
    }
    return true;
}

inline void mppe_clear_options(MppeOpts& opts)
{
    opts.opt_128 = false;
    opts.opt_40 = false;
    opts.opt_56 = false;
    opts.opt_d = false;
    opts.opt_mppc = false;
    opts.stateful = false;
    opts.unknown = false;
}

/**
 * Build a CI from mppe opts (see RFC 3078)
 *
 */
inline void
mppe_opts_to_ci(const MppeOpts opts, uint8_t* ci)
{
    //auto ptr = ci; /* uint8_t[4] */ /* H bit */
    size_t ptr = 0;
    if (opts.stateful) { ci[ptr++] = 0x0; }
    else { ci[ptr++] = MPPE_H_BIT; }
    ci[ptr++] = 0;
    ci[ptr++] = 0;
    ci[ptr++] = 0;
    // S,L bits
    if (opts.opt_128) { ci[ptr] |= MPPE_S_BIT; }
    if (opts.opt_40) { ci[ptr] |= MPPE_L_BIT; }
    // M,D,C bits not supported
}

/* The reverse of the above */
inline MppeOpts
MPPE_CI_TO_OPTS(const uint8_t* ci)
{
    const uint8_t* ptr = ci; /* uint8_t[4] */
    MppeOpts opts{}; /* H bit */
    if (!(ptr[0] & MPPE_H_BIT))
        opts.stateful = true;; /* S,L bits */
    if (ptr[3] & MPPE_S_BIT) { opts.opt_128 = true; }
    if (ptr[3] & MPPE_L_BIT)
        opts.opt_40 = true; /* M,D,C bits */
    if (ptr[3] & MPPE_M_BIT) { opts.opt_56 = true; }
    if (ptr[3] & MPPE_D_BIT)
        opts.opt_d = true;
    if (ptr[3] & MPPE_C_BIT)
        opts.opt_mppc = true; /* Other bits */
    if (ptr[0] & ~MPPE_H_BIT)
        opts.unknown = true;
    if (ptr[1] || ptr[2]) { opts.unknown = true; }
    if (ptr[3] & ~MPPE_ALL_BITS) { opts.unknown = true; }
    return opts;
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


bool
mppe_set_key(PppMppeState& state, std::vector<uint8_t>& key);

bool
mppe_init(PppPcb& pcb, PppMppeState& state, MppeOpts options);


bool
mppe_comp_reset(PppPcb& pcb, PppMppeState& state);


bool
mppe_compress(PppPcb& pcb, PppMppeState& state, ::PacketContainer& pb, uint16_t protocol);


bool
mppe_decomp_reset(PppPcb& pcb, PppMppeState& state);

bool
mppe_decompress(PppPcb& pcb, PppMppeState& ppp_mppe_state, PacketContainer& pkt_buf);

//
// END OF FILE
//