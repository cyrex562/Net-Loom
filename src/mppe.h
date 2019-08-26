//
// file: mppe.h
//
#pragma once
#include "pppcrypt.h"
#include "packet_buffer.h"
#include "lcp.h"
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


bool
mppe_set_key(PppMppeState& state, std::vector<uint8_t>& key);

bool
mppe_init(PppPcb& pcb, PppMppeState& state, uint8_t options);


bool
mppe_comp_reset(PppPcb& pcb, PppMppeState& state);


bool
mppe_compress(PppPcb& pcb, PppMppeState& state, ::PacketBuffer& pb, uint16_t protocol);


bool
mppe_decomp_reset(PppPcb& pcb, PppMppeState& state);

bool
mppe_decompress(PppPcb& pcb, PppMppeState& ppp_mppe_state, PacketBuffer& pkt_buf);

//
// END OF FILE
//