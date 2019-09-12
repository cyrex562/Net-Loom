/*
 * chap-new.c - New CHAP implementation.
 *
 * Copyright (c) 2003 Paul Mackerras. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. The name(s) of the authors of this software must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 3. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Paul Mackerras
 *     <paulus@samba.org>".
 *
 * THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define NOMINMAX
#include "auth.h"
#include "chap_md5.h"
#include "chap_new.h"
#include "magic.h"

#include "ppp_opts.h"
#include "ppp.h"
#include "spdlog/spdlog.h"

/*
 * Prototypes.
 */

/**
 * Reset to initial state.
 */
bool
chap_init(PppPcb& pcb)
{
    return true;
}

/*
 * chap_lowerup - we can start doing stuff now.
 */
bool
chap_lowerup(PppPcb& pcb)
{
    pcb.chap_client.flags.lower_up = true;

    pcb.chap_server.flags.lower_up = true;
    if (pcb.chap_server.flags.auth_started)
    {
        chap_timeout(pcb);
    }

    return true;
}


bool
chap_lower_down(PppPcb& pcb)
{
    clear_chap_state_flags(pcb.chap_client.flags);
    if (pcb.chap_server.flags.timeout_pending)
    {
        chap_timeout(pcb);
    }
    clear_chap_state_flags(pcb.chap_server.flags);
    return true;
}


/*
 * chap_auth_peer - Start authenticating the peer.
 * If the lower layer is already up, we start sending challenges,
 * otherwise we wait for the lower layer to come up.
 */
void
chap_auth_peer(PppPcb& pcb, std::string& our_name, int digest_code)
{
    const struct ChapDigestType* dp;

    if (pcb.chap_server.flags.auth_started)
    {
        ppp_error("CHAP: peer authentication already started!");
        return;
    }
    // for (auto i = 0; (dp = chap_digests[i]) != nullptr; ++i)
    //     if (dp->code == digest_code)
    //         break;
    if (dp == nullptr)
    {
        ppp_fatal("CHAP digest 0x%x requested but not available",
                  digest_code);
    }
    // todo: handle with pub/sub
    // pcb.chap_server.digest = dp;
    pcb.chap_server.name = our_name;
    /* Start with a random ID value */
    pcb.chap_server.id = magic();
    pcb.chap_server.flags.auth_started = true;
    if (pcb.chap_server.flags.lower_up)
    {
        chap_timeout(pcb);
    }
}


/**
 * Prepare to authenticate ourselves to the peer. There isn't much to do until we
 * receive a challenge.
 */
bool
chap_auth_with_peer(PppPcb& pcb, std::string& our_name, int digest_code)
{
    // const struct ChapDigestType dp;
    int i;

    if (pcb.chap_client.flags.auth_started)
    {
        spdlog::error("CHAP: authentication with peer already started!");
        return false;
    }

    // todo: get chap digest code
    // for (i = 0; (dp = chap_digests[i]) != nullptr; ++i)
    //     if (dp->code == digest_code)
    //         break;

    // if (dp == nullptr)
    // {
    //     ppp_fatal("CHAP digest 0x%x requested but not available",
    //               digest_code);
    // }
    // pcb.chap_client.digest = chap_digest_type;
    pcb.chap_client.name = our_name;
    pcb.chap_client.flags.auth_started = true;

    return true;
}

/*
 * chap_timeout - It's time to send another challenge to the peer.
 * This could be either a retransmission of a previous challenge,
 * or a new challenge to start re-authentication.
 */
bool
chap_timeout(PppPcb& pcb)
{
    pcb.chap_server.flags.timeout_pending = false;
    if ((pcb.chap_server.flags.challenge_valid == false))
    {
        pcb.chap_server.challenge_xmits = 0;
        chap_generate_challenge(pcb);
        pcb.chap_server.flags.challenge_valid = true;
    }
    else if (pcb.chap_server.challenge_xmits >= pcb.settings.chap_max_transmits)
    {
        pcb.chap_server.flags.challenge_valid = false;
        pcb.chap_server.flags.auth_done = true;
        pcb.chap_server.flags.auth_failed = true;
        auth_peer_fail(pcb, PPP_CHAP);
        return false;
    }

    PacketBuffer p = init_pkt_buf();

    memcpy(p.data.data(), pcb.chap_server.challenge.data(), pcb.chap_server.challenge_pktlen);

    ppp_write(pcb, p);
    ++pcb.chap_server.challenge_xmits;
    pcb.chap_server.flags.timeout_pending = true;

    // todo: figure out way to call with re-schedule
    // Timeout(chap_timeout, pcb, pcb.settings.chap_timeout_time);

    return true;
}


/**
 * generate a challenge string and format the challenge packet in
 * pcb.chap_server.challenge_pkt
 */
void
chap_generate_challenge(PppPcb& pcb)
{
    auto p = pcb.chap_server.challenge;
    size_t index = 0;
    ppp_make_header(p, PPP_CHAP, index);
    // auto p_ptr = p.data();
    // p_ptr += CHAP_HDR_LEN;
    index += CHAP_HDR_LEN;
    // todo: generate challenge based on digest type
    //pcb.chap_server.digest->generate_challenge(pcb, p);
    const auto clen = p[index];
    const auto nlen = pcb.chap_server.name.length();
    std::copy(pcb.chap_server.name.begin(),
              pcb.chap_server.name.end(),
              p.begin() + index + 1 + clen);
    const auto len = CHAP_HDR_LEN + 1 + clen + nlen;
    pcb.chap_server.challenge_pktlen = PPP_HDRLEN + len;
    // p_ptr = pcb.chap_server.challenge.data() + PPP_HDRLEN;
    p[0 + PPP_HDRLEN] = CHAP_CHALLENGE;
    p[1 + PPP_HDRLEN] = ++pcb.chap_server.id;
    p[2 + PPP_HDRLEN] = len >> 8;
    p[3 + PPP_HDRLEN] = len;
}

/*
 * chap_handle_response - check the response to our challenge.
 */
bool
chap_handle_response(PppPcb& pcb, int code, std::vector<uint8_t>& pkt)
{
    int response_len;
    std::string name;
    std::string rname;
    rname.reserve(MAXNAMELEN + 1);
    std::string message;
    message.reserve(256);
    if ((pcb.chap_server.flags.lower_up) == false)
    {
        return false;
    }
    if (code != pcb.chap_server.challenge[PPP_HDRLEN + 1] || pkt.size() < 2)
    {
        return false;
    }
    if (pcb.chap_server.flags.challenge_valid)
    {
        std::vector<uint8_t> response(pkt);
        // uint8_t* response = pkt.data();
        bool ok = true;
        uint8_t response_len = 0;
        std::tie(ok, response_len) = GETCHAR(pkt, 0);
        // len -= response_len + 1; /* length of name */
        // name = reinterpret_cast<char *>(response) + response_len;
        std::copy(response.begin(), response.begin() + response_len, name.begin());
        if (pcb.chap_server.flags.timeout_pending)
        {
            pcb.chap_server.flags.timeout_pending = false;
            chap_timeout(pcb);
        }
        if (pcb.settings.explicit_remote)
        {
            name = pcb.peer_authname;
        }
        else
        {
            /* Null terminate and clean remote name. */
            // ppp_slprintf(rname, sizeof(rname), "%.*v", len, name);
            // name = rname;
            rname = fmt::format("{}v", name);
            name = rname;
        }
        std::vector<uint8_t> challenge_part (pcb.chap_server.challenge.begin() + PPP_HDRLEN + CHAP_HDR_LEN, pcb.chap_server.challenge.end());
        ok = chap_verify_response(pcb,
                                  name,
                                  pcb.chap_server.name,
                                  code,
                                  challenge_part,
                                  response,
                                  message,
                                  sizeof(message));

        if (!ok)
        {
            pcb.chap_server.flags.auth_failed = true;
            spdlog::warn("peer {} failed CHAP authentication", name);
            return false;
        }
    }
    else if ((pcb.chap_server.flags.auth_done) == 0)
    {
        return false;
    }

    /* send the response */
    size_t mlen = message.size();
    size_t len = mlen + CHAP_HDR_LEN;
    size_t index = 0;
    std::vector<uint8_t> packet_data;
    ppp_make_header(packet_data, PPP_CHAP, index);

    // auto outp = static_cast<unsigned char *>(p->payload);
    // ppp_make_header(outp, PPP_CHAP);

    packet_data[0] = (pcb.chap_server.flags.auth_failed) ? CHAP_FAILURE : CHAP_SUCCESS;
    packet_data[1] = code;
    packet_data[2] = len >> 8;
    packet_data[3] = len;
    if (mlen > 0) { std::copy(message.begin(), message.begin() + mlen, packet_data.begin() + CHAP_HDR_LEN);
    }
    PacketBuffer _pkt{};
    _pkt.data = packet_data;
    if (!ppp_write(pcb, _pkt)) {
        return false;
    }

    if (pcb.chap_server.flags.challenge_valid)
    {
        pcb.chap_server.flags.challenge_valid = false;
        if (!(pcb.chap_server.flags.auth_done) && !(pcb.chap_server.flags.auth_failed))
        {
        }
        if (pcb.chap_server.flags.auth_failed)
        {
            auth_peer_fail(pcb, PPP_CHAP);
            // todo: check return value
        }
        else
        {
            if ((pcb.chap_server.flags.auth_done) == 0)
            {
                auth_peer_success(pcb,
                                  PPP_CHAP,
                                  pcb.chap_server.digest_code,
                                  name);
            }
            if (pcb.settings.chap_rechallenge_time)
            {
                pcb.chap_server.flags.timeout_pending = true;
                // todo: schedule chap timeout function
                // Timeout(chap_timeout,
                //         pcb,
                //         pcb.settings.chap_rechallenge_time);
            }
        }
        pcb.chap_server.flags.auth_done = true;
    }
}


/**
 * Check whether the peer's response matches what we think it should be.
 * Returns 1 if it does (authentication succeeded), or 0 if it doesn't.
 */
bool
chap_verify_response(PppPcb& pcb,
                     std::string& name,
                     std::string& ourname,
                     int id,
                     std::vector<uint8_t>& challenge,
                     std::vector<uint8_t>& response,
                     std::string& message,
                     int message_space)
{
    std::string secret;
    bool ok = false;

    /* Get the secret that the peer is supposed to know */
    if (!get_secret(pcb, name, ourname, secret)) {
        ppp_error("No CHAP secret found for authenticating %q", name.c_str());
        return false;
    }
    // todo: call appropriate verify_response function for the given digest type
    // auto ok = digest->verify_response(pcb,
    //                                  id,
    //                                  name,
    //                                  secret,
    //                                  challenge,
    //                                  response,
    //                                  message,
    //                                  message_space);
    // memset(secret, 0, sizeof(secret));
    return ok;
}


/**
 * Generate and send a response to a challenge.
 */
bool
chap_respond(PppPcb& pcb, const int id, std::vector<uint8_t>& pkt_data)
{
    std::string secret;
    size_t len = pkt_data.size();
    PacketBuffer p{};

    if ((!pcb.chap_client.flags.lower_up && !pcb.chap_client.flags.auth_started)) {
        return false; /* not ready */
    }

    /* too short */
    if (len < 2 || len < size_t(pkt_data[0]) + 1) { return false;  }
    size_t clen = pkt_data[0];
    size_t nlen = len - (clen + 1);

    /* Null terminate and clean remote name. */
    std::string rname = fmt::format("{}", pkt_data.data() + clen + 1);

    /* Microsoft doesn't send their name back in the PPP packet */
    if (pcb.settings.explicit_remote || (pcb.settings.remote_name[0] != 0 && rname[0] == 0
    )) rname = pcb.settings.remote_name;

    /* get secret for authenticating ourselves with the specified host */
    if (!get_secret(pcb, pcb.chap_client.name, rname, secret)) {
        spdlog::warn("No CHAP secret found for authenticating us to {}", rname);
    }
    size_t index = 0;
    ppp_make_header(p.data, PPP_CHAP, index);
    index += CHAP_HDR_LEN;

    // todo: execute function make_response by digest type
    // pcb.chap_client.digest->make_response(pcb,
    //                                        outp,
    //                                        id,
    //                                        pcb.chap_client.name,
    //                                        pkt_data,
    //                                        secret,
    //                                        pcb.chap_client.priv);
    // memset(secret, 0, secret_len);
    clen = p.data[0];
    nlen = pcb.chap_client.name.length();
    std::copy(pcb.chap_client.name.begin(),
              pcb.chap_client.name.end(),
              p.data.begin() + clen + 1);
    index += PPP_HDRLEN;
    len = CHAP_HDR_LEN + clen + 1 + nlen;
    p.data[index + 0] = CHAP_RESPONSE;
    p.data[index + 1] = id;
    p.data[index + 2] = len >> 8;
    p.data[index + 3] = len;
    return ppp_write(pcb, p);
}


/**
 *
 */
bool
chap_handle_status(PppPcb& pcb,
                   int code,
                   int id,
                   std::vector<uint8_t>& pkt)
{
    std::string msg;
    bool ok = false;


    auto flags = pcb.chap_client.flags;
    if (pcb.chap_client.flags.auth_started && pcb.chap_client.flags.lower_up) {
        return false;
    }

    pcb.chap_client.flags.auth_done = true;

    if (code == CHAP_SUCCESS)
    {
        /* used for MS-CHAP v2 mutual auth, yuck */
        // todo: call check_success method by digest type
        // if (pcb.chap_client.digest->check_success != nullptr)
        // {
        //     if (!(*pcb.chap_client.digest->check_success)(pcb, pkt, len, pcb.chap_client.priv))
        //     {
        //         code = CHAP_FAILURE;
        //     }
        // }
        // else
        // {
        //     msg = "CHAP authentication succeeded";
        // }
    }
    else
    {
        // todo: call handle_failure method by digest type
        // if (pcb.chap_client.digest->handle_failure != nullptr)
        //     (*pcb.chap_client.digest->handle_failure)(pcb, pkt, len);
        // else
        //     msg = "CHAP authentication failed";
    }
    if (msg.empty() == false)
    {
        if (!pkt.empty())
        {
            //spdlog::info("{}: {}", msg, pkt.size(), pkt);
        }
        else
        {
            ppp_info("%s", msg);
        }
    }
    if (code == CHAP_SUCCESS)
    {
        // todo: include digest code from somewhere
        // auth_withpeer_success(pcb, PPP_CHAP, pcb.chap_client.digest->code);
    }
    else
    {
        pcb.chap_client.flags.auth_failed = true;
        spdlog::error("CHAP authentication failed");
        ok = auth_withpeer_fail(pcb, PPP_CHAP);
    }

    return ok;
}


bool
chap_input(PppPcb& pcb, std::vector<uint8_t>& pkt)
{
    unsigned char code;
    unsigned char id;
    size_t len;
    size_t index = 0;
    bool ok;
    if (pkt.size() < CHAP_HDR_LEN)
    {
        return false;
    }
    std::tie(ok, code) = GETCHAR(pkt, index);
    if (!ok) { return false; }

    std::tie(ok, id) = GETCHAR(pkt, index);
    if (!ok) {return false;}

    std::tie(ok, len) = GETSHORT(pkt, index);
    if (len < CHAP_HDR_LEN || len > pkt.size()) { return false; }
    len -= CHAP_HDR_LEN;

    switch (code)
    {
    case CHAP_CHALLENGE:
        chap_respond(pcb, id, pkt);
        break;

    case CHAP_RESPONSE:
        chap_handle_response(pcb, id, pkt);
        break;

    case CHAP_FAILURE:
    case CHAP_SUCCESS:
        chap_handle_status(pcb, code, id, pkt);
        break;
    default:
        break;
    }
}


bool
chap_protrej(PppPcb& pcb)
{
    if (pcb.chap_server.flags.timeout_pending) {
        pcb.chap_server.flags.timeout_pending = false;
        // todo: un-schedule timeout
        //Untimeout(chap_timeout, pcb);
    }
    if (pcb.chap_server.flags.auth_started) {
        // todo: clear chap server flags;
        // pcb.chap_server.flags = 0;
        auth_peer_fail(pcb, PPP_CHAP);
    }
    if ((pcb.chap_client.flags.auth_started)) {
        pcb.chap_client.flags.auth_started = false;
        ppp_error("CHAP authentication failed due to protocol-reject");
        auth_withpeer_fail(pcb, PPP_CHAP);
    }

    return true;
}

//
// END OF FILE
//
