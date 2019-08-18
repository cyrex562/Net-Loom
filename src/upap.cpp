/**
 * file: upap.cpp
 * User/Password Authentication Protocol
 */
#include <upap.h>


/**
 * Initialize a UPAP unit.
 */
std::tuple<bool, upap_state>
upap_init(PppPcb& pcb)
{
    upap_state upap;
    upap.us_clientstate = UPAPCS_INITIAL;
    upap.us_serverstate = UPAPSS_INITIAL;
    upap.us_id = 0;
    return std::make_tuple(true, upap);
} /**
 * upap_authwithpeer - Authenticate us with our peer (start client).
 *
 * Set new state and send authenticate's.
 */
bool
upap_authwithpeer(PppPcb& pcb, std::string& user, std::string& password, upap_state& upap)
{
    if (user.empty() || password.empty()) {
        return false;
    } /* Save the username and password we're given */
    upap.us_user = user;
    upap.us_passwd = password;
    upap.us_transmits = 0; /* Lower layer up yet? */
    if (upap.us_clientstate == UPAPCS_INITIAL || upap.us_clientstate == UPAPCS_PENDING) {
        upap.us_clientstate = UPAPCS_PENDING;
        return false;
    }
    return upap_sauthreq(pcb, upap); /* Start protocol */
} /**
 * upap_authpeer - Authenticate our peer (start server).
 *
 * Set new state.
 */
bool
upap_authpeer(PppPcb& pcb, upap_state& upap)
{
    /* Lower layer up yet? */
    if (pcb.upap.us_serverstate == UPAPSS_INITIAL || pcb.upap.us_serverstate ==
        UPAPSS_PENDING) {
        pcb.upap.us_serverstate = UPAPSS_PENDING;
        return false;
    }
    pcb.upap.us_serverstate = UPAPSS_LISTEN;
    if (pcb.settings.pap_req_timeout > 0) {
        if (!upap_reqtimeout(pcb, upap)) {
            return false;
        }
    }
    return true;
} /**
 * Retransmission timer for sending auth-reqs expired.
 */
bool
upap_timeout(upap_state& upap, PppPcb& pcb)
{
    if (upap.us_clientstate != UPAPCS_AUTHREQ) return false;
    if (upap.us_transmits >= pcb.settings.pap_max_transmits) {
        /* give up in disgust */
        ppp_error("No response to PAP authenticate-requests");
        upap.us_clientstate = UPAPCS_BADAUTH;
        auth_withpeer_fail(pcb, PPP_PAP);
        return false;
    } /* Send Authenticate-Request */
    return upap_sauthreq(pcb, upap);
} /**
 * Give up waiting for the peer to send an auth-req.
 */
bool
upap_reqtimeout(PppPcb& pcb, upap_state& upap)
{
    if (upap.us_serverstate != UPAPSS_LISTEN) {
        return false; /* huh?? */
    }
    if (!auth_peer_fail(pcb, PPP_PAP)) {
        return false;
    }
    upap.us_serverstate = UPAPSS_BADAUTH;
    return true;
} /**
 * The lower layer is up. Start authenticating if pending.
 */
bool
upap_lowerup(PppPcb& pcb, upap_state& upap)
{
    if (upap.us_clientstate == UPAPCS_INITIAL) upap.us_clientstate = UPAPCS_CLOSED;
    else if (upap.us_clientstate == UPAPCS_PENDING) {
        if (!upap_sauthreq(pcb, upap)) {
            return false;
        }
    } /* send an auth-request */
    if (upap.us_serverstate == UPAPSS_INITIAL) upap.us_serverstate = UPAPSS_CLOSED;
    else if (upap.us_serverstate == UPAPSS_PENDING) {
        upap.us_serverstate = UPAPSS_LISTEN;
        if (pcb.settings.pap_req_timeout > 0) {
            if (!upap_reqtimeout(pcb, upap)) {
                return false;
            }
        }
    }
    return true;
}

/**
 * upap_lowerdown - The lower layer is down.
 *
 * Cancel all timeouts.
 */
bool
upap_lowerdown(PppPcb& pcb, upap_state& upap)
{
    if (upap.us_clientstate == UPAPCS_AUTHREQ) {
        if (!upap_timeout(upap, pcb)) {
            return false;
        }
    }
    if (upap.us_serverstate == UPAPSS_LISTEN && pcb.settings.pap_req_timeout > 0) {
        if (!upap_reqtimeout(pcb, upap)) {
            return false;
        }
    }
    upap.us_clientstate = UPAPCS_INITIAL;
    upap.us_serverstate = UPAPSS_INITIAL;
    return true;
}


/**
 * upap_protrej - Peer doesn't speak this protocol.
 *
 * This shouldn't happen.  In any case, pretend lower layer went down.
 */
bool
upap_proto_rejected(PppPcb& pcb, upap_state& upap)
{
    if (upap.us_clientstate == UPAPCS_AUTHREQ) {
        ppp_error("PAP authentication failed due to protocol-reject");
        auth_withpeer_fail(pcb, PPP_PAP);
    }
    if (upap.us_serverstate == UPAPSS_LISTEN) {
        ppp_error("PAP authentication of peer failed (protocol-reject)");
        auth_peer_fail(pcb, PPP_PAP);
    }
    return upap_lowerdown(pcb, upap);
}

/**
 * Input UPAP packet.
 */
bool
upap_input(PppPcb& pcb, std::vector<uint8_t>& in_packet, upap_state& upap)
{
    /*
     * Parse header (code, id and length).
     * If packet too short, drop it.
     */
    if (in_packet.size() < UPAP_HEADERLEN) {
        return false;
    }

    size_t index = 0;
    const auto code = GETCHAR(in_packet, index);
    auto id = GETCHAR(in_packet, index);
    auto len = GETSHORT(in_packet, index);
    if (len < UPAP_HEADERLEN) {
        return false;
    }
    if (len > in_packet.data.size()) {
        return false;
    }
    len -= UPAP_HEADERLEN;
    /*
     * Action depends on code.
     */
    if (code == UPAP_AUTHREQ) {
        return upap_recv_auth_req(pcb, in_packet, id, upap);
    }
    if (code == UPAP_AUTHACK) {
        return upap_rcv_auth_ack(pcb, in_packet, id, upap);
    }
    if (code == UPAP_AUTHNAK) {
        return upap_rauthnak(pcb, in_packet, id, upap);
    }
    return false;
    // todo: handle other cases
}

/*
 * upap_rauth - Receive Authenticate.
 */
bool
upap_recv_auth_req(PppPcb& pcb, std::vector<uint8_t>& in_pkt, const int id, upap_state& upap)
{
    std::string msg;
    size_t msglen;
    if (upap.us_serverstate < UPAPSS_LISTEN) {
        return false;
    }
    /*
     * If we receive a duplicate authenticate-request, we are
     * supposed to return the same status as for the first request.
     */
    std::string empty_str;;

    if (upap.us_serverstate == UPAPSS_OPEN) {
        upap_sresp(pcb, UPAP_AUTHACK, id, empty_str); /* return auth-ack */
        return false;
    }

    if (upap.us_serverstate == UPAPSS_BADAUTH) {
        upap_sresp(pcb, UPAP_AUTHNAK, id, empty_str); /* return auth-nak */
        return false;
    }

    /*
     * Parse user/passwd.
     */
    if (in_pkt.empty()) {
        return false;
    }

    size_t index = 0;
    const size_t remote_user_len = GETCHAR(in_pkt, index);
    int tracked_len = in_pkt.size();
    const auto req_len = sizeof(uint8_t) + remote_user_len + sizeof(uint8_t);
    tracked_len -= sizeof(uint8_t) + remote_user_len + sizeof(uint8_t);

    if (req_len > in_pkt.size()) {
        return false;
    }

    std::string ruser = reinterpret_cast<char *>(in_pkt.data()) + index;
    index += remote_user_len;
    const size_t rpasswdlen = GETCHAR(in_pkt, index);
    if (in_pkt.size() < rpasswdlen) {
        return false;
    }
    std::string rpasswd = (char *)in_pkt.data() + index;

    /**
     * Check the username and password given.
     */
    int retcode = UPAP_AUTHNAK;
    if (auth_check_passwd(pcb, ruser, rpasswd, msg)) {
        retcode = UPAP_AUTHACK;
    }

    // BZERO(rpasswd, rpasswdlen);
    if (!upap_sresp(pcb, retcode, id, msg)) { return false; }

    const std::string rhostname = ruser;
    if (retcode == UPAP_AUTHACK) {
        upap.us_serverstate = UPAPSS_OPEN;
        ppp_notice("PAP peer authentication succeeded for %q", rhostname);
        return auth_peer_success(pcb, PPP_PAP, 0, ruser);
    }
    upap.us_serverstate = UPAPSS_BADAUTH;
    ppp_warn("PAP peer authentication failed for %q", rhostname);

    auth_peer_fail(pcb, PPP_PAP);


    if (pcb.settings.pap_req_timeout > 0) {
        upap_reqtimeout(pcb, upap);
    }
}

/**
 * upap_rauthack - Receive Authenticate-Ack.
 */
bool
upap_rcv_auth_ack(PppPcb& pcb, std::vector<uint8_t>& in_pkt, int id, upap_state& upap)
{
    size_t index = 0;
    if (upap.us_clientstate != UPAPCS_AUTHREQ) {
        /* XXX */
        return false;
    }
    /*
     * Parse message.
     */
    if (in_pkt.empty()) {
        // UPAPDEBUG(("pap_rauthack: ignoring missing msg-length."));
    }
    else {
        const uint8_t msglen = GETCHAR(in_pkt, index);
        if (msglen > 0) {
            if (in_pkt.size() - 1 < msglen) {
                return false;
            }
            auto msg = reinterpret_cast<char *>(in_pkt.data()) + index;
            // PRINTMSG(msg, msglen);
        }
    }
    upap.us_clientstate = UPAPCS_OPEN;
    return auth_withpeer_success(pcb, PPP_PAP, 0);
}

/*
 * upap_rauthnak - Receive Authenticate-Nak.
 */
bool
upap_rauthnak(PppPcb& pcb, std::vector<uint8_t>& in_pkt, int id, upap_state& upap)
{
    if (upap.us_clientstate != UPAPCS_AUTHREQ) {
        /* XXX */
        return false;
    }

    /*
     * Parse message.
     */
    if (in_pkt.empty()) {
        return false;
    }
    size_t index = 0;
    const auto msglen = GETCHAR(in_pkt, index);
    if (msglen > 0) {
        if (in_pkt.size() - 1 < msglen) {
            return false;
        }
        const auto msg = reinterpret_cast<char *>(in_pkt.data()) + index;
        PRINTMSG(msg, msglen);
    }
    upap.us_clientstate = UPAPCS_BADAUTH;
    ppp_error("PAP authentication failed");
    return auth_withpeer_fail(pcb, PPP_PAP);
}

/**
 * Send an Authenticate-Request.
 */
bool
upap_sauthreq(PppPcb& pcb, upap_state& upap)
{
    const size_t out_len = UPAP_HEADERLEN + 2 * sizeof(uint8_t) + upap.us_user.length() +
        upap.us_passwd.length(); // todo: re-write not to overflow the buffer
    PacketBuffer p{};
    auto outp = p.data;
    MAKEHEADER(outp, PPP_PAP);
    PUTCHAR((uint8_t)UPAP_AUTHREQ, outp);
    PUTCHAR(upap.us_id, outp);
    PUTSHORT((uint16_t)out_len, outp);
    PUTCHAR(upap.us_user.length(), outp);
    PUTSTRING(upap.us_user, outp);
    PUTCHAR(upap.us_passwd.size(), outp);
    PUTSTRING(upap.us_passwd, outp);
    ppp_write(pcb, p); // Timeout(upap_timeout, pcb, pcb->settings.pap_timeout_time);
    ++upap.us_transmits;
    upap.us_clientstate = UPAPCS_AUTHREQ;
}

/**
 * Send a response (ack or nak).
 */
bool
upap_sresp(PppPcb& pcb, const uint8_t code, const uint8_t id, std::string& msg)
{
    const size_t outlen = UPAP_HEADERLEN + sizeof(uint8_t) + msg.length();
    PacketBuffer p{};
    MAKEHEADER(p.data, PPP_PAP);
    PUTCHAR(code, p.data);
    PUTCHAR(id, p.data);
    PUTSHORT(outlen, p.data);
    PUTCHAR(msg.length(), p.data);
    PUTSTRING(msg, p.data);
    return ppp_write(pcb, p);
}

//
// EOF
//