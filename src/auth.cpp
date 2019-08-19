
#define NOMINMAX

#include <ppp_opts.h>
#include <auth.h>
#include <ccp.h>
#include <chap_new.h>
#include <eap.h>
#include <ecp.h>
#include <lcp.h>
#include <upap.h>
#include <ppp.h>
#include <string>

/* Hook for plugin to hear when an interface joins a multilink bundle */
void (*multilink_join_hook)() = nullptr;



/**
 * An Open on LCP has requested a change from Dead to Establish phase.
 */
bool link_required(PppPcb* pcb)
{
    return false;
}

/**
 * LCP has terminated the link; go to the Dead phase and take the
 * physical layer down.
 */
bool
link_terminated(PppPcb& pcb, const bool doing_multilink)
{
    auto ok = true;
    if (pcb.phase == PPP_PHASE_DEAD || pcb.phase == PPP_PHASE_MASTER) {
        return false;
    }
    new_phase(pcb, PPP_PHASE_DISCONNECT);
    if (!doing_multilink) {
        ppp_notice("Connection terminated.");
    }
    else {
        ppp_notice("Link terminated.");
    }
    if (! lcp_lowerdown(pcb)) {
        return false;
    }
    if (! ppp_link_terminated(pcb)) {
        return false;
    }
    return true;
}

/**
 * LCP has gone down; it will either die or try to re-establish.
 */
bool
link_down(PppPcb& pcb, const bool doing_multilink)
{
    // notify(link_down_notifier, 0);
    if (!doing_multilink)
    {
        upper_layers_down(pcb);
        if (pcb.phase != PPP_PHASE_DEAD && pcb.phase != PPP_PHASE_MASTER)
        {
            new_phase(pcb, PPP_PHASE_ESTABLISH);
        }
    }
    /* XXX if doing_multilink, should do something to stop
       network-layer traffic on the link */
}

bool upper_layers_down(PppPcb& pcb)
{
    // TODO: figure out which lower layer protocols to call/signal for lowerdown()/close()
    return false;

    // for (auto i = 0; (protp = protocols[i]) != nullptr; ++i)
    // {
    //     if (protp->protocol != PPP_LCP && protp->lowerdown != nullptr)
    //         (*protp->lowerdown)(pcb);
    //     if (protp->protocol < 0xC000 && protp->close != nullptr)
    //         (*protp->close)(pcb, "LCP down");
    // }
    // pcb->num_np_open = 0;
    // pcb->num_np_up = 0;
    return false; // not implemented
}

/*
 * The link is established.
 * Proceed to the Dead, Authenticate or Network phase as appropriate.
 */
bool link_established(PppPcb& pcb, upap_state& state, const bool auth_required = false)
{
    auto wo = pcb.lcp_wantoptions;
    auto go = pcb.lcp_gotoptions;
    auto ho = pcb.lcp_hisoptions;

    // const struct Protent* protp; /*
    // TODO: send notification that LCP is up
    // if (!doing_multilink)
    // {
    //     for (auto i = 0; (protp = protocols[i]) != nullptr; ++i)
    //         if (protp->protocol != PPP_LCP
    //             && protp->lowerup != nullptr)
    //             (*protp->lowerup)(pcb);
    // }

    // if (!auth_required)
    //     set_allowed_addrs(unit, NULL, NULL);
    if (pcb.settings.auth_required && !(go.neg_upap || go.neg_chap || go.neg_eap))
    {
        /*
         * We wanted the peer to authenticate itself, and it refused:
         * if we have some address(es) it can use without auth, fine,
         * otherwise treat it as though it authenticated with PAP using
         * a username of "" and a password of "".  If that's not OK,
         * boot it out.
         */
        if (!pcb.settings.null_login || !wo.neg_upap)
        {
            ppp_warn("peer refused to authenticate: terminating link");
            pcb.err_code = PPPERR_AUTHFAIL;
            std::string reason = "peer refused to authenticate";
            // todo: check output of lcp_close
            lcp_close(pcb, reason);
            return false;
        }
    }
    new_phase(pcb, PPP_PHASE_AUTHENTICATE);
    auto auth = 0;
    if (go.neg_eap)
    {
        std::string our_name = PPP_OUR_NAME;
        eap_authpeer(pcb,our_name);
        auth |= EAP_PEER;
    }
    else if (go.neg_chap)
    {
        std::string our_name = PPP_OUR_NAME;
        chap_auth_peer(pcb, our_name, CHAP_DIGEST(go.chap_mdtype));
        auth |= CHAP_PEER;
    }
    else if (go.neg_upap)
    {
        upap_authpeer(pcb, state);
        auth |= PAP_PEER;
    }
    else
    {
    }
    if (ho.neg_eap)
    {
        eap_authwithpeer(pcb);
        auth |= EAP_WITHPEER;
    }
    else if (ho.neg_chap)
    {
        chap_auth_with_peer(pcb, pcb.settings.user, CHAP_DIGEST(ho.chap_mdtype),);
        auth |= CHAP_WITHPEER;
    }
    else if (ho.neg_upap)
    {
        upap_authwithpeer(pcb, pcb.settings.user, pcb.settings.passwd,);
        auth |= PAP_WITHPEER;
    }
    else
    {
    }
    pcb.auth_pending = auth;
    pcb.auth_done = 0;
    if (!auth)
    {
        enter_network_phase(pcb);
    }
    return true;
}

//
// Enter the network phase
//
bool enter_network_phase(PppPcb& pcb)
{
    return start_networks(pcb);
}

//
// Start networks?
//
bool start_networks(PppPcb* pcb, const bool multilink)
{
    new_phase(pcb, PPP_PHASE_NETWORK);
    if (multilink)
    {
        // TODO: figure out what bundle name should be used.
        std::string bundle_name = "bundle_name";
        if (mp_join_bundle(pcb, pcb->settings.remote_name, bundle_name))
        {
            if (multilink_join_hook != nullptr)
                (*multilink_join_hook)(); // if (updetach && !nodetach)
            //     detach();
            return false; // TODO: what should the return value be here?
        }
    } // if (!demand)
    //     set_filters(&pass_filter, &active_filter);
    // TODO: determine if we're using CCP and ECP
    bool start_ccp = true;
    bool start_ecp = true; // TODO: check bool result
    ccp_open(pcb); // TODO: check bool result
    int ecp_open_unit = 0;
    ecp_open(pcb, ecp_open_unit); /*
     * Bring up other network protocols iff encryption is not required.
     */
    if (!ecp_gotoptions[0].required && !pcb->ccp_gotoptions.mppe)
    {
        // TODO: check result
        continue_networks(pcb);
    }

    // TODO: update output result

    return true;
}

bool continue_networks(PppPcb* pcb)
{
    // TODO: determine which network protocols to start and start them.
    const auto none_started = true;

    // Start the "real" network protocols.
    // for (auto i = 0; (protp = protocols[i]) != nullptr; ++i)
    //     if (protp->protocol < 0xC000
    //         && protp->protocol != PPP_CCP
    //         && protp->protocol != PPP_ECP
    //         && protp->open != nullptr)
    //     {
    //         (*protp->open)(pcb);
    //         ++pcb->num_np_open;
    //     }

    // if (pcb->num_np_open == 0)
    //     /* nothing to do */
    //     lcp_close(pcb, "No network protocols running");

    if (none_started)
    {
        lcp_close(pcb, "no network protocols running");
        return false;
    }

    return true;
}

/**
 * Check the user name and passwd against configuration.
 *
 *  returns:
 *       0: Authentication failed.
 *       1: Authentication succeeded.
 * In either case, msg points to an appropriate message and msglen to the message len.
 */

bool
auth_check_passwd(PppPcb& pcb, std::string& auser, std::string& apasswd, std::string& msg)
{
    if (!pcb.settings.user.empty() && !pcb.settings.passwd.empty())
    {
        const auto secretuserlen = pcb.settings.user.length();
        const auto secretpasswdlen = pcb.settings.passwd.length();
        if (secretuserlen == auser.length() && secretpasswdlen == apasswd.length() &&
            auser == pcb.settings.user && apasswd == pcb.settings.passwd)
        {
            msg = "Login ok";
            return true;
        }
    }
    msg = "Login incorrect";
    return false;
}

/*
 * The peer has failed to authenticate himself using `protocol'.
 */
bool
auth_peer_fail(PppPcb& pcb, int protocol) {

    /*
     * Authentication failure: take the link down
     */
    pcb.err_code = PPPERR_AUTHFAIL;
    std::string reason = "Authentication failed.";
    return lcp_close(pcb, reason);
}

/*
 * The peer has been successfully authenticated using `protocol'.
 */
bool
auth_peer_success(PppPcb& pcb, int protocol, int prot_flavor, std::string& name)
{
    int bit;

    switch (protocol)
    {
    case PPP_CHAP:
        bit = CHAP_PEER;
        switch (prot_flavor)
        {
        case CHAP_MD5:
            bit |= CHAP_MD5_PEER;
            break;
        case CHAP_MICROSOFT:
            bit |= CHAP_MS_PEER;
            break;
        case CHAP_MICROSOFT_V2:
            bit |= CHAP_MS2_PEER;
            break;
        default:
            break;
        }
        break;
    case PPP_PAP:
        bit = PAP_PEER;
        break;
    case PPP_EAP:
        bit = EAP_PEER;
        break;
    default:
        ppp_warn("auth_peer_success: unknown protocol %x", protocol);
        return;
    }

    pcb->peer_authname = name;

    /* Save the authentication method for later. */
    pcb->auth_done |= bit;

    /*
     * If there is no more authentication still to be done,
     * proceed to the network (or callback) phase.
     */
    if ((pcb->auth_pending &= ~bit) == 0)
    {
        enter_network_phase(pcb);
    }
}

/**
 * We have failed to authenticate ourselves to the peer using `protocol'.
 */
bool
auth_withpeer_fail(PppPcb& pcb, int protocol)
{
    /*
     * We've failed to authenticate ourselves to our peer.
     *
     * Some servers keep sending CHAP challenges, but there
     * is no point in persisting without any way to get updated
     * authentication secrets.
     *
     * He'll probably take the link down, and there's not much
     * we can do except wait for that.
     */
    pcb.err_code = PPPERR_AUTHFAIL;
    std::string msg = "Failed to authenticate ourselves to peer";
    return lcp_close(pcb, msg);
}

/**
 * We have successfully authenticated ourselves with the peer using `protocol'.
 */
bool
auth_withpeer_success(PppPcb& pcb, int protocol, int prot_flavor)
{
    int bit;
    auto prot = "";

    switch (protocol)
    {
    case PPP_CHAP:
        bit = CHAP_WITHPEER;
        prot = "CHAP";
        switch (prot_flavor)
        {
        case CHAP_MD5:
            bit |= CHAP_MD5_WITHPEER;
            break;

        case CHAP_MICROSOFT:
            bit |= CHAP_MS_WITHPEER;
            break;
        case CHAP_MICROSOFT_V2:
            bit |= CHAP_MS2_WITHPEER;
            break;

        default:
            break;
        }
        break;

    case PPP_PAP:
        bit = PAP_WITHPEER;
        prot = "PAP";
        break;

    case PPP_EAP:
        bit = EAP_WITHPEER;
        prot = "EAP";
        break;

    default:
        ppp_warn("auth_withpeer_success: unknown protocol %x", protocol);
        bit = 0;
        /* no break */
    }

    ppp_notice("%s authentication succeeded", prot);

    /* Save the authentication method for later. */
    pcb.auth_done |= bit;

    /*
     * If there is no more authentication still being done,
     * proceed to the network (or callback) phase.
     */
    if ((pcb.auth_pending &= ~bit) == 0)
    {
        enter_network_phase(pcb);
    }
}



/*
 * np_up - a network protocol has come up.
 */
void np_up(PppPcb* pcb, int proto)
{
    if (pcb->num_np_up == 0)
    {
        /*
         * At this point we consider that the link has come up successfully.
         */
        new_phase(pcb, PPP_PHASE_RUNNING);
        const uint64_t tlim = pcb->settings.idle_time_limit;
    if (tlim > 0)
    {
        Timeout(check_idle, static_cast<void*>(pcb), tlim);
        } /*
     * Set a timeout to close the connection once the maximum
     * connect time has expired.
     */
    if (pcb->settings.maxconnect > 0)
    {
        Timeout(connect_time_expired, static_cast<void*>(pcb), pcb->settings.maxconnect);
        } // if (maxoctets > 0)
        // Timeout(check_maxoctets, NULL, maxoctets_timeout);


    }
    ++pcb->num_np_up;
}

/*
 * np_down - a network protocol has gone down.
 */
void np_down(PppPcb* pcb, int proto)
{

    if (--pcb->num_np_up == 0)
    {

    Untimeout(check_idle, static_cast<void*>(pcb));


    Untimeout(connect_time_expired, nullptr);


    // Untimeout(check_maxoctets, NULL);

        new_phase(pcb, PPP_PHASE_NETWORK);
    }
}

/*
 * np_finished - a network protocol has finished using the link.
 */
void np_finished(PppPcb* pcb, int proto)
{

    if (--pcb->num_np_open <= 0)
    {
        /* no further use for the link: shut up shop. */
        lcp_close(pcb, "No network protocols running");
    }
}



///
/// check_idle - check whether the link has been idle for long
/// enough that we can shut it down.
///
static void check_idle(void* arg) {
    const auto pcb = static_cast<PppPcb*>(arg);
    auto tlim = 0;

 //    if (!get_idle_time(pcb, &idle))
    // return;

    // itime = std::min(idle.xmit_idle, idle.recv_idle);
    // tlim = pcb->settings.idle_time_limit - itime;

    if (tlim <= 0) {
    /* link is idle: shut it down. */
    ppp_notice("Terminating connection due to lack of activity.");
    pcb->err_code = PPPERR_IDLETIMEOUT;
    lcp_close(pcb, "Link inactive");
    } else {
    Timeout(check_idle, static_cast<void*>(pcb), tlim);
    }
}


//
// connect_time_expired - log a message and close the connection.
//
static void connect_time_expired(void* arg)
{
    const auto pcb = static_cast<PppPcb*>(arg);
    ppp_info("Connect time expired");
    pcb->err_code = PPPERR_CONNECTTIME; /* Close connection */
    lcp_close(pcb, "Connect time expired");
}




/*
 * get_secret - open the CHAP secret file and return the secret
 * for authenticating the given client on the given server.
 * (We could be either client or server).
 */
bool
get_secret(PppPcb* pcb, std::string& client, std::string& server, std::string& secret)
{
    // if (!client || !client[0] || !pcb->settings.user || !pcb->settings.passwd || strcmp(client, pcb->settings.user))
    // {
    //     return 0;
    // }
    if (client != pcb->settings.user)
    {
        return false;
    }

    // auto len = strlen(pcb->settings.passwd);
    // if (len > MAXSECRETLEN)
    // {
    //     ppp_error("Secret for %s on %s is too long", client, server);
    //     len = MAXSECRETLEN;
    // }

    secret = pcb->settings.passwd;

    // memcpy(secret, pcb->settings.passwd, len);
    // *secret_len = len;
    return true;
}

//
// END OF FILE
//