/*
 * auth.c - PPP authentication and phase control.
 *
 * Copyright (c) 1993-2002 Paul Mackerras. All rights reserved.
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
 *
 * Derived from main.c, which is:
 *
 * Copyright (c) 1984-2000 Carnegie Mellon University. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "ppp_opts.h"
#include "ppp_impl.h"
#include "fsm.h"
#include "lcp.h"
#include "ccp.h"
#include "ecp.h"
#include "ipcp.h"
#include "upap.h"
#include "chap-new.h"
#include "eap.h"

/* Hook for plugin to hear when an interface joins a multilink bundle */
void (*multilink_join_hook)(void) = nullptr;

static void network_phase(PppPcb* pcb, Protent** protocols);
static void check_idle(void* arg);
static void connect_time_expired(void* arg);
// static void check_maxoctets(void*);

/*
 * An Open on LCP has requested a change from Dead to Establish phase.
 */
void link_required(PppPcb* pcb)
{
    LWIP_UNUSED_ARG(pcb);
}

/*
 * LCP has terminated the link; go to the Dead phase and take the
 * physical layer down.
 */
void link_terminated(PppPcb* pcb)
{
    if (pcb->phase == PPP_PHASE_DEAD
        || pcb->phase == PPP_PHASE_MASTER
    )
        return;
    new_phase(pcb, PPP_PHASE_DISCONNECT);

    if (!doing_multilink)
    {
        ppp_notice("Connection terminated.");
    }
    else
        ppp_notice("Link terminated.");

    lcp_lowerdown(pcb);

    ppp_link_terminated(pcb);
}

/*
 * LCP has gone down; it will either die or try to re-establish.
 */
void link_down(PppPcb* pcb, Protent** protocols)
{
    // notify(link_down_notifier, 0);
    if (!doing_multilink)
    {
        upper_layers_down(pcb, protocols);
        if (pcb->phase != PPP_PHASE_DEAD && pcb->phase != PPP_PHASE_MASTER)
        {
            new_phase(pcb, PPP_PHASE_ESTABLISH);
        }
    }
    /* XXX if doing_multilink, should do something to stop
       network-layer traffic on the link */
}

void upper_layers_down(PppPcb* pcb, Protent** protocols)
{
    const struct Protent* protp;

    for (auto i = 0; (protp = protocols[i]) != nullptr; ++i)
    {
        if (protp->protocol != PPP_LCP && protp->lowerdown != nullptr)
            (*protp->lowerdown)(pcb);
        if (protp->protocol < 0xC000 && protp->close != nullptr)
            (*protp->close)(pcb, "LCP down");
    }
    pcb->num_np_open = 0;
    pcb->num_np_up = 0;
}

/*
 * The link is established.
 * Proceed to the Dead, Authenticate or Network phase as appropriate.
 */
void link_established(PppPcb* pcb, Protent** protocols, bool auth_required)
{
    auto wo = &pcb->lcp_wantoptions;
    auto go = &pcb->lcp_gotoptions;
    auto ho = &pcb->lcp_hisoptions;
    const struct Protent* protp;

    /*
     * Tell higher-level protocols that LCP is up.
     */
    if (!doing_multilink)
    {
        for (auto i = 0; (protp = protocols[i]) != nullptr; ++i)
            if (protp->protocol != PPP_LCP
                && protp->lowerup != nullptr)
                (*protp->lowerup)(pcb);
    }


    // if (!auth_required)
    //     set_allowed_addrs(unit, NULL, NULL);


    if (pcb->settings.auth_required && !(0 || go->neg_upap || go->neg_chap || go->neg_eap))
    {
        /*
         * We wanted the peer to authenticate itself, and it refused:
         * if we have some address(es) it can use without auth, fine,
         * otherwise treat it as though it authenticated with PAP using
         * a username of "" and a password of "".  If that's not OK,
         * boot it out.
         */
        // if (noauth_addrs != NULL)
        // {
        //     set_allowed_addrs(unit, NULL, NULL);
        // }
        if (!pcb->settings.null_login

            || !wo->neg_upap

        )
        {
            ppp_warn("peer refused to authenticate: terminating link");
            pcb->err_code = PPPERR_AUTHFAIL;
            lcp_close(pcb, "peer refused to authenticate");
            return;
        }
    }


    new_phase(pcb, PPP_PHASE_AUTHENTICATE);
    auto auth = 0;

    if (go->neg_eap)
    {
        eap_authpeer(pcb, PPP_OUR_NAME);
        auth |= EAP_PEER;
    }
    else if (go->neg_chap)
    {
        chap_auth_peer(pcb, PPP_OUR_NAME, CHAP_DIGEST(go->chap_mdtype));
        auth |= CHAP_PEER;
    }
    else if (go->neg_upap)
    {
        upap_authpeer(pcb);
        auth |= PAP_PEER;
    }
    else

    {
    }


    if (ho->neg_eap)
    {
        eap_authwithpeer(pcb, pcb->settings.user);
        auth |= EAP_WITHPEER;
    }
    else if (ho->neg_chap)
    {
        chap_auth_with_peer(pcb, pcb->settings.user, CHAP_DIGEST(ho->chap_mdtype));
        auth |= CHAP_WITHPEER;
    }
    else if (ho->neg_upap)
    {
        upap_authwithpeer(pcb, pcb->settings.user, pcb->settings.passwd);
        auth |= PAP_WITHPEER;
    }
    else

    {
    }

    pcb->auth_pending = auth;
    pcb->auth_done = 0;

    if (!auth)
        network_phase(pcb, protocols);
}

/*
 * Proceed to the network phase.
 */
static void network_phase(PppPcb* pcb, Protent** protocols)
{
    start_networks(pcb, protocols);
}

void start_networks(PppPcb* pcb, Protent** protocols)
{
    const struct Protent* protp;

    new_phase(pcb, PPP_PHASE_NETWORK);

    if (multilink)
    {
        if (mp_join_bundle())
        {
            if (multilink_join_hook)
                (*multilink_join_hook)();
            // if (updetach && !nodetach)
            //     detach();
            return;
        }
    }


    // if (!demand)
    //     set_filters(&pass_filter, &active_filter);

    /* Start CCP and ECP */
    for (auto i = 0; (protp = protocols[i]) != nullptr; ++i)
        if (
            (0

                || protp->protocol == PPP_ECP

                || protp->protocol == PPP_CCP

            )
            && protp->open != nullptr)
            (*protp->open)(pcb);


    /*
     * Bring up other network protocols iff encryption is not required.
     */
    if (!ecp_gotoptions[0].required && !pcb->ccp_gotoptions.mppe)
        continue_networks(pcb, protocols);
}

void continue_networks(PppPcb* pcb, Protent** protocols)
{
    const struct Protent* protp;

    // Start the "real" network protocols.
    for (auto i = 0; (protp = protocols[i]) != nullptr; ++i)
        if (protp->protocol < 0xC000
            && protp->protocol != PPP_CCP
            && protp->protocol != PPP_ECP
            && protp->open != nullptr)
        {
            (*protp->open)(pcb);
            ++pcb->num_np_open;
        }

    if (pcb->num_np_open == 0)
        /* nothing to do */
        lcp_close(pcb, "No network protocols running");
}

/*
 * auth_check_passwd - Check the user name and passwd against configuration.
 *
 * returns:
 *      0: Authentication failed.
 *      1: Authentication succeeded.
 * In either case, msg points to an appropriate message and msglen to the message len.
 */
int auth_check_passwd(PppPcb *pcb, char *auser, int userlen, char *apasswd, int passwdlen, const char **msg, int *msglen) {
  int secretuserlen;
  int secretpasswdlen;

  if (pcb->settings.user && pcb->settings.passwd) {
    secretuserlen = (int)strlen(pcb->settings.user);
    secretpasswdlen = (int)strlen(pcb->settings.passwd);
    if (secretuserlen == userlen
        && secretpasswdlen == passwdlen
        && !memcmp(auser, pcb->settings.user, userlen)
        && !memcmp(apasswd, pcb->settings.passwd, passwdlen) ) {
      *msg = "Login ok";
      *msglen = sizeof("Login ok")-1;
      return 1;
    }
  }

  *msg = "Login incorrect";
  *msglen = sizeof("Login incorrect")-1;
  return 0;
}

/*
 * The peer has failed to authenticate himself using `protocol'.
 */
void auth_peer_fail(PppPcb *pcb, int protocol) {
    LWIP_UNUSED_ARG(protocol);
    /*
     * Authentication failure: take the link down
     */

    pcb->err_code = PPPERR_AUTHFAIL;
    lcp_close(pcb, "Authentication failed");
}

/*
 * The peer has been successfully authenticated using `protocol'.
 */
void auth_peer_success(PppPcb *pcb, int protocol, int prot_flavor, const char *name, int namelen, Protent** protocols) {
    int bit;

    switch (protocol) {
    case PPP_CHAP:
	bit = CHAP_PEER;
	switch (prot_flavor) {
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

    /*
     * Save the authenticated name of the peer for later.
     */
    if (namelen > (int)sizeof(pcb->peer_authname) - 1)
	namelen = (int)sizeof(pcb->peer_authname) - 1;
    MEMCPY(pcb->peer_authname, name, namelen);
    pcb->peer_authname[namelen] = 0;


    /* Save the authentication method for later. */
    pcb->auth_done |= bit;

    /*
     * If there is no more authentication still to be done,
     * proceed to the network (or callback) phase.
     */
    if ((pcb->auth_pending &= ~bit) == 0)
        network_phase(pcb, protocols);
}

/*
 * We have failed to authenticate ourselves to the peer using `protocol'.
 */
void auth_withpeer_fail(PppPcb* pcb, int protocol)
{
    LWIP_UNUSED_ARG(protocol);
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
    pcb->err_code = PPPERR_AUTHFAIL;
    lcp_close(pcb, "Failed to authenticate ourselves to peer");
}

/*
 * We have successfully authenticated ourselves with the peer using `protocol'.
 */
void auth_withpeer_success(PppPcb* pcb, int protocol, int prot_flavor, Protent** protocols)
{
    int bit;
    const char* prot = "";

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
    pcb->auth_done |= bit;

    /*
     * If there is no more authentication still being done,
     * proceed to the network (or callback) phase.
     */
    if ((pcb->auth_pending &= ~bit) == 0)
        network_phase(pcb, protocols);
}



/*
 * np_up - a network protocol has come up.
 */
void np_up(PppPcb* pcb, int proto)
{
    int tlim;

    if (pcb->num_np_up == 0)
    {
        /*
         * At this point we consider that the link has come up successfully.
         */
        new_phase(pcb, PPP_PHASE_RUNNING);



	    tlim = pcb->settings.idle_time_limit;
	if (tlim > 0)
	    TIMEOUT(check_idle, (void*)pcb, tlim);



	/*
	 * Set a timeout to close the connection once the maximum
	 * connect time has expired.
	 */
	if (pcb->settings.maxconnect > 0)
	    TIMEOUT(connect_time_expired, (void*)pcb, pcb->settings.maxconnect);


	if (maxoctets > 0)
	    TIMEOUT(check_maxoctets, NULL, maxoctets_timeout);


    }
    ++pcb->num_np_up;
}

/*
 * np_down - a network protocol has gone down.
 */
void np_down(PppPcb* pcb, int proto)
{
    LWIP_UNUSED_ARG(proto);
    if (--pcb->num_np_up == 0)
    {

	UNTIMEOUT(check_idle, (void*)pcb);


	UNTIMEOUT(connect_time_expired, NULL);


	UNTIMEOUT(check_maxoctets, NULL);

        new_phase(pcb, PPP_PHASE_NETWORK);
    }
}

/*
 * np_finished - a network protocol has finished using the link.
 */
void np_finished(PppPcb* pcb, int proto)
{
    LWIP_UNUSED_ARG(proto);
    if (--pcb->num_np_open <= 0)
    {
        /* no further use for the link: shut up shop. */
        lcp_close(pcb, "No network protocols running");
    }
}



/*
 * check_idle - check whether the link has been idle for long
 * enough that we can shut it down.
 */
static void check_idle(void *arg) {
    PppPcb *pcb = (PppPcb*)arg;
    // struct ppp_idle idle;
    time_t itime;
    int tlim;

    // if (!get_idle_time(pcb, &idle))
	// return;

	// itime = LWIP_MIN(idle.xmit_idle, idle.recv_idle);
	// tlim = pcb->settings.idle_time_limit - itime;

    if (tlim <= 0) {
	/* link is idle: shut it down. */
	ppp_notice("Terminating connection due to lack of activity.");
	pcb->err_code = PPPERR_IDLETIMEOUT;
	lcp_close(pcb, "Link inactive");
#if 0 /* UNUSED */
	need_holdoff = 0;
#endif /* UNUSED */
    } else {
	TIMEOUT(check_idle, (void*)pcb, tlim);
    }
}



/*
 * connect_time_expired - log a message and close the connection.
 */
static void connect_time_expired(void *arg) {
    PppPcb *pcb = (PppPcb*)arg;
    ppp_info("Connect time expired");
    pcb->err_code = PPPERR_CONNECTTIME;
    lcp_close(pcb, "Connect time expired");	/* Close connection */
}




/*
 * get_secret - open the CHAP secret file and return the secret
 * for authenticating the given client on the given server.
 * (We could be either client or server).
 */
int get_secret(PppPcb* pcb, const char* client, const char* server, char* secret, int* secret_len, int am_server)
{
    int len;
    LWIP_UNUSED_ARG(server);
    LWIP_UNUSED_ARG(am_server);

    if (!client || !client[0] || !pcb->settings.user || !pcb->settings.passwd || strcmp(client, pcb->settings.user))
    {
        return 0;
    }

    len = (int)strlen(pcb->settings.passwd);
    if (len > MAXSECRETLEN)
    {
        ppp_error("Secret for %s on %s is too long", client, server);
        len = MAXSECRETLEN;
    }

    MEMCPY(secret, pcb->settings.passwd, len);
    *secret_len = len;
    return 1;
}

