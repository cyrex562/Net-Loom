//
// auth.h: PPP authentication code header file.
//
//

#pragma once
#include <string>
#include "ppp_upap_state.h"
#include "ppp_chap_new.h"
#include "ppp_def.h"
// struct Protent;

struct PppPcb;

bool
auth_withpeer_fail(PppPcb& pcb, int protocol);

bool start_networks(PppPcb& pcb, const bool multilink = true);

static bool enter_network_phase(PppPcb& pcb);

bool
check_idle(PppPcb& pcb);

bool connect_time_expired(PppPcb& pcb); // static void check_maxoctets(void*);

bool link_required(PppPcb* pcb);

bool upper_layers_down(PppPcb& pcb);

bool continue_networks(PppPcb& pcb);

bool link_established(PppPcb& pcb, UpapState& state, const bool auth_required);

bool
link_terminated(PppPcb& pcb, const bool doing_multilink);

bool
link_down(PppPcb& pcb, const bool doing_multilink);


bool
auth_check_passwd(PppPcb& pcb, std::string& auser, std::string& apasswd, std::string& msg);

bool
auth_peer_fail(PppPcb& pcb, int protocol);

bool
auth_peer_success(PppPcb& pcb,
                  PppProtoFieldValue protocol,
                  ChapDigestCode prot_flavor,
                  std::string& name);

bool
np_up(PppPcb& pcb, int proto);

bool
np_down(PppPcb& pcb, int proto);

void np_finished(PppPcb& pcb, int proto);

bool
get_secret(PppPcb& pcb, std::string& client, std::string& server, std::string& secret);

bool
auth_withpeer_success(PppPcb& pcb, int protocol, int prot_flavor);

//
// END OF FILE
//