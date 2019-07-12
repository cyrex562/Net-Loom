//
// auth.h: PPP authentication code header file.
// 
//

#pragma once
struct PppPcb;
void auth_withpeer_fail(PppPcb* pcb, int protocol);

bool start_networks(PppPcb* pcb, const bool multilink = true);

static bool enter_network_phase(PppPcb* pcb);
static void check_idle(void* arg);
static void connect_time_expired(void* arg);
// static void check_maxoctets(void*);
bool link_required(PppPcb* pcb);
bool upper_layers_down(PppPcb* pcb);

bool continue_networks(PppPcb* pcb);

bool link_established(PppPcb* pcb, bool auth_required);

//
// END OF FILE
//
