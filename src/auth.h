//
// auth.h: PPP authentication code header file.
// 
//

#pragma once
struct Protent;
struct PppPcb;
void auth_withpeer_fail(PppPcb* pcb, int protocol);
bool start_networks(PppPcb* pcb, const bool multilink = true);
static bool enter_network_phase(PppPcb* pcb);
static void check_idle(void* arg);
static void connect_time_expired(void* arg); // static void check_maxoctets(void*);
bool link_required(PppPcb* pcb);
bool upper_layers_down(PppPcb* pcb);
bool continue_networks(PppPcb* pcb);
bool link_established(PppPcb* pcb, bool auth_required);
void link_terminated(PppPcb* pcb);
void link_down(PppPcb* pcb);
int auth_check_passwd(PppPcb* pcb,
                      char* auser,
                      int userlen,
                      char* apasswd,
                      int passwdlen,
                      const char** msg,
                      int* msglen);
void auth_peer_fail(PppPcb* pcb, int protocol);
void auth_peer_success(PppPcb* pcb,
                       int protocol,
                       int prot_flavor,
                       const char* name,
                       size_t namelen);

void np_up(PppPcb* pcb, int proto);
void np_down(PppPcb* pcb, int proto);
void np_finished(PppPcb* pcb, int proto);
int get_secret(PppPcb* pcb,
               const char* client,
               const char* server,
               char* secret,
               int* secret_len,
               int am_server);
void auth_withpeer_success(PppPcb* pcb, int protocol, int prot_flavor);
//
// END OF FILE
//
