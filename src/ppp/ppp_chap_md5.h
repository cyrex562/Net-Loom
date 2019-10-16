#pragma once
#include <cstdint>
#include "ppp_chap_new.h"

struct PppPcb;
constexpr auto MD5_HASH_SIZE = 16;
constexpr uint32_t MIN_MD5_CHALLENGEN_LEN = 17;
constexpr auto MAX_MD5_CHALLENGE_LEN = 24;
constexpr auto MIN_MAX_POW_2_MD5_CHALLENGE_LEN = 3   /* 2^3-1 = 7, 17+7 = 24 */;

void chap_md5_make_response(PppPcb* pcb,
                                   unsigned char* response,
                                   const int id,
                                   const char* our_name,
                                   const unsigned char* challenge,
                                   const char* secret,
                                   const int secret_len,
                                   unsigned char* private_);


int chap_md5_verify_response(PppPcb* pcb,
                                    const int id,
                                    const char* name,
                                    const unsigned char* secret,
                                    const int secret_len,
                                    const unsigned char* challenge,
                                    const unsigned char* response,
                                    char* message,
                                    const int message_space);


bool
chap_md5_generate_challenge(PppPcb& pcb, std::vector<uint8_t>& cp);


// constexpr ChapDigestType kMd5Digest = {
//     CHAP_MD5,
//     /* code */
//     chap_md5_generate_challenge,
//     chap_md5_verify_response,
//     chap_md5_make_response,
//     nullptr,
//     /* check_success */
//     nullptr,
//     /* handle_failure */
// };

//
// END OF FILE
//
