#pragma once
#include <cstdint>
#include "chap_new.h"

struct PppPcb;
constexpr auto MD5_HASH_SIZE = 16;
constexpr uint32_t kMd5MinChallenge = 17;
constexpr auto kMd5MaxChallenge = 24;
constexpr auto kMd5MinMaxPowerOfTwoChallenge = 3   /* 2^3-1 = 7, 17+7 = 24 */;

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


void chap_md5_generate_challenge(PppPcb* pcb, unsigned char* cp);


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
