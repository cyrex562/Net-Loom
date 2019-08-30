#pragma once
#include <cstdint>
#include "chap_new.h"


struct EndpointDiscriminator
{
    unsigned char class_; /* -- The word "class" is reserved in C++. */
    unsigned char length;
    //  unsigned char value[MAX_ENDP_LEN];
    std::vector<uint8_t> value;
};


/**
 * The state of options is described by an lcp_options structure.
 */
struct LcpOptions
{
    bool passive; /* Don't die if we don't get a response */
    bool silent; /* Wait for the other end to start first */
    bool restart; /* Restart vs. exit after close */
    bool neg_mru; /* Negotiate the MRU? */
    bool neg_asyncmap; /* Negotiate the async map? */
    bool neg_upap; /* Ask for UPAP authentication? */
    bool neg_chap; /* Ask for CHAP authentication? */
    bool neg_eap; /* Ask for EAP authentication? */
    bool neg_magicnumber; /* Ask for magic number? */
    bool neg_pcompression; /* HDLC Protocol Field Compression? */
    bool neg_accompression; /* HDLC Address/Control Field Compression? */
    bool neg_lqr; /* Negotiate use of Link Quality Reports */
    bool neg_cbcp; /* Negotiate use of CBCP */
    bool neg_mrru; /* negotiate multilink MRRU */
    bool neg_ssnhf; /* negotiate short sequence numbers */
    bool neg_endpoint; /* negotiate endpoint discriminator */
    uint16_t mru; /* Value of MRU */
    uint16_t mrru; /* Value of MRRU, and multilink enable */
    ChapMdTypes chap_mdtype; /* which MD types (hashing algorithm) */
    uint32_t asyncmap; /* Value of async map */
    uint32_t magicnumber;
    uint8_t numloops; /* Number of loops during magic number neg. */
    uint32_t lqr_period; /* Reporting period for LQR 1/100ths second */
    EndpointDiscriminator endpoint; /* endpoint discriminator */
};