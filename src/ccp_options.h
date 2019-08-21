#pragma once
#include <cstdint>
#include <mppe_def.h>


struct CcpOptions {
    bool deflate; /* do Deflate? */
    bool deflate_correct; /* use correct code for deflate? */
    bool deflate_draft; /* use draft RFC code for deflate? */
    bool bsd_compress; /* do BSD Compress? */
    bool predictor_1; /* do Predictor-1? */
    bool predictor_2; /* do Predictor-2? */
    MppeOptions mppe;			/* MPPE bitfield */
    uint16_t bsd_bits;		/* # bits/code for BSD Compress */
    uint16_t deflate_size;	/* lg(window size) for Deflate */
    uint8_t method;		/* code for chosen compression method */
};

//
// END OF FILE
//