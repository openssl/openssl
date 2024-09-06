#ifndef ALIGN_H
#define ALIGN_H

#include <stdint.h>
#include <immintrin.h>

#define ALIGNED_UINT8(N)        \
    union {                     \
        uint8_t coeffs[N];      \
        __m256i vec[(N+31)/32]; \
    }

#define ALIGNED_INT16(N)        \
    union {                     \
        int16_t coeffs[N];      \
        __m256i vec[(N+15)/16]; \
    }

#endif
