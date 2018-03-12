#ifndef PARAMS_H
#define PARAMS_H

#include <stdint.h>

#define PARAM_N 1024

#define PARAM_K 16 /* used in sampler */
#define PARAM_Q 12289

#define POLY_BYTES 1792
#define NEWHOPE_SEEDBYTES 32
#define NEWHOPE_RECBYTES 256

#define NEWHOPE_SENDABYTES (POLY_BYTES + NEWHOPE_SEEDBYTES)
#define NEWHOPE_SENDBBYTES (POLY_BYTES + NEWHOPE_RECBYTES)

extern uint16_t bitrev_table[];
extern uint16_t omegas_montgomery[];
extern uint16_t omegas_inv_montgomery[];
extern uint16_t psis_inv_montgomery[];
extern uint16_t psis_bitrev_montgomery[];

#if defined(_WIN32)
typedef unsigned __int16 uint16_t;
#endif

#endif
