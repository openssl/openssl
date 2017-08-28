#ifndef PARAMS_H
#define PARAMS_H

#define KYBER_N 256
#define KYBER_D 3
#define KYBER_K 4 /* used in sampler */
#define KYBER_Q 7681

#define KYBER_SEEDBYTES 32
#define KYBER_NOISESEEDBYTES 32
#define KYBER_COINBYTES 32
#define KYBER_SHAREDKEYBYTES 32

#define KYBER_POLYBYTES 416
#define KYBER_POLYCOMPRESSEDBYTES 96
#define KYBER_POLYVECBYTES (KYBER_D * KYBER_POLYBYTES)
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_D * 352)

#define KYBER_INDCPA_MSGBYTES 32
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_SEEDBYTES)
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)
#define KYBER_INDCPA_BYTES (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)

#define KYBER_PUBLICKEYBYTES (KYBER_INDCPA_PUBLICKEYBYTES)
#define KYBER_SECRETKEYBYTES (KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 32 + KYBER_SHAREDKEYBYTES)
#define KYBER_BYTES (KYBER_INDCPA_BYTES + KYBER_INDCPA_MSGBYTES) /* Second part is for Targhi-Unruh */

extern uint16_t oqs_kex_mlwe_kyber_omegas_montgomery[];
extern uint16_t oqs_kex_mlwe_kyber_omegas_inv_bitrev_montgomery[];
extern uint16_t oqs_kex_mlwe_kyber_psis_inv_montgomery[];
extern uint16_t oqs_kex_mlwe_kyber_psis_bitrev_montgomery[];

#if defined(WINDOWS)
typedef unsigned __int16 uint16_t;
#endif

#endif
