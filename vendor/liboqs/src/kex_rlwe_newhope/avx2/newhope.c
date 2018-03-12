#include "poly.h"
#include "randombytes.h"
#include "error_correction.h"
#include "fips202.h"

static void encode_a(unsigned char *r, const poly *pk, const unsigned char *seed)
{
  int i;
  poly_tobytes(r, pk);
  for(i=0;i<NEWHOPE_SEEDBYTES;i++)
    r[POLY_BYTES+i] = seed[i];
}

static void decode_a(poly *pk, unsigned char *seed, const unsigned char *r)
{
  int i;
  poly_frombytes(pk, r);
  for(i=0;i<NEWHOPE_SEEDBYTES;i++)
    seed[i] = r[POLY_BYTES+i];
}

static void encode_b(unsigned char *r, const poly *b, const poly *c)
{
  int i;
  poly_tobytes(r,b);
  for(i=0;i<PARAM_N/4;i++)
    r[POLY_BYTES+i] = c->coeffs[4*i] | (c->coeffs[4*i+1] << 2) | (c->coeffs[4*i+2] << 4) | (c->coeffs[4*i+3] << 6);
}

static void decode_b(poly *b, poly *c, const unsigned char *r)
{
  int i;
  poly_frombytes(b, r);
  for(i=0;i<PARAM_N/4;i++)
  {
    c->coeffs[4*i+0] =  r[POLY_BYTES+i]       & 0x03;
    c->coeffs[4*i+1] = (r[POLY_BYTES+i] >> 2) & 0x03;
    c->coeffs[4*i+2] = (r[POLY_BYTES+i] >> 4) & 0x03;
    c->coeffs[4*i+3] = (r[POLY_BYTES+i] >> 6);
  }
}

static void gen_a(poly *a, const unsigned char *seed)
{
    poly_uniform(a,seed);
}


// API FUNCTIONS 

void newhope_keygen(unsigned char *send, poly *sk)
{
  poly a, e, r, pk;
  unsigned char seed[NEWHOPE_SEEDBYTES];
  unsigned char noiseseed[32];

  randombytes(seed, NEWHOPE_SEEDBYTES);
  sha3256(seed, seed, NEWHOPE_SEEDBYTES); /* Don't send output of system RNG */
  randombytes(noiseseed, 32);

  gen_a(&a, seed);

  poly_getnoise(sk,noiseseed,0);
  poly_ntt(sk);
  
  poly_getnoise(&e,noiseseed,1);
  poly_ntt(&e);

  poly_pointwise(&r,sk,&a);
  poly_add(&pk,&e,&r);

  encode_a(send, &pk, seed);
}


void newhope_sharedb(unsigned char *sharedkey, unsigned char *send, const unsigned char *received)
{
  poly sp, ep, v, a, pka, c, epp, bp;
  unsigned char seed[NEWHOPE_SEEDBYTES];
  unsigned char noiseseed[32];
  
  randombytes(noiseseed, 32);

  decode_a(&pka, seed, received);
  gen_a(&a, seed);

  poly_getnoise(&sp,noiseseed,0);
  poly_ntt(&sp);
  poly_getnoise(&ep,noiseseed,1);
  poly_ntt(&ep);

  poly_pointwise(&bp, &a, &sp);
  poly_add(&bp, &bp, &ep);
  
  poly_pointwise(&v, &pka, &sp);
  poly_invntt(&v);

  poly_getnoise(&epp,noiseseed,2);
  poly_add(&v, &v, &epp);

  helprec(&c, &v, noiseseed, 3);

  encode_b(send, &bp, &c);
  
  rec(sharedkey, &v, &c);

#ifndef STATISTICAL_TEST 
  sha3256(sharedkey, sharedkey, 32);
#endif
}


void newhope_shareda(unsigned char *sharedkey, const poly *sk, const unsigned char *received)
{
  poly v,bp, c;

  decode_b(&bp, &c, received);

  poly_pointwise(&v,sk,&bp);
  poly_invntt(&v);
 
  rec(sharedkey, &v, &c);

#ifndef STATISTICAL_TEST 
  sha3256(sharedkey, sharedkey, 32); 
#endif
}
