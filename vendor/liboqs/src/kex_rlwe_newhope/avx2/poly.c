#include "poly.h"
#include "ntt.h"
#include "randombytes.h"
#include "fips202.h"
#include "crypto_stream.h"

static uint16_t barrett_reduce(uint16_t a)
{
  uint32_t u;

  u = ((uint32_t) a * 5) >> 16;
  u *= PARAM_Q;
  a -= u;
  return a;
}

void poly_frombytes(poly *r, const unsigned char *a)
{
  int i;
  for(i=0;i<PARAM_N/4;i++)
  {
    r->coeffs[4*i+0] =                               a[7*i+0]        | (((uint16_t)a[7*i+1] & 0x3f) << 8);
    r->coeffs[4*i+1] = (a[7*i+1] >> 6) | (((uint16_t)a[7*i+2]) << 2) | (((uint16_t)a[7*i+3] & 0x0f) << 10);
    r->coeffs[4*i+2] = (a[7*i+3] >> 4) | (((uint16_t)a[7*i+4]) << 4) | (((uint16_t)a[7*i+5] & 0x03) << 12);
    r->coeffs[4*i+3] = (a[7*i+5] >> 2) | (((uint16_t)a[7*i+6]) << 6); 
  }
}

void poly_tobytes(unsigned char *r, const poly *p)
{
  int i;
  uint16_t t0,t1,t2,t3,m;
  int16_t c;
  for(i=0;i<PARAM_N/4;i++)
  {
    t0 = barrett_reduce(p->coeffs[4*i+0]); //Make sure that coefficients have only 14 bits
    t1 = barrett_reduce(p->coeffs[4*i+1]);
    t2 = barrett_reduce(p->coeffs[4*i+2]);
    t3 = barrett_reduce(p->coeffs[4*i+3]);

    m = t0 - PARAM_Q;
    c = m;
    c >>= 15;
    t0 = m ^ ((t0^m)&c); // <Make sure that coefficients are in [0,q]

    m = t1 - PARAM_Q;
    c = m;
    c >>= 15;
    t1 = m ^ ((t1^m)&c); // <Make sure that coefficients are in [0,q]

    m = t2 - PARAM_Q;
    c = m;
    c >>= 15;
    t2 = m ^ ((t2^m)&c); // <Make sure that coefficients are in [0,q]

    m = t3 - PARAM_Q;
    c = m;
    c >>= 15;
    t3 = m ^ ((t3^m)&c); // <Make sure that coefficients are in [0,q]

    r[7*i+0] =  t0 & 0xff;
    r[7*i+1] = (t0 >> 8) | (t1 << 6);
    r[7*i+2] = (t1 >> 2);
    r[7*i+3] = (t1 >> 10) | (t2 << 4);
    r[7*i+4] = (t2 >> 4);
    r[7*i+5] = (t2 >> 12) | (t3 << 2);
    r[7*i+6] = (t3 >> 6);
  }
}



void poly_uniform(poly *a, const unsigned char *seed)
{
  unsigned int pos=0, ctr=0;
  uint16_t val;
  uint64_t state[25];
  unsigned int nblocks=13;
  uint8_t buf[SHAKE128_RATE*nblocks];

  shake128_absorb(state, seed, NEWHOPE_SEEDBYTES);
  
  shake128_squeezeblocks((unsigned char *) buf, nblocks, state);

  while(ctr < PARAM_N)
  {
    //val = (buf[pos] | ((uint16_t) buf[pos+1] << 8)) & 0x3fff; // Specialized for q = 12889
    val = (buf[pos] | ((uint16_t) buf[pos+1] << 8));
    if(val < 5*PARAM_Q)
      a->coeffs[ctr++] = val;
    pos += 2;
    if(pos > SHAKE128_RATE*nblocks-2)
    {
      nblocks=1;
      shake128_squeezeblocks((unsigned char *) buf,nblocks,state);
      pos = 0;
    }
  }
}


extern void cbd(poly *r, unsigned char *b);

void poly_getnoise(poly *r, unsigned char *seed, unsigned char nonce)
{
#if PARAM_K != 16
#error "poly_getnoise in poly.c only supports k=16"
#endif
  unsigned char buf[4*PARAM_N];
  unsigned char n[CRYPTO_STREAM_NONCEBYTES];
  int i;

  for(i=1;i<CRYPTO_STREAM_NONCEBYTES;i++)
    n[i] = 0;
  n[0] = nonce;

  crypto_stream(buf,4*PARAM_N,n,seed);
  cbd(r,buf);
}

void poly_add(poly *r, const poly *a, const poly *b)
{
  int i;
  for(i=0;i<PARAM_N;i++)
    r->coeffs[i] = barrett_reduce(a->coeffs[i] + b->coeffs[i]);
}

void poly_ntt(poly *r)
{
  double __attribute__ ((aligned (32))) temp[PARAM_N];
  poly_pointwise(r, r, (poly *)psis_bitrev);

  ntt_double(r->coeffs,omegas_double,temp);
}

void poly_invntt(poly *r)
{
  double __attribute__ ((aligned (32))) temp[PARAM_N];

  bitrev_vector(r->coeffs);
  ntt_double(r->coeffs, omegas_inv_double,temp);
  poly_pointwise(r, r, (poly *)psis_inv);
}
