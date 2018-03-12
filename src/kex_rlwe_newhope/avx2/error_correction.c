#include "crypto_stream.h"
#include "error_correction.h"

//See paper for details on the error reconciliation

extern void hr(poly *c, const poly *v, unsigned char rand[32]);

void helprec(poly *c, const poly *v, const unsigned char *seed, unsigned char nonce)
{
  unsigned char rand[32];
  unsigned char n[8];
  int i;

  for(i=0;i<7;i++)
    n[i] = 0;
  n[7] = nonce;

  crypto_stream(rand,32,n,seed);

  hr(c, v, rand);
}
