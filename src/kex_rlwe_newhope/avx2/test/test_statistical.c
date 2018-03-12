
#include "../newhope.h"
#include "../poly.h"
#include "../randombytes.h"
#include "../crypto_stream_chacha20.h"
#include "../error_correction.h"
#include <math.h>
#include <stdio.h>
#include <string.h>

#define NRUNS 10000000UL

int hamming[256] = {
0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 
1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 
1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 
2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 
2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 
1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 
2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 
2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 
3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 
4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8};


static int hamming32(const unsigned char *k)
{
  int i;
  int r = 0;
  for(i=0;i<32;i++)
    r += hamming[k[i]];
  return r;
}

int main(void)
{
  poly sk_a;
  unsigned char key_b[32];
  unsigned char senda[NEWHOPE_SENDABYTES];
  unsigned char sendb[NEWHOPE_SENDBBYTES];
  unsigned long i;
  long t = 0;

  for(i=0;i<NRUNS;i++)
  {
    newhope_keygen(senda, &sk_a);
    newhope_sharedb(key_b, sendb, senda);

    t += hamming32(key_b);
  }

  printf("ones:   %ld\n",t);
  printf("zeroes: %ld\n",256*NRUNS-t);
  printf("diff:   %ld\n",256*NRUNS-2*t);

  return 0;
}
