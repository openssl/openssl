#include "../newhope.h"
#include "../poly.h"
#include "../error_correction.h"
#include "../cpucycles.h"
#include <stdlib.h>
#include <stdio.h>

#define NTESTS 1000

static int cmp_llu(const void *a, const void*b)
{
  if(*(unsigned long long *)a < *(unsigned long long *)b) return -1;
  if(*(unsigned long long *)a > *(unsigned long long *)b) return 1;
  return 0;
}

static unsigned long long median(unsigned long long *l, size_t llen)
{
  qsort(l,llen,sizeof(unsigned long long),cmp_llu);

  if(llen%2) return l[llen/2];
  else return (l[llen/2-1]+l[llen/2])/2;
}

static unsigned long long average(unsigned long long *t, size_t tlen)
{
  unsigned long long acc=0;
  size_t i;
  for(i=0;i<tlen;i++)
    acc += t[i];
  return acc/(tlen);
}

static void print_results(const char *s, unsigned long long *t, size_t tlen)
{
  size_t i;
  printf("%s", s);
  for(i=0;i<tlen-1;i++)
  {
    t[i] = t[i+1] - t[i];
  //  printf("%llu ", t[i]);
  }
  printf("\n");
  printf("median: %llu\n", median(t, tlen));
  printf("average: %llu\n", average(t, tlen-1));
  printf("\n");
}


unsigned long long t[NTESTS];

int main(void)
{
  poly sk_a;
  unsigned char key_a[32], key_b[32];
  unsigned char senda[NTESTS*NEWHOPE_SENDABYTES];
  unsigned char sendb[NTESTS*NEWHOPE_SENDBBYTES];
  unsigned char seed[NEWHOPE_SEEDBYTES];
  int i;

  for(i=0; i<NTESTS; i++)
  {
    t[i] = cpucycles();
    randombytes(seed, NEWHOPE_SEEDBYTES);
    poly_uniform(&sk_a, seed);
  }
  print_results("poly_uniform: ", t, NTESTS);

  for(i=0; i<NTESTS; i++)
  {
    t[i] = cpucycles();
    poly_ntt(&sk_a);
  }
  print_results("poly_ntt: ", t, NTESTS);

  for(i=0; i<NTESTS; i++)
  {
    t[i] = cpucycles();
    poly_invntt(&sk_a);
  }
  print_results("poly_invntt: ", t, NTESTS);

  for(i=0; i<NTESTS; i++)
  {
    t[i] = cpucycles();
    poly_getnoise(&sk_a,seed,0);
  }
  print_results("poly_getnoise: ", t, NTESTS);

  for(i=0; i<NTESTS; i++)
  {
    t[i] = cpucycles();
    helprec(&sk_a, &sk_a, seed, 0);
  }
  print_results("helprec: ", t, NTESTS);

  for(i=0; i<NTESTS; i++)
  {
    t[i] = cpucycles();
    rec(key_a, &sk_a, &sk_a);
  }
  print_results("rec: ", t, NTESTS);

  for(i=0; i<NTESTS; i++)
  {
    t[i] = cpucycles();
    newhope_keygen(senda+i*NEWHOPE_SENDABYTES, &sk_a);
  }
  print_results("newhope_keygen: ", t, NTESTS);

  for(i=0; i<NTESTS; i++)
  {
    t[i] = cpucycles();
    newhope_sharedb(key_b, sendb+i*NEWHOPE_SENDBBYTES, senda+i*NEWHOPE_SENDABYTES);
  }
  print_results("newhope_sharedb: ", t, NTESTS);

  for(i=0; i<NTESTS; i++)
  {
    t[i] = cpucycles();
    newhope_shareda(key_a, &sk_a, sendb+i*NEWHOPE_SENDBBYTES);
  }
  print_results("newhope_shareda: ", t, NTESTS);
    
  
  return 0;
}
