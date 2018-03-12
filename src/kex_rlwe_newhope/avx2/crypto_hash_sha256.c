/*
20080913
D. J. Bernstein
Public domain.
*/

#define blocks crypto_hashblocks_sha256

typedef unsigned int uint32;

static uint32 load_bigendian(const unsigned char *x)
{
  return
      (uint32) (x[3]) \
  | (((uint32) (x[2])) << 8) \
  | (((uint32) (x[1])) << 16) \
  | (((uint32) (x[0])) << 24)
  ;
}

static void store_bigendian(unsigned char *x,uint32 u)
{
  x[3] = u; u >>= 8;
  x[2] = u; u >>= 8;
  x[1] = u; u >>= 8;
  x[0] = u;
}

#define SHR(x,c) ((x) >> (c))
#define ROTR(x,c) (((x) >> (c)) | ((x) << (32 - (c))))

#define Ch(x,y,z) ((x & y) ^ (~x & z))
#define Maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define Sigma0(x) (ROTR(x, 2) ^ ROTR(x,13) ^ ROTR(x,22))
#define Sigma1(x) (ROTR(x, 6) ^ ROTR(x,11) ^ ROTR(x,25))
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x,18) ^ SHR(x, 3))
#define sigma1(x) (ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10))

#define M(w0,w14,w9,w1) w0 = sigma1(w14) + w9 + sigma0(w1) + w0;

#define EXPAND \
  M(w0 ,w14,w9 ,w1 ) \
  M(w1 ,w15,w10,w2 ) \
  M(w2 ,w0 ,w11,w3 ) \
  M(w3 ,w1 ,w12,w4 ) \
  M(w4 ,w2 ,w13,w5 ) \
  M(w5 ,w3 ,w14,w6 ) \
  M(w6 ,w4 ,w15,w7 ) \
  M(w7 ,w5 ,w0 ,w8 ) \
  M(w8 ,w6 ,w1 ,w9 ) \
  M(w9 ,w7 ,w2 ,w10) \
  M(w10,w8 ,w3 ,w11) \
  M(w11,w9 ,w4 ,w12) \
  M(w12,w10,w5 ,w13) \
  M(w13,w11,w6 ,w14) \
  M(w14,w12,w7 ,w15) \
  M(w15,w13,w8 ,w0 )

#define F(w,k) \
  T1 = h + Sigma1(e) + Ch(e,f,g) + k + w; \
  T2 = Sigma0(a) + Maj(a,b,c); \
  h = g; \
  g = f; \
  f = e; \
  e = d + T1; \
  d = c; \
  c = b; \
  b = a; \
  a = T1 + T2;

static int crypto_hashblocks_sha256(unsigned char *statebytes,const unsigned char *in,unsigned long long inlen)
{
  uint32 state[8];
  uint32 a;
  uint32 b;
  uint32 c;
  uint32 d;
  uint32 e;
  uint32 f;
  uint32 g;
  uint32 h;
  uint32 T1;
  uint32 T2;

  a = load_bigendian(statebytes +  0); state[0] = a;
  b = load_bigendian(statebytes +  4); state[1] = b;
  c = load_bigendian(statebytes +  8); state[2] = c;
  d = load_bigendian(statebytes + 12); state[3] = d;
  e = load_bigendian(statebytes + 16); state[4] = e;
  f = load_bigendian(statebytes + 20); state[5] = f;
  g = load_bigendian(statebytes + 24); state[6] = g;
  h = load_bigendian(statebytes + 28); state[7] = h;

  while (inlen >= 64) {
    uint32 w0  = load_bigendian(in +  0);
    uint32 w1  = load_bigendian(in +  4);
    uint32 w2  = load_bigendian(in +  8);
    uint32 w3  = load_bigendian(in + 12);
    uint32 w4  = load_bigendian(in + 16);
    uint32 w5  = load_bigendian(in + 20);
    uint32 w6  = load_bigendian(in + 24);
    uint32 w7  = load_bigendian(in + 28);
    uint32 w8  = load_bigendian(in + 32);
    uint32 w9  = load_bigendian(in + 36);
    uint32 w10 = load_bigendian(in + 40);
    uint32 w11 = load_bigendian(in + 44);
    uint32 w12 = load_bigendian(in + 48);
    uint32 w13 = load_bigendian(in + 52);
    uint32 w14 = load_bigendian(in + 56);
    uint32 w15 = load_bigendian(in + 60);

    F(w0 ,0x428a2f98)
    F(w1 ,0x71374491)
    F(w2 ,0xb5c0fbcf)
    F(w3 ,0xe9b5dba5)
    F(w4 ,0x3956c25b)
    F(w5 ,0x59f111f1)
    F(w6 ,0x923f82a4)
    F(w7 ,0xab1c5ed5)
    F(w8 ,0xd807aa98)
    F(w9 ,0x12835b01)
    F(w10,0x243185be)
    F(w11,0x550c7dc3)
    F(w12,0x72be5d74)
    F(w13,0x80deb1fe)
    F(w14,0x9bdc06a7)
    F(w15,0xc19bf174)

    EXPAND

    F(w0 ,0xe49b69c1)
    F(w1 ,0xefbe4786)
    F(w2 ,0x0fc19dc6)
    F(w3 ,0x240ca1cc)
    F(w4 ,0x2de92c6f)
    F(w5 ,0x4a7484aa)
    F(w6 ,0x5cb0a9dc)
    F(w7 ,0x76f988da)
    F(w8 ,0x983e5152)
    F(w9 ,0xa831c66d)
    F(w10,0xb00327c8)
    F(w11,0xbf597fc7)
    F(w12,0xc6e00bf3)
    F(w13,0xd5a79147)
    F(w14,0x06ca6351)
    F(w15,0x14292967)

    EXPAND

    F(w0 ,0x27b70a85)
    F(w1 ,0x2e1b2138)
    F(w2 ,0x4d2c6dfc)
    F(w3 ,0x53380d13)
    F(w4 ,0x650a7354)
    F(w5 ,0x766a0abb)
    F(w6 ,0x81c2c92e)
    F(w7 ,0x92722c85)
    F(w8 ,0xa2bfe8a1)
    F(w9 ,0xa81a664b)
    F(w10,0xc24b8b70)
    F(w11,0xc76c51a3)
    F(w12,0xd192e819)
    F(w13,0xd6990624)
    F(w14,0xf40e3585)
    F(w15,0x106aa070)

    EXPAND

    F(w0 ,0x19a4c116)
    F(w1 ,0x1e376c08)
    F(w2 ,0x2748774c)
    F(w3 ,0x34b0bcb5)
    F(w4 ,0x391c0cb3)
    F(w5 ,0x4ed8aa4a)
    F(w6 ,0x5b9cca4f)
    F(w7 ,0x682e6ff3)
    F(w8 ,0x748f82ee)
    F(w9 ,0x78a5636f)
    F(w10,0x84c87814)
    F(w11,0x8cc70208)
    F(w12,0x90befffa)
    F(w13,0xa4506ceb)
    F(w14,0xbef9a3f7)
    F(w15,0xc67178f2)

    a += state[0];
    b += state[1];
    c += state[2];
    d += state[3];
    e += state[4];
    f += state[5];
    g += state[6];
    h += state[7];
  
    state[0] = a;
    state[1] = b;
    state[2] = c;
    state[3] = d;
    state[4] = e;
    state[5] = f;
    state[6] = g;
    state[7] = h;

    in += 64;
    inlen -= 64;
  }

  store_bigendian(statebytes +  0,state[0]);
  store_bigendian(statebytes +  4,state[1]);
  store_bigendian(statebytes +  8,state[2]);
  store_bigendian(statebytes + 12,state[3]);
  store_bigendian(statebytes + 16,state[4]);
  store_bigendian(statebytes + 20,state[5]);
  store_bigendian(statebytes + 24,state[6]);
  store_bigendian(statebytes + 28,state[7]);

  return inlen;
}

static const char iv[32] = {
  0x6a,0x09,0xe6,0x67,
  0xbb,0x67,0xae,0x85,
  0x3c,0x6e,0xf3,0x72,
  0xa5,0x4f,0xf5,0x3a,
  0x51,0x0e,0x52,0x7f,
  0x9b,0x05,0x68,0x8c,
  0x1f,0x83,0xd9,0xab,
  0x5b,0xe0,0xcd,0x19,
} ;

int crypto_hash_sha256(unsigned char *out,const unsigned char *in,unsigned long long inlen)
{
  unsigned char h[32];
  unsigned char padded[128];
  unsigned long long i;
  unsigned long long bits = inlen << 3;

  for (i = 0;i < 32;++i) h[i] = iv[i];

  blocks(h,in,inlen);
  in += inlen;
  inlen &= 63;
  in -= inlen;

  for (i = 0;i < inlen;++i) padded[i] = in[i];
  padded[inlen] = 0x80;

  if (inlen < 56) {
    for (i = inlen + 1;i < 56;++i) padded[i] = 0;
    padded[56] = bits >> 56;
    padded[57] = bits >> 48;
    padded[58] = bits >> 40;
    padded[59] = bits >> 32;
    padded[60] = bits >> 24;
    padded[61] = bits >> 16;
    padded[62] = bits >> 8;
    padded[63] = bits;
    blocks(h,padded,64);
  } else {
    for (i = inlen + 1;i < 120;++i) padded[i] = 0;
    padded[120] = bits >> 56;
    padded[121] = bits >> 48;
    padded[122] = bits >> 40;
    padded[123] = bits >> 32;
    padded[124] = bits >> 24;
    padded[125] = bits >> 16;
    padded[126] = bits >> 8;
    padded[127] = bits;
    blocks(h,padded,128);
  }

  for (i = 0;i < 32;++i) out[i] = h[i];

  return 0;
}



