/* crypto/bn/bn_comba.c */
#include <stdio.h>
#include "bn_lcl.h"
/* Auto generated from crypto/bn/comba.pl
 */

#undef bn_mul_comba8
#undef bn_mul_comba4
#undef bn_sqr_comba8
#undef bn_sqr_comba4

#ifdef BN_LLONG
#define mul_add_c(a,b,c0,c1,c2) \
	t=(BN_ULLONG)a*b; \
	t1=(BN_ULONG)Lw(t); \
	t2=(BN_ULONG)Hw(t); \
	c0=(c0+t1)&BN_MASK2; if ((c0) < t1) t2++; \
	c1=(c1+t2)&BN_MASK2; if ((c1) < t2) c2++;

#define mul_add_c2(a,b,c0,c1,c2) \
	t=(BN_ULLONG)a*b; \
	tt=(t+t)&BN_MASK; \
	if (tt < t) c2++; \
	t1=(BN_ULONG)Lw(tt); \
	t2=(BN_ULONG)Hw(tt); \
	c0=(c0+t1)&BN_MASK2;  \
	if ((c0 < t1) && (((++t2)&BN_MASK2) == 0)) c2++; \
	c1=(c1+t2)&BN_MASK2; if ((c1) < t2) c2++;

#define sqr_add_c(a,i,c0,c1,c2) \
	t=(BN_ULLONG)a[i]*a[i]; \
	t1=(BN_ULONG)Lw(t); \
	t2=(BN_ULONG)Hw(t); \
	c0=(c0+t1)&BN_MASK2; if ((c0) < t1) t2++; \
	c1=(c1+t2)&BN_MASK2; if ((c1) < t2) c2++;

#define sqr_add_c2(a,i,j,c0,c1,c2) \
	mul_add_c2((a)[i],(a)[j],c0,c1,c2)
#else
#define mul_add_c(a,b,c0,c1,c2) \
	t1=LBITS(a); t2=HBITS(a); \
	bl=LBITS(b); bh=HBITS(b); \
	mul64(t1,t2,bl,bh); \
	c0=(c0+t1)&BN_MASK2; if ((c0) < t1) t2++; \
	c1=(c1+t2)&BN_MASK2; if ((c1) < t2) c2++;

#define mul_add_c2(a,b,c0,c1,c2) \
	t1=LBITS(a); t2=HBITS(a); \
	bl=LBITS(b); bh=HBITS(b); \
	mul64(t1,t2,bl,bh); \
	if (t2 & BN_TBIT) c2++; \
	t2=(t2+t2)&BN_MASK2; \
	if (t1 & BN_TBIT) t2++; \
	t1=(t1+t1)&BN_MASK2; \
	c0=(c0+t1)&BN_MASK2;  \
	if ((c0 < t1) && (((++t2)&BN_MASK2) == 0)) c2++; \
	c1=(c1+t2)&BN_MASK2; if ((c1) < t2) c2++;

#define sqr_add_c(a,i,c0,c1,c2) \
	sqr64(t1,t2,(a)[i]); \
	c0=(c0+t1)&BN_MASK2; if ((c0) < t1) t2++; \
	c1=(c1+t2)&BN_MASK2; if ((c1) < t2) c2++;

#define sqr_add_c2(a,i,j,c0,c1,c2) \
	mul_add_c2((a)[i],(a)[j],c0,c1,c2)
#endif

void bn_mul_comba88(BN_ULONG *r,BN_ULONG *a,BN_ULONG *b);
void bn_mul_comba44(BN_ULONG *r,BN_ULONG *a,BN_ULONG *b);
void bn_sqr_comba88(BN_ULONG *r,BN_ULONG *a);
void bn_sqr_comba44(BN_ULONG *r,BN_ULONG *a);

void bn_mul_comba88(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b)
	{
#ifdef BN_LLONG
	BN_ULLONG t;
#else
	BN_ULONG bl,bh;
#endif
	BN_ULONG t1,t2;
	BN_ULONG c1,c2,c3;

	c1=0;
	c2=0;
	c3=0;
	mul_add_c(a[0],b[0],c1,c2,c3);
	r[0]=c1;
	c1=0;
	mul_add_c(a[0],b[1],c2,c3,c1);
	mul_add_c(a[1],b[0],c2,c3,c1);
	r[1]=c2;
	c2=0;
	mul_add_c(a[2],b[0],c3,c1,c2);
	mul_add_c(a[1],b[1],c3,c1,c2);
	mul_add_c(a[0],b[2],c3,c1,c2);
	r[2]=c3;
	c3=0;
	mul_add_c(a[0],b[3],c1,c2,c3);
	mul_add_c(a[1],b[2],c1,c2,c3);
	mul_add_c(a[2],b[1],c1,c2,c3);
	mul_add_c(a[3],b[0],c1,c2,c3);
	r[3]=c1;
	c1=0;
	mul_add_c(a[4],b[0],c2,c3,c1);
	mul_add_c(a[3],b[1],c2,c3,c1);
	mul_add_c(a[2],b[2],c2,c3,c1);
	mul_add_c(a[1],b[3],c2,c3,c1);
	mul_add_c(a[0],b[4],c2,c3,c1);
	r[4]=c2;
	c2=0;
	mul_add_c(a[0],b[5],c3,c1,c2);
	mul_add_c(a[1],b[4],c3,c1,c2);
	mul_add_c(a[2],b[3],c3,c1,c2);
	mul_add_c(a[3],b[2],c3,c1,c2);
	mul_add_c(a[4],b[1],c3,c1,c2);
	mul_add_c(a[5],b[0],c3,c1,c2);
	r[5]=c3;
	c3=0;
	mul_add_c(a[6],b[0],c1,c2,c3);
	mul_add_c(a[5],b[1],c1,c2,c3);
	mul_add_c(a[4],b[2],c1,c2,c3);
	mul_add_c(a[3],b[3],c1,c2,c3);
	mul_add_c(a[2],b[4],c1,c2,c3);
	mul_add_c(a[1],b[5],c1,c2,c3);
	mul_add_c(a[0],b[6],c1,c2,c3);
	r[6]=c1;
	c1=0;
	mul_add_c(a[0],b[7],c2,c3,c1);
	mul_add_c(a[1],b[6],c2,c3,c1);
	mul_add_c(a[2],b[5],c2,c3,c1);
	mul_add_c(a[3],b[4],c2,c3,c1);
	mul_add_c(a[4],b[3],c2,c3,c1);
	mul_add_c(a[5],b[2],c2,c3,c1);
	mul_add_c(a[6],b[1],c2,c3,c1);
	mul_add_c(a[7],b[0],c2,c3,c1);
	r[7]=c2;
	c2=0;
	mul_add_c(a[7],b[1],c3,c1,c2);
	mul_add_c(a[6],b[2],c3,c1,c2);
	mul_add_c(a[5],b[3],c3,c1,c2);
	mul_add_c(a[4],b[4],c3,c1,c2);
	mul_add_c(a[3],b[5],c3,c1,c2);
	mul_add_c(a[2],b[6],c3,c1,c2);
	mul_add_c(a[1],b[7],c3,c1,c2);
	r[8]=c3;
	c3=0;
	mul_add_c(a[2],b[7],c1,c2,c3);
	mul_add_c(a[3],b[6],c1,c2,c3);
	mul_add_c(a[4],b[5],c1,c2,c3);
	mul_add_c(a[5],b[4],c1,c2,c3);
	mul_add_c(a[6],b[3],c1,c2,c3);
	mul_add_c(a[7],b[2],c1,c2,c3);
	r[9]=c1;
	c1=0;
	mul_add_c(a[7],b[3],c2,c3,c1);
	mul_add_c(a[6],b[4],c2,c3,c1);
	mul_add_c(a[5],b[5],c2,c3,c1);
	mul_add_c(a[4],b[6],c2,c3,c1);
	mul_add_c(a[3],b[7],c2,c3,c1);
	r[10]=c2;
	c2=0;
	mul_add_c(a[4],b[7],c3,c1,c2);
	mul_add_c(a[5],b[6],c3,c1,c2);
	mul_add_c(a[6],b[5],c3,c1,c2);
	mul_add_c(a[7],b[4],c3,c1,c2);
	r[11]=c3;
	c3=0;
	mul_add_c(a[7],b[5],c1,c2,c3);
	mul_add_c(a[6],b[6],c1,c2,c3);
	mul_add_c(a[5],b[7],c1,c2,c3);
	r[12]=c1;
	c1=0;
	mul_add_c(a[6],b[7],c2,c3,c1);
	mul_add_c(a[7],b[6],c2,c3,c1);
	r[13]=c2;
	c2=0;
	mul_add_c(a[7],b[7],c3,c1,c2);
	r[14]=c3;
	r[15]=c1;
	}

void bn_mul_comba44(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b)
	{
#ifdef BN_LLONG
	BN_ULLONG t;
#else
	BN_ULONG bl,bh;
#endif
	BN_ULONG t1,t2;
	BN_ULONG c1,c2,c3;

	c1=0;
	c2=0;
	c3=0;
	mul_add_c(a[0],b[0],c1,c2,c3);
	r[0]=c1;
	c1=0;
	mul_add_c(a[0],b[1],c2,c3,c1);
	mul_add_c(a[1],b[0],c2,c3,c1);
	r[1]=c2;
	c2=0;
	mul_add_c(a[2],b[0],c3,c1,c2);
	mul_add_c(a[1],b[1],c3,c1,c2);
	mul_add_c(a[0],b[2],c3,c1,c2);
	r[2]=c3;
	c3=0;
	mul_add_c(a[0],b[3],c1,c2,c3);
	mul_add_c(a[1],b[2],c1,c2,c3);
	mul_add_c(a[2],b[1],c1,c2,c3);
	mul_add_c(a[3],b[0],c1,c2,c3);
	r[3]=c1;
	c1=0;
	mul_add_c(a[3],b[1],c2,c3,c1);
	mul_add_c(a[2],b[2],c2,c3,c1);
	mul_add_c(a[1],b[3],c2,c3,c1);
	r[4]=c2;
	c2=0;
	mul_add_c(a[2],b[3],c3,c1,c2);
	mul_add_c(a[3],b[2],c3,c1,c2);
	r[5]=c3;
	c3=0;
	mul_add_c(a[3],b[3],c1,c2,c3);
	r[6]=c1;
	r[7]=c2;
	}

void bn_sqr_comba88(BN_ULONG *r, BN_ULONG *a)
	{
#ifdef BN_LLONG
	BN_ULLONG t,tt;
#else
	BN_ULONG bl,bh;
#endif
	BN_ULONG t1,t2;
	BN_ULONG c1,c2,c3;

	c1=0;
	c2=0;
	c3=0;
	sqr_add_c(a,0,c1,c2,c3);
	r[0]=c1;
	c1=0;
	sqr_add_c2(a,1,0,c2,c3,c1);
	r[1]=c2;
	c2=0;
	sqr_add_c(a,1,c3,c1,c2);
	sqr_add_c2(a,2,0,c3,c1,c2);
	r[2]=c3;
	c3=0;
	sqr_add_c2(a,3,0,c1,c2,c3);
	sqr_add_c2(a,2,1,c1,c2,c3);
	r[3]=c1;
	c1=0;
	sqr_add_c(a,2,c2,c3,c1);
	sqr_add_c2(a,3,1,c2,c3,c1);
	sqr_add_c2(a,4,0,c2,c3,c1);
	r[4]=c2;
	c2=0;
	sqr_add_c2(a,5,0,c3,c1,c2);
	sqr_add_c2(a,4,1,c3,c1,c2);
	sqr_add_c2(a,3,2,c3,c1,c2);
	r[5]=c3;
	c3=0;
	sqr_add_c(a,3,c1,c2,c3);
	sqr_add_c2(a,4,2,c1,c2,c3);
	sqr_add_c2(a,5,1,c1,c2,c3);
	sqr_add_c2(a,6,0,c1,c2,c3);
	r[6]=c1;
	c1=0;
	sqr_add_c2(a,7,0,c2,c3,c1);
	sqr_add_c2(a,6,1,c2,c3,c1);
	sqr_add_c2(a,5,2,c2,c3,c1);
	sqr_add_c2(a,4,3,c2,c3,c1);
	r[7]=c2;
	c2=0;
	sqr_add_c(a,4,c3,c1,c2);
	sqr_add_c2(a,5,3,c3,c1,c2);
	sqr_add_c2(a,6,2,c3,c1,c2);
	sqr_add_c2(a,7,1,c3,c1,c2);
	r[8]=c3;
	c3=0;
	sqr_add_c2(a,7,2,c1,c2,c3);
	sqr_add_c2(a,6,3,c1,c2,c3);
	sqr_add_c2(a,5,4,c1,c2,c3);
	r[9]=c1;
	c1=0;
	sqr_add_c(a,5,c2,c3,c1);
	sqr_add_c2(a,6,4,c2,c3,c1);
	sqr_add_c2(a,7,3,c2,c3,c1);
	r[10]=c2;
	c2=0;
	sqr_add_c2(a,7,4,c3,c1,c2);
	sqr_add_c2(a,6,5,c3,c1,c2);
	r[11]=c3;
	c3=0;
	sqr_add_c(a,6,c1,c2,c3);
	sqr_add_c2(a,7,5,c1,c2,c3);
	r[12]=c1;
	c1=0;
	sqr_add_c2(a,7,6,c2,c3,c1);
	r[13]=c2;
	c2=0;
	sqr_add_c(a,7,c3,c1,c2);
	r[14]=c3;
	r[15]=c1;
	}

void bn_sqr_comba44(BN_ULONG *r, BN_ULONG *a)
	{
#ifdef BN_LLONG
	BN_ULLONG t,tt;
#else
	BN_ULONG bl,bh;
#endif
	BN_ULONG t1,t2;
	BN_ULONG c1,c2,c3;

	c1=0;
	c2=0;
	c3=0;
	sqr_add_c(a,0,c1,c2,c3);
	r[0]=c1;
	c1=0;
	sqr_add_c2(a,1,0,c2,c3,c1);
	r[1]=c2;
	c2=0;
	sqr_add_c(a,1,c3,c1,c2);
	sqr_add_c2(a,2,0,c3,c1,c2);
	r[2]=c3;
	c3=0;
	sqr_add_c2(a,3,0,c1,c2,c3);
	sqr_add_c2(a,2,1,c1,c2,c3);
	r[3]=c1;
	c1=0;
	sqr_add_c(a,2,c2,c3,c1);
	sqr_add_c2(a,3,1,c2,c3,c1);
	r[4]=c2;
	c2=0;
	sqr_add_c2(a,3,2,c3,c1,c2);
	r[5]=c3;
	c3=0;
	sqr_add_c(a,3,c1,c2,c3);
	r[6]=c1;
	r[7]=c2;
	}
