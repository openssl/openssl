/* crypto/bn/wei_mulw.c */

#include <stdio.h>
#include "cryptlib.h"
#include "bn.h"
#include "bn_lcl.h"

BN_ULONG bn_add_word(BN_ULONG *a,BN_ULONG c,int num);
BN_ULONG bn_add_words(BN_ULONG *ret,BN_ULONG *a,BN_ULONG *b,int num);
BN_ULONG bn_sub_words(BN_ULONG *ret,BN_ULONG *a,BN_ULONG *b,int num);

void BN_mul_4words(BN_ULONG *ret,BN_ULONG a0,BN_ULONG a1,
	BN_ULONG b0,BN_ULONG b1);

void pr(a,n,s)
BN_ULONG *a;
int n;
	{
	while (n--)
		fprintf(stdout,"%02X",a[n]);
	fprintf(stdout,"%s",s);
	}


BN_ULONG bn_add_word(a,w,num)
BN_ULONG *a;
BN_ULONG w;
int num;
	{
	BN_ULONG t;

#ifdef DEBUG
{ BN_ULONG *aa=a; int i; for (i=num; i>0; i--) fprintf(stdout,"%02X",aa[i-1]);
fprintf(stdout," + %X - ",w); i=num;
#endif
	
loop:
	t= *a;
	t=(t+w)&BN_MASK2;
	*(a++)=t;
	w=(t < w);
	if (w && --num) goto loop;

#ifdef DEBUG
for (; i>0; i--) fprintf(stdout,"%02X",aa[i-1]);
fprintf(stdout,"\n");
}
#endif

	return(w);
	}

BN_ULONG bn_add_words(r,a,b,num)
BN_ULONG *r;
BN_ULONG *a;
BN_ULONG *b;
int num;
	{
#if defined(BN_LLONG)
	BN_ULLONG t;
	BN_ULONG c=0;
	int i;

	if (num&1) abort();

	for (i=0; i<num; i+=2)
		{
		t=(BN_ULLONG)a[i]+b[i]+c;
		r[i+0]=L(t);
		t=(BN_ULLONG) H(t)+a[i+1]+b[i+1];
		r[i+1]=L(t);
		c=H(t);
		}
	return(c);
#else
	BN_ULONG c=0,t1,t2;

	for ( ; num; num--)
		{
		t1= *(a++);
		t2= *(b++);

		if (c)
			{
			c=(t2 >= ((~t1)&BN_MASK2));
			(*r++)=(t1+t2+1)&BN_MASK2;
			}
		else
			{
			t2=(t1+t2)&BN_MASK2;
			c=(t2 < t1);
			(*r++)=t2;
			}
		}
	return(c);
#endif
	}

BN_ULONG bn_sub_words(r,a,b,num)
BN_ULONG *r;
BN_ULONG *a;
BN_ULONG *b;
int num;
	{
#if defined(BN_LLONG)
	BN_ULLONG t;
	BN_ULONG c=0;
	int i;

	if (num&1) abort();

	for (i=0; i<num; i+=2)
		{
		t=(BN_ULLONG)a[i]-b[i]-c;
		r[i+0]=L(t);
		t=(BN_ULLONG)a[i+1]-b[i+1]-(0-H(t))&BN_MASK2;
		r[i+1]=L(t);
		c=H(t);
		}
	return(c);
#else
	BN_ULONG c=0,t1,t2;

	for ( ; num; num--)
		{
		t1= *(a++);
		t2= *(b++);

		if (c)
			{
			c=(t1 <= t2);
			t1=(t1-t2-1);
			}
		else
			{
			c=(t1 < t2);
			t1=(t1-t2);
			}
		(*r++)=t1&BN_MASK2;
		}
	return(c);
#endif
	}


/* ret[3,2,1,0] = a1,a0 * b1,b0 */
void BN_mul_4words(ret,a0,a1,b0,b1)
BN_ULONG *ret;
BN_ULONG a0,a1,b0,b1;
	{
	BN_ULONG s,u;
	BN_ULLONG fix,a0b0,a1b1,tmp;

	if (a1 >= a0)
		{
		s=(a1-a0);
		u=(b0-b1);
		fix=(BN_ULLONG)s*u;
		if (b0 >= b1) s=0;
		}
	else
		{
		BN_ULONG u;

		if (b0 > b1)
			{
			s=(b0-b1);
			u=(a1-a0);
			fix=(BN_ULLONG)s*u;
			}
		else
			{
			u=(a0-a1);
			s=(b1-b0);
			fix=(BN_ULLONG)s*u;
			s=0;
			}
		}
	
	a0b0=(BN_ULLONG)a0*b0;
	ret[0]=L(a0b0);

	a1b1=(BN_ULLONG)a1*b1;
	tmp=(BN_ULLONG) H(a0b0) + L(a0b0) + L(fix) + L(a1b1);
	ret[1]=L(tmp);

	tmp=(BN_ULLONG) a1b1 + H(tmp) + H(a0b0) + H(fix) + H(a1b1) - s;
	ret[2]=L(tmp);
	ret[3]=H(tmp);
	}

/* ret[3,2,1,0] += a1,a0 * b1,b0 */
BN_ULONG BN_mul_add_4words(ret,a0,a1,b0,b1)
BN_ULONG *ret;
BN_ULONG a0,a1,b0,b1;
	{
	BN_ULONG s,u;
	BN_ULLONG fix,a0b0,a1b1,tmp;

#ifdef DEBUG
fprintf(stdout,"%02X%02X%02X%02X",ret[3],ret[2],ret[1],ret[0]);
fprintf(stdout," + ( %02X%02X * %02X%02X ) - ",a1,a0,b1,b0);
#endif
	if (a1 >= a0)
		{
		s=(a1-a0);
		u=(b0-b1);
		fix=(BN_ULLONG)s*u;
		if (b0 >= b1) s=0;
		}
	else
		{
		if (b0 > b1)
			{
			s=(b0-b1);
			u=(a1-a0);
			fix=(BN_ULLONG)s*u;
			}
		else
			{
			u=(a0-a1);
			s=(b1-b0);
			fix=(BN_ULLONG)s*u;
			s=0;
			}
		}
	
	a0b0=(BN_ULLONG)a0*b0;
	tmp=a0b0+ret[0];
	ret[0]=L(tmp);

	a1b1=(BN_ULLONG)a1*b1;
	tmp=(BN_ULLONG) H(tmp) + L(a0b0) + L(fix) + L(a1b1) + ret[1];
	ret[1]=L(tmp);

	tmp=(BN_ULLONG) H(tmp) + L(a1b1) + H(a0b0) +
		H(fix) + H(a1b1) -s + ret[2];
	ret[2]=L(tmp);

	tmp=(BN_ULLONG) H(tmp) + H(a1b1) + ret[3];
	ret[3]=L(tmp);
#ifdef DEBUG
fprintf(stdout,"%02X%02X%02X%02X%02X\n",H(tmp),ret[3],ret[2],ret[1],ret[0]);
#endif
	return(H(tmp));
	}

/* ret[3,2,1,0] += a1,a0 * a1,a0 */
void BN_sqr_4words(ret,a0,a1)
BN_ULONG *ret;
BN_ULONG a0,a1;
	{
	BN_ULONG s,u;
	BN_ULLONG tmp,tmp2;

	tmp=(BN_ULLONG)a0*a0;
	ret[0]=L(tmp);

	tmp2=(BN_ULLONG)a0*a1;
	tmp=(BN_ULLONG)H(tmp)+L(tmp2)*2;
	ret[1]=L(tmp);

	tmp=(BN_ULLONG)a1*a1+H(tmp)+H(tmp2)*2;
	ret[2]=L(tmp);
	ret[3]=L(tmp);
	}

#define N0	(0)
#define N1	(half)
#define N2	(num)
#define N3	(num+half)

#define word_cmp(r,a,b,num) \
	{ \
	int n=num; \
\
	(r)=0; \
	while (n--) \
		{ \
		if ((a)[(n)] > (b)[(n)]) \
			{ (r)=1; break; } \
		else if ((a)[(n)] < (b)[(n)]) \
			{ (r)= -1; break; } \
		} \
	}


/* (a->top == b->top) && (a->top >= 2) && !(a->top & 1) */
void bn_recursize_mul(r,t,a,b,num)
BN_ULONG *r,*t,*a,*b;
int num;
	{
	if ((num < 2) || (num&1))
		abort();

/* fprintf(stderr,"num=%d half=%d\n",num,num/2);*/
	if (num == 2)
		BN_mul_4words(r,a[0],a[1],b[0],b[1]);
	else if (num == 4)
		{
		BN_ULONG c,tmp;

		BN_mul_4words(&(r[0]),a[0],a[1],b[0],b[1]);
		BN_mul_4words(&(r[4]),a[2],a[3],b[2],b[3]);

		c =BN_mul_add_4words(&(r[2]),a[0],a[1],b[2],b[3]);
		c+=BN_mul_add_4words(&(r[2]),a[2],a[3],b[0],b[1]);

		bn_add_word(&(r[6]),c,2);
		}
	else
		{
		int half=num/2;
		int carry,cmp_a,cmp_b;

		word_cmp(cmp_a,&(a[0]),&(a[half]),half);
		word_cmp(cmp_b,&(b[0]),&(b[half]),half);

		switch (cmp_a*2+cmp_a+cmp_b)
			{
		case -4:
			bn_sub_words(&(t[N0]),&(a[N1]),&(a[N0]),half);
			bn_sub_words(&(t[N1]),&(b[N0]),&(b[N1]),half);
			bn_recursize_mul(&(r[N1]),&(t[N2]),
				&(t[N0]),&(t[N1]),half);
			bn_sub_words(&(r[N2]),&(r[N2]),&(t[N0]),half);
			carry= -1;
			break;
		case -2:
			bn_sub_words(&(t[N0]),&(a[N1]),&(a[N0]),half);
			bn_sub_words(&(t[N1]),&(b[N0]),&(b[N1]),half);
			bn_recursize_mul(&(r[N1]),&(t[N2]),
				&(t[N0]),&(t[N1]),half);
			carry=0;
			break;
		case 2:
			bn_sub_words(&(t[N0]),&(a[N0]),&(a[N1]),half);
			bn_sub_words(&(t[N1]),&(b[N1]),&(b[N0]),half);
			bn_recursize_mul(&(r[N1]),&(t[N2]),
				&(t[N0]),&(t[N1]),half);
			carry=0;
			break;
		case 4:
			bn_sub_words(&(t[N0]),&(a[N1]),&(a[N0]),half);
			bn_sub_words(&(t[N1]),&(b[N0]),&(b[N1]),half);
			bn_recursize_mul(&(r[N1]),&(t[N2]),
				&(t[N0]),&(t[N1]),half);
			bn_sub_words(&(r[N2]),&(r[N2]),&(t[N1]),half);
			carry= -1;
			break;
		default:
			memset(&(r[N1]),0,sizeof(BN_ULONG)*num);
			break;
			}
		
		bn_recursize_mul(&(t[N0]),&(t[N2]),&(a[N0]),&(b[N0]),half);
#ifdef DEBUG
	pr(a,half," * ");
	pr(b,half," - ");
	pr(t,num," - 0\n");
#endif
		memcpy(&(r[N0]),&(t[N0]),half*sizeof(BN_ULONG));
		if (bn_add_words(&(r[N1]),&(r[N1]),&(t[N1]),half))
			{ bn_add_word(&(t[N1]),1,half); }

		carry+=bn_add_words(&(r[N1]),&(r[N1]),&(t[N0]),num);

		bn_recursize_mul(&(t[N0]),&(t[N2]),&(a[N1]),&(b[N1]),half);

		carry+=bn_add_words(&(r[N1]),&(r[N1]),&(t[N0]),num);
		carry+=bn_add_words(&(r[N2]),&(r[N2]),&(t[N0]),half);
		memcpy(&(r[N3]),&(t[N1]),half*sizeof(BN_ULONG));

		bn_add_word(&(r[N3]),carry,half);
		}
	}

main()
	{
	BIGNUM *a,*b,*r,*t;
	int i,j;

	a=BN_new();
	b=BN_new();
	r=BN_new();
	t=BN_new();

#define BITS 1024
	bn_expand(r,BITS*2);
	bn_expand(t,BITS*2);
	fprintf(stdout,"obase=16\n");
	fprintf(stdout,"ibase=16\n");
	for (i=0; i<10; i++)
		{
		BN_rand(a,BITS,0,0);
		BN_rand(b,BITS,0,0);
		r->top=(BITS*2)/BN_BITS2;
		memset(r->d,0,sizeof(r->top)*sizeof(BN_ULONG));
		memset(t->d,0,sizeof(r->top)*sizeof(BN_ULONG));
		for (j=0; j<1000; j++)
			{

/*			BN_mul(r,a,b); /**/
			bn_recursize_mul(r->d,t->d,a->d,b->d,a->top); /**/
			}
		BN_print(stdout,a); fprintf(stdout," * ");
		BN_print(stdout,b); fprintf(stdout," - ");
		BN_print(stdout,r); fprintf(stdout,"\n");
		}
	}
