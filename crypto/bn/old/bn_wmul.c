#include <stdio.h>
#include "bn_lcl.h"

#if 1

int bn_mull(BIGNUM *r,BIGNUM *a,BIGNUM *b, BN_CTX *ctx);

int bn_mull(BIGNUM *r, BIGNUM *a, BIGNUM *b, BN_CTX *ctx)
	{
	int top,i,j,k,al,bl;
	BIGNUM *t;

#ifdef BN_COUNT
printf("bn_mull %d * %d\n",a->top,b->top);
#endif

	bn_check_top(a);
	bn_check_top(b);
	bn_check_top(r);

	al=a->top;
	bl=b->top;
	r->neg=a->neg^b->neg;

	top=al+bl;
	if ((al < 4) || (bl < 4))
		{
		if (bn_wexpand(r,top) == NULL) return(0);
		r->top=top;
		bn_mul_normal(r->d,a->d,al,b->d,bl);
		goto end;
		}
	else if (al == bl) /* A good start, they are the same size */
		goto symetric;
	else
		{
		i=(al-bl);
		if ((i ==  1) && !BN_get_flags(b,BN_FLG_STATIC_DATA))
			{
			bn_wexpand(b,al);
			b->d[bl]=0;
			bl++;
			goto symetric;
			}
		else if ((i ==  -1) && !BN_get_flags(a,BN_FLG_STATIC_DATA))
			{
			bn_wexpand(a,bl);
			a->d[al]=0;
			al++;
			goto symetric;
			}
		}

	/* asymetric and >= 4 */ 
	if (bn_wexpand(r,top) == NULL) return(0);
	r->top=top;
	bn_mul_normal(r->d,a->d,al,b->d,bl);

	if (0)
		{
		/* symetric and > 4 */
symetric:
		if (al == 4)
			{
			if (bn_wexpand(r,al*2) == NULL) return(0);
			r->top=top;
			bn_mul_comba4(r->d,a->d,b->d);
			goto end;
			}
		if (al == 8)
			{
			if (bn_wexpand(r,al*2) == NULL) return(0);
			r->top=top;
			bn_mul_comba8(r->d,a->d,b->d);
			goto end;
			}
		if (al <= BN_MULL_NORMAL_SIZE)
			{
			if (bn_wexpand(r,al*2) == NULL) return(0);
			r->top=top;
			bn_mul_normal(r->d,a->d,al,b->d,bl);
			goto end;
			}
		/* 16 or larger */
		j=BN_num_bits_word((BN_ULONG)al);
		j=1<<(j-1);
		k=j+j;
		t= &(ctx->bn[ctx->tos]);
		if (al == j) /* exact multiple */
			{
			bn_wexpand(t,k*2);
			bn_wexpand(r,k*2);
			bn_mul_recursive(r->d,a->d,b->d,al,t->d);
			}
		else
			{
			bn_wexpand(a,k);
			bn_wexpand(b,k);
			bn_wexpand(t,k*4);
			bn_wexpand(r,k*4);
			for (i=a->top; i<k; i++)
				a->d[i]=0;
			for (i=b->top; i<k; i++)
				b->d[i]=0;
			bn_mul_part_recursive(r->d,a->d,b->d,al-j,j,t->d);
			}
		r->top=top;
		}
end:
	bn_fix_top(r);
	return(1);
	}
#endif

void bn_mul_normal(BN_ULONG *r, BN_ULONG *a, int na, BN_ULONG *b, int nb)
	{
	BN_ULONG *rr;

#ifdef BN_COUNT
printf(" bn_mul_normal %d * %d\n",na,nb);
#endif

	if (na < nb)
		{
		int itmp;
		BN_ULONG *ltmp;

		itmp=na; na=nb; nb=itmp;
		ltmp=a;   a=b;   b=ltmp;

		}
	rr= &(r[na]);
	rr[0]=bn_mul_words(r,a,na,b[0]);

	for (;;)
		{
		if (--nb <= 0) return;
		rr[1]=bn_mul_add_words(&(r[1]),a,na,b[1]);
		if (--nb <= 0) return;
		rr[2]=bn_mul_add_words(&(r[2]),a,na,b[2]);
		if (--nb <= 0) return;
		rr[3]=bn_mul_add_words(&(r[3]),a,na,b[3]);
		if (--nb <= 0) return;
		rr[4]=bn_mul_add_words(&(r[4]),a,na,b[4]);
		rr+=4;
		r+=4;
		b+=4;
		}
	}

#if 1
void bn_mul_low_normal(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b, int n)
	{
#ifdef BN_COUNT
printf(" bn_mul_low_normal %d * %d\n",n,n);
#endif
	bn_mul_words(r,a,n,b[0]);

	for (;;)
		{
		if (--n <= 0) return;
		bn_mul_add_words(&(r[1]),a,n,b[1]);
		if (--n <= 0) return;
		bn_mul_add_words(&(r[2]),a,n,b[2]);
		if (--n <= 0) return;
		bn_mul_add_words(&(r[3]),a,n,b[3]);
		if (--n <= 0) return;
		bn_mul_add_words(&(r[4]),a,n,b[4]);
		r+=4;
		b+=4;
		}
	}
#endif
