#include <stdio.h>
#include "cryptlib.h"
#include "bn_lcl.h"

#define SIZE	32

#define BN_MONT_CTX_set		bn_mcs
#define BN_from_montgomery	bn_fm
#define BN_mod_mul_montgomery	bn_mmm
#undef BN_to_montgomery
#define BN_to_montgomery(r,a,mont,ctx)	bn_mmm(\
	r,a,(mont)->RR,(mont),ctx)

main()
	{
	BIGNUM prime,a,b,r,A,B,R;
	BN_MONT_CTX *mont;
	BN_CTX *ctx;
	int i;

	ctx=BN_CTX_new();
	BN_init(&prime);
	BN_init(&a); BN_init(&b); BN_init(&r);
	BN_init(&A); BN_init(&B); BN_init(&R);

	BN_generate_prime(&prime,SIZE,0,NULL,NULL,NULL,NULL);
	BN_rand(&A,SIZE,1,0);
	BN_rand(&B,SIZE,1,0);
	BN_mod(&A,&A,&prime,ctx);
	BN_mod(&B,&B,&prime,ctx);

	i=A.top;
	BN_mul(&R,&A,&B,ctx);
	BN_mask_bits(&R,i*BN_BITS2);


	BN_print_fp(stdout,&A); printf(" <- a\n");
	BN_print_fp(stdout,&B); printf(" <- b\n");
	BN_mul_high(&r,&A,&B,&R,i);
	BN_print_fp(stdout,&r); printf(" <- high(BA*DC)\n");

	BN_mask_bits(&A,i*32);
	BN_mask_bits(&B,i*32);

	BN_mul(&R,&A,&B);
	BN_rshift(&R,&R,i*32);
	BN_print_fp(stdout,&R); printf(" <- norm BA*DC\n");
	BN_sub(&R,&R,&r);
	BN_print_fp(stdout,&R); printf(" <- diff\n");
	}

#if 0
int bn_mul_high(BIGNUM *r, BIGNUM *a, BIGNUM *b, BIGNUM *low, int words)
	{
	int i;
	BIGNUM t1,t2,t3,h,ah,al,bh,bl,m,s0,s1;

	BN_init(&al); BN_init(&ah);
	BN_init(&bl); BN_init(&bh);
	BN_init(&t1); BN_init(&t2); BN_init(&t3);
	BN_init(&s0); BN_init(&s1);
	BN_init(&h); BN_init(&m);

	i=a->top;
	if (i >= words)
		{
		al.top=words;
		ah.top=a->top-words;
		ah.d= &(a->d[ah.top]);
		}
	else
		al.top=i;
	al.d=a->d;

	i=b->top;
	if (i >= words)
		{
		bl.top=words;
		bh.top=i-words;
		bh.d= &(b->d[bh.top]);
		}
	else
		bl.top=i;
	bl.d=b->d;

	i=low->top;
	if (i >= words)
		{
		s0.top=words;
		s1.top=i-words;
		s1.d= &(low->d[s1.top]);
		}
	else
		s0.top=i;
	s0.d=low->d;

al.max=al.top; ah.max=ah.top;
bl.max=bl.top; bh.max=bh.top;
s0.max=bl.top; s1.max=bh.top;

	/* Calculate (al-ah)*(bh-bl) */
	BN_sub(&t1,&al,&ah);
	BN_sub(&t2,&bh,&bl);
	BN_mul(&m,&t1,&t2);

	/* Calculate ah*bh */
	BN_mul(&h,&ah,&bh);

	/* s0 == low(al*bl)
	 * s1 == low(ah*bh)+low((al-ah)*(bh-bl))+low(al*bl)+high(al*bl)
	 * We know s0 and s1 so the only unknown is high(al*bl)
	 * high(al*bl) == s1 - low(ah*bh+(al-ah)*(bh-bl)+s0)
	 */
	BN_add(&m,&m,&h);
	BN_add(&t2,&m,&s0);
	/* Quick and dirty mask off of high words */
	t3.d=t2.d;
	t3.top=(t2.top > words)?words:t2.top;
	t3.neg=t2.neg;
t3.max=t3.top;
/* BN_print_fp(stdout,&s1); printf(" s1\n"); */
/* BN_print_fp(stdout,&t2); printf(" middle value\n"); */
/* BN_print_fp(stdout,&t3); printf(" low middle value\n"); */
	BN_sub(&t1,&s1,&t3);

	if (t1.neg)
		{
/*printf("neg fixup\n"); BN_print_fp(stdout,&t1); printf(" before\n"); */
		BN_lshift(&t2,BN_value_one(),words*32);
		BN_add(&t1,&t2,&t1);
		BN_mask_bits(&t1,words*32);
/* BN_print_fp(stdout,&t1); printf(" after\n"); */
		}
	/* al*bl == high(al*bl)<<words+s0 */
	BN_lshift(&t1,&t1,words*32);
	BN_add(&t1,&t1,&s0);
	
	/* We now have
	 * al*bl			- t1
	 * (al-ah)*(bh-bl)+ah*bh	- m
	 * ah*bh			- h
	 */
	BN_copy(r,&t1);
	BN_mask_bits(r,words*32*2);

	/*BN_lshift(&m,&m,words*/

	BN_free(&t1); BN_free(&t2);
	BN_free(&m); BN_free(&h);
	}

int BN_mod_mul_montgomery(BIGNUM *r, BIGNUM *a, BIGNUM *b, BN_MONT_CTX *mont,
	     BN_CTX *ctx)
	{
	BIGNUM *tmp;

        tmp= &(ctx->bn[ctx->tos++]);

	if (a == b)
		{
		if (!BN_sqr(tmp,a,ctx)) goto err;
		}
	else
		{
		if (!BN_mul(tmp,a,b)) goto err;
		}
	/* reduce from aRR to aR */
	if (!BN_from_montgomery(r,tmp,mont,ctx)) goto err;
	ctx->tos--;
	return(1);
err:
	return(0);
	}

int BN_from_montgomery(BIGNUM *r, BIGNUM *a, BN_MONT_CTX *mont, BN_CTX *ctx)
	{
	BIGNUM z1;
	BIGNUM *t1,*t2;
	BN_ULONG *ap,*bp,*rp;
	int j,i,bl,al;

	BN_init(&z1);
	t1= &(ctx->bn[ctx->tos]);
	t2= &(ctx->bn[ctx->tos+1]);

	if (!BN_copy(t1,a)) goto err;
	/* can cheat */
	BN_mask_bits(t1,mont->ri);
	if (!BN_mul(t2,t1,mont->Ni)) goto err;
	BN_mask_bits(t2,mont->ri);

	if (!BN_mul(t1,t2,mont->N)) goto err;
	if (!BN_add(t2,t1,a)) goto err;

	/* At this point, t2 has the bottom ri bits set to zero.
	 * This means that the bottom ri bits == the 1^ri minus the bottom
	 * ri bits of a.
	 * This means that only the bits above 'ri' in a need to be added,
	 * and XXXXXXXXXXXXXXXXXXXXXXXX
	 */
BN_print_fp(stdout,t2); printf("\n");
	BN_rshift(r,t2,mont->ri);

	if (BN_ucmp(r,mont->N) >= 0)
		BN_usub(r,r,mont->N);

	return(1);
err:
	return(0);
	}

int BN_MONT_CTX_set(BN_MONT_CTX *mont, BIGNUM *mod, BN_CTX *ctx)
	{
	BIGNUM *Ri=NULL,*R=NULL;

	if (mont->RR == NULL) mont->RR=BN_new();
	if (mont->N == NULL)  mont->N=BN_new();

	R=mont->RR;					/* grab RR as a temp */
	BN_copy(mont->N,mod);				/* Set N */

	mont->ri=(BN_num_bits(mod)+(BN_BITS2-1))/BN_BITS2*BN_BITS2;
	BN_lshift(R,BN_value_one(),mont->ri);			/* R */
	if ((Ri=BN_mod_inverse(NULL,R,mod,ctx)) == NULL) goto err;/* Ri */
	BN_lshift(Ri,Ri,mont->ri);				/* R*Ri */
	BN_usub(Ri,Ri,BN_value_one());				/* R*Ri - 1 */
	BN_div(Ri,NULL,Ri,mod,ctx);
	if (mont->Ni != NULL) BN_free(mont->Ni);
	mont->Ni=Ri;					/* Ni=(R*Ri-1)/N */

	/* setup RR for conversions */
	BN_lshift(mont->RR,BN_value_one(),mont->ri*2);
	BN_mod(mont->RR,mont->RR,mont->N,ctx);

	return(1);
err:
	return(0);
	}


#endif
