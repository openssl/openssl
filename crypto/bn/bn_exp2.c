#include <stdio.h>
#include "cryptlib.h"
#include "bn_lcl.h"

/* I've done some timing with different table sizes.
 * The main hassle is that even with bits set at 3, this requires
 * 63 BIGNUMs to store the pre-calculated values.
 *          512   1024 
 * bits=1  75.4%  79.4%
 * bits=2  61.2%  62.4%
 * bits=3  61.3%  59.3%
 * The lack of speed improvement is also a function of the pre-calculation
 * which could be removed.
 */
#define EXP2_TABLE_BITS	2 /* 1  2  3  4  5  */
#define EXP2_TABLE_SIZE	4 /* 2  4  8 16 32  */

int BN_mod_exp2_mont(BIGNUM *rr, BIGNUM *a1, BIGNUM *p1, BIGNUM *a2,
	     BIGNUM *p2, BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont)
	{
	int i,j,k,bits,bits1,bits2,ret=0,wstart,wend,window,xvalue,yvalue;
	int start=1,ts=0,x,y;
	BIGNUM *d,*aa1,*aa2,*r;
	BIGNUM val[EXP2_TABLE_SIZE][EXP2_TABLE_SIZE];
	BN_MONT_CTX *mont=NULL;

	bn_check_top(a1);
	bn_check_top(p1);
	bn_check_top(a2);
	bn_check_top(p2);
	bn_check_top(m);

	if (!(m->d[0] & 1))
		{
		BNerr(BN_F_BN_MOD_EXP_MONT,BN_R_CALLED_WITH_EVEN_MODULUS);
		return(0);
		}
	bits1=BN_num_bits(p1);
	bits2=BN_num_bits(p2);
	if ((bits1 == 0) && (bits2 == 0))
		{
		BN_one(rr);
		return(1);
		}

	BN_CTX_start(ctx);
	d = BN_CTX_get(ctx);
	r = BN_CTX_get(ctx);
	if (d == NULL || r == NULL) goto err;

	bits=(bits1 > bits2)?bits1:bits2;

	/* If this is not done, things will break in the montgomery
	 * part */

	if (in_mont != NULL)
		mont=in_mont;
	else
		{
		if ((mont=BN_MONT_CTX_new()) == NULL) goto err;
		if (!BN_MONT_CTX_set(mont,m,ctx)) goto err;
		}

	BN_init(&(val[0][0]));
	BN_init(&(val[1][1]));
	BN_init(&(val[0][1]));
	BN_init(&(val[1][0]));
	ts=1;
	if (BN_ucmp(a1,m) >= 0)
		{
		BN_mod(&(val[1][0]),a1,m,ctx);
		aa1= &(val[1][0]);
		}
	else
		aa1=a1;
	if (BN_ucmp(a2,m) >= 0)
		{
		BN_mod(&(val[0][1]),a2,m,ctx);
		aa2= &(val[0][1]);
		}
	else
		aa2=a2;
	if (!BN_to_montgomery(&(val[1][0]),aa1,mont,ctx)) goto err;
	if (!BN_to_montgomery(&(val[0][1]),aa2,mont,ctx)) goto err;
	if (!BN_mod_mul_montgomery(&(val[1][1]),
		&(val[1][0]),&(val[0][1]),mont,ctx))
		goto err;

#if 0
	if (bits <= 20) /* This is probably 3 or 0x10001, so just do singles */
		window=1;
	else if (bits > 250)
		window=5;	/* max size of window */
	else if (bits >= 120)
		window=4;
	else
		window=3;
#else
	window=EXP2_TABLE_BITS;
#endif

	k=1<<window;
	for (x=0; x<k; x++)
		{
		if (x >= 2)
			{
			BN_init(&(val[x][0]));
			BN_init(&(val[x][1]));
			if (!BN_mod_mul_montgomery(&(val[x][0]),
				&(val[1][0]),&(val[x-1][0]),mont,ctx)) goto err;
			if (!BN_mod_mul_montgomery(&(val[x][1]),
				&(val[1][0]),&(val[x-1][1]),mont,ctx)) goto err;
			}
		for (y=2; y<k; y++)
			{
			BN_init(&(val[x][y]));
			if (!BN_mod_mul_montgomery(&(val[x][y]),
				&(val[x][y-1]),&(val[0][1]),mont,ctx))
				goto err;
			}
		}
	ts=k;

	start=1;	/* This is used to avoid multiplication etc
			 * when there is only the value '1' in the
			 * buffer. */
	xvalue=0;	/* The 'x value' of the window */
	yvalue=0;	/* The 'y value' of the window */
	wstart=bits-1;	/* The top bit of the window */
	wend=0;		/* The bottom bit of the window */

        if (!BN_to_montgomery(r,BN_value_one(),mont,ctx)) goto err;
	for (;;)
		{
		xvalue=BN_is_bit_set(p1,wstart);
		yvalue=BN_is_bit_set(p2,wstart);
		if (!(xvalue || yvalue))
			{
			if (!start)
				{
				if (!BN_mod_mul_montgomery(r,r,r,mont,ctx))
					goto err;
				}
			wstart--;
			if (wstart < 0) break;
			continue;
			}
		/* We now have wstart on a 'set' bit, we now need to work out
		 * how bit a window to do.  To do this we need to scan
		 * forward until the last set bit before the end of the
		 * window */
		j=wstart;
		/* xvalue=BN_is_bit_set(p1,wstart); already set */
		/* yvalue=BN_is_bit_set(p1,wstart); already set */
		wend=0;
		for (i=1; i<window; i++)
			{
			if (wstart-i < 0) break;
			xvalue+=xvalue;
			xvalue|=BN_is_bit_set(p1,wstart-i);
			yvalue+=yvalue;
			yvalue|=BN_is_bit_set(p2,wstart-i);
			}

		/* i is the size of the current window */
		/* add the 'bytes above' */
		if (!start)
			for (j=0; j<i; j++)
				{
				if (!BN_mod_mul_montgomery(r,r,r,mont,ctx))
					goto err;
				}
		
		/* wvalue will be an odd number < 2^window */
		if (xvalue || yvalue)
			{
			if (!BN_mod_mul_montgomery(r,r,&(val[xvalue][yvalue]),
				mont,ctx)) goto err;
			}

		/* move the 'window' down further */
		wstart-=i;
		start=0;
		if (wstart < 0) break;
		}
	BN_from_montgomery(rr,r,mont,ctx);
	ret=1;
err:
	if ((in_mont == NULL) && (mont != NULL)) BN_MONT_CTX_free(mont);
	BN_CTX_end(ctx);
	for (i=0; i<ts; i++)
		{
		for (j=0; j<ts; j++)
			{
			BN_clear_free(&(val[i][j]));
			}
		}
	return(ret);
	}
