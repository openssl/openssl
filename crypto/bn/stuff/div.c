/* crypto/bn/div.c */

#include <stdio.h>
#include "cryptlib.h"
#include "bn.h"

BN_ULONG bn_div_2word();

int BN_div2(dv, rm, num, div,ctx)
BIGNUM *dv;
BIGNUM *rm;
BIGNUM *num;
BIGNUM *div;
BN_CTX *ctx;
	{
	int norm_shift,i,j,nm,nd,loop;
	BIGNUM *tmp,wnum,*snum,*sdiv,*res;
	BN_ULONG *resp,*wnump;
	BN_ULONG d0,d1;
	int num_n,div_n;

#ifdef DEBUG
BN_print(stdout,num); printf(" number\n");
BN_print(stdout,div); printf(" divisor\n");
#endif
	if (BN_is_zero(num))
		{
		BNerr(BN_F_BN_DIV,BN_R_DIV_BY_ZERO);
		return(0);
		}

	if (BN_cmp(num,div) < 0)
		{
		if (rm != NULL)
			{ if (BN_copy(rm,num) == NULL) return(0); }
		if (dv != NULL) BN_zero(dv);
		return(1);
		}

	tmp=ctx->bn[ctx->tos]; 
	snum=ctx->bn[ctx->tos+1];
	sdiv=ctx->bn[ctx->tos+2];
	if (dv == NULL)
		res=ctx->bn[ctx->tos+3];
	else	res=dv;

	/* First we normalise the numbers */
	norm_shift=BN_BITS2-((BN_num_bits(div))%BN_BITS2);
	BN_lshift(sdiv,div,norm_shift);
	norm_shift+=BN_BITS2;
	BN_lshift(snum,num,norm_shift);
	div_n=sdiv->top;
	num_n=snum->top;
	loop=num_n-div_n;
#ifdef DEBUG
BN_print(stdout,snum); printf(" shifted num, forget last word\n");
BN_print(stdout,sdiv); printf(" shifted div\n");
#endif

	/* Lets setup a 'win'dow into snum
	 * This is the part that corresponds to the current
	 * 'area' being divided */
	wnum.d=	 &(snum->d[loop]);
	wnum.top= div_n;
	wnum.max= snum->max; /* a bit of a lie */
	wnum.neg= 0;

	/* Get the top 2 words of sdiv */
	i=sdiv->top;
	d0=sdiv->d[div_n-1];
	d1=sdiv->d[div_n-2];

	/* pointer to the 'top' of snum */
	wnump= &(snum->d[num_n-1]);

	/* Setup to 'res' */
	res->neg=0;
	res->top=loop;
	resp= &(res->d[loop-1]);
	bn_expand(res,(loop+1)*BN_BITS2);

	/* space for temp */
	bn_expand(tmp,(div_n+1)*BN_BITS2);

#ifdef DEBUG
printf("wnum="); BN_print(stdout,&wnum); printf(" initial sub check\n");
printf("div ="); BN_print(stdout,sdiv); printf(" loop=%d\n",loop);
#endif
	if (BN_cmp(&wnum,sdiv) >= 0)
		{
		BN_sub(&wnum,&wnum,sdiv);
		*resp=1;
		res->d[res->top-1]=1;
		}
	else
		res->top--;
	resp--;
#ifdef DEBUG
BN_print(stdout,res); printf(" initial result\n");
BN_print(stdout,&wnum); printf(" wnum\n");
#endif

	for (i=0; i<loop-1; i++)
		{
		BN_ULONG q,n0;
		BN_ULLONG t1,t2,t3;
		BN_ULONG l0;

		wnum.d--;
		wnum.top++;

#ifdef DEBUG
BN_print(stderr,&wnum); printf(" to divide\n");
#endif

		q=0;
		n0=wnump[0];
		t1=((BN_ULLONG)n0<<BN_BITS2)|wnump[-1];
		if (n0 == d0)
			q=BN_MASK2;
		else
			{
			t2=(t1/d0);
			q=(t2&BN_MASK2);
#ifdef DEBUG
printf("t1=%08X / d0=%08X = %X (%X)\n",t1,d0,q,t2);
#endif
			}
		for (;;)
			{
			t2=(BN_ULLONG)d1*q;
			t3=t1-(BN_ULLONG)q*d0;
#ifdef DEBUG
printf("d1*q= %X    n01-q*d0 = %X\n",t2,t3);
#endif
			if ((t3>>BN_BITS2) ||
				(t2 <= ((t3<<BN_BITS2)+wnump[-2])))
				break;
#ifdef DEBUG
printf("reduce q\n");
#endif
			q--;
			}
		l0=bn_mul_word(tmp->d,sdiv->d,div_n,q);
		if (l0)
			tmp->d[div_n]=l0;
		else
			tmp->d[div_n]=0;
		for (j=div_n+1; j>0; j--)
			if (tmp->d[j-1]) break;
		tmp->top=j;

#ifdef DEBUG
printf("q=%08X\n",q);
BN_print(stdout,&wnum); printf(" number\n");
BN_print(stdout,tmp); printf(" subtract\n");

BN_print(stdout,snum); printf(" shifted number before\n");
BN_print(stdout,&wnum); printf(" wnum before\n");
#endif
		j=wnum.top;
		BN_sub(&wnum,&wnum,tmp);
		snum->top=snum->top+wnum.top-j;

#ifdef DEBUG
BN_print(stdout,&wnum); printf(" wnum after\n");
BN_print(stdout,snum); printf(" shifted number after\n");
#endif

		if (wnum.neg)
			{
			q--;
			j=wnum.top;
			BN_add(&wnum,&wnum,sdiv);
			snum->top+=wnum.top-j;
			fprintf(stderr,"addback\n");
#ifdef DEBUG
BN_print(stdout,snum); printf("after addback************************:\n");
#endif
			}
		*(resp--)=q;
#ifdef DEBUG
BN_print(stdout,res); printf(" result\n");
#endif
		wnump--;
		}
	if (rm != NULL)
		BN_rshift(rm,snum,norm_shift);
	return(1);
	}

main()
	{
	BIGNUM *a,*b,*c,*d;
	BIGNUM *cc,*dd;
	BN_CTX *ctx;
	int i,x;

	a=BN_new();
	b=BN_new();
	c=BN_new();
	d=BN_new();
	cc=BN_new();
	dd=BN_new();
	ctx=BN_CTX_new();

for (i=0; i<10240; i++)
	{
	BN_rand(a,80,0,0);
	BN_rand(b,60,0,0);
	
	BN_div2(d,c,a,b,ctx);
	BN_div(dd,cc,a,b,ctx);
	if ((BN_cmp(d,dd) != 0) || (BN_cmp(c,cc) != 0))
		{
		BN_print(stderr,a); fprintf(stderr," / ");
		BN_print(stderr,b); fprintf(stderr," d=");
		BN_print(stderr,d); fprintf(stderr," r= ");
		BN_print(stderr,c); fprintf(stderr,"\nd=");
		BN_print(stderr,dd); fprintf(stderr," r= ");
		BN_print(stderr,cc); fprintf(stderr,"\n");
		}

	}

#ifdef undef
/*
	BN_rand(a,600,0,0);
	BN_rand(b,400,0,0);
	for (i=0; i<2000000; i++)
		{
		BN_div2(d,c,a,b,ctx);
		}
*/
/*	for (i=0;;) */
/*	for (i=0; i<0xffffffff; i++)
		{
		BN_ULONG rr,r,a,b,c;
		BN_ULLONG l;

		a=rand()&BN_MASK2;
		b=rand()&BN_MASK2;
		for (;;)
			{
			c=rand()&BN_MASK2;
			if (c) break;
			}
/*		for (x=1; x<256*256; x++) */
			{
			c=x;
			a=i>>8;
			b=i&0xff;
			a&= ~(0xFFFFFF<<(BN_num_bits_word(c)));

			r=bn_div_2word(a,b,c);

			rr=(BN_ULONG)((((BN_ULLONG)a<<BN_BITS2)|b)/c);

			if ((i & 0xfffff) == 0) fprintf(stderr,"%d\n",i,r,rr); 
/*if (x == 255)
	fprintf(stderr,"%6d/%3d = %4d %4d\n",(a<<8)|b,c,r,rr); */
			if (rr != r)
				{
				fprintf(stderr,"%8d %02X%02X / %02X = %02X %02X\n",
					i,a,b,c,rr,r);
				abort();
				}
			}
		}
#endif
	}

/* Divide h-l by d and return the result. */
BN_ULONG bn_div_2word(l,h,d)
BN_ULONG l,h,d;
	{
	BN_ULONG dh,dl,q,ret=0,th,tl,t,top;
	int i,count=2;

	if (d == 0) return(-1);

	i=BN_num_bits_word(d);
	if ((i != BN_BITS2) && (h > 1<<i))
		{
		fprintf(stderr,"Division would overflow\n");
		abort();
		}
	i=BN_BITS2-i;
	if (h >= d) h-=d;

	if (i)
		{
		d<<=i;
		h=(h<<i)|(l>>(BN_BITS2-i));
		l<<=i;
		}
	dh=(d&BN_MASK2h)>>BN_BITS4;
	dl=(d&BN_MASK2l);
	for (;;)
		{
		if ((h>>BN_BITS4) == dh)
			q=BN_MASK2l;
		else
			q=h/dh;

		for (;;)
			{
			t=(h-q*dh);
			if ((t&BN_MASK2h) ||
				((dl*q) <= (
					(t<<BN_BITS4)+
					((l&BN_MASK2h)>>BN_BITS4))))
				break;
			q--;
			}
		th=q*dh;
		tl=q*dl;
		t=(tl>>BN_BITS4);
		tl=(tl<<BN_BITS4)&BN_MASK2h;
		th+=t;

		if (l < tl) th++;
		l-=tl;
		if (h < th)
			{
			fprintf(stderr,"add back\n");
			h+=d;
			q--;
			}
		h-=th;

		if (--count == 0) break;

		ret=q<<BN_BITS4;
		h=((h<<BN_BITS4)|(l>>BN_BITS4))&BN_MASK2;
		l=(l&BN_MASK2l)<<BN_BITS4;
		}
	ret|=q;
	return(ret);
	}
