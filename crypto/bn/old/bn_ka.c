#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include "bn_lcl.h"

/* r is 2*n2 words in size,
 * a and b are both n2 words in size.
 * n2 must be a power of 2.
 * We multiply and return the result.
 * t must be 2*n2 words in size
 * We calulate
 * a[0]*b[0]
 * a[0]*b[0]+a[1]*b[1]+(a[0]-a[1])*(b[1]-b[0])
 * a[1]*b[1]
 */
void bn_mul_recursive(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b, int n2,
	     BN_ULONG *t)
	{
	int n=n2/2;
	int neg,zero,c1,c2;
	BN_ULONG ln,lo,*p;

#ifdef BN_COUNT
printf(" bn_mul_recursive %d * %d\n",n2,n2);
#endif
	if (n2 <= 8)
		{
		if (n2 == 8)
			bn_mul_comba8(r,a,b);
		else
			bn_mul_normal(r,a,n2,b,n2);
		return;
		}

	if (n2 < BN_MUL_RECURSIVE_SIZE_NORMAL)
		{
		/* This should not happen */
		/*abort(); */
		bn_mul_normal(r,a,n2,b,n2);
		return;
		}
	/* r=(a[0]-a[1])*(b[1]-b[0]) */
	c1=bn_cmp_words(a,&(a[n]),n);
	c2=bn_cmp_words(&(b[n]),b,n);
	zero=neg=0;
	switch (c1*3+c2)
		{
	case -4:
		bn_sub_words(t,      &(a[n]),a,      n); /* - */
		bn_sub_words(&(t[n]),b,      &(b[n]),n); /* - */
		break;
	case -3:
		zero=1;
		break;
	case -2:
		bn_sub_words(t,      &(a[n]),a,      n); /* - */
		bn_sub_words(&(t[n]),&(b[n]),b,      n); /* + */
		neg=1;
		break;
	case -1:
	case 0:
	case 1:
		zero=1;
		break;
	case 2:
		bn_sub_words(t,      a,      &(a[n]),n); /* + */
		bn_sub_words(&(t[n]),b,      &(b[n]),n); /* - */
		neg=1;
		break;
	case 3:
		zero=1;
		break;
	case 4:
		bn_sub_words(t,      a,      &(a[n]),n);
		bn_sub_words(&(t[n]),&(b[n]),b,      n);
		break;
		}

	if (n == 8)
		{
		if (!zero)
			bn_mul_comba8(&(t[n2]),t,&(t[n]));
		else
			memset(&(t[n2]),0,8*sizeof(BN_ULONG));
		
		bn_mul_comba8(r,a,b);
		bn_mul_comba8(&(r[n2]),&(a[n]),&(b[n]));
		}
	else
		{
		p= &(t[n2*2]);
		if (!zero)
			bn_mul_recursive(&(t[n2]),t,&(t[n]),n,p);
		else
			memset(&(t[n2]),0,n*sizeof(BN_ULONG));
		bn_mul_recursive(r,a,b,n,p);
		bn_mul_recursive(&(r[n2]),&(a[n]),&(b[n]),n,p);
		}

	/* t[32] holds (a[0]-a[1])*(b[1]-b[0]), c1 is the sign
	 * r[10] holds (a[0]*b[0])
	 * r[32] holds (b[1]*b[1])
	 */

	c1=bn_add_words(t,r,&(r[n2]),n2);

	if (neg) /* if t[32] is negative */
		{
		c1-=bn_sub_words(&(t[n2]),t,&(t[n2]),n2);
		}
	else
		{
		/* Might have a carry */
		c1+=bn_add_words(&(t[n2]),&(t[n2]),t,n2);
		}

	/* t[32] holds (a[0]-a[1])*(b[1]-b[0])+(a[0]*b[0])+(a[1]*b[1])
	 * r[10] holds (a[0]*b[0])
	 * r[32] holds (b[1]*b[1])
	 * c1 holds the carry bits
	 */
	c1+=bn_add_words(&(r[n]),&(r[n]),&(t[n2]),n2);
	if (c1)
		{
		p= &(r[n+n2]);
		lo= *p;
		ln=(lo+c1)&BN_MASK2;
		*p=ln;

		/* The overflow will stop before we over write
		 * words we should not overwrite */
		if (ln < c1)
			{
			do	{
				p++;
				lo= *p;
				ln=(lo+1)&BN_MASK2;
				*p=ln;
				} while (ln == 0);
			}
		}
	}

/* n+tn is the word length
 * t needs to be n*4 is size, as does r */
void bn_mul_part_recursive(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b, int tn,
	     int n, BN_ULONG *t)
	{
	int n2=n*2,i,j;
	int c1;
	BN_ULONG ln,lo,*p;

#ifdef BN_COUNT
printf(" bn_mul_part_recursive %d * %d\n",tn+n,tn+n);
#endif
	if (n < 8)
		{
		i=tn+n;
		bn_mul_normal(r,a,i,b,i);
		return;
		}

	/* r=(a[0]-a[1])*(b[1]-b[0]) */
	bn_sub_words(t,      a,      &(a[n]),n); /* + */
	bn_sub_words(&(t[n]),b,      &(b[n]),n); /* - */

	if (n == 8)
		{
		bn_mul_comba8(&(t[n2]),t,&(t[n]));
		bn_mul_comba8(r,a,b);
		bn_mul_normal(&(r[n2]),&(a[n]),tn,&(b[n]),tn);
		memset(&(r[n2+tn*2]),0,sizeof(BN_ULONG)*(n2-tn*2));
		}
	else
		{
		p= &(t[n2*2]);
		bn_mul_recursive(&(t[n2]),t,&(t[n]),n,p);
		bn_mul_recursive(r,a,b,n,p);
		i=n/2;
		/* If there is only a bottom half to the number,
		 * just do it */
		j=tn-i;
		if (j == 0)
			{
			bn_mul_recursive(&(r[n2]),&(a[n]),&(b[n]),i,p);
			memset(&(r[n2+i*2]),0,sizeof(BN_ULONG)*(n2-i*2));
			}
		else if (j > 0) /* eg, n == 16, i == 8 and tn == 11 */
				{
				bn_mul_part_recursive(&(r[n2]),&(a[n]),&(b[n]),
					j,i,p);
				memset(&(r[n2+tn*2]),0,
					sizeof(BN_ULONG)*(n2-tn*2));
				}
		else /* (j < 0) eg, n == 16, i == 8 and tn == 5 */
			{
			memset(&(r[n2]),0,sizeof(BN_ULONG)*(tn*2));
			for (;;)
				{
				i/=2;
				if (i < tn)
					{
					bn_mul_part_recursive(&(r[n2]),
						&(a[n]),&(b[n]),
						tn-i,i,p);
					break;
					}
				else if (i == tn)
					{
					bn_mul_recursive(&(r[n2]),
						&(a[n]),&(b[n]),
						i,p);
					break;
					}
				}
			}
		}

	/* t[32] holds (a[0]-a[1])*(b[1]-b[0]), c1 is the sign
	 * r[10] holds (a[0]*b[0])
	 * r[32] holds (b[1]*b[1])
	 */

	c1=bn_add_words(t,r,&(r[n2]),n2);
	c1-=bn_sub_words(&(t[n2]),t,&(t[n2]),n2);

	/* t[32] holds (a[0]-a[1])*(b[1]-b[0])+(a[0]*b[0])+(a[1]*b[1])
	 * r[10] holds (a[0]*b[0])
	 * r[32] holds (b[1]*b[1])
	 * c1 holds the carry bits
	 */
	c1+=bn_add_words(&(r[n]),&(r[n]),&(t[n2]),n2);
	if (c1)
		{
		p= &(r[n+n2]);
		lo= *p;
		ln=(lo+c1)&BN_MASK2;
		*p=ln;

		/* The overflow will stop before we over write
		 * words we should not overwrite */
		if (ln < c1)
			{
			do	{
				p++;
				lo= *p;
				ln=(lo+1)&BN_MASK2;
				*p=ln;
				} while (ln == 0);
			}
		}
	}

/* r is 2*n words in size,
 * a and b are both n words in size.
 * n must be a power of 2.
 * We multiply and return the result.
 * t must be 2*n words in size
 * We calulate
 * a[0]*b[0]
 * a[0]*b[0]+a[1]*b[1]+(a[0]-a[1])*(b[1]-b[0])
 * a[1]*b[1]
 */
void bn_sqr_recursive(BN_ULONG *r, BN_ULONG *a, int n2, BN_ULONG *t)
	{
	int n=n2/2;
	int zero,c1;
	BN_ULONG ln,lo,*p;

#ifdef BN_COUNT
printf(" bn_sqr_recursive %d * %d\n",n2,n2);
#endif
	if (n2 == 4)
		{
		bn_sqr_comba4(r,a);
		return;
		}
	else if (n2 == 8)
		{
		bn_sqr_comba8(r,a);
		return;
		}
	if (n2 < BN_SQR_RECURSIVE_SIZE_NORMAL)
		{
		bn_sqr_normal(r,a,n2,t);
		return;
		abort();
		}
	/* r=(a[0]-a[1])*(a[1]-a[0]) */
	c1=bn_cmp_words(a,&(a[n]),n);
	zero=0;
	if (c1 > 0)
		bn_sub_words(t,a,&(a[n]),n);
	else if (c1 < 0)
		bn_sub_words(t,&(a[n]),a,n);
	else
		zero=1;

	/* The result will always be negative unless it is zero */

	if (n == 8)
		{
		if (!zero)
			bn_sqr_comba8(&(t[n2]),t);
		else
			memset(&(t[n2]),0,8*sizeof(BN_ULONG));
		
		bn_sqr_comba8(r,a);
		bn_sqr_comba8(&(r[n2]),&(a[n]));
		}
	else
		{
		p= &(t[n2*2]);
		if (!zero)
			bn_sqr_recursive(&(t[n2]),t,n,p);
		else
			memset(&(t[n2]),0,n*sizeof(BN_ULONG));
		bn_sqr_recursive(r,a,n,p);
		bn_sqr_recursive(&(r[n2]),&(a[n]),n,p);
		}

	/* t[32] holds (a[0]-a[1])*(a[1]-a[0]), it is negative or zero
	 * r[10] holds (a[0]*b[0])
	 * r[32] holds (b[1]*b[1])
	 */

	c1=bn_add_words(t,r,&(r[n2]),n2);

	/* t[32] is negative */
	c1-=bn_sub_words(&(t[n2]),t,&(t[n2]),n2);

	/* t[32] holds (a[0]-a[1])*(a[1]-a[0])+(a[0]*a[0])+(a[1]*a[1])
	 * r[10] holds (a[0]*a[0])
	 * r[32] holds (a[1]*a[1])
	 * c1 holds the carry bits
	 */
	c1+=bn_add_words(&(r[n]),&(r[n]),&(t[n2]),n2);
	if (c1)
		{
		p= &(r[n+n2]);
		lo= *p;
		ln=(lo+c1)&BN_MASK2;
		*p=ln;

		/* The overflow will stop before we over write
		 * words we should not overwrite */
		if (ln < c1)
			{
			do	{
				p++;
				lo= *p;
				ln=(lo+1)&BN_MASK2;
				*p=ln;
				} while (ln == 0);
			}
		}
	}

#if 1
/* a and b must be the same size, which is n2.
 * r needs to be n2 words and t needs to be n2*2
 */
void bn_mul_low_recursive(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b, int n2,
	     BN_ULONG *t)
	{
	int n=n2/2;

#ifdef BN_COUNT
printf(" bn_mul_low_recursive %d * %d\n",n2,n2);
#endif

	bn_mul_recursive(r,a,b,n,&(t[0]));
	if (n > BN_MUL_LOW_RECURSIVE_SIZE_NORMAL)
		{
		bn_mul_low_recursive(&(t[0]),&(a[0]),&(b[n]),n,&(t[n2]));
		bn_add_words(&(r[n]),&(r[n]),&(t[0]),n);
		bn_mul_low_recursive(&(t[0]),&(a[n]),&(b[0]),n,&(t[n2]));
		bn_add_words(&(r[n]),&(r[n]),&(t[0]),n);
		}
	else
		{
		bn_mul_low_normal(&(t[0]),&(a[0]),&(b[n]),n);
		bn_mul_low_normal(&(t[n]),&(a[n]),&(b[0]),n);
		bn_add_words(&(r[n]),&(r[n]),&(t[0]),n);
		bn_add_words(&(r[n]),&(r[n]),&(t[n]),n);
		}
	}

/* a and b must be the same size, which is n2.
 * r needs to be n2 words and t needs to be n2*2
 * l is the low words of the output.
 * t needs to be n2*3
 */
void bn_mul_high(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b, BN_ULONG *l, int n2,
	     BN_ULONG *t)
	{
	int j,i,n,c1,c2;
	int neg,oneg,zero;
	BN_ULONG ll,lc,*lp,*mp;

#ifdef BN_COUNT
printf(" bn_mul_high %d * %d\n",n2,n2);
#endif
	n=(n2+1)/2;

	/* Calculate (al-ah)*(bh-bl) */
	neg=zero=0;
	c1=bn_cmp_words(&(a[0]),&(a[n]),n);
	c2=bn_cmp_words(&(b[n]),&(b[0]),n);
	switch (c1*3+c2)
		{
	case -4:
		bn_sub_words(&(r[0]),&(a[n]),&(a[0]),n);
		bn_sub_words(&(r[n]),&(b[0]),&(b[n]),n);
		break;
	case -3:
		zero=1;
		break;
	case -2:
		bn_sub_words(&(r[0]),&(a[n]),&(a[0]),n);
		bn_sub_words(&(r[n]),&(b[n]),&(b[0]),n);
		neg=1;
		break;
	case -1:
	case 0:
	case 1:
		zero=1;
		break;
	case 2:
		bn_sub_words(&(r[0]),&(a[0]),&(a[n]),n);
		bn_sub_words(&(r[n]),&(b[0]),&(b[n]),n);
		neg=1;
		break;
	case 3:
		zero=1;
		break;
	case 4:
		bn_sub_words(&(r[0]),&(a[0]),&(a[n]),n);
		bn_sub_words(&(r[n]),&(b[n]),&(b[0]),n);
		break;
		}
		
	oneg=neg;
	/* t[10] = (a[0]-a[1])*(b[1]-b[0]) */
	bn_mul_recursive(&(t[0]),&(r[0]),&(r[n]),n,&(t[n2]));
	/* r[10] = (a[1]*b[1]) */
	bn_mul_recursive(r,&(a[n]),&(b[n]),n,&(t[n2]));

	/* s0 == low(al*bl)
	 * s1 == low(ah*bh)+low((al-ah)*(bh-bl))+low(al*bl)+high(al*bl)
	 * We know s0 and s1 so the only unknown is high(al*bl)
	 * high(al*bl) == s1 - low(ah*bh+s0+(al-ah)*(bh-bl))
	 * high(al*bl) == s1 - (r[0]+l[0]+t[0])
	 */
	if (l != NULL)
		{
		lp= &(t[n2+n]);
		c1=bn_add_words(lp,&(r[0]),&(l[0]),n);
		}
	else
		{
		c1=0;
		lp= &(r[0]);
		}

	if (neg)
		neg=bn_sub_words(&(t[n2]),lp,&(t[0]),n);
	else
		{
		bn_add_words(&(t[n2]),lp,&(t[0]),n);
		neg=0;
		}

	if (l != NULL)
		{
		bn_sub_words(&(t[n2+n]),&(l[n]),&(t[n2]),n);
		}
	else
		{
		lp= &(t[n2+n]);
		mp= &(t[n2]);
		for (i=0; i<n; i++)
			lp[i]=((~mp[i])+1)&BN_MASK2;
		}

	/* s[0] = low(al*bl)
	 * t[3] = high(al*bl)
	 * t[10] = (a[0]-a[1])*(b[1]-b[0]) neg is the sign
	 * r[10] = (a[1]*b[1])
	 */
	/* R[10] = al*bl
	 * R[21] = al*bl + ah*bh + (a[0]-a[1])*(b[1]-b[0])
	 * R[32] = ah*bh
	 */
	/* R[1]=t[3]+l[0]+r[0](+-)t[0] (have carry/borrow)
	 * R[2]=r[0]+t[3]+r[1](+-)t[1] (have carry/borrow)
	 * R[3]=r[1]+(carry/borrow)
	 */
	if (l != NULL)
		{
		lp= &(t[n2]);
		c1= bn_add_words(lp,&(t[n2+n]),&(l[0]),n);
		}
	else
		{
		lp= &(t[n2+n]);
		c1=0;
		}
	c1+=bn_add_words(&(t[n2]),lp,  &(r[0]),n);
	if (oneg)
		c1-=bn_sub_words(&(t[n2]),&(t[n2]),&(t[0]),n);
	else
		c1+=bn_add_words(&(t[n2]),&(t[n2]),&(t[0]),n);

	c2 =bn_add_words(&(r[0]),&(r[0]),&(t[n2+n]),n);
	c2+=bn_add_words(&(r[0]),&(r[0]),&(r[n]),n);
	if (oneg)
		c2-=bn_sub_words(&(r[0]),&(r[0]),&(t[n]),n);
	else
		c2+=bn_add_words(&(r[0]),&(r[0]),&(t[n]),n);
	
	if (c1 != 0) /* Add starting at r[0], could be +ve or -ve */
		{
		i=0;
		if (c1 > 0)
			{
			lc=c1;
			do	{
				ll=(r[i]+lc)&BN_MASK2;
				r[i++]=ll;
				lc=(lc > ll);
				} while (lc);
			}
		else
			{
			lc= -c1;
			do	{
				ll=r[i];
				r[i++]=(ll-lc)&BN_MASK2;
				lc=(lc > ll);
				} while (lc);
			}
		}
	if (c2 != 0) /* Add starting at r[1] */
		{
		i=n;
		if (c2 > 0)
			{
			lc=c2;
			do	{
				ll=(r[i]+lc)&BN_MASK2;
				r[i++]=ll;
				lc=(lc > ll);
				} while (lc);
			}
		else
			{
			lc= -c2;
			do	{
				ll=r[i];
				r[i++]=(ll-lc)&BN_MASK2;
				lc=(lc > ll);
				} while (lc);
			}
		}
	}
#endif
