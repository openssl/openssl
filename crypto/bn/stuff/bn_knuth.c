/* crypto/bn/bn_knuth.c */

#include <stdio.h>
#include "cryptlib.h"
#include "bn.h"

/* This is just a test implementation, it has not been modified for
 * speed and it still has memory leaks. */

int BN_mask_bits(BIGNUM *a,int n);

#undef DEBUG
#define MAIN

/* r must be different to a and b
 * Toom-Cook multiplication algorithm, taken from
 * The Art Of Computer Programming, Volume 2, Donald Knuth
 */

#define	CODE1		((BIGNUM *)0x01)
#define	CODE2		((BIGNUM *)0x02)
#define	CODE3		((BIGNUM *)0x03)
#define MAXK		(30+1)

#define C3	3
#define C4	4
#define C5	5
#define C6	6
#define C7	7
#define C8	8
#define C9	9
#define C10	10
#define DONE	11

int new_total=0;
int Free_total=0;
int max=0,max_total=0;

BIGNUM *LBN_new(void );
BIGNUM *LBN_dup(BIGNUM *a);
void LBN_free(BIGNUM *a);

int BN_mul_knuth(w, a, b)
BIGNUM *w;
BIGNUM *a;
BIGNUM *b;
	{
	int ret=1;
	int i,j,n,an,bn,y,z;
	BIGNUM *U[MAXK],*V[MAXK],*T[MAXK];
	BIGNUM *C[(MAXK*2*3)];
	BIGNUM *W[(MAXK*2)],*t1,*t2,*t3,*t4;
	int Utos,Vtos,Ctos,Wtos,Ttos;
	unsigned int k,Q,R;
	unsigned int q[MAXK];
	unsigned int r[MAXK];
	int state;

	/* C1 */
	Utos=Vtos=Ctos=Wtos=Ttos=0;
	k=1;
	q[0]=q[1]=64;
	r[0]=r[1]=4;
	Q=6;
	R=2;

	if (!bn_expand(w,BN_BITS2*2)) goto err;
	an=BN_num_bits(a);
	bn=BN_num_bits(b);
	n=(an > bn)?an:bn;
	while ((q[k-1]+q[k]) < n)
		{
		k++;
		Q+=R;
		i=R+1;
		if ((i*i) <= Q) R=i;
		q[k]=(1<<Q);
		r[k]=(1<<R);
		}
#ifdef DEBUG
	printf("k   =");
	for (i=0; i<=k; i++) printf("%7d",i);
	printf("\nq[k]=");
	for (i=0; i<=k; i++) printf("%7d",q[i]);
	printf("\nr[k]=");
	for (i=0; i<=k; i++) printf("%7d",r[i]);
	printf("\n");
#endif

	/* C2 */
	C[Ctos++]=CODE1;
	if ((t1=LBN_dup(a)) == NULL) goto err;
	C[Ctos++]=t1;
	if ((t1=LBN_dup(b)) == NULL) goto err;
	C[Ctos++]=t1;

	state=C3;
	for (;;)
		{
#ifdef DEBUG
		printf("state=C%d, Ctos=%d Wtos=%d\n",state,Ctos,Wtos);
#endif
		switch (state)
			{
			int lr,lq,lp;
		case C3:
			k--;
			if (k == 0)
				{
				t1=C[--Ctos];
				t2=C[--Ctos];
#ifdef DEBUG
				printf("Ctos=%d poped %d\n",Ctos,2);
#endif
				if ((t2->top == 0) || (t1->top == 0))
					w->top=0;
				else
					BN_mul(w,t1,t2);

				LBN_free(t1); /* FREE */
				LBN_free(t2); /* FREE */
				state=C10;
				}
			else
				{
				lr=r[k];
				lq=q[k];
				lp=q[k-1]+q[k];
				state=C4;
				}
			break;
		case C4:
			for (z=0; z<2; z++) /* do for u and v */
				{
				/* break the item at C[Ctos-1] 
				 * into lr+1 parts of lq bits each
				 * for j=0; j<=2r; j++
				 */
				t1=C[--Ctos]; /* pop off u */
#ifdef DEBUG
				printf("Ctos=%d poped %d\n",Ctos,1);
#endif
				if ((t2=LBN_dup(t1)) == NULL) goto err;
				BN_mask_bits(t2,lq);
				T[Ttos++]=t2;
#ifdef DEBUG
				printf("C4 r=0 bits=%d\n",BN_num_bits(t2));
#endif
				for (i=1; i<=lr; i++)
					{
					if (!BN_rshift(t1,t1,lq)) goto err;
					if ((t2=LBN_dup(t1)) == NULL) goto err;
					BN_mask_bits(t2,lq);
					T[Ttos++]=t2;
#ifdef DEBUG
					printf("C4 r=%d bits=%d\n",i,
						BN_num_bits(t2));
#endif
					}
				LBN_free(t1);

				if ((t2=LBN_new()) == NULL) goto err;
				if ((t3=LBN_new()) == NULL) goto err;
				for (j=0; j<=2*lr; j++)
					{
					if ((t1=LBN_new()) == NULL) goto err;

					if (!BN_set_word(t3,j)) goto err;
					for (i=lr; i>=0; i--)
						{
						if (!BN_mul(t2,t1,t3)) goto err;
						if (!BN_add(t1,t2,T[i])) goto err;
						}
					/* t1 is U(j) */
					if (z == 0)
						U[Utos++]=t1;
					else
						V[Vtos++]=t1;
					}
				LBN_free(t2);
				LBN_free(t3);
				while (Ttos) LBN_free(T[--Ttos]);
				}
#ifdef DEBUG
			for (i=0; i<Utos; i++)
				printf("U[%2d]=%4d bits\n",i,BN_num_bits(U[i]));
			for (i=0; i<Vtos; i++)
				printf("V[%2d]=%4d bits\n",i,BN_num_bits(V[i]));
#endif
			/* C5 */
#ifdef DEBUG
			printf("PUSH CODE2 and %d CODE3 onto stack\n",2*lr);
#endif
			C[Ctos++]=CODE2;
			for (i=2*lr; i>0; i--)
				{
				C[Ctos++]=V[i];
				C[Ctos++]=U[i];
				C[Ctos++]=CODE3;
				}
			C[Ctos++]=V[0];
			C[Ctos++]=U[0];
#ifdef DEBUG
				printf("Ctos=%d pushed %d\n",Ctos,2*lr*3+3);
#endif
			Vtos=Utos=0;
			state=C3;
			break;
		case C6:
			if ((t1=LBN_dup(w)) == NULL) goto err;
			W[Wtos++]=t1;
#ifdef DEBUG
			printf("put %d bit number onto w\n",BN_num_bits(t1));
#endif
			state=C3;
			break;
		case C7:
			lr=r[k];
			lq=q[k];
			lp=q[k]+q[k-1];
			z=Wtos-2*lr-1;
			for (j=1; j<=2*lr; j++)
				{
				for (i=2*lr; i>=j; i--)
					{
					if (!BN_sub(W[z+i],W[z+i],W[z+i-1])) goto err;
					BN_div_word(W[z+i],j);
					}
				}
			state=C8;
			break;
		case C8:
			y=2*lr-1;
			if ((t1=LBN_new()) == NULL) goto err;
			if ((t3=LBN_new()) == NULL) goto err;

			for (j=y; j>0; j--)
				{
				if (!BN_set_word(t3,j)) goto err;
				for (i=j; i<=y; i++)
					{
					if (!BN_mul(t1,W[z+i+1],t3)) goto err;
					if (!BN_sub(W[z+i],W[z+i],t1)) goto err;
					}
				}
			LBN_free(t1);
			LBN_free(t3);
			state=C9;
			break;
		case C9:
			BN_zero(w);
#ifdef DEBUG
			printf("lq=%d\n",lq);
#endif
			for (i=lr*2; i>=0; i--)
				{
				BN_lshift(w,w,lq);
				BN_add(w,w,W[z+i]);
				}
			for (i=0; i<=lr*2; i++)
				LBN_free(W[--Wtos]);
			state=C10;
			break;
		case C10:
			k++;
			t1=C[--Ctos];
#ifdef DEBUG
			printf("Ctos=%d poped %d\n",Ctos,1);
			printf("code= CODE%d\n",t1);
#endif
			if (t1 == CODE3)
				state=C6;
			else if (t1 == CODE2)
				{
				if ((t2=LBN_dup(w)) == NULL) goto err;
				W[Wtos++]=t2;
				state=C7;
				}
			else if (t1 == CODE1)
				{
				state=DONE;
				}
			else
				{
				printf("BAD ERROR\n");
				goto err;
				}
			break;
		default:
			printf("bad state\n");
			goto err;
			break;
			}
		if (state == DONE) break;
		}
	ret=1;
err:
	if (ret == 0) printf("ERROR\n");
	return(ret);
	}

#ifdef MAIN
main()
	{
	BIGNUM *a,*b,*r;
	int i;

	if ((a=LBN_new()) == NULL) goto err;
	if ((b=LBN_new()) == NULL) goto err;
	if ((r=LBN_new()) == NULL) goto err;

	if (!BN_rand(a,1024*2,0,0)) goto err;
	if (!BN_rand(b,1024*2,0,0)) goto err;

	for (i=0; i<10; i++)
		{
		if (!BN_mul_knuth(r,a,b)) goto err; /**/
		/*if (!BN_mul(r,a,b)) goto err; /**/
		}
BN_print(stdout,a); printf(" * ");
BN_print(stdout,b); printf(" =\n");
BN_print(stdout,r); printf("\n");

printf("BN_new() =%d\nBN_free()=%d max=%d\n",new_total,Free_total,max);


	exit(0);
err:
	ERR_load_crypto_strings();
	ERR_print_errors(stderr);
	exit(1);
	}
#endif

int BN_mask_bits(a,n)
BIGNUM *a;
int n;
	{
	int b,w;

	w=n/BN_BITS2;
	b=n%BN_BITS2;
	if (w >= a->top) return(0);
	if (b == 0)
		a->top=w;
	else
		{
		a->top=w+1;
		a->d[w]&= ~(BN_MASK2<<b);
		}
	return(1);
	}

BIGNUM *LBN_dup(a)
BIGNUM *a;
	{
	new_total++;
	max_total++;
	if (max_total > max) max=max_total;
	return(BN_dup(a));
	}

BIGNUM *LBN_new()
	{
	new_total++;
	max_total++;
	if (max_total > max) max=max_total;
	return(BN_new());
	}

void LBN_free(a)
BIGNUM *a;
	{
	max_total--;
	if (max_total > max) max=max_total;
	Free_total++;
	BN_free(a);
	}
