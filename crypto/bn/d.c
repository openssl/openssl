#include <stdio.h>
#include <openssl/bio.h>
#include "bn_lcl.h"

#define SIZE_A (100*4+4)
#define SIZE_B (13*4)

main(argc,argv)
int argc;
char *argv[];
	{
	BN_CTX ctx;
	BN_RECP_CTX recp;
	BIGNUM a,b,dd,d,r,rr,t,l;
	int i;

	MemCheck_start();
	MemCheck_on();
	BN_CTX_init(&ctx);
	BN_RECP_CTX_init(&recp);

	BN_init(&r);
	BN_init(&rr);
	BN_init(&d);
	BN_init(&dd);
	BN_init(&a);
	BN_init(&b);

	{
	BN_rand(&a,SIZE_A,0,0);
	BN_rand(&b,SIZE_B,0,0);

	a.neg=1;
	BN_RECP_CTX_set(&recp,&b,&ctx);

	BN_print_fp(stdout,&a); printf(" a\n");
	BN_print_fp(stdout,&b); printf(" b\n");

	BN_print_fp(stdout,&recp.N); printf(" N\n");
	BN_print_fp(stdout,&recp.Nr); printf(" Nr num_bits=%d\n",recp.num_bits);

	BN_div_recp(&r,&d,&a,&recp,&ctx);

for (i=0; i<300; i++)
	BN_div(&rr,&dd,&a,&b,&ctx);

	BN_print_fp(stdout,&r); printf(" div recp\n");
	BN_print_fp(stdout,&rr); printf(" div\n");
	BN_print_fp(stdout,&d); printf(" rem recp\n");
	BN_print_fp(stdout,&dd); printf(" rem\n");
	}
	BN_CTX_free(&ctx);
	BN_RECP_CTX_free(&recp);

	BN_free(&r);
	BN_free(&rr);
	BN_free(&d);
	BN_free(&dd);
	BN_free(&a);
	BN_free(&b);

	{
	BIO *out;

	if ((out=BIO_new(BIO_s_file())) != NULL)
		BIO_set_fp(out,stderr,BIO_NOCLOSE|BIO_FP_TEXT);

        CRYPTO_mem_leaks(out);
	BIO_free(out);
	}

	}
