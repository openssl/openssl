#include <openssl/bn.h>

int rand(n)
{
    unsigned char x[2];
    RAND_bytes(&x,2);
    return (x[0] + 2*x[1]);
}

void bug(char *m, BIGNUM *a, BIGNUM *b)
{
    printf("%s!\na=",m);
    BN_print_fp(stdout, a);
    printf("\nb=");
    BN_print_fp(stdout, b);
    printf("\n");
}

main()
{
    BIGNUM *a=BN_new(), *b=BN_new(), *c=BN_new(), *d=BN_new(),
	*C=BN_new(), *D=BN_new();
    BN_RECP_CTX *recp=BN_RECP_CTX_new();
    BN_CTX *ctx=BN_CTX_new();

    for(;;) {
	BN_rand(a,rand(),0,0);
	BN_rand(b,rand(),0,0);
	if (BN_is_zero(b)) continue;

	BN_RECP_CTX_set(recp,b,ctx);
	if (BN_div(C,D,a,b,ctx) != 1)
	    bug("BN_div failed",a,b);
	if (BN_div_recp(c,d,a,recp,ctx) != 1)
	    bug("BN_div_recp failed",a,b);
	else if (BN_cmp(c,C) != 0 || BN_cmp(c,C) != 0)
	    bug("mismatch",a,b);
    }
}
