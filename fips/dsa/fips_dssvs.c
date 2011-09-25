#include <openssl/opensslconf.h>

#ifndef OPENSSL_FIPS
#include <stdio.h>

int main()
{
    printf("No FIPS DSA support\n");
    return(0);
}
#else

#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/fips.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string.h>
#include <ctype.h>

#include "fips_utl.h"

void primes(FILE *in, FILE *out)
    {
    char buf[10240];
    char lbuf[10240];
    char *keyword, *value;

    while(fgets(buf,sizeof buf,in) != NULL)
	{
	fputs(buf,out);
	if (!parse_line(&keyword, &value, lbuf, buf))
		continue;
	if(!strcmp(keyword,"Prime"))
	    {
	    BIGNUM *pp;

	    pp=BN_new();
	    do_hex2bn(&pp,value);
	    fprintf(out, "result= %c\n",
		   BN_is_prime_ex(pp,20,NULL,NULL) ? 'P' : 'F');
	    }	    
	}
    }

void pqg(FILE *in, FILE *out)
    {
    char buf[1024];
    char lbuf[1024];
    char *keyword, *value;
    int nmod=0;

    while(fgets(buf,sizeof buf,in) != NULL)
	{
	if (!parse_line(&keyword, &value, lbuf, buf))
		{
		fputs(buf,out);
		continue;
		}
	if(!strcmp(keyword,"[mod"))
	    nmod=atoi(value);
	else if(!strcmp(keyword,"N"))
	    {
	    int n=atoi(value);

	    fprintf(out, "[mod = %d]\n\n",nmod);

	    while(n--)
		{
		unsigned char seed[20];
		DSA *dsa;
		int counter;
		unsigned long h;
		dsa = FIPS_dsa_new();

		if (!DSA_generate_parameters_ex(dsa, nmod,seed,0,&counter,&h,NULL))
			{
			do_print_errors();
			exit(1);
			}
		do_bn_print_name(out, "P",dsa->p);
		do_bn_print_name(out, "Q",dsa->q);
		do_bn_print_name(out, "G",dsa->g);
		OutputValue("Seed",seed,20, out, 0);
		fprintf(out, "c = %d\n",counter);
		fprintf(out, "H = %lx\n",h);
		fputs("\n", out);
		}
	    }
	else
	    fputs(buf,out);
	}
    }


void pqgver(FILE *in, FILE *out)
    {
    char buf[1024];
    char lbuf[1024];
    char *keyword, *value;
    BIGNUM *p = NULL, *q = NULL, *g = NULL;
    int counter, counter2;
    unsigned long h, h2;
    DSA *dsa=NULL;
    int nmod=0;
    unsigned char seed[1024];

    while(fgets(buf,sizeof buf,in) != NULL)
	{
	if (!parse_line(&keyword, &value, lbuf, buf))
		{
		fputs(buf,out);
		continue;
		}
	if(!strcmp(keyword,"[mod"))
	    nmod=atoi(value);
	else if(!strcmp(keyword,"P"))
	    p=hex2bn(value);
	else if(!strcmp(keyword,"Q"))
	    q=hex2bn(value);
	else if(!strcmp(keyword,"G"))
	    g=hex2bn(value);
	else if(!strcmp(keyword,"Seed"))
	    {
	    int slen = hex2bin(value, seed);
	    if (slen != 20)
		{
		fprintf(stderr, "Seed parse length error\n");
		exit (1);
		}
	    }
	else if(!strcmp(keyword,"c"))
	    counter =atoi(buf+4);
	else if(!strcmp(keyword,"H"))
	    {
	    h = atoi(value);
	    if (!p || !q || !g)
		{
		fprintf(stderr, "Parse Error\n");
		exit (1);
		}
	    do_bn_print_name(out, "P",p);
	    do_bn_print_name(out, "Q",q);
	    do_bn_print_name(out, "G",g);
	    OutputValue("Seed",seed,20, out, 0);
	    fprintf(out, "c = %d\n",counter);
	    fprintf(out, "H = %lx\n",h);
	    dsa = FIPS_dsa_new();
	    if (!DSA_generate_parameters_ex(dsa, nmod,seed,20 ,&counter2,&h2,NULL))
			{
			do_print_errors();
			exit(1);
			}
            if (BN_cmp(dsa->p, p) || BN_cmp(dsa->q, q) || BN_cmp(dsa->g, g)
		|| (counter != counter2) || (h != h2))
	    	fprintf(out, "Result = F\n");
	    else
	    	fprintf(out, "Result = T\n");
	    BN_free(p);
	    BN_free(q);
	    BN_free(g);
	    p = NULL;
	    q = NULL;
	    g = NULL;
	    FIPS_dsa_free(dsa);
	    dsa = NULL;
	    }
	}
    }


void keypair(FILE *in, FILE *out)
    {
    char buf[1024];
    char lbuf[1024];
    char *keyword, *value;
    int nmod=0;

    while(fgets(buf,sizeof buf,in) != NULL)
	{
	if (!parse_line(&keyword, &value, lbuf, buf))
		{
		fputs(buf,out);
		continue;
		}
	if(!strcmp(keyword,"[mod"))
	    nmod=atoi(value);
	else if(!strcmp(keyword,"N"))
	    {
	    DSA *dsa;
	    int n=atoi(value);

	    fprintf(out, "[mod = %d]\n\n",nmod);
	    dsa = FIPS_dsa_new();
	    if (!DSA_generate_parameters_ex(dsa, nmod,NULL,0,NULL,NULL,NULL))
		{
		do_print_errors();
		exit(1);
		}
	    do_bn_print_name(out, "P",dsa->p);
	    do_bn_print_name(out, "Q",dsa->q);
	    do_bn_print_name(out, "G",dsa->g);
	    fputs("\n", out);

	    while(n--)
		{
		if (!DSA_generate_key(dsa))
			{
			do_print_errors();
			exit(1);
			}

		do_bn_print_name(out, "X",dsa->priv_key);
		do_bn_print_name(out, "Y",dsa->pub_key);
		fputs("\n", out);
		}
	    }
	}
    }

void siggen(FILE *in, FILE *out)
    {
    char buf[1024];
    char lbuf[1024];
    char *keyword, *value;
    int nmod=0;
    DSA *dsa=NULL;

    while(fgets(buf,sizeof buf,in) != NULL)
	{
	if (!parse_line(&keyword, &value, lbuf, buf))
		{
		fputs(buf,out);
		continue;
		}
	if(!strcmp(keyword,"[mod"))
	    {
	    nmod=atoi(value);
	    fprintf(out, "[mod = %d]\n\n",nmod);
	    if (dsa)
		FIPS_dsa_free(dsa);
	    dsa = FIPS_dsa_new();
	    if (!DSA_generate_parameters_ex(dsa, nmod,NULL,0,NULL,NULL,NULL))
		{
		do_print_errors();
		exit(1);
		}
	    do_bn_print_name(out, "P",dsa->p);
	    do_bn_print_name(out, "Q",dsa->q);
	    do_bn_print_name(out, "G",dsa->g);
	    fputs("\n", out);
	    }
	else if(!strcmp(keyword,"Msg"))
	    {
	    unsigned char msg[1024];
	    unsigned char sbuf[60];
	    unsigned int slen;
	    int n;
	    EVP_PKEY pk;
	    EVP_MD_CTX mctx;
	    DSA_SIG *sig;
	    EVP_MD_CTX_init(&mctx);

	    n=hex2bin(value,msg);
	    OutputValue("Msg",msg,n, out, 0);

	    if (!DSA_generate_key(dsa))
		{
		do_print_errors();
		exit(1);
		}
	    pk.type = EVP_PKEY_DSA;
	    pk.pkey.dsa = dsa;
	    do_bn_print_name(out, "Y",dsa->pub_key);

	    EVP_SignInit_ex(&mctx, EVP_dss1(), NULL);
	    EVP_SignUpdate(&mctx, msg, n);
	    EVP_SignFinal(&mctx, sbuf, &slen, &pk);

	    sig = DSA_SIG_new();
	    FIPS_dsa_sig_decode(sig, sbuf, slen);

	    do_bn_print_name(out, "R",sig->r);
	    do_bn_print_name(out, "S",sig->s);
	    fputs("\n", out);
	    DSA_SIG_free(sig);
	    EVP_MD_CTX_cleanup(&mctx);
	    }
	}
	if (dsa)
		FIPS_dsa_free(dsa);
    }

void sigver(FILE *in, FILE *out)
    {
    DSA *dsa=NULL;
    char buf[1024];
    char lbuf[1024];
    unsigned char msg[1024];
    int n;
    char *keyword, *value;
    int nmod=0;
    DSA_SIG sg, *sig = &sg;

    sig->r = NULL;
    sig->s = NULL;

    while(fgets(buf,sizeof buf,in) != NULL)
	{
	if (!parse_line(&keyword, &value, lbuf, buf))
		{
		fputs(buf,out);
		continue;
		}
	if(!strcmp(keyword,"[mod"))
	    {
	    nmod=atoi(value);
	    if(dsa)
		FIPS_dsa_free(dsa);
	    dsa=FIPS_dsa_new();
	    }
	else if(!strcmp(keyword,"P"))
	    dsa->p=hex2bn(value);
	else if(!strcmp(keyword,"Q"))
	    dsa->q=hex2bn(value);
	else if(!strcmp(keyword,"G"))
	    {
	    dsa->g=hex2bn(value);

	    fprintf(out, "[mod = %d]\n\n",nmod);
	    do_bn_print_name(out, "P",dsa->p);
	    do_bn_print_name(out, "Q",dsa->q);
	    do_bn_print_name(out, "G",dsa->g);
	    fputs("\n", out);
	    }
	else if(!strcmp(keyword,"Msg"))
	    {
	    n=hex2bin(value,msg);
	    OutputValue("Msg",msg,n, out, 0);
	    }
	else if(!strcmp(keyword,"Y"))
	    dsa->pub_key=hex2bn(value);
	else if(!strcmp(keyword,"R"))
	    sig->r=hex2bn(value);
	else if(!strcmp(keyword,"S"))
	    {
	    EVP_MD_CTX mctx;
	    EVP_PKEY pk;
	    unsigned char sigbuf[60];
	    unsigned int slen;
	    int r;
	    EVP_MD_CTX_init(&mctx);
	    pk.type = EVP_PKEY_DSA;
	    pk.pkey.dsa = dsa;
	    sig->s=hex2bn(value);
	
	    do_bn_print_name(out, "Y",dsa->pub_key);
	    do_bn_print_name(out, "R",sig->r);
	    do_bn_print_name(out, "S",sig->s);

	    slen = FIPS_dsa_sig_encode(sigbuf, sig);
	    EVP_VerifyInit_ex(&mctx, EVP_dss1(), NULL);
	    EVP_VerifyUpdate(&mctx, msg, n);
	    r = EVP_VerifyFinal(&mctx, sigbuf, slen, &pk);
	    EVP_MD_CTX_cleanup(&mctx);
	
	    fprintf(out, "Result = %c\n", r == 1 ? 'P' : 'F');
	    fputs("\n", out);
	    }
	}
    }

int main(int argc,char **argv)
    {
    FILE *in, *out;
    if (argc == 4)
	{
	in = fopen(argv[2], "r");
	if (!in)
		{
		fprintf(stderr, "Error opening input file\n");
		exit(1);
		}
	out = fopen(argv[3], "w");
	if (!out)
		{
		fprintf(stderr, "Error opening output file\n");
		exit(1);
		}
	}
    else if (argc == 2)
	{
	in = stdin;
	out = stdout;
	}
    else
	{
	fprintf(stderr,"%s [prime|pqg|pqgver|keypair|siggen|sigver]\n",argv[0]);
	exit(1);
	}
    if(!FIPS_mode_set(1))
	{
	do_print_errors();
	exit(1);
	}
    if(!strcmp(argv[1],"prime"))
	primes(in, out);
    else if(!strcmp(argv[1],"pqg"))
	pqg(in, out);
    else if(!strcmp(argv[1],"pqgver"))
	pqgver(in, out);
    else if(!strcmp(argv[1],"keypair"))
	keypair(in, out);
    else if(!strcmp(argv[1],"siggen"))
	siggen(in, out);
    else if(!strcmp(argv[1],"sigver"))
	sigver(in, out);
    else
	{
	fprintf(stderr,"Don't know how to %s.\n",argv[1]);
	exit(1);
	}

    if (argc == 4)
	{
	fclose(in);
	fclose(out);
	}

    return 0;
    }

#endif
