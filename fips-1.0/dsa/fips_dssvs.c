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
#include <openssl/fips_sha.h>
#include <string.h>
#include <ctype.h>

#include "fips_utl.h"

static void pbn(const char *name, BIGNUM *bn)
	{
	int len, i;
	unsigned char *tmp;
	len = BN_num_bytes(bn);
	tmp = OPENSSL_malloc(len);
	if (!tmp)
		{
		fprintf(stderr, "Memory allocation error\n");
		return;
		}
	BN_bn2bin(bn, tmp);
	printf("%s = ", name);
	for (i = 0; i < len; i++)
		printf("%02X", tmp[i]);
	fputs("\n", stdout);
	OPENSSL_free(tmp);
	return;
	}

void primes()
    {
    char buf[10240];
    char lbuf[10240];
    char *keyword, *value;

    while(fgets(buf,sizeof buf,stdin) != NULL)
	{
	fputs(buf,stdout);
	if (!parse_line(&keyword, &value, lbuf, buf))
		continue;
	if(!strcmp(keyword,"Prime"))
	    {
	    BIGNUM *pp;

	    pp=BN_new();
	    do_hex2bn(&pp,value);
	    printf("result= %c\n",
		   BN_is_prime_ex(pp,20,NULL,NULL) ? 'P' : 'F');
	    }	    
	}
    }

void pqg()
    {
    char buf[1024];
    char lbuf[1024];
    char *keyword, *value;
    int nmod=0;

    while(fgets(buf,sizeof buf,stdin) != NULL)
	{
	if (!parse_line(&keyword, &value, lbuf, buf))
		{
		fputs(buf,stdout);
		continue;
		}
	if(!strcmp(keyword,"[mod"))
	    nmod=atoi(value);
	else if(!strcmp(keyword,"N"))
	    {
	    int n=atoi(value);

	    printf("[mod = %d]\n\n",nmod);

	    while(n--)
		{
		unsigned char seed[20];
		DSA *dsa;
		int counter;
		unsigned long h;
		dsa = FIPS_dsa_new();

		DSA_generate_parameters_ex(dsa, nmod,seed,0,&counter,&h,NULL);
		pbn("P",dsa->p);
		pbn("Q",dsa->q);
		pbn("G",dsa->g);
		pv("Seed",seed,20);
		printf("c = %d\n",counter);
		printf("H = %lx\n",h);
		putc('\n',stdout);
		}
	    }
	else
	    fputs(buf,stdout);
	}
    }

void keypair()
    {
    char buf[1024];
    char lbuf[1024];
    char *keyword, *value;
    int nmod=0;

    while(fgets(buf,sizeof buf,stdin) != NULL)
	{
	if (!parse_line(&keyword, &value, lbuf, buf))
		{
		fputs(buf,stdout);
		continue;
		}
	if(!strcmp(keyword,"[mod"))
	    nmod=atoi(value);
	else if(!strcmp(keyword,"N"))
	    {
	    DSA *dsa;
	    int n=atoi(value);

	    printf("[mod = %d]\n\n",nmod);
	    dsa = FIPS_dsa_new();
	    DSA_generate_parameters_ex(dsa, nmod,NULL,0,NULL,NULL,NULL);
	    pbn("P",dsa->p);
	    pbn("Q",dsa->q);
	    pbn("G",dsa->g);
	    putc('\n',stdout);

	    while(n--)
		{
		DSA_generate_key(dsa);

		pbn("X",dsa->priv_key);
		pbn("Y",dsa->pub_key);
		putc('\n',stdout);
		}
	    }
	}
    }

void siggen()
    {
    char buf[1024];
    char lbuf[1024];
    char *keyword, *value;
    int nmod=0;
    DSA *dsa=NULL;

    while(fgets(buf,sizeof buf,stdin) != NULL)
	{
	if (!parse_line(&keyword, &value, lbuf, buf))
		{
		fputs(buf,stdout);
		continue;
		}
	if(!strcmp(keyword,"[mod"))
	    {
	    nmod=atoi(value);
	    printf("[mod = %d]\n\n",nmod);

	    dsa = FIPS_dsa_new();
	    DSA_generate_parameters_ex(dsa, nmod,NULL,0,NULL,NULL,NULL);
	    pbn("P",dsa->p);
	    pbn("Q",dsa->q);
	    pbn("G",dsa->g);
	    putc('\n',stdout);
	    }
	else if(!strcmp(keyword,"Msg"))
	    {
	    unsigned char msg[1024];
	    unsigned char hash[20];
	    int n;
	    DSA_SIG *sig;

	    n=hex2bin(value,msg);
	    pv("Msg",msg,n);

	    DSA_generate_key(dsa);
	    pbn("Y",dsa->pub_key);

	    SHA1(msg,n,hash);
	    sig=DSA_do_sign(hash,sizeof hash,dsa);
	    pbn("R",sig->r);
	    pbn("S",sig->s);
	    putc('\n',stdout);
	    }
	}
    }

void sigver()
    {
    DSA *dsa=NULL;
    char buf[1024];
    char lbuf[1024];
    char *keyword, *value;
    int nmod=0;
    unsigned char hash[20];
    DSA_SIG sg, *sig = &sg;

    sig->r = NULL;
    sig->s = NULL;

    while(fgets(buf,sizeof buf,stdin) != NULL)
	{
	if (!parse_line(&keyword, &value, lbuf, buf))
		{
		fputs(buf,stdout);
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

	    printf("[mod = %d]\n\n",nmod);
	    pbn("P",dsa->p);
	    pbn("Q",dsa->q);
	    pbn("G",dsa->g);
	    putc('\n',stdout);
	    }
	else if(!strcmp(keyword,"Msg"))
	    {
	    unsigned char msg[1024];
	    int n;

	    n=hex2bin(value,msg);
	    pv("Msg",msg,n);
	    SHA1(msg,n,hash);
	    }
	else if(!strcmp(keyword,"Y"))
	    dsa->pub_key=hex2bn(value);
	else if(!strcmp(keyword,"R"))
	    sig->r=hex2bn(value);
	else if(!strcmp(keyword,"S"))
	    {
	    sig->s=hex2bn(value);
	
	    pbn("Y",dsa->pub_key);
	    pbn("R",sig->r);
	    pbn("S",sig->s);
	    printf("Result = %c\n",DSA_do_verify(hash,sizeof hash,sig,dsa)
		   ? 'P' : 'F');
	    putc('\n',stdout);
	    }
	}
    }

int main(int argc,char **argv)
    {
    if(argc != 2)
	{
	fprintf(stderr,"%s [prime|pqg]\n",argv[0]);
	exit(1);
	}
    if(!FIPS_mode_set(1))
	{
	do_print_errors();
	exit(1);
	}
    if(!strcmp(argv[1],"prime"))
	primes();
    else if(!strcmp(argv[1],"pqg"))
	pqg();
    else if(!strcmp(argv[1],"keypair"))
	keypair();
    else if(!strcmp(argv[1],"siggen"))
	siggen();
    else if(!strcmp(argv[1],"sigver"))
	sigver();
    else
	{
	fprintf(stderr,"Don't know how to %s.\n",argv[1]);
	exit(1);
	}

    return 0;
    }

#endif
