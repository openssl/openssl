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

static int parse_line(char **pkw, char **pval, char *linebuf, char *olinebuf)
	{
	char *keyword, *value, *p, *q;
	strcpy(linebuf, olinebuf);
	keyword = linebuf;
	/* Skip leading space */
	while (isspace((unsigned char)*keyword))
		keyword++;

	/* Look for = sign */
	p = strchr(linebuf, '=');

	/* If no '=' exit */
	if (!p)
		return 0;

	q = p - 1;

	/* Remove trailing space */
	while (isspace((unsigned char)*q))
		*q-- = 0;

	*p = 0;
	value = p + 1;

	/* Remove leading space from value */
	while (isspace((unsigned char)*value))
		value++;

	/* Remove trailing space from value */
	p = value + strlen(value) - 1;

	while (*p == '\n' || isspace((unsigned char)*p))
		*p-- = 0;

	*pkw = keyword;
	*pval = value;
	return 1;
	}

int hex2bin(const char *in, unsigned char *out)
    {
    int n1, n2;
    unsigned char ch;

    for (n1=0,n2=0 ; in[n1] && in[n1] != '\n' ; )
	{ /* first byte */
	if ((in[n1] >= '0') && (in[n1] <= '9'))
	    ch = in[n1++] - '0';
	else if ((in[n1] >= 'A') && (in[n1] <= 'F'))
	    ch = in[n1++] - 'A' + 10;
	else if ((in[n1] >= 'a') && (in[n1] <= 'f'))
	    ch = in[n1++] - 'a' + 10;
	else
	    return -1;
	if(!in[n1])
	    {
	    out[n2++]=ch;
	    break;
	    }
	out[n2] = ch << 4;
	/* second byte */
	if ((in[n1] >= '0') && (in[n1] <= '9'))
	    ch = in[n1++] - '0';
	else if ((in[n1] >= 'A') && (in[n1] <= 'F'))
	    ch = in[n1++] - 'A' + 10;
	else if ((in[n1] >= 'a') && (in[n1] <= 'f'))
	    ch = in[n1++] - 'a' + 10;
	else
	    return -1;
	out[n2++] |= ch;
	}
    return n2;
    }

BIGNUM *hex2bn(const char *in)
    {
    BIGNUM *p=BN_new();

    BN_hex2bn(&p,in);

    return p;
    }

int bin2hex(const unsigned char *in,int len,char *out)
    {
    int n1, n2;
    unsigned char ch;

    for (n1=0,n2=0 ; n1 < len ; ++n1)
	{
	ch=in[n1] >> 4;
	if (ch <= 0x09)
	    out[n2++]=ch+'0';
	else
	    out[n2++]=ch-10+'a';
	ch=in[n1] & 0x0f;
	if(ch <= 0x09)
	    out[n2++]=ch+'0';
	else
	    out[n2++]=ch-10+'a';
	}
    out[n2]='\0';
    return n2;
    }

void pv(const char *tag,const unsigned char *val,int len)
    {
    char obuf[2048];

    bin2hex(val,len,obuf);
    printf("%s = %s\n",tag,obuf);
    }

void pbn(const char *tag,const BIGNUM *val)
    {
    printf("%s = %s\n",tag,BN_bn2hex(val));
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
	    BN_hex2bn(&pp,value);
	    printf("result= %c\n",
		   BN_is_prime(pp,20,NULL,NULL,NULL) ? 'P' : 'F');
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

		dsa=DSA_generate_parameters(nmod,seed,0,&counter,&h,NULL,NULL);
		printf("P = %s\n",BN_bn2hex(dsa->p));
		printf("Q = %s\n",BN_bn2hex(dsa->q));
		printf("G = %s\n",BN_bn2hex(dsa->g));
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

	    dsa=DSA_generate_parameters(nmod,NULL,0,NULL,NULL,NULL,NULL);
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

	    dsa=DSA_generate_parameters(nmod,NULL,0,NULL,NULL,NULL,NULL);
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
    DSA_SIG *sig=DSA_SIG_new();

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
		DSA_free(dsa);
	    dsa=DSA_new();
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
	ERR_load_crypto_strings();
	ERR_print_errors(BIO_new_fp(stderr,BIO_NOCLOSE));
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
