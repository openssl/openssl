#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/fips.h>
#include <openssl/err.h>
#include <string.h>

int hex2bin(const char *in, unsigned char *out)
    {
    int n1, n2;
    unsigned char ch;

    for (n1=0,n2=0 ; in[n1] ; )
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
    int olen;

    olen=bin2hex(val,len,obuf);
    printf("%s = %s\n",tag,obuf);
    }

void pbn(const char *tag,const BIGNUM *val)
    {
    printf("%s = %s\n",tag,BN_bn2hex(val));
    }

void primes()
    {
    char buf[10240];

    while(fgets(buf,sizeof buf,stdin) != NULL)
	{
	fputs(buf,stdout);
	if(!strncmp(buf,"Prime= ",7))
	    {
	    BIGNUM *pp;

	    pp=BN_new();
	    BN_hex2bn(&pp,buf+7);
	    printf("result= %c\n",
		   BN_is_prime(pp,20,NULL,NULL,NULL) ? 'P' : 'F');
	    }	    
	}
    }

void pqg()
    {
    char buf[1024];
    int nmod=0;

    while(fgets(buf,sizeof buf,stdin) != NULL)
	{
	if(!strncmp(buf,"[mod = ",7))
	    nmod=atoi(buf+7);
	else if(!strncmp(buf,"N = ",4))
	    {
	    int n=atoi(buf+4);

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
    int nmod=0;

    while(fgets(buf,sizeof buf,stdin) != NULL)
	{
	if(!strncmp(buf,"[mod = ",7))
	    nmod=atoi(buf+7);
	else if(!strncmp(buf,"N = ",4))
	    {
	    DSA *dsa;
	    int n=atoi(buf+4);

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

int main(int argc,char **argv)
    {
    if(argc != 2)
	{
	fprintf(stderr,"%s [prime|pqg]\n",argv[0]);
	exit(1);
	}
    if(!FIPS_mode_set(1,argv[0]))
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
    //    else if(!strcmp(argv[1],"versig"))
    //	versig();
    else
	{
	fprintf(stderr,"Don't know how to %s.\n",argv[1]);
	exit(1);
	}

    return 0;
    }
