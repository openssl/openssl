#include <stdio.h>
#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/fips.h>
#ifdef FLAT_INC
#include "e_os.h"
#else
#include "../e_os.h"
#endif

#ifndef OPENSSL_FIPS
int main(int argc, char *argv[])
{
    printf("No FIPS SHA1 support\n");
    return(0);
}
#else

#define MAX_TEST_BITS 103432

static void dump(const unsigned char *b,int n)
    {
    while(n-- > 0)
	printf("%02X",*b++);
    }

static void bitfill(unsigned char *buf,int bit,int b,int n)
    {
    for( ; n > 0 ; --n,++bit)
	{
	assert(bit < MAX_TEST_BITS);
	buf[bit/8]|=b << (7-bit%8);
	}
    }

void montecarlo(unsigned char *seed,int n)
    {
    int i,j;
    unsigned char m[10240];

    memcpy(m,seed,n);
    for(j=0 ; j < 100 ; ++j)
	{
	for(i=1 ; i <= 50000 ; ++i)
	    {
	    memset(m+n,'\0',j/4+3);
	    n+=j/4+3;
	    m[n++]=i >> 24;
	    m[n++]=i >> 16;
	    m[n++]=i >> 8;
	    m[n++]=i;
/*  	    putchar(' '); */
/*  	    dump(m,bit/8); */
/*  	    putchar('\n'); */
	    SHA1(m,n,m);
	    n=20;
	    }
	dump(m,20);
	puts(" ^");
	}
    }

int main(int argc,char **argv)
    {
    FILE *fp;
    int phase;

    if(argc != 2)
	{
	fprintf(stderr,"%s <test vector file>\n",argv[0]);
	EXIT(1);
	}

    if(!FIPS_mode_set(1,argv[0]))
	{
	ERR_load_crypto_strings();
	ERR_print_errors(BIO_new_fp(stderr,BIO_NOCLOSE));
	EXIT(1);
	}
    fp=fopen(argv[1],"r");
    if(!fp)
	{
	perror(argv[1]);
	EXIT(2);
	}

    for(phase=0 ; ; )
	{
	unsigned char buf[MAX_TEST_BITS/8];
	unsigned char md[20];
	char line[10240];
	int n,t,b,bit;
	char *p;

	fgets(line,1024,fp);
	if(feof(fp))
	    break;
	n=strlen(line);
	line[n-1]='\0';
	if(!strcmp(line,"D>"))
	    ++phase;

	if(!isdigit(line[0]))
	    {
	    puts(line);
	    continue;
	    }
	for( ; ; )
	    {
	    assert(n > 1);
	    if(line[n-2] == '^')
		break;
	    fgets(line+n-1,sizeof(line)-n+1,fp);
	    n=strlen(line);
	    /*	    printf("line=%s\n",line); */
	    assert(!feof(fp));
	    }

	p=strtok(line," ");
	t=atoi(p);
	p=strtok(NULL," ");
	b=atoi(p);
	memset(buf,'\0',sizeof buf);
	for(bit=0,p=strtok(NULL," ") ; p && *p != '^' ; p=strtok(NULL," "))
	    {
	    assert(t-- > 0);
	    bitfill(buf,bit,b,atoi(p));
	    bit+=atoi(p);
	    b=1-b;
	    }
	assert(t == 0);
	assert((bit%8) == 0);
	/*	dump(buf,bit/8); */
	/*	putchar('\n'); */
	if(phase < 3)
	    {
	    SHA1(buf,bit/8,md);
	    dump(md,20);
	    puts(" ^");
	    }
	else
	    montecarlo(buf,bit/8);
	}
    EXIT(0);
    return(0);
    }
#endif
