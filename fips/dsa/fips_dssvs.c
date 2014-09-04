
#define OPENSSL_FIPSAPI
#include <openssl/opensslconf.h>

#ifndef OPENSSL_FIPS
#include <stdio.h>

int main(int argc, char **argv)
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

static int parse_mod(char *line, int *pdsa2, int *pL, int *pN,
				const EVP_MD **pmd)
	{
	char lbuf[10240];
	char *keyword, *value;

	char *p;
	p = strchr(line, ',');
	if (!p)
		{
		*pL = atoi(line);
		*pdsa2 = 0;
		*pN = 160;
		if (pmd)
			*pmd = EVP_sha1();
		return 1;
		}
	*pdsa2 = 1;
	*p = 0;
	if (!parse_line2(&keyword, &value, lbuf, line, 0))
		return 0;
	if (strcmp(keyword, "L"))
		return 0;
	*pL = atoi(value);
	strcpy(line, p + 1);
	if (pmd)
		p = strchr(line, ',');
	else
		p = strchr(line, ']');
	if (!p)
		return 0;
	*p = 0;
	if (!parse_line2(&keyword, &value, lbuf, line, 0))
		return 0;
	if (strcmp(keyword, "N"))
		return 0;
	*pN = atoi(value);
	if (!pmd)
		return 1;
	strcpy(line, p + 1);
	p = strchr(line, ']');
	if (!p)
		return 0;
	*p = 0;
	p = line;
	while(isspace(*p))
		p++;
	if (!strcmp(p, "SHA-1"))
		*pmd = EVP_sha1();
	else if (!strcmp(p, "SHA-224"))
		*pmd = EVP_sha224();
	else if (!strcmp(p, "SHA-256"))
		*pmd = EVP_sha256();
	else if (!strcmp(p, "SHA-384"))
		*pmd = EVP_sha384();
	else if (!strcmp(p, "SHA-512"))
		*pmd = EVP_sha512();
	else
		return 0;
	return 1;
	}

static void primes(FILE *in, FILE *out)
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
	    fprintf(out, "result= %c" RESP_EOL,
		   BN_is_prime_ex(pp,20,NULL,NULL) ? 'P' : 'F');
	    }	    
	}
    }

int dsa_builtin_paramgen(DSA *ret, size_t bits, size_t qbits,
	const EVP_MD *evpmd, const unsigned char *seed_in, size_t seed_len,
	unsigned char *seed_out,
	int *counter_ret, unsigned long *h_ret, BN_GENCB *cb);
int dsa_builtin_paramgen2(DSA *ret, size_t L, size_t N,
	const EVP_MD *evpmd, const unsigned char *seed_in, size_t seed_len,
	int idx, unsigned char *seed_out,
	int *counter_ret, unsigned long *h_ret, BN_GENCB *cb);

int dsa_paramgen_check_g(DSA *dsa);

static void pqg(FILE *in, FILE *out)
    {
    char buf[1024];
    char lbuf[1024];
    char *keyword, *value;
    int dsa2, L, N;
    const EVP_MD *md = NULL;
    BIGNUM *p = NULL, *q = NULL;
    enum pqtype { PQG_NONE, PQG_PQ, PQG_G, PQG_GCANON}
		pqg_type = PQG_NONE;
    int seedlen=-1, idxlen, idx = -1;
    unsigned char seed[1024], idtmp[1024];

    while(fgets(buf,sizeof buf,in) != NULL)
	{
	if (buf[0] == '[')
		{
	    	if (strstr(buf, "Probable"))
			pqg_type = PQG_PQ;
	    	else if (strstr(buf, "Unverifiable"))
			pqg_type = PQG_G;
	    	else if (strstr(buf, "Canonical"))
			pqg_type = PQG_GCANON;
		}
	if (!parse_line(&keyword, &value, lbuf, buf))
		{
		fputs(buf,out);
		continue;
		}
	if (strcmp(keyword, "Num"))
		fputs(buf,out);
	if(!strcmp(keyword,"[mod"))
	    {
	    if (!parse_mod(value, &dsa2, &L, &N, &md))
		{
		fprintf(stderr, "Mod Parse Error\n");
		exit (1);
		}
	    }
	else if(!strcmp(keyword,"N") 
		|| (!strcmp(keyword, "Num") && pqg_type == PQG_PQ))
	    {
	    int n=atoi(value);

	    while(n--)
		{
		DSA *dsa;
		int counter;
		unsigned long h;
		dsa = FIPS_dsa_new();

		if (!dsa2 && !dsa_builtin_paramgen(dsa, L, N, md,
						NULL, 0, seed,
						&counter, &h, NULL))
			{
			fprintf(stderr, "Parameter Generation error\n");
			exit(1);
			}
		if (dsa2 && dsa_builtin_paramgen2(dsa, L, N, md,
						NULL, 0, -1, seed,
						&counter, &h, NULL) <= 0)
			{
			fprintf(stderr, "Parameter Generation error\n");
			exit(1);
			}
 
		do_bn_print_name(out, "P",dsa->p);
		do_bn_print_name(out, "Q",dsa->q);
		if (!dsa2)
			do_bn_print_name(out, "G",dsa->g);
		OutputValue(dsa2 ? "domain_parameter_seed" : "Seed",
				seed, M_EVP_MD_size(md), out, 0);
		if (!dsa2)
			{
			fprintf(out, "c = %d" RESP_EOL, counter);
			fprintf(out, "H = %lx" RESP_EOL RESP_EOL,h);
			}
		else
			{
			fprintf(out, "counter = %d" RESP_EOL RESP_EOL, counter);
			}
		FIPS_dsa_free(dsa);
		}
	    }
	else if(!strcmp(keyword,"P"))
	    p=hex2bn(value);
	else if(!strcmp(keyword,"Q"))
	    q=hex2bn(value);
	else if(!strcmp(keyword,"domain_parameter_seed"))
	    seedlen = hex2bin(value, seed);
	else if(!strcmp(keyword,"firstseed"))
	    seedlen = hex2bin(value, seed);
	else if(!strcmp(keyword,"pseed"))
	    seedlen += hex2bin(value, seed + seedlen);
	else if(!strcmp(keyword,"qseed"))
	    seedlen += hex2bin(value, seed + seedlen);
	else if(!strcmp(keyword,"index"))
	    {
	    idxlen = hex2bin(value, idtmp);
            if (idxlen != 1)
		{
		fprintf(stderr, "Index value error\n");
		exit (1);
		}
	    idx = idtmp[0];
	    }
	if ((idx >= 0 && pqg_type == PQG_GCANON) || (q && pqg_type == PQG_G))
		{
		DSA *dsa;
		dsa = FIPS_dsa_new();
		dsa->p = p;
		dsa->q = q;
		p = q = NULL;
		if (dsa_builtin_paramgen2(dsa, L, N, md,
						seed, seedlen, idx, NULL,
						NULL, NULL, NULL) <= 0)
			{
			fprintf(stderr, "Parameter Generation error\n");
			exit(1);
			}
		do_bn_print_name(out, "G",dsa->g);
		FIPS_dsa_free(dsa);
		idx = -1;
		}
	}
    }

static void pqgver(FILE *in, FILE *out)
    {
    char buf[1024];
    char lbuf[1024];
    char *keyword, *value;
    BIGNUM *p = NULL, *q = NULL, *g = NULL;
    int counter=-1, counter2;
    unsigned long h=0, h2;
    DSA *dsa=NULL;
    int dsa2, L, N, part_test = 0;
    const EVP_MD *md = NULL;
    int seedlen=-1, idxlen, idx = -1;
    unsigned char seed[1024], idtmp[1024];

    while(fgets(buf,sizeof buf,in) != NULL)
	{
	if (!parse_line(&keyword, &value, lbuf, buf))
		{
		if (p && q)
			{
			part_test = 1;
			goto partial;
			}
		fputs(buf,out);
		continue;
		}
	fputs(buf, out);
	if(!strcmp(keyword,"[mod"))
	    {
	    if (!parse_mod(value, &dsa2, &L, &N, &md))
		{
		fprintf(stderr, "Mod Parse Error\n");
		exit (1);
		}
	    }
	else if(!strcmp(keyword,"P"))
	    p=hex2bn(value);
	else if(!strcmp(keyword,"Q"))
	    q=hex2bn(value);
	else if(!strcmp(keyword,"G"))
	    g=hex2bn(value);
	else if(!strcmp(keyword,"firstseed"))
	    seedlen = hex2bin(value, seed);
	else if(!strcmp(keyword,"pseed"))
	    seedlen += hex2bin(value, seed + seedlen);
	else if(!strcmp(keyword,"qseed"))
	    seedlen += hex2bin(value, seed + seedlen);
	else if(!strcmp(keyword,"Seed")
		|| !strcmp(keyword,"domain_parameter_seed"))
	    {
	    seedlen = hex2bin(value, seed);
	    if (!dsa2 && seedlen != 20)
		{
		fprintf(stderr, "Seed parse length error\n");
		exit (1);
		}
	    if (idx > 0)
		part_test = 1;
	    }
	else if(!strcmp(keyword,"index"))
	    {
	    idxlen = hex2bin(value, idtmp);
            if (idxlen != 1)
		{
		fprintf(stderr, "Index value error\n");
		exit (1);
		}
	    idx = idtmp[0];
	    }
	else if(!strcmp(keyword,"c"))
	    counter = atoi(buf+4);
	partial:
	if (part_test && idx < 0 && h == 0 && g)
	    {
	    dsa = FIPS_dsa_new();
	    dsa->p = BN_dup(p);
	    dsa->q = BN_dup(q);
	    dsa->g = BN_dup(g);
	    if (dsa_paramgen_check_g(dsa))
		fprintf(out, "Result = P" RESP_EOL);
	    else
		fprintf(out, "Result = F" RESP_EOL);
	    BN_free(p);
	    BN_free(q);
	    BN_free(g);
	    p = NULL;
	    q = NULL;
	    g = NULL;
	    FIPS_dsa_free(dsa);
	    dsa = NULL;
	    part_test = 0;
	    }
	else if(!strcmp(keyword,"H") || part_test)
	    {
	    if (!part_test)
	    	h = atoi(value);
	    if (!p || !q || (!g && !part_test))
		{
		fprintf(stderr, "Parse Error\n");
		exit (1);
		}
	    dsa = FIPS_dsa_new();
	    if (idx >= 0)
		{
		dsa->p = BN_dup(p);
		dsa->q = BN_dup(q);
		}
	    no_err = 1;
	    if (!dsa2 && !dsa_builtin_paramgen(dsa, L, N, md,
					seed, seedlen, NULL,
					&counter2, &h2, NULL))
			{
			fprintf(stderr, "Parameter Generation error\n");
			exit(1);
			}
	    if (dsa2 && dsa_builtin_paramgen2(dsa, L, N, md,
					seed, seedlen, idx, NULL,
					&counter2, &h2, NULL) < 0)
			{
			fprintf(stderr, "Parameter Generation error\n");
			exit(1);
			}
	    no_err = 0;
	    if (idx >= 0)
		{
		if (BN_cmp(dsa->g, g))
			fprintf(out, "Result = F" RESP_EOL);
		else
			fprintf(out, "Result = P" RESP_EOL);
		}
            else if (BN_cmp(dsa->p, p) || BN_cmp(dsa->q, q) || 
		(!part_test &&
		((BN_cmp(dsa->g, g) || (counter != counter2) || (h != h2)))))
	    	fprintf(out, "Result = F" RESP_EOL);
	    else
	    	fprintf(out, "Result = P" RESP_EOL);
	    BN_free(p);
	    BN_free(q);
	    BN_free(g);
	    p = NULL;
	    q = NULL;
	    g = NULL;
	    FIPS_dsa_free(dsa);
	    dsa = NULL;
	    if (part_test)
		{
		if (idx == -1)
			fputs(buf,out);
		part_test = 0;
		}
	    idx = -1;
	    }
	}
    }

/* Keypair verification routine. NB: this isn't part of the standard FIPS140-2
 * algorithm tests. It is an additional test to perform sanity checks on the
 * output of the KeyPair test.
 */

static int dss_paramcheck(int L, int N, BIGNUM *p, BIGNUM *q, BIGNUM *g,
							BN_CTX *ctx)
    {
    BIGNUM *rem = NULL;
    if (BN_num_bits(p) != L)
	return 0;
    if (BN_num_bits(q) != N)
	return 0;
    if (BN_is_prime_ex(p, BN_prime_checks, ctx, NULL) != 1)
	return 0;
    if (BN_is_prime_ex(q, BN_prime_checks, ctx, NULL) != 1)
	return 0;
    rem = BN_new();
    if (!BN_mod(rem, p, q, ctx) || !BN_is_one(rem)
    	|| (BN_cmp(g, BN_value_one()) <= 0)
	|| !BN_mod_exp(rem, g, q, p, ctx) || !BN_is_one(rem))
	{
	BN_free(rem);
	return 0;
	}
    /* Todo: check g */
    BN_free(rem);
    return 1;
    }

static void keyver(FILE *in, FILE *out)
    {
    char buf[1024];
    char lbuf[1024];
    char *keyword, *value;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *X = NULL, *Y = NULL;
    BIGNUM *Y2;
    BN_CTX *ctx = NULL;
    int dsa2, L, N;
    int paramcheck = 0;

    ctx = BN_CTX_new();
    Y2 = BN_new();

    while(fgets(buf,sizeof buf,in) != NULL)
	{
	if (!parse_line(&keyword, &value, lbuf, buf))
		{
		fputs(buf,out);
		continue;
		}
	if(!strcmp(keyword,"[mod"))
	    {
	    if (p)
		BN_free(p);
	    p = NULL;
	    if (q)
		BN_free(q);
	    q = NULL;
	    if (g)
		BN_free(g);
	    g = NULL;
	    paramcheck = 0;
	    if (!parse_mod(value, &dsa2, &L, &N, NULL))
		{
		fprintf(stderr, "Mod Parse Error\n");
		exit (1);
		}
	    }
	else if(!strcmp(keyword,"P"))
	    p=hex2bn(value);
	else if(!strcmp(keyword,"Q"))
	    q=hex2bn(value);
	else if(!strcmp(keyword,"G"))
	    g=hex2bn(value);
	else if(!strcmp(keyword,"X"))
	    X=hex2bn(value);
	else if(!strcmp(keyword,"Y"))
	    {
	    Y=hex2bn(value);
	    if (!p || !q || !g || !X || !Y)
		{
		fprintf(stderr, "Parse Error\n");
		exit (1);
		}
	    do_bn_print_name(out, "P",p);
	    do_bn_print_name(out, "Q",q);
	    do_bn_print_name(out, "G",g);
	    do_bn_print_name(out, "X",X);
	    do_bn_print_name(out, "Y",Y);
	    if (!paramcheck)
		{
		if (dss_paramcheck(L, N, p, q, g, ctx))
			paramcheck = 1;
		else
			paramcheck = -1;
		}
	    if (paramcheck != 1)
	   	fprintf(out, "Result = F" RESP_EOL);
	    else
		{
		if (!BN_mod_exp(Y2, g, X, p, ctx) || BN_cmp(Y2, Y))
	    		fprintf(out, "Result = F" RESP_EOL);
	        else
	    		fprintf(out, "Result = P" RESP_EOL);
		}
	    BN_free(X);
	    BN_free(Y);
	    X = NULL;
	    Y = NULL;
	    }
	}
	if (p)
	    BN_free(p);
	if (q)
	    BN_free(q);
	if (g)
	    BN_free(g);
	if (Y2)
	    BN_free(Y2);
	if (ctx)
	    BN_CTX_free(ctx);
    }

static void keypair(FILE *in, FILE *out)
    {
    char buf[1024];
    char lbuf[1024];
    char *keyword, *value;
    int dsa2, L, N;

    while(fgets(buf,sizeof buf,in) != NULL)
	{
	if (!parse_line(&keyword, &value, lbuf, buf))
		{
		continue;
		}
	if(!strcmp(keyword,"[mod"))
	    {
	    if (!parse_mod(value, &dsa2, &L, &N, NULL))
		{
		fprintf(stderr, "Mod Parse Error\n");
		exit (1);
		}
	    fputs(buf,out);
	    }
	else if(!strcmp(keyword,"N"))
	    {
	    DSA *dsa;
	    int n=atoi(value);

	    dsa = FIPS_dsa_new();
	    if (!dsa)
		{
		fprintf(stderr, "DSA allocation error\n");
		exit(1);
		}
	    if (!dsa2 && !dsa_builtin_paramgen(dsa, L, N, NULL, NULL, 0,
						NULL, NULL, NULL, NULL))
			{
			fprintf(stderr, "Parameter Generation error\n");
			exit(1);
			}
	    if (dsa2 && dsa_builtin_paramgen2(dsa, L, N, NULL, NULL, 0, -1,
						NULL, NULL, NULL, NULL) <= 0)
			{
			fprintf(stderr, "Parameter Generation error\n");
			exit(1);
			}
	    do_bn_print_name(out, "P",dsa->p);
	    do_bn_print_name(out, "Q",dsa->q);
	    do_bn_print_name(out, "G",dsa->g);
	    fputs(RESP_EOL, out);

	    while(n--)
		{
		if (!DSA_generate_key(dsa))
			exit(1);

		do_bn_print_name(out, "X",dsa->priv_key);
		do_bn_print_name(out, "Y",dsa->pub_key);
	    	fputs(RESP_EOL, out);
		}
	    FIPS_dsa_free(dsa);
	    }
	}
    }

static void siggen(FILE *in, FILE *out)
    {
    char buf[1024];
    char lbuf[1024];
    char *keyword, *value;
    int dsa2, L, N;
    const EVP_MD *md = NULL;
    DSA *dsa=NULL;

    while(fgets(buf,sizeof buf,in) != NULL)
	{
	if (!parse_line(&keyword, &value, lbuf, buf))
		{
		fputs(buf,out);
		continue;
		}
	fputs(buf,out);
	if(!strcmp(keyword,"[mod"))
	    {
	    if (!parse_mod(value, &dsa2, &L, &N, &md))
		{
		fprintf(stderr, "Mod Parse Error\n");
		exit (1);
		}
	    if (dsa)
		FIPS_dsa_free(dsa);
	    dsa = FIPS_dsa_new();
	    if (!dsa2 && !dsa_builtin_paramgen(dsa, L, N, md, NULL, 0,
						NULL, NULL, NULL, NULL))
			{
			fprintf(stderr, "Parameter Generation error\n");
			exit(1);
			}
	    if (dsa2 && dsa_builtin_paramgen2(dsa, L, N, md, NULL, 0, -1,
						NULL, NULL, NULL, NULL) <= 0)
			{
			fprintf(stderr, "Parameter Generation error\n");
			exit(1);
			}
	    do_bn_print_name(out, "P",dsa->p);
	    do_bn_print_name(out, "Q",dsa->q);
	    do_bn_print_name(out, "G",dsa->g);
	    fputs(RESP_EOL, out);
	    }
	else if(!strcmp(keyword,"Msg"))
	    {
	    unsigned char msg[1024];
	    int n;
	    DSA_SIG *sig;

	    n=hex2bin(value,msg);

	    if (!DSA_generate_key(dsa))
		exit(1);
	    do_bn_print_name(out, "Y",dsa->pub_key);

	    sig = FIPS_dsa_sign(dsa, msg, n, md);

	    do_bn_print_name(out, "R",sig->r);
	    do_bn_print_name(out, "S",sig->s);
	    fputs(RESP_EOL, out);
	    FIPS_dsa_sig_free(sig);
	    }
	}
    if (dsa)
	FIPS_dsa_free(dsa);
    }

static void sigver(FILE *in, FILE *out)
    {
    DSA *dsa=NULL;
    char buf[1024];
    char lbuf[1024];
    unsigned char msg[1024];
    char *keyword, *value;
    int n=0;
    int dsa2, L, N;
    const EVP_MD *md = NULL;
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
	fputs(buf,out);
	if(!strcmp(keyword,"[mod"))
	    {
	    if (!parse_mod(value, &dsa2, &L, &N, &md))
		{
		fprintf(stderr, "Mod Parse Error\n");
		exit (1);
		}
	    if (dsa)
		FIPS_dsa_free(dsa);
	    dsa = FIPS_dsa_new();
	    }
	else if(!strcmp(keyword,"P"))
	    do_hex2bn(&dsa->p, value);
	else if(!strcmp(keyword,"Q"))
	    do_hex2bn(&dsa->q, value);
	else if(!strcmp(keyword,"G"))
	    do_hex2bn(&dsa->g, value);
	else if(!strcmp(keyword,"Msg"))
	    n=hex2bin(value,msg);
	else if(!strcmp(keyword,"Y"))
	    do_hex2bn(&dsa->pub_key, value);
	else if(!strcmp(keyword,"R"))
	    sig->r=hex2bn(value);
	else if(!strcmp(keyword,"S"))
	    {
	    int r;
	    sig->s=hex2bn(value);

	    no_err = 1;
	    r = FIPS_dsa_verify(dsa, msg, n, md, sig);
	    no_err = 0;
	    if (sig->s)
		{
		BN_free(sig->s);
		sig->s = NULL;
		}
	    if (sig->r)
		{
		BN_free(sig->r);
		sig->r = NULL;
		}
	
	    fprintf(out, "Result = %c" RESP_EOL RESP_EOL, r == 1 ? 'P' : 'F');
	    }
	}
	if (dsa)
	    FIPS_dsa_free(dsa);
    }

#ifdef FIPS_ALGVS
int fips_dssvs_main(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
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
	fprintf(stderr,"%s [prime|pqg|pqgver|keypair|keyver|siggen|sigver]\n",argv[0]);
	exit(1);
	}
    fips_algtest_init();
    if(!strcmp(argv[1],"prime"))
	primes(in, out);
    else if(!strcmp(argv[1],"pqg"))
	pqg(in, out);
    else if(!strcmp(argv[1],"pqgver"))
	pqgver(in, out);
    else if(!strcmp(argv[1],"keypair"))
	keypair(in, out);
    else if(!strcmp(argv[1],"keyver"))
	keyver(in, out);
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
