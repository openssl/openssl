/* ====================================================================
 * Copyright (c) 2011 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef FIPS_UTL_H
#define FIPS_UTL_H

#define OPENSSL_FIPSAPI

#include <openssl/fips_rand.h>
#include <openssl/objects.h>

#ifdef OPENSSL_SYS_WIN32
#define RESP_EOL	"\n"
#else
#define RESP_EOL	"\r\n"
#endif

#ifndef FIPS_AUTH_OFFICER_PASS
#define FIPS_AUTH_OFFICER_PASS	"Default FIPS Crypto Officer Password"
#endif

#ifndef FIPS_AUTH_USER_PASS
#define FIPS_AUTH_USER_PASS	"Default FIPS Crypto User Password"
#endif


int hex2bin(const char *in, unsigned char *out);
unsigned char *hex2bin_m(const char *in, long *plen);
int do_hex2bn(BIGNUM **pr, const char *in);
int do_bn_print(FILE *out, const BIGNUM *bn);
int do_bn_print_name(FILE *out, const char *name, const BIGNUM *bn);
int parse_line(char **pkw, char **pval, char *linebuf, char *olinebuf);
int parse_line2(char **pkw, char **pval, char *linebuf, char *olinebuf, int eol);
BIGNUM *hex2bn(const char *in);
int tidy_line(char *linebuf, char *olinebuf);
int copy_line(const char *in, FILE *ofp);
int bint2bin(const char *in, int len, unsigned char *out);
int bin2bint(const unsigned char *in,int len,char *out);
void PrintValue(char *tag, unsigned char *val, int len);
void OutputValue(char *tag, unsigned char *val, int len, FILE *rfp,int bitmode);
void fips_algtest_init(void);
void do_entropy_stick(void);
int fips_strncasecmp(const char *str1, const char *str2, size_t n);
int fips_strcasecmp(const char *str1, const char *str2);

static int no_err;

static void put_err_cb(int lib, int func,int reason,const char *file,int line)
	{
	if (no_err)
		return;
	fprintf(stderr, "ERROR:%08lX:lib=%d,func=%d,reason=%d"
				":file=%s:line=%d\n",
			ERR_PACK(lib, func, reason),
			lib, func, reason, file, line);
	}

static void add_err_cb(int num, va_list args)
	{
	int i;
	char *str;
	if (no_err)
		return;
	fputs("\t", stderr);
	for (i = 0; i < num; i++)
		{
		str = va_arg(args, char *);
		if (str)
			fputs(str, stderr);
		}
	fputs("\n", stderr);
	}

/* Dummy Entropy to keep DRBG happy. WARNING: THIS IS TOTALLY BOGUS
 * HAS ZERO SECURITY AND MUST NOT BE USED IN REAL APPLICATIONS.
 */

static unsigned char dummy_entropy[1024];

static size_t dummy_cb(DRBG_CTX *ctx, unsigned char **pout,
                                int entropy, size_t min_len, size_t max_len)
	{
	*pout = dummy_entropy;
	return min_len;
	}

static int entropy_stick = 0;

static void fips_algtest_init_nofips(void)
	{
	DRBG_CTX *ctx;
	size_t i;
	FIPS_set_error_callbacks(put_err_cb, add_err_cb);
	for (i = 0; i < sizeof(dummy_entropy); i++)
		dummy_entropy[i] = i & 0xff;
	if (entropy_stick)
		memcpy(dummy_entropy + 32, dummy_entropy + 16, 16);
	ctx = FIPS_get_default_drbg();
	FIPS_drbg_init(ctx, NID_aes_256_ctr, DRBG_FLAG_CTR_USE_DF);
	FIPS_drbg_set_callbacks(ctx, dummy_cb, 0, 16, dummy_cb, 0);
	FIPS_drbg_instantiate(ctx, dummy_entropy, 10);
	FIPS_rand_set_method(FIPS_drbg_method());
	}

void do_entropy_stick(void)
	{
	entropy_stick = 1;
	}

void fips_algtest_init(void)
	{
	fips_algtest_init_nofips();
	if (!FIPS_module_mode_set(1, FIPS_AUTH_USER_PASS))
		{
		fprintf(stderr, "Error entering FIPS mode\n");
		exit(1);
		}
	}

int hex2bin(const char *in, unsigned char *out)
    {
    int n1, n2, isodd = 0;
    unsigned char ch;

    n1 = strlen(in);
    if (in[n1 - 1] == '\n')
	n1--;

    if (n1 & 1)
	isodd = 1;

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
	/* If input is odd length first digit is least significant: assumes
	 * all digits valid hex and null terminated which is true for the
	 * strings we pass.
	 */
	if (n1 == 1 && isodd)
		{
		out[n2++] = ch;
		continue;
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

unsigned char *hex2bin_m(const char *in, long *plen)
	{
	unsigned char *p;
	if (strlen(in) == 0)
		{
		*plen = 0;
		return OPENSSL_malloc(1);
		}
	p = OPENSSL_malloc((strlen(in) + 1)/2);
	*plen = hex2bin(in, p);
	return p;
	}

int do_hex2bn(BIGNUM **pr, const char *in)
	{
	unsigned char *p;
	long plen;
	int r = 0;
	p = hex2bin_m(in, &plen);
	if (!p)
		return 0;
	if (!*pr)
		*pr = BN_new();
	if (!*pr)
		return 0;
	if (BN_bin2bn(p, plen, *pr))
		r = 1;
	OPENSSL_free(p);
	return r;
	}

int do_bn_print(FILE *out, const BIGNUM *bn)
	{
	int len, i;
	unsigned char *tmp;
	len = BN_num_bytes(bn);
	if (len == 0)
		{
		fputs("00", out);
		return 1;
		}

	tmp = OPENSSL_malloc(len);
	if (!tmp)
		{
		fprintf(stderr, "Memory allocation error\n");
		return 0;
		}
	BN_bn2bin(bn, tmp);
	for (i = 0; i < len; i++)
		fprintf(out, "%02x", tmp[i]);
	OPENSSL_free(tmp);
	return 1;
	}

int do_bn_print_name(FILE *out, const char *name, const BIGNUM *bn)
	{
	int r;
	fprintf(out, "%s = ", name);
	r = do_bn_print(out, bn);
	if (!r)
		return 0;
	fputs(RESP_EOL, out);
	return 1;
	}

int parse_line(char **pkw, char **pval, char *linebuf, char *olinebuf)
	{
	return parse_line2(pkw, pval, linebuf, olinebuf, 1);
	}

int parse_line2(char **pkw, char **pval, char *linebuf, char *olinebuf, int eol)
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

	if (eol && *p != '\n')
		fprintf(stderr, "Warning: missing EOL\n");

	while (*p == '\n' || isspace((unsigned char)*p))
		*p-- = 0;

	*pkw = keyword;
	*pval = value;
	return 1;
	}

BIGNUM *hex2bn(const char *in)
    {
    BIGNUM *p=NULL;

    if (!do_hex2bn(&p, in))
	return NULL;

    return p;
    }

/* To avoid extensive changes to test program at this stage just convert
 * the input line into an acceptable form. Keyword lines converted to form
 * "keyword = value\n" no matter what white space present, all other lines
 * just have leading and trailing space removed.
 */

int tidy_line(char *linebuf, char *olinebuf)
	{
	char *keyword, *value, *p, *q;
	strcpy(linebuf, olinebuf);
	keyword = linebuf;
	/* Skip leading space */
	while (isspace((unsigned char)*keyword))
		keyword++;
	/* Look for = sign */
	p = strchr(linebuf, '=');

	/* If no '=' just chop leading, trailing ws */
	if (!p)
		{
		p = keyword + strlen(keyword) - 1;
		while (*p == '\n' || isspace((unsigned char)*p))
			*p-- = 0;
		strcpy(olinebuf, keyword);
		strcat(olinebuf, "\n");
		return 1;
		}

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

	strcpy(olinebuf, keyword);
	strcat(olinebuf, " = ");
	strcat(olinebuf, value);
	strcat(olinebuf, "\n");

	return 1;
	}
/* Copy supplied line to ofp replacing \n with \r\n */
int copy_line(const char *in, FILE *ofp)
	{
	const char *p;
	p = strchr(in, '\n');
	if (p)
		{
		fwrite(in, 1, (size_t)(p - in), ofp);
		fputs(RESP_EOL, ofp);
		}
	else
		fputs(in, ofp);
	return 1;
	}

/* NB: this return the number of _bits_ read */
int bint2bin(const char *in, int len, unsigned char *out)
    {
    int n;

    memset(out,0,len);
    for(n=0 ; n < len ; ++n)
	if(in[n] == '1')
	    out[n/8]|=(0x80 >> (n%8));
    return len;
    }

int bin2bint(const unsigned char *in,int len,char *out)
    {
    int n;

    for(n=0 ; n < len ; ++n)
	out[n]=(in[n/8]&(0x80 >> (n%8))) ? '1' : '0';
    return n;
    }

/*-----------------------------------------------*/

void PrintValue(char *tag, unsigned char *val, int len)
{
#ifdef VERBOSE
	OutputValue(tag, val, len, stdout, 0);
#endif
}

void OutputValue(char *tag, unsigned char *val, int len, FILE *rfp,int bitmode)
    {
    char obuf[2048];
    int olen;

    if(bitmode)
	{
	olen=bin2bint(val,len,obuf);
    	fprintf(rfp, "%s = %.*s" RESP_EOL, tag, olen, obuf);
	}
    else
	{
	int i;
    	fprintf(rfp, "%s = ", tag);
	for (i = 0; i < len; i++)
		fprintf(rfp, "%02x", val[i]);
	fputs(RESP_EOL, rfp);
	}

#if VERBOSE
    printf("%s = %.*s\n", tag, olen, obuf);
#endif
    }

/* Not all platforms support strcasecmp and strncasecmp: implement versions
 * in here to avoid need to include them in the validated module. Taken
 * from crypto/o_str.c written by Richard Levitte (richard@levitte.org)
 */

int fips_strncasecmp(const char *str1, const char *str2, size_t n)
	{
	while (*str1 && *str2 && n)
		{
		int res = toupper(*str1) - toupper(*str2);
		if (res) return res < 0 ? -1 : 1;
		str1++;
		str2++;
		n--;
		}
	if (n == 0)
		return 0;
	if (*str1)
		return 1;
	if (*str2)
		return -1;
	return 0;
	}

int fips_strcasecmp(const char *str1, const char *str2)
	{
	return fips_strncasecmp(str1, str2, (size_t)-1);
	}


#endif
