/* apps/passwd.c */

#if !defined(NO_DES) /* && !defined(prerequisites of other algorithms) */

#include <assert.h>
#include <string.h>

#include "apps.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#ifndef NO_DES
# include <openssl/des.h>
#endif

#undef PROG
#define PROG passwd_main


static unsigned const char cov_2char[64]={
	/* from crypto/des/fcrypt.c */
	0x2E,0x2F,0x30,0x31,0x32,0x33,0x34,0x35,
	0x36,0x37,0x38,0x39,0x41,0x42,0x43,0x44,
	0x45,0x46,0x47,0x48,0x49,0x4A,0x4B,0x4C,
	0x4D,0x4E,0x4F,0x50,0x51,0x52,0x53,0x54,
	0x55,0x56,0x57,0x58,0x59,0x5A,0x61,0x62,
	0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6A,
	0x6B,0x6C,0x6D,0x6E,0x6F,0x70,0x71,0x72,
	0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7A
};

/* -crypt        - standard Unix password algorithm (default, only choice)
 * -salt string  - salt
 * -quiet        - no warnings
 * -table        - format output as table
 */

int MAIN(int argc, char **argv)
	{
	int ret = 1;
	char *salt = NULL, *passwd, **passwds = NULL;
	char *salt_malloc = NULL, *passwd_malloc = NULL;
	BIO *out = NULL;
	int i, badopt, opt_done;
	int passed_salt = 0, quiet = 0, table = 0;
	int crypt = 0;
	size_t pw_maxlen = 0;

	apps_startup();

	if (bio_err == NULL)
		if ((bio_err=BIO_new(BIO_s_file())) != NULL)
			BIO_set_fp(bio_err,stderr,BIO_NOCLOSE|BIO_FP_TEXT);
	out = BIO_new(BIO_s_file());
	if (out == NULL)
		goto err;
	BIO_set_fp(out, stdout, BIO_NOCLOSE | BIO_FP_TEXT);

	badopt = 0, opt_done = 0;
	i = 0;
	while (!badopt && !opt_done && argv[++i] != NULL)
		{
		if (strcmp(argv[i], "-crypt") == 0)
			crypt = 1;
		else if (strcmp(argv[i], "-salt") == 0)
			{
			if ((argv[i+1] != NULL) && (salt == NULL))
				{
				passed_salt = 1;
				salt = argv[++i];
				}
			else badopt = 1;
			}
		else if (strcmp(argv[i], "-quiet") == 0)
			quiet = 1;
		else if (strcmp(argv[i], "-table") == 0)
			table = 1;
		else if (argv[i][0] == '-')
			badopt = 1;
		else
			/* non-option argument */
			{
			passwds = &argv[i];
			opt_done = 1;
			}
		}

	if (crypt /* + algo2 + algo3 + ... */ == 0) /* use default */
		crypt = 1;
	if (crypt /* + algo2 + algo3 */ > 1) /* conflict */
		badopt = 1;

	if (badopt) 
		{
		BIO_printf(bio_err, "Usage: passwd [options] [passwords]\n");
		BIO_printf(bio_err, "where options are\n");
		BIO_printf(bio_err, "-crypt             standard Unix password algorithm (default)\n");
		BIO_printf(bio_err, "-salt string       use provided salt\n");
		BIO_printf(bio_err, "-quiet             no warnings\n");
		BIO_printf(bio_err, "-table             format output as table\n");
		
		goto err;
		}

	if (crypt)
		pw_maxlen = 8;
	/* else if ... */

	if (passwds == NULL)
		{
		/* build a null-terminated list */
		static char *passwds_static[2] = {NULL, NULL};
		   
		passwds = passwds_static;
		passwd_malloc = Malloc(pw_maxlen + 1);
		if (passwd_malloc == NULL)
			goto err;
		if (EVP_read_pw_string(passwd_malloc, pw_maxlen + 1, "Password: ", 0) != 0)
			goto err;
		passwds[0] = passwd_malloc;
		}

	assert(passwds != NULL);
	assert(*passwds != NULL);
	
	do /* loop over list of passwords */
		{
		/* first make sure we have a salt */
		if (!passed_salt)
			{
			if (crypt)
				{
				if (salt_malloc == NULL)
					{
					salt = salt_malloc = Malloc(3);
					if (salt_malloc == NULL)
						goto err;
					}
				if (RAND_pseudo_bytes((unsigned char *)salt, 2) < 0)
					goto err;
				salt[0] = cov_2char[salt[0] & 0x3f]; /* 6 bits */
				salt[1] = cov_2char[salt[1] & 0x3f]; /* 6 bits */
				salt[2] = 0;
#ifdef CHARSET_EBCDIC
				ascii2ebcdic(salt, salt, 2); /* des_crypt will convert
				                              * back to ASCII */
#endif
				}
			/* else if (algo2) ... */
			}
		
		assert(salt != NULL);

		/* truncate password if necessary */
		passwd = *passwds++;
		if ((strlen(passwd) > pw_maxlen))
			{
			if (!quiet)
				BIO_printf(bio_err, "Warning: truncating password to %u characters\n", pw_maxlen);
			passwd[pw_maxlen] = 0;
			}
		assert(strlen(passwd) <= pw_maxlen);
		
		/* now compute password hash */
		if (crypt)
			{
			char *hash = des_crypt(passwd, salt);
			if (table)
				BIO_printf(out, "%s\t%s\n", passwd, hash);
			else
				BIO_printf(out, "%s\n", hash);
			}
		/* else if (algo2) { ... } else if (algo3) { ... } */
		else
			assert(0);
		}
	while (*passwds != NULL);
	
err:
	ERR_print_errors(bio_err);
	if (salt_malloc)
		Free(salt_malloc);
	if (passwd_malloc)
		Free(passwd_malloc);
	if (out)
		BIO_free(out);
	EXIT(ret);
	}
#endif
