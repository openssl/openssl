/* apps/rand.c */

#include "apps.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#undef PROG
#define PROG rand_main

/* -out file         - write to file
 * -rand file:file   - PRNG seed files
 * -base64           - encode output
 * num               - write 'num' bytes
 */

int MAIN(int, char **);

int MAIN(int argc, char **argv)
	{
	int i, r, ret = 1;
	int badopt;
	char *outfile = NULL;
	char *inrand = NULL;
	int base64 = 0;
	BIO *out = NULL;
	int num = -1;

	apps_startup();

	if (bio_err == NULL)
		if ((bio_err = BIO_new(BIO_s_file())) != NULL)
			BIO_set_fp(bio_err, stderr, BIO_NOCLOSE|BIO_FP_TEXT);

	badopt = 0;
	i = 0;
	while (!badopt && argv[++i] != NULL)
		{
		if (strcmp(argv[i], "-out") == 0)
			{
			if ((argv[i+1] != NULL) && (outfile == NULL))
				outfile = argv[++i];
			else
				badopt = 1;
			}
		else if (strcmp(argv[i], "-rand") == 0)
			{
			if ((argv[i+1] != NULL) && (inrand == NULL))
				inrand = argv[++i];
			else
				badopt = 1;
			}
		else if (strcmp(argv[i], "-base64") == 0)
			{
			if (!base64)
				base64 = 1;
			else
				badopt = 1;
			}
		else if (isdigit((unsigned char)argv[i][0]))
			{
			if (num < 0)
				{
				r = sscanf(argv[i], "%d", &num);
				if (r == 0 || num < 0)
					badopt = 1;
				}
			else
				badopt = 1;
			}
		else
			badopt = 1;
		}

	if (num < 0)
		badopt = 1;
	
	if (badopt) 
		{
		BIO_printf(bio_err, "Usage: rand [options] num\n");
		BIO_printf(bio_err, "where options are\n");
		BIO_printf(bio_err, "-out file            - write to file\n");
		BIO_printf(bio_err, "-rand file%cfile%c...  - seed PRNG from files\n", LIST_SEPARATOR_CHAR, LIST_SEPARATOR_CHAR);
		BIO_printf(bio_err, "-base64              - encode output\n");
		goto err;
		}

	app_RAND_load_file(NULL, bio_err, (inrand != NULL));
	if (inrand != NULL)
		BIO_printf(bio_err,"%ld semi-random bytes loaded\n",
			app_RAND_load_files(inrand));

	out = BIO_new(BIO_s_file());
	if (out == NULL)
		goto err;
	if (outfile != NULL)
		r = BIO_write_filename(out, outfile);
	else
		{
		r = BIO_set_fp(out, stdout, BIO_NOCLOSE | BIO_FP_TEXT);
#ifdef VMS
		{
		BIO *tmpbio = BIO_new(BIO_f_linebuffer());
		out = BIO_push(tmpbio, out);
		}
#endif
		}
	if (r <= 0)
		goto err;

	if (base64)
		{
		BIO *b64 = BIO_new(BIO_f_base64());
		if (b64 == NULL)
			goto err;
		out = BIO_push(b64, out);
		}
	
	while (num > 0) 
		{
		unsigned char buf[4096];
		int chunk;

		chunk = num;
		if (chunk > sizeof buf)
			chunk = sizeof buf;
		r = RAND_bytes(buf, chunk);
		if (r <= 0)
			goto err;
		BIO_write(out, buf, chunk);
		num -= chunk;
		}
	BIO_flush(out);

	app_RAND_write_file(NULL, bio_err);
	ret = 0;
	
err:
	ERR_print_errors(bio_err);
	if (out)
		BIO_free_all(out);
	EXIT(ret);
	}
