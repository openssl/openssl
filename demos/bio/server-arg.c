/* NOCW */
/* demos/bio/saccept.c */

/* A minimal program to server an SSL connection.
 * It uses blocking.
 * saccept host:port
 * host is the interface IP to use.  If any interface, use *:port
 * The default it *:4433
 *
 * cc -I../../include saccept.c -L../.. -lssl -lcrypto
 */

#include <stdio.h>
#include <signal.h>
#include <openssl/err.h>
#include <openssl/ssl.h>


int main(int argc, char *argv[])
	{
	char *port = "*:4433";
	BIO *ssl_bio,*tmp;
	SSL_CTX *ctx;
	SSL_CONF_CTX *cctx;
	char buf[512];
	BIO *in=NULL;
	int ret=1,i;
	char **args = argv + 1;
	int nargs = argc - 1;

	SSL_load_error_strings();

	/* Add ciphers and message digests */
	OpenSSL_add_ssl_algorithms();

	ctx=SSL_CTX_new(SSLv23_server_method());

	cctx = SSL_CONF_CTX_new();
	SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_SERVER);
	SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CERTIFICATE);
	SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);
	while(*args && **args == '-')
		{
		int rv;
		/* Parse standard arguments */
		rv = SSL_CONF_cmd_argv(cctx, &nargs, &args);
		if (rv == -3)
			{
			fprintf(stderr, "Missing argument for %s\n", *args);
			goto err;
			}
		if (rv < 0)
			{
			fprintf(stderr, "Error in command %s\n", *args);
			ERR_print_errors_fp(stderr);
			goto err;
			}
		/* If rv > 0 we processed something so proceed to next arg */
		if (rv > 0)
			continue;
		/* Otherwise application specific argument processing */
		if (!strcmp(*args, "-port"))
			{
			port = args[1];
			if (port == NULL)
				{
				fprintf(stderr, "Missing -port argument\n");
				goto err;
				}
			args += 2;
			nargs -= 2;
			continue;
			}
		else
			{
			fprintf(stderr, "Unknown argument %s\n", *args);
			goto err;
			}
		}

	if (!SSL_CONF_CTX_finish(cctx))
		{
		fprintf(stderr, "Finish error\n");
		ERR_print_errors_fp(stderr);
		goto err;
		}

	/* Setup server side SSL bio */
	ssl_bio=BIO_new_ssl(ctx,0);

	if ((in=BIO_new_accept(port)) == NULL) goto err;

	/* This means that when a new connection is acceptede on 'in',
	 * The ssl_bio will be 'dupilcated' and have the new socket
	 * BIO push into it.  Basically it means the SSL BIO will be
	 * automatically setup */
	BIO_set_accept_bios(in,ssl_bio);

again:
	/* The first call will setup the accept socket, and the second
	 * will get a socket.  In this loop, the first actual accept
	 * will occur in the BIO_read() function. */

	if (BIO_do_accept(in) <= 0) goto err;

	for (;;)
		{
		i=BIO_read(in,buf,512);
		if (i == 0)
			{
			/* If we have finished, remove the underlying
			 * BIO stack so the next time we call any function
			 * for this BIO, it will attempt to do an
			 * accept */
			printf("Done\n");
			tmp=BIO_pop(in);
			BIO_free_all(tmp);
			goto again;
			}
		if (i < 0) goto err;
		fwrite(buf,1,i,stdout);
		fflush(stdout);
		}

	ret=0;
err:
	if (ret)
		{
		ERR_print_errors_fp(stderr);
		}
	if (in != NULL) BIO_free(in);
	exit(ret);
	return(!ret);
	}

