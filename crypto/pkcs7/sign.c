#include <stdio.h>
#include "bio.h"
#include "x509.h"
#include "pem.h"

main(argc,argv)
int argc;
char *argv[];
	{
	X509 *x509;
	EVP_PKEY *pkey;
	PKCS7 *p7;
	PKCS7 *p7_data;
	PKCS7_SIGNER_INFO *si;
	BIO *in;
	BIO *data,*p7bio;
	char buf[1024*4];
	int i,j;
	int nodetach=0;

	EVP_add_digest(EVP_md2());
	EVP_add_digest(EVP_md5());
	EVP_add_digest(EVP_sha1());
	EVP_add_digest(EVP_mdc2());

	data=BIO_new(BIO_s_file());
again:
	if (argc > 1)
		{
		if (strcmp(argv[1],"-nd") == 0)
			{
			nodetach=1;
			argv++; argc--;
			goto again;
			}
		if (!BIO_read_filename(data,argv[1]))
			goto err;
		}
	else
		BIO_set_fp(data,stdin,BIO_NOCLOSE);

	if ((in=BIO_new_file("server.pem","r")) == NULL) goto err;
	if ((x509=PEM_read_bio_X509(in,NULL,NULL)) == NULL) goto err;
	BIO_reset(in);
	if ((pkey=PEM_read_bio_PrivateKey(in,NULL,NULL)) == NULL) goto err;
	BIO_free(in);

	p7=PKCS7_new();
	PKCS7_set_type(p7,NID_pkcs7_signed);
	 
	if (PKCS7_add_signature(p7,x509,pkey,EVP_sha1()) == NULL) goto err;

	/* we may want to add more */
	PKCS7_add_certificate(p7,x509);

	/* Set the content of the signed to 'data' */
	PKCS7_content_new(p7,NID_pkcs7_data);

	if (!nodetach)
		PKCS7_set_detached(p7,1);

	if ((p7bio=PKCS7_dataInit(p7,NULL)) == NULL) goto err;

	for (;;)
		{
		i=BIO_read(data,buf,sizeof(buf));
		if (i <= 0) break;
		BIO_write(p7bio,buf,i);
		}

	if (!PKCS7_dataSign(p7,p7bio)) goto err;
	BIO_free(p7bio);

	PEM_write_PKCS7(stdout,p7);
	PKCS7_free(p7);

	exit(0);
err:
	ERR_load_crypto_strings();
	ERR_print_errors_fp(stderr);
	exit(1);
	}

