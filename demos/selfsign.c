/* NOCW */
/* cc -o ssdemo -I../include selfsign.c ../libcrypto.a */

#include <stdio.h>
#include <stdlib.h>

#include "buffer.h"
#include "crypto.h"
#include "objects.h"
#include "asn1.h"
#include "evp.h"
#include "x509.h"
#include "pem.h"

int mkit(X509 **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days);

int main()
	{
	BIO *bio_err;
	X509 *x509=NULL;
	EVP_PKEY *pkey=NULL;

	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

	X509v3_add_netscape_extensions();

	if ((bio_err=BIO_new(BIO_s_file())) != NULL)
		BIO_set_fp(bio_err,stderr,BIO_NOCLOSE);

	mkit(&x509,&pkey,512,0,365);

	RSA_print_fp(stdout,pkey->pkey.rsa,0);
	X509_print_fp(stdout,x509);

	PEM_write_RSAPrivateKey(stdout,pkey->pkey.rsa,NULL,NULL,0,NULL);
	PEM_write_X509(stdout,x509);

	X509_free(x509);
	EVP_PKEY_free(pkey);
	BIO_free(bio_err);

	X509_cleanup_extensions();

	CRYPTO_mem_leaks(bio_err);
	return(0);
	}

#ifdef WIN16
#  define MS_CALLBACK   _far _loadds
#  define MS_FAR        _far
#else
#  define MS_CALLBACK
#  define MS_FAR
#endif

static void MS_CALLBACK callback(p, n)
int p;
int n;
	{
	char c='B';

	if (p == 0) c='.';
	if (p == 1) c='+';
	if (p == 2) c='*';
	if (p == 3) c='\n';
	fputc(c,stderr);
	}

int mkit(x509p,pkeyp,bits,serial,days)
X509 **x509p;
EVP_PKEY **pkeyp;
int bits;
int serial;
int days;
	{
	X509 *x;
	EVP_PKEY *pk;
	RSA *rsa;
	char *s;
	X509_NAME *name=NULL;
	X509_NAME_ENTRY *ne=NULL;
	X509_EXTENSION *ex=NULL;
	ASN1_OCTET_STRING *data=NULL;

	
	if ((pkeyp == NULL) || (*pkeyp == NULL))
		{
		if ((pk=EVP_PKEY_new()) == NULL)
			{
			abort(); 
			return(0);
			}
		}
	else
		pk= *pkeyp;

	if ((x509p == NULL) || (*x509p == NULL))
		{
		if ((x=X509_new()) == NULL)
			goto err;
		}
	else
		x= *x509p;

	rsa=RSA_generate_key(bits,RSA_F4,callback);
	if (!EVP_PKEY_assign_RSA(pk,rsa))
		{
		abort();
		goto err;
		}
	rsa=NULL;

	X509_set_version(x,3);
	ASN1_INTEGER_set(X509_get_serialNumber(x),serial);
	X509_gmtime_adj(X509_get_notBefore(x),0);
	X509_gmtime_adj(X509_get_notAfter(x),(long)60*60*24*days);
	X509_set_pubkey(x,pk);

	name=X509_NAME_new();

	ne=X509_NAME_ENTRY_create_by_NID(NULL,NID_countryName,
		V_ASN1_APP_CHOOSE,"AU",-1);
	X509_NAME_add_entry(name,ne,0,0);

	X509_NAME_ENTRY_create_by_NID(&ne,NID_commonName,
		V_ASN1_APP_CHOOSE,"Eric Young",-1);
	X509_NAME_add_entry(name,ne,1,0);

	/* finished with structure */
	X509_NAME_ENTRY_free(ne);

	X509_set_subject_name(x,name);
	X509_set_issuer_name(x,name);

	/* finished with structure */
	X509_NAME_free(name);

	data=X509v3_pack_string(NULL,V_ASN1_BIT_STRING,
		"\001",1);
	ex=X509_EXTENSION_create_by_NID(NULL,NID_netscape_cert_type,0,data);
	X509_add_ext(x,ex,-1);

	X509v3_pack_string(&data,V_ASN1_IA5STRING,
		"example comment extension",-1);
	X509_EXTENSION_create_by_NID(&ex,NID_netscape_comment,0,data);
	X509_add_ext(x,ex,-1);

	X509v3_pack_string(&data,V_ASN1_BIT_STRING,
		"www.cryptsoft.com",-1);
	X509_EXTENSION_create_by_NID(&ex,NID_netscape_ssl_server_name,0,data);
	X509_add_ext(x,ex,-1);
	
	X509_EXTENSION_free(ex);
	ASN1_OCTET_STRING_free(data);

	if (!X509_sign(x,pk,EVP_md5()))
		goto err;

	*x509p=x;
	*pkeyp=pk;
	return(1);
err:
	return(0);
	}
			 



