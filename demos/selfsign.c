/* NOCW */
/* cc -o ssdemo -I../include selfsign.c ../libcrypto.a */

#include <stdio.h>
#include <stdlib.h>

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>

int mkit(X509 **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days);

int main()
	{
	BIO *bio_err;
	X509 *x509=NULL;
	EVP_PKEY *pkey=NULL;

	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

	X509V3_add_standard_extensions();

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

	X509V3_EXT_cleanup();

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

static void MS_CALLBACK callback(p, n, arg)
int p;
int n;
void *arg;
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
	X509_NAME *name=NULL;
	X509_NAME_ENTRY *ne=NULL;
	X509_EXTENSION *ex=NULL;

	
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

	rsa=RSA_generate_key(bits,RSA_F4,callback,NULL);
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

	/* Add extension using V3 code: we can set the config file as NULL
	 * because we wont reference any other sections. We can also set
         * the context to NULL because none of these extensions below will need
	 * to access it.
	 */

	ex = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_cert_type, "server");
	X509_add_ext(x,ex,-1);

	ex = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_comment,
						"example comment extension");
	X509_add_ext(x,ex,-1);

	ex = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_ssl_server_name,
							"www.openssl.org");

	X509_add_ext(x,ex,-1);

#if 0
	/* might want something like this too.... */
	ex = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints,
							"critical,CA:TRUE");


	X509_add_ext(x,ex,-1);
#endif
	
	if (!X509_sign(x,pk,EVP_md5()))
		goto err;

	*x509p=x;
	*pkeyp=pk;
	return(1);
err:
	return(0);
	}
