/* NOCW */
/*
        Please read the README file for condition of use, before
        using this software.

        Maurice Gittens  <mgittens@gits.nl>   January 1997

*/

#include <unistd.h>
#include <stdio.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <strings.h>
#include <stdlib.h>

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

EVP_PKEY * ReadPublicKey(const char *certfile)
{
  FILE *fp = fopen (certfile, "r");   
  X509 *x509;
  EVP_PKEY *pkey;

  if (!fp) 
     return NULL; 

  x509 = (X509 *)PEM_ASN1_read ((char *(*)())d2i_X509,
                                   PEM_STRING_X509,
                                   fp, NULL, NULL);

  if (x509 == NULL) 
  {  
     ERR_print_errors_fp (stderr);
     return NULL;   
  }

  fclose (fp);
  
  pkey=X509_extract_key(x509);

  X509_free(x509);

  if (pkey == NULL) 
     ERR_print_errors_fp (stderr);

  return pkey; 
}

EVP_PKEY *ReadPrivateKey(const char *keyfile)
{
	FILE *fp = fopen(keyfile, "r");
	EVP_PKEY *pkey;

	if (!fp)
		return NULL;

	pkey = (EVP_PKEY*)PEM_ASN1_read ((char *(*)())d2i_PrivateKey,
                              PEM_STRING_EVP_PKEY,
                              fp,
                              NULL, NULL);

	fclose (fp);

  	if (pkey == NULL) 
		ERR_print_errors_fp (stderr);   

	return pkey;
}


