
#include "openssl.h"

MODULE =  OpenSSL::X509	PACKAGE = OpenSSL::X509	PREFIX = p5_X509_

PROTOTYPES: ENABLE
VERSIONCHECK: DISABLE

void
p5_X509_new(void )
	PREINIT:
		X509 *x509;
		SV *arg;
	PPCODE:
		pr_name("p5_X509_new");
		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		x509=X509_new();
		sv_setref_pv(ST(0),"OpenSSL::X509",(void *)x509);

char *
p5_X509_get_subject_name(x509)
	X509 *x509;
	PREINIT:
		char *p;
		X509_NAME *name;
		char buf[1024];
		int i;
	CODE:
		name=X509_get_subject_name(x509);
		X509_NAME_oneline(name,buf,sizeof(buf));
		p= &(buf[0]);
		RETVAL=p;
	OUTPUT:
		RETVAL

char *
p5_X509_get_issuer_name(x509)
	X509 *x509;
	PREINIT:
		char *p;
		X509_NAME *name;
		char buf[1024];
		int i;
	CODE:
		name=X509_get_issuer_name(x509);
		X509_NAME_oneline(name,buf,sizeof(buf));
		p= &(buf[0]);
		RETVAL=p;
	OUTPUT:
		RETVAL

int
p5_X509_get_version(x509)
	X509 *x509;
	CODE:
		RETVAL=X509_get_version(x509);
	OUTPUT:
		RETVAL

BIGNUM *
p5_X509_get_serialNumber(x509)
	X509 *x509;
	CODE:
		RETVAL=ASN1_INTEGER_to_BN(X509_get_serialNumber(x509),NULL);
	OUTPUT:
		RETVAL

void
p5_X509_DESTROY(x509)
	X509 *x509;
	CODE:
	pr_name("p5_X509_DESTROY");
	X509_free(x509);

