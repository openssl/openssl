
#include "openssl.h"

int boot_err()
	{
	SSL_load_error_strings();
	return(1);
	}

MODULE =  OpenSSL::ERR	PACKAGE = OpenSSL::ERR	PREFIX = p5_ERR_

PROTOTYPES: ENABLE
VERSIONCHECK: DISABLE

#	md->error() - returns the last error in text or numeric context

void
p5_ERR_get_error(...)
	PPCODE:
		char buf[512];
		unsigned long l;

		pr_name("p5_ERR_get_code");
		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		l=ERR_get_error();
		ERR_error_string(l,buf);
		sv_setiv(ST(0),l);
		sv_setpv(ST(0),buf);
		SvIOK_on(ST(0));

void
p5_ERR_peek_error(...)
	PPCODE:
		char buf[512];
		unsigned long l;

		pr_name("p5_ERR_get_code");
		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		l=ERR_peek_error();
		ERR_error_string(l,buf);
		sv_setiv(ST(0),l);
		sv_setpv(ST(0),buf);
		SvIOK_on(ST(0));


