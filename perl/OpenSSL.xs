/*
**  OpenSSL.xs
*/

#include "openssl.h"

SV *new_ref(type,obj,mort)
char *type;
char *obj;
	{
	SV *ret;

	if (mort)
		ret=sv_newmortal();
	else
		ret=newSViv(0);
printf(">new_ref %d\n",type);
	sv_setref_pv(ret,type,(void *)obj);
	return(ret);
	}

int ex_new(obj,data,ad,idx,argl,argp)
char *obj;
SV *data;
CRYPTO_EX_DATA *ad;
int idx;
long argl;
char *argp;
	{
	SV *sv;

fprintf(stderr,"ex_new %08X %s\n",obj,argp);
	sv=sv_newmortal();
	sv_setref_pv(sv,argp,(void *)obj);
printf("%d>new_ref '%s'\n",sv,argp);
	CRYPTO_set_ex_data(ad,idx,(char *)sv);
	return(1);
	}

void ex_cleanup(obj,data,ad,idx,argl,argp)
char *obj;
SV *data;
CRYPTO_EX_DATA *ad;
int idx;
long argl;
char *argp;
	{
	pr_name("ex_cleanup");
fprintf(stderr,"ex_cleanup %08X %s\n",obj,argp);
	if (data != NULL)
		SvREFCNT_dec((SV *)data);
	}

MODULE =  OpenSSL        PACKAGE = OpenSSL

BOOT:
	boot_bio();
	boot_cipher();
	boot_digest();
	boot_err();
	boot_ssl();
	boot_OpenSSL__BN();
	boot_OpenSSL__BIO();
	boot_OpenSSL__Cipher();
	boot_OpenSSL__MD();
	boot_OpenSSL__ERR();
	boot_OpenSSL__SSL();
	boot_OpenSSL__X509();

