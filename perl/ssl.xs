#include "p5SSLeay.h"

static int p5_ssl_ex_ssl_ptr=0;
static int p5_ssl_ex_ssl_info_callback=0;
static int p5_ssl_ex_ssl_ctx_ptr=0;
static int p5_ssl_ctx_ex_ssl_info_callback=0;

typedef struct ssl_ic_args_st {
	SV *cb;
	SV *arg;
	} SSL_IC_ARGS;

static void p5_ssl_info_callback(ssl,mode,ret)
SSL *ssl;
int mode;
int ret;
	{
	int i;
	SV *me,*cb;

	me=(SV *)SSL_get_ex_data(ssl,p5_ssl_ex_ssl_ptr);
	cb=(SV *)SSL_get_ex_data(ssl,p5_ssl_ex_ssl_info_callback);
	if (cb == NULL)
		cb=(SV *)SSL_CTX_get_ex_data(
			SSL_get_SSL_CTX(ssl),p5_ssl_ctx_ex_ssl_info_callback);
	if (cb != NULL)
		{
		dSP;

		PUSHMARK(sp);
		XPUSHs(me);
		XPUSHs(sv_2mortal(newSViv(mode)));
		XPUSHs(sv_2mortal(newSViv(ret)));
		PUTBACK;

		i=perl_call_sv(cb,G_DISCARD);
		}
	else
		{
		croak("Internal error in SSL p5_ssl_info_callback");
		}
	}

int boot_ssl()
	{
	p5_ssl_ex_ssl_ptr=		
		SSL_get_ex_new_index(0,"SSLeay::SSL",ex_new,NULL,ex_cleanup);
	p5_ssl_ex_ssl_info_callback=
		SSL_get_ex_new_index(0,"ssl_info_callback",NULL,NULL,
			ex_cleanup);
	p5_ssl_ex_ssl_ctx_ptr=
		SSL_get_ex_new_index(0,"ssl_ctx_ptr",NULL,NULL,
			ex_cleanup);
	p5_ssl_ctx_ex_ssl_info_callback=
		SSL_CTX_get_ex_new_index(0,"ssl_ctx_info_callback",NULL,NULL,
			ex_cleanup);
	return(1);
	}

MODULE =  SSLeay::SSL	PACKAGE = SSLeay::SSL::CTX PREFIX = p5_SSL_CTX_

VERSIONCHECK: DISABLE

void
p5_SSL_CTX_new(...)
	PREINIT:
		SSL_METHOD *meth;
		SSL_CTX *ctx;
		char *method;
	PPCODE:
		pr_name("p5_SSL_CTX_new");
		if ((items == 1) && SvPOK(ST(0)))
			method=SvPV(ST(0),na);
		else if ((items == 2) && SvPOK(ST(1)))
			method=SvPV(ST(1),na);
		else
			croak("Usage: SSLeay::SSL_CTX::new(type)");
			
		if (strcmp(method,"SSLv3") == 0)
			meth=SSLv3_method();
		else if (strcmp(method,"SSLv3_client") == 0)
			meth=SSLv3_client_method();
		else if (strcmp(method,"SSLv3_server") == 0)
			meth=SSLv3_server_method();
		else if (strcmp(method,"SSLv23") == 0)
			meth=SSLv23_method();
		else if (strcmp(method,"SSLv23_client") == 0)
			meth=SSLv23_client_method();
		else if (strcmp(method,"SSLv23_server") == 0)
			meth=SSLv23_server_method();
		else if (strcmp(method,"SSLv2") == 0)
			meth=SSLv2_method();
		else if (strcmp(method,"SSLv2_client") == 0)
			meth=SSLv2_client_method();
		else if (strcmp(method,"SSLv2_server") == 0)
			meth=SSLv2_server_method();
		else
			{
			croak("Not passed a valid SSL method name, should be 'SSLv[23] [client|server]'");
			}
		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		ctx=SSL_CTX_new(meth);
		sv_setref_pv(ST(0), "SSLeay::SSL::CTX", (void*)ctx);

int
p5_SSL_CTX_use_PrivateKey_file(ctx,file,...)
	SSL_CTX *ctx;
	char *file;
	PREINIT:
		int i=SSL_FILETYPE_PEM;
		char *ptr;
	CODE:
		pr_name("p5_SSL_CTX_use_PrivateKey_file");
		if (items > 3)
			croak("SSLeay::SSL::CTX::use_PrivateKey_file(ssl_ctx,file[,type])");
		if (items == 3)
			{
			ptr=SvPV(ST(2),na);
			if (strcmp(ptr,"der") == 0)
				i=SSL_FILETYPE_ASN1;
			else
				i=SSL_FILETYPE_PEM;
			}
		RETVAL=SSL_CTX_use_RSAPrivateKey_file(ctx,file,i);
	OUTPUT:
		RETVAL

int
p5_SSL_CTX_set_options(ctx,...)
	SSL_CTX *ctx;
	PREINIT:
		int i;
		char *ptr;
		SV *sv;
	CODE:
		pr_name("p5_SSL_CTX_set_options");

		for (i=1; i<items; i++)
			{
			if (!SvPOK(ST(i)))
				croak("Usage: SSLeay::SSL_CTX::set_options(ssl_ctx[,option,value]+)");
			ptr=SvPV(ST(i),na);
			if (strcmp(ptr,"-info_callback") == 0)
				{
				SSL_CTX_set_info_callback(ctx,
					p5_ssl_info_callback);
				sv=sv_mortalcopy(ST(i+1));
				SvREFCNT_inc(sv);
				SSL_CTX_set_ex_data(ctx,
					p5_ssl_ctx_ex_ssl_info_callback,
						(char *)sv);
				i++;
				}
			else
				{
				croak("SSLeay::SSL_CTX::set_options(): unknown option");
				}
			}

void
p5_SSL_CTX_DESTROY(ctx)
	SSL_CTX *ctx
	PREINIT:
		SV *sv;
	PPCODE:
		pr_name_d("p5_SSL_CTX_DESTROY",ctx->references);
		SSL_CTX_free(ctx);

MODULE =  SSLeay::SSL	PACKAGE = SSLeay::SSL PREFIX = p5_SSL_

void
p5_SSL_new(...)
	PREINIT:
		SV *sv_ctx;
		SSL_CTX *ctx;
		SSL *ssl;
		int i;
		SV *arg;
	PPCODE:
		pr_name("p5_SSL_new");
		if ((items != 1) && (items != 2))
			croak("Usage: SSLeay::SSL::new(ssl_ctx)");
		if (sv_derived_from(ST(items-1),"SSLeay::SSL::CTX"))
			{
			IV tmp = SvIV((SV*)SvRV(ST(items-1)));
			ctx=(SSL_CTX *)tmp;
			sv_ctx=ST(items-1);
			}
		else
			croak("ssl_ctx is not of type SSLeay::SSL::CTX");

		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		ssl=SSL_new(ctx);
		sv_setref_pv(ST(0), "SSLeay::SSL", (void*)ssl);

		/* Now this is being a little hairy, we keep a pointer to
		 * our perl reference.  We need to do a different one
		 * to the one we return because it will have it's reference
		 * count droped to 0 apon return and if we up its reference
		 * count, it will never be DESTROYED */
		arg=newSVsv(ST(0));
		SSL_set_ex_data(ssl,p5_ssl_ex_ssl_ptr,(char *)arg);
		SvREFCNT_inc(sv_ctx);
		SSL_set_ex_data(ssl,p5_ssl_ex_ssl_ctx_ptr,(char *)sv_ctx);

int
p5_SSL_connect(ssl)
	SSL *ssl;
	CODE:
		RETVAL=SSL_connect(ssl);
	OUTPUT:
		RETVAL

int
p5_SSL_accept(ssl)
	SSL *ssl;
	CODE:
		RETVAL=SSL_connect(ssl);
	OUTPUT:
		RETVAL

int
p5_SSL_sysread(ssl,in,num, ...)
	SSL *ssl;
	SV *in;
	int num;
	PREINIT:
		int i,n,olen;
		int offset;
		char *p;
	CODE:
		offset=0;
		if (!SvPOK(in))
			sv_setpvn(in,"",0);
		SvPV(in,olen);
		if (items > 3)
			{
			offset=SvIV(ST(3));
			if (offset < 0)
				{
				if (-offset > olen)
					croad("Offset outside string");
				offset+=olen;
				}
			}
		if ((num+offset) > olen)
			{
			SvGROW(in,num+offset+1);
			p=SvPV(in,i);
			memset(&(p[olen]),0,(num+offset)-olen+1);
			}
		p=SvPV(in,n);

		i=SSL_read(ssl,p+offset,num);
		RETVAL=i;
		if (i <= 0) i=0;
		SvCUR_set(in,offset+i);
	OUTPUT:
		RETVAL

int
p5_SSL_syswrite(ssl,in, ...)
	SSL *ssl;
	SV *in;
	PREINIT:
		char *ptr;
		int len,in_len;
		int offset=0;
		int n;
	CODE:
		ptr=SvPV(in,in_len);
		if (items > 2)
			{
			len=SvOK(ST(2))?SvIV(ST(2)):in_len;
			if (items > 3)
				{
				offset=SvIV(ST(3));
				if (offset < 0)
					{
					if (-offset > in_len)
						croak("Offset outside string");
					offset+=in_len;
					}
				else if ((offset >= in_len) && (in_len > 0))
					croak("Offset outside string");
				}
			if (len >= (in_len-offset))
				len=in_len-offset;
			}
		else
			len=in_len;

		RETVAL=SSL_write(ssl,ptr+offset,len);
	OUTPUT:
		RETVAL

void
p5_SSL_set_bio(ssl,bio)
	SSL *ssl;
	BIO *bio;
	CODE:
		bio->references++;
		SSL_set_bio(ssl,bio,bio);

int
p5_SSL_set_options(ssl,...)
	SSL *ssl;
	PREINIT:
		int i;
		char *ptr;
		SV *sv;
	CODE:
		pr_name("p5_SSL_set_options");

		for (i=1; i<items; i++)
			{
			if (!SvPOK(ST(i)))
				croak("Usage: SSLeay::SSL::set_options(ssl[,option,value]+)");
			ptr=SvPV(ST(i),na);
			if (strcmp(ptr,"-info_callback") == 0)
				{
				SSL_set_info_callback(ssl,
					p5_ssl_info_callback);
				sv=sv_mortalcopy(ST(i+1));
				SvREFCNT_inc(sv);
				SSL_set_ex_data(ssl,
					p5_ssl_ex_ssl_info_callback,(char *)sv);
				i++;
				}
			else if (strcmp(ptr,"-connect_state") == 0)
				{
				SSL_set_connect_state(ssl);
				}
			else if (strcmp(ptr,"-accept_state") == 0)
				{
				SSL_set_accept_state(ssl);
				}
			else
				{
				croak("SSLeay::SSL::set_options(): unknown option");
				}
			}

void
p5_SSL_state(ssl)
	SSL *ssl;
	PREINIT:
		int state;
	PPCODE:
		pr_name("p5_SSL_state");
		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		state=SSL_state(ssl);
		sv_setpv(ST(0),SSL_state_string_long(ssl));
		sv_setiv(ST(0),state);
		SvPOK_on(ST(0));

void
p5_SSL_DESTROY(ssl)
	SSL *ssl;
	CODE:
	pr_name_dd("p5_SSL_DESTROY",ssl->references,ssl->ctx->references);
	fprintf(stderr,"SSL_DESTROY %d\n",ssl->references);
	SSL_free(ssl);

int
p5_SSL_references(ssl)
	SSL *ssl;
	CODE:
		RETVAL=ssl->references;
	OUTPUT:
		RETVAL

int
p5_SSL_do_handshake(ssl)
	SSL *ssl;
	CODE:
		RETVAL=SSL_do_handshake(ssl);
	OUTPUT:
		RETVAL

int
p5_SSL_renegotiate(ssl)
	SSL *ssl;
	CODE:
		RETVAL=SSL_renegotiate(ssl);
	OUTPUT:
		RETVAL

int
p5_SSL_shutdown(ssl)
	SSL *ssl;
	CODE:
		RETVAL=SSL_shutdown(ssl);
	OUTPUT:
		RETVAL

char *
p5_SSL_get_version(ssl)
	SSL *ssl;
	CODE:
		RETVAL=SSL_get_version(ssl);
	OUTPUT:
		RETVAL

SSL_CIPHER *
p5_SSL_get_current_cipher(ssl)
	SSL *ssl;
	CODE:
		RETVAL=SSL_get_current_cipher(ssl);
	OUTPUT:
		RETVAL

X509 *
p5_SSL_get_peer_certificate(ssl)
	SSL *ssl
	CODE:
		RETVAL=SSL_get_peer_certificate(ssl);
	OUTPUT:
		RETVAL

MODULE =  SSLeay::SSL	PACKAGE = SSLeay::SSL::CIPHER PREFIX = p5_SSL_CIPHER_

int
p5_SSL_CIPHER_get_bits(sc)
	SSL_CIPHER *sc
	PREINIT:
		int i,ret;
	PPCODE:
		EXTEND(sp,2);
		PUSHs(sv_newmortal());
		PUSHs(sv_newmortal());
		ret=SSL_CIPHER_get_bits(sc,&i);
		sv_setiv(ST(0),(IV)ret);
		sv_setiv(ST(1),(IV)i);

char *
p5_SSL_CIPHER_get_version(sc)
	SSL_CIPHER *sc
	CODE:
		RETVAL=SSL_CIPHER_get_version(sc);
	OUTPUT:
		RETVAL

char *
p5_SSL_CIPHER_get_name(sc)
	SSL_CIPHER *sc
	CODE:
		RETVAL=SSL_CIPHER_get_name(sc);
	OUTPUT:
		RETVAL

MODULE =  SSLeay::SSL	PACKAGE = SSLeay::BIO PREFIX = p5_BIO_

void
p5_BIO_get_ssl(bio)
	BIO *bio;
	PREINIT:
		SSL *ssl;
		SV *ret;
		int i;
	PPCODE:
		if ((i=BIO_get_ssl(bio,&ssl)) > 0)
			{
			ret=(SV *)SSL_get_ex_data(ssl,p5_ssl_ex_ssl_ptr);
			ret=sv_mortalcopy(ret);
			}
		else
			ret= &sv_undef;
		EXTEND(sp,1);
		PUSHs(ret);

