
#include "openssl.h"

int sv_to_BIGNUM(var,arg,name)
BIGNUM **var;
SV *arg;
char *name;
	{
	int ret=1;

	if (sv_derived_from(arg,"OpenSSL::BN"))
		{
		IV tmp = SvIV((SV*)SvRV(arg));
		*var = (BIGNUM *) tmp;
		}
	else if (SvIOK(arg)) {
		SV *tmp=sv_newmortal();
		*var=BN_new();
		BN_set_word(*var,SvIV(arg));
		sv_setref_pv(tmp,"OpenSSL::BN",(void*)*var);
		}
	else if (SvPOK(arg)) {
		char *ptr;
		STRLEN len;
		SV *tmp=sv_newmortal();
		*var=BN_new();
		sv_setref_pv(tmp,"OpenSSL::BN", (void*)*var);
		ptr=SvPV(arg,len);
		SvGROW(arg,len+1);
		ptr[len]='\0';
		BN_dec2bn(var,ptr);
		}
	else
		{
		croak(name);
		ret=0;
		}
	return(ret);
	}

typedef struct gpc_args_st {
	SV *cb;
	SV *arg;
	} GPC_ARGS;

static void generate_prime_callback(pos,num,arg)
int pos;
int num;
char *arg;
	{
	dSP ;
	int i;
	GPC_ARGS *a=(GPC_ARGS *)arg;

	ENTER ;
	SAVETMPS ;

	PUSHMARK(sp);
	XPUSHs(sv_2mortal(newSViv(pos)));
	XPUSHs(sv_2mortal(newSViv(num)));
	XPUSHs(sv_2mortal(newSVsv(a->arg)));
	PUTBACK;

	i=perl_call_sv(a->cb,G_DISCARD);

	SPAGAIN;

	PUTBACK;
	FREETMPS;
	LEAVE;
	}

MODULE =  OpenSSL::BN	PACKAGE = OpenSSL::BN	PREFIX = p5_BN_

PROTOTYPES: ENABLE
VERSIONCHECK: DISABLE

void
p5_BN_new(...)
	PREINIT:
		BIGNUM *bn;
		SV *arg;
	PPCODE:
		pr_name("p5_BN_new");
		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		bn=BN_new();
		sv_setref_pv(ST(0), "OpenSSL::BN", (void*)bn);

void
p5_BN_dup(a)
	BIGNUM *a;
	PREINIT:
		BIGNUM *bn;
	PPCODE:
		pr_name("p5_BN_dup");
		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		bn=BN_dup(a);
		sv_setref_pv(ST(0), "OpenSSL::BN", (void*)bn);

void
p5_BN_rand(bits,...)
	int bits;
	PREINIT:
		int top=1;
		int bottom=0;
		BIGNUM *ret;
	PPCODE:	
		pr_name("p5_BN_rand");
		if ((items < 1) || (items > 3))
			croak("Usage: OpenSSL::BN::rand(bits[,top_bit][,bottombit]");
		if (items >= 2) top=(int)SvIV(ST(0));
		if (items >= 3) bottom=(int)SvIV(ST(1));
		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		ret=BN_new();
		BN_rand(ret,bits,top,bottom);
		sv_setref_pv(ST(0), "OpenSSL::BN", (void*)ret);

void
p5_BN_bin2bn(a)
	datum a;
	PREINIT:
		BIGNUM *ret;
	PPCODE:
		pr_name("p5_BN_bin2bn");
		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		ret=BN_bin2bn(a.dptr,a.dsize,NULL);
		sv_setref_pv(ST(0), "OpenSSL::BN", (void*)ret);

void
p5_BN_bn2bin(a)
	BIGNUM *a;
	PREINIT:
		int i;
	PPCODE:
		pr_name("p5_BN_bn2bin");
		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		i=BN_num_bytes(a)+2;
		sv_setpvn(ST(0),"",1);
		SvGROW(ST(0),i+1);
		SvCUR_set(ST(0),BN_bn2bin(a,SvPV(ST(0),na)));

void
p5_BN_mpi2bn(a)
	datum a;
	PREINIT:
		BIGNUM *ret;
	PPCODE:
		pr_name("p5_BN_mpi2bn");
		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		ret=BN_mpi2bn(a.dptr,a.dsize,NULL);
		sv_setref_pv(ST(0), "OpenSSL::BN", (void*)ret);

void
p5_BN_bn2mpi(a)
	BIGNUM *a;
	PREINIT:
		int i;
	PPCODE:
		pr_name("p5_BN_bn2mpi");
		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		i=BN_bn2mpi(a,NULL);
		sv_setpvn(ST(0),"",1);
		SvGROW(ST(0),i+1);
		SvCUR_set(ST(0),BN_bn2mpi(a,SvPV(ST(0),na)));

void
p5_BN_hex2bn(a)
	datum a;
	PREINIT:
		BIGNUM *ret;
	PPCODE:
		pr_name("p5_BN_hex2bn");
		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		ret=BN_new();
		sv_setref_pv(ST(0), "OpenSSL::BN", (void*)ret);
		BN_hex2bn(&ret,a.dptr);

void
p5_BN_dec2bn(a)
	datum a;
	PREINIT:
		BIGNUM *ret;
	PPCODE:
		pr_name("p5_BN_dec2bn");
		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		ret=BN_new();
		sv_setref_pv(ST(0), "OpenSSL::BN", (void*)ret);
		BN_dec2bn(&ret,a.dptr);

SV *
p5_BN_bn2hex(a)
	BIGNUM *a;
	PREINIT:
		char *ptr;
		int i;
	CODE:
		pr_name("p5_BN_bn2hex");
		ptr=BN_bn2hex(a);
		RETVAL=newSVpv("",0);
		i=strlen(ptr);
		SvGROW(RETVAL,i+1);
		memcpy(SvPV(RETVAL,na),ptr,i+1);
		SvCUR_set(RETVAL,i);
		Free(ptr);
	OUTPUT:
		RETVAL

SV *
p5_BN_bn2dec(a)
	BIGNUM *a;
	PREINIT:
		char *ptr;
		int i;
	CODE:
		pr_name("p5_BN_bn2dec");
		ptr=BN_bn2dec(a);
		RETVAL=newSVpv("",0);
		i=strlen(ptr);
		SvGROW(RETVAL,i+1);
		memcpy(SvPV(RETVAL,na),ptr,i+1);
		SvCUR_set(RETVAL,i);
		Free(ptr);
	OUTPUT:
		RETVAL

void
p5_BN_add(a,b)
	BIGNUM *a;
	BIGNUM *b;
	PREINIT:
		BIGNUM *ret;
	PPCODE:
		pr_name("p5_BN_add");
		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		ret=BN_new();
		sv_setref_pv(ST(0), "OpenSSL::BN", (void*)ret);
		BN_add(ret,a,b);

void
p5_BN_sub(a,b)
	BIGNUM *a;
	BIGNUM *b;
	PREINIT:
		BIGNUM *ret;
	PPCODE:
		pr_name("p5_BN_sub");
		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		ret=BN_new();
		sv_setref_pv(ST(0), "OpenSSL::BN", (void*)ret);
		BN_sub(ret,a,b);

void
p5_BN_mul(a,b)
	BIGNUM *a;
	BIGNUM *b;
	PREINIT:
		static BN_CTX *ctx=NULL;
		BIGNUM *ret;
	PPCODE:
		pr_name("p5_BN_mul");
		if (ctx == NULL) ctx=BN_CTX_new();
		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		ret=BN_new();
		sv_setref_pv(ST(0), "OpenSSL::BN", (void*)ret);
		BN_mul(ret,a,b,ctx);

void
p5_BN_div(a,b)
	BIGNUM *a;
	BIGNUM *b;
	PREINIT:
		static BN_CTX *ctx=NULL;
		BIGNUM *div,*mod;
	PPCODE:
		pr_name("p5_BN_div");
		if (ctx == NULL) ctx=BN_CTX_new();
		EXTEND(sp,2);
		PUSHs(sv_newmortal());
		PUSHs(sv_newmortal());
		div=BN_new();
		mod=BN_new();
		sv_setref_pv(ST(0), "OpenSSL::BN", (void*)div);
		sv_setref_pv(ST(1), "OpenSSL::BN", (void*)mod);
		BN_div(div,mod,a,b,ctx);

void
p5_BN_mod(a,b)
	BIGNUM *a;
	BIGNUM *b;
	PREINIT:
		static BN_CTX *ctx=NULL;
		BIGNUM *rem;
	PPCODE:
		pr_name("p5_BN_mod");
		if (ctx == NULL) ctx=BN_CTX_new();
		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		rem=BN_new();
		sv_setref_pv(ST(0), "OpenSSL::BN", (void*)rem);
		BN_mod(rem,a,b,ctx);

void
p5_BN_exp(a,p)
	BIGNUM *a;
	BIGNUM *p;
	PREINIT:
		BIGNUM *ret;
		static BN_CTX *ctx=NULL;
	PPCODE:
		pr_name("p5_BN_exp");
		if (ctx == NULL) ctx=BN_CTX_new();
		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		ret=BN_new();
		sv_setref_pv(ST(0), "OpenSSL::BN", (void*)ret);
		BN_exp(ret,a,p,ctx);

void
p5_BN_mod_mul(a,b,c)
	BIGNUM *a;
	BIGNUM *b;
	BIGNUM *c;
	PREINIT:
		static BN_CTX *ctx=NULL;
		BIGNUM *ret;
	PPCODE:
		pr_name("p5_BN_mod_mul");
		if (ctx == NULL) ctx=BN_CTX_new();
		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		ret=BN_new();
		sv_setref_pv(ST(0), "OpenSSL::BN", (void*)ret);
		BN_mod_mul(ret,a,b,c,ctx);

void
p5_BN_mod_exp(a,b,c)
	BIGNUM *a;
	BIGNUM *b;
	BIGNUM *c;
	PREINIT:
		static BN_CTX *ctx=NULL;
		BIGNUM *ret;
	PPCODE:
		pr_name("p5_BN_mod_exp");
		if (ctx == NULL) ctx=BN_CTX_new();
		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		ret=BN_new();
		sv_setref_pv(ST(0), "OpenSSL::BN", (void*)ret);
		BN_mod_exp(ret,a,b,c,ctx);

void
p5_BN_generate_prime(...)
	PREINIT:
		int bits=512;
		int strong=0;
		BIGNUM *ret=NULL;
		SV *callback=NULL;
		SV *cb_arg=NULL;
		GPC_ARGS arg;
		dSP;

	PPCODE:
		pr_name("p5_BN_generate_prime");
		if ((items < 0) || (items > 4))
			croak("Usage: OpenSSL::BN::generate_prime(a[,strong][,callback][,cb_arg]");
		if (items >= 1) bits=(int)SvIV(ST(0));
		if (items >= 2) strong=(int)SvIV(ST(1));
		if (items >= 3) callback=ST(2);
		if (items == 4) cb_arg=ST(3);

		if (callback == NULL)
			ret=BN_generate_prime(ret,bits,strong,NULL,NULL,NULL,NULL);
		else
			{
			arg.cb=callback;
			arg.arg=cb_arg;

			ret=BN_generate_prime(ret,bits,strong,NULL,NULL,
				generate_prime_callback,(char *)&arg);
			}

		SPAGAIN;
		sp-=items; /* a bit evil that I do this */

		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		sv_setref_pv(ST(0), "OpenSSL::BN", (void*)ret);

void
p5_BN_is_prime(p,...)
	BIGNUM *p;
	PREINIT:
	int nchecks=5,ret;
	SV *callback=NULL;
	SV *cb_arg=NULL;
	GPC_ARGS arg;
	dSP;
	static BN_CTX *ctx=NULL;
	PPCODE:
		pr_name("p5_BN_is_prime");
		if ((items < 1) || (items > 4))
			croak("Usage: OpenSSL::BN::is_prime(a[,ncheck][,callback][,callback_arg]");
		if (ctx == NULL) ctx=BN_CTX_new();
		if (items >= 2) nchecks=(int)SvIV(ST(1));
		if (items >= 3) callback=ST(2);
		if (items >= 4) cb_arg=ST(3);
		arg.arg=cb_arg; 
		if (callback == NULL)
			ret=BN_is_prime(p,nchecks,NULL,ctx,NULL);
		else
			{
			arg.cb=callback;
			arg.arg=cb_arg;
			ret=BN_is_prime(p,nchecks,generate_prime_callback,
				ctx,(char *)&arg);
			}
		SPAGAIN;
		sp-=items; /* a bit evil */
		PUSHs(sv_2mortal(newSViv(ret)));

int
p5_BN_num_bits(a)
	BIGNUM *a;
	CODE:
		pr_name("p5_BN_num_bits");
		RETVAL=BN_num_bits(a);
	OUTPUT:
		RETVAL

int
p5_BN_cmp(a,b)
	BIGNUM *a;
	BIGNUM *b;
	CODE:
		pr_name("p5_BN_cmp");
		RETVAL=BN_cmp(a,b);
	OUTPUT:
		RETVAL

int
p5_BN_ucmp(a,b)
	BIGNUM *a;
	BIGNUM *b;
	CODE:
		pr_name("p5_BN_ucmp");
		RETVAL=BN_ucmp(a,b);
	OUTPUT:
		RETVAL

int
p5_BN_is_bit_set(a,b)
	BIGNUM *a;
	int b;
	CODE:
		pr_name("p5_BN_is_bit_set");
		RETVAL=BN_is_bit_set(a,b);
	OUTPUT:
		RETVAL

void
p5_BN_set_bit(a,b)
	BIGNUM *a;
	int b;
	PREINIT:
		BIGNUM *ret;
	PPCODE:
		pr_name("p5_BN_set_bit");
		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		ret=BN_dup(a);
		sv_setref_pv(ST(0), "OpenSSL::BN", (void*)ret);
		BN_set_bit(ret,b);

void
p5_BN_clear_bit(a,b)
	BIGNUM *a;
	int b;
	PREINIT:
		BIGNUM *ret;
	PPCODE:
		pr_name("p5_BN_clear_bit");
		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		ret=BN_dup(a);
		sv_setref_pv(ST(0), "OpenSSL::BN", (void*)ret);
		BN_clear_bit(ret,b);

void
p5_BN_lshift(a,b)
	BIGNUM *a;
	int b;
	PREINIT:
		BIGNUM *ret;
	PPCODE:
		pr_name("p5_BN_lshift");
		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		ret=BN_new();
		sv_setref_pv(ST(0), "OpenSSL::BN", (void*)ret);
		if (b == 1)
			BN_lshift1(ret,a);
		else
			BN_lshift(ret,a,b);

void
p5_BN_rshift(a,b)
	BIGNUM *a;
	int b;
	PREINIT:
		BIGNUM *ret;
	PPCODE:
		pr_name("p5_BN_rshift");
		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		ret=BN_new();
		sv_setref_pv(ST(0), "OpenSSL::BN", (void*)ret);
		if (b == 1)
			BN_rshift1(ret,a);
		else
			BN_rshift(ret,a,b);

void
p5_BN_mask_bits(a,b)
	BIGNUM *a;
	int b;
	PREINIT:
		BIGNUM *ret;
	PPCODE:
		pr_name("p5_BN_mask_bits");
		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		ret=BN_dup(a);
		sv_setref_pv(ST(0), "OpenSSL::BN", (void*)ret);
		BN_mask_bits(ret,b);

void
p5_BN_clear(a)
	BIGNUM *a;
	PPCODE:
		pr_name("p5_BN_clear");
		BN_clear(a);

void
p5_BN_gcd(a,b)
	BIGNUM *a;
	BIGNUM *b;
	PREINIT:
		static BN_CTX *ctx=NULL;
		BIGNUM *ret;
	PPCODE:
		pr_name("p5_BN_gcd");
		if (ctx == NULL) ctx=BN_CTX_new();
		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		ret=BN_new();
		sv_setref_pv(ST(0), "OpenSSL::BN", (void*)ret);
		BN_gcd(ret,a,b,ctx);

void
p5_BN_mod_inverse(a,mod)
	BIGNUM *a;
	BIGNUM *mod;
	PREINIT:
		static BN_CTX *ctx=NULL;
		BIGNUM *ret;
	PPCODE:
		pr_name("p5_BN_mod_inverse");
		if (ctx == NULL) ctx=BN_CTX_new();
		ret=BN_mod_inverse(ret,a,mod,ctx);
		EXTEND(sp,1);
		PUSHs(sv_newmortal());
		sv_setref_pv(ST(0), "OpenSSL::BN", (void*)ret);

void
p5_BN_DESTROY(bn)
	BIGNUM *bn
	CODE:
	pr_name("p5_BN_DESTROY");
	BN_free(bn);

