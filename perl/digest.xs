#include "p5SSLeay.h"

int boot_digest()
	{
	SSLeay_add_all_digests();
	return(1);
	}

MODULE =  SSLeay::MD	PACKAGE = SSLeay::MD	PREFIX = p5_EVP_MD_

PROTOTYPES: ENABLE
VERSIONCHECK: DISABLE

# SSLeay::MD::new(name) name= md2, md5, sha, sha1, or mdc2
#	md->name() - returns the name
#	md->init() - reinitalises the digest
#	md->update(data) - adds more data to digest
#	digest=md->final() - returns digest
#

void
p5_EVP_MD_new(...)
	PREINIT:
		EVP_MD_CTX *ctx;
		EVP_MD *md;
		char *name;
	PPCODE:
		if ((items == 1) && SvPOK(ST(0)))
			name=SvPV(ST(0),na);
		else if ((items == 2) && SvPOK(ST(1)))
			name=SvPV(ST(1),na);
		else
			croak("Usage: SSLeay::MD::new(type)");
		PUSHs(sv_newmortal());
		md=EVP_get_digestbyname(name);
		if (md != NULL)
			{
			ctx=malloc(sizeof(EVP_MD_CTX));
			EVP_DigestInit(ctx,md);
			sv_setref_pv(ST(0), "SSLeay::MD", (void*)ctx);
			}

datum
p5_EVP_MD_name(ctx)
	EVP_MD_CTX *ctx
	CODE:
		RETVAL.dptr=OBJ_nid2ln(EVP_MD_type(EVP_MD_CTX_type(ctx)));
		RETVAL.dsize=strlen(RETVAL.dptr);
	OUTPUT:
		RETVAL
	
void
p5_EVP_MD_init(ctx)
	EVP_MD_CTX *ctx
	CODE:
		EVP_DigestInit(ctx,EVP_MD_CTX_type(ctx));

void
p5_EVP_MD_update(ctx, in)
	EVP_MD_CTX *ctx
	datum in
	CODE:
		EVP_DigestUpdate(ctx,in.dptr,in.dsize);

datum
p5_EVP_MD_final(ctx)
	EVP_MD_CTX *ctx
	PREINIT:
		char md[EVP_MAX_MD_SIZE];
		int len;
	CODE:
		EVP_DigestFinal(ctx,md,&len);
		RETVAL.dptr=md;
		RETVAL.dsize=len;
	OUTPUT:
		RETVAL

void
p5_EVP_MD_DESTROY(ctx)
	EVP_MD_CTX *ctx
	CODE:
	free((char *)ctx);

