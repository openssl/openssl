#include <openssl/opensslconf.h>

#include <string.h>
#include <openssl/bio.h>
#include <openssl/dso.h>

#include "ssl.h"

#ifndef OPENSSL_SYS_WIN32
#include <netdb.h>
#include <sys/socket.h>
#endif

#ifndef OPENSSL_NO_LIBUNBOUND
#include <unbound.h>

static struct ub_ctx *ctx = NULL;
static DSO *unbound_dso = NULL;

static union {
	void *p; struct ub_ctx *(*f)(); }
	p_ub_ctx_create = {NULL};

static union {
	void *p; int (*f)(struct ub_ctx *,const char *); }
	p_ub_ctx_resolvconf = {NULL};

static union {
	void *p; int (*f)(struct ub_ctx *,const char *); }
	p_ub_ctx_add_ta_file = {NULL};

static union {
	void *p; void (*f)(struct ub_ctx *); }
	p_ub_ctx_delete = {NULL};

static union {
	void *p; int (*f)(struct ub_ctx *,const char *,int,int,struct ub_result**); }
	p_ub_resolve = {NULL};

static union {
	void *p; void (*f)(struct ub_result*); }
	p_ub_resolve_free = {NULL};

#if defined(__GNUC__) && __GNUC__>=2
 static void unbound_init(void) __attribute__((constructor));
 static void unbound_fini(void) __attribute__((destructor));
#endif 

static void unbound_init(void)
{
	DSO *dso;

	if ((dso = DSO_load(NULL, "unbound", NULL, 0)) == NULL) return;

	if ((p_ub_ctx_create.p = DSO_bind_func(dso,"ub_ctx_create")) == NULL ||
	    (p_ub_ctx_resolvconf.p = DSO_bind_func(dso,"ub_ctx_resolvconf")) == NULL ||
	    (p_ub_ctx_add_ta_file.p = DSO_bind_func(dso,"ub_ctx_add_ta_file")) == NULL ||
	    (p_ub_ctx_delete.p = DSO_bind_func(dso,"ub_ctx_delete")) == NULL ||
	    (p_ub_resolve.p = DSO_bind_func(dso,"ub_resolve")) == NULL ||
	    (p_ub_resolve_free.p = DSO_bind_func(dso,"ub_resolve_free")) == NULL ||
	    (ctx = p_ub_ctx_create.f()) == NULL) {
		DSO_free(dso);
		return;
	}

	unbound_dso = dso;

	/* FIXME: parameterize these through CONF */
	p_ub_ctx_resolvconf.f(ctx,"/etc/resolv.conf");
	p_ub_ctx_add_ta_file.f(ctx,"/var/lib/unbound/root.key");
}

static void unbound_fini(void)
{
	if (ctx != NULL) p_ub_ctx_delete.f(ctx);
	if (unbound_dso != NULL) DSO_free(unbound_dso);
}
#endif

/*
 * Output is array packed as [len][data][len][data][0]
 */
unsigned char *SSL_get_tlsa_record_byname (const char *name,int port,int type)
{
	unsigned char *ret=NULL;
	char *query=NULL;
	size_t qlen;

#ifndef OPENSSL_NO_LIBUNBOUND
	if (ctx == NULL) return NULL;
#elif defined(RRSET_VALIDATED)
	static union {
		void *p; int (*f)(const char*,unsigned int,unsigned int,unsigned int,struct rrsetinfo **); }
		p_getrrsetbyname = {NULL};
	static union {
		void *p; void (*f)(struct rrsetinfo *); }
		p_freerrset = {NULL};

	if (p_getrrsetbyname.p==NULL) {
		if ((p_getrrsetbyname.p = DSO_global_lookup("getrrsetbyname")) == NULL ||
		    (p_freerrset.p = DSO_global_lookup("freerrset")) == NULL)
			p_getrrsetbyname.p = (void*)-1;
	}

	if (p_getrrsetbyname.p == (void *)-1) return NULL;
#endif

	qlen = 7+5+strlen(name)+1;
	if ((query = OPENSSL_malloc(qlen)) == NULL)
		return NULL;

	BIO_snprintf(query,qlen,"_%u._%s.%s",port&0xffff,type==SOCK_STREAM?"tcp":"udp",name);

#ifndef OPENSSL_NO_LIBUNBOUND
	{
	struct ub_result *tlsa=NULL;

	if (p_ub_resolve.f(ctx,query,52,1,&tlsa)==0 &&
	    tlsa->havedata && tlsa->data[0]!=NULL) {
		ret=(void*)-1;	/* -1 means insecure */
		if (tlsa->secure) do {
			unsigned char *data;
			unsigned int dlen, i;

			for (dlen=0, i=0; tlsa->data[i]; i++)
				dlen += sizeof(int)+(unsigned int)tlsa->len[i];
			dlen +=sizeof(int);

			if ((ret = OPENSSL_malloc(dlen)) == NULL) break;
			
			for (data=ret, i=0; tlsa->data[i]; i++) {
				dlen = (unsigned int)tlsa->len[i];
				memcpy(data,&dlen,sizeof(dlen));
				data += sizeof(dlen);
				memcpy(data,tlsa->data[i],dlen);
				data += dlen;
			}
			dlen = 0;
			memcpy(data,&dlen,sizeof(dlen)); /* trailing zero */
		} while (0);	
		p_ub_resolve_free.f(tlsa);
	}
	}
#elif defined(RRSET_VALIDATED)
	{
	struct rrsetinfo *rrset=NULL;

	if (p_getrrsetbyname.f(query,1,52,RRSET_VALIDATED,&rrset) == 0 && rrset->rri_nrdatas) {
		ret=(void*)-1;	/* -1 means insecure */
		if ((rrset->rri_flags&RRSET_VALIDATED)) do {
			unsigned char *data;
			unsigned int dlen, i;

			for (dlen=0, i=0; i<rrset->rri_nrdatas; i++)
				dlen += sizeof(int)+rrset->rri_rdatas[i].rdi_length;
			dlen +=sizeof(int);

			if ((ret = OPENSSL_malloc(sizeof(int)+dlen)) == NULL) break;

			for (data=ret, i=0; i<rrset->rri_rdatas[i].rdi_length; i++) {
				*(unsigned int *)data = dlen = rrset->rri_rdatas[i].rdi_length;
				data += sizeof(unsigned int);
				memcpy(data,rrset->rri_rdatas[i].rdi_data,dlen);
				data += dlen;
			}
			*(unsigned int *)data = 0;	/* trailing zero */
		} while (0);	
		p_freerrset.f(rrset);
	}
	}
#elif defined(_WIN32_NOT_YET)
	{
	PDNS_RECORD rrset;

	DnsQuery_A(query,52,DNS_QUERY_STANDARD,NULL,&rrset,NULL);
	DnsRecordListFree(rrset,DnsFreeRecordList);
	}
#endif
	CRYPTO_free(query);

	return ret;
}
