#include "tunala.h"

#ifndef NO_OPENSSL

/* For callbacks generating output, here are their file-descriptors. */
static FILE *fp_cb_ssl_info = NULL;
static FILE *fp_cb_ssl_verify = NULL;

/* Other static rubbish (to mirror s_cb.c where required) */
static int int_verify_depth = 10;
static int int_verify_error = X509_V_OK;

/* This function is largely borrowed from the one used in OpenSSL's "s_client"
 * and "s_server" utilities. */
void cb_ssl_info(SSL *s, int where, int ret)
{
	char *str1, *str2;
	int w;

	if(!fp_cb_ssl_info)
		return;

	w = where & ~SSL_ST_MASK;
	str1 = (w & SSL_ST_CONNECT ? "SSL_connect" : (w & SSL_ST_ACCEPT ?
				"SSL_accept" : "undefined")),
	str2 = SSL_state_string_long(s);

	if (where & SSL_CB_LOOP)
		fprintf(fp_cb_ssl_info, "%s:%s\n", str1, str2);
	else if (where & SSL_CB_EXIT) {
		if (ret == 0)
			fprintf(fp_cb_ssl_info, "%s:failed in %s\n", str1, str2);
		else if (ret < 0)
			fprintf(fp_cb_ssl_info, "%s:error in %s\n", str1, str2);
	}
}

void cb_ssl_info_set_output(FILE *fp)
{
	fp_cb_ssl_info = fp;
}

/* Stolen wholesale from apps/s_cb.c :-) */
int cb_ssl_verify(int ok, X509_STORE_CTX *ctx)
{
	char buf[256];
	X509 *err_cert;
	int err, depth;
	BIO *bio;

	if(!fp_cb_ssl_verify)
		return ok;
	/* There's no <damned>FILE*</damned> version of ASN1_TIME_print */
	bio = BIO_new_fp(fp_cb_ssl_verify, BIO_NOCLOSE);
	err_cert = X509_STORE_CTX_get_current_cert(ctx);
	err = X509_STORE_CTX_get_error(ctx);
	depth = X509_STORE_CTX_get_error_depth(ctx);

	X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);
	fprintf(fp_cb_ssl_verify, "depth=%d %s\n", depth, buf);
	if(!ok) {
		fprintf(fp_cb_ssl_verify,"verify error:num=%d:%s\n",err,
			X509_verify_cert_error_string(err));
		if((int)int_verify_depth >= depth)
			int_verify_error = err;
		else
			int_verify_error = X509_V_ERR_CERT_CHAIN_TOO_LONG;
	}
	switch (ctx->error) {
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
		X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert),
				buf, 256);
		fprintf(fp_cb_ssl_verify, "issuer= %s\n", buf);
		break;
	case X509_V_ERR_CERT_NOT_YET_VALID:
	case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
		fprintf(fp_cb_ssl_verify, "notBefore=");
		ASN1_TIME_print(bio, X509_get_notBefore(ctx->current_cert));
		fprintf(fp_cb_ssl_verify, "\n");
		break;
	case X509_V_ERR_CERT_HAS_EXPIRED:
	case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
		fprintf(fp_cb_ssl_verify, "notAfter=");
		ASN1_TIME_print(bio, X509_get_notAfter(ctx->current_cert));
		fprintf(fp_cb_ssl_verify, "\n");
		break;
	}
	fprintf(fp_cb_ssl_verify, "verify return:%d\n",ok);
	return ok;
}

void cb_ssl_verify_set_output(FILE *fp)
{
	fp_cb_ssl_verify = fp;
}

void cb_ssl_verify_set_depth(unsigned int verify_depth)
{
	int_verify_depth = verify_depth;
}

#endif /* !defined(NO_OPENSSL) */

