#include "tunala.h"

#ifndef NO_OPENSSL

/* For callbacks generating output, here are their file-descriptors. */
static FILE *fp_cb_ssl_info = NULL;

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
		fprintf(stderr, "%s:%s\n", str1, str2);
	else if (where & SSL_CB_EXIT) {
		if (ret == 0)
			fprintf(stderr, "%s:failed in %s\n", str1, str2);
		else if (ret < 0)
			fprintf(stderr, "%s:error in %s\n", str1, str2);
	}
}

void cb_ssl_info_set_output(FILE *fp)
{
	fp_cb_ssl_info = fp;
}

#endif /* !defined(NO_OPENSSL) */

