/* ssl/kssl.c -*- mode: C; c-file-style: "eay" -*- */
/* Written by Vern Staats <staatsvr@asc.hpc.mil> for the OpenSSL project 2000.
 */
/* ====================================================================
 * Copyright (c) 2000 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */


/*	ssl/kssl.c  --  Routines to support (& debug) Kerberos5 auth for openssl
**
**	19990701	VRS 	Started.
*/

#ifndef NO_KRB5
#include <string.h>
#include <openssl/ssl.h>

char
*kstring(char *string)
        {
        static char	*null = "[NULL]";

	return ((string == NULL)? null: string);
        }

#define	MAXKNUM	255
char
*knumber(int len, krb5_octet *contents)
        {
	static char	buf[MAXKNUM+1];
	int 		i;

	BIO_snprintf(buf, MAXKNUM, "[%d] ", len);

	for (i=0; i < len  &&  MAXKNUM > strlen(buf)+3; i++)
                {
                BIO_snprintf(&buf[strlen(buf)], 3, "%02x", contents[i]);
                }

	return (buf);
}


/*	Set kssl_err error info when reason text is a simple string
**		kssl_err = struct { int reason; char text[KSSL_ERR_MAX+1]; }
*/
void
kssl_err_set(KSSL_ERR *kssl_err, int reason, char *text)
        {
	if (kssl_err == NULL)  return;

	kssl_err->reason = reason;
	BIO_snprintf(kssl_err->text, KSSL_ERR_MAX, text);
	return;
        }


/*	Display contents of krb5_data struct, for debugging
*/
void
print_krb5_data(char *label, krb5_data *kdata)
        {
	int 	i;

	printf("%s[%d] ", label, kdata->length);
	for (i=0; i < kdata->length; i++)
                {
		if (isprint((int) kdata->data[i]))
                        printf(	"%c ",  kdata->data[i]);
		else
                        printf(	"%02x", kdata->data[i]);
		}
	printf("\n");
        }


/*	Display contents of krb5_authdata struct, for debugging
*/
void
print_krb5_authdata(char *label, krb5_authdata **adata)
        {
	if (adata == NULL)
                {
		printf("%s, authdata==0\n", label);
		return;
		}
	printf("%s [%p]\n", label, adata);
#if 0
	{
        int 	i;
	printf("%s[at%d:%d] ", label, adata->ad_type, adata->length);
	for (i=0; i < adata->length; i++)
                {
                printf((isprint(adata->contents[i]))? "%c ": "%02x",
                        adata->contents[i]);
		}
	printf("\n");
	}
#endif
}


/*	Display contents of krb5_keyblock struct, for debugging
*/
void
print_krb5_keyblock(char *label, krb5_keyblock *keyblk)
        {
	int 	i;

	if (keyblk == NULL)
                {
		printf("%s, keyblk==0\n", label);
		return;
		}
	printf("%s\n\t[et%d:%d]: ", label, keyblk->enctype, keyblk->length);
	for (i=0; i < keyblk->length; i++)
                {
		printf("%02x",keyblk->contents[i]);
		}
	printf("\n");
        }


/*	Given krb5 service (typically "kssl") and hostname in kssl_ctx,
**	Create Kerberos AP_REQ message for SSL Client.
**
**	19990628	VRS 	Started.
*/
krb5_error_code
kssl_cget_tkt(	/* UPDATE */	KSSL_CTX *kssl_ctx,
                /* OUT    */	krb5_data *krb5_app_req, KSSL_ERR *kssl_err)
{
	krb5_error_code		krb5rc = KRB5KRB_ERR_GENERIC;
	krb5_context		krb5context = NULL;
	krb5_auth_context	krb5auth_context = NULL;
	krb5_ccache 		krb5ccdef = NULL;
	krb5_creds		krb5creds, *krb5credsp = NULL;
	krb5_data 		krb5in_data;

	kssl_err_set(kssl_err, 0, "");
	memset((char *)&krb5creds, 0, sizeof(krb5creds));

	if (!kssl_ctx)
                {
		kssl_err_set(kssl_err, SSL_R_KRB5_S_INIT,
                        "No kssl_ctx defined.\n");
		goto err;
		}
	else if (!kssl_ctx->service_host)
                {
		kssl_err_set(kssl_err, SSL_R_KRB5_S_INIT,
                        "kssl_ctx service_host undefined.\n");
		goto err;
		}

	if ((krb5rc = krb5_init_context(&krb5context)) != 0)
                {
		BIO_snprintf(kssl_err->text,KSSL_ERR_MAX,
                        "krb5_init_context() fails: %d\n", krb5rc);
		kssl_err->reason = SSL_R_KRB5_C_INIT;
		goto err;
		}

	if ((krb5rc = krb5_sname_to_principal(krb5context,
                kssl_ctx->service_host,
                (kssl_ctx->service_name)? kssl_ctx->service_name: KRB5SVC,
                KRB5_NT_SRV_HST, &krb5creds.server)) != 0)
                {
		BIO_snprintf(kssl_err->text,KSSL_ERR_MAX,
                        "krb5_sname_to_principal() fails for %s/%s\n",
                        kssl_ctx->service_host,
                        (kssl_ctx->service_name)? kssl_ctx->service_name: KRB5SVC);
		kssl_err->reason = SSL_R_KRB5_C_INIT;
		goto err;
		}

	if ((krb5rc = krb5_cc_default(krb5context, &krb5ccdef)) != 0)
                {
		kssl_err_set(kssl_err, SSL_R_KRB5_C_CC_PRINC,
                        "krb5_cc_default fails.\n");
		goto err;
		}

	if ((krb5rc = krb5_cc_get_principal(krb5context, krb5ccdef,
                &krb5creds.client)) != 0)
                {
		kssl_err_set(kssl_err, SSL_R_KRB5_C_CC_PRINC,
                        "krb5_cc_get_principal() fails.\n");
		goto err;
		}

	if ((krb5rc = krb5_get_credentials(krb5context, 0, krb5ccdef,
                &krb5creds, &krb5credsp)) != 0)
                {
		kssl_err_set(kssl_err, SSL_R_KRB5_C_GET_CRED,
                        "krb5_get_credentials() fails.\n");
		goto err;
		}

	krb5in_data.data = NULL;
	krb5in_data.length = 0;

	krb5rc = KRB5KRB_ERR_GENERIC;
	/*	caller should free data of krb5_app_req  */
        if ((krb5rc = krb5_mk_req_extended(krb5context, &krb5auth_context,
                0, &krb5in_data, krb5credsp, krb5_app_req)) != 0)
                {
		kssl_err_set(kssl_err, SSL_R_KRB5_C_MK_REQ,
                        "krb5_mk_req_extended() fails.\n");
		goto err;
		}
	else if (kssl_ctx_setkey(kssl_ctx, &krb5credsp->keyblock))
                {
		kssl_err_set(kssl_err, SSL_R_KRB5_C_INIT,
                        "kssl_ctx_setkey() fails.\n");
		}
	else	krb5rc = 0;

 err:
#ifdef KSSL_DEBUG
	kssl_ctx_show(kssl_ctx);
#endif	/* KSSL_DEBUG */

	if (krb5creds.client)	krb5_free_principal(krb5context, krb5creds.client);
	if (krb5creds.server)	krb5_free_principal(krb5context, krb5creds.server);
	if (krb5auth_context)	krb5_auth_con_free(krb5context, krb5auth_context);
	if (krb5context)	krb5_free_context(krb5context);
	return (krb5rc);
}


/*	Given krb5 service name in KSSL_CTX *kssl_ctx (typically "kssl"),
**		and krb5 AP_REQ message & message length,
**	Return Kerberos session key and client principle
**		to SSL Server in KSSL_CTX *kssl_ctx.
**
**	19990702	VRS 	Started.
*/
krb5_error_code
kssl_sget_tkt(	/* UPDATE */	KSSL_CTX *kssl_ctx,
		/* IN     */	char *msg, int msglen,
		/* OUT    */	KSSL_ERR *kssl_err  )
        {
        krb5_error_code			krb5rc = KRB5KRB_ERR_GENERIC;
        static krb5_context		krb5context = NULL;
	static krb5_auth_context	krb5auth_context = NULL;
	krb5_ticket 			*krb5ticket = NULL;
	krb5_keytab 			krb5keytab = NULL;
	krb5_principal			krb5server;
	krb5_data			krb5in_data;
	krb5_flags			ap_option;

	kssl_err_set(kssl_err, 0, "");

	if (!kssl_ctx)
                {
		kssl_err_set(kssl_err, SSL_R_KRB5_S_INIT, "No kssl_ctx defined.\n");
		goto err;
		}

#ifdef KSSL_DEBUG
	printf("in kssl_sget_tkt(%s)\n", kstring(kssl_ctx->service_name));
#endif	/* KSSL_DEBUG */

	if (!krb5context  &&  (krb5rc = krb5_init_context(&krb5context)))
                {
		kssl_err_set(kssl_err, SSL_R_KRB5_S_INIT,
                        "krb5_init_context() fails.\n");
		goto err;
		}
	if (krb5auth_context  &&
		(krb5rc = krb5_auth_con_free(krb5context, krb5auth_context)))
                {
		kssl_err_set(kssl_err, SSL_R_KRB5_S_INIT,
                        "krb5_auth_con_free() fails.\n");
		goto err;
		}
	else  krb5auth_context = NULL;
	if (!krb5auth_context  &&
		(krb5rc = krb5_auth_con_init(krb5context, &krb5auth_context)))
                {
		kssl_err_set(kssl_err, SSL_R_KRB5_S_INIT,
                        "krb5_auth_con_init() fails.\n");
		goto err;
		}

	if ((krb5rc = krb5_sname_to_principal(krb5context, NULL,
                (kssl_ctx->service_name)? kssl_ctx->service_name: KRB5SVC,
                KRB5_NT_SRV_HST, &krb5server)) != 0)
                {
		kssl_err_set(kssl_err, SSL_R_KRB5_S_INIT,
                        "krb5_sname_to_principal() fails.\n");
		goto err;
		}

	if (kssl_ctx->keytab_file  &&
		((krb5rc = krb5_kt_resolve(krb5context, kssl_ctx->keytab_file,
                        &krb5keytab))))
                {
		kssl_err_set(kssl_err, SSL_R_KRB5_S_INIT, "krb5_kt_resolve() fails.\n");
		goto err;
		}
	/*	kssl_ctx->keytab_file == NULL ==> use Kerberos default /etc/krb5.keytab
	*/

	/*	Actual Kerberos5 krb5_recvauth() has initial conversation here
	**	o	check KRB5_SENDAUTH_BADAUTHVERS unless KRB5_RECVAUTH_SKIP_VERSION
	**	o	check KRB5_SENDAUTH_BADAPPLVERS
	**	o	send "0" msg if all OK
	*/

	krb5in_data.data = msg;
	krb5in_data.length = msglen;
	if ((krb5rc = krb5_rd_req(krb5context, &krb5auth_context, &krb5in_data,
                krb5server, krb5keytab, &ap_option, &krb5ticket))
                != 0)
                {
		BIO_snprintf(kssl_err->text, KSSL_ERR_MAX,
                        "krb5_rd_req() fails with %x.\n", krb5rc);
		kssl_err->reason = SSL_R_KRB5_S_RD_REQ;
		goto err;
		}

	krb5rc = KRB5_NO_TKT_SUPPLIED;
	if (!krb5ticket  ||	!krb5ticket->enc_part2  ||
                !krb5ticket->enc_part2->client  ||
                !krb5ticket->enc_part2->client->data  ||
                !krb5ticket->enc_part2->session)
                {
                kssl_err_set(kssl_err, SSL_R_KRB5_S_BAD_TICKET,
                        "bad ticket from krb5_rd_req.\n");
		}
	else if (kssl_ctx_setprinc(kssl_ctx, KSSL_CLIENT,
                &krb5ticket->enc_part2->client->realm,
                krb5ticket->enc_part2->client->data))
                {
		kssl_err_set(kssl_err, SSL_R_KRB5_S_BAD_TICKET,
                        "kssl_ctx_setprinc() fails.\n");
		}
	else if (kssl_ctx_setkey(kssl_ctx, krb5ticket->enc_part2->session))
                {
		kssl_err_set(kssl_err, SSL_R_KRB5_S_BAD_TICKET,
                        "kssl_ctx_setkey() fails.\n");
		}
	else	krb5rc = 0;

 err:
#ifdef KSSL_DEBUG
	kssl_ctx_show(kssl_ctx);
#endif	/* KSSL_DEBUG */

	if (krb5ticket) 	krb5_free_ticket(krb5context, krb5ticket);
	if (krb5server) 	krb5_free_principal(krb5context, krb5server);
	return (krb5rc);
        }


/*	Allocate & return a new kssl_ctx struct.
*/
KSSL_CTX	*
kssl_ctx_new(void)
        {
	return ((KSSL_CTX *) calloc(1, sizeof(KSSL_CTX)));
        }


/*	Frees a kssl_ctx struct and any allocated memory it holds.
**	Returns NULL.
*/
KSSL_CTX	*
kssl_ctx_free(KSSL_CTX *kssl_ctx)
        {
	if (kssl_ctx == NULL)  return kssl_ctx;

	if (kssl_ctx->key)  		memset(kssl_ctx->key, 0, kssl_ctx->length);
	if (kssl_ctx->key)  		free(kssl_ctx->key);
	if (kssl_ctx->client_princ) 	free(kssl_ctx->client_princ);
	if (kssl_ctx->service_host) 	free(kssl_ctx->service_host);
	if (kssl_ctx->service_name) 	free(kssl_ctx->service_name);
	if (kssl_ctx->keytab_file) 	free(kssl_ctx->keytab_file);

	free(kssl_ctx);
	return (KSSL_CTX *) NULL;
        }


/*	Given a (krb5_data *) entity (and optional realm),
**	set the plain (char *) client_princ or service_host member
**	of the kssl_ctx struct.
*/
krb5_error_code
kssl_ctx_setprinc(KSSL_CTX *kssl_ctx, int which,
        krb5_data *realm, krb5_data *entity)
        {
	char	**princ;
	int 	length;

	if (kssl_ctx == NULL  ||  entity == NULL)  return KSSL_CTX_ERR;

	switch (which)
                {
        case KSSL_CLIENT:	princ = &kssl_ctx->client_princ;	break;
        case KSSL_SERVER:	princ = &kssl_ctx->service_host;	break;
        default:		return KSSL_CTX_ERR;			break;
		}
	if (*princ)  free(*princ);

	length = entity->length + ((realm)? realm->length + 2: 1);
	if ((*princ = calloc(1, length)) == NULL)	return KSSL_CTX_ERR;
	else
                {
		strncpy(*princ, entity->data, entity->length);
		if (realm)
                        {
			strcat (*princ, "@");
			(void) strncat(*princ, realm->data, realm->length);
			}
		}

	return KSSL_CTX_OK;
        }


/*	Set one of the plain (char *) string members of the kssl_ctx struct.
**	Default values should be:
**		which == KSSL_SERVICE	=>	"kssl" (KRB5SVC)
**		which == KSSL_KEYTAB	=>	"/etc/krb5.keytab.kssl" (KRB5KEYTAB)
*/
krb5_error_code
kssl_ctx_setstring(KSSL_CTX *kssl_ctx, int which, char *text)
        {
	char	**string;

	if (!kssl_ctx)  return KSSL_CTX_ERR;

	switch (which)
                {
        case KSSL_SERVICE:	string = &kssl_ctx->service_name;	break;
        case KSSL_SERVER:	string = &kssl_ctx->service_host;	break;
        case KSSL_CLIENT:	string = &kssl_ctx->client_princ;	break;
        case KSSL_KEYTAB:	string = &kssl_ctx->keytab_file;	break;
        default:		return KSSL_CTX_ERR;			break;
		}
	if (*string)  free(*string);

	if (!text)
                {
		*string = '\0';
		return KSSL_CTX_OK;
		}

	if ((*string = calloc(1, strlen(text) + 1)) == NULL)  return KSSL_CTX_ERR;
	else	strcpy(*string, text);

	return KSSL_CTX_OK;
        }


/*	Copy the Kerberos session key from a (krb5_keyblock *) to a kssl_ctx
**	struct.  Clear kssl_ctx->key if Kerberos session key is NULL.
*/
krb5_error_code
kssl_ctx_setkey(KSSL_CTX *kssl_ctx, krb5_keyblock *session)
        {
	if (!kssl_ctx)  return KSSL_CTX_ERR;

	if (kssl_ctx->key)
                {
		memset(kssl_ctx->key, 0, kssl_ctx->length);
		free(kssl_ctx->key);
		}

	if (session)
                {
		kssl_ctx->enctype = session->enctype;
		kssl_ctx->length  = session->length;
		}
	else
                {
		kssl_ctx->enctype = ENCTYPE_UNKNOWN;
		kssl_ctx->length  = 0;
		return KSSL_CTX_OK;
		}

	if ((kssl_ctx->key =
                (krb5_octet FAR *) calloc(1, kssl_ctx->length)) == NULL)
                {
		kssl_ctx->length  = 0;
		return KSSL_CTX_ERR;
		}
	else	memcpy(kssl_ctx->key, session->contents, session->length);

	return KSSL_CTX_OK;
        }


/*	Display contents of kssl_ctx struct
*/
void
kssl_ctx_show(KSSL_CTX *kssl_ctx)
        {
	int 	i;

	printf("kssl_ctx: ");
	if (kssl_ctx == NULL)
                {
		printf("NULL\n");
		return;
		}
	else	printf("%p\n", kssl_ctx);

	printf("\tservice:\t%s\n",
                (kssl_ctx->service_name)? kssl_ctx->service_name: "NULL");
	printf("\tclient:\t%s\n",
                (kssl_ctx->client_princ)? kssl_ctx->client_princ: "NULL");
	printf("\tserver:\t%s\n",
                (kssl_ctx->service_host)? kssl_ctx->service_host: "NULL");
	printf("\tkeytab:\t%s\n",
                (kssl_ctx->keytab_file)? kssl_ctx->keytab_file: "NULL");
	printf("\tkey [%d:%d]:\t",
                kssl_ctx->enctype, kssl_ctx->length);

	for (i=0; i < kssl_ctx->length  &&  kssl_ctx->key; i++)
                {
		printf("%02x", kssl_ctx->key[i]);
		}
	printf("\n");
	return;
        }

#endif	/* NO_KRB5	*/

