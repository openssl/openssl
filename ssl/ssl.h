/* ssl/ssl.h */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#ifndef HEADER_SSL_H 
#define HEADER_SSL_H 

#ifdef  __cplusplus
extern "C" {
#endif

/* SSLeay version number for ASN.1 encoding of the session information */
/* Version 0 - initial version
 * Version 1 - added the optional peer certificate
 */
#define SSL_SESSION_ASN1_VERSION 0x0001

/* text strings for the ciphers */
#define SSL_TXT_NULL_WITH_MD5		SSL2_TXT_NULL_WITH_MD5			
#define SSL_TXT_RC4_128_WITH_MD5	SSL2_TXT_RC4_128_WITH_MD5		
#define SSL_TXT_RC4_128_EXPORT40_WITH_MD5 SSL2_TXT_RC4_128_EXPORT40_WITH_MD5	
#define SSL_TXT_RC2_128_CBC_WITH_MD5	SSL2_TXT_RC2_128_CBC_WITH_MD5		
#define SSL_TXT_RC2_128_CBC_EXPORT40_WITH_MD5 SSL2_TXT_RC2_128_CBC_EXPORT40_WITH_MD5	
#define SSL_TXT_IDEA_128_CBC_WITH_MD5	SSL2_TXT_IDEA_128_CBC_WITH_MD5		
#define SSL_TXT_DES_64_CBC_WITH_MD5	SSL2_TXT_DES_64_CBC_WITH_MD5		
#define SSL_TXT_DES_64_CBC_WITH_SHA	SSL2_TXT_DES_64_CBC_WITH_SHA		
#define SSL_TXT_DES_192_EDE3_CBC_WITH_MD5 SSL2_TXT_DES_192_EDE3_CBC_WITH_MD5	
#define SSL_TXT_DES_192_EDE3_CBC_WITH_SHA SSL2_TXT_DES_192_EDE3_CBC_WITH_SHA	

#define SSL_MAX_SSL_SESSION_ID_LENGTH		32

#define SSL_MIN_RSA_MODULUS_LENGTH_IN_BYTES	(512/8)
#define SSL_MAX_KEY_ARG_LENGTH			8
#define SSL_MAX_MASTER_KEY_LENGTH		48

/* These are used to specify which ciphers to use and not to use */
#define SSL_TXT_LOW		"LOW"
#define SSL_TXT_MEDIUM		"MEDIUM"
#define SSL_TXT_HIGH		"HIGH"
#define SSL_TXT_kFZA		"kFZA"
#define	SSL_TXT_aFZA		"aFZA"
#define SSL_TXT_eFZA		"eFZA"
#define SSL_TXT_FZA		"FZA"

#define	SSL_TXT_aNULL		"aNULL"
#define	SSL_TXT_eNULL		"eNULL"
#define	SSL_TXT_NULL		"NULL"

#define SSL_TXT_kRSA		"kRSA"
#define SSL_TXT_kDHr		"kDHr"
#define SSL_TXT_kDHd		"kDHd"
#define SSL_TXT_kEDH		"kEDH"
#define	SSL_TXT_aRSA		"aRSA"
#define	SSL_TXT_aDSS		"aDSS"
#define	SSL_TXT_aDH		"aDH"
#define	SSL_TXT_DSS		"DSS"
#define SSL_TXT_DH		"DH"
#define SSL_TXT_EDH		"EDH"
#define SSL_TXT_ADH		"ADH"
#define SSL_TXT_RSA		"RSA"
#define SSL_TXT_DES		"DES"
#define SSL_TXT_3DES		"3DES"
#define SSL_TXT_RC4		"RC4"
#define SSL_TXT_RC2		"RC2"
#define SSL_TXT_IDEA		"IDEA"
#define SSL_TXT_MD5		"MD5"
#define SSL_TXT_SHA1		"SHA1"
#define SSL_TXT_SHA		"SHA"
#define SSL_TXT_EXP		"EXP"
#define SSL_TXT_EXPORT		"EXPORT"
#define SSL_TXT_SSLV2		"SSLv2"
#define SSL_TXT_SSLV3		"SSLv3"
#define SSL_TXT_ALL		"ALL"

/* 'DEFAULT' at the start of the cipher list insert the following string
 * in addition to this being the default cipher string */
#ifndef NO_RSA
#define SSL_DEFAULT_CIPHER_LIST	"ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP"
#else
#define SSL_ALLOW_ADH
#define SSL_DEFAULT_CIPHER_LIST	"HIGH:MEDIUM:LOW:ADH+3DES:ADH+RC4:ADH+DES:+EXP"
#endif

/* Used in SSL_set_shutdown()/SSL_get_shutdown(); */
#define SSL_SENT_SHUTDOWN	1
#define SSL_RECEIVED_SHUTDOWN	2

#include "crypto.h"
#include "lhash.h"
#include "buffer.h"
#include "bio.h"
#include "x509.h"

#define SSL_FILETYPE_ASN1	X509_FILETYPE_ASN1
#define SSL_FILETYPE_PEM	X509_FILETYPE_PEM

/* This is needed to stop compilers complaining about the
 * 'struct ssl_st *' function parameters used to prototype callbacks
 * in SSL_CTX. */
typedef struct ssl_st *ssl_crock_st;

/* used to hold info on the particular ciphers used */
typedef struct ssl_cipher_st
	{
	int valid;
	char *name;			/* text name */
	unsigned long id;		/* id, 4 bytes, first is version */
	unsigned long algorithms;	/* what ciphers are used */
	unsigned long algorithm2;	/* Extra flags */
	unsigned long mask;		/* used for matching */
	} SSL_CIPHER;

/* Used to hold functions for SSLv2 or SSLv3/TLSv1 functions */
typedef struct ssl_method_st
	{
	int version;
	int (*ssl_new)();
	void (*ssl_clear)();
	void (*ssl_free)();
	int (*ssl_accept)();
	int (*ssl_connect)();
	int (*ssl_read)();
	int (*ssl_peek)();
	int (*ssl_write)();
	int (*ssl_shutdown)();
	int (*ssl_renegotiate)();
	long (*ssl_ctrl)();
	long (*ssl_ctx_ctrl)();
	SSL_CIPHER *(*get_cipher_by_char)();
	int (*put_cipher_by_char)();
	int (*ssl_pending)();
	int (*num_ciphers)();
	SSL_CIPHER *(*get_cipher)();
	struct ssl_method_st *(*get_ssl_method)();
	long (*get_timeout)();
	struct ssl3_enc_method *ssl3_enc; /* Extra SSLv3/TLS stuff */
	} SSL_METHOD;

typedef struct ssl_compression_st
	{
	char *stuff;
	} SSL_COMPRESSION;

/* Lets make this into an ASN.1 type structure as follows
 * SSL_SESSION_ID ::= SEQUENCE {
 *	version 		INTEGER,	-- structure version number
 *	SSLversion 		INTEGER,	-- SSL version number
 *	Cipher 			OCTET_STRING,	-- the 3 byte cipher ID
 *	Session_ID 		OCTET_STRING,	-- the Session ID
 *	Master_key 		OCTET_STRING,	-- the master key
 *	Key_Arg [ 0 ] IMPLICIT	OCTET_STRING,	-- the optional Key argument
 *	Time [ 1 ] EXPLICIT	INTEGER,	-- optional Start Time
 *	Timeout [ 2 ] EXPLICIT	INTEGER,	-- optional Timeout ins seconds
 *	Peer [ 3 ] EXPLICIT	X509,		-- optional Peer Certificate
 *	}
 * Look in ssl/ssl_asn1.c for more details
 * I'm using EXPLICIT tags so I can read the damn things using asn1parse :-).
 */
typedef struct ssl_session_st
	{
	int ssl_version;	/* what ssl version session info is
				 * being kept in here? */

	/* only really used in SSLv2 */
	unsigned int key_arg_length;
	unsigned char key_arg[SSL_MAX_KEY_ARG_LENGTH];
	int master_key_length;
	unsigned char master_key[SSL_MAX_MASTER_KEY_LENGTH];
	/* session_id - valid? */
	unsigned int session_id_length;
	unsigned char session_id[SSL_MAX_SSL_SESSION_ID_LENGTH];

	int not_resumable;

	/* The cert is the certificate used to establish this connection */
	struct cert_st /* CERT */ *cert;

	/* This is the cert for the other end.  On servers, it will be
	 * the same as cert->x509 */
	X509 *peer;

	int references;
	long timeout;
	long time;

	SSL_COMPRESSION *read_compression;
	SSL_COMPRESSION *write_compression;

	SSL_CIPHER *cipher;
	unsigned long cipher_id;	/* when ASN.1 loaded, this
					 * needs to be used to load
					 * the 'cipher' structure */

	STACK /* SSL_CIPHER */ *ciphers; /* shared ciphers? */

	CRYPTO_EX_DATA ex_data; /* application specific data */

	/* These are used to make removal of session-ids more
	 * efficient and to implement a maximum cache size. */
	struct ssl_session_st *prev,*next;
	} SSL_SESSION;

#define SSL_OP_MICROSOFT_SESS_ID_BUG			0x00000001L
#define SSL_OP_NETSCAPE_CHALLENGE_BUG			0x00000002L
#define SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG		0x00000008L
#define SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG		0x00000010L
#define SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER		0x00000020L
#define SSL_OP_MSIE_SSLV2_RSA_PADDING			0x00000040L
#define SSL_OP_SSLEAY_080_CLIENT_DH_BUG			0x00000080L
#define SSL_OP_TLS_D5_BUG				0x00000100L
#define	SSL_OP_TLS_BLOCK_PADDING_BUG			0x00000200L

/* If set, only use tmp_dh parameters once */
#define SSL_OP_SINGLE_DH_USE				0x00100000L
/* Set to also use the tmp_rsa key when doing RSA operations. */
#define SSL_OP_EPHEMERAL_RSA				0x00200000L

#define SSL_OP_NETSCAPE_CA_DN_BUG			0x20000000L
#define SSL_OP_NON_EXPORT_FIRST 			0x40000000L
#define SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG		0x80000000L
#define SSL_OP_ALL					0x000FFFFFL

#define SSL_CTX_set_options(ctx,op)	((ctx)->options|=(op))
#define SSL_set_options(ssl,op)		((ssl)->options|=(op))

#define SSL_OP_NO_SSLv2					0x01000000L
#define SSL_OP_NO_SSLv3					0x02000000L
#define SSL_OP_NO_TLSv1					0x04000000L

/* Normally you will only use these if your application wants to use
 * the certificate store in other places, perhaps PKCS7 */
#define SSL_CTX_get_cert_store(ctx)     ((ctx)->cert_store)
#define SSL_CTX_set_cert_store(ctx,cs) \
                (X509_STORE_free((ctx)->cert_store),(ctx)->cert_store=(cs))


#define SSL_SESSION_CACHE_MAX_SIZE_DEFAULT	(1024*20)

typedef struct ssl_ctx_st
	{
	SSL_METHOD *method;
	unsigned long options;

	STACK /* SSL_CIPHER */ *cipher_list;
	/* same as above but sorted for lookup */
	STACK /* SSL_CIPHER */ *cipher_list_by_id;

	struct x509_store_st /* X509_STORE */ *cert_store;
	struct lhash_st /* LHASH */ *sessions;	/* a set of SSL_SESSION's */
	/* Most session-ids that will be cached, default is
	 * SSL_SESSION_CACHE_SIZE_DEFAULT. 0 is unlimited. */
	unsigned long session_cache_size;
	struct ssl_session_st *session_cache_head;
	struct ssl_session_st *session_cache_tail;

	/* This can have one of 2 values, ored together,
	 * SSL_SESS_CACHE_CLIENT,
	 * SSL_SESS_CACHE_SERVER,
	 * Default is SSL_SESSION_CACHE_SERVER, which means only
	 * SSL_accept which cache SSL_SESSIONS. */
	int session_cache_mode;

	/* If timeout is not 0, it is the default timeout value set
	 * when SSL_new() is called.  This has been put in to make
	 * life easier to set things up */
	long session_timeout;

	/* If this callback is not null, it will be called each
	 * time a session id is added to the cache.  If this function
	 * returns 1, it means that the callback will do a
	 * SSL_SESSION_free() when it has finished using it.  Otherwise,
	 * on 0, it means the callback has finished with it.
	 * If remove_session_cb is not null, it will be called when
	 * a session-id is removed from the cache.  Again, a return
	 * of 0 mens that SSLeay should not SSL_SESSION_free() since
	 * the application is doing something with it. */
#ifndef NOPROTO
	int (*new_session_cb)(struct ssl_st *ssl,SSL_SESSION *sess);
	void (*remove_session_cb)(struct ssl_ctx_st *ctx,SSL_SESSION *sess);
	SSL_SESSION *(*get_session_cb)(struct ssl_st *ssl,
		unsigned char *data,int len,int *copy);
#else
	int (*new_session_cb)();
	void (*remove_session_cb)();
	SSL_SESSION *(*get_session_cb)();
#endif

	int sess_connect;	/* SSL new connection - started */
	int sess_connect_renegotiate;/* SSL renegotiatene  - requested */
	int sess_connect_good;	/* SSL new connection/renegotiate - finished */
	int sess_accept;	/* SSL new accept - started */
	int sess_accept_renegotiate;/* SSL renegotiatene - requested */
	int sess_accept_good;	/* SSL accept/renegotiate - finished */
	int sess_miss;		/* session lookup misses  */
	int sess_timeout;	/* session reuse attempt on timeouted session */
	int sess_cache_full;	/* session removed due to full cache */
	int sess_hit;		/* session reuse actually done */
	int sess_cb_hit;	/* session-id that was not in the cache was
				 * passed back via the callback.  This
				 * indicates that the application is supplying
				 * session-id's from other processes -
				 * spooky :-) */

	int references;

	void (*info_callback)();

	/* if defined, these override the X509_verify_cert() calls */
	int (*app_verify_callback)();
	char *app_verify_arg;

	/* default values to use in SSL structures */
	struct cert_st /* CERT */ *default_cert;
	int default_read_ahead;
	int default_verify_mode;
	int (*default_verify_callback)();

	/* Default password callback. */
	int (*default_passwd_callback)();

	/* get client cert callback */
	int (*client_cert_cb)(/* SSL *ssl, X509 **x509, EVP_PKEY **pkey */);

	/* what we put in client requests */
	STACK *client_CA;

	int quiet_shutdown;

	CRYPTO_EX_DATA ex_data;

	EVP_MD *rsa_md5;/* For SSLv2 - name is 'ssl2-md5' */
	EVP_MD *md5;	/* For SSLv3/TLSv1 'ssl3-md5' */
	EVP_MD *sha1;   /* For SSLv3/TLSv1 'ssl3->sha1' */
	} SSL_CTX;

#define SSL_SESS_CACHE_OFF			0x0000
#define SSL_SESS_CACHE_CLIENT			0x0001
#define SSL_SESS_CACHE_SERVER			0x0002
#define SSL_SESS_CACHE_BOTH	(SSL_SESS_CACHE_CLIENT|SSL_SESS_CACHE_SERVER)
#define SSL_SESS_CACHE_NO_AUTO_CLEAR		0x0080
/* This one, when set, makes the server session-id lookup not look
 * in the cache.  If there is an application get_session callback
 * defined, this will still get called. */
#define SSL_SESS_CACHE_NO_INTERNAL_LOOKUP	0x0100

#define SSL_CTX_sessions(ctx)		((ctx)->sessions)
/* You will need to include lhash.h to access the following #define */
#define SSL_CTX_sess_number(ctx)	((ctx)->sessions->num_items)
#define SSL_CTX_sess_connect(ctx)	((ctx)->sess_connect)
#define SSL_CTX_sess_connect_good(ctx)	((ctx)->sess_connect_good)
#define SSL_CTX_sess_accept(ctx)	((ctx)->sess_accept)
#define SSL_CTX_sess_accept_renegotiate(ctx)	((ctx)->sess_accept_renegotiate)
#define SSL_CTX_sess_connect_renegotiate(ctx)	((ctx)->sess_connect_renegotiate)
#define SSL_CTX_sess_accept_good(ctx)	((ctx)->sess_accept_good)
#define SSL_CTX_sess_hits(ctx)		((ctx)->sess_hit)
#define SSL_CTX_sess_cb_hits(ctx)	((ctx)->sess_cb_hit)
#define SSL_CTX_sess_misses(ctx)	((ctx)->sess_miss)
#define SSL_CTX_sess_timeouts(ctx)	((ctx)->sess_timeout)
#define SSL_CTX_sess_cache_full(ctx)	((ctx)->sess_cache_full)

#define SSL_CTX_sess_set_cache_size(ctx,t) ((ctx)->session_cache_size=(t))
#define SSL_CTX_sess_get_cache_size(ctx)   ((ctx)->session_cache_size)

#define SSL_CTX_sess_set_new_cb(ctx,cb)	((ctx)->new_session_cb=(cb))
#define SSL_CTX_sess_get_new_cb(ctx)	((ctx)->new_session_cb)
#define SSL_CTX_sess_set_remove_cb(ctx,cb)	((ctx)->remove_session_cb=(cb))
#define SSL_CTX_sess_get_remove_cb(ctx)	((ctx)->remove_session_cb)
#define SSL_CTX_sess_set_get_cb(ctx,cb)	((ctx)->get_session_cb=(cb))
#define SSL_CTX_sess_get_get_cb(ctx)	((ctx)->get_session_cb)
#define SSL_CTX_set_session_cache_mode(ctx,m)	((ctx)->session_cache_mode=(m))
#define SSL_CTX_get_session_cache_mode(ctx)	((ctx)->session_cache_mode)
#define SSL_CTX_set_timeout(ctx,t)	((ctx)->session_timeout=(t))
#define SSL_CTX_get_timeout(ctx)	((ctx)->session_timeout)

#define SSL_CTX_set_info_callback(ctx,cb)	((ctx)->info_callback=(cb))
#define SSL_CTX_get_info_callback(ctx)		((ctx)->info_callback)
#define SSL_CTX_set_default_read_ahead(ctx,m) (((ctx)->default_read_ahead)=(m))

#define SSL_CTX_set_client_cert_cb(ctx,cb)	((ctx)->client_cert_cb=(cb))
#define SSL_CTX_get_client_cert_cb(ctx)		((ctx)->client_cert_cb)

#define SSL_NOTHING	1
#define SSL_WRITING	2
#define SSL_READING	3
#define SSL_X509_LOOKUP	4

/* These will only be used when doing non-blocking IO */
#define SSL_want(s)		((s)->rwstate)
#define SSL_want_nothing(s)	((s)->rwstate == SSL_NOTHING)
#define SSL_want_read(s)	((s)->rwstate == SSL_READING)
#define SSL_want_write(s)	((s)->rwstate == SSL_WRITING)
#define SSL_want_x509_lookup(s)	((s)->rwstate == SSL_X509_LOOKUP)

typedef struct ssl_st
	{
	/* procol version
	 * 2 for SSLv2
	 * 3 for SSLv3
	 * -3 for SSLv3 but accept SSLv2 */
	int version;
	int type; /* SSL_ST_CONNECT or SSL_ST_ACCEPT */

	SSL_METHOD *method; /* SSLv3 */

	/* There are 2 BIO's even though they are normally both the
	 * same.  This is so data can be read and written to different
	 * handlers */

#ifdef HEADER_BIO_H
	BIO *rbio; /* used by SSL_read */
	BIO *wbio; /* used by SSL_write */
	BIO *bbio; /* used during session-id reuse to concatinate
		    * messages */
#else
	char *rbio; /* used by SSL_read */
	char *wbio; /* used by SSL_write */
	char *bbio;
#endif
	/* This holds a variable that indicates what we were doing
	 * when a 0 or -1 is returned.  This is needed for
	 * non-blocking IO so we know what request needs re-doing when
	 * in SSL_accept or SSL_connect */
	int rwstate;

	/* true when we are actually in SSL_accept() or SSL_connect() */
	int in_handshake;
	int (*handshake_func)();

/*	int server;*/	/* are we the server side? */

	int new_session;/* 1 if we are to use a new session */
	int quiet_shutdown;/* don't send shutdown packets */
	int shutdown;	/* we have shut things down, 0x01 sent, 0x02
			 * for received */
	int state;	/* where we are */
	int rstate;	/* where we are when reading */

	BUF_MEM *init_buf;	/* buffer used during init */
	int init_num;		/* amount read/written */
	int init_off;		/* amount read/written */

	/* used internally to point at a raw packet */
	unsigned char *packet;
	unsigned int packet_length;

	struct ssl2_ctx_st *s2;	/* SSLv2 variables */
	struct ssl3_ctx_st *s3;	/* SSLv3 variables */

	int read_ahead;		/* Read as many input bytes as possible */
	int hit;		/* reusing a previous session */

	/* crypto */
	STACK /* SSL_CIPHER */ *cipher_list;
	STACK /* SSL_CIPHER */ *cipher_list_by_id;

	/* These are the ones being used, the ones is SSL_SESSION are
	 * the ones to be 'copied' into these ones */

	EVP_CIPHER_CTX *enc_read_ctx;		/* cryptographic state */
	EVP_MD *read_hash;			/* used for mac generation */
	SSL_COMPRESSION *read_compression;	/* compression */

	EVP_CIPHER_CTX *enc_write_ctx;		/* cryptographic state */
	EVP_MD *write_hash;			/* used for mac generation */
	SSL_COMPRESSION *write_compression;	/* compression */

	/* session info */

	/* client cert? */
	/* This is used to hold the server certificate used */
	struct cert_st /* CERT */ *cert;

	/* This can also be in the session once a session is established */
	SSL_SESSION *session;

	/* Used in SSL2 and SSL3 */
	int verify_mode;	/* 0 don't care about verify failure.
				 * 1 fail if verify fails */
	int (*verify_callback)(); /* fail if callback returns 0 */
	void (*info_callback)(); /* optional informational callback */

	int error;		/* error bytes to be written */
	int error_code;		/* actual code */

	SSL_CTX *ctx;
	/* set this flag to 1 and a sleep(1) is put into all SSL_read()
	 * and SSL_write() calls, good for nbio debuging :-) */
	int debug;	

	/* extra application data */
	long verify_result;
	CRYPTO_EX_DATA ex_data;

	/* for server side, keep the list of CA_dn we can use */
	STACK /* X509_NAME */ *client_CA;

	int references;
	unsigned long options;
	int first_packet;
	} SSL;

#include "ssl2.h"
#include "ssl3.h"
#include "tls1.h" /* This is mostly sslv3 with a few tweaks */
#include "ssl23.h"

/* compatablity */
#define SSL_set_app_data(s,arg)		(SSL_set_ex_data(s,0,(char *)arg))
#define SSL_get_app_data(s)		(SSL_get_ex_data(s,0))
#define SSL_SESSION_set_app_data(s,a)	(SSL_SESSION_set_ex_data(s,0,(char *)a))
#define SSL_SESSION_get_app_data(s)	(SSL_SESSION_get_ex_data(s,0))
#define SSL_CTX_get_app_data(ctx)	(SSL_CTX_get_ex_data(ctx,0))
#define SSL_CTX_set_app_data(ctx,arg)	(SSL_CTX_set_ex_data(ctx,0,(char *)arg))

/* The following are the possible values for ssl->state are are
 * used to indicate where we are upto in the SSL connection establishment.
 * The macros that follow are about the only things you should need to use
 * and even then, only when using non-blocking IO.
 * It can also be useful to work out where you were when the connection
 * failed */

#define SSL_ST_CONNECT			0x1000
#define SSL_ST_ACCEPT			0x2000
#define SSL_ST_MASK			0x0FFF
#define SSL_ST_INIT			(SSL_ST_CONNECT|SSL_ST_ACCEPT)
#define SSL_ST_BEFORE			0x4000
#define SSL_ST_OK			0x03
#define SSL_ST_RENEGOTIATE		(0x04|SSL_ST_INIT)

#define SSL_CB_LOOP			0x01
#define SSL_CB_EXIT			0x02
#define SSL_CB_READ			0x04
#define SSL_CB_WRITE			0x08
#define SSL_CB_ALERT			0x4000 /* used in callback */
#define SSL_CB_READ_ALERT		(SSL_CB_ALERT|SSL_CB_READ)
#define SSL_CB_WRITE_ALERT		(SSL_CB_ALERT|SSL_CB_WRITE)
#define SSL_CB_ACCEPT_LOOP		(SSL_ST_ACCEPT|SSL_CB_LOOP)
#define SSL_CB_ACCEPT_EXIT		(SSL_ST_ACCEPT|SSL_CB_EXIT)
#define SSL_CB_CONNECT_LOOP		(SSL_ST_CONNECT|SSL_CB_LOOP)
#define SSL_CB_CONNECT_EXIT		(SSL_ST_CONNECT|SSL_CB_EXIT)
#define SSL_CB_HANDSHAKE_START		0x10
#define SSL_CB_HANDSHAKE_DONE		0x20

/* Is the SSL_connection established? */
#define SSL_get_state(a)		SSL_state(a)
#define SSL_is_init_finished(a)		(SSL_state(a) == SSL_ST_OK)
#define SSL_in_init(a)			(SSL_state(a)&SSL_ST_INIT)
#define SSL_in_before(a)		(SSL_state(a)&SSL_ST_BEFORE)
#define SSL_in_connect_init(a)		(SSL_state(a)&SSL_ST_CONNECT)
#define SSL_in_accept_init(a)		(SSL_state(a)&SSL_ST_ACCEPT)

/* The following 2 states are kept in ssl->rstate when reads fail,
 * you should not need these */
#define SSL_ST_READ_HEADER			0xF0
#define SSL_ST_READ_BODY			0xF1
#define SSL_ST_READ_DONE			0xF2

/* use either SSL_VERIFY_NONE or SSL_VERIFY_PEER, the last 2 options
 * are 'ored' with SSL_VERIFY_PEER if they are desired */
#define SSL_VERIFY_NONE			0x00
#define SSL_VERIFY_PEER			0x01
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT	0x02
#define SSL_VERIFY_CLIENT_ONCE		0x04

/* this is for backward compatablility */
#if 0 /* NEW_SSLEAY */
#define SSL_CTX_set_default_verify(a,b,c) SSL_CTX_set_verify(a,b,c)
#define SSL_set_pref_cipher(c,n)	SSL_set_cipher_list(c,n)
#define SSL_add_session(a,b)            SSL_CTX_add_session((a),(b))
#define SSL_remove_session(a,b)		SSL_CTX_remove_session((a),(b))
#define SSL_flush_sessions(a,b)		SSL_CTX_flush_sessions((a),(b))
#endif
/* More backward compatablity */
#define SSL_get_cipher(s) \
		SSL_CIPHER_get_name(SSL_get_current_cipher(s))
#define SSL_get_cipher_bits(s,np) \
		SSL_CIPHER_get_bits(SSL_get_current_cipher(s),np)
#define SSL_get_cipher_version(s) \
		SSL_CIPHER_get_version(SSL_get_current_cipher(s))
#define SSL_get_cipher_name(s) \
		SSL_CIPHER_get_name(SSL_get_current_cipher(s))
#define SSL_get_time(a)		SSL_SESSION_get_time(a)
#define SSL_set_time(a,b)	SSL_SESSION_set_time((a),(b))
#define SSL_get_timeout(a)	SSL_SESSION_get_timeout(a)
#define SSL_set_timeout(a,b)	SSL_SESSION_set_timeout((a),(b))

/* VMS linker has a 31 char name limit */
#define SSL_CTX_set_cert_verify_callback(a,b,c) \
		SSL_CTX_set_cert_verify_cb((a),(b),(c))

#if 1 /*SSLEAY_MACROS*/
#define d2i_SSL_SESSION_bio(bp,s_id) (SSL_SESSION *)ASN1_d2i_bio( \
	(char *(*)())SSL_SESSION_new,(char *(*)())d2i_SSL_SESSION, \
	(bp),(unsigned char **)(s_id))
#define i2d_SSL_SESSION_bio(bp,s_id) ASN1_i2d_bio(i2d_SSL_SESSION, \
	bp,(unsigned char *)s_id)
#define PEM_read_SSL_SESSION(fp,x,cb) (SSL_SESSION *)PEM_ASN1_read( \
	(char *(*)())d2i_SSL_SESSION,PEM_STRING_SSL_SESSION,fp,(char **)x,cb)
#define PEM_read_bio_SSL_SESSION(bp,x,cb) (SSL_SESSION *)PEM_ASN1_read_bio( \
	(char *(*)())d2i_SSL_SESSION,PEM_STRING_SSL_SESSION,bp,(char **)x,cb)
#define PEM_write_SSL_SESSION(fp,x) \
	PEM_ASN1_write((int (*)())i2d_SSL_SESSION, \
		PEM_STRING_SSL_SESSION,fp, (char *)x, NULL,NULL,0,NULL)
#define PEM_write_bio_SSL_SESSION(bp,x) \
	PEM_ASN1_write_bio((int (*)())i2d_SSL_SESSION, \
		PEM_STRING_SSL_SESSION,bp, (char *)x, NULL,NULL,0,NULL)
#endif

/* These alert types are for SSLv3 and TLSv1 */
#define SSL_AD_CLOSE_NOTIFY		SSL3_AD_CLOSE_NOTIFY
#define SSL_AD_UNEXPECTED_MESSAGE	SSL3_AD_UNEXPECTED_MESSAGE /* fatal */
#define SSL_AD_BAD_RECORD_MAC		SSL3_AD_BAD_RECORD_MAC     /* fatal */
#define SSL_AD_DECRYPTION_FAILED	TLS1_AD_DECRYPTION_FAILED
#define SSL_AD_RECORD_OVERFLOW		TLS1_AD_RECORD_OVERFLOW
#define SSL_AD_DECOMPRESSION_FAILURE	SSL3_AD_DECOMPRESSION_FAILURE/* fatal */
#define SSL_AD_HANDSHAKE_FAILURE	SSL3_AD_HANDSHAKE_FAILURE/* fatal */
#define SSL_AD_NO_CERTIFICATE		SSL3_AD_NO_CERTIFICATE /* Not for TLS */
#define SSL_AD_BAD_CERTIFICATE		SSL3_AD_BAD_CERTIFICATE
#define SSL_AD_UNSUPPORTED_CERTIFICATE	SSL3_AD_UNSUPPORTED_CERTIFICATE
#define SSL_AD_CERTIFICATE_REVOKED	SSL3_AD_CERTIFICATE_REVOKED
#define SSL_AD_CERTIFICATE_EXPIRED	SSL3_AD_CERTIFICATE_EXPIRED
#define SSL_AD_CERTIFICATE_UNKNOWN	SSL3_AD_CERTIFICATE_UNKNOWN
#define SSL_AD_ILLEGAL_PARAMETER	SSL3_AD_ILLEGAL_PARAMETER   /* fatal */
#define SSL_AD_UNKNOWN_CA		TLS1_AD_UNKNOWN_CA	/* fatal */
#define SSL_AD_ACCESS_DENIED		TLS1_AD_ACCESS_DENIED	/* fatal */
#define SSL_AD_DECODE_ERROR		TLS1_AD_DECODE_ERROR	/* fatal */
#define SSL_AD_DECRYPT_ERROR		TLS1_AD_DECRYPT_ERROR
#define SSL_AD_EXPORT_RESTRICION	TLS1_AD_EXPORT_RESTRICION/* fatal */
#define SSL_AD_PROTOCOL_VERSION		TLS1_AD_PROTOCOL_VERSION /* fatal */
#define SSL_AD_INSUFFICIENT_SECURITY	TLS1_AD_INSUFFICIENT_SECURITY/* fatal */
#define SSL_AD_INTERNAL_ERROR		TLS1_AD_INTERNAL_ERROR	/* fatal */
#define SSL_AD_USER_CANCLED		TLS1_AD_USER_CANCLED
#define SSL_AD_NO_RENEGOTIATION		TLS1_AD_NO_RENEGOTIATION

#define SSL_ERROR_NONE			0
#define SSL_ERROR_SSL			1
#define SSL_ERROR_WANT_READ		2
#define SSL_ERROR_WANT_WRITE		3
#define SSL_ERROR_WANT_X509_LOOKUP	4
#define SSL_ERROR_SYSCALL		5 /* look at errno */
#define SSL_ERROR_ZERO_RETURN		6
#define SSL_ERROR_WANT_CONNECT		7

#define SSL_CTRL_NEED_TMP_RSA			1
#define SSL_CTRL_SET_TMP_RSA			2
#define SSL_CTRL_SET_TMP_DH			3
#define SSL_CTRL_SET_TMP_RSA_CB			4
#define SSL_CTRL_SET_TMP_DH_CB			5
/* Add these ones */
#define SSL_CTRL_GET_SESSION_REUSED		6
#define SSL_CTRL_GET_CLIENT_CERT_REQUEST	7
#define SSL_CTRL_GET_NUM_RENEGOTIATIONS		8
#define SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS	9
#define SSL_CTRL_GET_TOTAL_RENEGOTIATIONS	10

#define SSL_session_reused(ssl) \
	SSL_ctrl((ssl),SSL_CTRL_GET_SESSION_REUSED,0,NULL)
#define SSL_num_renegotiations(ssl) \
	SSL_ctrl((ssl),SSL_CTRL_GET_NUM_RENEGOTIATIONS,0,NULL)
#define SSL_clear_num_renegotiations(ssl) \
	SSL_ctrl((ssl),SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS,0,NULL)
#define SSL_total_renegotiations(ssl) \
	SSL_ctrl((ssl),SSL_CTRL_GET_TOTAL_RENEGOTIATIONS,0,NULL)

#define SSL_CTX_need_tmp_RSA(ctx) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_NEED_TMP_RSA,0,NULL)
#define SSL_CTX_set_tmp_rsa(ctx,rsa) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_RSA,0,(char *)rsa)
#define SSL_CTX_set_tmp_dh(ctx,dh) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_DH,0,(char *)dh)

/* For the next 2, the callbacks are 
 * RSA *tmp_rsa_cb(int export)
 * DH *tmp_dh_cb(int export)
 */
#define SSL_CTX_set_tmp_rsa_callback(ctx,cb) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_RSA_CB,0,(char *)cb)
#define SSL_CTX_set_tmp_dh_callback(ctx,dh) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_DH_CB,0,(char *)dh)

#ifndef NOPROTO

#ifdef HEADER_BIO_H
BIO_METHOD *BIO_f_ssl(void);
BIO *BIO_new_ssl(SSL_CTX *ctx,int client);
BIO *BIO_new_ssl_connect(SSL_CTX *ctx);
BIO *BIO_new_buffer_ssl_connect(SSL_CTX *ctx);
int BIO_ssl_copy_session_id(BIO *to,BIO *from);
void BIO_ssl_shutdown(BIO *ssl_bio);

#endif

int	SSL_CTX_set_cipher_list(SSL_CTX *,char *str);
SSL_CTX *SSL_CTX_new(SSL_METHOD *meth);
void	SSL_CTX_free(SSL_CTX *);
void	SSL_clear(SSL *s);
void	SSL_CTX_flush_sessions(SSL_CTX *ctx,long tm);

SSL_CIPHER *SSL_get_current_cipher(SSL *s);
int	SSL_CIPHER_get_bits(SSL_CIPHER *c,int *alg_bits);
char *	SSL_CIPHER_get_version(SSL_CIPHER *c);
char *	SSL_CIPHER_get_name(SSL_CIPHER *c);

int	SSL_get_fd(SSL *s);
char  * SSL_get_cipher_list(SSL *s,int n);
char *	SSL_get_shared_ciphers(SSL *s, char *buf, int len);
int	SSL_get_read_ahead(SSL * s);
int	SSL_pending(SSL *s);
#ifndef NO_SOCK
int	SSL_set_fd(SSL *s, int fd);
int	SSL_set_rfd(SSL *s, int fd);
int	SSL_set_wfd(SSL *s, int fd);
#endif
#ifdef HEADER_BIO_H
void	SSL_set_bio(SSL *s, BIO *rbio,BIO *wbio);
BIO *	SSL_get_rbio(SSL *s);
BIO *	SSL_get_wbio(SSL *s);
#endif
int	SSL_set_cipher_list(SSL *s, char *str);
void	SSL_set_read_ahead(SSL *s, int yes);
int	SSL_get_verify_mode(SSL *s);
int	(*SSL_get_verify_callback(SSL *s))();
void	SSL_set_verify(SSL *s, int mode, int (*callback) ());
int	SSL_use_RSAPrivateKey(SSL *ssl, RSA *rsa);
int	SSL_use_RSAPrivateKey_ASN1(SSL *ssl, unsigned char *d, long len);
int	SSL_use_PrivateKey(SSL *ssl, EVP_PKEY *pkey);
int	SSL_use_PrivateKey_ASN1(int pk,SSL *ssl, unsigned char *d, long len);
int	SSL_use_certificate(SSL *ssl, X509 *x);
int	SSL_use_certificate_ASN1(SSL *ssl, int len, unsigned char *d);

#ifndef NO_STDIO
int	SSL_use_RSAPrivateKey_file(SSL *ssl, char *file, int type);
int	SSL_use_PrivateKey_file(SSL *ssl, char *file, int type);
int	SSL_use_certificate_file(SSL *ssl, char *file, int type);
int	SSL_CTX_use_RSAPrivateKey_file(SSL_CTX *ctx, char *file, int type);
int	SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, char *file, int type);
int	SSL_CTX_use_certificate_file(SSL_CTX *ctx, char *file, int type);
STACK * SSL_load_client_CA_file(char *file);
#endif

void	ERR_load_SSL_strings(void );
void	SSL_load_error_strings(void );
char * 	SSL_state_string(SSL *s);
char * 	SSL_rstate_string(SSL *s);
char * 	SSL_state_string_long(SSL *s);
char * 	SSL_rstate_string_long(SSL *s);
long	SSL_SESSION_get_time(SSL_SESSION *s);
long	SSL_SESSION_set_time(SSL_SESSION *s, long t);
long	SSL_SESSION_get_timeout(SSL_SESSION *s);
long	SSL_SESSION_set_timeout(SSL_SESSION *s, long t);
void	SSL_copy_session_id(SSL *to,SSL *from);

SSL_SESSION *SSL_SESSION_new(void);
unsigned long SSL_SESSION_hash(SSL_SESSION *a);
int	SSL_SESSION_cmp(SSL_SESSION *a,SSL_SESSION *b);
#ifndef NO_FP_API
int	SSL_SESSION_print_fp(FILE *fp,SSL_SESSION *ses);
#endif
#ifdef HEADER_BIO_H
int	SSL_SESSION_print(BIO *fp,SSL_SESSION *ses);
#endif
void	SSL_SESSION_free(SSL_SESSION *ses);
int	i2d_SSL_SESSION(SSL_SESSION *in,unsigned char **pp);
int	SSL_set_session(SSL *to, SSL_SESSION *session);
int	SSL_CTX_add_session(SSL_CTX *s, SSL_SESSION *c);
int	SSL_CTX_remove_session(SSL_CTX *,SSL_SESSION *c);
SSL_SESSION *d2i_SSL_SESSION(SSL_SESSION **a,unsigned char **pp,long length);

#ifdef HEADER_X509_H
X509 *	SSL_get_peer_certificate(SSL *s);
#endif

STACK *	SSL_get_peer_cert_chain(SSL *s);

int SSL_CTX_get_verify_mode(SSL_CTX *ctx);
int (*SSL_CTX_get_verify_callback(SSL_CTX *ctx))();
void SSL_CTX_set_verify(SSL_CTX *ctx,int mode,int (*callback)());
void SSL_CTX_set_cert_verify_cb(SSL_CTX *ctx, int (*cb)(),char *arg);
int SSL_CTX_use_RSAPrivateKey(SSL_CTX *ctx, RSA *rsa);
int SSL_CTX_use_RSAPrivateKey_ASN1(SSL_CTX *ctx, unsigned char *d, long len);
int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey);
int SSL_CTX_use_PrivateKey_ASN1(int pk,SSL_CTX *ctx,
	unsigned char *d, long len);
int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x);
int SSL_CTX_use_certificate_ASN1(SSL_CTX *ctx, int len, unsigned char *d);

void SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx,int (*cb)());

int SSL_CTX_check_private_key(SSL_CTX *ctx);
int SSL_check_private_key(SSL *ctx);

SSL *	SSL_new(SSL_CTX *ctx);
void    SSL_clear(SSL *s);
void	SSL_free(SSL *ssl);
int 	SSL_accept(SSL *ssl);
int 	SSL_connect(SSL *ssl);
int 	SSL_read(SSL *ssl,char *buf,int num);
int 	SSL_peek(SSL *ssl,char *buf,int num);
int 	SSL_write(SSL *ssl,char *buf,int num);
long	SSL_ctrl(SSL *ssl,int cmd, long larg, char *parg);
long	SSL_CTX_ctrl(SSL_CTX *ctx,int cmd, long larg, char *parg);

int	SSL_get_error(SSL *s,int ret_code);
char *	SSL_get_version(SSL *s);

/* This sets the 'default' SSL version that SSL_new() will create */
int SSL_CTX_set_ssl_version(SSL_CTX *ctx,SSL_METHOD *meth);

SSL_METHOD *SSLv2_method(void);		/* SSLv2 */
SSL_METHOD *SSLv2_server_method(void);	/* SSLv2 */
SSL_METHOD *SSLv2_client_method(void);	/* SSLv2 */

SSL_METHOD *SSLv3_method(void);		/* SSLv3 */
SSL_METHOD *SSLv3_server_method(void);	/* SSLv3 */
SSL_METHOD *SSLv3_client_method(void);	/* SSLv3 */

SSL_METHOD *SSLv23_method(void);	/* SSLv3 but can rollback to v2 */
SSL_METHOD *SSLv23_server_method(void);	/* SSLv3 but can rollback to v2 */
SSL_METHOD *SSLv23_client_method(void);	/* SSLv3 but can rollback to v2 */

SSL_METHOD *TLSv1_method(void);		/* TLSv1.0 */
SSL_METHOD *TLSv1_server_method(void);	/* TLSv1.0 */
SSL_METHOD *TLSv1_client_method(void);	/* TLSv1.0 */

STACK *SSL_get_ciphers(SSL *s);

int SSL_do_handshake(SSL *s);
int SSL_renegotiate(SSL *s);
int SSL_shutdown(SSL *s);

SSL_METHOD *SSL_get_ssl_method(SSL *s);
int SSL_set_ssl_method(SSL *s,SSL_METHOD *method);
char *SSL_alert_type_string_long(int value);
char *SSL_alert_type_string(int value);
char *SSL_alert_desc_string_long(int value);
char *SSL_alert_desc_string(int value);

void SSL_set_client_CA_list(SSL *s, STACK *list);
void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, STACK *list);
STACK *SSL_get_client_CA_list(SSL *s);
STACK *SSL_CTX_get_client_CA_list(SSL_CTX *s);
int SSL_add_client_CA(SSL *ssl,X509 *x);
int SSL_CTX_add_client_CA(SSL_CTX *ctx,X509 *x);

void SSL_set_connect_state(SSL *s);
void SSL_set_accept_state(SSL *s);

long SSL_get_default_timeout(SSL *s);

void SSLeay_add_ssl_algorithms(void );

char *SSL_CIPHER_description(SSL_CIPHER *,char *buf,int size);
STACK *SSL_dup_CA_list(STACK *sk);

SSL *SSL_dup(SSL *ssl);

X509 *SSL_get_certificate(SSL *ssl);
/* EVP_PKEY */ struct evp_pkey_st *SSL_get_privatekey(SSL *ssl);

void SSL_CTX_set_quiet_shutdown(SSL_CTX *ctx,int mode);
int SSL_CTX_get_quiet_shutdown(SSL_CTX *ctx);
void SSL_set_quiet_shutdown(SSL *ssl,int mode);
int SSL_get_quiet_shutdown(SSL *ssl);
void SSL_set_shutdown(SSL *ssl,int mode);
int SSL_get_shutdown(SSL *ssl);
int SSL_version(SSL *ssl);
int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx);
int SSL_CTX_load_verify_locations(SSL_CTX *ctx,char *CAfile,char *CApath);
SSL_SESSION *SSL_get_session(SSL *ssl);
SSL_CTX *SSL_get_SSL_CTX(SSL *ssl);
void SSL_set_info_callback(SSL *ssl,void (*cb)());
void (*SSL_get_info_callback(SSL *ssl))();
int SSL_state(SSL *ssl);

void SSL_set_verify_result(SSL *ssl,long v);
long SSL_get_verify_result(SSL *ssl);

int SSL_set_ex_data(SSL *ssl,int idx,char *data);
char *SSL_get_ex_data(SSL *ssl,int idx);
int SSL_get_ex_new_index(long argl, char *argp, int (*new_func)(),
	int (*dup_func)(), void (*free_func)());

int SSL_SESSION_set_ex_data(SSL_SESSION *ss,int idx,char *data);
char *SSL_SESSION_get_ex_data(SSL_SESSION *ss,int idx);
int SSL_SESSION_get_ex_new_index(long argl, char *argp, int (*new_func)(),
	int (*dup_func)(), void (*free_func)());

int SSL_CTX_set_ex_data(SSL_CTX *ssl,int idx,char *data);
char *SSL_CTX_get_ex_data(SSL_CTX *ssl,int idx);
int SSL_CTX_get_ex_new_index(long argl, char *argp, int (*new_func)(),
	int (*dup_func)(), void (*free_func)());

#else

BIO_METHOD *BIO_f_ssl();
BIO *BIO_new_ssl();
BIO *BIO_new_ssl_connect();
BIO *BIO_new_buffer_ssl_connect();
int BIO_ssl_copy_session_id();
void BIO_ssl_shutdown();

int	SSL_CTX_set_cipher_list();
SSL_CTX *SSL_CTX_new();
void	SSL_CTX_free();
void	SSL_clear();
void	SSL_CTX_flush_sessions();

SSL_CIPHER *SSL_get_current_cipher();
int	SSL_CIPHER_get_bits();
char *	SSL_CIPHER_get_version();
char *	SSL_CIPHER_get_name();

int	SSL_get_fd();
char  * SSL_get_cipher_list();
char *	SSL_get_shared_ciphers();
int	SSL_get_read_ahead();
int	SSL_pending();
#ifndef NO_SOCK
int	SSL_set_fd();
int	SSL_set_rfd();
int	SSL_set_wfd();
#endif
#ifdef HEADER_BIO_H
void	SSL_set_bio();
BIO *	SSL_get_rbio();
BIO *	SSL_get_wbio();
#endif
int	SSL_set_cipher_list();
void	SSL_set_read_ahead();
int	SSL_get_verify_mode();

void	SSL_set_verify();
int	SSL_use_RSAPrivateKey();
int	SSL_use_RSAPrivateKey_ASN1();
int	SSL_use_PrivateKey();
int	SSL_use_PrivateKey_ASN1();
int	SSL_use_certificate();
int	SSL_use_certificate_ASN1();

#ifndef NO_STDIO
int	SSL_use_RSAPrivateKey_file();
int	SSL_use_PrivateKey_file();
int	SSL_use_certificate_file();
int	SSL_CTX_use_RSAPrivateKey_file();
int	SSL_CTX_use_PrivateKey_file();
int	SSL_CTX_use_certificate_file();
STACK * SSL_load_client_CA_file();
#endif

void	ERR_load_SSL_strings();
void	SSL_load_error_strings();
char * 	SSL_state_string();
char * 	SSL_rstate_string();
char * 	SSL_state_string_long();
char * 	SSL_rstate_string_long();
long	SSL_SESSION_get_time();
long	SSL_SESSION_set_time();
long	SSL_SESSION_get_timeout();
long	SSL_SESSION_set_timeout();
void	SSL_copy_session_id();

SSL_SESSION *SSL_SESSION_new();
unsigned long SSL_SESSION_hash();
int	SSL_SESSION_cmp();
#ifndef NO_FP_API
int	SSL_SESSION_print_fp();
#endif
#ifdef HEADER_BIO_H
int	SSL_SESSION_print();
#endif
void	SSL_SESSION_free();
int	i2d_SSL_SESSION();
int	SSL_set_session();
int	SSL_CTX_add_session();
int	SSL_CTX_remove_session();
SSL_SESSION *d2i_SSL_SESSION();

#ifdef HEADER_X509_H
X509 *	SSL_get_peer_certificate();
#endif

STACK *	SSL_get_peer_cert_chain();

int SSL_CTX_get_verify_mode();
int (*SSL_CTX_get_verify_callback())();
void SSL_CTX_set_verify();
void SSL_CTX_set_cert_verify_cb();
int SSL_CTX_use_RSAPrivateKey();
int SSL_CTX_use_RSAPrivateKey_ASN1();
int SSL_CTX_use_PrivateKey();
int SSL_CTX_use_PrivateKey_ASN1();
int SSL_CTX_use_certificate();
int SSL_CTX_use_certificate_ASN1();

void SSL_CTX_set_default_passwd_cb();

int SSL_CTX_check_private_key();
int SSL_check_private_key();

SSL *	SSL_new();
void    SSL_clear();
void	SSL_free();
int 	SSL_accept();
int 	SSL_connect();
int 	SSL_read();
int 	SSL_peek();
int 	SSL_write();
long	SSL_ctrl();
long	SSL_CTX_ctrl();

int	SSL_get_error();
char *	SSL_get_version();

int SSL_CTX_set_ssl_version();

SSL_METHOD *SSLv2_method();
SSL_METHOD *SSLv2_server_method();
SSL_METHOD *SSLv2_client_method();

SSL_METHOD *SSLv3_method();
SSL_METHOD *SSLv3_server_method();
SSL_METHOD *SSLv3_client_method();

SSL_METHOD *SSLv23_method();
SSL_METHOD *SSLv23_server_method();
SSL_METHOD *SSLv23_client_method();

SSL_METHOD *TLSv1_method();
SSL_METHOD *TLSv1_server_method();
SSL_METHOD *TLSv1_client_method();

STACK *SSL_get_ciphers();

int SSL_do_handshake();
int SSL_renegotiate();
int SSL_shutdown();

SSL_METHOD *SSL_get_ssl_method();
int SSL_set_ssl_method();
char *SSL_alert_type_string_long();
char *SSL_alert_type_string();
char *SSL_alert_desc_string_long();
char *SSL_alert_desc_string();

void SSL_set_client_CA_list();
void SSL_CTX_set_client_CA_list();
STACK *SSL_get_client_CA_list();
STACK *SSL_CTX_get_client_CA_list();
int SSL_add_client_CA();
int SSL_CTX_add_client_CA();

void SSL_set_connect_state();
void SSL_set_accept_state();

long SSL_get_default_timeout();

void SSLeay_add_ssl_algorithms();

char *SSL_CIPHER_description();
STACK *SSL_dup_CA_list();

SSL *SSL_dup();

X509 *SSL_get_certificate();
/* EVP * */ struct evp_pkey_st *SSL_get_privatekey();

#ifdef this_is_for_mk1mf_pl
EVP *SSL_get_privatekey();

void SSL_CTX_set_quiet_shutdown();
int SSL_CTX_get_quiet_shutdown();
void SSL_set_quiet_shutdown();
int SSL_get_quiet_shutdown();
void SSL_set_shutdown();
int SSL_get_shutdown();
int SSL_version();
int SSL_CTX_set_default_verify_paths();
int SSL_CTX_load_verify_locations();
SSL_SESSION *SSL_get_session();
SSL_CTX *SSL_get_SSL_CTX();
void SSL_set_info_callback();
int (*SSL_get_info_callback())();
int SSL_state();
void SSL_set_verify_result();
long SSL_get_verify_result();

int SSL_set_ex_data();
char *SSL_get_ex_data();
int SSL_get_ex_new_index();

int SSL_SESSION_set_ex_data();
char *SSL_SESSION_get_ex_data();
int SSL_SESSION_get_ex_new_index();

int SSL_CTX_set_ex_data();
char *SSL_CTX_get_ex_data();
int SSL_CTX_get_ex_new_index();

#endif

#endif

/* BEGIN ERROR CODES */
/* Error codes for the SSL functions. */

/* Function codes. */
#define SSL_F_CLIENT_CERTIFICATE			 100
#define SSL_F_CLIENT_HELLO				 101
#define SSL_F_CLIENT_MASTER_KEY				 102
#define SSL_F_D2I_SSL_SESSION				 103
#define SSL_F_DO_SSL3_WRITE				 104
#define SSL_F_GET_CLIENT_FINISHED			 105
#define SSL_F_GET_CLIENT_HELLO				 106
#define SSL_F_GET_CLIENT_MASTER_KEY			 107
#define SSL_F_GET_SERVER_FINISHED			 108
#define SSL_F_GET_SERVER_HELLO				 109
#define SSL_F_GET_SERVER_VERIFY				 110
#define SSL_F_I2D_SSL_SESSION				 111
#define SSL_F_READ_N					 112
#define SSL_F_REQUEST_CERTIFICATE			 113
#define SSL_F_SERVER_HELLO				 114
#define SSL_F_SSL23_ACCEPT				 115
#define SSL_F_SSL23_CLIENT_HELLO			 116
#define SSL_F_SSL23_CONNECT				 117
#define SSL_F_SSL23_GET_CLIENT_HELLO			 118
#define SSL_F_SSL23_GET_SERVER_HELLO			 119
#define SSL_F_SSL23_READ				 120
#define SSL_F_SSL23_WRITE				 121
#define SSL_F_SSL2_ACCEPT				 122
#define SSL_F_SSL2_CONNECT				 123
#define SSL_F_SSL2_ENC_INIT				 124
#define SSL_F_SSL2_READ					 125
#define SSL_F_SSL2_SET_CERTIFICATE			 126
#define SSL_F_SSL2_WRITE				 127
#define SSL_F_SSL3_ACCEPT				 128
#define SSL_F_SSL3_CHANGE_CIPHER_STATE			 129
#define SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM		 130
#define SSL_F_SSL3_CLIENT_HELLO				 131
#define SSL_F_SSL3_CONNECT				 132
#define SSL_F_SSL3_CTX_CTRL				 133
#define SSL_F_SSL3_ENC					 134
#define SSL_F_SSL3_GET_CERTIFICATE_REQUEST		 135
#define SSL_F_SSL3_GET_CERT_VERIFY			 136
#define SSL_F_SSL3_GET_CLIENT_CERTIFICATE		 137
#define SSL_F_SSL3_GET_CLIENT_HELLO			 138
#define SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE		 139
#define SSL_F_SSL3_GET_FINISHED				 140
#define SSL_F_SSL3_GET_KEY_EXCHANGE			 141
#define SSL_F_SSL3_GET_MESSAGE				 142
#define SSL_F_SSL3_GET_RECORD				 143
#define SSL_F_SSL3_GET_SERVER_CERTIFICATE		 144
#define SSL_F_SSL3_GET_SERVER_DONE			 145
#define SSL_F_SSL3_GET_SERVER_HELLO			 146
#define SSL_F_SSL3_OUTPUT_CERT_CHAIN			 147
#define SSL_F_SSL3_READ_BYTES				 148
#define SSL_F_SSL3_READ_N				 149
#define SSL_F_SSL3_SEND_CERTIFICATE_REQUEST		 150
#define SSL_F_SSL3_SEND_CLIENT_CERTIFICATE		 151
#define SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE		 152
#define SSL_F_SSL3_SEND_CLIENT_VERIFY			 153
#define SSL_F_SSL3_SEND_SERVER_CERTIFICATE		 154
#define SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE		 155
#define SSL_F_SSL3_SETUP_BUFFERS			 156
#define SSL_F_SSL3_SETUP_KEY_BLOCK			 157
#define SSL_F_SSL3_WRITE_BYTES				 158
#define SSL_F_SSL3_WRITE_PENDING			 159
#define SSL_F_SSL_BAD_METHOD				 160
#define SSL_F_SSL_BYTES_TO_CIPHER_LIST			 161
#define SSL_F_SSL_CERT_NEW				 162
#define SSL_F_SSL_CHECK_PRIVATE_KEY			 163
#define SSL_F_SSL_CREATE_CIPHER_LIST			 164
#define SSL_F_SSL_CTX_CHECK_PRIVATE_KEY			 165
#define SSL_F_SSL_CTX_NEW				 166
#define SSL_F_SSL_CTX_SET_SSL_VERSION			 167
#define SSL_F_SSL_CTX_USE_CERTIFICATE			 168
#define SSL_F_SSL_CTX_USE_CERTIFICATE_ASN1		 169
#define SSL_F_SSL_CTX_USE_CERTIFICATE_FILE		 170
#define SSL_F_SSL_CTX_USE_PRIVATEKEY			 171
#define SSL_F_SSL_CTX_USE_PRIVATEKEY_ASN1		 172
#define SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE		 173
#define SSL_F_SSL_CTX_USE_RSAPRIVATEKEY			 174
#define SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_ASN1		 175
#define SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_FILE		 176
#define SSL_F_SSL_DO_HANDSHAKE				 177
#define SSL_F_SSL_GET_NEW_SESSION			 178
#define SSL_F_SSL_GET_SERVER_SEND_CERT			 179
#define SSL_F_SSL_GET_SIGN_PKEY				 180
#define SSL_F_SSL_INIT_WBIO_BUFFER			 181
#define SSL_F_SSL_LOAD_CLIENT_CA_FILE			 182
#define SSL_F_SSL_NEW					 183
#define SSL_F_SSL_RSA_PRIVATE_DECRYPT			 184
#define SSL_F_SSL_RSA_PUBLIC_ENCRYPT			 185
#define SSL_F_SSL_SESSION_NEW				 186
#define SSL_F_SSL_SESSION_PRINT_FP			 187
#define SSL_F_SSL_SET_CERT				 188
#define SSL_F_SSL_SET_FD				 189
#define SSL_F_SSL_SET_PKEY				 190
#define SSL_F_SSL_SET_RFD				 191
#define SSL_F_SSL_SET_SESSION				 192
#define SSL_F_SSL_SET_WFD				 193
#define SSL_F_SSL_UNDEFINED_FUNCTION			 194
#define SSL_F_SSL_USE_CERTIFICATE			 195
#define SSL_F_SSL_USE_CERTIFICATE_ASN1			 196
#define SSL_F_SSL_USE_CERTIFICATE_FILE			 197
#define SSL_F_SSL_USE_PRIVATEKEY			 198
#define SSL_F_SSL_USE_PRIVATEKEY_ASN1			 199
#define SSL_F_SSL_USE_PRIVATEKEY_FILE			 200
#define SSL_F_SSL_USE_RSAPRIVATEKEY			 201
#define SSL_F_SSL_USE_RSAPRIVATEKEY_ASN1		 202
#define SSL_F_SSL_USE_RSAPRIVATEKEY_FILE		 203
#define SSL_F_SSL_WRITE					 204
#define SSL_F_TLS1_CHANGE_CIPHER_STATE			 205
#define SSL_F_TLS1_ENC					 206
#define SSL_F_TLS1_SETUP_KEY_BLOCK			 207
#define SSL_F_WRITE_PENDING				 208

/* Reason codes. */
#define SSL_R_APP_DATA_IN_HANDSHAKE			 100
#define SSL_R_BAD_ALERT_RECORD				 101
#define SSL_R_BAD_AUTHENTICATION_TYPE			 102
#define SSL_R_BAD_CHANGE_CIPHER_SPEC			 103
#define SSL_R_BAD_CHECKSUM				 104
#define SSL_R_BAD_CLIENT_REQUEST			 105
#define SSL_R_BAD_DATA_RETURNED_BY_CALLBACK		 106
#define SSL_R_BAD_DECOMPRESSION				 107
#define SSL_R_BAD_DH_G_LENGTH				 108
#define SSL_R_BAD_DH_PUB_KEY_LENGTH			 109
#define SSL_R_BAD_DH_P_LENGTH				 110
#define SSL_R_BAD_DIGEST_LENGTH				 111
#define SSL_R_BAD_DSA_SIGNATURE				 112
#define SSL_R_BAD_MAC_DECODE				 113
#define SSL_R_BAD_MESSAGE_TYPE				 114
#define SSL_R_BAD_PACKET_LENGTH				 115
#define SSL_R_BAD_PROTOCOL_VERSION_NUMBER		 116
#define SSL_R_BAD_RESPONSE_ARGUMENT			 117
#define SSL_R_BAD_RSA_DECRYPT				 118
#define SSL_R_BAD_RSA_ENCRYPT				 119
#define SSL_R_BAD_RSA_E_LENGTH				 120
#define SSL_R_BAD_RSA_MODULUS_LENGTH			 121
#define SSL_R_BAD_RSA_SIGNATURE				 122
#define SSL_R_BAD_SIGNATURE				 123
#define SSL_R_BAD_SSL_FILETYPE				 124
#define SSL_R_BAD_SSL_SESSION_ID_LENGTH			 125
#define SSL_R_BAD_STATE					 126
#define SSL_R_BAD_WRITE_RETRY				 127
#define SSL_R_BIO_NOT_SET				 128
#define SSL_R_BLOCK_CIPHER_PAD_IS_WRONG			 129
#define SSL_R_BN_LIB					 130
#define SSL_R_CA_DN_LENGTH_MISMATCH			 131
#define SSL_R_CA_DN_TOO_LONG				 132
#define SSL_R_CCS_RECEIVED_EARLY			 133
#define SSL_R_CERTIFICATE_VERIFY_FAILED			 134
#define SSL_R_CERT_LENGTH_MISMATCH			 135
#define SSL_R_CHALLENGE_IS_DIFFERENT			 136
#define SSL_R_CIPHER_CODE_WRONG_LENGTH			 137
#define SSL_R_CIPHER_OR_HASH_UNAVAILABLE		 138
#define SSL_R_CIPHER_TABLE_SRC_ERROR			 139
#define SSL_R_COMPRESSED_LENGTH_TOO_LONG		 140
#define SSL_R_COMPRESSION_FAILURE			 141
#define SSL_R_CONNECTION_ID_IS_DIFFERENT		 142
#define SSL_R_CONNECTION_TYPE_NOT_SET			 143
#define SSL_R_DATA_BETWEEN_CCS_AND_FINISHED		 144
#define SSL_R_DATA_LENGTH_TOO_LONG			 145
#define SSL_R_DECRYPTION_FAILED				 146
#define SSL_R_DH_PUBLIC_VALUE_LENGTH_IS_WRONG		 147
#define SSL_R_DIGEST_CHECK_FAILED			 148
#define SSL_R_ENCRYPTED_LENGTH_TOO_LONG			 149
#define SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST		 150
#define SSL_R_EXCESSIVE_MESSAGE_SIZE			 151
#define SSL_R_EXTRA_DATA_IN_MESSAGE			 152
#define SSL_R_GOT_A_FIN_BEFORE_A_CCS			 153
#define SSL_R_HTTPS_PROXY_REQUEST			 154
#define SSL_R_HTTP_REQUEST				 155
#define SSL_R_INTERNAL_ERROR				 156
#define SSL_R_INVALID_CHALLENGE_LENGTH			 157
#define SSL_R_LENGTH_MISMATCH				 158
#define SSL_R_LENGTH_TOO_SHORT				 159
#define SSL_R_LIBRARY_HAS_NO_CIPHERS			 160
#define SSL_R_MISSING_DH_DSA_CERT			 161
#define SSL_R_MISSING_DH_KEY				 162
#define SSL_R_MISSING_DH_RSA_CERT			 163
#define SSL_R_MISSING_DSA_SIGNING_CERT			 164
#define SSL_R_MISSING_EXPORT_TMP_DH_KEY			 165
#define SSL_R_MISSING_EXPORT_TMP_RSA_KEY		 166
#define SSL_R_MISSING_RSA_CERTIFICATE			 167
#define SSL_R_MISSING_RSA_ENCRYPTING_CERT		 168
#define SSL_R_MISSING_RSA_SIGNING_CERT			 169
#define SSL_R_MISSING_TMP_DH_KEY			 170
#define SSL_R_MISSING_TMP_RSA_KEY			 171
#define SSL_R_MISSING_TMP_RSA_PKEY			 172
#define SSL_R_MISSING_VERIFY_MESSAGE			 173
#define SSL_R_NON_SSLV2_INITIAL_PACKET			 174
#define SSL_R_NO_CERTIFICATES_RETURNED			 175
#define SSL_R_NO_CERTIFICATE_ASSIGNED			 176
#define SSL_R_NO_CERTIFICATE_RETURNED			 177
#define SSL_R_NO_CERTIFICATE_SET			 178
#define SSL_R_NO_CERTIFICATE_SPECIFIED			 179
#define SSL_R_NO_CIPHERS_AVAILABLE			 180
#define SSL_R_NO_CIPHERS_PASSED				 181
#define SSL_R_NO_CIPHERS_SPECIFIED			 182
#define SSL_R_NO_CIPHER_LIST				 183
#define SSL_R_NO_CIPHER_MATCH				 184
#define SSL_R_NO_CLIENT_CERT_RECEIVED			 185
#define SSL_R_NO_COMPRESSION_SPECIFIED			 186
#define SSL_R_NO_PRIVATEKEY				 187
#define SSL_R_NO_PRIVATE_KEY_ASSIGNED			 188
#define SSL_R_NO_PROTOCOLS_AVAILABLE			 189
#define SSL_R_NO_PUBLICKEY				 190
#define SSL_R_NO_SHARED_CIPHER				 191
#define SSL_R_NULL_SSL_CTX				 192
#define SSL_R_NULL_SSL_METHOD_PASSED			 193
#define SSL_R_OLD_SESSION_CIPHER_NOT_RETURNED		 194
#define SSL_R_PACKET_LENGTH_TOO_LONG			 195
#define SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE		 196
#define SSL_R_PEER_ERROR				 197
#define SSL_R_PEER_ERROR_CERTIFICATE			 198
#define SSL_R_PEER_ERROR_NO_CERTIFICATE			 199
#define SSL_R_PEER_ERROR_NO_CIPHER			 200
#define SSL_R_PEER_ERROR_UNSUPPORTED_CERTIFICATE_TYPE	 201
#define SSL_R_PRE_MAC_LENGTH_TOO_LONG			 202
#define SSL_R_PROBLEMS_MAPPING_CIPHER_FUNCTIONS		 203
#define SSL_R_PROTOCOL_IS_SHUTDOWN			 204
#define SSL_R_PUBLIC_KEY_ENCRYPT_ERROR			 205
#define SSL_R_PUBLIC_KEY_IS_NOT_RSA			 206
#define SSL_R_PUBLIC_KEY_NOT_RSA			 207
#define SSL_R_READ_BIO_NOT_SET				 208
#define SSL_R_READ_WRONG_PACKET_TYPE			 209
#define SSL_R_RECORD_LENGTH_MISMATCH			 210
#define SSL_R_RECORD_TOO_LARGE				 211
#define SSL_R_REQUIRED_CIPHER_MISSING			 212
#define SSL_R_REUSE_CERT_LENGTH_NOT_ZERO		 213
#define SSL_R_REUSE_CERT_TYPE_NOT_ZERO			 214
#define SSL_R_REUSE_CIPHER_LIST_NOT_ZERO		 215
#define SSL_R_SHORT_READ				 216
#define SSL_R_SIGNATURE_FOR_NON_SIGNING_CERTIFICATE	 217
#define SSL_R_SSL3_SESSION_ID_TOO_SHORT			 218
#define SSL_R_SSLV3_ALERT_BAD_CERTIFICATE		 1042
#define SSL_R_SSLV3_ALERT_BAD_RECORD_MAC		 1020
#define SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED		 1045
#define SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED		 1044
#define SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN		 1046
#define SSL_R_SSLV3_ALERT_DECOMPRESSION_FAILURE		 1030
#define SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE		 1040
#define SSL_R_SSLV3_ALERT_ILLEGAL_PARAMETER		 1047
#define SSL_R_SSLV3_ALERT_NO_CERTIFICATE		 1041
#define SSL_R_SSLV3_ALERT_PEER_ERROR_CERTIFICATE	 219
#define SSL_R_SSLV3_ALERT_PEER_ERROR_NO_CERTIFICATE	 220
#define SSL_R_SSLV3_ALERT_PEER_ERROR_NO_CIPHER		 221
#define SSL_R_SSLV3_ALERT_PEER_ERROR_UNSUPPORTED_CERTIFICATE_TYPE 222
#define SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE		 1010
#define SSL_R_SSLV3_ALERT_UNKNOWN_REMOTE_ERROR_TYPE	 223
#define SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE	 1043
#define SSL_R_SSL_CTX_HAS_NO_DEFAULT_SSL_VERSION	 224
#define SSL_R_SSL_HANDSHAKE_FAILURE			 225
#define SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS		 226
#define SSL_R_SSL_SESSION_ID_IS_DIFFERENT		 227
#define SSL_R_TLS_CLIENT_CERT_REQ_WITH_ANON_CIPHER	 228
#define SSL_R_TLS_PEER_DID_NOT_RESPOND_WITH_CERTIFICATE_LIST 229
#define SSL_R_TLS_RSA_ENCRYPTED_VALUE_LENGTH_IS_WRONG	 230
#define SSL_R_TRIED_TO_USE_UNSUPPORTED_CIPHER		 231
#define SSL_R_UNABLE_TO_DECODE_DH_CERTS			 232
#define SSL_R_UNABLE_TO_EXTRACT_PUBLIC_KEY		 233
#define SSL_R_UNABLE_TO_FIND_DH_PARAMETERS		 234
#define SSL_R_UNABLE_TO_FIND_PUBLIC_KEY_PARAMETERS	 235
#define SSL_R_UNABLE_TO_FIND_SSL_METHOD			 236
#define SSL_R_UNABLE_TO_LOAD_SSL2_MD5_ROUTINES		 237
#define SSL_R_UNABLE_TO_LOAD_SSL3_MD5_ROUTINES		 238
#define SSL_R_UNABLE_TO_LOAD_SSL3_SHA1_ROUTINES		 239
#define SSL_R_UNEXPECTED_MESSAGE			 240
#define SSL_R_UNEXPECTED_RECORD				 241
#define SSL_R_UNKNOWN_ALERT_TYPE			 242
#define SSL_R_UNKNOWN_CERTIFICATE_TYPE			 243
#define SSL_R_UNKNOWN_CIPHER_RETURNED			 244
#define SSL_R_UNKNOWN_CIPHER_TYPE			 245
#define SSL_R_UNKNOWN_KEY_EXCHANGE_TYPE			 246
#define SSL_R_UNKNOWN_PKEY_TYPE				 247
#define SSL_R_UNKNOWN_PROTOCOL				 248
#define SSL_R_UNKNOWN_REMOTE_ERROR_TYPE			 249
#define SSL_R_UNKNOWN_SSL_VERSION			 250
#define SSL_R_UNKNOWN_STATE				 251
#define SSL_R_UNSUPPORTED_CIPHER			 252
#define SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM		 253
#define SSL_R_UNSUPPORTED_PROTOCOL			 254
#define SSL_R_UNSUPPORTED_SSL_VERSION			 255
#define SSL_R_WRITE_BIO_NOT_SET				 256
#define SSL_R_WRONG_CIPHER_RETURNED			 257
#define SSL_R_WRONG_MESSAGE_TYPE			 258
#define SSL_R_WRONG_NUMBER_OF_KEY_BITS			 259
#define SSL_R_WRONG_SIGNATURE_LENGTH			 260
#define SSL_R_WRONG_SIGNATURE_SIZE			 261
#define SSL_R_WRONG_SSL_VERSION				 262
#define SSL_R_WRONG_VERSION_NUMBER			 263
#define SSL_R_X509_LIB					 264
 
#ifdef  __cplusplus
}
#endif
#endif

