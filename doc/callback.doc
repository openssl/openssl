Callback functions used in SSLeay.

--------------------------
The BIO library.  

Each BIO structure can have a callback defined against it.  This callback is
called 2 times for each BIO 'function'.  It is passed 6 parameters.
BIO_debug_callback() is an example callback which is defined in
crypto/buffer/bio_cb.c and is used in apps/dgst.c  This is intended mostly
for debuging or to notify the application of IO.

long BIO_debug_callback(BIO *bio,int cmd,char *argp,int argi,long argl,
	long ret);
bio is the BIO being called, cmd is the type of BIO function being called.
Look at the BIO_CB_* defines in buffer.h.  Argp and argi are the arguments
passed to BIO_read(), BIO_write, BIO_gets(), BIO_puts().  In the case of
BIO_ctrl(), argl is also defined.  The first time the callback is called,
before the underlying function has been executed, 0 is passed as 'ret', and
if the return code from the callback is not > 0, the call is aborted
and the returned <= 0 value is returned.
The second time the callback is called, the 'cmd' value also has
BIO_CB_RETURN logically 'or'ed with it.  The 'ret' value is the value returned
from the actuall function call and whatever the callback returns is returned
from the BIO function.

BIO_set_callback(b,cb) can be used to set the callback function
(b is a BIO), and BIO_set_callback_arg(b,arg) can be used to
set the cb_arg argument in the BIO strucutre.  This field is only intended
to be used by application, primarily in the callback function since it is
accessable since the BIO is passed.

--------------------------
The PEM library.

The pem library only really uses one type of callback,
static int def_callback(char *buf, int num, int verify);
which is used to return a password string if required.
'buf' is the buffer to put the string in.  'num' is the size of 'buf'
and 'verify' is used to indicate that the password should be checked.
This last flag is mostly used when reading a password for encryption.

For all of these functions, a NULL callback will call the above mentioned
default callback.  This default function does not work under Windows 3.1.
For other machines, it will use an application defined prompt string
(EVP_set_pw_prompt(), which defines a library wide prompt string)
if defined, otherwise it will use it's own PEM password prompt.
It will then call EVP_read_pw_string() to get a password from the console.
If your application wishes to use nice fancy windows to retrieve passwords,
replace this function.  The callback should return the number of bytes read
into 'buf'.  If the number of bytes <= 0, it is considered an error.

Functions that take this callback are listed below.  For the 'read' type
functions, the callback will only be required if the PEM data is encrypted.

For the Write functions, normally a password can be passed in 'kstr', of
'klen' bytes which will be used if the 'enc' cipher is not NULL.  If
'kstr' is NULL, the callback will be used to retrieve a password.

int PEM_do_header (EVP_CIPHER_INFO *cipher, unsigned char *data,long *len,
	int (*callback)());
char *PEM_ASN1_read_bio(char *(*d2i)(),char *name,BIO *bp,char **x,int (*cb)());
char *PEM_ASN1_read(char *(*d2i)(),char *name,FILE *fp,char **x,int (*cb)());
int PEM_ASN1_write_bio(int (*i2d)(),char *name,BIO *bp,char *x,
	EVP_CIPHER *enc,unsigned char *kstr,int klen,int (*callback)());
int PEM_ASN1_write(int (*i2d)(),char *name,FILE *fp,char *x,
	EVP_CIPHER *enc,unsigned char *kstr,int klen,int (*callback)());
STACK *PEM_X509_INFO_read(FILE *fp, STACK *sk, int (*cb)());
STACK *PEM_X509_INFO_read_bio(BIO *fp, STACK *sk, int (*cb)());

#define	PEM_write_RSAPrivateKey(fp,x,enc,kstr,klen,cb)
#define	PEM_write_DSAPrivateKey(fp,x,enc,kstr,klen,cb)
#define	PEM_write_bio_RSAPrivateKey(bp,x,enc,kstr,klen,cb)
#define	PEM_write_bio_DSAPrivateKey(bp,x,enc,kstr,klen,cb)
#define	PEM_read_SSL_SESSION(fp,x,cb)
#define	PEM_read_X509(fp,x,cb)
#define	PEM_read_X509_REQ(fp,x,cb)
#define	PEM_read_X509_CRL(fp,x,cb)
#define	PEM_read_RSAPrivateKey(fp,x,cb)
#define	PEM_read_DSAPrivateKey(fp,x,cb)
#define	PEM_read_PrivateKey(fp,x,cb)
#define	PEM_read_PKCS7(fp,x,cb)
#define	PEM_read_DHparams(fp,x,cb)
#define	PEM_read_bio_SSL_SESSION(bp,x,cb)
#define	PEM_read_bio_X509(bp,x,cb)
#define	PEM_read_bio_X509_REQ(bp,x,cb)
#define	PEM_read_bio_X509_CRL(bp,x,cb)
#define	PEM_read_bio_RSAPrivateKey(bp,x,cb)
#define	PEM_read_bio_DSAPrivateKey(bp,x,cb)
#define	PEM_read_bio_PrivateKey(bp,x,cb)
#define	PEM_read_bio_PKCS7(bp,x,cb)
#define	PEM_read_bio_DHparams(bp,x,cb)
int i2d_Netscape_RSA(RSA *a, unsigned char **pp, int (*cb)());
RSA *d2i_Netscape_RSA(RSA **a, unsigned char **pp, long length, int (*cb)());

Now you will notice that macros like
#define PEM_write_X509(fp,x) \
                PEM_ASN1_write((int (*)())i2d_X509,PEM_STRING_X509,fp, \
		                        (char *)x, NULL,NULL,0,NULL)
Don't do encryption normally.  If you want to PEM encrypt your X509 structure,
either just call PEM_ASN1_write directly or just define you own
macro variant.  As you can see, this macro just sets all encryption related
parameters to NULL.


--------------------------
The SSL library.

#define SSL_set_info_callback(ssl,cb)
#define SSL_CTX_set_info_callback(ctx,cb)
void callback(SSL *ssl,int location,int ret)
This callback is called each time around the SSL_connect()/SSL_accept() 
state machine.  So it will be called each time the SSL protocol progresses.
It is mostly present for use when debugging.  When SSL_connect() or
SSL_accept() return, the location flag is SSL_CB_ACCEPT_EXIT or
SSL_CB_CONNECT_EXIT and 'ret' is the value about to be returned.
Have a look at the SSL_CB_* defines in ssl.h.  If an info callback is defined
against the SSL_CTX, it is called unless there is one set against the SSL.
Have a look at
void client_info_callback() in apps/s_client() for an example.

Certificate verification.
void SSL_set_verify(SSL *s, int mode, int (*callback) ());
void SSL_CTX_set_verify(SSL_CTX *ctx,int mode,int (*callback)());
This callback is used to help verify client and server X509 certificates.
It is actually passed to X509_cert_verify(), along with the SSL structure
so you have to read about X509_cert_verify() :-).  The SSL_CTX version is used
if the SSL version is not defined.  X509_cert_verify() is the function used
by the SSL part of the library to verify certificates.  This function is
nearly always defined by the application.

void SSL_CTX_set_cert_verify_cb(SSL_CTX *ctx, int (*cb)(),char *arg);
int callback(char *arg,SSL *s,X509 *xs,STACK *cert_chain);
This call is used to replace the SSLeay certificate verification code.
The 'arg' is kept in the SSL_CTX and is passed to the callback.
If the callback returns 0, the certificate is rejected, otherwise it
is accepted.  The callback is replacing the X509_cert_verify() call.
This feature is not often used, but if you wished to implement
some totally different certificate authentication system, this 'hook' is
vital.

SSLeay keeps a cache of session-ids against each SSL_CTX.  These callbacks can
be used to notify the application when a SSL_SESSION is added to the cache
or to retrieve a SSL_SESSION that is not in the cache from the application.
#define SSL_CTX_sess_set_get_cb(ctx,cb)
SSL_SESSION *callback(SSL *s,char *session_id,int session_id_len,int *copy);
If defined, this callback is called to return the SESSION_ID for the
session-id in 'session_id', of 'session_id_len' bytes.  'copy' is set to 1
if the server is to 'take a copy' of the SSL_SESSION structure.  It is 0
if the SSL_SESSION is being 'passed in' so the SSLeay library is now
responsible for 'free()ing' the structure.  Basically it is used to indicate
if the reference count on the SSL_SESSION structure needs to be incremented.

#define SSL_CTX_sess_set_new_cb(ctx,cb)
int callback(SSL *s, SSL_SESSION *sess);
When a new connection is established, if the SSL_SESSION is going to be added
to the cache, this callback is called.  Return 1 if a 'copy' is required,
otherwise, return 0.  This return value just causes the reference count
to be incremented (on return of a 1), this means the application does
not need to worry about incrementing the refernece count (and the
locking that implies in a multi-threaded application).

void SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx,int (*cb)());
This sets the SSL password reading function.
It is mostly used for windowing applications
and used by PEM_read_bio_X509() and PEM_read_bio_RSAPrivateKey()
calls inside the SSL library.   The only reason this is present is because the
calls to PEM_* functions is hidden in the SSLeay library so you have to
pass in the callback some how.

#define SSL_CTX_set_client_cert_cb(ctx,cb)
int callback(SSL *s,X509 **x509, EVP_PKEY **pkey);
Called when a client certificate is requested but there is not one set
against the SSL_CTX or the SSL.  If the callback returns 1, x509 and
pkey need to point to valid data.  The library will free these when
required so if the application wants to keep these around, increment
their reference counts.  If 0 is returned, no client cert is
available.  If -1 is returned, it is assumed that the callback needs
to be called again at a later point in time.  SSL_connect will return
-1 and SSL_want_x509_lookup(ssl) returns true.  Remember that
application data can be attached to an SSL structure via the
SSL_set_app_data(SSL *ssl,char *data) call.

--------------------------
The X509 library.

int X509_cert_verify(CERTIFICATE_CTX *ctx,X509 *xs, int (*cb)(),
	int *error,char *arg,STACK *cert_chain);
int verify_callback(int ok,X509 *xs,X509 *xi,int depth,int error,char *arg,
	STACK *cert_chain);

X509_cert_verify() is used to authenticate X509 certificates.  The 'ctx' holds
the details of the various caches and files used to locate certificates.
'xs' is the certificate to verify and 'cb' is the application callback (more
detail later).  'error' will be set to the error code and 'arg' is passed
to the 'cb' callback.  Look at the VERIFY_* defines in crypto/x509/x509.h

When ever X509_cert_verify() makes a 'negative' decision about a
certitificate, the callback is called.  If everything checks out, the
callback is called with 'VERIFY_OK' or 'VERIFY_ROOT_OK' (for a self
signed cert that is not the passed certificate).

The callback is passed the X509_cert_verify opinion of the certificate 
in 'ok', the certificate in 'xs', the issuer certificate in 'xi',
the 'depth' of the certificate in the verification 'chain', the
VERIFY_* code in 'error' and the argument passed to X509_cert_verify()
in 'arg'. cert_chain is a list of extra certs to use if they are not
in the cache.

The callback can be used to look at the error reason, and then return 0
for an 'error' or '1' for ok.  This will override the X509_cert_verify()
opinion of the certificates validity.  Processing will continue depending on
the return value.  If one just wishes to use the callback for informational
reason, just return the 'ok' parameter.

--------------------------
The BN and DH library.

BIGNUM *BN_generate_prime(int bits,int strong,BIGNUM *add,
	BIGNUM *rem,void (*callback)(int,int));
int BN_is_prime(BIGNUM *p,int nchecks,void (*callback)(int,int),

Read doc/bn.doc for the description of these 2.

DH *DH_generate_parameters(int prime_len,int generator,
	void (*callback)(int,int));
Read doc/bn.doc for the description of the callback, since it is just passed
to BN_generate_prime(), except that it is also called as
callback(3,0) by this function.

--------------------------
The CRYPTO library.

void CRYPTO_set_locking_callback(void (*func)(int mode,int type,char *file,
	int line));
void CRYPTO_set_add_lock_callback(int (*func)(int *num,int mount,
	int type,char *file, int line));
void CRYPTO_set_id_callback(unsigned long (*func)(void));

Read threads.doc for info on these ones.

