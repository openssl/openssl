I have just checked over and re-worked the session stuff.
The following brief example will ignore all setup information to do with
authentication.

Things operate as follows.

The SSL environment has a 'context', a SSL_CTX structure.  This holds the
cached SSL_SESSIONS (which can be reused) and the certificate lookup
information.  Each SSL structure needs to be associated with a SSL_CTX.
Normally only one SSL_CTX structure is needed per program.

SSL_CTX *SSL_CTX_new(void ); 
void    SSL_CTX_free(SSL_CTX *);
These 2 functions create and destroy SSL_CTX structures

The SSL_CTX has a session_cache_mode which is by default,
in SSL_SESS_CACHE_SERVER mode.  What this means is that the library
will automatically add new session-id's to the cache apon sucsessful
SSL_accept() calls.
If SSL_SESS_CACHE_CLIENT is set, then client certificates are also added
to the cache.
SSL_set_session_cache_mode(ctx,mode)  will set the 'mode' and
SSL_get_session_cache_mode(ctx) will get the cache 'mode'.
The modes can be
SSL_SESS_CACHE_OFF	- no caching
SSL_SESS_CACHE_CLIENT	- only SSL_connect()
SSL_SESS_CACHE_SERVER	- only SSL_accept()
SSL_SESS_NO_CACHE_BOTH	- Either SSL_accept() or SSL_connect().
If SSL_SESS_CACHE_NO_AUTO_CLEAR is set, old timed out sessions are
not automatically removed each 255, SSL_connect()s or SSL_accept()s.

By default, apon every 255 successful SSL_connect() or SSL_accept()s,
the cache is flush.  Please note that this could be expensive on
a heavily loaded SSL server, in which case, turn this off and
clear the cache of old entries 'manually' (with one of the functions
listed below) every few hours.  Perhaps I should up this number, it is hard
to say.  Remember, the '255' new calls is just a mechanims to get called
every now and then, in theory at most 255 new session-id's will have been
added but if 100 are added every minute, you would still have
500 in the cache before any would start being flushed (assuming a 3 minute
timeout)..

int SSL_CTX_sess_hits(SSL_CTX *ctx);
int SSL_CTX_sess_misses(SSL_CTX *ctx);
int SSL_CTX_sess_timeouts(SSL_CTX *ctx);
These 3 functions return statistics about the SSL_CTX.  These 3 are the
number of session id reuses.  hits is the number of reuses, misses are the
number of lookups that failed, and timeouts is the number of cached
entries ignored because they had timeouted.

ctx->new_session_cb is a function pointer to a function of type
int new_session_callback(SSL *ssl,SSL_SESSION *new);
This function, if set in the SSL_CTX structure is called whenever a new
SSL_SESSION is added to the cache.  If the callback returns non-zero, it
means that the application will have to do a SSL_SESSION_free()
on the structure (this is
to do with the cache keeping the reference counts correct, without the
application needing to know about it.
The 'active' parameter is the current SSL session for which this connection
was created.

void SSL_CTX_sess_set_new_cb(SSL_CTX *ctx,int (*cb)());
to set the callback,
int (*cb)() SSL_CTX_sess_get_new_cb(SSL_CTX *ctx)
to get the callback.

If the 'get session' callback is set, when a session id is looked up and
it is not in the session-id cache, this callback is called.  The callback is
of the form
SSL_SESSION *get_session_callback(unsigned char *sess_id,int sess_id_len,
	int *copy);

The get_session_callback is intended to return null if no session id is found.
The reference count on the SSL_SESSION in incremented by the SSL library,
if copy is 1.  Otherwise, the reference count is not modified.

void SSL_CTX_sess_set_get_cb(ctx,cb) sets the callback and
int (*cb)()SSL_CTX_sess_get_get_cb(ctx) returns the callback.

These callbacks are basically indended to be used by processes to
send their session-id's to other processes.  I currently have not implemented
non-blocking semantics for these callbacks, it is upto the appication
to make the callbacks effiecent if they require blocking (perhaps
by 'saving' them and then 'posting them' when control returns from
the SSL_accept().

LHASH *SSL_CTX_sessions(SSL_CTX *ctx)
This returns the session cache.  The lhash strucutre can be accessed for
statistics about the cache.

void lh_stats(LHASH *lh, FILE *out);
void lh_node_stats(LHASH *lh, FILE *out);
void lh_node_usage_stats(LHASH *lh, FILE *out);

can be used to print details about it's activity and current state.
You can also delve directly into the lhash structure for 14 different
counters that are kept against the structure.  When I wrote the lhash library,
I was interested in gathering statistics :-).
Have a read of doc/lhash.doc in the SSLeay distribution area for more details
on the lhash library.

Now as mentioned ealier, when a SSL is created, it needs a SSL_CTX.
SSL *   SSL_new(SSL_CTX *);

This stores a session.  A session is secret information shared between 2
SSL contexts.  It will only be created if both ends of the connection have
authenticated their peer to their satisfaction.  It basically contains
the information required to use a particular secret key cipher.

To retrieve the SSL_CTX being used by a SSL,
SSL_CTX *SSL_get_SSL_CTX(SSL *s);

Now when a SSL session is established between to programs, the 'session'
information that is cached in the SSL_CTX can me manipulated by the
following functions.
int SSL_set_session(SSL *s, SSL_SESSION *session);
This will set the SSL_SESSION to use for the next SSL_connect().  If you use
this function on an already 'open' established SSL connection, 'bad things
will happen'.  This function is meaning-less when used on a ssl strucutre
that is just about to be used in a SSL_accept() call since the
SSL_accept() will either create a new session or retrieve one from the
cache.

SSL_SESSION *SSL_get_session(SSL *s);
This will return the SSL_SESSION for the current SSL, NULL if there is
no session associated with the SSL structure.

The SSL sessions are kept in the SSL_CTX in a hash table, to remove a
session
void    SSL_CTX_remove_session(SSL_CTX *,SSL_SESSION *c);
and to add one
int    SSL_CTX_add_session(SSL_CTX *s, SSL_SESSION *c);
SSL_CTX_add_session() returns 1 if the session was already in the cache (so it
was not added).
Whenever a new session is created via SSL_connect()/SSL_accept(),
they are automatically added to the cache, depending on the session_cache_mode
settings.  SSL_set_session()
does not add it to the cache.  Just call SSL_CTX_add_session() if you do want the
session added.  For a 'client' this would not normally be the case.
SSL_CTX_add_session() is not normally ever used, except for doing 'evil' things
which the next 2 funtions help you do.

int     i2d_SSL_SESSION(SSL_SESSION *in,unsigned char **pp);
SSL_SESSION *d2i_SSL_SESSION(SSL_SESSION **a,unsigned char **pp,long length);
These 2 functions are in the standard ASN1 library form and can be used to
load and save to a byte format, the SSL_SESSION structure.
With these functions, you can save and read these structures to a files or
arbitary byte string.
The PEM_write_SSL_SESSION(fp,x) and PEM_read_SSL_SESSION(fp,x,cb) will
write to a file pointer in base64 encoding.

What you can do with this, is pass session information between separate
processes.  Please note, that you will probably also need to modify the
timeout information on the SSL_SESSIONs.

long SSL_get_time(SSL_SESSION *s)
will return the 'time' that the session
was loaded.  The timeout is relative to this time.  This information is
saved when the SSL_SESSION is converted to binarary but it is stored
in as a unix long, which is rather OS dependant, but easy to convert back.

long SSL_set_time(SSL_SESSION *s,long t) will set the above mentioned time.
The time value is just the value returned from time(3), and should really
be defined by be to be time_t.

long SSL_get_timeout(SSL_SESSION *s);
long SSL_set_timeout(SSL_SESSION *s,long t);
These 2 retrieve and set the timeout which is just a number of secconds
from the 'SSL_get_time()' value.  When this time period has elapesed,
the session will no longer be in the cache (well it will actually be removed
the next time it is attempted to be retrieved, so you could 'bump'
the timeout so it remains valid).
The 'time' and 'timeout' are set on a session when it is created, not reset
each time it is reused.  If you did wish to 'bump it', just after establishing
a connection, do a
SSL_set_time(ssl,time(NULL));

You can also use
SSL_CTX_set_timeout(SSL_CTX *ctx,unsigned long t) and
SSL_CTX_get_timeout(SSL_CTX *ctx) to manipulate the default timeouts for
all SSL connections created against a SSL_CTX.  If you set a timeout in
an SSL_CTX, all new SSL's created will inherit the timeout.  It can be over
written by the SSL_set_timeout(SSL *s,unsigned long t) function call.
If you 'set' the timeout back to 0, the system default will be used.

SSL_SESSION *SSL_SESSION_new();
void SSL_SESSION_free(SSL_SESSION *ses);
These 2 functions are used to create and dispose of SSL_SESSION functions.
You should not ever normally need to use them unless you are using 
i2d_SSL_SESSION() and/or d2i_SSL_SESSION().  If you 'load' a SSL_SESSION
via d2i_SSL_SESSION(), you will need to SSL_SESSION_free() it.
Both SSL_set_session() and SSL_CTX_add_session() will 'take copies' of the
structure (via reference counts) when it is passed to them.

SSL_CTX_flush_sessions(ctx,time);
The first function will clear all sessions from the cache, which have expired
relative to 'time' (which could just be time(NULL)).

SSL_CTX_flush_sessions(ctx,0);
This is a special case that clears everything.

As a final comment, a 'session' is not enough to establish a new
connection.  If a session has timed out, a certificate and private key
need to have been associated with the SSL structure.
SSL_copy_session_id(SSL *to,SSL *from); will copy not only the session
strucutre but also the private key and certificate associated with
'from'.

EXAMPLES.

So lets play at being a wierd SSL server.

/* setup a context */
ctx=SSL_CTX_new();

/* Lets load some session from binary into the cache, why one would do
 * this is not toally clear, but passing between programs does make sense
 * Perhaps you are using 4096 bit keys and are happy to keep them
 * valid for a week, to avoid the RSA overhead of 15 seconds, I'm not toally
 * sure, perhaps this is a process called from an SSL inetd and this is being 
 * passed to the application. */
session=d2i_SSL_SESSION(....)
SSL_CTX_add_session(ctx,session);

/* Lets even add a session from a file */
session=PEM_read_SSL_SESSION(....)
SSL_CTX_add_session(ctx,session);

/* create a new SSL structure */
ssl=SSL_new(ctx);

/* At this point we want to be able to 'create' new session if
 * required, so we need a certificate and RSAkey. */
SSL_use_RSAPrivateKey_file(ssl,...)
SSL_use_certificate_file(ssl,...)

/* Now since we are a server, it make little sence to load a session against
 * the ssl strucutre since a SSL_accept() will either create a new session or
 * grab an existing one from the cache. */

/* grab a socket descriptor */
fd=accept(...);

/* associated it with the ssl strucutre */
SSL_set_fd(ssl,fd);

SSL_accept(ssl); /* 'do' SSL using out cert and RSA key */

/* Lets print out the session details or lets save it to a file,
 * perhaps with a secret key cipher, so that we can pass it to the FBI
 * when they want to decode the session :-).  While we have RSA
 * this does not matter much but when I do SSLv3, this will allow a mechanism
 * for the server/client to record the information needed to decode
 * the traffic that went over the wire, even when using Diffie-Hellman */
PEM_write_SSL_SESSION(SSL_get_session(ssl),stdout,....)

Lets 'connect' back to the caller using the same session id.

ssl2=SSL_new(ctx);
fd2=connect(them);
SSL_set_fd(ssl2,fd2);
SSL_set_session(ssl2,SSL_get_session(ssl));
SSL_connect(ssl2);

/* what the hell, lets accept no more connections using this session */
SSL_CTX_remove_session(SSL_get_SSL_CTX(ssl),SSL_get_session(ssl));

/* we could have just as easily used ssl2 since they both are using the
 * same session.
 * You will note that both ssl and ssl2 are still using the session, and
 * the SSL_SESSION structure will be free()ed when both ssl and ssl2
 * finish using the session.  Also note that you could continue to initiate
 * connections using this session by doing SSL_get_session(ssl) to get the
 * existing session, but SSL_accept() will not be able to find it to
 * use for incoming connections.
 * Of corse, the session will timeout at the far end and it will no
 * longer be accepted after a while.  The time and timeout are ignored except
 * by SSL_accept(). */

/* Since we have had our server running for 10 weeks, and memory is getting
 * short, perhaps we should clear the session cache to remove those
 * 100000 session entries that have expired.  Some may consider this
 * a memory leak :-) */

SSL_CTX_flush_sessions(ctx,time(NULL));

/* Ok, after a bit more time we wish to flush all sessions from the cache
 * so that all new connections will be authenticated and incure the
 * public key operation overhead */

SSL_CTX_flush_sessions(ctx,0);

/* As a final note, to copy everything to do with a SSL, use */
SSL_copy_session_id(SSL *to,SSL *from);
/* as this also copies the certificate and RSA key so new session can
 * be established using the same details */

