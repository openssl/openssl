Encrypted ClientHello (ECH) APIs
================================

There is an [OpenSSL fork](https://github.com/sftcd/openssl/tree/ECH-draft-13c)
that has an implementation of Encrypted Client Hello (ECH) and these are design
notes relating to the current APIs for that, and an analysis of how these
differ from those currently in the boringssl library.

The [plan](https://github.com/openssl/project/issues/659) is to incrementally 
get that code reviewed in this feature/ech branch.

ECH involves creating an "inner" ClientHello (CH) that contains the potentially
sensitive content of a CH, primarily the SNI and perhaps the ALPN values. That
inner CH is then encrypted and embedded (as a CH extension) in an outer CH that
contains presumably less sensitive values. The spec includes a "compression"
scheme that allows the inner CH to refer to extensions from the outer CH where
the same value would otherwise be present in both.

ECH makes use of [HPKE](https://datatracker.ietf.org/doc/rfc9180/) for the
encryption of the inner CH. HPKE code was merged to the master branch in
November 2022.

The current APIs implemented in this fork are also documented
[here](https://github.com/sftcd/openssl/blob/ECH-draft-13c/doc/man3/SSL_ech_set1_echconfig.pod).
The descriptions here are less formal and provide some justification for the
API design.

Unless otherwise stated all APIs return 1 in the case of success and 0 for
error. All APIs call ``SSLfatal`` or ``ERR_raise`` macros as appropriate before
returning an error.

Prototypes are mostly in
[``include/openssl/ech.h``](https://github.com/sftcd/openssl/blob/ECH-draft-13c/include/openssl/ech.h)
for now.

Specification
-------------

ECH is an IETF TLS WG specification. It has been stable since
[draft-13](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/13/), published
in August 2021.  The latest draft can be found
[here](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/).

Once browsers and others have done sufficient testing the plan is to
proceed to publishing ECH as an RFC. That will likely include a change
of version code-points which have been tracking Internet-Draft version
numbers during the course of spec development.

The only current ECHConfig version supported is 0xfe0d which will be the
value to be used in the eventual RFC when that issues. (We'll replace the
XXXX with the relevant RFC number once that's known.)

```c
/* version from RFC XXXX */
#  define OSSL_ECH_RFCXXXX_VERSION 0xfe0d
/* latest version from an RFC */
#  define OSSL_ECH_CURRENT_VERSION OSSL_ECH_RFCXXXX_VERSION
```

Note that 0xfe0d is also the value of the ECH extension codepoint:

```c
#  define TLSEXT_TYPE_ech                       0xfe0d
```

The uses of those should be correctly differentiated in the implementation, to
more easily avoid problems if/when new versions are defined.

"GREASEing" is defined in
[RFC8701](https://datatracker.ietf.org/doc/html/rfc8701) and is a mechanism
intended to discourage protocol ossification that can be used for ECH.  GREASEd
ECH may turn out to be important as an initial step towards widespread
deployment of ECH.

Minimal Sample Code
-------------------

OpenSSL includes code for an
[``sslecho``](https://github.com/sftcd/openssl/tree/ECH-draft-13c/demos/sslecho)
demo.  We've added a minimal
[``echecho``](https://github.com/sftcd/openssl/blob/ECH-draft-13c/demos/sslecho/echecho.c)
that shows that adding one new server call
(``SSL_CTX_ech_enable_server_buffer()``) and one new client call
(``SSL_CTX_ech_set1_echconfig()``) is all that's needed to ECH-enable this
demo.

Handling Custom Extensions
--------------------------

OpenSSL supports custom extensions (via ``SSL_CTX_add_custom_ext()``) so that
extension values are supplied and parsed by client and server applications via
a callback.  The ECH specification of course doesn't deal with such
implementation matters, but comprehensive ECH support for such custom
extensions could quickly become complex. At present, in the absence of evidence
of sensitive custom extension values, we handle all such extensions by using
the ECH compression mechanism.  That means we require no API changes, only make
one call to the application callbacks and get interoperability, but that such
extension values remain visible to network observers. That could change if some
custom value turns out to be sensitive such that we'd prefer to not include it
in the outer CH.

Server-side APIs
----------------

The main server-side APIs involve generating a key and the related
ECHConfigList structure that ends up published in the DNS, periodically loading
such keys into a server to prepare for ECH decryption and handling so-called
ECH split-mode where a server only does ECH decryption but passes along the
inner CH to another server that does the actual TLS handshake with the client.

### Key and ECHConfigList Generation

``ossl_edch_make_echconfig()`` is for use by command line or other key
management tools, for example the ``openssl ech`` command documented
[here](https://github.com/sftcd/openssl/blob/ECH-draft-13c/doc/man1/openssl-ech.pod.in).

The ECHConfigList structure that will eventually be published in the DNS
contains the ECH public value (an ECC public key) and other ECH related
information, mainly the ``public_name`` that will be used as the SNI value in
outer CH messages.

```c
int OSSL_ech_make_echconfig(unsigned char *echconfig, size_t *echconfiglen,
                            unsigned char *priv, size_t *privlen,
                            uint16_t ekversion, uint16_t max_name_length,
                            const char *public_name, OSSL_HPKE_SUITE suite,
                            const unsigned char *extvals, size_t extlen);
```

The ``echconfig`` and ``priv`` buffer outputs are allocated by the caller
with the allocated size on input and the used-size on output. On output,
the ``echconfig`` contains the base64 encoded ECHConfigList and the
``priv`` value contains the PEM encoded PKCS#8 private value.

The ``ekversion`` should be ``OSSL_ECH_CURRENT_VERSION`` for the current version.

The ``max_name_length`` is an element of the ECHConfigList that is used
by clients as part of a padding algorithm. (That design is part of the
spec, but isn't necessarily great - the idea is to include the longest
value that might be the length of a DNS name included as an inner CH
SNI.) A value of 0 is perhaps most likely to be used, indicating that
the maximum isn't known.

The ECHConfigList structure is extensible, but, to date, no extensions
have been defined. If provided, the ``extvals`` buffer should contain an
already TLS-encoded set of extensions for inclusion in the ECHConfigList.

The ``openssl ech`` command can write the private key and the ECHConfigList
values to a file that matches the ECH PEM file format we have proposed to the
IETF
([draft-farrell-tls-pemesni](https://datatracker.ietf.org/doc/draft-farrell-tls-pemesni/)).
Note that that file format is not an "adopted" work item for the IETF TLS WG
(but should be:-). ``openssl ech`` also allows the two values to be output to
two separate files.

### Server Key Management

The APIs here are mainly designed for web servers and have been used in
proof-of-concept (PoC) integrations with nginx, apache, lighttpd and haproxy,
in addition to the ``openssl s_server``. (See [defo.ie](https://defo.ie) for
details and code for those PoC implementations.)

As ECH is essentially an ephemeral-static DH scheme, it is likely servers will
fairly frequently update the ECH key pairs in use, to provide something more
akin to forward secrecy. So it is a goal to make it easy for web servers to
re-load keys without complicating their configuration file handling.

Cloudflare's test ECH service rotates published ECH public keys hourly
(re-verified on 2023-01-26). We expect other services to do similarly (and do
so for some of our test services at defo.ie).

```c
int SSL_CTX_ech_server_enable_file(SSL_CTX *ctx, const char *file,
                                   int for_retry);
int SSL_CTX_ech_server_enable_dir(SSL_CTX *ctx, int *loaded,
                                  const char *echdir, int for_retry);
int SSL_CTX_ech_server_enable_buffer(SSL_CTX *ctx, const unsigned char *buf,
                                     const size_t blen, int for_retry);
```

The three functions above support loading keys, the first attempts to load a
key based on an individual file name. The second attempts to load all files
from a directory that have a ``.ech`` file extension - this allows web server
configurations to simply name that directory and then trigger a configuration
reload periodically as keys in that directory have been updated by some
external key management process (likely managed via a cronjob).  The last
allows the application to load keys from a buffer (that should contain the same
content as a file) and was added for haproxy which prefers not to do disk reads
after initial startup (for resilience reasons apparently).

If the ``for_retry`` input has the value 1, then the corresponding ECHConfig
values will be returned to clients that GREASE or use the wrong public value in
the ``retry-config`` that may enable a client to use ECH in a subsequent
connection.

The content of files referred to above must also match the format defined in
[draft-farrell-tls-pemesni](https://datatracker.ietf.org/doc/draft-farrell-tls-pemesni/).

There are also functions to allow a server to see how many keys are currently
loaded, and one to flush keys that are older than ``age`` seconds.

```c
int SSL_CTX_ech_server_get_key_status(SSL_CTX *ctx, int *numkeys);
int SSL_CTX_ech_server_flush_keys(SSL_CTX *ctx, unsigned int age);
```

### Split-mode handling

ECH split-mode involves a front-end server that only does ECH decryption and
then passes on the decrypted inner CH to a back-end TLS server that negotiates
the actual TLS session with the client, based on the inner CH content. The
function to support this simply takes the outer CH, indicates whether
decryption has succeeded or not, and if it has, returns the inner CH and SNI
values (allowing routing to the correct back-end). Both the supplied (outer)
CH and returned (inner) CH here include the record layer header.

```c
int SSL_CTX_ech_raw_decrypt(SSL_CTX *ctx,
                            int *decrypted_ok,
                            char **inner_sni, char **outer_sni,
                            unsigned char *outer_ch, size_t outer_len,
                            unsigned char *inner_ch, size_t *inner_len,
                            unsigned char **hrrtok, size_t *toklen);
```

The caller allocates the ``inner_ch`` buffer, on input ``inner_len`` should
contain the size of the ``inner_ch`` buffer, on output the size of the actual
inner CH. Note that, when ECH decryption succeeds, the inner CH will always be
smaller than the outer CH.

If there is no ECH present in the outer CH then this will return 1 (i.e., the
call will succeed) but ``decrypted_ok`` will be zero. The same will result if a
GREASEd ECH is present or decryption fails for some other (indistinguishable)
reason.

If the caller wishes to support HelloRetryRequest (HRR), then it must supply
the same ``hrrtok`` and ``toklen`` pointers to both calls to
``SSL_CTX_ech_raw_decrypt()`` (for the initial and second ClientHello
messages). When done, the caller must free the ``hrrtok`` using
``OPENSSL_free()``.  If the caller doesn't need to support HRR, then it can
supply NULL values for these parameters. The value of the token is the client's
ephemeral public value, which is not sensitive having being sent in clear in
the first ClientHello.  This value is missing from the second ClientHello but
is needed for ECH decryption.

Note that ``SSL_CTX_ech_raw_decrypt()`` only takes a ClientHello as input. If
the flight containing the ClientHello contains other messages (e.g. a
ChangeCipherSuite or Early data), then the caller is responsible for
disentangling those, and for assembling a new flight containing the inner
ClientHello.

### ECH-specific Padding of server messages

If a web server were to host a set of web sites, one of which had a much longer
name than the others, the size of some TLS handshake server messages could
expose which web site was being accessed. Similarly, if the TLS server
certificate for one web site were significantly larger or smaller than others,
message sizes could reveal which web site was being visited.  For these
reasons, we provide a way to enable additional ECH-specific padding of the
Certifiate, CertificateVerify and EncryptedExtensions messages sent from the
server to the client during the handshake.

To enable ECH-specific padding, one makes a call to:

```c
    SSL_CTX_set_options(ctx, SSL_OP_ECH_SPECIFIC_PADDING);
```

The default padding scheme is to ensure the following sizes for the plaintext
form of these messages:

| ------------------- | ------------ | ------------------- |
| Message             | Minimum Size | Size is multiple of |
| ------------------- | ------------ | ------------------- |
| Certificate         | 1792         | 128                 |
| CertificateVerify   | 480          | 16                  |
| EncryptedExtensions | 32           | 16                  |
| ------------------- | ------------ | ------------------- |

The ciphertext form of these messages, as seen on the network in the record
layer protocol, will usually be 16 octets more, due to the AEAD tag that is
added as part of encryption.

If a server wishes to have finer-grained control of these sizes, then it can
make use of the ``SSL_CTX_ech_set_pad_sizes()`` or ``SSL_ech_set_pad_sizes()``
APIs. Both involve populating an ``OSSL_ECH_PAD_SIZES`` data structure as
described below in the obvious manner.

```c
/*
 * Fine-grained ECH-spacific padding controls for a server
 */
typedef struct ossl_ech_pad_sizes_st {
    size_t cert_min; /* minimum size */
    size_t cert_unit; /* size will be multiple of */
    size_t certver_min; /* minimum size */
    size_t certver_unit; /* size will be multiple of */
    size_t ee_min; /* minimum size */
    size_t ee_unit; /* size will be multiple of */
} OSSL_ECH_PAD_SIZES;

int SSL_CTX_ech_set_pad_sizes(SSL_CTX *ctx, OSSL_ECH_PAD_SIZES *sizes);
int SSL_ech_set_pad_sizes(SSL *s, OSSL_ECH_PAD_SIZES *sizes);
```

Client-side APIs
----------------

ECHConfig values contain a version, algorithm parameters, the public key to use
for HPKE encryption and the ``public_name`` that is by default used for the
outer SNI when ECH is attempted.

Clients need to provide one or more ECHConfig values in order to enable ECH for
an SSL connection. ``SSL_ech_set1_echconfig()`` and
``SSL_CTX_set1_echconfig()`` allow clients to provide these to the library in
binary, ascii-hex or base64 encoded format. Multiple calls to these functions
will accumulate the set of ECHConfig values available for a connection. If the
input value provided contains no suitable ECHConfig values (e.g. if it only
contains ECHConfig versions that are not supported), then these functions will
fail and return zero.

```c
int SSL_ech_set1_echconfig(SSL *s, const unsigned char *val, size_t len);
int SSL_CTX_ech_set1_echconfig(SSL_CTX *ctx, const unsigned char *val,
                               size_t len);
```

ECHConfig values may be provided via a command line argument to the calling
application or (more likely) have been retrieved from DNS resource records by
the application. ECHConfig values may be provided in various encodings (base64,
ascii hex or binary) each of which may suit different applications.  ECHConfig
values may also be provided embedded in the DNS wire encoding of HTTPS or SVCB
resource records or in the equivalent zone file presentation format.

``OSSL_ech_find_echconfigs()`` attempts to find and return the (possibly empty)
set of ECHConfig values from a buffer containing one of the encoded forms
described above. Each successfully returned ECHConfigList will have
exactly one ECHConfig, i.e., a single public value.

```c
int OSSL_ech_find_echconfigs(int *num_echs,
                             unsigned char ***echconfigs, size_t **echlens,
                             const unsigned char *val, size_t len);
```

``OSSL_ech_find_echconfigs()`` returns the number of ECHConfig values from the
input (``val``/``len``) successfully decoded  in the ``num_echs`` output.  If
no ECHConfig values values are encountered (which can happen for good HTTPS RR
values) then ``num_echs`` will be zero but the function returns 1. If the
input contains more than one (syntactically correct) ECHConfig, then only
those that contain locally supported options (e.g. AEAD ciphers) will be
returned. If no ECHConfig found has supported options then none will be
returned and the function will return 0.

After a call to ``OSSL_ech_find_echconfigs()``, the application can make a
sequence of calls to ``SSL_ech_set1_echconfig()`` for each of the ECHConfig
values found.  (The various output buffers must be freed by the client
afterwards, see the example code in
[``test/ech_test.c``](https://github.com/sftcd/openssl/blob/ECH-draft-13c/test/ech_test.c).)

Clients can additionally more directly control the values to be used for inner
and outer SNI and ALPN values via specific APIs. This allows a client to
override the ``public_name`` present in an ECHConfigList that will otherwise
be used for the outer SNI. The ``no_outer`` input allows a client to emit an
outer CH with no SNI at all.

```c
int SSL_ech_set_server_names(SSL *s, const char *inner_name,
                             const char *outer_name, int no_outer);
int SSL_ech_set_outer_server_name(SSL *s, const char *outer_name, int no_outer);
int SSL_ech_set_outer_alpn_protos(SSL *s, const unsigned char *protos,
                                  unsigned int protos_len);
int SSL_CTX_ech_set_outer_alpn_protos(SSL_CTX *s, const unsigned char *protos,
                                      unsigned int protos_len);
```

If a client attempts ECH but that fails, or sends an ECH-GREASEd CH, to
an ECH-supporting server, then that server may return an ECH "retry-config"
value that the client could choose to use in a subsequent connection. The
client can detect this situation via the ``SSL_ech_get_status()`` API and
can access the retry config value via:

```c
int SSL_ech_get_retry_config(SSL *s, unsigned char **ec, size_t *eclen);
```

Clients that need fine control over which ECHConfig (from those available) will
be used, can query the SSL connection, retrieving information about the set of
ECHConfig values available, and then, if desired, down-select to one of those,
e.g., based on the ``public_name`` that will be used. This would enable a
client that selects the server address to use based on IP address hints that
can also be present in an HTTPS/SCVB resource record to ensure that the correct
matching ECHConfig is used. The information is presented to the client using
the ``OSSL_ECH_INFO`` type, which provides a simplified view of ECHConfig data,
but where each element of an array corresponds to exactly one ECH public value
and set of names.

```c
/*
 * Application-visible form of ECH information from the DNS, from config
 * files, or from earlier API calls. APIs produce/process an array of these.
 */
typedef struct ossl_ech_info_st {
    int index; /* externally re-usable reference to this value */
    char *public_name; /* public_name from API or ECHConfig */
    char *inner_name; /* server-name (for inner CH if doing ECH) */
    char *outer_alpns; /* outer ALPN string */
    char *inner_alpns; /* inner ALPN string */
    char *echconfig; /* a JSON-like version of the associated ECHConfig */
} OSSL_ECH_INFO;

void OSSL_ECH_INFO_free(OSSL_ECH_INFO *info, int count);
int OSSL_ECH_INFO_print(BIO *out, OSSL_ECH_INFO *info, int count);
int SSL_ech_get_info(SSL *s, OSSL_ECH_INFO **info, int *count);
int SSL_ech_reduce(SSL *s, int index);
```

The ``SSL_ech_reduce()`` function allows the caller to reduce the active set of
ECHConfig values down to just the one they prefer, based on the
``OSSL_ECH_INFO`` index value and whatever criteria the caller uses to prefer
one ECHConfig over another (e.g. the ``public_name``).

If a client wishes to GREASE ECH using a specific HPKE suite or ECH version
(represented by the TLS extension type code-point) then it can set those values
via:

```c
int SSL_ech_set_grease_suite(SSL *s, const char *suite);
int SSL_ech_set_grease_type(SSL *s, uint16_t type);
```

ECH Status API
--------------

Clients and servers can check the status of ECH processing
on an SSL connection using this API:

```c
int SSL_ech_get_status(SSL *s, char **inner_sni, char **outer_sni);

/* Return codes from SSL_ech_get_status */
#  define SSL_ECH_STATUS_BACKEND    4 /* ECH back-end: saw an ech_is_inner */
#  define SSL_ECH_STATUS_GREASE_ECH 3 /* GREASEd and got an ECH in return */
#  define SSL_ECH_STATUS_GREASE     2 /* ECH GREASE happened  */
#  define SSL_ECH_STATUS_SUCCESS    1 /* Success */
#  define SSL_ECH_STATUS_FAILED     0 /* Some internal or protocol error */
#  define SSL_ECH_STATUS_BAD_CALL   -100 /* Some in/out arguments were NULL */
#  define SSL_ECH_STATUS_NOT_TRIED  -101 /* ECH wasn't attempted  */
#  define SSL_ECH_STATUS_BAD_NAME   -102 /* ECH ok but server cert bad */
#  define SSL_ECH_STATUS_NOT_CONFIGURED -103 /* ECH wasn't configured */
#  define SSL_ECH_STATUS_FAILED_ECH -105 /* We tried, failed and got an ECH, from a good name */
#  define SSL_ECH_STATUS_FAILED_ECH_BAD_NAME -106 /* We tried, failed and got an ECH, from a bad name */
```

The ``inner_sni`` and ``outer_sni`` values should be freed by callers
via ``OPENSSL_free()``.

The function returns one of the status values above.

Call-backs and options
----------------------

Clients and servers can set a callback that will be triggered when ECH is
attempted and the result of ECH processing is known. The callback function can
access a string (``str``) that can be used for logging (but not for branching).
Callback functions might typically call ``SSL_ech_get_status()`` if branching
is required.

```c
typedef unsigned int (*SSL_ech_cb_func)(SSL *s, const char *str);

void SSL_ech_set_callback(SSL *s, SSL_ech_cb_func f);
void SSL_CTX_ech_set_callback(SSL_CTX *ctx, SSL_ech_cb_func f);
```

The following options are defined for ECH and may be set via
``SSL_set_options()``:

```c
/* set this to tell client to emit greased ECH values when not doing
 * "real" ECH */
#define SSL_OP_ECH_GREASE                               SSL_OP_BIT(36)
/* If this is set then the server side will attempt trial decryption */
/* of ECHs even if there is no matching record_digest. That's a bit  */
/* inefficient, but more privacy friendly */
#define SSL_OP_ECH_TRIALDECRYPT                         SSL_OP_BIT(37)
/* If set, clients will ignore the supplied ECH config_id and replace
 * that with a random value */
#define SSL_OP_ECH_IGNORE_CID                           SSL_OP_BIT(38)
/* If set, servers will add GREASEy ECHConfig values to those sent
 * in retry_configs */
#define SSL_OP_ECH_GREASE_RETRY_CONFIG                  SSL_OP_BIT(39)
/* If set, servers will add ECH-specific padding to Certificate,
 * CertificateVerify and EncryptedExtensions messages */
#define SSL_OP_ECH_SPECIFIC_PADDING                     SSL_OP_BIT(40)
```

Build Options
-------------

All ECH code is protected via ``#ifndef OPENSSL_NO_ECH`` and there is
a ``no-ech`` option to build without this code.

BoringSSL APIs
--------------

Brief descriptions of boringssl APIs are below together with initial comments
comparing those to the above. (It may be useful to consider the extent to
which it is useful to make OpenSSL and boring APIs resemble one another.)

Just as our implementation is under development, boring's ``include/openssl/ssl.h``
says: "ECH support in BoringSSL is still experimental and under development."

### GREASE

Boring uses an API to enable GREASEing rather than an option.

```c
OPENSSL_EXPORT void SSL_set_enable_ech_grease(SSL *ssl, int enable);
```

This could work as well for our implementation, or boring could probably change
to use an option, unless there's some reason to prefer not adding new options.

### Setting an ECHConfigList

```c
OPENSSL_EXPORT int SSL_set1_ech_config_list(SSL *ssl,
                                            const uint8_t *ech_config_list,
                                            size_t ech_config_list_len);
```

This provides a subset of the equivalent client capabilities from our fork.

### Verifying the outer CH rather than inner

Boring seems to use this API to change the DNS name being verified in order to
validate a ``retry_config``.

```c
OPENSSL_EXPORT void SSL_get0_ech_name_override(const SSL *ssl,
                                               const char **out_name,
                                               size_t *out_name_len);
```

I'm not sure how this compares. Need to investigate.

### Create an ECHConfigList

The first function below outputs an ECHConfig, the second adds one of those to
an ``SSL_ECH_KEYS`` structure, the last emits an ECHConfigList from that
structure. There are other APIs for managing memory for ``SSL_ECH_KEYS``

These APIs also expose HPKE to the application via ``EVP_HPKE_KEY`` which is
defined in ``include/openssl/hpke.h``. HPKE handling differs quite a bit from
the HPKE APIs merged to OpenSSL.

```c
OPENSSL_EXPORT int SSL_marshal_ech_config(uint8_t **out, size_t *out_len,
                                          uint8_t config_id,
                                          const EVP_HPKE_KEY *key,
                                          const char *public_name,
                                          size_t max_name_len);
OPENSSL_EXPORT int SSL_ECH_KEYS_add(SSL_ECH_KEYS *keys, int is_retry_config,
                                    const uint8_t *ech_config,
                                    size_t ech_config_len,
                                    const EVP_HPKE_KEY *key);
OPENSSL_EXPORT int SSL_ECH_KEYS_marshal_retry_configs(const SSL_ECH_KEYS *keys,
                                                      uint8_t **out,
                                                      size_t *out_len);

```

Collectively these are similar to ``OSSL_ech_make_echconfig()``.

### Setting ECH keys on a server

Again using the ``SSL_ECH_KEYS`` type and APIs, servers can build up a set of
ECH keys using:

```c
OPENSSL_EXPORT int SSL_CTX_set1_ech_keys(SSL_CTX *ctx, SSL_ECH_KEYS *keys);
```

This is similar to the ``SSL_CTX_ech_server_enable_*()`` APIs.

### Getting status

Boring has:

```c
OPENSSL_EXPORT int SSL_ech_accepted(const SSL *ssl);
```

That seems to be a subset of ``SSL_ech_get_status()``.
