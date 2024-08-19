Encrypted ClientHello (ECH) APIs
================================

TODO(ECH): replace references/links to the [sftcd
ECH-draft-13c](https://github.com/sftcd/openssl/tree/ECH-draft-13c) (the branch
that has good integration and interop) with relative links as files are
migrated into (PRs for) the feature branch. The `OSSL_ECHSTORE` related text
here is based on another [prototype
branch](https://github.com/sftcd/openssl/tree/ECHStore-1) that is new.

There is an [OpenSSL fork](https://github.com/sftcd/openssl/tree/ECH-draft-13c)
that has an implementation of Encrypted Client Hello (ECH) and these are design
notes taking the APIs implemented there as a starting point.

The ECH Protocol
----------------

ECH involves creating an "inner" ClientHello (CH) that contains the potentially
sensitive content of a CH, primarily the SNI and perhaps the ALPN values. That
inner CH is then encrypted and embedded (as a CH extension) in an outer CH that
contains presumably less sensitive values. The spec includes a "compression"
scheme that allows the inner CH to refer to extensions from the outer CH where
the same value would otherwise be present in both.

ECH makes use of [HPKE](https://datatracker.ietf.org/doc/rfc9180/) for the
encryption of the inner CH. HPKE code was merged to the master branch in
November 2022.

The ECH APIs are also documented
[here](https://github.com/sftcd/openssl/blob/ECH-draft-13c/doc/man3/SSL_ech_set1_echconfig.pod).
The descriptions here are less formal and provide some justification for the
API design.

Unless otherwise stated all APIs return 1 in the case of success and 0 for
error. All APIs call `SSLfatal` or `ERR_raise` macros as appropriate before
returning an error.

Prototypes are mostly in
[`include/openssl/ech.h`](https://github.com/sftcd/openssl/blob/ECH-draft-13c/include/openssl/ech.h)
for now.

General Approach
----------------

This ECH implementation has been prototyped via integrations with curl, apache2,
lighttpd, nginx and haproxy. The implementation interoperates with all other
known ECH implementations, including browsers, the libraries they use
(NSS/BoringSSL), a closed-source server implementation (Cloudflare's test
server) and with wolfssl and (reportedly) a rusttls client.

To date, the approach taken has been to minimise the application layer code
changes required to ECH-enable those applications. There is of course a tension
between that minimisation goal and providing generic and future-proof
interfaces.

In terms of implementation, it is expected (and welcome) that many details of
the current ECH implementation will change during review.

Specification
-------------

ECH is an IETF TLS WG specification. It has been stable since
[draft-13](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/13/), published
in August 2021.  The latest draft can be found
[here](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/).

Once browsers and others have done sufficient testing the plan is to
proceed to publishing ECH as an RFC.

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

Minimal Sample Code
-------------------

TODO(ECH): This sample code has only been compiled. The `OSSL_ECHSTORE` stuff
doesn't work yet.

OpenSSL includes code for an [`sslecho`](../../demos/sslecho) demo.  We've
added a minimal [`echecho`](../../demos/sslecho/echecho.c) that shows how to
ECH-enable this demo.

Handling Custom Extensions
--------------------------

OpenSSL supports custom extensions (via `SSL_CTX_add_custom_ext()`) so that
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

Padding
-------

The privacy protection provided by ECH benefits from an observer not being able
to differentiate access to different web origins based on TLS handshake
packets. Some TLS handshake messages can however reduce the size of the
anonymity-set due to message-sizes. In particular the Certificate message size
will depend on the name of the SNI from the inner ClientHello. TLS however does
allow for record layer padding which can reduce the impact of underlying
message sizes on the size of the anonymity set. The recently added
`SSL_CTX_record_padding_ex()` and `SSL_record_padding_ex()` APIs allow for
setting separate padding sizes for the handshake messages, (that most affect
ECH), and application data messages (where padding may affect efficiency more).

ECHConfig Extensions
--------------------

The ECH protocol supports extensibility [within the ECHConfig
structure](https://www.ietf.org/archive/id/draft-ietf-tls-esni-18.html#section-4.2)
via a typical TLS type, length, value scheme.  However, to date, there are no
extensions defined, nor do other implementations provide APIs for adding or
manipulating ECHConfig extensions. We therefore take the same approach here.

When running the ECH protocol, implementations are required to skip over
unknown ECHConfig extensions, or to fail for so-called "mandatory" unsupported
ECHConfig extensions. Our library code is compliant in that respect - it will
skip over extensions that are not "mandatory" (extension type high bit clear)
and fail if any "mandatory" ECHConfig extension (extension type high bit set)
is seen.

For testing purposes, ECHConfigList values that contain ECHConfig extensions
can be produced using external scripts, and used with the library, but there is
no API support for generating such, and the library has no support for any
specific ECHConfig extension type.  (Other than skipping over or failing as
described above.)

In general, the ECHConfig extensibility mechanism seems to have no proven
utility. (If new fields for an ECHConfig are required, a new ECHConfig version
with the proposed changes can just as easily be developed/deployed.)

The theory for ECHConfig extensions is that such values might be used to
control the outer ClientHello - controls to affect the inner ClientHello, when
ECH is used, are envisaged to be published as SvcParamKey values in SVCB/HTTP
resource records in the DNS.

To repeat though: after a number of years of the development of ECH, no such
ECHConfig extensions have been proposed.

Should some useful ECHConfig extensions be defined in future, then the
`OSSL_ECHSTORE` APIs could be extended to enable management of such, or, new
opaque types could be developed enabling further manipulation of ECHConfig and
ECHConfigList values.

ECH keys versus TLS server keys
-------------------------------

ECH private keys are similar to, but different from, TLS server private keys
used to authenticate servers. Notably:

- ECH private keys are expected to be rotated roughly hourly, rather than every
  month or two for TLS server private keys. Hourly ECH key rotation is an
  attempt to provide better forward secrecy, given ECH implements an
  ephemeral-static ECDH scheme.

- ECH private keys stand alone - there are no hierarchies and there is no
  chaining, and no certificates and no defined relationships between current
  and older ECH private keys. The expectation is that a "current" ECH public key
  will be published in the DNS and that plus approx. 2 "older" ECH private keys
  will remain usable for decryption at any given time. This is a way to balance
  DNS TTLs versus forward secrecy and robustness.

- In particular, the above means that we do not see any need to repeatedly
  parse or process related ECHConfigList structures - each can be processed
  independently for all practical purposes.

- There are all the usual algorithm variations, and those will likely result in
  the same x25519 versus p256 combinatorics. How that plays out has yet to be
  seen as FIPS compliance for ECH is not (yet) a thing. For OpenSSL, it seems
  wise to be agnostic and support all relevant combinations. (And doing so is not
  that hard.)

ECH Store APIs
--------------

We introduce an externally opaque type `OSSL_ECHSTORE` to allow applications
to create and manage ECHConfigList values and associated meta-data. The
external APIs using `OSSL_ECHSTORE` are:

```c
typedef struct ossl_echstore_st OSSL_ECHSTORE;

/* if a caller wants to index the last entry in the store */
# define OSSL_ECHSTORE_LAST -1

OSSL_ECHSTORE *OSSL_ECHSTORE_new(OSSL_LIB_CTX *libctx, const char *propq);
void OSSL_ECHSTORE_free(OSSL_ECHSTORE *es);
int OSSL_ECHSTORE_new_config(OSSL_ECHSTORE *es,
                             uint16_t echversion, uint8_t max_name_length,
                             const char *public_name, OSSL_HPKE_SUITE suite);
int OSSL_ECHSTORE_write_pem(OSSL_ECHSTORE *es, int index, BIO *out);

int OSSL_ECHSTORE_read_echconfiglist(OSSL_ECHSTORE *es, BIO *in);

int OSSL_ECHSTORE_get1_info(OSSL_ECHSTORE *es, OSSL_ECH_INFO **info,
                            int *count);
int OSSL_ECHSTORE_downselect(OSSL_ECHSTORE *es, int index);

int OSSL_ECHSTORE_set1_key_and_read_pem(OSSL_ECHSTORE *es, EVP_PKEY *priv,
                                        BIO *in, int for_retry);
int OSSL_ECHSTORE_read_pem(OSSL_ECHSTORE *es, BIO *in, int for_retry);
int OSSL_ECHSTORE_num_keys(OSSL_ECHSTORE *es, int *numkeys);
int OSSL_ECHSTORE_flush_keys(OSSL_ECHSTORE *es, time_t age);
```

`OSSL_ECHSTORE_new()` and `OSSL_ECHSTORE_free()` are relatively obvious.

`OSSL_ECHSTORE_new_config()` allows the caller to create a new private key
value and the related "singleton" ECHConfigList structure.
`OSSL_ECHSTORE_write_pem()` allows the caller to produce a "PEM" data
structure (conforming to the [PEMECH
specification](https://datatracker.ietf.org/doc/draft-farrell-tls-pemesni/))
from the `OSSL_ECHSTORE` entry identified by the `index`. (An `index` of
`OSSL_ECHSTORE_LAST` will select the last entry.)
These two APIs will typically be used via the `openssl ech` command line tool.

`OSSL_ECHSTORE_read_echconfiglist()` will typically be used by a client to
ingest the "ech=" SvcParamKey value found in an SVCB or HTTPS RR retrieved from
the DNS. The resulting set of ECHConfig values can then be associated with an
`SSL_CTX` or `SSL` structure for TLS connections.

Generally, clients will deal with "singleton" ECHConfigList values, but it is
also possible (in multi-CDN or multi-algorithm cases), that a client may need
more fine-grained control of which ECHConfig from a set to use for a particular
TLS connection. Clients that only support a subset of algorithms can
automatically make such decisions, however, a client faced with a set of HTTPS
RR values might (in theory) need to match (in particular) the server IP address
for the connection to the ECHConfig value via the `public_name` field within
the ECHConfig value. To enable this selection, the `OSSL_ECHSTORE_get1_info()`
API presents the client with the information enabling such selection, and the
`OSSL_ECHSTORE_downselect()` API gives the client a way to select one
particular ECHConfig value from the set stored (discarding the rest).

`OSSL_ECHSTORE_set1_key_and_read_pem()` and `OSSL_ECHSTORE_read_pem()` can be
used to load a private key value and associated "singleton" ECHConfigList.
Those can be used (by servers) to enable ECH for an `SSL_CTX` or `SSL`
connection. In addition to loading those values, the application can also
indicate via `for_retry` which ECHConfig value(s) are to be included in the
`retry_configs` fallback scheme defined by the ECH protocol.

`OSSL_ECHSTORE_num_keys()` allows a server to see how many usable ECH private
keys are currently in the store, and `OSSL_ECHSTORE_flush_keys()` allows a
server to flush keys that are older than `age` seconds.  The general model is
that a server can maintain an `OSSL_ECHSTORE` into which it periodically loads
the "latest" set of keys, e.g. hourly, and also discards the keys that are too
old, e.g. more than 3 hours old. This allows for more robust private key
management even if public key distribution suffers temporary failures.

The APIs the clients and servers can use to associate an `OSSL_ECHSTORE`
with an `SSL_CTX` or `SSL` structure:

```c
int SSL_CTX_set1_echstore(SSL_CTX *ctx, OSSL_ECHSTORE *es);
int SSL_set1_echstore(SSL *s, OSSL_ECHSTORE *es);
```

ECH will be enabled for the relevant `SSL_CTX` or `SSL` connection
when these functions succeed. Any previously associated `OSSL_ECHSTORE`
will be `OSSL_ECHSTORE_free()`ed.

To access the `OSSL_ECHSTORE` associated with an `SSL_CTX` or
`SSL` connection:

```c
OSSL_ECHSTORE *SSL_CTX_get1_echstore(const SSL_CTX *ctx);
OSSL_ECHSTORE *SSL_get1_echstore(const SSL *s);
```

The resulting `OSSL_ECHSTORE` can be modified and then re-associated
with an `SSL_CTX` or `SSL` connection.

Finer-grained client control
----------------------------

TODO(ECH): revisit this later, when we hopefully have some more information
about ECH deployments.

Applications that need fine control over which ECHConfigList (from those
available) will be used, can query an `OSSL_ECHSTORE`, retrieving information
about the set of "singleton" ECHConfigList values available, and then, if
desired, down-select to one of those, e.g., based on the `public_name` that
will be used. This would enable a client that selects the server address to use
based on IP address hints that can also be present in an HTTPS/SCVB resource
record to ensure that the correct matching ECH public value is used. The
information is presented to the caller using the `OSSL_ECH_INFO` type, which
provides a simplified view of ECH data, but where each element of an array
corresponds to exactly one ECH public value and set of names.

```c
/*
 * Application-visible form of ECH information from the DNS, from config
 * files, or from earlier API calls. APIs produce/process an array of these.
 */
typedef struct ossl_ech_info_st {
    int index; /* externally re-usable reference to this value */
    char *public_name; /* public_name from API or ECHConfig */
    char *inner_name; /* server-name (for inner CH if doing ECH) */
    unsigned char *outer_alpns; /* outer ALPN string */
    size_t outer_alpns_len;
    unsigned char *inner_alpns; /* inner ALPN string */
    size_t inner_alpns_len;
    char *echconfig; /* a JSON-like version of the associated ECHConfig */
} OSSL_ECH_INFO;

void OSSL_ECH_INFO_free(OSSL_ECH_INFO *info, int count);
int OSSL_ECH_INFO_print(BIO *out, OSSL_ECH_INFO *info, int count);
```

ECH Store Internals
-------------------

The internal structure of an ECH Store is as described below:

```c
typedef struct ossl_echext_st {
    uint16_t type;
    uint16_t len;
    unsigned char *val;
} OSSL_ECHEXT;

DEFINE_STACK_OF(OSSL_ECHEXT)

typedef struct ossl_echstore_entry_st {
    uint16_t version; /* 0xff0d for draft-13 */
    char *public_name;
    size_t pub_len;
    unsigned char *pub;
    unsigned int nsuites;
    OSSL_HPKE_SUITE *suites;
    uint8_t max_name_length;
    uint8_t config_id;
    STACK_OF(OSSL_ECHEXT) *exts;
    char *pemfname; /* name of PEM file from which this was loaded */
    time_t loadtime; /* time public and private key were loaded from file */
    EVP_PKEY *keyshare; /* long(ish) term ECH private keyshare on a server */
    int for_retry; /* whether to use this ECHConfigList in a retry */
    size_t encoded_len; /* length of overall encoded content */
    unsigned char *encoded; /* overall encoded content */
} OSSL_ECHSTORE_entry;

DEFINE_STACK_OF(OSSL_ECHSTORE_entry)

typedef struct ossl_echstore_st {
    STACK_OF(OSSL_ECHSTORE_entry) *entries;
    OSSL_LIB_CTX *libctx;
    const char *propq;
} OSSL_ECHSTORE;
```

Some notes on the above ECHConfig fields:

- `version` should be `OSSL_ECH_CURRENT_VERSION` for the current version.

- `public_name` field is the name used in the SNI of the outer ClientHello, and
  that a server ought be able to authenticate if using the `retry_configs`
  fallback mechanism.

- `config_id` is a one-octet value used by servers to select which private
  value to use to attempt ECH decryption. Servers can also do trial decryption
  if desired, as clients might use a random value for the `confid_id` as an
  anti-fingerprinting mechanism. (The use of one octet for this value was the
  result of an extended debate about efficiency versus fingerprinting.)

- The `max_name_length` is an element of the ECHConfigList that is used by
  clients as part of a padding algorithm. (That design is part of the spec, but
  isn't necessarily great - the idea is to include the longest value that might
  be the length of a DNS name included as an inner CH SNI.) A value of 0 is
  perhaps most likely to be used, indicating that the maximum isn't known.

Essentially, an ECH store is a set of ECHConfig values, plus optionally
(for servers), relevant private key value information.

When a non-singleton ECHConfigList is ingested, that is expanded into
a store that is the same as if a set of singleton ECHConfigList values
had been ingested sequentially.

In addition to the obvious fields from each ECHConfig, we also store:

- The `encoded` value (and length) of the ECHConfig, as that is used
  as an input for the HPKE encapsulation of the inner ClientHello. (Used
  by both clients and servers.)

- The `EVP_PKEY` pointer to the private key value associated with the
  relevant ECHConfig, for use by servers.

- The PEM filename and file modification time from which a private key value
  and ECHConfigList were loaded. If those values are loaded from memory,
  the filename value is the SHA-256 hash of the encoded ECHConfigList and
  the load time is the time of loading. These values assist when servers
  periodically re-load sets of files or PEM structures from memory.

Split-mode handling
-------------------

TODO(ECH): This ECH split-mode API should be considered tentative. It's design
will be revisited as we get to considering the internals.

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

The caller allocates the `inner_ch` buffer, on input `inner_len` should
contain the size of the `inner_ch` buffer, on output the size of the actual
inner CH. Note that, when ECH decryption succeeds, the inner CH will always be
smaller than the outer CH.

If there is no ECH present in the outer CH then this will return 1 (i.e., the
call will succeed) but `decrypted_ok` will be zero. The same will result if a
GREASEd ECH is present or decryption fails for some other (indistinguishable)
reason.

If the caller wishes to support HelloRetryRequest (HRR), then it must supply
the same `hrrtok` and `toklen` pointers to both calls to
`SSL_CTX_ech_raw_decrypt()` (for the initial and second ClientHello
messages). When done, the caller must free the `hrrtok` using
`OPENSSL_free()`.  If the caller doesn't need to support HRR, then it can
supply NULL values for these parameters. The value of the token is the client's
ephemeral public value, which is not sensitive having being sent in clear in
the first ClientHello.  This value is missing from the second ClientHello but
is needed for ECH decryption.

Note that `SSL_CTX_ech_raw_decrypt()` only takes a ClientHello as input. If
the flight containing the ClientHello contains other messages (e.g. a
ChangeCipherSuite or Early data), then the caller is responsible for
disentangling those, and for assembling a new flight containing the inner
ClientHello.

Different encodings
-------------------

ECHConfigList values may be provided via a command line argument to the calling
application or (more likely) have been retrieved from DNS resource records by
the application. ECHConfigList values may be provided in various encodings
(base64, ascii hex or binary) each of which may suit different applications.
ECHConfigList values may also be provided embedded in the DNS wire encoding of
HTTPS or SVCB resource records or in the equivalent zone file presentation
format.

`OSSL_ECHSTORE_find_echconfigs()` attempts to find and return the (possibly empty)
set of ECHConfigList values as an `OSSL_ECHSTORE` from the input `BIO`.

```c
OSSL_ECHSTORE *OSSL_ECHSTORE_find_echconfigs(BIO *in);
```

If the input contains more than one (syntactically correct) ECHConfigList, then only
those that contain locally supported options (e.g. AEAD ciphers) will be
returned. If no ECHConfigList found has supported options then none will be
returned and the function will return NULL.

Additional Client Controls
--------------------------

Clients can additionally more directly control the values to be used for inner
and outer SNI and ALPN values via specific APIs. This allows a client to
override the `public_name` present in an ECHConfigList that will otherwise
be used for the outer SNI. The `no_outer` input allows a client to emit an
outer CH with no SNI at all. Providing a `NULL` for the `outer_name` means
to send the `public_name` provided from the ECHConfigList.

```c
int SSL_ech_set1_server_names(SSL *s, const char *inner_name,
                             const char *outer_name, int no_outer);
int SSL_ech_set1_outer_server_name(SSL *s, const char *outer_name, int no_outer);
int SSL_ech_set1_outer_alpn_protos(SSL *s, const unsigned char *protos,
                                   size_t protos_len);
int SSL_CTX_ech_set1_outer_alpn_protos(SSL_CTX *s, const unsigned char *protos,
                                       size_t protos_len);
```

If a client attempts ECH but that fails, or sends an ECH-GREASEd CH, to
an ECH-supporting server, then that server may return an ECH "retry-config"
value that the client could choose to use in a subsequent connection. The
client can detect this situation via the `SSL_ech_get1_status()` API and
can access the retry config value via:

```c
OSSL_ECHSTORE *SSL_ech_get1_retry_config(SSL *s);
```

GREASEing
---------

"GREASEing" is defined in
[RFC8701](https://datatracker.ietf.org/doc/html/rfc8701) and is a mechanism
intended to discourage protocol ossification that can be used for ECH.  GREASEd
ECH may turn out to be important as an initial step towards widespread
deployment of ECH.

If a client wishes to GREASE ECH using a specific HPKE suite or ECH version
(represented by the TLS extension type code-point) then it can set those values
via:

```c
int SSL_ech_set1_grease_suite(SSL *s, const char *suite);
int SSL_ech_set_grease_type(SSL *s, uint16_t type);
```

ECH Status API
--------------

Clients and servers can check the status of ECH processing
on an SSL connection using this API:

```c
int SSL_ech_get1_status(SSL *s, char **inner_sni, char **outer_sni);

/* Return codes from SSL_ech_get1_status */
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

The `inner_sni` and `outer_sni` values should be freed by callers
via `OPENSSL_free()`.

The function returns one of the status values above.

Call-backs and options
----------------------

Clients and servers can set a callback that will be triggered when ECH is
attempted and the result of ECH processing is known. The callback function can
access a string (`str`) that can be used for logging (but not for branching).
Callback functions might typically call `SSL_ech_get1_status()` if branching
is required.

```c
typedef unsigned int (*SSL_ech_cb_func)(SSL *s, const char *str);

void SSL_ech_set_callback(SSL *s, SSL_ech_cb_func f);
void SSL_CTX_ech_set_callback(SSL_CTX *ctx, SSL_ech_cb_func f);
```

The following options are defined for ECH and may be set via
`SSL_set_options()`:

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
```

A Note on `_get_`,`_get0_`,`_get1_`,`_set_`,`_set0_`,`_set1_`
-------------------------------------------------------------

TODO(ECH): This text will likely disappear as things settle.

The abstraction behind the `_get_`,`_get0_`,`_get1_`,`_set_`,`_set0_`,`_set1_`
convention used in OpenSSL APIs is somewhat non-obvious, (but is what it is),
so some words of explanation of the function names above may be useful, partly
as a check that those usages are consistent with other APIs:

- `_set_` is appropriate where the input/output type(s) are basic and involve
  no type-specific memory management (e.g. `SSL_set_enable_ech_grease`)
- there are no uses of `_get_` or `_get0_` above
- `_get1_` is appropriate when a pointer to a complex type is being returned
  that may be modified and must be free'd by the application, e.g.
  `OSSL_ECHSTORE_get1_info`.
- `_set0_` is also unused above, because...
- the `_set1_` variant seems easier to handle for the application ("with ECH
  stuff, if you make it then give it to the library, you still need to free
  it") and for consistency amongst these APIs, so that is often used, e.g.
  `OSSL_ECHSTORE_set1_key_and_read_pem`.

Build Options
-------------

All ECH code is protected via `#ifndef OPENSSL_NO_ECH` and there is
a `no-ech` option to build without this code.

BoringSSL APIs
--------------

Brief descriptions of BoringSSL APIs are below together with initial comments
comparing those to the above. (It may be useful to consider the extent to
which it is useful to make OpenSSL and BoringSSL APIs resemble one another.)

Just as our implementation is under development, BoringSSL's
`include/openssl/ssl.h` says: "ECH support in BoringSSL is still experimental
and under development."

### GREASE

BoringSSL uses an API to enable GREASEing rather than an option.

```c
OPENSSL_EXPORT void SSL_set_enable_ech_grease(SSL *ssl, int enable);
```

This could work as well for our implementation, or BoringSSL could probably
change to use an option, unless there's some reason to prefer not adding new
options.

### Setting an ECHConfigList

```c
OPENSSL_EXPORT int SSL_set1_ech_config_list(SSL *ssl,
                                            const uint8_t *ech_config_list,
                                            size_t ech_config_list_len);
```

This provides a subset of the equivalent client capabilities from our fork.

### Verifying the outer CH rather than inner

BoringSSL seems to use this API to change the DNS name being verified in order
to validate a `retry_config`.

```c
OPENSSL_EXPORT void SSL_get0_ech_name_override(const SSL *ssl,
                                               const char **out_name,
                                               size_t *out_name_len);
```

I'm not sure how this compares. Need to investigate.

### Create an ECHConfigList

The first function below outputs an ECHConfig, the second adds one of those to
an `SSL_ECH_KEYS` structure, the last emits an ECHConfigList from that
structure. There are other APIs for managing memory for `SSL_ECH_KEYS`

These APIs also expose HPKE to the application via `EVP_HPKE_KEY` which is
defined in `include/openssl/hpke.h`. HPKE handling differs quite a bit from
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

Collectively these are similar to `OSSL_ECH_make_echconfig()`.

### Setting ECH keys on a server

Again using the `SSL_ECH_KEYS` type and APIs, servers can build up a set of
ECH keys using:

```c
OPENSSL_EXPORT int SSL_CTX_set1_ech_keys(SSL_CTX *ctx, SSL_ECH_KEYS *keys);
```

This is similar to the `SSL_CTX_ech_server_enable_*()` APIs.

### Getting status

BoringSSL has:

```c
OPENSSL_EXPORT int SSL_ech_accepted(const SSL *ssl);
```

That seems to be a subset of `SSL_ech_get1_status()`.
