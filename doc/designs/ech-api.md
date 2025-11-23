Encrypted ClientHello (ECH) APIs
================================

The ECH [feature branch](https://github.com/openssl/openssl/tree/feature/ech).
has an implementation of Encrypted Client Hello (ECH) and these are design
notes for the APIs implemented there.

This text was last updated on 2025-11-20.

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

The ECH APIs are documented
[here](../../doc/man3/SSL_set1_echstore.pod)
The descriptions here are less formal and provide some justification for the
API design.

Unless otherwise stated all APIs return 1 in the case of success and 0 for
error. All APIs call `SSLfatal` or `ERR_raise` macros as appropriate before
returning an error.

Prototypes are mostly in
[`include/openssl/ech.h`](../../include/openssl/ech.h).

General Approach
----------------

This ECH implementation was prototyped via integrations with curl, apache2,
lighttpd, nginx, freenginx and haproxy. The implementation interoperates with all other
known ECH implementations, including browsers, the libraries they use
(NSS/BoringSSL), a closed-source server implementation (Cloudflare's test
server) and with wolfssl and rusttls.

The approach taken has been to minimise the application layer code
changes required to ECH-enable those applications. There is of course a tension
between that minimisation goal and providing generic and future-proof
interfaces.

ECH Specification
-----------------

ECH is an IETF TLS WG specification. It has been stable since
[draft-13](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/13/), published
in August 2021.  The latest draft can be found
[here](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/).
The specification is currently in the RFC editor's queue and is
part of a [cluster](https://www.rfc-editor.org/cluster_info.php?cid=C430)
of related drafts that will be published together.

The only current ECHConfig version defined is 0xfe0d which will be the
value to be used in the eventual RFC when that issues. (We'll replace the
XXXX with the relevant RFC number once that's known.)
TODO(ECH): Update XXXX when RFC published, and check other occurrences
of XXXX throughout the source tree.

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

ECH PEM file format
-------------------

Servers supporting ECH need to read a set of ECH private keys and
ECHConfigLists from storage. There is a specification for a
[PEM file format for ECH](https://datatracker.ietf.org/doc/draft-farrell-tls-pemesni/)
that is supported by the library. That specification is being
processed within the IETF as an area-director sponsored draft,
so is not a TLS WG work item, but will be an IETF stream
RFC when completed.

This PEM file format is supported by code for a number of TLS servers,
including (at the time of writing) lighttpd, freenginx, apache2 and haproxy.
ECH support in those servers is currently an experimental feature or similar.

Minimal Sample Code
-------------------

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
message sizes on the size of the anonymity set. The
`SSL_CTX_record_padding_ex()` and `SSL_record_padding_ex()` APIs allow for
setting separate padding sizes for the handshake messages, (that most affect
ECH), and application data messages (where padding may affect efficiency more).

ECHConfig Extensions
--------------------

The ECH protocol supports extensibility [within the ECHConfig
structure](https://www.ietf.org/archive/id/draft-ietf-tls-esni-25.html#name-configuration-extensions)
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

In general, the ECHConfig extensibility mechanism seems to have little proven
utility. (If new fields for an ECHConfig are required, a new ECHConfig version
with the proposed changes could just as easily be developed/deployed.)

The theory for ECHConfig extensions is that such values might be used to
control the outer ClientHello - controls to affect the inner ClientHello, when
ECH is used, are envisaged to be published as SvcParamKey values in SVCB/HTTP
resource records in the DNS.

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
  independently for all practical purposes, and there is no equivalent to
  X.509 path processing.

- There are all the usual algorithm variations, and those will likely result in
  the same x25519 versus p256 combinatorics. How that plays out has yet to be
  seen as FIPS compliance for ECH is not (yet) a thing. For OpenSSL, it seems
  wise to be agnostic and support all relevant combinations. (And doing so is not
  that hard.)

- At the time of writing there is work ongoing to specify use of post-quantum
  KEMs with HPKE. Once that work matures, and the relevant (hybrid) KEMs are
  supported by OpenSSL, then they should be usable with ECH. It is quite likely
  at least some test code will need changes due to the increase in the size
  of the ECH extension. For now, there is no support for e.g. use of an
  equivalent to X25519MLKEM768 for ECH encryption. ECH does work fine if
  X25519MLKEM768 is used for the TLS key exchange.

ECH Store APIs
--------------

We introduce an externally opaque type `OSSL_ECHSTORE` to allow applications
to create and manage ECHConfigList values and associated meta-data. The
external APIs using `OSSL_ECHSTORE` are:

```c
typedef struct ossl_echstore_st OSSL_ECHSTORE;

/* if a caller wants to index the last entry in the store */
# define OSSL_ECHSTORE_LAST -1
/* if a caller wants all entries in the store, e.g. to print public values */
#  define OSSL_ECHSTORE_ALL -2

OSSL_ECHSTORE *OSSL_ECHSTORE_new(OSSL_LIB_CTX *libctx, const char *propq);
void OSSL_ECHSTORE_free(OSSL_ECHSTORE *es);
int OSSL_ECHSTORE_new_config(OSSL_ECHSTORE *es,
                             uint16_t echversion, uint8_t max_name_length,
                             const char *public_name, OSSL_HPKE_SUITE suite);
int OSSL_ECHSTORE_write_pem(OSSL_ECHSTORE *es, int index, BIO *out);

int OSSL_ECHSTORE_read_echconfiglist(OSSL_ECHSTORE *es, BIO *in);

int OSSL_ECHSTORE_get1_info(OSSL_ECHSTORE *es, int index, time_t *loaded_secs,
                            char **public_name, char **echconfig,
                            int *has_private, int *for_retry);
int OSSL_ECHSTORE_downselect(OSSL_ECHSTORE *es, int index);

int OSSL_ECHSTORE_set1_key_and_read_pem(OSSL_ECHSTORE *es, EVP_PKEY *priv,
                                        BIO *in, int for_retry);
int OSSL_ECHSTORE_read_pem(OSSL_ECHSTORE *es, BIO *in, int for_retry);
int OSSL_ECHSTORE_num_entries(OSSL_ECHSTORE *es, int *numentries);
int OSSL_ECHSTORE_num_keys(OSSL_ECHSTORE *es, int *numkeys);
int OSSL_ECHSTORE_flush_keys(OSSL_ECHSTORE *es, time_t age);
```

`OSSL_ECHSTORE_new()` and `OSSL_ECHSTORE_free()` are relatively obvious.

`OSSL_ECHSTORE_new_config()` allows the caller to create a new private key
value and the related "singleton" ECHConfigList structure.
`OSSL_ECHSTORE_write_pem()` allows the caller to produce a "PEM" data
structure (conforming to the ECH PEM file format)
from the `OSSL_ECHSTORE` entry identified by the `index`. (An `index` of
`OSSL_ECHSTORE_LAST` will select the last entry. An `index` of
`OSSL_ECHSTORE_ALL` will output all public values, and no private values.)
These two APIs will typically be used via the `openssl ech` command line tool.

`OSSL_ECHSTORE_read_echconfiglist()` will typically be used by a client to
ingest the "ech=" SvcParamKey value found in an SVCB or HTTPS RR retrieved from
the DNS. The resulting set of ECHConfig values can then be associated with an
`SSL_CTX` or `SSL` structure for TLS connections.

`OSSL_ECHSTORE_get1_info()` presents the caller with information about the
content of the store for logging or for display, e.g. in a command line tool.
`OSSL_ECHSTORE_downselect()` API gives the client a way to select one
particular ECHConfig value from the set stored (discarding the rest).

`OSSL_ECHSTORE_set1_key_and_read_pem()` and `OSSL_ECHSTORE_read_pem()` can be
used to load a private key value and associated "singleton" ECHConfigList.
Those can be used (by servers) to enable ECH for an `SSL_CTX` or `SSL`
connection. In addition to loading those values, the application can also
indicate via `for_retry` which ECHConfig value(s) are to be included in the
`retry_configs` fallback scheme defined by the ECH protocol.

`OSSL_ECHSTORE_num_entries()` and `OSSL_ECHSTORE_num_keys()` allow an
application  to see how many usable ECH configs and private keys are currently
in the store, and `OSSL_ECHSTORE_flush_keys()` allows a server to flush keys
that are older than `age` seconds.  The general model is that a server can
maintain an `OSSL_ECHSTORE` into which it periodically loads the "latest" set
of keys, e.g.  hourly, and also discards the keys that are too old, e.g. more
than 3 hours old. This allows for more robust private key management even if
public key distribution suffers temporary failures.

The APIs the clients and servers can use to associate an `OSSL_ECHSTORE`
with an `SSL_CTX` or `SSL` structure:

```c
int SSL_CTX_set1_echstore(SSL_CTX *ctx, OSSL_ECHSTORE *es);
int SSL_set1_echstore(SSL *s, OSSL_ECHSTORE *es);
```

ECH will be enabled for the relevant `SSL_CTX` or `SSL` connection
when these functions succeed. Any previously associated `OSSL_ECHSTORE`
will be `OSSL_ECHSTORE_free()`ed.

There is also an API that allows setting an ECHConfigList for an SSL
connection, that is compatible with BoringSSL, leading to smaller code changes
for clients that support OpenSSL or BoringSSL. Note that the input `ecl` here
for OpenSSL can be either base64 or binary encoded, but for BoringSSL it must
be binary encoded.

```c
int SSL_set1_ech_config_list(SSL *ssl, const uint8_t *ecl, size_t ecl_len);
```

To access the `OSSL_ECHSTORE` associated with an `SSL_CTX` or
`SSL` connection:

```c
OSSL_ECHSTORE *SSL_CTX_get1_echstore(const SSL_CTX *ctx);
OSSL_ECHSTORE *SSL_get1_echstore(const SSL *s);
```

The resulting `OSSL_ECHSTORE` can be modified and then re-associated
with an `SSL_CTX` or `SSL` connection.

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
    uint16_t version; /* 0xfe0d for RFC XXXX */
    char *public_name;
    size_t pub_len;
    unsigned char *pub;
    unsigned int nsuites;
    OSSL_HPKE_SUITE *suites;
    uint8_t max_name_length;
    uint8_t config_id;
    STACK_OF(OSSL_ECHEXT) *exts;
    time_t loadtime; /* time public and private key were loaded from file */
    EVP_PKEY *keyshare; /* long(ish) term ECH private keyshare on a server */
    int for_retry; /* whether to use this ECHConfigList in a retry */
    size_t encoded_len; /* length of overall encoded content */
    unsigned char *encoded; /* overall encoded content */
} OSSL_ECHSTORE_ENTRY;

DEFINE_STACK_OF(OSSL_ECHSTORE_ENTRY)

struct ossl_echstore_st {
    STACK_OF(OSSL_ECHSTORE_ENTRY) *entries;
    OSSL_LIB_CTX *libctx;
    const char *propq;
};
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

- The time at which a private key value and/or ECHConfigList were loaded.
  This value is useful when servers periodically re-load sets of files
  or PEM structures from memory, e.g. for the haproxy server.

Split-mode handling
-------------------

TODO(ECH): This ECH split-mode API should be considered tentative. It's design
should be revisited now, and either omitted from the initial release that'd
only support shared-mode ECH, or else (better:-), agreed and included in the
same time frame.

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
(base64 or binary) each of which may suit different applications.

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
/* Set this to tell client to emit greased ECH values */
# define SSL_OP_ECH_GREASE                               SSL_OP_BIT(37)
/*
 * If this is set then the server side will attempt trial decryption
 * of ECHs even if there is no matching ECH config_id. That's a bit
 * inefficient, but more privacy friendly.
 */
# define SSL_OP_ECH_TRIALDECRYPT                         SSL_OP_BIT(38)
/*
 * If set, clients will ignore the supplied ECH config_id and replace
 * that with a random value.
 */
# define SSL_OP_ECH_IGNORE_CID                           SSL_OP_BIT(39)
/*
 * If set, servers will add GREASEy ECHConfig values to those sent
 * in retry_configs.
 */
# define SSL_OP_ECH_GREASE_RETRY_CONFIG                  SSL_OP_BIT(40)
```

Build Options
-------------

Almost all ECH code is protected via `#ifndef OPENSSL_NO_ECH` and there is a
`no-ech` option to build without this code.

Applications using ECH may choose to detect the availability of ECH in
the library by checking that `SSL_OP_ECH_GREASE` is defined. This is
used by some server applications today.

ECH Tests
---------

The following tests are included in the `make test` target:

- [`test_app_ech`](../../test/recipes/20-test_app_ech.t)
- [`test_ech`](../../test/ech_test.c)
- [`test_ech_corrupt`](../../test/ech_corrupt_test.c)
- [`test_ech_client_server`](../../test/recipes/82-test_ech_client_server.t)

There are also two external tests to check interoperability
with the NSS and BoringSSL libraries:

- [`test_external_ech_nss`](../../test/recipes/95-test_external_ech_nss.t)
- [`test_external_ech_bssl`](../../test/recipes/95-test_external_ech_bssl.t)

The `test_app_ech` test excercises the `openssl ech` command line utility that
can be used to generate and manipulate ECH keys and configurations.

The `test_ech` test exercises ECH APIs, including round-trip tests that use ECH
in TLS sessions. The code for this includes many valid and invalid test vectors
and is designed to be relatively easily extended with additional tests.

`test_ech_corrupt` is modelled on [sslcorruptetst.c](../../test/sslcorrupttest.c)
and mainly includes tests where variously incorrectly encoded inner ClientHello
test vectors are encrypted using HPKE and then successfully decrypted by a
server that then rejects the connection returning the expected error code.

`test_ech_client_server` exercises the various ECH command line
options for the OpenSSL `s_client` and `s_server` commands. Changes to
the output from those command may require changes to these tests as
they use pattern matching on the outputs to detect expected successes
or failures.

The external tests check that the library correctly interoperates,
as a client or server, with NSS or BoringSSL. These require a build
configured with `enable-external-tests` and are quite time consuming
when first run, as they need to download and build the relevant
NSS or BoringSSL library. The client/server tests here are not very
extensive and just check that a basic configuration interoperates.

How to measure coverage of ECH tests
------------------------------------

There are likely many ways to do this, but the following is the
recipe used during ECH development:

```bash
./config --debug enable-external-tests --coverage no-asm no-afalgeng no-shared -DPEDANTIC -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
make -s -j12
make test TESTS='test_ech test_ech_corrupt test_app_ech test_ech_client_server test_external_ech_bssl test_external_ech_nss'
# next line failed, was replaced the the one following
# lcov -d . -c -o ./lcov.info
/usr/bin/geninfo . --output-filename ./lcov.info --memory 0 --ignore-errors mismatch
genhtml ./lcov.info --output-directory $HOME/tmp/myco
```

To clean away the coverage files:

```bash
find . -name '*.gcda'  -exec rm {} \;
find . -name '*.gcno'  -exec rm {} \;
rm lcov.info
make clean
make -j12
```

Checking memory errors
----------------------

As is typical with the library there is a good bit of code that handles error
cases that are hard to test. Causing memory allocation failures though allows
us to get at most of those code fragments.

To get to those error handling lines of code, one can use an exhaustive script
that incrementally allows more and more memory allocations to work before
triggering failures such as:

```bash
#!/bin/bash
#
# run 16k tests

# if you want tracing
# export OPENSSL_TRACE="TLS"
logfile=loads.log
iter=0

function whenisitagain()
{
    /bin/date -u +%Y%m%d-%H%M%S
}
NOW=$(whenisitagain)
echo "==================================" >>$logfile
echo "Started at $NOW" >>$logfile

# 16,000 calls without failures should be enough for the
# test to pass - gprof says we have 15,558 calls to
# CRYPTO_malloc for the test below
while ((iter < 16000))
do
    echo "Doing $iter" >>$logfile
    iter=$((iter+1))
    export OPENSSL_MALLOC_FAILURES="$iter@0;0@99;"
    ./test/ech_test -test 6 -iter 1 >>$logfile 2>&1
    echo "Done $iter"
    echo "Done $iter" >>$logfile
    echo "" >>$logfile
    echo "" >>$logfile
done

NOW=$(whenisitagain)
echo "Ended at $NOW" >>$logfile
echo "==================================" >>$logfile
```

An `OPENSSL_MALLOC_FAILURES` value of `100@0;0@99` means to allow the first 100
memory allocations to work, and to then switch to a mode where there's a 99%
chance of memory allocation failing. By using `$iter` we just keep incrementing
how far into the run we allow nominal memory allocation before we break things,
which should result in (eventually:-) hitting every possible memory allocation
failure handling line of code.

You need to build with the `crypto-mdebug` option to get the memory allocation
failure, so that'd be something like:

```bash
./config --debug enable-external-tests enable-crypto-mdebug --coverage no-asm no-afalgeng no-shared -DPEDANTIC -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
```

The script above gets us from 75% lines of code covered based on normal tests
to 85.6% for the `ech_internal.c` file, which is our least well covered by
normal tests. The script takes about 20 minutes to run on a developer laptop.
