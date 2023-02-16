PKCS11 Provider
==============

Introduction
-----------------------------
This design document covers the design and specification of a PKCS11 provider.
There are many PKCS11 provider projects outside OpenSSL, but the problem is 
to identify how the quality and completion of those providers are and how
regularly they're getting updated and maintained.

Why having a PKCS11 provider inside OpenSSL?

The trust of this OpenSSL PKCS11 provider would be high because:
- PKCS11 is a PKCS standard which a toolkit like OpenSSL should support out of the box.
- A PKCS11 provider inside OpenSSL would be maintained if OpenSSL changes
  the provider functionality or internal provider methods automatically.
- Everyone who needs a PKCS11 provider would try to use the OpenSSL PKCS11
  provider and contribute additional functionality and fixes.
- Contribution and fixes have to go through the OpenSSL code review which
  ensures high quality.
- Not so important, but worth to mention would be the advantage for developers to
  find source inside OpenSSL how to write a provider for all areas like 
  key management, sign / verify, encrypt, decrypt, storage and so on.


PKCS11 requirements
----------------------------
These are the minimum requirements that were identified for a PKCS11 provider:

- The PKCS11 provider should be compatible with the PKCS#11 standard v2.40.
- The PKCS11 provider should work with libraries, which are conformed to PKCS#11
  standard v2.40 and v3.0.
- The PKCS11 provider should be used for TLS connections
- The PKCS11 provider should support the generation of RSA and ECDSA asymmetric keys
  using the OpenSSL common EVP APIs.
- The PKCS11 provider should optionally support digests defined in the PKCS11 standard
  using the OpenSSL common EVP API's
- The PKCS11 provider should support storage using the standard OSSL_STORE APIs
  Storage of keys and certificates should be supported.
  Searching the store should be supported. 
- The PKCS11 provider should support signing and verifying using the standard
  OpenSSL EVP API's 
- The PKCS11 provider should support the Key URI standard
  (https://www.rfc-editor.org/rfc/rfc3986)
- Supporting URI Scheme RFC 7512 standard to find objects using the URI standard with
  the OSSL_STORE_open API.


Restrictions:
----------------------------
- The PKCS11 provider will not support dynamic PKCS#11 library selection,
  as described in RFC 7512.
- Each PKCS11 provider context is limited to one or more slots/tokes with
  the same capabilities (mechanism list, key-length, etc).


OpenSSL addition
-----------------------------
The PKCS11 provider needs some enhancement in OpenSSL to fulfill the requirements
and cover the behaviour of a PKCS11 driver.

Provider parameters:
The PKCS11 provider needs at least 3 parameters to set up the provider.
- MODULE parameter -> will contain the path to the PKCS11 driver library
- SLOT parameter -> will contain the slot which should be used by the PKCS11 provider.
- TOKEN parameter -> can be used instead of the SLOT parameter to select the PKCS11 device.
- PIN-SOURCE parameter -> can be used to optionally define a fallback
  pin-source, if it is not specified in the object, provided by the store. The
  parameter works similar to the "pin-source" query attribute in RFC 7512.

Multiple provider instances:
It should be possible to work on multiple devices on different slot at the same time.
This requires an additional OpenSSL provider load API to create multiple instances
from one provider library.
