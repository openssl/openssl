OpenSSL FIPS support
====================

This release of OpenSSL includes a cryptographic module that can be
FIPS validated. The module is implemented as an OpenSSL provider.
A provider is essentially a dynamically loadable module which implements
cryptographic algorithms, see the [README-PROVIDERS](README-PROVIDERS.md) file
for further details.

A cryptographic module is only FIPS validated after it has gone through the complex
FIPS 140 validation process. As this process takes a very long time, it is not
possible to validate every minor release of OpenSSL.
If you need a FIPS validated module then you must ONLY generate a FIPS provider
using OpenSSL versions that have valid FIPS certificates. A FIPS certificate
contains a link to a Security Policy, and you MUST follow the instructions
in the Security Policy in order to be FIPS compliant.
See <https://www.openssl.org/source/> for information related to OpenSSL
FIPS certificates and Security Policies.

Newer OpenSSL Releases that include security or bug fixes can be used to build
all other components (such as the core API's, TLS and the default, base and
legacy providers) without any restrictions, but the FIPS provider must be built
as specified in the Security Policy (normally with a different version of the
source code).

The OpenSSL FIPS provider is a shared library called `fips.so` (on Unix), or
resp. `fips.dll` (on Windows). The FIPS provider does not get built and
installed automatically. To enable it, you need to configure OpenSSL using
the `enable-fips` option.

Installing the FIPS provider
============================

In order to be FIPS compliant you must only use FIPS validated source code.
Refer to <https://www.openssl.org/source/> for information related to
which versions are FIPS validated. The instructions given below build OpenSSL
just using the FIPS validated source code.

If you want to use a validated FIPS provider, but also want to use the latest
OpenSSL release to build everything else, then refer to the next section.

The following is only a guide.
Please read the Security Policy for up to date installation instructions.

If the FIPS provider is enabled, it gets installed automatically during the
normal installation process. Simply follow the normal procedure (configure,
make, make test, make install) as described in the [INSTALL](INSTALL.md) file.

For example, on Unix the final command

    $ make install

effectively executes the following install targets

    $ make install_sw
    $ make install_ssldirs
    $ make install_docs
    $ make install_fips     # for `enable-fips` only

The `install_fips` make target can also be invoked explicitly to install
the FIPS provider independently, without installing the rest of OpenSSL.

The Installation of the FIPS provider consists of two steps. In the first step,
the shared library is copied to its installed location, which by default is

    /usr/local/lib/ossl-modules/fips.so                  on Unix, and
    C:\Program Files\OpenSSL\lib\ossl-modules\fips.dll   on Windows.

In the second step, the `openssl fipsinstall` command is executed, which completes
the installation by doing the following two things:

- Runs the FIPS module self tests
- Generates the so-called FIPS module configuration file containing information
  about the module such as the module checksum (and for OpenSSL 3.0 the
  self test status).

The FIPS module must have the self tests run, and the FIPS module config file
output generated on every machine that it is to be used on. For OpenSSL 3.0,
you must not copy the FIPS module config file output data from one machine to another.

On Unix, the `openssl fipsinstall` command will be invoked as follows by default:

    $ openssl fipsinstall -out /usr/local/ssl/fipsmodule.cnf -module /usr/local/lib/ossl-modules/fips.so

If you configured OpenSSL to be installed to a different location, the paths will
vary accordingly. In the rare case that you need to install the fipsmodule.cnf
to a non-standard location, you can execute the `openssl fipsinstall` command manually.

Installing the FIPS provider and using it with the latest release
=================================================================

This normally requires you to download 2 copies of the OpenSSL source code.

Download and build a validated FIPS provider
--------------------------------------------

Refer to <https://www.openssl.org/source/> for information related to
which versions are FIPS validated. For this example we use OpenSSL 3.0.0.

    $ wget https://www.openssl.org/source/openssl-3.0.0.tar.gz
    $ tar -xf openssl-3.0.0.tar.gz
    $ cd openssl-3.0.0
    $ ./Configure enable-fips
    $ make
    $ cd ..

Download and build the latest release of OpenSSL
------------------------------------------------

We use OpenSSL 3.1.0 here, (but you could also use the latest 3.0.X)

    $ wget https://www.openssl.org/source/openssl-3.1.0.tar.gz
    $ tar -xf openssl-3.1.0.tar.gz
    $ cd openssl-3.1.0
    $ ./Configure enable-fips
    $ make

Use the OpenSSL FIPS provider for testing
-----------------------------------------

We do this by replacing the artifact for the OpenSSL 3.1.0 FIPS provider.
Note that the OpenSSL 3.1.0 FIPS provider has not been validated
so it must not be used for FIPS purposes.

    $ cp ../openssl-3.0.0/providers/fips.so providers/.
    $ cp ../openssl-3.0.0/providers/fipsmodule.cnf providers/.
    // Note that for OpenSSL 3.0 that the `fipsmodule.cnf` file should not
    // be copied across multiple machines if it contains an entry for
    // `install-status`. (Otherwise the self tests would be skipped).

    // Validate the output of the following to make sure we are using the
    // OpenSSL 3.0.0 FIPS provider
    $ ./util/wrap.pl -fips apps/openssl list -provider-path providers \
    -provider fips -providers

    // Now run the current tests using the OpenSSL 3.0 FIPS provider.
    $ make tests

Copy the FIPS provider artifacts (`fips.so` & `fipsmodule.cnf`) to known locations
-------------------------------------------------------------------------------------

    $ cd ../openssl-3.0.0
    $ sudo make install_fips

Check that the correct FIPS provider is being used
--------------------------------------------------

    $./util/wrap.pl -fips apps/openssl list -provider-path providers \
    -provider fips -providers

    // This should produce the following output
    Providers:
      base
        name: OpenSSL Base Provider
        version: 3.1.0
        status: active
      fips
        name: OpenSSL FIPS Provider
        version: 3.0.0
        status: active

Using the FIPS Module in applications
=====================================

Documentation about using the FIPS module is available on the [fips_module(7)]
manual page.

 [fips_module(7)]: https://www.openssl.org/docs/manmaster/man7/fips_module.html

Entropy Source
==============

The FIPS provider typically relies on an external entropy source,
specified during OpenSSL build configuration (default: `os`).  However, by
enabling the `enable-fips-jitter` option during configuration, an internal
jitter entropy source will be used instead.  Note that this will cause
the FIPS provider to operate in a non-compliant mode unless an entropy
assessment [ESV] and validation through the [CMVP] are additionally conducted.

Note that the `enable-fips-jitter` option is only available in OpenSSL
versions 3.5 and later.

 [CMVP]: https://csrc.nist.gov/projects/cryptographic-module-validation-program
 [ESV]: https://csrc.nist.gov/Projects/cryptographic-module-validation-program/entropy-validations

3rd-Party Vendor Builds
=====================================

Some Vendors choose to patch/modify/build their own FIPS provider,
test it with a Security Laboratory and submit it under their own CMVP
certificate, instead of using OpenSSL Project submissions. When doing
so, FIPS provider should uniquely identify its own name and version
number. The build infrastructure allows to customize FIPS provider
build information via changes to strings in `VERSION.dat`.

Setting "PRE_RELEASE_TAG" (dashed suffix), "BUILD_METADATA" (plus
suffix), and "FIPS_VENDOR" allow to control reported FIPS provider
name and build version as required for CMVP submission.

# FIPS Indicator Parameters

This section defines various FIPS (Federal Information Processing Standards) indicator parameters used in the OpenSSL library. Each parameter is defined using the `OSSL_FIPS_PARAM` macro, which takes three arguments: the parameter name, the corresponding macro name, and the default value.

## Parameters

1. **security_checks**
   - **Macro:** `SECURITY_CHECKS`
   - **Default Value:** `1`
   - **Description:** Enables or disables security checks.

2. **tls1_prf_ems_check**
   - **Macro:** `TLS1_PRF_EMS_CHECK`
   - **Default Value:** `0`
   - **Description:** Checks for the use of the TLS 1.0 PRF with EMS.

3. **no_short_mac**
   - **Macro:** `NO_SHORT_MAC`
   - **Default Value:** `1`
   - **Description:** Disallows the use of short MACs.

4. **hmac_key_check**
   - **Macro:** `HMAC_KEY_CHECK`
   - **Default Value:** `0`
   - **Description:** Checks the HMAC key.

5. **kmac_key_check**
   - **Macro:** `KMAC_KEY_CHECK`
   - **Default Value:** `0`
   - **Description:** Checks the KMAC key.

6. **restricted_drbg_digests**
   - **Macro:** `DRBG_TRUNC_DIGEST`
   - **Default Value:** `0`
   - **Description:** Restricts the use of truncated DRBG digests.

7. **signature_digest_check**
   - **Macro:** `SIGNATURE_DIGEST_CHECK`
   - **Default Value:** `0`
   - **Description:** Checks the digest used in signatures.

8. **hkdf_digest_check**
   - **Macro:** `HKDF_DIGEST_CHECK`
   - **Default Value:** `0`
   - **Description:** Checks the digest used in HKDF.

9. **tls13_kdf_digest_check**
   - **Macro:** `TLS13_KDF_DIGEST_CHECK`
   - **Default Value:** `0`
   - **Description:** Checks the digest used in TLS 1.3 KDF.

10. **tls1_prf_digest_check**
    - **Macro:** `TLS1_PRF_DIGEST_CHECK`
    - **Default Value:** `0`
    - **Description:** Checks the digest used in TLS 1.0 PRF.

11. **sshkdf_digest_check**
    - **Macro:** `SSHKDF_DIGEST_CHECK`
    - **Default Value:** `0`
    - **Description:** Checks the digest used in SSH KDF.

12. **sskdf_digest_check**
    - **Macro:** `SSKDF_DIGEST_CHECK`
    - **Default Value:** `0`
    - **Description:** Checks the digest used in SSKDF.

13. **x963kdf_digest_check**
    - **Macro:** `X963KDF_DIGEST_CHECK`
    - **Default Value:** `0`
    - **Description:** Checks the digest used in X9.63 KDF.

14. **dsa_sign_disallowed**
    - **Macro:** `DSA_SIGN_DISABLED`
    - **Default Value:** `0`
    - **Description:** Disallows DSA signing.

15. **tdes_encrypt_disallowed**
    - **Macro:** `TDES_ENCRYPT_DISABLED`
    - **Default Value:** `0`
    - **Description:** Disallows TDES encryption.

16. **rsa_pkcs15_padding_disabled**
    - **Macro:** `RSA_PKCS15_PAD_DISABLED`
    - **Default Value:** `0`
    - **Description:** Disables RSA PKCS#15 padding.

17. **rsa_pss_saltlen_check**
    - **Macro:** `RSA_PSS_SALTLEN_CHECK`
    - **Default Value:** `0`
    - **Description:** Checks the salt length in RSA PSS.

18. **rsa_sign_x931_disallowed**
    - **Macro:** `RSA_SIGN_X931_PAD_DISABLED`
    - **Default Value:** `0`
    - **Description:** Disallows RSA signing with X9.31 padding.

19. **hkdf_key_check**
    - **Macro:** `HKDF_KEY_CHECK`
    - **Default Value:** `0`
    - **Description:** Checks the HKDF key.

20. **kbkdf_key_check**
    - **Macro:** `KBKDF_KEY_CHECK`
    - **Default Value:** `0`
    - **Description:** Checks the KBKDF key.

21. **tls13_kdf_key_check**
    - **Macro:** `TLS13_KDF_KEY_CHECK`
    - **Default Value:** `0`
    - **Description:** Checks the TLS 1.3 KDF key.

22. **tls1_prf_key_check**
    - **Macro:** `TLS1_PRF_KEY_CHECK`
    - **Default Value:** `0`
    - **Description:** Checks the TLS 1.0 PRF key.

23. **sshkdf_key_check**
    - **Macro:** `SSHKDF_KEY_CHECK`
    - **Default Value:** `0`
    - **Description:** Checks the SSH KDF key.

24. **sskdf_key_check**
    - **Macro:** `SSKDF_KEY_CHECK`
    - **Default Value:** `0`
    - **Description:** Checks the SSKDF key.

25. **x963kdf_key_check**
    - **Macro:** `X963KDF_KEY_CHECK`
    - **Default Value:** `0`
    - **Description:** Checks the X9.63 KDF key.

26. **x942kdf_key_check**
    - **Macro:** `X942KDF_KEY_CHECK`
    - **Default Value:** `0`
    - **Description:** Checks the X9.42 KDF key.

27. **pbkdf2_lower_bound_check**
    - **Macro:** `PBKDF2_LOWER_BOUND_CHECK`
    - **Default Value:** `1`
    - **Description:** Checks the lower bound for PBKDF2.

28. **ecdh_cofactor_check**
    - **Macro:** `ECDH_COFACTOR_CHECK`
    - **Default Value:** `0`
    - **Description:** Checks the ECDH cofactor.

These parameters are used to enforce various security policies and checks within the OpenSSL library, ensuring compliance with FIPS standards.