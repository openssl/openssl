/*
 * Handles the loading of FIPS algorithm conditional options from a config file
 * passed from the core using OSSL_PARAM.
 *
 * The following lines are of the form:
 *   OSSL_FIPS_PARAM(security_checks, SECURITY_CHECKS, 1)
 *
 * The first parameter is used to create a function of the form:
 *   int ossl_fips_config_security_checks(OSSL_LIB_CTX *libctx)
 * that can be accessed by FIPS algorithms to tell if an option is enabled.
 * The function returns 1 if enabled or 0 otherwise.
 *
 * The second parameter is converted to OSSL_PROV_PARAM_SECURITY_CHECKS and is used
 * to optionally retrieve a FIPS module configuration option using an OSSL_PARAM
 * from the core. If the option is not available then the third parameter is
 * used as the default value. (which is 1 in this case).
 * NOTE: fipsinstall.c uses the OSSL_PROV_PARAM_SECURITY_CHECKS value.
 *
 * These options are used to either cause an error when a FIPS related check fails,
 * or flag that the check failed using a FIPS indicator.
 * See L<fips_module(7)/FIPS indicators for further information.
 */
OSSL_FIPS_PARAM(security_checks, SECURITY_CHECKS, 1)
OSSL_FIPS_PARAM(tls1_prf_ems_check, TLS1_PRF_EMS_CHECK, 0)
OSSL_FIPS_PARAM(no_short_mac, NO_SHORT_MAC, 1)
OSSL_FIPS_PARAM(hmac_key_check, HMAC_KEY_CHECK, 0)
OSSL_FIPS_PARAM(kmac_key_check, KMAC_KEY_CHECK, 0)
OSSL_FIPS_PARAM(restricted_drbg_digests, DRBG_TRUNC_DIGEST, 0)
OSSL_FIPS_PARAM(signature_digest_check, SIGNATURE_DIGEST_CHECK, 0)
OSSL_FIPS_PARAM(hkdf_digest_check, HKDF_DIGEST_CHECK, 0)
OSSL_FIPS_PARAM(tls13_kdf_digest_check, TLS13_KDF_DIGEST_CHECK, 0)
OSSL_FIPS_PARAM(tls1_prf_digest_check, TLS1_PRF_DIGEST_CHECK, 0)
OSSL_FIPS_PARAM(sshkdf_digest_check, SSHKDF_DIGEST_CHECK, 0)
OSSL_FIPS_PARAM(sskdf_digest_check, SSKDF_DIGEST_CHECK, 0)
OSSL_FIPS_PARAM(x963kdf_digest_check, X963KDF_DIGEST_CHECK, 0)
OSSL_FIPS_PARAM(dsa_sign_disallowed, DSA_SIGN_DISABLED, 0)
OSSL_FIPS_PARAM(tdes_encrypt_disallowed, TDES_ENCRYPT_DISABLED, 0)
OSSL_FIPS_PARAM(rsa_pkcs15_padding_disabled, RSA_PKCS15_PAD_DISABLED, 0)
OSSL_FIPS_PARAM(rsa_pss_saltlen_check, RSA_PSS_SALTLEN_CHECK, 0)
OSSL_FIPS_PARAM(rsa_sign_x931_disallowed, RSA_SIGN_X931_PAD_DISABLED, 0)
OSSL_FIPS_PARAM(hkdf_key_check, HKDF_KEY_CHECK, 0)
OSSL_FIPS_PARAM(kbkdf_key_check, KBKDF_KEY_CHECK, 0)
OSSL_FIPS_PARAM(tls13_kdf_key_check, TLS13_KDF_KEY_CHECK, 0)
OSSL_FIPS_PARAM(tls1_prf_key_check, TLS1_PRF_KEY_CHECK, 0)
OSSL_FIPS_PARAM(sshkdf_key_check, SSHKDF_KEY_CHECK, 0)
OSSL_FIPS_PARAM(sskdf_key_check, SSKDF_KEY_CHECK, 0)
OSSL_FIPS_PARAM(x963kdf_key_check, X963KDF_KEY_CHECK, 0)
OSSL_FIPS_PARAM(x942kdf_key_check, X942KDF_KEY_CHECK, 0)
OSSL_FIPS_PARAM(pbkdf2_lower_bound_check, PBKDF2_LOWER_BOUND_CHECK, 1)
OSSL_FIPS_PARAM(ecdh_cofactor_check, ECDH_COFACTOR_CHECK, 0)
