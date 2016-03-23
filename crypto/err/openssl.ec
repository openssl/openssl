# crypto/err/openssl.ec

# configuration file for util/mkerr.pl

# files that may have to be rewritten by util/mkerr.pl
L ERR		NONE				NONE
L BN		include/openssl/bn.h		crypto/bn/bn_err.c
L RSA		include/openssl/rsa.h		crypto/rsa/rsa_err.c
L DH		include/openssl/dh.h		crypto/dh/dh_err.c
L EVP		include/openssl/evp.h		crypto/evp/evp_err.c
L BUF		include/openssl/buffer.h	crypto/buffer/buf_err.c
L OBJ		include/openssl/objects.h	crypto/objects/obj_err.c
L PEM		include/openssl/pem.h		crypto/pem/pem_err.c
L DSA		include/openssl/dsa.h		crypto/dsa/dsa_err.c
L X509		include/openssl/x509.h		crypto/x509/x509_err.c
L ASN1		include/openssl/asn1.h		crypto/asn1/asn1_err.c
L CONF		include/openssl/conf.h		crypto/conf/conf_err.c
L CRYPTO	include/openssl/crypto.h	crypto/cpt_err.c
L EC		include/openssl/ec.h		crypto/ec/ec_err.c
L SSL		include/openssl/ssl.h		ssl/ssl_err.c
L BIO		include/openssl/bio.h		crypto/bio/bio_err.c
L PKCS7		include/openssl/pkcs7.h		crypto/pkcs7/pkcs7err.c
L X509V3	include/openssl/x509v3.h	crypto/x509v3/v3err.c
L PKCS12	include/openssl/pkcs12.h	crypto/pkcs12/pk12err.c
L RAND		include/openssl/rand.h		crypto/rand/rand_err.c
L DSO		include/internal/dso.h		crypto/dso/dso_err.c
L ENGINE	include/openssl/engine.h	crypto/engine/eng_err.c
L OCSP		include/openssl/ocsp.h		crypto/ocsp/ocsp_err.c
L UI		include/openssl/ui.h		crypto/ui/ui_err.c
L COMP		include/openssl/comp.h		crypto/comp/comp_err.c
L STORE		include/openssl/store.h		crypto/store/str_err.c
L TS		include/openssl/ts.h		crypto/ts/ts_err.c
L HMAC		include/openssl/hmac.h		crypto/hmac/hmac_err.c
L CMS		include/openssl/cms.h		crypto/cms/cms_err.c
L FIPS		include/openssl/fips.h		crypto/fips_err.h
L CT		include/openssl/ct.h		crypto/ct/ct_err.c
L ASYNC		include/openssl/async.h		crypto/async/async_err.c
L KDF		include/openssl/kdf.h		crypto/kdf/kdf_err.c

# additional header files to be scanned for function names
L NONE		crypto/x509/x509_vfy.h		NONE
L NONE		crypto/ec/ec_lcl.h		NONE
L NONE		crypto/asn1/asn_lcl.h		NONE
L NONE		crypto/cms/cms_lcl.h		NONE
L NONE		crypto/ct/ct_locl.h		NONE
L NONE		fips/rand/fips_rand.h		NONE
L NONE		ssl/ssl_locl.h			NONE

F RSAREF_F_RSA_BN2BIN
F RSAREF_F_RSA_PRIVATE_DECRYPT
F RSAREF_F_RSA_PRIVATE_ENCRYPT
F RSAREF_F_RSA_PUBLIC_DECRYPT
F RSAREF_F_RSA_PUBLIC_ENCRYPT

R RSAREF_R_CONTENT_ENCODING			0x0400
R RSAREF_R_DATA					0x0401
R RSAREF_R_DIGEST_ALGORITHM			0x0402
R RSAREF_R_ENCODING				0x0403
R RSAREF_R_KEY					0x0404
R RSAREF_R_KEY_ENCODING				0x0405
R RSAREF_R_LEN					0x0406
R RSAREF_R_MODULUS_LEN				0x0407
R RSAREF_R_NEED_RANDOM				0x0408
R RSAREF_R_PRIVATE_KEY				0x0409
R RSAREF_R_PUBLIC_KEY				0x040a
R RSAREF_R_SIGNATURE				0x040b
R RSAREF_R_SIGNATURE_ENCODING			0x040c
R RSAREF_R_ENCRYPTION_ALGORITHM			0x040d

