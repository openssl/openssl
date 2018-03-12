AUTOMAKE_OPTIONS = foreign
noinst_LTLIBRARIES = libntru.la


libntru_la_SOURCES = kex_ntru.c \
	ntru_crypto_drbg.c \
	ntru_crypto_hash.c \
	ntru_crypto_hmac.c \
	ntru_crypto_msbyte_uint32.c \
	ntru_crypto_ntru_convert.c \
	ntru_crypto_ntru_encrypt.c \
	ntru_crypto_ntru_encrypt_key.c \
	ntru_crypto_ntru_encrypt_param_sets.c \
	ntru_crypto_ntru_mgf1.c \
	ntru_crypto_ntru_poly.c \
	ntru_crypto_sha256.c \
	ntru_crypto_sha1.c \
	ntru_crypto_sha2.c \
	ntru_crypto_ntru_mult_indices.c \
	ntru_crypto_ntru_mult_coeffs_karat.c


libntru_la_CPPFLAGS = -I../../include
libntru_la_CPPFLAGS += $(AM_CPPFLAGS) 

