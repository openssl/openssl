AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I config

# DOXYGEN SUPPORT
include aminclude.am

# ensure the distribution of the doxygen configuration file
EXTRA_DIST = doxygen.cfg

CLANGFORMAT ?= clang-format-3.9

SUBDIRS = ${SRCDIR}

BUILT_SOURCES = links
lib_LTLIBRARIES = liboqs.la
liboqs_la_SOURCES =
liboqs_la_LIBADD =  src/common/libcommon.la
liboqs_la_LIBADD += src/crypto/aes/libaes.la
liboqs_la_LIBADD += src/crypto/rand/librand.la
liboqs_la_LIBADD += src/crypto/rand_urandom_aesctr/librandaesctr.la
liboqs_la_LIBADD += src/crypto/rand_urandom_chacha20/librandchacha20.la
liboqs_la_LIBADD += src/crypto/sha3/libsha3.la
liboqs_la_LIBADD += src/kex/libkex.la
if USE_KEX_LWE_FRODO
liboqs_la_LIBADD += src/kex_lwe_frodo/libfrodo.la
endif
if USE_KEX_MLWE_KYBER
liboqs_la_LIBADD += src/kex_mlwe_kyber/libkyber.la
endif
if USE_KEX_NTRU
liboqs_la_LIBADD += src/kex_ntru/libntru.la
endif
liboqs_la_LIBADD += src/kex_rlwe_bcns15/libbcns15.la
if USE_KEX_RLWE_MSRLN16
liboqs_la_LIBADD += src/kex_rlwe_msrln16/libmsrln16.la
endif
if USE_KEX_RLWE_NEWHOPE
liboqs_la_LIBADD += src/kex_rlwe_newhope/libnewhope.la
endif
if USE_KEX_SIDH_CLN16
liboqs_la_LIBADD += src/kex_sidh_cln16/libcln16.la
endif

liboqs_la_LIBADD += src/sig/libsig.la

if USE_MCBITS
liboqs_la_LIBADD += src/kex_code_mcbits/libmcbits.la
endif
if USE_SIDH_IQC
liboqs_la_LIBADD += src/kex_sidh_iqc_ref/libsidhiqc.la
endif

if USE_PICNIC
liboqs_la_LIBADD += src/sig_picnic/libpicnic.la
endif

noinst_bin_PROGRAMS = test_rand test_kex test_aes

if USE_PICNIC
if USE_OPENSSL
noinst_bin_PROGRAMS += pp_matrices test_sig
endif
endif

noinst_bindir=$(prefix)/tests
test_kex_LDADD =  liboqs.la -lm
test_kex_SOURCES = src/kex/test_kex.c
test_kex_CPPFLAGS = -I./include
test_kex_CPPFLAGS += $(AM_CPPFLAGS)
if USE_MCBITS
test_kex_LDADD += -L${SODIUM_DIR}/lib -lsodium
endif
if USE_OPENSSL
test_kex_LDADD += -L$(OPENSSL_DIR)/lib -lcrypto
endif
if USE_SIDH_IQC
test_kex_LDADD += -L$(GMP_DIR)/lib -lgmp
endif

if USE_PICNIC
if USE_OPENSSL
test_sig_LDADD =  liboqs.la -lm
test_sig_SOURCES = src/sig/test_sig.c
test_sig_CPPFLAGS = -I${OPENSSL_DIR}/include -I./include
test_sig_CPPFLAGS += $(AM_CPPFLAGS)
test_sig_LDADD += -L${OPENSSL_DIR}/lib -lssl -lcrypto

pp_matrices_LDADD =  liboqs.la -lm
pp_matrices_SOURCES = src/sig_picnic/external/Picnic-master/preprocessMatrices.c
pp_matrices_CPPFLAGS = -std=c99 -I${OPENSSL_DIR}/include -I${M4RI_DIR}/include/m4ri -I./include
#pp_matrices_CPPFLAGS += $(AM_CPPFLAGS)
pp_matrices_LDADD += -L${OPENSSL_DIR}/lib -L${M4RI_DIR}/lib -lssl -lcrypto -lm4ri
endif
endif

test_aes_LDADD =  liboqs.la -lm
test_aes_SOURCES = src/crypto/aes/test_aes.c
test_aes_CPPFLAGS = -I./include
test_aes_CPPFLAGS += $(AM_CPPFLAGS)

if USE_OPENSSL
test_aes_LDADD += -L$(OPENSSL_DIR)/lib -lcrypto
endif

test_rand_SOURCES = src/crypto/rand/test_rand.c

test_rand_CPPFLAGS = -Iinclude -Isrc/crypto/rand_urandom_aesctr/
test_rand_CPPFLAGS += $(AM_CPPFLAGS)
test_rand_LDADD = liboqs.la
if USE_OPENSSL
test_rand_LDADD += -L$(OPENSSL_DIR)/lib -lcrypto
else
if USE_AES_NI
test_rand_CPPFLAGS += -maes -msse2
endif
endif

test: clean-tests
	make
	./test_kex --quiet
	./test_rand --quiet
	./test_aes
if USE_PICNIC
if USE_OPENSSL
	mkdir -p precomputed_data
	./pp_matrices
	./test_sig
endif
endif


links:
	$(MKDIR_P) include/oqs
	cp -f src/common/common.h include/oqs
	cp -f src/crypto/aes/aes.h include/oqs
	cp -f src/crypto/rand/rand.h include/oqs
	cp -f src/crypto/rand_urandom_aesctr/rand_urandom_aesctr.h include/oqs
	cp -f src/crypto/rand_urandom_chacha20/rand_urandom_chacha20.h include/oqs
	cp -f src/crypto/sha3/sha3.h include/oqs
	cp -f src/kex/kex.h include/oqs
	cp -f src/kex_lwe_frodo/kex_lwe_frodo.h include/oqs
	cp -f src/kex_mlwe_kyber/kex_mlwe_kyber.h include/oqs
	cp -f src/kex_ntru/kex_ntru.h include/oqs
	cp -f src/kex_rlwe_bcns15/kex_rlwe_bcns15.h include/oqs
	cp -f src/kex_rlwe_msrln16/kex_rlwe_msrln16.h include/oqs
	cp -f src/kex_rlwe_newhope/kex_rlwe_newhope.h include/oqs
	cp -f src/kex_sidh_cln16/kex_sidh_cln16.h include/oqs
	cp -f src/kex_mlwe_kyber/kex_mlwe_kyber.h include/oqs
	cp -f src/sig/sig.h include/oqs
if USE_PICNIC
if USE_OPENSSL
	cp -f src/sig_picnic/external/Picnic-master/picnic.h include/oqs
endif
endif
	$(LN_S) -f .libs/liboqs.a
if USE_MCBITS
	cp -f src/kex_code_mcbits/kex_code_mcbits.h include/oqs
endif
if USE_SIDH_IQC
	cp -f src/kex_sidh_iqc_ref/kex_sidh_iqc_ref.h include/oqs
	$(LN_S) -f src/kex_sidh_iqc_ref/sample_params
endif
if USE_PICNIC
	$(LN_S) -f ../../src/sig_picnic/sig_picnic.h include/oqs
endif

clean-local:
	rm -f liboqs.a
	rm -rf include
if USE_SIDH_IQC
	rm -f sample_params
endif
clean-tests:
	rm -f test_kex test_rand test_aes
if USE_PICNIC
if USE_OPENSSL
	rm -f test_sig
	rm -f pp_matrices
	rm -rf precomputed_data
endif
endif

prettyprint:
	find src -name '*.c' -o -name '*.h' | grep -v Picnic*| xargs $(CLANGFORMAT) -style=file -i

docs: links
	doxygen
