include $(top_srcdir)/Makefile.am.common

bin_PROGRAMS = openssl

openssl_CFLAGS = $(USER_CFLAGS)
openssl_LDADD = $(PLATFORM_LDADD)
openssl_LDADD += $(top_builddir)/crypto/libcrypto.la
openssl_LDADD += $(top_builddir)/ssl/libssl.la

openssl_SOURCES =
noinst_HEADERS =

if NO_STRTONUM
openssl_SOURCES += strtonum.c
endif
openssl_SOURCES += apps.c
openssl_SOURCES += asn1pars.c
openssl_SOURCES += ca.c
openssl_SOURCES += ciphers.c
openssl_SOURCES += cms.c
openssl_SOURCES += crl.c
openssl_SOURCES += crl2p7.c
openssl_SOURCES += dgst.c
openssl_SOURCES += dh.c
openssl_SOURCES += dhparam.c
openssl_SOURCES += dsa.c
openssl_SOURCES += dsaparam.c
openssl_SOURCES += ec.c
openssl_SOURCES += ecparam.c
openssl_SOURCES += enc.c
openssl_SOURCES += engine.c
openssl_SOURCES += errstr.c
openssl_SOURCES += gendh.c
openssl_SOURCES += gendsa.c
openssl_SOURCES += genpkey.c
openssl_SOURCES += genrsa.c
openssl_SOURCES += nseq.c
openssl_SOURCES += ocsp.c
openssl_SOURCES += openssl.c
openssl_SOURCES += passwd.c
openssl_SOURCES += pkcs12.c
openssl_SOURCES += pkcs7.c
openssl_SOURCES += pkcs8.c
openssl_SOURCES += pkey.c
openssl_SOURCES += pkeyparam.c
openssl_SOURCES += pkeyutl.c
openssl_SOURCES += prime.c
openssl_SOURCES += rand.c
openssl_SOURCES += req.c
openssl_SOURCES += rsa.c
openssl_SOURCES += rsautl.c
openssl_SOURCES += s_cb.c
openssl_SOURCES += s_client.c
openssl_SOURCES += s_server.c
openssl_SOURCES += s_socket.c
openssl_SOURCES += s_time.c
openssl_SOURCES += sess_id.c
openssl_SOURCES += smime.c
openssl_SOURCES += speed.c
openssl_SOURCES += spkac.c
openssl_SOURCES += ts.c
openssl_SOURCES += verify.c
openssl_SOURCES += version.c
openssl_SOURCES += x509.c
noinst_HEADERS += apps.h
noinst_HEADERS += progs.h
noinst_HEADERS += s_apps.h
noinst_HEADERS += testdsa.h
noinst_HEADERS += testrsa.h
noinst_HEADERS += timeouts.h
