#
# SSLeay/crypto/ts/Makefile
#


 
CFLAGS_crypto_ts= $(INCLUDES_crypto) $(CFLAG)

GENERAL_crypto_ts= crypto/ts/Makefile
TEST_crypto_ts=
APPS_crypto_ts=

LIB_crypto_ts=libcrypto.a
LIBSRC_crypto_ts=	crypto/ts/ts_err.c crypto/ts/ts_req_utils.c crypto/ts/ts_req_print.c crypto/ts/ts_rsp_utils.c crypto/ts/ts_rsp_print.c \
	crypto/ts/ts_rsp_sign.c crypto/ts/ts_rsp_verify.c crypto/ts/ts_verify_ctx.c crypto/ts/ts_lib.c crypto/ts/ts_conf.c \
	crypto/ts/ts_asn1.c
LIBOBJ_crypto_ts= crypto/ts/ts_err.o crypto/ts/ts_req_utils.o crypto/ts/ts_req_print.o crypto/ts/ts_rsp_utils.o crypto/ts/ts_rsp_print.o \
	crypto/ts/ts_rsp_sign.o crypto/ts/ts_rsp_verify.o crypto/ts/ts_verify_ctx.o crypto/ts/ts_lib.o crypto/ts/ts_conf.o \
	crypto/ts/ts_asn1.o

SRC_crypto_ts= $(LIBSRC_crypto_ts)

EXHEADER_crypto_ts= crypto/ts/ts.h
HEADER_crypto_ts=	$(EXHEADER_crypto_ts)

ALL_crypto_ts=    $(GENERAL_crypto_ts) $(SRC_crypto_ts) $(HEADER_crypto_ts)


test: test_crypto_ts
test_crypto_ts:

all: all_crypto_ts
all_crypto_ts:	crypto/ts/lib

crypto/ts/lib:	$(LIBOBJ_crypto_ts)
	$(ARX) $(LIB_crypto_ts) $(LIBOBJ_crypto_ts)
	$(RANLIB) $(LIB_crypto_ts) || echo Never mind.
	@touch crypto/ts/lib

files: files_crypto_ts
files_crypto_ts:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_ts
links_crypto_ts:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_ts)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_ts)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_ts)

install: install_crypto_ts
install_crypto_ts:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_ts)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_ts
tags_crypto_ts:
	ctags $(SRC_crypto_ts)

lint: lint_crypto_ts
lint_crypto_ts:
	lint -DLINT $(INCLUDES_crypto) $(SRC_crypto_ts)>crypto/ts/fluff

dclean: dclean_crypto_ts
dclean_crypto_ts:

clean: clean_crypto_ts
clean_crypto_ts:
	rm -f crypto/ts/*.o crypto/ts/*.d crypto/ts/*.obj crypto/ts/lib crypto/ts/tags crypto/ts/core crypto/ts/.pure crypto/ts/.nfs* crypto/ts/*.old crypto/ts/*.bak crypto/ts/fluff crypto/ts/enc crypto/ts/dec crypto/ts/sign crypto/ts/verify

