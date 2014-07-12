#
# SSLeay/crypto/ts/Makefile
#

DIR_crypto_ts=	ts
INCLUDES_crypto_ts= -I.. -I../../include

 
CFLAGS_crypto_ts= $(INCLUDES_crypto_ts) $(CFLAG)

GENERAL_crypto_ts= Makefile
TEST_crypto_ts=
APPS_crypto_ts=

LIB_crypto_ts=$(TOP_crypto_ts)/libcrypto.a
LIBSRC_crypto_ts=	ts_err.c ts_req_utils.c ts_req_print.c ts_rsp_utils.c ts_rsp_print.c \
	ts_rsp_sign.c ts_rsp_verify.c ts_verify_ctx.c ts_lib.c ts_conf.c \
	ts_asn1.c
LIBOBJ_crypto_ts= ts_err.o ts_req_utils.o ts_req_print.o ts_rsp_utils.o ts_rsp_print.o \
	ts_rsp_sign.o ts_rsp_verify.o ts_verify_ctx.o ts_lib.o ts_conf.o \
	ts_asn1.o

SRC_crypto_ts= $(LIBSRC_crypto_ts)

EXHEADER_crypto_ts= ts.h
HEADER_crypto_ts=	$(EXHEADER_crypto_ts)

ALL_crypto_ts=    $(GENERAL_crypto_ts) $(SRC_crypto_ts) $(HEADER_crypto_ts)

top: top_crypto_ts
top_crypto_ts:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR_crypto_ts) sub_all)

test: test_crypto_ts
test_crypto_ts:

all: all_crypto_ts
all_crypto_ts:	lib

lib: lib_crypto_ts
lib_crypto_ts:	$(LIBOBJ_crypto_ts)
	$(ARX) $(LIB_crypto_ts) $(LIBOBJ_crypto_ts)
	$(RANLIB) $(LIB_crypto_ts) || echo Never mind.
	@touch lib

files: files_crypto_ts
files_crypto_ts:
	$(PERL) $(TOP_crypto_ts)/util/files.pl TOP=$(TOP_crypto_ts) Makefile >> $(TOP_crypto_ts)/MINFO

links: links_crypto_ts
links_crypto_ts:
	@$(PERL) $(TOP_crypto_ts)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_ts)
	@$(PERL) $(TOP_crypto_ts)/util/mklink.pl ../../test $(TEST_crypto_ts)
	@$(PERL) $(TOP_crypto_ts)/util/mklink.pl ../../apps $(APPS_crypto_ts)

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
	lint -DLINT $(INCLUDES_crypto_ts) $(SRC_crypto_ts)>fluff

dclean: dclean_crypto_ts
dclean_crypto_ts:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean: clean_crypto_ts
clean_crypto_ts:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff enc dec sign verify

.c.o:
	$(CC) $(CFLAGS_crypto_ts) $(CPPFLAGS) -c -o $@ $<
