#
# OpenSSL/crypto/objects/Makefile
#


CFLAGS_crypto_objects= $(INCLUDES_crypto) $(CFLAG)

GENERAL_crypto_objects=crypto/objects/Makefile crypto/objects/README
TEST_crypto_objects=
APPS_crypto_objects=

LIB_crypto_objects=libcrypto.a
LIBSRC_crypto_objects=	crypto/objects/o_names.c crypto/objects/obj_dat.c crypto/objects/obj_lib.c crypto/objects/obj_err.c crypto/objects/obj_xref.c
LIBOBJ_crypto_objects= crypto/objects/o_names.o crypto/objects/obj_dat.o crypto/objects/obj_lib.o crypto/objects/obj_err.o crypto/objects/obj_xref.o

SRC_crypto_objects= $(LIBSRC_crypto_objects)

EXHEADER_crypto_objects= crypto/objects/objects.h crypto/objects/obj_mac.h
HEADER_crypto_objects=	$(EXHEADER_crypto_objects) crypto/objects/obj_dat.h crypto/objects/obj_xref.h

ALL_crypto_objects=    $(GENERAL_crypto_objects) $(SRC_crypto_objects) $(HEADER_crypto_objects)


all: all_crypto_objects
all_crypto_objects:crypto/objects/obj_dat.h crypto/objects/obj_xref.h 	$(LIBOBJ_crypto_objects)


crypto/objects/obj_dat.h: crypto/objects/obj_dat.pl crypto/objects/obj_mac.h
	$(PERL) crypto/objects/obj_dat.pl crypto/objects/obj_mac.h crypto/objects/obj_dat.h

# objects.pl both reads and writes obj_mac.num
crypto/objects/obj_mac.h: crypto/objects/objects.pl crypto/objects/objects.txt crypto/objects/obj_mac.num
	$(PERL) crypto/objects/objects.pl crypto/objects/objects.txt crypto/objects/obj_mac.num crypto/objects/obj_mac.h
	@sleep 1; touch crypto/objects/obj_mac.h; sleep 1

crypto/objects/obj_xref.h: crypto/objects/objxref.pl crypto/objects/obj_xref.txt crypto/objects/obj_mac.num
	$(PERL) crypto/objects/objxref.pl crypto/objects/obj_mac.num crypto/objects/obj_xref.txt > crypto/objects/obj_xref.h
	@sleep 1; touch crypto/objects/obj_xref.h; sleep 1

files: files_crypto_objects
files_crypto_objects:
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

links: links_crypto_objects
links_crypto_objects:
	@$(PERL) util/mklink.pl include/openssl $(EXHEADER_crypto_objects)
	@$(PERL) util/mklink.pl ./test $(TEST_crypto_objects)
	@$(PERL) util/mklink.pl ./apps $(APPS_crypto_objects)

install: install_crypto_objects
install_crypto_objects:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER_crypto_objects)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags: tags_crypto_objects
tags_crypto_objects:
	ctags $(SRC_crypto_objects)

tests: tests_crypto_objects
tests_crypto_objects:

lint: lint_crypto_objects
lint_crypto_objects:
	lint -DLINT $(INCLUDES_crypto) $(SRC_crypto_objects)>crypto/objects/fluff

dclean: dclean_crypto_objects
dclean_crypto_objects:

clean: clean_crypto_objects
clean_crypto_objects:
	rm -f crypto/objects/*.o crypto/objects/*.d crypto/objects/*.obj crypto/objects/lib crypto/objects/tags crypto/objects/core crypto/objects/.pure crypto/objects/.nfs* crypto/objects/*.old crypto/objects/*.bak crypto/objects/fluff

