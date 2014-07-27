#
# OpenSSL/crypto/objects/Makefile
#

INCLUDES_crypto_objects= -I.. -I$(TOP_crypto_objects) -I../../include

CFLAGS_crypto_objects= $(INCLUDES_crypto_objects) $(CFLAG)

GENERAL_crypto_objects=Makefile README
TEST_crypto_objects=
APPS_crypto_objects=

LIB_crypto_objects=$(TOP_crypto_objects)/libcrypto.a
LIBSRC_crypto_objects=	o_names.c obj_dat.c obj_lib.c obj_err.c obj_xref.c
LIBOBJ_crypto_objects= o_names.o obj_dat.o obj_lib.o obj_err.o obj_xref.o

SRC_crypto_objects= $(LIBSRC_crypto_objects)

EXHEADER_crypto_objects= objects.h obj_mac.h
HEADER_crypto_objects=	$(EXHEADER_crypto_objects) obj_dat.h obj_xref.h

ALL_crypto_objects=    $(GENERAL_crypto_objects) $(SRC_crypto_objects) $(HEADER_crypto_objects)


all: all_crypto_objects
all_crypto_objects:	obj_dat.h obj_xref.h lib

lib:	$(LIBOBJ_crypto_objects)
	$(ARX) $(LIB_crypto_objects) $(LIBOBJ_crypto_objects)
	$(RANLIB) $(LIB_crypto_objects) || echo Never mind.
	@touch lib

obj_dat.h: obj_dat.pl obj_mac.h
	$(PERL) obj_dat.pl obj_mac.h obj_dat.h

# objects.pl both reads and writes obj_mac.num
obj_mac.h: objects.pl objects.txt obj_mac.num
	$(PERL) objects.pl objects.txt obj_mac.num obj_mac.h
	@sleep 1; touch obj_mac.h; sleep 1

obj_xref.h: objxref.pl obj_xref.txt obj_mac.num
	$(PERL) objxref.pl obj_mac.num obj_xref.txt > obj_xref.h
	@sleep 1; touch obj_xref.h; sleep 1

files: files_crypto_objects
files_crypto_objects:
	$(PERL) $(TOP_crypto_objects)/util/files.pl TOP=$(TOP_crypto_objects) Makefile >> $(TOP_crypto_objects)/MINFO

links: links_crypto_objects
links_crypto_objects:
	@$(PERL) $(TOP_crypto_objects)/util/mklink.pl ../../include/openssl $(EXHEADER_crypto_objects)
	@$(PERL) $(TOP_crypto_objects)/util/mklink.pl ../../test $(TEST_crypto_objects)
	@$(PERL) $(TOP_crypto_objects)/util/mklink.pl ../../apps $(APPS_crypto_objects)

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
	lint -DLINT $(INCLUDES_crypto_objects) $(SRC_crypto_objects)>fluff

dclean: dclean_crypto_objects
dclean_crypto_objects:

clean: clean_crypto_objects
clean_crypto_objects:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_crypto_objects) $(CPPFLAGS) -c -o $@ $<
