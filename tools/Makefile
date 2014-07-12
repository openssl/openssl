#
# OpenSSL/tools/Makefile
#

DIR=	tools
INCLUDES= -I$(TOP) -I../../include

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=
APPS= c_rehash
MISC_APPS= c_hash c_info c_issuer c_name

all: all_tools
all_tools:

install: install_tools
install_tools:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@for i in $(APPS) ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new; \
	chmod 755 $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new; \
	mv -f $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i ); \
	done;
	@for i in $(MISC_APPS) ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i.new; \
	chmod 755 $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i.new; \
	mv -f $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i.new $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i ); \
	done;

files: files_tools
files_tools:
	$(PERL) $(TOP)/util/files.pl TOP=$(TOP) Makefile >> $(TOP)/MINFO

links: links_tools
links_tools:

lint: lint_tools
lint_tools:

tags: tags_tools
tags_tools:

errors: errors_tools
errors_tools:

dclean: dclean_tools
dclean_tools:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)
	rm -f c_rehash

clean: clean_tools
clean_tools:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff
