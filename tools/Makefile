#
# OpenSSL/tools/Makefile
#

DIR_tools=	tools
INCLUDES_tools= -I$(TOP_tools) -I../include

CFLAGS_tools= $(INCLUDES_tools) $(CFLAG)

GENERAL_tools=Makefile
TEST_tools=
APPS_tools= c_rehash
MISC_APPS= c_hash c_info c_issuer c_name

all: all_tools
all_tools:

install: install_tools
install_tools:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@for i in $(APPS_tools) ; \
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
	$(PERL) $(TOP_tools)/util/files.pl TOP=$(TOP_tools) Makefile >> $(TOP_tools)/MINFO

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
	rm -f c_rehash

clean: clean_tools
clean_tools:
	rm -f *.o *.d *.obj lib tags core .pure .nfs* *.old *.bak fluff

.c.o:
	$(CC) $(CFLAGS_tools) $(CPPFLAGS) -c -o $@ $<
