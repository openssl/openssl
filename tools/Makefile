#
# OpenSSL/tools/Makefile
#

INCLUDES_tools= -I. -Iinclude

CFLAGS_tools= $(INCLUDES_tools) $(CFLAG)

GENERAL_tools=tools/Makefile
TEST_tools=
APPS_tools= tools/c_rehash
MISC_APPS= tools/c_hash tools/c_info tools/c_issuer tools/c_name

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
	$(PERL) util/files.pl TOP=. Makefile >> MINFO

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
	rm -f tools/c_rehash

clean: clean_tools
clean_tools:
	rm -f tools/*.o tools/*.d tools/*.obj tools/lib tools/tags tools/core tools/.pure tools/.nfs* tools/*.old tools/*.bak tools/fluff

.c.o:
	$(CC) $(CFLAGS_tools) $(CPPFLAGS) -c -o $@ $<
