# Makefile for easy-tls example application (rudimentary client and server)
# $Id: Makefile,v 1.2 2001/09/18 09:15:40 bodo Exp $

SOLARIS_CFLAGS=-Wall -pedantic -g -O2
SOLARIS_LIBS=-lxnet

LINUX_CFLAGS=-Wall -pedantic -g -O2
LINUX_LIBS=


demos/easy_tls/auto-all:
	case `uname -s` in \
	SunOS) echo Using SunOS configuration; \
	  make SYSCFLAGS="$(SOLARIS_CFLAGS)" SYSLIBS="$(SOLARIS_LIBS)" demos/easy_tls/all;; \
	Linux) echo Using Linux configuration; \
	  make SYSCFLAGS="$(LINUX_CFLAGS)" SYSLIBS="$(LINUX_LIBS)" demos/easy_tls/all;; \
	*) echo "unknown system"; exit 1;; \
	esac

all: all_demos_easy_tls
all_demos_easy_tls: test_demos_easy_tls demos/easy_tls/TAGS

# For adapting this Makefile to a different system, only the following
# definitions should need customizing:


SYSCFLAGS=whatever
SYSLIBS=whatever


#############################################################################
#
# SSLeay/OpenSSL imports
#
# OPENSSLDIR (set above) can be either the directory where OpenSSL is
# installed or the directory where it was compiled.

# We rely on having a new OpenSSL release where include files
# have names like <openssl/ssl.h> (not just <ssl.h>).
OPENSSLINCLUDES=-I$(OPENSSLDIR)/include

# libcrypto.a and libssl.a are directly in $(OPENSSLDIR) if this is
# the compile directory, or in $(OPENSSLDIR)/lib if we use an installed
# library.  With the following definition, we can handle either case.
OPENSSLLIBS=-L$(OPENSSLDIR) -L$(OPENSSLDIR)/lib -lssl -lcrypto


#############################################################################
#
# Stuff for handling the source files
#

SOURCES=easy-tls.c test.c
HEADERS=demos/easy_tls/easy-tls.h demos/easy_tls/test.h
DOCSandEXAMPLESetc=Makefile cert.pem cacerts.pem
EVERYTHING=$(SOURCES) $(HEADERS) $(DOCSandEXAMPLESetc)

demos/easy_tls/ls: demos/easy_tls/ls-l
demos/easy_tls/ls-l:
	demos/easy_tls/ls -l $(EVERYTHING)
# For RCS:
demos/easy_tls/tag:
	-rcs -n_`date +%y%m%d`: $(EVERYTHING)
	rcs -nMYTAG $(EVERYTHING)
	rcs -nMYTAG: $(EVERYTHING)
demos/easy_tls/diff:
	-rcsdiff -rMYTAG -u $(EVERYTHING)
demos/easy_tls/today:
	-rcsdiff -r_`date +%y%m%d` -u $(EVERYTHING)
demos/easy_tls/ident:
	for a in $(EVERYTHING); do demos/easy_tls/ident $$a; done

# Distribution .tar:
demos/easy_tls/easy-tls.tar.gz: $(EVERYTHING)
	tar cvf - $(EVERYTHING) | \
	gzip -9 > demos/easy_tls/easy-tls.tar.gz

# Working .tar:
demos/easy_tls/tls.tgz: $(EVERYTHING)
	tar cfv - `find . -type f -a ! -name '*.tgz' -a ! -name '*.tar.gz'` | \
	gzip -9 > demos/easy_tls/tls.tgz

# For emacs:
demos/easy_tls/etags: demos/easy_tls/TAGS
demos/easy_tls/TAGS: $(SOURCES) $(HEADERS)
	-etags $(SOURCES) $(HEADERS)


#############################################################################
#
# Compilation
#
# The following definitions are system dependent (and hence defined
# at the beginning of this Makefile, where they are more easily found):

### CC=gcc
### SYSCFLAGS=-Wall -pedantic -g -O2
### SYSLIBS=-lxnet

EXTRACFLAGS=-DTLS_APP=\"test.h\"
# EXTRACFLAGS=-DTLS_APP=\"test.h\" -DDEBUG_TLS

#
# The rest shouldn't need to be touched.
#
LDFLAGS_demos_easy_tls=$(SYSLIBS) $(OPENSSLLIBS)
INCLUDES_demos_easy_tls=$(OPENSSLINCLUDES)
CFLAGS_demos_easy_tls=$(SYSCFLAGS) $(EXTRACFLAGS) $(INCLUDES_demos_easy_tls)

OBJS_demos_easy_tls=demos/easy_tls/easy-tls.o demos/easy_tls/test.o

clean: clean_demos_easy_tls
clean_demos_easy_tls:
	demos/easy_tls/@rm -f test
	demos/easy_tls/@rm -f demos/easy_tls/TAGS
	demos/easy_tls/@rm -f demos/easy_tls/*.o
	demos/easy_tls/@rm -f demos/easy_tls/core

test: test_demos_easy_tls
test_demos_easy_tls: $(OBJS_demos_easy_tls)
	$(CC) $(OBJS_demos_easy_tls) $(LDFLAGS_demos_easy_tls) -o test

demos/easy_tls/test.o: $(HEADERS)
demos/easy_tls/easy-tls.o: $(HEADERS)

.c.o:
	$(CC) $(CFLAGS_demos_easy_tls) $(CPPFLAGS) -c -o $@ $<
