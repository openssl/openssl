# OPENSSL_DIR is a root directory of openssl sources
THISDIR?=$(shell perl -MCwd -e 'print getcwd')
OPENSSL_DIR?=$(THISDIR)/../openssl
ENGINE_ID?=gost
TESTSUITE_DIR?=$(THISDIR)/test-suite
FOR?=$(HOST)
CC=gcc
CFLAGS=-fPIC -g -Wall -I$(OPENSSL_DIR)/include
LDFLAGS=-g -L $(OPENSSL_DIR) -static-libgcc
ifeq "$(FOR)" "s64"
CFLAGS+=-m64
LDFLAGS+=-m64
endif
OS:=$(shell uname -s)
ifeq "$(OS)" "FreeBSD" 
LIBDIR:=$(shell LD_LIBRARY_PATH=$(OPENSSL_DIR) $(OPENSSL_DIR)/apps/openssl version -d|sed -e 's/^[^"]*"//' -e 's/".*$$//')/lib
LDFLAGS+=-rpath $(LIBDIR)
endif


ifeq "$(FOR)" "w32"
ENGINE_LIB?=$(ENGINE_ID)$(DLLSUFFIX)
DLLSUFFIX=.dll
EXESUFFIX=.exe
CFLAGS+=-mno-cygwin
LDFLAGS+=-mno-cygwin
ifeq "$(OS)" "Linux"
CC=i586-mingw32msvc-gcc
endif
LIBS=-lcrypto.dll 
else
ENGINE_LIB?=lib$(ENGINE_ID)$(DLLSUFFIX)
LIBS=-lcrypto 
DLLSUFFIX=.so
endif
export DLLSUFFIX
export EXESUFFIX
ifneq "$(FOR)" ""
export FOR
endif
CFLAGS+=$(DEBUG_FLAGS)
export ENGINE_LIB
ENG_SOURCES=md_gost.c  gost_crypt.c  gost_asn1.c ameth.c pmeth.c\
	gost_crypt.c gost_sign.c gost2001.c md_gost.c gost_crypt.c\
	engine.c gost94_keyx.c keywrap.c gost2001_keyx.c
all: $(ENGINE_LIB) openssl.cnf
buildtests:
$(ENGINE_LIB): e_gost_err.o engine.o ameth.o pmeth.o params.o md_gost.o gosthash.o gost89.o gost_sign.o gost_crypt.o  keywrap.o  gost2001.o gost94_keyx.o gost2001_keyx.o gost_asn1.o
	$(CC) $(LDFLAGS) -shared -o $@ $+ $(LIBS) $(LDFLAGS)
openssl.cnf: openssl.cnf.1 openssl.cnf.2
	cat $+ > $@
openssl.cnf.1:
	echo "openssl_conf = openssl_def" > $@
openssl.cnf.2:
	echo "[openssl_def]" > $@
	echo "engines = engine_section" >> $@
	echo "[engine_section]" >> $@
	echo "$(ENGINE_ID) = $(ENGINE_ID)_section" >> $@
	echo "[$(ENGINE_ID)_section]" >> $@
	echo "dynamic_path = $(THISDIR)/$(ENGINE_LIB)" >> $@
	echo "engine_id = $(ENGINE_ID)" >> $@
	echo "default_algorithms = ALL" >> $@
gosthash1.o: gosthash.c
	$(CC) -c $(CFLAGS) -o $@ -DOPENSSL_BUILD $+
gostsum: gostsum.o gosthash.o gost89.o
inttests: gosttest$(EXESUFFIX) etalon wraptest$(EXESUFFIX) etalon.wrap ectest$(EXESUFFIX) etalon.ec
	./gosttest${EXESUFFIX} > gost_test
	diff -uw gost_test etalon
	./wraptest$(EXESUFFIX) > wrap_test
	diff -uw wrap_test etalon.wrap
	./ectest$(EXESUFFIX) > ec_test 2>&1
	diff -uw ec_test etalon.ec
ectest$(EXESUFFIX): ectest.o gost2001_dbg.o gost_sign_dbg.o params.o e_gost_err.o
	$(CC) -o $@ $(LDFLAGS) $+ -lcrypto 
%_dbg.o: %.c	
	$(CC) -c $(CFLAGS) -DDEBUG_SIGN -DDEBUG_KEYS -o $@ $+
gosttest$(EXESUFFIX): gosttest.o gosthash.o gost89.o
	$(CC) $(LDFLAGS) -o $@ $+
wraptest$(EXESUFFIX): wraptest.c keywrap.c gost89.c 	
	$(CC) -DDEBUG_DH $(LDFLAGS) -o $@ $+
sign_ex: LOADLIBES=-lcrypto
sign_ex: sign_ex.o
clean:
	rm -f core gosttest gostsum *.o gost_test openssl.cnf* $(ENGINE_LIB)
	if [ -f t/Makefile ]; then $(MAKE) -C t clean; fi
	if [ -f $(TESTSUITE_DIR)/Makefile ]; then $(MAKE) -C $(TESTSUITE_DIR) clean; fi
e_gost_err.c e_gost_err.h: $(ENG_SOURCES) gost.ec e_gost_err.proto
	perl $(OPENSSL_DIR)/util/mkerr.pl -conf gost.ec -nostatic -debug -write $(ENG_SOURCES)

tests: openssl.cnf.2
	OPENSSL_DIR=$(OPENSSL_DIR) $(MAKE) -C $(TESTSUITE_DIR) CONFADD=$(THISDIR)/openssl.cnf.2

# depedencies
#
#
gost_sign.o: gost_sign.c sign.h paramset.h tools.h e_gost_err.h

pmeth.o: pmeth.c meth.h pmeth.h sign.h paramset.h e_gost_err.h

ameth.o: ameth.c tools.h meth.h pmeth.h gost_asn1.h crypt.h e_gost_err.h paramset.h

keywrap.o: keywrap.c gost89.h keywrap.h

gost2001.o: gost2001.c tools.h sign.h paramset.h e_gost_err.h

engine.o: engine.c md.h crypt.h meth.h e_gost_err.h

gost89.o: gost89.c gost89.h

gost_asn1.o: gost_asn1.c gost_asn1.h

gost_crypt.o: gost_crypt.c crypt.h gost89.h e_gost_err.h gost_asn1.h

gosthash.o: gosthash.c gost89.h gosthash.h

md_gost.o: md_gost.c md.h gosthash.h e_gost_err.h

params.o: params.c paramset.h

gost94_keyx.o: gost94_keyx.c  gost_asn1.h gost89.h gosthash.h crypt.h pmeth.h keywrap.h e_gost_err.h gostkeyx.h

gost2001_keyx.o: gost2001_keyx.c gost89.h gost_asn1.h e_gost_err.h keywrap.h crypt.h sign.h gostkeyx.h pmeth.h gosthash.h tools.h
