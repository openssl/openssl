#
# Makefile for all the SSL related library routines and utilities
VERSION	= 0.8.1a
#
# make install will install:
#   libraries into $INSTALLTOP/lib
#   headers   into $INSTALLTOP/include
#   utilities into $INSTALLTOP/bin
#
# By default INSTALLTOP is set to /usr/local/ssl
# If you want things install elsewere, consider running
# perl util/ssldir.pl /new/path
#
# Interesting Mailing Lists:
#     ssl-bugs@mincom.oz.au
#     ssl-users@mincom.oz.au
#
# To join the Mailing Lists:
#     ssl-bugs-request@mincom.oz.au
#     ssl-users-request@mincom.oz.au
#
# If you must get hold of people directly (we much prefer the above
# lists to be used if the question is of general interest!):
#	Eric Young <eay@cryptsoft.com>
#	Tim Hudson <tjh@cryptsoft.com>
#	or both    <ssleay@cryptsoft.com>
#
# The primary distribution of SSLeay is from
# ftp://ftp.psy.uq.oz.au/pub/Crypto/SSL
#
# NOCONST - Define for C compilers that don't like the const key word.
# NOPROTO - Define in if your compiler does not support prototypes.
# RSAref  - Define if we are to link with RSAref.
# NO_IDEA - Define to build without the IDEA algorithm
# NO_RC4  - Define to build without the RC4 algorithm
# NO_RC2  - Define to build without the RC2 algorithm
# THREADS - Define when building with threads, you will probably also need any
#	    system defines as well, i.e. _REENTERANT for Solaris 2.[34]
# TERMIO  - Define the termio terminal subsystem, needed if sgtty is missing.
# TERMIOS - Define the termios terminal subsystem, Silicon Graphics.
# LONGCRYPT - Define to use HPUX 10.x's long password modification to crypt(3).
# DEVRANDOM - Give this the value of the 'random device' if your OS supports
#	    one.  32 bytes will be read from this when the random
#	    number generator is initalised.
# SSL_ALLOW_ADH - define if you want the server to be able to use the
#	    SSLv3 anon-DH ciphers.
# SSL_ALLOW_ENULL - define if you want the server to be able to use the
#	    NULL encryption ciphers.
#
# LOCK_DEBUG - turns on lots of lock debug output :-)
# REF_CHECK - turn on some xyz_free() assertions.
# CRYPTO_MDEBUG - turns on my 'memory leak' detecting stuff
# MFUNC - Make all Malloc/Free/Realloc calls call
#	CRYPTO_malloc/CRYPTO_free/CRYPTO_realloc which can be setup to
#	call application defined callbacks via CRYPTO_set_mem_functions()


CC= cc
CFLAG= -O -DNOPROTO
#CFLAG= -DL_ENDIAN -DTERMIO -O3 -fomit-frame-pointer -m486 -Wall -Wuninitialized
PEX_LIBS= -L. -L.. -L../.. -L../../..
EX_LIBS= 
#EX_LIBS= #-lRSAglue -lrsaref -lnsl -lsocket
AR=ar r

# Set BN_MULW to bn_mulw.o if you want to use the C version
#BN_MULW= asm/x86-lnx.o
BN_MULW= bn_mulw.o
#BN_MULW= asm/x86-lnx.o		# elf
#BN_MULW= asm/x86-sol.o		# solaris
#BN_MULW= asm/x86-lnxa.o	# a.out, FreeBSD
#BN_MULW= asm/x86-bsdi.o	# bsdi
#BN_MULW= asm/alpha.o		# DEC Alpha
#BN_MULW= asm/pa-risc2.o	# HP-UX PA-RISC
#BN_MULW= asm/r3000.o		# SGI MIPS cpu
#BN_MULW= asm/sparc.o		# Sun solaris/SunOS
#BN_MULW= asm/x86nt32.o		# Windows 95/NT
#BN_MULW= asm/x86w16.o		# 16 bit code for Windows 3.1/DOS
#BN_MULW= asm/x86w32.o		# 32 bit code for Windows 3.1

# Set DES_ENC to des_enc.o if you want to use the C version
#There are 4 x86 assember options.
DES_ENC= des_enc.o fcrypt_b.o
#DES_ENC= des_enc.o fcrypt_b.o		# C
#DES_ENC= asm/dx86-elf.o asm/cx86-elf.o # elf
#DES_ENC= asm/dx86-sol.o asm/cx86-sol.o	# solaris
#DES_ENC= asm/dx86-out.o asm/cx86-out.o	# a.out, FreeBSD
#DES_ENC= asm/dx86bsdi.o asm/cx86bsdi.o	# bsdi

# Set BF_ENC to bf_enc.o if you want to use the C version
#There are 4 x86 assember options.
BF_ENC= bf_enc.o
#BF_ENC= bf_enc.o	# C
#BF_ENC= asm/bx86-elf.o # elf
#BF_ENC= asm/bx86-sol.o	# solaris
#BF_ENC= asm/bx86-out.o	# a.out, FreeBSD
#BF_ENC= asm/bx86bsdi.o	# bsdi

DIRS=	crypto ssl rsaref apps test tools
# dirs in crypto to build
SDIRS=  \
	md sha mdc2 des rc4 rc2 idea bf bn rsa dsa dh \
	buffer bio stack lhash rand err objects \
	evp pem asn1 x509 conf txt_db pkcs7

# If you change the INSTALLTOP, make sure to also change the values
# in crypto/location.h
INSTALLTOP=/usr/local/ssl

MAKEFILE= Makefile.ssl
MAKE=	  make -f Makefile.ssl

MAN1=1
MAN3=3
SHELL=/bin/sh

TOP=	.
ONEDIRS=out tmp
EDIRS=	times doc bugs util include certs ms shlib mt demos
MISC=	COPYRIGHT Configure HISTORY.066 INSTALL Makefile.ssl Makefile \
	README TODO HISTORY README.066 README.080 \
	VERSION PROBLEMS MINFO makefile.one e_os.h \
	MICROSOFT makevms.com
WDIRS=	windows
LIBS=	libcrypto.a libssl.a 

GENERAL=	Makefile
BASENAME=	SSLeay
NAME=		$(BASENAME)-$(VERSION)
TARFILE=	$(NAME).tar
WTARFILE=	$(NAME)-win.tar
EX_HEADER=
HEADER=		e_os.h

all:
	@for i in $(DIRS) ;\
	do \
	(cd $$i; echo "making $$i..."; \
	$(MAKE) CC='${CC}' CFLAG='${CFLAG}' INSTALLTOP='${INSTALLTOP}' PEX_LIBS='${PEX_LIBS}' EX_LIBS='${EX_LIBS}' BN_MULW='${BN_MULW}' DES_ENC='${DES_ENC}' BF_ENC='${BF_ENC}' SDIRS='${SDIRS}' AR='${AR}' all ); \
	done;

sub_all:
	@for i in $(DIRS) ;\
	do \
	(cd $$i; echo "making $$i..."; \
	$(MAKE) CC='${CC}' CFLAG='${CFLAG}' SDIRS='$(SDIRS)' INSTALLTOP='${INSTALLTOP}' PEX_LIBS='${PEX_LIBS}' EX_LIBS='${EX_LIBS}' BN_MULW='${BN_MULW}' DES_ENC='${DES_ENC}' BF_ENC='${BF_ENC}' AR='${AR}' all ); \
	done;

clean:
	/bin/rm -f *.o core a.out fluff *.map
	@for i in $(DIRS) ;\
	do \
	(cd $$i; echo "cleaning $$i..."; \
	$(MAKE) SDIRS='${SDIRS}' clean ); \
	/bin/rm -f $(LIBS); \
	done;
	/bin/rm -f *.a *.o speed.* *.map *.so .pure core
	/bin/rm -f $(TARFILE)
	@for i in $(ONEDIRS) ;\
	do \
	/bin/rm -f $$i/*; \
	done

makefile.one: files
	perl util/mk1mf.pl >makefile.one; \
	sh util/do_ms.sh

files:	MINFO
	perl $(TOP)/util/files.pl Makefile.ssl > $(TOP)/MINFO
	@for i in $(DIRS) ;\
	do \
	(cd $$i; echo "making 'files' in $$i..."; \
	$(MAKE) SDIRS='${SDIRS}' files ); \
	done;

links:
	/bin/rm -f Makefile;
	./util/point.sh Makefile.ssl Makefile;
	@for i in $(DIRS) ;\
	do \
	(cd $$i; echo "making links in $$i..."; \
	$(MAKE) SDIRS='${SDIRS}' links ); \
	done;
	# @(cd apps; sh ./mklinks)
	sh tools/c_rehash certs

dclean:
	/bin/rm -f *.bak
	@for i in $(DIRS) ;\
	do \
	(cd $$i; echo "undoing makedepend in $$i..."; \
	$(MAKE) SDIRS='${SDIRS}' dclean ); \
	done;

rehash:
	@(PATH="`pwd`/apps:${PATH}"; sh tools/c_rehash certs)

test:	tests

tests:
	(cd test; echo "testing $$i..."; \
	$(MAKE) CC='${CC}' CFLAG='${CFLAG}' INSTALLTOP='${INSTALLTOP}' PEX_LIBS='${PEX_LIBS}' EX_LIBS='${EX_LIBS}' BN_MULW='${BN_MULW}' DES_ENC='${DES_ENC}' BF_ENC='${BF_ENC}' SDIRS='${SDIRS}' AR='${AR}' tests );
	@apps/ssleay version -a

depend:
	@for i in $(DIRS) ;\
	do \
	(cd $$i; echo "making dependancies $$i..."; \
	$(MAKE) SDIRS='${SDIRS}' depend ); \
	done;

lint:
	@for i in $(DIRS) ;\
	do \
	(cd $$i; echo "making lint $$i..."; \
	$(MAKE) SDIRS='${SDIRS}' lint ); \
	done;

tags:
	@for i in $(DIRS) ;\
	do \
	(cd $$i; echo "making tags $$i..."; \
	$(MAKE) SDIRS='${SDIRS}' tags ); \
	done;

errors:
	@for i in $(DIRS) ;\
	do \
	(cd $$i; echo "making errors in $$i..."; \
	$(MAKE) SDIRS='${SDIRS}' errors ); \
	done;

tar:
	@(cd ..;\
	mv $(BASENAME) $(NAME); \
	export STUFF; \
	for i in $(MISC) $(DIRS) $(EDIRS) $(ONEDIRS) ;\
	do \
		STUFF="$$STUFF $(NAME)/$$i"; \
	done; \
	tar cf $(NAME)/$(TARFILE) $$STUFF; \
	mv $(NAME) $(BASENAME) ) 
	gzip -f $(TARFILE)

dist:	
	perl Configure dist
	@$(MAKE) dist_pem_h
	@$(MAKE) SDIRS='${SDIRS}' clean
	@$(MAKE) SDIRS='${SDIRS}' dclean
	@(cd apps; sh ./rmlinks)
	@$(MAKE) makefile.one
	@$(MAKE) tar

dist_pem_h:
	(cd crypto/pem; $(MAKE) SDIRS='${SDIRS}' CFLAG='${CFLAG}' pem.h; $(MAKE) clean)

install: all
	@-mkdir -p $(INSTALLTOP)/bin 2>/dev/null
	@-mkdir -p $(INSTALLTOP)/lib 2>/dev/null
	@-mkdir -p $(INSTALLTOP)/include 2>/dev/null
	@-mkdir -p $(INSTALLTOP)/certs 2>/dev/null
	@-mkdir -p $(INSTALLTOP)/private 2>/dev/null
	@for i in $(DIRS) ;\
	do \
	(cd $$i; echo "installing $$i..."; \
	$(MAKE) CC='${CC}' CFLAG='${CFLAG}' INSTALLTOP='${INSTALLTOP}' EX_LIBS='${EX_LIBS}' SDIRS='${SDIRS}' install ); \
	done
	@for i in $(LIBS) ;\
	do \
	(	echo installing $$i; \
		cp $$i $(INSTALLTOP)/lib; \
		sh util/ranlib.sh $(INSTALLTOP)/lib/$$i; \
		chmod 644 $(INSTALLTOP)/lib/$$i ); \
	done

# DO NOT DELETE THIS LINE -- make depend depends on it.
