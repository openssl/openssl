# You must select the correct terminal control system to be used to
# turn character echo off when reading passwords.  There a 5 systems
# SGTTY   - the old BSD system
# TERMIO  - most system V boxes
# TERMIOS - SGI (ala IRIX).
# VMS     - the DEC operating system
# MSDOS   - we all know what it is :-)
# read_pwd.c makes a reasonable guess at what is correct.

# Targets
# make          - twidle the options yourself :-)
# make cc       - standard cc options
# make gcc      - standard gcc options
# make x86-elf  - linux-elf etc
# make x86-out  - linux-a.out, FreeBSD etc
# make x86-solaris
# make x86-bdsi

# If you are on a DEC Alpha, edit des.h and change the DES_LONG
# define to 'unsigned int'.  I have seen this give a %20 speedup.

OPTS0= -DLIBDES_LIT -DRAND -DTERMIO #-DNOCONST

# Version 1.94 has changed the strings_to_key function so that it is
# now compatible with MITs when the string is longer than 8 characters.
# If you wish to keep the old version, uncomment the following line.
# This will affect the -E/-D options on des(1).
#OPTS1= -DOLD_STR_TO_KEY

# There are 4 possible performance options
# -DDES_PTR
# -DDES_RISC1
# -DDES_RISC2 (only one of DES_RISC1 and DES_RISC2)
# -DDES_UNROLL
# after the initial build, run 'des_opts' to see which options are best
# for your platform.  There are some listed in options.txt
#OPTS2= -DDES_PTR 
#OPTS3= -DDES_RISC1 # or DES_RISC2
#OPTS4= -DDES_UNROLL

OPTS= $(OPTS0) $(OPTS1) $(OPTS2) $(OPTS3) $(OPTS4)

MAKE=make -f Makefile
#CC=cc
#CFLAG= -O

CC=gcc
#CFLAG= -O4 -funroll-loops -fomit-frame-pointer
CFLAG= -O3 -fomit-frame-pointer

CFLAGS=$(OPTS) $(CFLAG)
CPP=$(CC) -E
AS=as

# Assember version of des_encrypt*().
DES_ENC=des_enc.o fcrypt_b.o		# normal C version
#DES_ENC=asm/dx86-elf.o	asm/yx86-elf.o	# elf format x86
#DES_ENC=asm/dx86-out.o	asm/yx86-out.o	# a.out format x86
#DES_ENC=asm/dx86-sol.o	asm/yx86-sol.o	# solaris format x86 
#DES_ENC=asm/dx86bsdi.o	asm/yx86basi.o	# bsdi format x86 

LIBDIR=/usr/local/lib
BINDIR=/usr/local/bin
INCDIR=/usr/local/include
MANDIR=/usr/local/man
MAN1=1
MAN3=3
SHELL=/bin/sh
OBJ_LIT=cbc_enc.o ecb_enc.o $(DES_ENC) fcrypt.o set_key.o
OBJ_FULL=cbc_cksm.o $(OBJ_LIT) pcbc_enc.o \
	xcbc_enc.o qud_cksm.o \
	cfb64ede.o cfb64enc.o cfb_enc.o ecb3_enc.o \
	enc_read.o enc_writ.o ofb64ede.o ofb64enc.o ofb_enc.o  \
	rand_key.o read_pwd.o read2pwd.o rpc_enc.o  str2key.o supp.o

GENERAL_LIT=COPYRIGHT INSTALL README VERSION Makefile des_crypt.man \
	des.doc options.txt asm
GENERAL_FULL=$(GENERAL_LIT) FILES Imakefile times vms.com KERBEROS MODES.DES \
	des.man DES.pm DES.pod DES.xs Makefile.PL dess.cpp des3s.cpp \
	Makefile.uni typemap t Makefile.ssl makefile.bc Makefile.lit \
	des.org des_locl.org
TESTING_LIT=	destest speed des_opts
TESTING_FULL=	rpw $(TESTING_LIT)
TESTING_SRC_LIT=destest.c speed.c des_opts.c
TESTING_SRC_FULL=rpw.c $(TESTING_SRC_LIT)
HEADERS_LIT=des_ver.h des.h des_locl.h podd.h sk.h spr.h
HEADERS_FULL= $(HEADERS_LIT) rpc_des.h
LIBDES_LIT=cbc_enc.c ecb_enc.c fcrypt.c set_key.c des_enc.c fcrypt_b.c
LIBDES_FULL= cbc_cksm.c pcbc_enc.c qud_cksm.c \
	cfb64ede.c cfb64enc.c cfb_enc.c ecb3_enc.c \
	enc_read.c enc_writ.c ofb64ede.c ofb64enc.c ofb_enc.c  \
	rand_key.c rpc_enc.c  str2key.c  supp.c \
	xcbc_enc.c $(LIBDES_LIT) read_pwd.c read2pwd.c

PERL=	des.pl testdes.pl doIP doPC1 doPC2 PC1 PC2 shifts.pl

OBJ=	$(OBJ_LIT)
GENERAL=$(GENERAL_LIT)
TESTING=$(TESTING_LIT)
TESTING_SRC=$(TESTING_SRC_LIT)
HEADERS=$(HEADERS_LIT)
LIBDES=	$(LIBDES_LIT)

ALL=	$(GENERAL) $(TESTING_SRC) $(LIBDES) $(PERL) $(HEADERS)

DLIB=	libdes.a

all: $(DLIB) $(TESTING)

cc:
	$(MAKE) CC=cc CFLAGS="-O $(OPTS) $(CFLAG)" all

gcc:
	$(MAKE) CC=gcc CFLAGS="-O3 -fomit-frame-pointer $(OPTS) $(CFLAG)" all

x86-elf:
	$(MAKE) DES_ENC='asm/dx86-elf.o asm/yx86-elf.o' CC=$(CC) CFLAGS="-DELF $(OPTS) $(CFLAG)" all

x86-out:
	$(MAKE) DES_ENC='asm/dx86-out.o asm/yx86-out.o' CC=$(CC) CFLAGS="-DOUT $(OPTS) $(CFLAG)" all

x86-solaris:
	$(MAKE) DES_ENC='asm/dx86-sol.o asm/yx86-sol.o' CC=$(CC) CFLAGS="-DSOL $(OPTS) $(CFLAG)" all

x86-bsdi:
	$(MAKE) DES_ENC='asm/dx86bsdi.o asm/yx86bsdi.o' CC=$(CC) CFLAGS="-DBSDI $(OPTS) $(CFLAG)" all

# elf
asm/dx86-elf.o: asm/dx86unix.cpp
	$(CPP) -DELF asm/dx86unix.cpp | $(AS) -o asm/dx86-elf.o

asm/yx86-elf.o: asm/yx86unix.cpp
	$(CPP) -DELF asm/yx86unix.cpp | $(AS) -o asm/yx86-elf.o

# solaris
asm/dx86-sol.o: asm/dx86unix.cpp
	$(CC) -E -DSOL asm/dx86unix.cpp | sed 's/^#.*//' > asm/dx86-sol.s
	as -o asm/dx86-sol.o asm/dx86-sol.s
	rm -f asm/dx86-sol.s

asm/yx86-sol.o: asm/yx86unix.cpp
	$(CC) -E -DSOL asm/yx86unix.cpp | sed 's/^#.*//' > asm/yx86-sol.s
	as -o asm/yx86-sol.o asm/yx86-sol.s
	rm -f asm/yx86-sol.s

# a.out
asm/dx86-out.o: asm/dx86unix.cpp
	$(CPP) -DOUT asm/dx86unix.cpp | $(AS) -o asm/dx86-out.o

asm/yx86-out.o: asm/yx86unix.cpp
	$(CPP) -DOUT asm/yx86unix.cpp | $(AS) -o asm/yx86-out.o

# bsdi
asm/dx86bsdi.o: asm/dx86unix.cpp
	$(CPP) -DBSDI asm/dx86unix.cpp | $(AS) -o asm/dx86bsdi.o

asm/yx86bsdi.o: asm/yx86unix.cpp
	$(CPP) -DBSDI asm/yx86unix.cpp | $(AS) -o asm/yx86bsdi.o

asm/dx86unix.cpp:
	(cd asm; perl des-586.pl cpp >dx86unix.cpp)

asm/yx86unix.cpp:
	(cd asm; perl crypt586.pl cpp >yx86unix.cpp)

test:	all
	./destest

$(DLIB): $(OBJ)
	/bin/rm -f $(DLIB)
	ar cr $(DLIB) $(OBJ)
	-if test -s /bin/ranlib; then /bin/ranlib $(DLIB); \
	else if test -s /usr/bin/ranlib; then /usr/bin/ranlib $(DLIB); \
	else exit 0; fi; fi

des_opts: des_opts.o $(DLIB)
	$(CC) $(CFLAGS) -o des_opts des_opts.o $(DLIB)

destest: destest.o $(DLIB)
	$(CC) $(CFLAGS) -o destest destest.o $(DLIB)

rpw: rpw.o $(DLIB)
	$(CC) $(CFLAGS) -o rpw rpw.o $(DLIB)

speed: speed.o $(DLIB)
	$(CC) $(CFLAGS) -o speed speed.o $(DLIB)

des: des.o $(DLIB)
	$(CC) $(CFLAGS) -o des des.o $(DLIB)

tags:
	ctags $(TESTING_SRC) $(LIBDES)

tar_lit:
	/bin/mv Makefile Makefile.tmp
	/bin/cp Makefile.lit Makefile
	tar chf libdes-l.tar $(LIBDES_LIT) $(HEADERS_LIT) \
		$(GENERAL_LIT) $(TESTING_SRC_LIT)
	/bin/rm -f Makefile
	/bin/mv Makefile.tmp Makefile

tar:
	tar chf libdes.tar $(ALL)

shar:
	shar $(ALL) >libdes.shar

depend:
	makedepend $(LIBDES) $(TESTING_SRC)

clean:
	/bin/rm -f *.o tags core $(TESTING) $(DLIB) .nfs* *.old *.bak asm/*.o 

dclean:
	sed -e '/^# DO NOT DELETE THIS LINE/ q' Makefile >Makefile.new
	mv -f Makefile.new Makefile

# Eric is probably going to choke when he next looks at this --tjh
install:
	if test $(INSTALLTOP); then \
	    echo SSL style install; \
	    cp $(DLIB) $(INSTALLTOP)/lib; \
	    if test -s /bin/ranlib; then \
	        /bin/ranlib $(INSTALLTOP)/lib/$(DLIB); \
	    else \
		if test -s /usr/bin/ranlib; then \
		/usr/bin/ranlib $(INSTALLTOP)/lib/$(DLIB); \
	    fi; fi; \
	    chmod 644 $(INSTALLTOP)/lib/$(DLIB); \
	    cp des.h $(INSTALLTOP)/include; \
	    chmod 644 $(INSTALLTOP)/include/des.h; \
	else \
	    echo Standalone install; \
	    cp $(DLIB) $(LIBDIR)/$(DLIB); \
	    if test -s /bin/ranlib; then \
	      /bin/ranlib $(LIBDIR)/$(DLIB); \
	    else \
	      if test -s /usr/bin/ranlib; then \
		/usr/bin/ranlib $(LIBDIR)/$(DLIB); \
	      fi; \
	    fi; \
	    chmod 644 $(LIBDIR)/$(DLIB); \
	    cp des_crypt.man $(MANDIR)/man$(MAN3)/des_crypt.$(MAN3); \
	    chmod 644 $(MANDIR)/man$(MAN3)/des_crypt.$(MAN3); \
	    cp des.man $(MANDIR)/man$(MAN1)/des.$(MAN1); \
	    chmod 644 $(MANDIR)/man$(MAN1)/des.$(MAN1); \
	    cp des.h $(INCDIR)/des.h; \
	    chmod 644 $(INCDIR)/des.h; \
	fi
# DO NOT DELETE THIS LINE -- make depend depends on it.
