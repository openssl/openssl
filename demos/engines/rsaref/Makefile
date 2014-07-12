LIBNAME=	librsaref
SRC=		rsaref.c
OBJ=		rsaref.o
HEADER=		rsaref.h

PIC=		-fPIC
CFLAGS=		-g -I../../../include $(PIC) -DENGINE_DYNAMIC_SUPPORT

LIB=		$(LIBNAME).a
SHLIB=		$(LIBNAME).so

all: all_demos_engines_rsaref
all_demos_engines_rsaref:
		@echo 'Please choose a system to build on:'
		@echo ''
		@echo 'tru64:    Tru64 Unix, Digital Unix, Digital OSF/1'
		@echo 'solaris:  Solaris'
		@echo 'irix:     IRIX'
		@echo 'hpux32:   32-bit HP/UX'
		@echo 'hpux64:   64-bit HP/UX'
		@echo 'aix:      AIX'
		@echo 'gnu:      Generic GNU-based system (gcc and GNU ld)'
		@echo ''

FORCE.install:
install: install_demos_engines_rsaref
install_demos_engines_rsaref:	FORCE.install
		cd install; \
			make -f unix/makefile CFLAGS='-I. -DPROTOTYPES=1 -O -c' RSAREFLIB=librsaref.a librsaref.a

FORCE.update: FORCE.update_demos_engines_rsaref
FORCE.update_demos_engines_rsaref:
update: update_demos_engines_rsaref
update_demos_engines_rsaref:		FORCE.update
		perl ../../../util/mkerr.pl -conf rsaref.ec \
			-nostatic -staticloader -write rsaref.c

darwin:		install $(SHLIB).darwin
cygwin:		install $(SHLIB).cygwin
gnu: gnu_demos_engines_rsaref
gnu_demos_engines_rsaref:		install $(SHLIB).gnu
alpha-osf1:	install $(SHLIB).alpha-osf1
tru64: tru64_demos_engines_rsaref
tru64_demos_engines_rsaref:		install $(SHLIB).tru64
solaris: solaris_demos_engines_rsaref
solaris_demos_engines_rsaref:	install $(SHLIB).solaris
irix: irix_demos_engines_rsaref
irix_demos_engines_rsaref:		install $(SHLIB).irix
hpux32: hpux32_demos_engines_rsaref
hpux32_demos_engines_rsaref:		install $(SHLIB).hpux32
hpux64: hpux64_demos_engines_rsaref
hpux64_demos_engines_rsaref:		install $(SHLIB).hpux64
aix: aix_demos_engines_rsaref
aix_demos_engines_rsaref:		install $(SHLIB).aix
reliantunix:	install $(SHLIB).reliantunix

$(LIB):		$(OBJ)
		$(AR) $(LIB) $(OBJ)
		- $(RANLIB) $(LIB)

LINK_SO=	\
  ld -r -o $(LIBNAME).o $$ALLSYMSFLAGS $(LIB) install/librsaref.a && \
  (nm -Pg $(LIBNAME).o | grep ' [BDT] ' | cut -f1 -d' ' > $(LIBNAME).exp; \
   $$SHAREDCMD $$SHAREDFLAGS -o $(SHLIB) $(LIBNAME).o -L ../../.. -lcrypto -lc)

$(SHLIB).darwin:	$(LIB) install/librsaref.a
		ALLSYMSFLAGS='-all_load' \
		SHAREDFLAGS='-dynamiclib -install_name $(SHLIB)' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO)
		touch $(SHLIB).darwin
$(SHLIB).cygwin:	$(LIB) install/librsaref.a
		ALLSYMSFLAGS='--whole-archive' \
		SHAREDFLAGS='-shared -Wl,-Bsymbolic -Wl,--out-implib,$(LIBNAME).dll.a' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO)
		touch $(SHLIB).cygwin
$(SHLIB).gnu:	$(LIB) install/librsaref.a
		ALLSYMSFLAGS='--whole-archive' \
		SHAREDFLAGS='-shared -Wl,-soname=$(SHLIB)' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO)
		touch $(SHLIB).gnu
$(SHLIB).tru64:	$(LIB) install/librsaref.a
		ALLSYMSFLAGS='-all' \
		SHAREDFLAGS='-shared' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO)
		touch $(SHLIB).tru64
$(SHLIB).solaris:	$(LIB) install/librsaref.a
		ALLSYMSFLAGS='-z allextract' \
		SHAREDFLAGS='-G -h $(SHLIB)' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO)
		touch $(SHLIB).solaris
$(SHLIB).irix:	$(LIB) install/librsaref.a
		ALLSYMSFLAGS='-all' \
		SHAREDFLAGS='-shared -Wl,-soname,$(SHLIB)' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO)
		touch $(SHLIB).irix
$(SHLIB).hpux32:	$(LIB) install/librsaref.a
		ALLSYMSFLAGS='-Fl' \
		SHAREDFLAGS='+vnocompatwarnings -b -z +s +h $(SHLIB)' \
		SHAREDCMD='/usr/ccs/bin/ld'; \
		$(LINK_SO)
		touch $(SHLIB).hpux32
$(SHLIB).hpux64:	$(LIB) install/librsaref.a
		ALLSYMSFLAGS='+forceload' \
		SHAREDFLAGS='-b -z +h $(SHLIB)' \
		SHAREDCMD='/usr/ccs/bin/ld'; \
		$(LINK_SO)
		touch $(SHLIB).hpux64
$(SHLIB).aix:	$(LIB) install/librsaref.a
		ALLSYMSFLAGS='-bnogc' \
		SHAREDFLAGS='-G -bE:$(LIBNAME).exp -bM:SRE' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO)
		touch $(SHLIB).aix

