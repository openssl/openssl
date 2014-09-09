LIBNAME_demos_engines_rsaref=	librsaref
SRC_demos_engines_rsaref=		demos/engines/rsaref/rsaref.c
OBJ_demos_engines_rsaref=		demos/engines/rsaref/rsaref.o
HEADER_demos_engines_rsaref=		demos/engines/rsaref/rsaref.h

PIC_demos_engines_rsaref=		-fPIC
CFLAGS_demos_engines_rsaref=		-g -I../../../include $(PIC_demos_engines_rsaref) -DENGINE_DYNAMIC_SUPPORT

LIB_demos_engines_rsaref=		$(LIBNAME_demos_engines_rsaref).a
SHLIB_demos_engines_rsaref=		$(LIBNAME_demos_engines_rsaref).so

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

demos/engines/rsaref/FORCE.install:
install: install_demos_engines_rsaref
install_demos_engines_rsaref:	demos/engines/rsaref/FORCE.install
		cd demos/engines/rsaref/install; \
			make -f unix/makefile CFLAGS='-I. -DPROTOTYPES=1 -O -c' RSAREFLIB=librsaref.a librsaref.a

FORCE.update: FORCE.update_demos_engines_rsaref
FORCE.update_demos_engines_rsaref:
update: update_demos_engines_rsaref
update_demos_engines_rsaref:		FORCE.update_demos_engines_rsaref
		perl util/mkerr.pl -conf rsaref.ec \
			-nostatic -staticloader -write demos/engines/rsaref/rsaref.c

demos/engines/rsaref/darwin:		install_demos_engines_rsaref $(SHLIB_demos_engines_rsaref).darwin
demos/engines/rsaref/cygwin:		install_demos_engines_rsaref $(SHLIB_demos_engines_rsaref).cygwin
gnu: gnu_demos_engines_rsaref
gnu_demos_engines_rsaref:		install_demos_engines_rsaref $(SHLIB_demos_engines_rsaref).gnu
demos/engines/rsaref/alpha-osf1:	install_demos_engines_rsaref $(SHLIB_demos_engines_rsaref).alpha-osf1
tru64: tru64_demos_engines_rsaref
tru64_demos_engines_rsaref:		install_demos_engines_rsaref $(SHLIB_demos_engines_rsaref).tru64
solaris: solaris_demos_engines_rsaref
solaris_demos_engines_rsaref:	install_demos_engines_rsaref $(SHLIB_demos_engines_rsaref).solaris
irix: irix_demos_engines_rsaref
irix_demos_engines_rsaref:		install_demos_engines_rsaref $(SHLIB_demos_engines_rsaref).irix
hpux32: hpux32_demos_engines_rsaref
hpux32_demos_engines_rsaref:		install_demos_engines_rsaref $(SHLIB_demos_engines_rsaref).hpux32
hpux64: hpux64_demos_engines_rsaref
hpux64_demos_engines_rsaref:		install_demos_engines_rsaref $(SHLIB_demos_engines_rsaref).hpux64
aix: aix_demos_engines_rsaref
aix_demos_engines_rsaref:		install_demos_engines_rsaref $(SHLIB_demos_engines_rsaref).aix
demos/engines/rsaref/reliantunix:	install_demos_engines_rsaref $(SHLIB_demos_engines_rsaref).reliantunix

$(LIB_demos_engines_rsaref):		$(OBJ_demos_engines_rsaref)
		$(AR) $(LIB_demos_engines_rsaref) $(OBJ_demos_engines_rsaref)
		- $(RANLIB) $(LIB_demos_engines_rsaref)

LINK_SO_demos_engines_rsaref=	\
  ld -r -o $(LIBNAME_demos_engines_rsaref).o $$ALLSYMSFLAGS $(LIB_demos_engines_rsaref) install/librsaref.a && \
  (nm -Pg $(LIBNAME_demos_engines_rsaref).o | grep ' [BDT] ' | cut -f1 -d' ' > $(LIBNAME_demos_engines_rsaref).exp; \
   $$SHAREDCMD $$SHAREDFLAGS -o $(SHLIB_demos_engines_rsaref) $(LIBNAME_demos_engines_rsaref).o -L ../../.. -lcrypto -lc)

$(SHLIB_demos_engines_rsaref).darwin:	$(LIB_demos_engines_rsaref) install/librsaref.a
		ALLSYMSFLAGS='-all_load' \
		SHAREDFLAGS='-dynamiclib -install_name $(SHLIB_demos_engines_rsaref)' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO_demos_engines_rsaref)
		touch $(SHLIB_demos_engines_rsaref).darwin
$(SHLIB_demos_engines_rsaref).cygwin:	$(LIB_demos_engines_rsaref) install/librsaref.a
		ALLSYMSFLAGS='--whole-archive' \
		SHAREDFLAGS='-shared -Wl,-Bsymbolic -Wl,--out-implib,$(LIBNAME_demos_engines_rsaref).dll.a' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO_demos_engines_rsaref)
		touch $(SHLIB_demos_engines_rsaref).cygwin
$(SHLIB_demos_engines_rsaref).gnu:	$(LIB_demos_engines_rsaref) install/librsaref.a
		ALLSYMSFLAGS='--whole-archive' \
		SHAREDFLAGS='-shared -Wl,-soname=$(SHLIB_demos_engines_rsaref)' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO_demos_engines_rsaref)
		touch $(SHLIB_demos_engines_rsaref).gnu
$(SHLIB_demos_engines_rsaref).tru64:	$(LIB_demos_engines_rsaref) install/librsaref.a
		ALLSYMSFLAGS='-all' \
		SHAREDFLAGS='-shared' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO_demos_engines_rsaref)
		touch $(SHLIB_demos_engines_rsaref).tru64
$(SHLIB_demos_engines_rsaref).solaris:	$(LIB_demos_engines_rsaref) install/librsaref.a
		ALLSYMSFLAGS='-z allextract' \
		SHAREDFLAGS='-G -h $(SHLIB_demos_engines_rsaref)' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO_demos_engines_rsaref)
		touch $(SHLIB_demos_engines_rsaref).solaris
$(SHLIB_demos_engines_rsaref).irix:	$(LIB_demos_engines_rsaref) install/librsaref.a
		ALLSYMSFLAGS='-all' \
		SHAREDFLAGS='-shared -Wl,-soname,$(SHLIB_demos_engines_rsaref)' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO_demos_engines_rsaref)
		touch $(SHLIB_demos_engines_rsaref).irix
$(SHLIB_demos_engines_rsaref).hpux32:	$(LIB_demos_engines_rsaref) install/librsaref.a
		ALLSYMSFLAGS='-Fl' \
		SHAREDFLAGS='+vnocompatwarnings -b -z +s +h $(SHLIB_demos_engines_rsaref)' \
		SHAREDCMD='/usr/ccs/bin/ld'; \
		$(LINK_SO_demos_engines_rsaref)
		touch $(SHLIB_demos_engines_rsaref).hpux32
$(SHLIB_demos_engines_rsaref).hpux64:	$(LIB_demos_engines_rsaref) install/librsaref.a
		ALLSYMSFLAGS='+forceload' \
		SHAREDFLAGS='-b -z +h $(SHLIB_demos_engines_rsaref)' \
		SHAREDCMD='/usr/ccs/bin/ld'; \
		$(LINK_SO_demos_engines_rsaref)
		touch $(SHLIB_demos_engines_rsaref).hpux64
$(SHLIB_demos_engines_rsaref).aix:	$(LIB_demos_engines_rsaref) install/librsaref.a
		ALLSYMSFLAGS='-bnogc' \
		SHAREDFLAGS='-G -bE:$(LIBNAME_demos_engines_rsaref).exp -bM:SRE' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO_demos_engines_rsaref)
		touch $(SHLIB_demos_engines_rsaref).aix

