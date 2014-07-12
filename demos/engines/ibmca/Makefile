LIBNAME=	libibmca
SRC=		hw_ibmca.c
OBJ=		hw_ibmca.o
HEADER=		hw_ibmca.h

PIC=		-fPIC
CFLAGS=		-g -I../../../include $(PIC) -DENGINE_DYNAMIC_SUPPORT -DFLAT_INC

LIB=		$(LIBNAME).a
SHLIB=		$(LIBNAME).so

all: all_demos_engines_ibmca
all_demos_engines_ibmca:
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

FORCE.update: FORCE.update_demos_engines_ibmca
FORCE.update_demos_engines_ibmca:
update: update_demos_engines_ibmca
update_demos_engines_ibmca:		FORCE.update
		perl ../../../util/mkerr.pl -conf hw_ibmca.ec \
			-nostatic -staticloader -write hw_ibmca.c

gnu: gnu_demos_engines_ibmca
gnu_demos_engines_ibmca:		$(SHLIB).gnu
tru64: tru64_demos_engines_ibmca
tru64_demos_engines_ibmca:		$(SHLIB).tru64
solaris: solaris_demos_engines_ibmca
solaris_demos_engines_ibmca:	$(SHLIB).solaris
irix: irix_demos_engines_ibmca
irix_demos_engines_ibmca:		$(SHLIB).irix
hpux32: hpux32_demos_engines_ibmca
hpux32_demos_engines_ibmca:		$(SHLIB).hpux32
hpux64: hpux64_demos_engines_ibmca
hpux64_demos_engines_ibmca:		$(SHLIB).hpux64
aix: aix_demos_engines_ibmca
aix_demos_engines_ibmca:		$(SHLIB).aix

$(LIB):		$(OBJ)
		$(AR) $(LIB) $(OBJ)
		- $(RANLIB) $(LIB)

LINK_SO=	\
  ld -r -o $(LIBNAME).o $$ALLSYMSFLAGS $(LIB) && \
  (nm -Pg $(LIBNAME).o | grep ' [BDT] ' | cut -f1 -d' ' > $(LIBNAME).exp; \
   $$SHAREDCMD $$SHAREDFLAGS -o $(SHLIB) $(LIBNAME).o -L ../../.. -lcrypto -lc)

$(SHLIB).gnu:	$(LIB)
		ALLSYMSFLAGS='--whole-archive' \
		SHAREDFLAGS='-shared -Wl,-soname=$(SHLIB)' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO)
		touch $(SHLIB).gnu
$(SHLIB).tru64:	$(LIB)
		ALLSYMSFLAGS='-all' \
		SHAREDFLAGS='-shared' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO)
		touch $(SHLIB).tru64
$(SHLIB).solaris:	$(LIB)
		ALLSYMSFLAGS='-z allextract' \
		SHAREDFLAGS='-G -h $(SHLIB)' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO)
		touch $(SHLIB).solaris
$(SHLIB).irix:	$(LIB)
		ALLSYMSFLAGS='-all' \
		SHAREDFLAGS='-shared -Wl,-soname,$(SHLIB)' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO)
		touch $(SHLIB).irix
$(SHLIB).hpux32:	$(LIB)
		ALLSYMSFLAGS='-Fl' \
		SHAREDFLAGS='+vnocompatwarnings -b -z +s +h $(SHLIB)' \
		SHAREDCMD='/usr/ccs/bin/ld'; \
		$(LINK_SO)
		touch $(SHLIB).hpux32
$(SHLIB).hpux64:	$(LIB)
		ALLSYMSFLAGS='+forceload' \
		SHAREDFLAGS='-b -z +h $(SHLIB)' \
		SHAREDCMD='/usr/ccs/bin/ld'; \
		$(LINK_SO)
		touch $(SHLIB).hpux64
$(SHLIB).aix:	$(LIB)
		ALLSYMSFLAGS='-bnogc' \
		SHAREDFLAGS='-G -bE:$(LIBNAME).exp -bM:SRE' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO)
		touch $(SHLIB).aix

