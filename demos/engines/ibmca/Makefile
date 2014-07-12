LIBNAME_demos_engines_ibmca=	libibmca
SRC_demos_engines_ibmca=		hw_ibmca.c
OBJ_demos_engines_ibmca=		hw_ibmca.o
HEADER_demos_engines_ibmca=		hw_ibmca.h

PIC_demos_engines_ibmca=		-fPIC
CFLAGS_demos_engines_ibmca=		-g -I../../../include $(PIC_demos_engines_ibmca) -DENGINE_DYNAMIC_SUPPORT -DFLAT_INC

LIB_demos_engines_ibmca=		$(LIBNAME_demos_engines_ibmca).a
SHLIB_demos_engines_ibmca=		$(LIBNAME_demos_engines_ibmca).so

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
gnu_demos_engines_ibmca:		$(SHLIB_demos_engines_ibmca).gnu
tru64: tru64_demos_engines_ibmca
tru64_demos_engines_ibmca:		$(SHLIB_demos_engines_ibmca).tru64
solaris: solaris_demos_engines_ibmca
solaris_demos_engines_ibmca:	$(SHLIB_demos_engines_ibmca).solaris
irix: irix_demos_engines_ibmca
irix_demos_engines_ibmca:		$(SHLIB_demos_engines_ibmca).irix
hpux32: hpux32_demos_engines_ibmca
hpux32_demos_engines_ibmca:		$(SHLIB_demos_engines_ibmca).hpux32
hpux64: hpux64_demos_engines_ibmca
hpux64_demos_engines_ibmca:		$(SHLIB_demos_engines_ibmca).hpux64
aix: aix_demos_engines_ibmca
aix_demos_engines_ibmca:		$(SHLIB_demos_engines_ibmca).aix

$(LIB_demos_engines_ibmca):		$(OBJ_demos_engines_ibmca)
		$(AR) $(LIB_demos_engines_ibmca) $(OBJ_demos_engines_ibmca)
		- $(RANLIB) $(LIB_demos_engines_ibmca)

LINK_SO_demos_engines_ibmca=	\
  ld -r -o $(LIBNAME_demos_engines_ibmca).o $$ALLSYMSFLAGS $(LIB_demos_engines_ibmca) && \
  (nm -Pg $(LIBNAME_demos_engines_ibmca).o | grep ' [BDT] ' | cut -f1 -d' ' > $(LIBNAME_demos_engines_ibmca).exp; \
   $$SHAREDCMD $$SHAREDFLAGS -o $(SHLIB_demos_engines_ibmca) $(LIBNAME_demos_engines_ibmca).o -L ../../.. -lcrypto -lc)

$(SHLIB_demos_engines_ibmca).gnu:	$(LIB_demos_engines_ibmca)
		ALLSYMSFLAGS='--whole-archive' \
		SHAREDFLAGS='-shared -Wl,-soname=$(SHLIB_demos_engines_ibmca)' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO_demos_engines_ibmca)
		touch $(SHLIB_demos_engines_ibmca).gnu
$(SHLIB_demos_engines_ibmca).tru64:	$(LIB_demos_engines_ibmca)
		ALLSYMSFLAGS='-all' \
		SHAREDFLAGS='-shared' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO_demos_engines_ibmca)
		touch $(SHLIB_demos_engines_ibmca).tru64
$(SHLIB_demos_engines_ibmca).solaris:	$(LIB_demos_engines_ibmca)
		ALLSYMSFLAGS='-z allextract' \
		SHAREDFLAGS='-G -h $(SHLIB_demos_engines_ibmca)' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO_demos_engines_ibmca)
		touch $(SHLIB_demos_engines_ibmca).solaris
$(SHLIB_demos_engines_ibmca).irix:	$(LIB_demos_engines_ibmca)
		ALLSYMSFLAGS='-all' \
		SHAREDFLAGS='-shared -Wl,-soname,$(SHLIB_demos_engines_ibmca)' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO_demos_engines_ibmca)
		touch $(SHLIB_demos_engines_ibmca).irix
$(SHLIB_demos_engines_ibmca).hpux32:	$(LIB_demos_engines_ibmca)
		ALLSYMSFLAGS='-Fl' \
		SHAREDFLAGS='+vnocompatwarnings -b -z +s +h $(SHLIB_demos_engines_ibmca)' \
		SHAREDCMD='/usr/ccs/bin/ld'; \
		$(LINK_SO_demos_engines_ibmca)
		touch $(SHLIB_demos_engines_ibmca).hpux32
$(SHLIB_demos_engines_ibmca).hpux64:	$(LIB_demos_engines_ibmca)
		ALLSYMSFLAGS='+forceload' \
		SHAREDFLAGS='-b -z +h $(SHLIB_demos_engines_ibmca)' \
		SHAREDCMD='/usr/ccs/bin/ld'; \
		$(LINK_SO_demos_engines_ibmca)
		touch $(SHLIB_demos_engines_ibmca).hpux64
$(SHLIB_demos_engines_ibmca).aix:	$(LIB_demos_engines_ibmca)
		ALLSYMSFLAGS='-bnogc' \
		SHAREDFLAGS='-G -bE:$(LIBNAME_demos_engines_ibmca).exp -bM:SRE' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO_demos_engines_ibmca)
		touch $(SHLIB_demos_engines_ibmca).aix

.c.o:
	$(CC) $(CFLAGS_demos_engines_ibmca) $(CPPFLAGS) -c -o $@ $<
