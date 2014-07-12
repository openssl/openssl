LIBNAME_demos_engines_zencod=	libzencod
SRC_demos_engines_zencod=		hw_zencod.c
OBJ_demos_engines_zencod=		hw_zencod.o
HEADER_demos_engines_zencod=		hw_zencod.h

PIC_demos_engines_zencod=		-fPIC
CFLAGS_demos_engines_zencod=		-g -I../../../include $(PIC_demos_engines_zencod) -DENGINE_DYNAMIC_SUPPORT -DFLAT_INC

LIB_demos_engines_zencod=		$(LIBNAME_demos_engines_zencod).a
SHLIB_demos_engines_zencod=		$(LIBNAME_demos_engines_zencod).so

all: all_demos_engines_zencod
all_demos_engines_zencod:
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

FORCE.update: FORCE.update_demos_engines_zencod
FORCE.update_demos_engines_zencod:
update: update_demos_engines_zencod
update_demos_engines_zencod:		FORCE.update
		perl ../../../util/mkerr.pl -conf hw_zencod.ec \
			-nostatic -staticloader -write hw_zencod.c

gnu: gnu_demos_engines_zencod
gnu_demos_engines_zencod:		$(SHLIB_demos_engines_zencod).gnu
tru64: tru64_demos_engines_zencod
tru64_demos_engines_zencod:		$(SHLIB_demos_engines_zencod).tru64
solaris: solaris_demos_engines_zencod
solaris_demos_engines_zencod:	$(SHLIB_demos_engines_zencod).solaris
irix: irix_demos_engines_zencod
irix_demos_engines_zencod:		$(SHLIB_demos_engines_zencod).irix
hpux32: hpux32_demos_engines_zencod
hpux32_demos_engines_zencod:		$(SHLIB_demos_engines_zencod).hpux32
hpux64: hpux64_demos_engines_zencod
hpux64_demos_engines_zencod:		$(SHLIB_demos_engines_zencod).hpux64
aix: aix_demos_engines_zencod
aix_demos_engines_zencod:		$(SHLIB_demos_engines_zencod).aix

$(LIB_demos_engines_zencod):		$(OBJ_demos_engines_zencod)
		$(AR) $(LIB_demos_engines_zencod) $(OBJ_demos_engines_zencod)
		- $(RANLIB) $(LIB_demos_engines_zencod)

LINK_SO_demos_engines_zencod=	\
  ld -r -o $(LIBNAME_demos_engines_zencod).o $$ALLSYMSFLAGS $(LIB_demos_engines_zencod) && \
  (nm -Pg $(LIBNAME_demos_engines_zencod).o | grep ' [BDT] ' | cut -f1 -d' ' > $(LIBNAME_demos_engines_zencod).exp; \
   $$SHAREDCMD $$SHAREDFLAGS -o $(SHLIB_demos_engines_zencod) $(LIBNAME_demos_engines_zencod).o -L ../../.. -lcrypto -lc)

$(SHLIB_demos_engines_zencod).gnu:	$(LIB_demos_engines_zencod)
		ALLSYMSFLAGS='--whole-archive' \
		SHAREDFLAGS='-shared -Wl,-soname=$(SHLIB_demos_engines_zencod)' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO_demos_engines_zencod)
		touch $(SHLIB_demos_engines_zencod).gnu
$(SHLIB_demos_engines_zencod).tru64:	$(LIB_demos_engines_zencod)
		ALLSYMSFLAGS='-all' \
		SHAREDFLAGS='-shared' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO_demos_engines_zencod)
		touch $(SHLIB_demos_engines_zencod).tru64
$(SHLIB_demos_engines_zencod).solaris:	$(LIB_demos_engines_zencod)
		ALLSYMSFLAGS='-z allextract' \
		SHAREDFLAGS='-G -h $(SHLIB_demos_engines_zencod)' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO_demos_engines_zencod)
		touch $(SHLIB_demos_engines_zencod).solaris
$(SHLIB_demos_engines_zencod).irix:	$(LIB_demos_engines_zencod)
		ALLSYMSFLAGS='-all' \
		SHAREDFLAGS='-shared -Wl,-soname,$(SHLIB_demos_engines_zencod)' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO_demos_engines_zencod)
		touch $(SHLIB_demos_engines_zencod).irix
$(SHLIB_demos_engines_zencod).hpux32:	$(LIB_demos_engines_zencod)
		ALLSYMSFLAGS='-Fl' \
		SHAREDFLAGS='+vnocompatwarnings -b -z +s +h $(SHLIB_demos_engines_zencod)' \
		SHAREDCMD='/usr/ccs/bin/ld'; \
		$(LINK_SO_demos_engines_zencod)
		touch $(SHLIB_demos_engines_zencod).hpux32
$(SHLIB_demos_engines_zencod).hpux64:	$(LIB_demos_engines_zencod)
		ALLSYMSFLAGS='+forceload' \
		SHAREDFLAGS='-b -z +h $(SHLIB_demos_engines_zencod)' \
		SHAREDCMD='/usr/ccs/bin/ld'; \
		$(LINK_SO_demos_engines_zencod)
		touch $(SHLIB_demos_engines_zencod).hpux64
$(SHLIB_demos_engines_zencod).aix:	$(LIB_demos_engines_zencod)
		ALLSYMSFLAGS='-bnogc' \
		SHAREDFLAGS='-G -bE:$(LIBNAME_demos_engines_zencod).exp -bM:SRE' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO_demos_engines_zencod)
		touch $(SHLIB_demos_engines_zencod).aix

.c.o:
	$(CC) $(CFLAGS_demos_engines_zencod) $(CPPFLAGS) -c -o $@ $<
