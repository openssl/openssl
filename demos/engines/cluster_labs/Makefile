LIBNAME_demos_engines_cluster_labs=	libclabs
SRC_demos_engines_cluster_labs=		demos/engines/cluster_labs/hw_cluster_labs.c
OBJ_demos_engines_cluster_labs=		demos/engines/cluster_labs/hw_cluster_labs.o
HEADER_demos_engines_cluster_labs=		demos/engines/cluster_labs/hw_cluster_labs.h

PIC_demos_engines_cluster_labs=		-fPIC
CFLAGS_demos_engines_cluster_labs=		-g -I../../../include $(PIC_demos_engines_cluster_labs) -DENGINE_DYNAMIC_SUPPORT -DFLAT_INC

LIB_demos_engines_cluster_labs=		$(LIBNAME_demos_engines_cluster_labs).a
SHLIB_demos_engines_cluster_labs=		$(LIBNAME_demos_engines_cluster_labs).so

all: all_demos_engines_cluster_labs
all_demos_engines_cluster_labs:
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

FORCE.update: FORCE.update_demos_engines_cluster_labs
FORCE.update_demos_engines_cluster_labs:
update: update_demos_engines_cluster_labs
update_demos_engines_cluster_labs:		FORCE.update_demos_engines_cluster_labs
		perl util/mkerr.pl -conf hw_cluster_labs.ec \
			-nostatic -staticloader -write demos/engines/cluster_labs/hw_cluster_labs.c

gnu: gnu_demos_engines_cluster_labs
gnu_demos_engines_cluster_labs:		$(SHLIB_demos_engines_cluster_labs).gnu
tru64: tru64_demos_engines_cluster_labs
tru64_demos_engines_cluster_labs:		$(SHLIB_demos_engines_cluster_labs).tru64
solaris: solaris_demos_engines_cluster_labs
solaris_demos_engines_cluster_labs:	$(SHLIB_demos_engines_cluster_labs).solaris
irix: irix_demos_engines_cluster_labs
irix_demos_engines_cluster_labs:		$(SHLIB_demos_engines_cluster_labs).irix
hpux32: hpux32_demos_engines_cluster_labs
hpux32_demos_engines_cluster_labs:		$(SHLIB_demos_engines_cluster_labs).hpux32
hpux64: hpux64_demos_engines_cluster_labs
hpux64_demos_engines_cluster_labs:		$(SHLIB_demos_engines_cluster_labs).hpux64
aix: aix_demos_engines_cluster_labs
aix_demos_engines_cluster_labs:		$(SHLIB_demos_engines_cluster_labs).aix

$(LIB_demos_engines_cluster_labs):		$(OBJ_demos_engines_cluster_labs)
		$(AR) $(LIB_demos_engines_cluster_labs) $(OBJ_demos_engines_cluster_labs)
		- $(RANLIB) $(LIB_demos_engines_cluster_labs)

LINK_SO_demos_engines_cluster_labs=	\
  ld -r -o $(LIBNAME_demos_engines_cluster_labs).o $$ALLSYMSFLAGS $(LIB_demos_engines_cluster_labs) && \
  (nm -Pg $(LIBNAME_demos_engines_cluster_labs).o | grep ' [BDT] ' | cut -f1 -d' ' > $(LIBNAME_demos_engines_cluster_labs).exp; \
   $$SHAREDCMD $$SHAREDFLAGS -o $(SHLIB_demos_engines_cluster_labs) $(LIBNAME_demos_engines_cluster_labs).o -L ../../.. -lcrypto -lc)

$(SHLIB_demos_engines_cluster_labs).gnu:	$(LIB_demos_engines_cluster_labs)
		ALLSYMSFLAGS='--whole-archive' \
		SHAREDFLAGS='-shared -Wl,-soname=$(SHLIB_demos_engines_cluster_labs)' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO_demos_engines_cluster_labs)
		touch $(SHLIB_demos_engines_cluster_labs).gnu
$(SHLIB_demos_engines_cluster_labs).tru64:	$(LIB_demos_engines_cluster_labs)
		ALLSYMSFLAGS='-all' \
		SHAREDFLAGS='-shared' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO_demos_engines_cluster_labs)
		touch $(SHLIB_demos_engines_cluster_labs).tru64
$(SHLIB_demos_engines_cluster_labs).solaris:	$(LIB_demos_engines_cluster_labs)
		ALLSYMSFLAGS='-z allextract' \
		SHAREDFLAGS='-G -h $(SHLIB_demos_engines_cluster_labs)' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO_demos_engines_cluster_labs)
		touch $(SHLIB_demos_engines_cluster_labs).solaris
$(SHLIB_demos_engines_cluster_labs).irix:	$(LIB_demos_engines_cluster_labs)
		ALLSYMSFLAGS='-all' \
		SHAREDFLAGS='-shared -Wl,-soname,$(SHLIB_demos_engines_cluster_labs)' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO_demos_engines_cluster_labs)
		touch $(SHLIB_demos_engines_cluster_labs).irix
$(SHLIB_demos_engines_cluster_labs).hpux32:	$(LIB_demos_engines_cluster_labs)
		ALLSYMSFLAGS='-Fl' \
		SHAREDFLAGS='+vnocompatwarnings -b -z +s +h $(SHLIB_demos_engines_cluster_labs)' \
		SHAREDCMD='/usr/ccs/bin/ld'; \
		$(LINK_SO_demos_engines_cluster_labs)
		touch $(SHLIB_demos_engines_cluster_labs).hpux32
$(SHLIB_demos_engines_cluster_labs).hpux64:	$(LIB_demos_engines_cluster_labs)
		ALLSYMSFLAGS='+forceload' \
		SHAREDFLAGS='-b -z +h $(SHLIB_demos_engines_cluster_labs)' \
		SHAREDCMD='/usr/ccs/bin/ld'; \
		$(LINK_SO_demos_engines_cluster_labs)
		touch $(SHLIB_demos_engines_cluster_labs).hpux64
$(SHLIB_demos_engines_cluster_labs).aix:	$(LIB_demos_engines_cluster_labs)
		ALLSYMSFLAGS='-bnogc' \
		SHAREDFLAGS='-G -bE:$(LIBNAME_demos_engines_cluster_labs).exp -bM:SRE' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO_demos_engines_cluster_labs)
		touch $(SHLIB_demos_engines_cluster_labs).aix

