#
# OpenSSL/engines/ccgost/GNUmakefile
#

include engines/ccgost/Makefile
-include $(SRC_engines_ccgost:.c=.d)

all_engines_ccgost: $(LIBOBJ_engines_ccgost)

ifdef SHARED_LIBS
all_engines_ccgost: engines/ccgost/lib
engines/ccgost/lib: $(LIBOBJ_engines_ccgost)
	cat configure.mk Makefile.shared | $(MAKE) -f - \
		LIBNAME=$(LIBNAME_engines_ccgost) \
		LIBEXTRAS='$(LIBOBJ_engines_ccgost)' \
		LIBDEPS='-L. -lcrypto' \
		link_o.$(SHLIB_TARGET)
	touch engines/ccgost/lib
endif

engines/ccgost/%.o: engines/ccgost/%.c
	$(CC) $(CFLAGS_engines_ccgost) $(CPPFLAGS) -c -o $@ $<
