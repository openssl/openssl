#
# OpenSSL/engines/GNUmakefile
#

include engines/Makefile
-include $(SRC_engines:.c=.d)

ifdef SHARED_LIBS
all_engines:	engines/lib
engines/lib:	$(LIB_crypto)
	set -e; \
	for l in $(LIBNAMES); do \
		cat configure.mk Makefile.shared | $(MAKE) -f - \
			LIBNAME=$$l LIBEXTRAS="e_$$l*.o" \
			LIBDEPS='-L.. -lcrypto $(EX_LIBS)' \
			link_o.$(SHLIB_TARGET); \
	done; \
	touch engines/lib
else
all_engines:	$(LIB_crypto)
endif


# $(1) is the subdir, $(2) is the target, $(3) is the subdir target.
define ENGINES_SUBDIR_RULE_template
$(3)_engines_$(1)_announce:
	@echo "making $(3) in engines/$(1)..."
$(3)_engines_$(1): $(3)_engines_$(1)_announce
$(2): $(3)_engines_$(1)
endef

$(foreach dir, $(ENGDIRS), \
  $(eval $(call ENGINES_SUBDIR_RULE_template,$(dir),files,files)))
$(foreach dir, $(ENGDIRS), \
  $(eval $(call ENGINES_SUBDIR_RULE_template,$(dir),links,links)))
$(foreach dir, $(ENGDIRS), \
  $(eval $(call ENGINES_SUBDIR_RULE_template,$(dir),install,install)))
$(foreach dir, $(ENGDIRS), \
  $(eval $(call ENGINES_SUBDIR_RULE_template,$(dir),lint,lint)))
$(foreach dir, $(ENGDIRS), \
  $(eval $(call ENGINES_SUBDIR_RULE_template,$(dir),clean,clean)))
$(foreach dir, $(ENGDIRS), \
  $(eval $(call ENGINES_SUBDIR_RULE_template,$(dir),dclean,dclean)))

include $(foreach dir, $(ENGDIRS), engines/$(dir)/GNUmakefile)

# The LIBOBJ_engdirs dependency of LIB_crypto has to be declared here, after
# including all the other Makefiles. Declaring this dependency in
# crypto/Makefile directly causes LIBOBJ_engdirs to be empty at the time
# prerequisites are calculated.
LIBOBJ_engdirs= $(foreach dir, $(ENGDIRS), $(LIBOBJ_engines_$(dir)))
$(LIBOBJ_engines) $(LIBOBJ_engdirs): crypto/buildinf.h
$(LIB_crypto): $(LIBOBJ_engines) $(LIBOBJ_engdirs)

engines/%.o: engines/%.c
	$(CC) $(CFLAGS_engines) $(CPPFLAGS) -c -o $@ $<
engines/%.o: engines/%.s
	$(AS) $(ASFLAGS_engines) -o $@ $<
