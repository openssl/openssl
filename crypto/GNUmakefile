#
# OpenSSL/crypto/GNUmakefile
#

include crypto/Makefile
-include $(SRC_crypto:.c=.d)

# Ensure the "making all in..." announcements are printed, even if there is
# nothing to build.
all_crypto: $(LIBOBJ_crypto) $(foreach dir, $(SDIRS), all_crypto_$(dir)) \
	all_engines

define FIPS_OBJS_RULE_template
fips_objs_$(1)_announce:
	@echo making fips in $(DIR_crypto)/$(1)...
fips: fips_objs_$(1)_announce \
	$(foreach obj, $(shell \
	FIPS_EX_OBJ="$(FIPS_EX_OBJ)"\
	AES_ENC="$(AES_ENC)"\
	BN_ASM="$(BN_ASM)"\
	DES_ENC="$(DES_ENC)"\
	SHA1_ASM_OBJ="$(SHA1_ASM_OBJ)"\
	MODES_ASM_OBJ="$(MODES_ASM_OBJ)"\
	$(PERL) util/fipsobj.pl $(1)), crypto/$(1)/$(obj))
endef

ifdef FIPSCANISTERONLY
$(foreach dir,$(SDIRS),$(eval $(call FIPS_OBJS_RULE_template,$(dir))))
endif

ifdef SHARED_LIBS
$(SHARED_LIB_crypto): $(LIB_crypto)
shared_crypto: $(SHARED_LIB_crypto)
else
all_crypto: $(LIB_crypto)
shared_crypto:
endif

# $(1) is the subdir, $(2) is the target, $(3) is the subdir target.
define CRYPTO_SUBDIR_RULE_template
$(3)_crypto_$(1)_announce:
	@echo "making $(3) in crypto/$(1)..."
$(3)_crypto_$(1): $(3)_crypto_$(1)_announce
$(2): $(3)_crypto_$(1)
endef

$(foreach dir, $(SDIRS), \
  $(eval $(call CRYPTO_SUBDIR_RULE_template,$(dir),all,all)))
$(foreach dir, $(SDIRS), \
  $(eval $(call CRYPTO_SUBDIR_RULE_template,$(dir),files,files)))
$(foreach dir, $(SDIRS), \
  $(eval $(call CRYPTO_SUBDIR_RULE_template,$(dir),links,links)))
$(foreach dir, $(SDIRS), \
  $(eval $(call CRYPTO_SUBDIR_RULE_template,$(dir),libs,lib)))
$(foreach dir, $(SDIRS), \
  $(eval $(call CRYPTO_SUBDIR_RULE_template,$(dir),install,install)))
$(foreach dir, $(SDIRS), \
  $(eval $(call CRYPTO_SUBDIR_RULE_template,$(dir),lint,lint)))
$(foreach dir, $(SDIRS), \
  $(eval $(call CRYPTO_SUBDIR_RULE_template,$(dir),clean,clean)))
$(foreach dir, $(SDIRS), \
  $(eval $(call CRYPTO_SUBDIR_RULE_template,$(dir),dclean,dclean)))

include $(foreach dir, $(SDIRS), crypto/$(dir)/GNUmakefile)

# The LIBOBJ_subdirs dependency of LIB_crypto has to be declared here, after
# including all the other Makefiles. Declaring this dependency in
# crypto/Makefile directly causes LIBOBJ_subdirs to be empty at the time
# prerequisites are calculated.
LIBOBJ_subdirs= $(foreach dir, $(SDIRS), $(LIBOBJ_crypto_$(dir)))
$(LIBOBJ_crypto) $(LIBOBJ_subdirs): crypto/buildinf.h
$(LIB_crypto): $(LIBOBJ_subdirs)

crypto/%.o: crypto/%.c
	$(CC) $(CFLAGS_crypto) $(CPPFLAGS) -c -o $@ $<
crypto/%.o: crypto/%.s
	$(AS) $(ASFLAGS_crypto) -o $@ $<
