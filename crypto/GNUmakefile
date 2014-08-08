#
# OpenSSL/crypto/GNUmakefile
#

include crypto/Makefile
-include $(SRC_crypto:.c=.d)

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
$(SHARED_LIB_crypto): crypto/buildinf.h crypto/lib crypto/subdirs
shared_crypto: $(SHARED_LIB_crypto)
else
all_crypto: crypto/buildinf.h crypto/lib crypto/subdirs
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
  $(eval $(call CRYPTO_SUBDIR_RULE_template,$(dir),crypto/subdirs,all)))
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

# TODO(mbland): add all of the crypto/*/lib target objects into
# $(LIB_crypto) to allow parallelism.

crypto/%.o: crypto/%.c
	$(CC) $(CFLAGS_crypto) $(CPPFLAGS) -c -o $@ $<
crypto/%.o: crypto/%.s
	$(AS) $(ASFLAGS_crypto) -o $@ $<
