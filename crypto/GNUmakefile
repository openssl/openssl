#
# OpenSSL/crypto/GNUmakefile
#

include $(TOP_crypto)/configure.mk
include Makefile
-include $(SRC_crypto:.c=.d)

define FIPS_OBJS_RULE_template
fips_objs_$(1):
	@cd $(1) && echo making fips in $(DIR_crypto)/$(1)... && \
	$(MAKE) -e TOP=../.. DIR=$(1) INCLUDES_crypto_$(1)='$(INCLUDES_crypto)' \
	`FIPS_EX_OBJ="$(FIPS_EX_OBJ)"\
	AES_ENC="$(AES_ENC)"\
	BN_ASM="$(BN_ASM)"\
	DES_ENC="$(DES_ENC)"\
	SHA1_ASM_OBJ="$(SHA1_ASM_OBJ)"\
	MODES_ASM_OBJ="$(MODES_ASM_OBJ)"\
	$(PERL) $(TOP_crypto)/../util/fipsobj.pl $(1)`

fips: fips_objs_$(1)
endef

$(foreach dir,$(SDIRS),$(eval $(call FIPS_OBJS_RULE_template,$(dir))))

# $(1) is the subdir, $(2) is the target, $(3) is the subdir target.
define CRYPTO_SUBDIR_RULE_template
$(2)_crypto_$(1):
	@cd $(1) && echo "making $(3) in crypto/$(1)..." && \
	$(MAKE) -e TOP=../.. DIR=$(1) INCLUDES_crypto_$(1)='$(INCLUDES_crypto)' \
	$(3)

$(2): $(2)_crypto_$(1)
endef

$(foreach dir, $(SDIRS), \
  $(eval $(call CRYPTO_SUBDIR_RULE_template,$(dir),subdirs,all)))
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
