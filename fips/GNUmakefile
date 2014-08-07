#
# OpenSSL/fips/GNUmakefile
#

include fips/Makefile

ifdef FIPSCANISTERONLY
all_fips: subdirs_fips lib
else ifndef FIPSLIBDIR
all_fips: subdirs_fips lib fips_premain_dso$(EXE_EXT)
else
all_fips: lib fips_premain_dso$(EXE_EXT) fips_standalone_sha1$(EXE_EXT)
include fips_standalone_sha1.mk
endif

-include $(SRC_fips:.c=.d)

# $(1) is the subdir, $(2) is the target, $(3) is the subdir target.
define FIPS_SUBDIR_RULE_template
$(2)_fips_$(1):
	@cd $(1) && echo "making $(3) in fips/$(1)..." && \
	$(MAKE) -e TOP=../.. DIR=$(1) INCLUDES_fips_$(1)='$(INCLUDES_fips)' \
	$(3)

$(2): $(2)_fips_$(1)
endef

$(foreach dir, $(FDIRS), \
  $(eval $(call FIPS_SUBDIR_RULE_template,$(dir),subdirs,all)))
$(foreach dir, $(FDIRS), \
  $(eval $(call FIPS_SUBDIR_RULE_template,$(dir),files,files)))
$(foreach dir, $(FDIRS), \
  $(eval $(call FIPS_SUBDIR_RULE_template,$(dir),links,links)))
$(foreach dir, $(FDIRS), \
  $(eval $(call FIPS_SUBDIR_RULE_template,$(dir),libs,lib)))
$(foreach dir, $(FDIRS), \
  $(eval $(call FIPS_SUBDIR_RULE_template,$(dir),fips_test,fips_test)))
$(foreach dir, $(FDIRS), \
  $(eval $(call FIPS_SUBDIR_RULE_template,$(dir),install,install)))
$(foreach dir, $(FDIRS), \
  $(eval $(call FIPS_SUBDIR_RULE_template,$(dir),lint,lint)))
$(foreach dir, $(FDIRS), \
  $(eval $(call FIPS_SUBDIR_RULE_template,$(dir),clean,clean)))
$(foreach dir, $(FDIRS), \
  $(eval $(call FIPS_SUBDIR_RULE_template,$(dir),dclean,dclean)))

INSTALL_FIPS_SUBDIRS_TARGETS= $(foreach dir, $(FDIRS), install_fips_$(dir))
$(INSTALL_FIPS_SUBDIRS_TARGETS): install_fips_before_subdirs
install_fips_subdirs: $(INSTALL_FIPS_SUBDIRS_TARGETS)

fips/%.o: fips/%.c
	$(CC) $(CFLAGS_fips) $(CPPFLAGS) -c -o $@ $<
fips/%.o: fips/%.s
	$(AS) $(ASFLAGS_fips) -o $@ $<
