#
# OpenSSL/engines/GNUmakefile
#

include engines/Makefile
-include $(SRC_engines:.c=.d)

# $(1) is the subdir, $(2) is the target, $(3) is the subdir target.
define ENGINES_SUBDIR_RULE_template
$(2)_engines_$(1):
	@cd $(1) && echo "making $(3) in engines/$(1)..." && \
	$(MAKE) -e TOP=../.. DIR=$(1) $(3)

$(2): $(2)_engines_$(1)
endef

$(foreach dir, $(ENGDIRS), \
  $(eval $(call ENGINES_SUBDIR_RULE_template,$(dir),subdirs,all)))
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
