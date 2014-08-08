#
# OpenSSL/engines/GNUmakefile
#

include engines/Makefile
-include $(SRC_engines:.c=.d)

# $(1) is the subdir, $(2) is the target, $(3) is the subdir target.
define ENGINES_SUBDIR_RULE_template
$(3)_engines_$(1)_announce:
	@echo "making $(3) in engines/$(1)..."
$(3)_engines_$(1): $(3)_engines_$(1)_announce
$(2): $(3)_engines_$(1)
endef

$(foreach dir, $(ENGDIRS), \
  $(eval $(call ENGINES_SUBDIR_RULE_template,$(dir),engines/subdirs,all)))
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

engines/%.o: engines/%.c
	$(CC) $(CFLAGS_engines) $(CPPFLAGS) -c -o $@ $<
engines/%.o: engines/%.s
	$(AS) $(ASFLAGS_engines) -o $@ $<
