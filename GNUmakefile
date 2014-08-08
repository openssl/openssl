##
## GNUmakefile for OpenSSL
##

include configure.mk
include Makefile
all_engines: AS= $(CC) -c

ifdef FIPSCANLIB
all_crypto: EXCL_OBJ=
all_crypto: ARX= EXCL_OBJ="$(AES_ENC) $(BN_ASM) $(DES_ENC) $(CPUID_OBJ) \
	$(SHA1_ASM_OBJ) $(MODES_ASM_OBJ) $(FIPS_EX_OBJ)" \
	$(PERL) $${TOP}/util/arx.pl $(AR)
build_fips: all_fips
else
all_crypto: ARX=$(AR)
build_fips:
endif

ifeq ($(FIPSCANISTERINTERNAL), "y")
all_crypto: AS=
else
all_crypto: AS= $(CC) -c
endif

# $(1) is the subdir, $(2) is the target.
define DIRS_ANNOUNCE_template
$(2)_$(1)_announce:
	@echo "making $(2) in $(1)..."
$(2)_$(1): $(2)_$(1)_announce
endef

$(foreach dir, $(DIRS), $(eval $(call DIRS_ANNOUNCE_template,$(dir),all)))

include $(foreach dir, $(DIRS), $(dir)/GNUmakefile)
