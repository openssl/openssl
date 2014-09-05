##
## GNUmakefile for OpenSSL
##

include configure.mk
include Makefile

# $(1) is the target, $(2) is the subdir.
define DIRS_ANNOUNCE_template
$(1)_$(2)_announce:
	@echo "making $(1) in $(2)..."
$(1)_$(2): $(1)_$(2)_announce
endef

$(foreach dir, $(DIRS), $(eval $(call DIRS_ANNOUNCE_template,all,$(dir))))

include $(foreach dir, $(DIRS), $(dir)/GNUmakefile)

all_engines: AS= $(CC) -c

ifdef FIPSCANLIB
$(LIB_crypto): ARX = EXCL_OBJ="$(AES_ENC) $(BN_ASM) $(DES_ENC) $(CPUID_OBJ) \
	$(SHA1_ASM_OBJ) $(MODES_ASM_OBJ) $(FIPS_EX_OBJ)" \
	$(PERL) $${TOP}/util/arx.pl $(AR)
build_fips: all_fips
else
$(LIB_crypto): ARX = $(AR)
build_fips:
endif

ifeq ($(FIPSCANISTERINTERNAL), "y")
all_crypto: AS=
else
all_crypto: AS= $(CC) -c
endif
