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
else
all_crypto: ARX=$(AR)
endif

ifeq ($(FIPSCANISTERINTERNAL), "y")
all_crypto: AS=
else
all_crypto: AS= $(CC) -c
endif

include $(foreach dir, $(DIRS), $(dir)/GNUmakefile)
