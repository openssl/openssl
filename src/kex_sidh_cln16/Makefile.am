AUTOMAKE_OPTIONS = foreign
noinst_LTLIBRARIES = libcln16.la


libcln16_la_SOURCES = ec_isogeny.c fpx.c kex_sidh_cln16.c SIDH.c sidh_kex.c SIDH_setup.c

if X86_64
libcln16_la_SOURCES += AMD64/fp_x64.c AMD64/fp_x64_asm.S
else
if ARM64
libcln16_la_SOURCES += ARM64/fp_arm64.c ARM64/fp_arm64_asm.S
else
libcln16_la_SOURCES += generic/fp_generic.c
endif
endif

libcln16_la_CPPFLAGS = -I../../include -I.-fPIC -w
libcln16_la_CPPFLAGS += $(AM_CPPFLAGS) 
