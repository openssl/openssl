AUTOMAKE_OPTIONS = foreign
noinst_LTLIBRARIES = libsidhmsr.la

libsidhmsr_la_SOURCES = kex_sidh_msr.c P503/P503.c P751/P751.c sha3/fips202.c

libsidhmsr_la_CPPFLAGS = -I../../include -I.-fPIC -w
libsidhmsr_la_CPPFLAGS += $(AM_CPPFLAGS) 
