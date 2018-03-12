AUTOMAKE_OPTIONS = foreign
noinst_LTLIBRARIES = librand.la

librand_la_SOURCES = rand.c

librand_la_CPPFLAGS = -I../../../include
if USE_OPENSSL
librand_la_CPPFLAGS += -I$(OPENSSL_DIR)/include
endif
librand_la_CPPFLAGS += $(AM_CPPFLAGS)

librand_la_LDFLAGS =
if USE_OPENSSL
librand_la_LDFLAGS += -L$(OPENSSL_DIR)/lib
endif
librand_la_LDFLAGS += $(AM_LDFLAGS)
