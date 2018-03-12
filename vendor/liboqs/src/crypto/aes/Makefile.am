AUTOMAKE_OPTIONS = foreign
noinst_LTLIBRARIES = libaes.la

libaes_la_SOURCES = aes.c

libaes_la_CPPFLAGS = -I../../../include
if USE_OPENSSL
libaes_la_CPPFLAGS += -I$(OPENSSL_DIR)/include
endif

if USE_AES_NI
libaes_la_CPPFLAGS += -maes -msse2
libaes_la_SOURCES += aes_ni.c
endif

libaes_la_SOURCES += aes_c.c
libaes_la_CPPFLAGS += $(AM_CPPFLAGS)

