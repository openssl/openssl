# Our includes come from the OpenSSL build-tree we're in
INCLUDES		= -I$(top_builddir)/../../include

lib_LTLIBRARIES		= libtunala.la

libtunala_la_SOURCES	= buffer.c cb.c ip.c sm.c breakage.c

bin_PROGRAMS		= tunala

tunala_SOURCES		= tunala.c
tunala_LDADD		= libtunala.la -L$(top_builddir)/../.. -lssl -lcrypto
