AUTOMAKE_OPTIONS = foreign
noinst_LTLIBRARIES = libpicnic.la


libpicnic_la_SOURCES = sig_picnic.c external/Picnic-master/picnic.c external/Picnic-master/LowMCEnc.c external/Picnic-master/LowMC.c
libpicnic_la_CPPFLAGS = -march=native -I$(OPENSSL_DIR)/include -I../../include -Iexternal/Picnic-master
#libpicnic_la_CPPFLAGS += $(AM_CPPFLAGS) 
libpicnic_la_CPPFLAGS += -std=c99 

