AUTOMAKE_OPTIONS = foreign
noinst_LTLIBRARIES = libsidhiqc.la


libsidhiqc_la_SOURCES = kex_sidh_iqc_ref_params.c kex_sidh_iqc_ref.c sidh_elliptic_curve.c sidh_elliptic_curve_dlp.c sidh_isogeny.c
libsidhiqc_la_SOURCES += sidh_private_key.c sidh_public_key.c sidh_public_key_encryption.c sidh_public_key_validation.c
libsidhiqc_la_SOURCES += sidh_public_param.c sidh_quadratic_ext.c sidh_shared_key.c sidh_util.c
libsidhiqc_la_CPPFLAGS = -I../../include -I.-fPIC
libsidhiqc_la_CPPFLAGS += $(AM_CPPFLAGS) -I$(GMP_DIR)/include

libsidhiqc_la_LDFLAGS = -L$(GMP_DIR)/lib $(AM_LDFLAGS)
