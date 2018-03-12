AUTOMAKE_OPTIONS = foreign
noinst_LTLIBRARIES = libpicnic_i.la

libpicnic_i_la_SOURCES = sig_picnic.c external/aligned_alloc.c external/bitstream.c external/cpu.c external/io.c external/kdf_shake.c external/lowmc.c external/lowmc_pars.c external/lowmc_128_128_20.c external/lowmc_192_192_30.c external/lowmc_256_256_38.c external/mpc.c external/mpc_lowmc.c external/mzd_additional.c external/picnic.c external/picnic_impl.c external/sha3/KeccakHash.c external/sha3/KeccakSponge.c external/sha3/opt64/KeccakP-1600-opt64.c
libpicnic_i_la_CPPFLAGS = -I../../include -Iexternal -Iexternal/sha3 -Iexternal/sha3/opt64 -DMUL_M4RI -DREDUCED_LINEAR_LAYER -DHAVE_POSIX_MEMALIGN -DWITH_LOWMC_128_128_20 -DWITH_LOWMC_192_192_30 -DWITH_LOWMC_256_256_38 -DWITH_OPT
if !ARM
libpicnic_i_la_CPPFLAGS += -DWITH_SSE2 -DWITH_SSE4_1
endif
libpicnic_i_la_CPPFLAGS += $(AM_CPPFLAGS) 

