use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile being created.
&writeMakefile(
	'potential_libs' => '',   # e.g., '-lm' 
	'INC' => '',     # e.g., '-I/usr/include/other' 
	'DISTNAME' => 'DES',
	'VERSION' => '0.1',
	'DEFINE' => '-DPERL5',
	'OBJECT' => 'DES.o cbc_cksm.o cbc_enc.o ecb_enc.o pcbc_enc.o \
	rand_key.o set_key.o str2key.o \
	enc_read.o enc_writ.o fcrypt.o cfb_enc.o \
	ecb3_enc.o ofb_enc.o cbc3_enc.o des_enc.o',
	);
