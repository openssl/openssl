use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
	'OPTIMIZE'	=> '-g',
	'DISTNAME'	=> 'SSLeay-perl5-0.8.5',
	'NAME'		=> 'SSLeay',
	'VERSION_FROM'	=> 'SSLeay.pm',
	'LIBS'		=> ['-L.. -lssl -lcrypto'],
	'DEFINE'	=> '',
	'INC'		=> '-I../include',
	'C'		=> ['callback.c'],
	'H'		=> ['p5SSLeay.h'],
	'OBJECT'	=> "	SSLeay.o bio.o bn.o cipher.o digest.o err.o 
				ssl.o x509.o",
	'XS'		=> {	'SSLeay.xs'	=>	'SSLeay.c',
				'bio.xs'	=>	'bio.c',
				'bn.xs'		=>	'bn.c',
				'cipher.xs'	=>	'cipher.c',
				'digest.xs'	=>	'digest.c',
				'err.xs'	=>	'err.c',
				'ssl.xs'	=>	'ssl.c',
				'x509.xs'	=>	'x509.c',
				}
	);
