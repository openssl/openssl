
perl util\mkfiles.pl >MINFO
perl util\mk1mf.pl no-asm VC-WINPHONE >ms\nt.mak
perl util\mk1mf.pl dll no-asm VC-WINPHONE >ms\ntdll.mak
perl util\mkdef.pl 32 libeay > ms\libeay32.def
perl util\mkdef.pl 32 ssleay > ms\ssleay32.def
