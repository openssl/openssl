
perl util\mkfiles.pl >MINFO
perl util\mk1mf.pl nasm VC-CORE32 >ms\nt.mak
perl util\mk1mf.pl dll nasm VC-CORE32 >ms\ntdll.mak
perl util\mkdef.pl 32 libeay > ms\libeay32.def
perl util\mkdef.pl 32 ssleay > ms\ssleay32.def
