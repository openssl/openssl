
perl util\mkfiles.pl >MINFO
perl util\mk1mf.pl no-asm %1 VC-NT >ms\nt.mak
perl util\mk1mf.pl dll no-asm %1 VC-NT >ms\ntdll.mak

perl util\mkdef.pl libeay NT > ms\libeay32.def
perl util\mkdef.pl ssleay NT > ms\ssleay32.def
