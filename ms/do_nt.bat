
perl util\mkfiles.pl >MINFO
perl util\mk1mf.pl VC-NT no-asm >ms\nt.mak
perl util\mk1mf.pl VC-NT dll no-asm >ms\ntdll.mak

perl util\mkdef.pl NT libeay > ms\libeay32.def
perl util\mkdef.pl NT ssleay > ms\ssleay32.def
