
rem perl util\mk1mf.pl VC-MSDOS no-sock >ms\msdos.mak
rem perl util\mk1mf.pl VC-W31-32 >ms\w31.mak
perl util\mk1mf.pl VC-W31-32 dll >ms\w31dll.mak
rem perl util\mk1mf.pl VC-WIN32 >ms\nt.mak
perl util\mk1mf.pl VC-WIN32 dll >ms\ntdll.mak

perl util\mkdef.pl 16 libeay > ms\libeay16.def
perl util\mkdef.pl 32 libeay > ms\libeay32.def
perl util\mkdef.pl 16 ssleay > ms\ssleay16.def
perl util\mkdef.pl 32 ssleay > ms\ssleay32.def
