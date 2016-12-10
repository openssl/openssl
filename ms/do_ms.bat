
perl util\mkfiles.pl >MINFO
rem perl util\mk1mf.pl no-sock %1 VC-MSDOS >ms\msdos.mak
rem perl util\mk1mf.pl %1 VC-W31-32 >ms\w31.mak
rem perl util\mk1mf.pl dll %1 VC-W31-32 >ms\w31dll.mak
perl util\mk1mf.pl no-asm %1 VC-WIN32 >ms\nt.mak
perl util\mk1mf.pl dll no-asm %1 VC-WIN32 >ms\ntdll.mak
perl util\mk1mf.pl no-asm %1 VC-CE >ms\ce.mak
perl util\mk1mf.pl dll no-asm %1 VC-CE >ms\cedll.mak

perl util\mkdef.pl 16 libeay %1 > ms\libeay16.def
perl util\mkdef.pl 32 libeay %1 > ms\libeay32.def
perl util\mkdef.pl 16 ssleay %1 > ms\ssleay16.def
perl util\mkdef.pl 32 ssleay %1 > ms\ssleay32.def
