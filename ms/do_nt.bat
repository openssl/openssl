
perl util\mkfiles.pl >MINFO
perl util\mk1mf.pl no-asm VC-NT >ms\nt.mak
perl util\mk1mf.pl dll no-asm VC-NT >ms\ntdll.mak

perl util\mkdef.pl libcrypto NT > ms\libcrypto32.def
perl util\mkdef.pl libssl NT > ms\libssl32.def
