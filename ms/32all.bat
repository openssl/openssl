set OPTS=no_asm

perl Configure VC-WIN32
perl util\mk1mf.pl %OPTS% debug VC-WIN32 >d32.mak
perl util\mk1mf.pl %OPTS% VC-WIN32 >32.mak
perl util\mk1mf.pl %OPTS% debug dll VC-WIN32 >d32dll.mak
perl util\mk1mf.pl %OPTS% dll VC-WIN32 >32dll.mak

nmake -f d32.mak
nmake -f 32.mak
nmake -f d32dll.mak
nmake -f 32dll.mak
