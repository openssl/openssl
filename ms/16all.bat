set OPTS=no_asm

perl Configure VC-WIN16
perl util\mk1mf.pl %OPTS% debug VC-WIN16 >d16.mak
perl util\mk1mf.pl %OPTS% VC-WIN16 >16.mak
perl util\mk1mf.pl %OPTS% debug dll VC-WIN16 >d16dll.mak
perl util\mk1mf.pl %OPTS% dll VC-WIN16 >16dll.mak

nmake -f d16.mak
nmake -f 16.mak
nmake -f d16dll.mak
nmake -f 16dll.mak
