perl Configure BC-32
perl util\mkfiles.pl > MINFO

@rem create make file
perl util\mk1mf.pl BC-NT no-asm > bcb.mak

