$       ! Used by the main descrip.mms to print the statging installation
$       ! complete
$       ! message.
$       ! Arguments:
$       ! P1    staging software installation directory
$       ! P2    staging data installation directory
$       ! P3    final software installation directory
$       ! P4    final data installation directory
$       ! P5    startup / setup / shutdown scripts directory
$       ! P6    distinguishing version number ("major version")
$
$       staging_instdir = p1
$       staging_datadir = p2
$       final_instdir = p3
$       final_datadir = p4
$       systartup = p5
$       osslver = p6
$
$       WRITE SYS$OUTPUT "Staging installation complete"
$       WRITE SYS$OUTPUT ""
$       WRITE SYS$OUTPUT "Finish or package in such a way that the contents of the directory tree"
$       WRITE SYS$OUTPUT staging_instdir
$       WRITE SYS$OUTPUT "ends up in ''final_instdir',"
$       WRITE SYS$OUTPUT "and that the contents of the contents of the directory tree"
$       WRITE SYS$OUTPUT staging_datadir
$       WRITE SYS$OUTPUT "ends up in ''final_datadir"
$       WRITE SYS$OUTPUT ""
$       WRITE SYS$OUTPUT "When in its final destination,"
$       WRITE SYS$OUTPUT "Run @''systartup'openssl_startup''osslver' to set up logical names"
$       WRITE SYS$OUTPUT "then run @''systartup'openssl_utils''osslver' to define commands"
$       WRITE SYS$OUTPUT ""
