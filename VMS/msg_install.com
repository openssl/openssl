$       ! Used by the main descrip.mms to print the installation complete
$       ! message.
$       ! Arguments:
$       ! P1    startup / setup / shutdown scripts directory
$       ! P2    distinguishing version number ("major version")
$
$       systartup = p1
$       osslver = p2
$
$       WRITE SYS$OUTPUT "Installation complete"
$       WRITE SYS$OUTPUT ""
$       WRITE SYS$OUTPUT "Run @''systartup'openssl_startup''osslver' to set up logical names"
$       WRITE SYS$OUTPUT "then run @''systartup'openssl_utils''osslver' to define commands"
$       WRITE SYS$OUTPUT ""
