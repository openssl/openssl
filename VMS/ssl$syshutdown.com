$!
$! SSL$SYSHUTDOWN.COM - This command procedure is used for site specific SSL
$!			shutdown tasks.  Anything setup in SSL$SYSTARTUP.COM
$!			should be cleaned up in this command procedure.
$!
$ DEASSIGN/SYSTEM/EXEC  RANDFILE
$ DEASSIGN/SYSTEM/EXEC  SSL$RANDFILE
$!
