$!
$!------------------------------------------------------------------------------
$! SSL$REM_ENV.COM - Remove the SSL Initialize Environment
$!------------------------------------------------------------------------------
$!
$ Verify = F$VERIFY (0)
$ Set NoOn
$!
$!------------------------------------------------------------------------------
$! Description 
$!------------------------------------------------------------------------------
$!
$! This procedure deletes the SSL environment logicals & symbols set up by
$! SSL$INIT_ENV.COM.
$!
$! P1 = Mode of the logicals (ie - "/SYSTEM/EXECUTIVE_MODE").
$!      Note - if P1 is not passed in, P1 will default to PROCESS.
$!
$!------------------------------------------------------------------------------
$! Initialization 
$!------------------------------------------------------------------------------
$!
$ IF F$TRNLNM("SSL$ROOT") .EQS. ""
$ THEN
$    WRITE SYS$OUTPUT " "
$    WRITE SYS$OUTPUT " SSL-E-ERROR, SSL has not been started."
$    WRITE SYS$OUTPUT " "
$    WRITE SYS$OUTPUT " Execute the command procedure, SYS$STARTUP:SSL$STARTUP.COM, and then try this procedure again."
$    WRITE SYS$OUTPUT " "
$    EXIT
$ ENDIF
$!
$ IF P1 .EQS. ""
$ THEN
$    P1 = "/PROCESS"
$ ENDIF
$!
$!------------------------------------------------------------------------------
$! Define logicals
$!------------------------------------------------------------------------------
$!
$ DEASSIGN 'P1 	SSL$CA_CONF
$ DEASSIGN 'P1 	SSL$CONF
$ DEASSIGN 'P1 	SSL$COM
$ DEASSIGN 'P1	SSL$CRT
$ DEASSIGN 'P1 	SSL$CSR
$ DEASSIGN 'P1 	SSL$KEY
$ DEASSIGN 'P1 	SSL$DB
$!
$!------------------------------------------------------------------------------
$! Define foreign symbols
$!------------------------------------------------------------------------------
$!
$ DELETE/SYMBOL/GLOBAL OPENSSL
$ DELETE/SYMBOL/GLOBAL HOSTADDR
$ DELETE/SYMBOL/GLOBAL HOSTNAME
$!
$!------------------------------------------------------------------------------
$! Exit
$!------------------------------------------------------------------------------
$!
$ EXIT
