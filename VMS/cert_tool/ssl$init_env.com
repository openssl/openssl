$!
$!------------------------------------------------------------------------------
$! SSL$INIT_ENV.COM - SSL Initialize Environment
$!------------------------------------------------------------------------------
$!
$ Verify = F$VERIFY (0)
$ Set NoOn
$!
$!------------------------------------------------------------------------------
$! Description 
$!------------------------------------------------------------------------------
$!
$! This procedure sets up the SSL environment logicals & symbols.
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
$ DEFINE 'P1 	SSL$CA_CONF	SSL$ROOT:[CONF]SSL$CA.CNF
$ DEFINE 'P1 	SSL$CONF	SSL$ROOT:[CONF]SSL$CERT.CNF
$ DEFINE 'P1 	SSL$COM		SSL$ROOT:[COM]
$ DEFINE 'P1	SSL$CRT		SSL$ROOT:[CERTS]
$ DEFINE 'P1 	SSL$CSR		SSL$ROOT:[CERTS]
$ DEFINE 'P1 	SSL$KEY		SSL$ROOT:[CERTS]
$ DEFINE 'P1 	SSL$DB		SSL$ROOT:[PRIVATE]
$!
$!------------------------------------------------------------------------------
$! Define foreign symbols
$!------------------------------------------------------------------------------
$!
$ OPENSSL	:== $ SSL$EXE:OPENSSL
$ HOSTADDR	:== $ SSL$EXE:SSL$HOSTADDR
$ HOSTNAME	:== $ SSL$EXE:SSL$HOSTNAME
$!
$!------------------------------------------------------------------------------
$! Exit
$!------------------------------------------------------------------------------
$!
$ EXIT
