$!
$!------------------------------------------------------------------------------
$! SSL$AUTO_CERT.COM - SSL Automatic Self-Signed Certificate procedure
$!------------------------------------------------------------------------------
$!
$ Verify = F$VERIFY (0)
$!
$ Set NoOn
$ Set NoControl=Y
$!
$!------------------------------------------------------------------------------
$! Define Symbols
$!------------------------------------------------------------------------------
$! 
$ OPENSSL       :== $ SSL$EXE:OPENSSL
$ HOSTNAME      :== $ SSL$EXE:SSL$HOSTNAME
$!
$ HOSTNAME -s HOST_NAME
$ PID = F$GETJPI ("","PID")
$ USER = F$EDIT (F$GETJPI ("","USERNAME"),"TRIM")
$ KEY_FILE = "SSL$KEY:SERVER.KEY"
$ CRT_FILE = "SSL$CRT:SERVER.CRT"
$!
$!------------------------------------------------------------------------------
$! Create a Temporary SSL Configuration
$!------------------------------------------------------------------------------
$!
$ OPEN /WRITE CFILE SYS$LOGIN:SSL_'PID'.CNF
$ WRITE CFILE "[req]"
$ WRITE CFILE "default_bits = 1024"
$ WRITE CFILE "distinguished_name = REQ_distinguished_name"
$ WRITE CFILE "[REQ_distinguished_name]"
$ WRITE CFILE "countryName = Country Name ?"
$ WRITE CFILE "countryName_default = "
$ WRITE CFILE "stateOrProvinceName = State or Province Name ?"
$ WRITE CFILE "stateOrProvinceName_default = "
$ WRITE CFILE "localityName = City Name ?"
$ WRITE CFILE "localityName_default = "
$ WRITE CFILE "0.organizationName = Organization Name ?"
$ WRITE CFILE "0.organizationName_default = "
$ WRITE CFILE "organizationalUnitName = Organization Unit Name ?
$ WRITE CFILE "organizationalUnitName_default = "
$ WRITE CFILE "commonName = Common Name ?"
$ WRITE CFILE "commonName_default = ''HOST_NAME'"
$ WRITE CFILE "emailAddress = Email Address ?"
$ WRITE CFILE "emailAddress_default = ''USER'@''HOST_NAME'"
$ CLOSE CFILE
$!
$!------------------------------------------------------------------------------
$! Create the Self-Signed Server Certificiate
$!------------------------------------------------------------------------------
$!
$ DEFINE /USER /NOLOG SYS$ERROR  NL:
$ DEFINE /USER /NOLOG SYS$OUTPUT NL:
$ SHOW SYSTEM /FULL /OUT=SYS$LOGIN:SSL_'PID'.RND
$!
$ OPEN /WRITE OFILE SYS$LOGIN:SSL_'PID'.COM
$ WRITE OFILE "$ DEFINE /USER /NOLOG RANDFILE    SYS$LOGIN:SSL_''PID'.RND"
$ WRITE OFILE "$ DEFINE /USER /NOLOG SYS$ERROR   SYS$LOGIN:SSL_''PID'.LOG"
$ WRITE OFILE "$ DEFINE /USER /NOLOG SYS$OUTPUT  SYS$LOGIN:SSL_''PID'.LOG"
$ WRITE OFILE "$ DEFINE /USER /NOLOG SYS$COMMAND SYS$INPUT"
$ WRITE OFILE "$ OPENSSL req -nodes -new -days 30 -x509 -config SYS$LOGIN:SSL_''PID'.CNF -keyout ''KEY_FILE' -out ''CRT_FILE'"
$ WRITE OFILE ""
$ WRITE OFILE ""
$ WRITE OFILE ""
$ WRITE OFILE ""
$ WRITE OFILE ""
$ WRITE OFILE ""
$ WRITE OFILE ""
$ CLOSE OFILE
$!
$ @SYS$LOGIN:SSL_'PID'.COM
$!
$ DELETE /NOLOG /NOCONFIRM SYS$LOGIN:SSL_'PID'.CNF;*
$ DELETE /NOLOG /NOCONFIRM SYS$LOGIN:SSL_'PID'.RND;*
$ DELETE /NOLOG /NOCONFIRM SYS$LOGIN:SSL_'PID'.COM;*
$!
$ DEFINE /USER /NOLOG SYS$ERROR  NL:
$ DEFINE /USER /NOLOG SYS$OUTPUT NL:
$ SEARCH SYS$LOGIN:SSL_'PID'.LOG /OUT=SYS$LOGIN:SSL_'PID'.ERR ":error:"
$!
$ IF F$SEARCH ("SYS$LOGIN:SSL_''PID'.ERR") .NES. "" 
$ THEN 
$     IF F$FILE_ATTRIBUTE ("SYS$LOGIN:SSL_''PID'.ERR","ALQ") .NE. 0
$     THEN 
$         TYPE SYS$LOGIN:SSL_'PID'.LOG
$     ENDIF
$     DELETE /NOLOG /NOCONFIRM SYS$LOGIN:SSL_'PID'.ERR;*
$ ENDIF
$!
$ DELETE /NOLOG /NOCONFIRM SYS$LOGIN:SSL_'PID'.LOG;*
$!
$!------------------------------------------------------------------------------
$! Exit
$!------------------------------------------------------------------------------
$!
$EXIT:
$!
$ Verify = F$VERIFY (Verify)
$!
$ EXIT
