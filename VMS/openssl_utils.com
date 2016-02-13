$	! OpenSSL utilities
$	!
$
$	OPENSSL		:== $OSSL$EXE:OPENSSL
$
$	IF F$SYMBOL(PERL) .EQS. "STRING"
$	THEN
$	    OSSLCA	:== 'PERL' OSSL$EXE:CA.pl
$	    OSSLREHASH	:== 'PERL' OSSL$EXE:c_rehash.pl
$	ELSE
$	    WRITE SYS$ERROR "NOTE: no perl => no OSSLCA or OSSLREHASH"
$	ENDIF
