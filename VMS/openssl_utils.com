$	! OpenSSL utilities
$	!
$
$	OPENSSL		:== $OSSL$EXE:OPENSSL
$
$	IF F$SYMBOL(PERL) .EQS. "STRING"
$	THEN
$	    C_REHASH	:== 'PERL' OSSL$EXE:c_rehash.pl
$	ELSE
$	    WRITE SYS$ERROR "NOTE: no perl => no C_REHASH"
$	ENDIF
