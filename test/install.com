$! INSTALL.COM -- Installs the files in a given directory tree
$!
$! Author: Richard Levitte <richard@levitte.org>
$! Time of creation: 22-MAY-1998 10:13
$!
$! P1	root of the directory tree
$!
$	IF P1 .EQS. ""
$	THEN
$	    WRITE SYS$OUTPUT "First argument missing."
$	    WRITE SYS$OUTPUT "Should be the directory where you want things installed."
$	    EXIT
$	ENDIF
$
$	ROOT = F$PARSE(P1,"[]A.;0",,,"SYNTAX_ONLY,NO_CONCEAL") - "A.;0"
$	ROOT_DEV = F$PARSE(ROOT,,,"DEVICE","SYNTAX_ONLY")
$	ROOT_DIR = F$PARSE(ROOT,,,"DIRECTORY","SYNTAX_ONLY") -
		   - "[000000." - "][" - "[" - "]"
$	ROOT = ROOT_DEV + "[" + ROOT_DIR
$
$	DEFINE/NOLOG WRK_SSLROOT 'ROOT'.] /TRANS=CONC
$	DEFINE/NOLOG WRK_SSLTEST WRK_SSLROOT:[TEST]
$
$	IF F$PARSE("WRK_SSLROOT:[000000]") .EQS. "" THEN -
	   CREATE/DIR/LOG WRK_SSLROOT:[000000]
$	IF F$PARSE("WRK_SSLTEST:") .EQS. "" THEN -
	   CREATE/DIR/LOG WRK_SSLTEST:
$
$	COM_FILES := SSL$IVP, -
		     TCRL,TESTCA,TESTENC,TESTGEN,TESTS,TESTSS, -
		     TESTSSL,TESTS_SHARE,TPKCS7,TPKCS7D, -
	             TREQ,TRSA,TSID,TVERIFY,TX509
$
$	I = 0
$ LOOP_COM: 
$	CF = F$EDIT(F$ELEMENT(I, ",",COM_FILES ),"TRIM")
$	I = I + 1
$	IF CF .EQS. "," THEN GOTO LOOP_COM_END
$	SET NOON
$	IF F$SEARCH(CF+".COM") .NES. ""
$	THEN
$	  COPY 'CF'.COM WRK_SSLTEST:'CF'.COM/log
$	  SET FILE/PROT=W:RE WRK_SSLTEST:'CF'.COM
$	ENDIF
$	SET ON
$	GOTO LOOP_COM
$ LOOP_COM_END:
$!
$       VEXE_DIR := [-.VAX.EXE.TEST]
$       AEXE_DIR := [-.AXP.EXE.TEST]
$!
$	EXE_FILES := BFTEST,BNTEST,CASTTEST,DESTEST, -
		     DHTEST,DSATEST,EXPTEST,HMACTEST, -
		     IDEATEST,MD2TEST,MD4TEST,MD5TEST, -
		     MDC2TEST,RANDTEST,RC2TEST,RC4TEST, -
		     RC5TEST,RMDTEST,RSA_TEST,SHA1TEST, -
		     SHATEST,SSLTEST
$!
$!
$	I = 0
$ LOOP_EXE:
$       E = F$EDIT(F$ELEMENT(I, ",", EXE_FILES),"TRIM")
$       I = I + 1
$       IF E .EQS. "," THEN GOTO LOOP_EXE_END
$       SET NOON
$       IF F$SEARCH(VEXE_DIR+E+".EXE") .NES. ""
$       THEN
$         COPY 'VEXE_DIR''E'.EXE WRK_SSLTEST:'E'.EXE/log
$         SET FILE/PROT=W:RE WRK_SSLTEST:'E'.EXE
$       ENDIF
$       IF F$SEARCH(AEXE_DIR+E+".EXE") .NES. ""
$       THEN
$         COPY 'AEXE_DIR''E'.EXE WRK_SSLTEST:'E'.EXE/log
$         SET FILE/PROT=W:RE WRK_SSLTEST:'E'.EXE
$       ENDIF
$       SET ON
$       GOTO LOOP_EXE
$ LOOP_EXE_END:
$!
$!
$	EXIT
