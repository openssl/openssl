$! INSTALL.COM -- Installs the files in a given directory tree
$!
$! Author: Richard Levitte <richard@levitte.org>
$! Time of creation: 23-MAY-1998 19:22
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
$
$	IF F$PARSE("WRK_SSLROOT:[000000]") .EQS. "" THEN -
	   CREATE/DIR/LOG WRK_SSLROOT:[000000]
$!
$	EXAMPLE_DIR := [.VMS_EXAMPLES]
$	EXAMPLE_FILES := SSL$BIO_CLI.C,SSL$BIO_SERV.C,SSL$CLI_SESS_RENEGO.C, -
			SSL$CLI_SESS_RENEGO_CLI_VER.C,SSL$CLI_SESS_REUSE.C, -
			SSL$CLI_SESS_REUSE_CLI_VER.C,SSL$CLI_VERIFY_CLIENT.C, -
			SSL$SERV_SESS_RENEGO.C,SSL$SERV_SESS_RENEGO_CLI_VER.C, -
			SSL$SERV_SESS_REUSE.C,SSL$SERV_SESS_REUSE_CLI_VER.C, -
			SSL$SERV_VERIFY_CLIENT.C,SSL$SIMPLE_CLI.C,SSL$SIMPLE_SERV.C, -
			SSL$EXAMPLES_SETUP.COM
$!
$	I = 0
$ LOOP:
$       EF = F$EDIT(F$ELEMENT(I, ",", EXAMPLE_FILES),"TRIM")
$       I = I + 1
$       IF eF .EQS. "," THEN GOTO LOOP_END
$       SET NOON
$       IF F$SEARCH(EXAMPLE_DIR+EF) .NES. ""
$       THEN
$         COPY 'EXAMPLE_DIR''EF' WRK_SSLROOT:[000000]*.*/log
$         SET FILE/PROT=W:RE WRK_SSLROOT:[000000]'EF'
$       ENDIF
$       SET ON
$       GOTO LOOP
$ LOOP_END:
$!
$	EXIT
