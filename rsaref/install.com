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
$	DEFINE/NOLOG WRK_SSLVLIB WRK_SSLROOT:[VAX_LIB]
$	DEFINE/NOLOG WRK_SSLALIB WRK_SSLROOT:[ALPHA_LIB]
$
$	IF F$PARSE("WRK_SSLROOT:[000000]") .EQS. "" THEN -
	   CREATE/DIR/LOG WRK_SSLROOT:[000000]
$	IF F$PARSE("WRK_SSLVLIB:") .EQS. "" THEN -
	   CREATE/DIR/LOG WRK_SSLVLIB:
$	IF F$PARSE("WRK_SSLALIB:") .EQS. "" THEN -
	   CREATE/DIR/LOG WRK_SSLALIB:
$
$	LIBS := LIBRSAGLUE
$
$	VEXE_DIR := [-.VAX.EXE.CRYPTO]
$	AEXE_DIR := [-.AXP.EXE.CRYPTO]
$
$	I = 0
$ LOOP_LIB: 
$	E = F$EDIT(F$ELEMENT(I, ",", LIBS),"TRIM")
$	I = I + 1
$	IF E .EQS. "," THEN GOTO LOOP_LIB_END
$	SET NOON
$	IF F$SEARCH(VEXE_DIR+E+".OLB") .NES. ""
$	THEN
$	  COPY 'VEXE_DIR''E'.OLB WRK_SSLVLIB:'E'.OLB/log
$	  SET FILE/PROT=W:RE WRK_SSLVLIB:'E'.OLB
$	ENDIF
$	! Preparing for the time when we have shareable images
$	IF F$SEARCH(VEXE_DIR+E+".EXE") .NES. ""
$	THEN
$	  COPY 'VEXE_DIR''E'.EXE WRK_SSLVLIB:'E'.EXE/log
$	  SET FILE/PROT=W:RE WRK_SSLVLIB:'E'.EXE
$	ENDIF
$	IF F$SEARCH(AEXE_DIR+E+".OLB") .NES. ""
$	THEN
$	  COPY 'AEXE_DIR''E'.OLB WRK_SSLALIB:'E'.OLB/log
$	  SET FILE/PROT=W:RE WRK_SSLALIB:'E'.OLB
$	ENDIF
$	! Preparing for the time when we have shareable images
$	IF F$SEARCH(AEXE_DIR+E+".EXE") .NES. ""
$	THEN
$	  COPY 'AEXE_DIR''E'.EXE WRK_SSLALIB:'E'.EXE/log
$	  SET FILE/PROT=W:RE WRK_SSLALIB:'E'.EXE
$	ENDIF
$	SET ON
$	GOTO LOOP_LIB
$ LOOP_LIB_END:
$
$	EXIT
