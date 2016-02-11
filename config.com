$	! OpenSSL config: determine the architecture and run Configure
$	!
$	! Very simple for the moment, it will take the following arguments:
$	!
$	! 32		sets /POINTER_SIZE=32
$	! 64		sets /POINTER_SIZE=64
$	! DEBUG		sets debugging
$	! HELP		prints a usage and exits
$
$	arch == f$edit( f$getsyi( "arch_name"), "lowercase")
$	pointer_size = ""
$	debug = ""
$	here = F$PARSE("A.;",F$ENVIRONMENT("PROCEDURE"),,,"SYNTAX_ONLY") - "A.;"
$
$	collected_args = ""
$	P_index = 0
$	LOOP1:
$	    P_index = P_index + 1
$	    IF P_index .GT. 8 THEN GOTO ENDLOOP1
$	    P1 = F$EDIT(P1,"TRIM")
$	    IF P1 .EQS. "HELP" THEN GOTO USAGE
$	    IF P1 .EQS. "32"
$	    THEN
$		pointer_size = "-P32"
$		P1 = ""
$	    ENDIF
$	    IF P1 .EQS. "64"
$	    THEN
$		pointer_size = "-P64"
$		P1 = ""
$	    ENDIF
$	    IF P1 .EQS. "DEBUG"
$	    THEN
$		debug = "--debug"
$		P1 = ""
$	    ENDIF
$	    IF P1 .NES. "" THEN -
	       collected_args = collected_args + " " + P1
$	    P1 = P2
$	    P2 = P3
$	    P3 = P4
$	    P4 = P5
$	    P5 = P6
$	    P6 = P7
$	    P7 = P8
$	    P8 = ""
$	    GOTO LOOP1
$	ENDLOOP1:
$
$	target = "vms-''arch'''pointer_size'"
$	PERL 'here'Configure "''target'" 'debug' 'collected_args'
$	EXIT $STATUS
$
$ USAGE:
$	TYPE SYS$INPUT
$	DECK
usage: @config [options]

  32		build with 32-bit pointer size
  64		build with 64-bit pointer size
  DEBUG		build with debugging
  HELP		this text

Any other option is simply passed to Configure.
$	EOD
