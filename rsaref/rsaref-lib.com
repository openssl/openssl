$!
$!  RSAREF-LIB.COM
$!  Written By:  Robert Byer
$!               Vice-President
$!               A-Com Computing, Inc.
$!               byer@mail.all-net.net
$!
$!  Changes by Richard Levitte <richard@levitte.org>
$!
$!  This command files compiles and creates the "[.xxx.EXE.RSAREF]LIBRSAGLUE.OLB"
$!  library.  The "xxx" denotes the machine architecture of AXP or VAX.
$!
$!  Specify one of the following to build just that part or "ALL" to
$!  just build everything.
$!
$!         ALL       To Just Build "Everything".
$!         LIBRARY   To Just Build The [.xxx.EXE.RSAREF]LIBRSAGLUE.OLB Library.
$!         DHDEMO    To Just Build The [.xxx.EXE.RSAREF]DHDEMO.EXE Program.
$!         RDEMO     To Just Build The [.xxx.EXE.RSAREF]RDEMO.EXE Program.
$!
$!  Specify DEBUG or NODEBUG as P2 to compile with or without debugging
$!  information.
$!
$!  Specify which compiler at P3 to try to compile under.
$!
$!	   VAXC	 For VAX C.
$!	   DECC	 For DEC C.
$!	   GNUC	 For GNU C.
$!
$!  If you don't speficy a compiler, it will prompt you for one.
$!
$!  P4, if defined, sets a compiler thread NOT needed on OpenVMS 7.1 (and up)
$!
$!
$! Check Which Architecture We Are Using.
$!
$ IF (F$GETSYI("CPU").GE.128)
$ THEN
$!
$!  The Architecture Is AXP
$!
$   ARCH := AXP
$!
$! Else...
$!
$ ELSE
$!
$!  The Architecture Is VAX.
$!
$   ARCH := VAX
$!
$! End The Architecture Check.
$!
$ ENDIF
$!
$! Check To Make Sure We Have Valid Command Line Parameters.
$!
$ GOSUB CHECK_OPTIONS
$!
$! Initialise logical names and such
$!
$ GOSUB INITIALISE
$!
$! Tell The User What Kind of Machine We Run On.
$!
$ WRITE SYS$OUTPUT "Compiling On A ",ARCH," Machine."
$!
$! Define The OBJ Directory Name.
$!
$ OBJ_DIR := SYS$DISK:[-.'ARCH'.OBJ.RSAREF]
$!
$! Check To See If The Architecture Specific OBJ Directory Exists.
$!
$ IF (F$PARSE(OBJ_DIR).EQS."")
$ THEN
$!
$!  It Dosen't Exist, So Create It.
$!
$   CREATE/DIR 'OBJ_DIR'
$!
$! End The Architecture Specific OBJ Directory Check.
$!
$ ENDIF
$!
$! Define The EXE Directory Name.
$!
$ EXE_DIR := SYS$DISK:[-.'ARCH'.EXE.RSAREF]
$!
$! Check To See If The Architecture Specific EXE Directory Exists.
$!
$ IF (F$PARSE(EXE_DIR).EQS."")
$ THEN
$!
$!  It Dosen't Exist, So Create It.
$!
$   CREATE/DIR 'EXE_DIR'
$!
$! End The Architecture Specific EXE Directory Check.
$!
$ ENDIF
$!
$! Define The Library Name.
$!
$ LIB_NAME := 'EXE_DIR'LIBRSAGLUE.OLB
$!
$! Check To See What We Are To Do.
$!
$ IF (BUILDALL.EQS."TRUE")
$ THEN
$!
$!  Since Nothing Special Was Specified, Do Everything.
$!
$   GOSUB LIBRARY
$   GOSUB DHDEMO
$   GOSUB RDEMO
$!
$! Else...
$!
$ ELSE
$!
$!    Build Just What The User Wants Us To Build.
$!
$     GOSUB 'BUILDALL'
$!
$! End The BUILDALL Check.
$!
$ ENDIF
$!
$! Time To EXIT.
$!
$ EXIT:
$ GOSUB CLEANUP
$ EXIT
$!
$ LIBRARY:
$!
$! Tell The User That We Are Compiling.
$!
$ WRITE SYS$OUTPUT "Compiling The ",LIB_NAME," Files."
$!
$! Check To See If We Already Have A "LIBRSAGLUE.OLB" Library...
$!
$ IF (F$SEARCH(LIB_NAME).EQS."")
$ THEN
$!
$! Guess Not, Create The Library.
$!
$   LIBRARY/CREATE/OBJECT 'LIB_NAME'
$!
$! End The Library Exist Check.
$!
$ ENDIF
$!
$! Define The RSAREF Library Files.
$!
$ LIB_RSAREF = "DESC,DIGIT,MD2C,MD5C,NN,PRIME,RSA,R_DH,R_ENCODE,R_ENHANC," + -
               "R_KEYGEN,R_RANDOM,R_STDLIB"
$!
$!  Define A File Counter And Set It To "0".
$!
$ FILE_COUNTER = 0
$!
$! Top Of The File Loop.
$!
$ NEXT_FILE:
$!
$! O.K, Extract The File Name From The File List.
$!
$ FILE_NAME = F$ELEMENT(FILE_COUNTER,",",LIB_RSAREF)
$!
$! Check To See If We Are At The End Of The File List.
$!
$ IF (FILE_NAME.EQS.",") THEN GOTO FILE_DONE
$!
$! Increment The Counter.
$!
$ FILE_COUNTER = FILE_COUNTER + 1
$!
$! Create The Source File Name.
$!
$ SOURCE_FILE = "SYS$DISK:[.SOURCE]" + FILE_NAME + ".C"
$!
$!  Tell The User We Are Compiling The Source File.
$!
$ WRITE SYS$OUTPUT "	",FILE_NAME,".C"
$!
$! Create The Object File Name.
$!
$ OBJECT_FILE = OBJ_DIR + FILE_NAME + ".OBJ"
$ ON WARNING THEN GOTO NEXT_FILE
$!
$! Check To See If The File We Want To Compile Actually Exists.
$!
$ IF (F$SEARCH(SOURCE_FILE).EQS."")
$ THEN
$!
$!  Tell The User That The File Dosen't Exist.
$!
$   WRITE SYS$OUTPUT ""
$   WRITE SYS$OUTPUT "The File ",SOURCE_FILE," Dosen't Exist."
$   WRITE SYS$OUTPUT ""
$!
$!  Exit The Build.
$!
$   EXIT
$!
$! End The File Exist Check.
$!
$ ENDIF
$!
$! Compile The File.
$!
$ ON ERROR THEN GOTO NEXT_FILE
$ CC/OBJECT='OBJECT_FILE' 'SOURCE_FILE'
$!
$! Add It To The Library.
$!
$ LIBRARY/REPLACE/OBJECT 'LIB_NAME' 'OBJECT_FILE'
$!
$! Time To Clean Up The Object File.
$!
$ DELETE 'OBJECT_FILE';*
$!
$! Go Back And Do It Again.
$!
$ GOTO NEXT_FILE
$!
$! All Done With This Library Part.
$!
$ FILE_DONE:
$!
$! Tell The User That We Are All Done.
$!
$ WRITE SYS$OUTPUT "Library ",LIB_NAME," Built."
$!
$! All Done, Time To Return.
$!
$ RETURN
$!
$!  Compile The [.xxx.EXE.RSAREF]DHDEMO Program.
$!
$ DHDEMO:
$!
$! Check To See If We Have The Proper Libraries.
$!
$ GOSUB LIB_CHECK
$!
$! Check To See If We Have A Linker Option File.
$!
$ GOSUB CHECK_OPT_FILE
$!
$! Check To See If The File We Want To Compile Actually Exists.
$!
$ IF (F$SEARCH("SYS$DISK:[.RDEMO]DHDEMO.C").EQS."")
$ THEN
$!
$!  Tell The User That The File Dosen't Exist.
$!
$   WRITE SYS$OUTPUT ""
$   WRITE SYS$OUTPUT "The File [.RDEMO]DHDEMO.C Dosen't Exist."
$   WRITE SYS$OUTPUT ""
$!
$!  Exit The Build.
$!
$   EXIT
$!
$! End The [.RDEMO]DHDEMO.C File Check.
$!
$ ENDIF
$!
$! Tell The User What We Are Building.
$!
$ WRITE SYS$OUTPUT "Building ",EXE_DIR,"DHDEMO.EXE"
$!
$! Compile The DHDEMO Program.
$!
$ CC/OBJECT='OBJ_DIR'DHDEMO.OBJ SYS$DISK:[.RDEMO]DHDEMO.C
$!
$! Link The DHDEMO Program.
$!
$ LINK/'DEBUGGER'/'TRACEBACK'/CONTIGUOUS -
      /EXE='EXE_DIR'DHDEMO.EXE 'OBJ_DIR'DHDEMO.OBJ, -
      'LIB_NAME'/LIBRARY,'OPT_FILE'/OPTION
$!
$! All Done, Time To Return.
$!
$ RETURN
$!
$!  Compile The RDEMO Program.
$!
$ RDEMO:
$!
$! Check To See If We Have The Proper Libraries.
$!
$ GOSUB LIB_CHECK
$!
$! Check To See If We Have A Linker Option File.
$!
$ GOSUB CHECK_OPT_FILE
$!
$! Check To See If The File We Want To Compile Actually Exists.
$!
$ IF (F$SEARCH("SYS$DISK:[.RDEMO]RDEMO.C").EQS."")
$ THEN
$!
$!  Tell The User That The File Dosen't Exist.
$!
$   WRITE SYS$OUTPUT ""
$   WRITE SYS$OUTPUT "The File [.RDEMO]RDEMO.C Dosen't Exist."
$   WRITE SYS$OUTPUT ""
$!
$!  Exit The Build.
$!
$   EXIT
$!
$! End The [.RDEMO]RDEMO.C File Check.
$!
$ ENDIF
$!
$! Tell The User What We Are Building.
$!
$ WRITE SYS$OUTPUT "Building ",EXE_DIR,"RDEMO.EXE"
$!
$! Compile The RDEMO Program.
$!
$ CC/OBJECT='OBJ_DIR'RDEMO.OBJ SYS$DISK:[.RDEMO]RDEMO.C
$!
$! Link The RDEMO Program.
$!
$ LINK/'DEBUGGER'/'TRACEBACK'/CONTIGUOUS -
      /EXE='EXE_DIR'RDEMO.EXE 'OBJ_DIR'RDEMO.OBJ, -
      'LIB_NAME'/LIBRARY,'OPT_FILE'/OPTION
$!
$! All Done, Time To Return.
$!
$ RETURN
$!
$! Check For The Link Option FIle.
$!
$ CHECK_OPT_FILE:
$!
$! Check To See If We Need To Make A VAX C Option File.
$!
$ IF (COMPILER.EQS."VAXC")
$ THEN
$!
$!  Check To See If We Already Have A VAX C Linker Option File.
$!
$   IF (F$SEARCH(OPT_FILE).EQS."")
$   THEN
$!
$!    We Need A VAX C Linker Option File.
$!
$     CREATE 'OPT_FILE'
$DECK
!
! Default System Options File To Link Agianst 
! The Sharable VAX C Runtime Library.
!
SYS$SHARE:VAXCRTL.EXE/SHARE
$EOD
$!
$!  End The Option File Check.
$!
$   ENDIF
$!
$! End The VAXC Check.
$!
$ ENDIF
$!
$! Check To See If We Need A GNU C Option File.
$!
$ IF (COMPILER.EQS."GNUC")
$ THEN
$!
$!  Check To See If We Already Have A GNU C Linker Option File.
$!
$   IF (F$SEARCH(OPT_FILE).EQS."")
$   THEN
$!
$!    We Need A GNU C Linker Option File.
$!
$     CREATE 'OPT_FILE'
$DECK
!
! Default System Options File To Link Agianst 
! The Sharable C Runtime Library.
!
GNU_CC:[000000]GCCLIB/LIBRARY
SYS$SHARE:VAXCRTL/SHARE
$EOD
$!
$!  End The Option File Check.
$!
$   ENDIF
$!
$! End The GNU C Check.
$!
$ ENDIF
$!
$! Check To See If We Need A DEC C Option File.
$!
$ IF (COMPILER.EQS."DECC")
$ THEN
$!
$!  Check To See If We Already Have A DEC C Linker Option File.
$!
$   IF (F$SEARCH(OPT_FILE).EQS."")
$   THEN
$!
$!    Figure Out If We Need An AXP Or A VAX Linker Option File.
$!
$     IF (ARCH.EQS."VAX")
$     THEN
$!
$!      We Need A DEC C Linker Option File For VAX.
$!
$       CREATE 'OPT_FILE'
$DECK
!
! Default System Options File To Link Agianst 
! The Sharable DEC C Runtime Library.
!
SYS$SHARE:DECC$SHR.EXE/SHARE
$EOD
$!
$!    Else...
$!
$     ELSE
$!
$!      Create The AXP Linker Option File.
$!
$       CREATE 'OPT_FILE'
$DECK
!
! Default System Options File For AXP To Link Agianst 
! The Sharable C Runtime Library.
!
SYS$SHARE:CMA$OPEN_LIB_SHR/SHARE
SYS$SHARE:CMA$OPEN_RTL/SHARE
$EOD
$!
$!    End The VAX/AXP DEC C Option File Check.
$!
$     ENDIF
$!
$!  End The Option File Search.
$!
$   ENDIF
$!
$! End The DEC C Check.
$!
$ ENDIF
$!
$!  Tell The User What Linker Option File We Are Using.
$!
$ WRITE SYS$OUTPUT "Using Linker Option File ",OPT_FILE,"."	
$!
$! Time To RETURN.
$!
$ RETURN
$ LIB_CHECK:
$!
$! Look For The Library LIBRSAGLUE.OLB.
$!
$ IF (F$SEARCH(LIB_NAME).EQS."")
$ THEN
$!
$!  Tell The User We Can't Find The [.xxx.EXE.RSAREF]LIBRSAGLUE.OLB Library.
$!
$   WRITE SYS$OUTPUT ""
$   WRITE SYS$OUTPUT "Can't Find The Library ",LIB_NAME,"."
$   WRITE SYS$OUTPUT "We Can't Link Without It."
$   WRITE SYS$OUTPUT ""
$!
$!  And Ask If They Would Like To Build It.
$!
$   INQUIRE YESNO "Would You Like To Build The Library Now (Y/N)?"
$!
$!  Check The Answer.
$!
$   IF (YESNO.EQS."Y").OR.(YESNO.EQS."y")
$   THEN
$!
$!    Then Build The Library.
$!
$     GOSUB LIBRARY
$!
$!    When Done With That, RETURN To Finish What Ever We Were Doing
$!    That Needed The Library.
$!
$     RETURN
$!
$!  Else...
$!
$   ELSE
$!
$!    Since We Can't Link Without It, Exit.
$!
$     EXIT
$!
$!  End The Answer Check.
$!
$   ENDIF
$!
$! End The Library Check.
$!
$ ENDIF
$!
$! Time To Return.
$!
$ RETURN
$!
$! Check The User's Options.
$!
$ CHECK_OPTIONS:
$!
$! Check To See If P1 Is Blank.
$!
$ IF (P1.EQS."ALL")
$ THEN
$!
$!   P1 Is Blank, So Build Everything.
$!
$    BUILDALL = "TRUE"
$!
$! Else...
$!
$ ELSE
$!
$!  Else, Check To See If P1 Has A Valid Arguement.
$!
$   IF (P1.EQS."LIBRARY").OR.(P1.EQS."DHDEMO").OR.(P1.EQS."RDEMO")
$   THEN
$!
$!    A Valid Arguement.
$!
$     BUILDALL = P1
$!
$!  Else....
$!
$   ELSE
$!
$!    Tell The User We Don't Know What They Want.
$!
$     WRITE SYS$OUTPUT ""
$     WRITE SYS$OUTPUT "The Option ",P1," Is Invalid.  The Valid Options Are:"
$     WRITE SYS$OUTPUT ""
$     WRITE SYS$OUTPUT "    ALL      :  To Just Build Everything."
$     WRITE SYS$OUTPUT "    LIBRARY  :  To Compile Just The [.xxx.EXE.RSAREF]LIBRSAGLUE.OLB Library."
$     WRITE SYS$OUTPUT "    DHDEMO   :  To Compile Just The [.xxx.EXE.RSAREF]DHDEMO Program."
$     WRITE SYS$OUTPUT "    RDEMO    :  To Compile Just The [.xxx.EXE.RSAREF]RDEMO Program.
$     WRITE SYS$OUTPUT ""
$     WRITE SYS$OUTPUT " Where 'xxx' Stands For:"
$     WRITE SYS$OUTPUT ""
$     WRITE SYS$OUTPUT "        AXP  :  Alpha Architecture."
$     WRITE SYS$OUTPUT "        VAX  :  VAX Architecture."
$     WRITE SYS$OUTPUT ""
$!
$!    Time To EXIT.
$!
$     EXIT
$!
$!  End The Valid Arguement Check.
$!
$   ENDIF
$!
$! End The P1 Check.
$!
$ ENDIF
$!
$! Check To See If P2 Is Blank.
$!
$ IF (P2.EQS."NODEBUG")
$ THEN
$!
$!   P2 Is "NODEBUG" So Compile Without Debugger Information.
$!
$    DEBUGGER  = "NODEBUG"
$    TRACEBACK = "NOTRACEBACK" 
$    GCC_OPTIMIZE = "OPTIMIZE"
$    CC_OPTIMIZE = "OPTIMIZE"
$    WRITE SYS$OUTPUT "No Debugger Information Will Be Produced During Compile."
$    WRITE SYS$OUTPUT "Compiling With Compiler Optimization."
$ ELSE
$!
$!  Check To See If We Are To Compile With Debugger Information.
$!
$   IF (P2.EQS."DEBUG")
$   THEN
$!
$!    Compile With Debugger Information.
$!
$     DEBUGGER  = "DEBUG"
$     TRACEBACK = "TRACEBACK"
$     GCC_OPTIMIZE = "NOOPTIMIZE"
$     CC_OPTIMIZE = "NOOPTIMIZE"
$     WRITE SYS$OUTPUT "Debugger Information Will Be Produced During Compile."
$     WRITE SYS$OUTPUT "Compiling Without Compiler Optimization."
$   ELSE
$!
$!    Tell The User Entered An Invalid Option..
$!
$     WRITE SYS$OUTPUT ""
$     WRITE SYS$OUTPUT "The Option ",P2," Is Invalid.  The Valid Options Are:"
$     WRITE SYS$OUTPUT ""
$     WRITE SYS$OUTPUT "    DEBUG    :  Compile With The Debugger Information."
$     WRITE SYS$OUTPUT "    NODEBUG  :  Compile Without The Debugger Information."
$     WRITE SYS$OUTPUT ""
$!
$!    Time To EXIT.
$!
$     EXIT
$!
$!  End The Valid Arguement Check.
$!
$   ENDIF
$!
$! End The P2 Check.
$!
$ ENDIF
$!
$! Special Threads For OpenVMS v7.1 Or Later.
$!
$! Written By:  Richard Levitte
$!              richard@levitte.org
$!
$!
$! Check To See If We Have A Option For P4.
$!
$ IF (P4.EQS."")
$ THEN
$!
$!  Get The Version Of VMS We Are Using.
$!
$   ISSEVEN :=
$   TMP = F$ELEMENT(0,"-",F$EXTRACT(1,4,F$GETSYI("VERSION")))
$   TMP = F$INTEGER(F$ELEMENT(0,".",TMP)+F$ELEMENT(1,".",TMP))
$!
$!  Check To See If The VMS Version Is v7.1 Or Later.
$!
$   IF (TMP.GE.71)
$   THEN
$!
$!    We Have OpenVMS v7.1 Or Later, So Use The Special Threads.
$!
$     ISSEVEN := ,PTHREAD_USE_D4
$!
$!  End The VMS Version Check.
$!
$   ENDIF
$!
$! End The P4 Check.
$!
$ ENDIF
$!
$! Check To See If P3 Is Blank.
$!
$ IF (P3.EQS."")
$ THEN
$!
$!  O.K., The User Didn't Specify A Compiler, Let's Try To
$!  Find Out Which One To Use.
$!
$!  Check To See If We Have GNU C.
$!
$   IF (F$TRNLNM("GNU_CC").NES."")
$   THEN
$!
$!    Looks Like GNUC, Set To Use GNUC.
$!
$     COMPILER = "GNUC"
$!
$!  End The GNU C Compiler Check.
$!
$   ELSE
$!
$!  Check To See If We Have VAXC Or DECC.
$!
$     IF (ARCH.EQS."ALPHA").OR.(F$TRNLNM("DECC$CC_DEFAULT").NES."")
$     THEN 
$!
$!      Looks Like DECC, Set To Use DECC.
$!
$       COMPILER = "DECC"
$!
$!      Tell The User We Are Using DECC.
$!
$       WRITE SYS$OUTPUT "Using DECC 'C' Compiler."
$!
$!      Else...
$!
$     ELSE
$!
$!      Looks Like VAXC, Set To Use VAXC.
$!
$       COMPILER = "VAXC"
$!
$!    End The VAXC Compiler Check.
$!
$     ENDIF
$!
$!  End The DECC & VAXC Compiler Check.
$!
$   ENDIF
$!
$!  End The Compiler Check.
$!
$ ENDIF
$!
$! Set Up Initial CC Definitions, Possibly With User Ones
$!
$ CCDEFS = "VMS=1"
$ IF F$TYPE(USER_CCDEFS) .NES. "" THEN CCDEFS = CCDEFS + "," + USER_CCDEFS
$ CCEXTRAFLAGS = ""
$ IF F$TYPE(USER_CCFLAGS) .NES. "" THEN CCEXTRAFLAGS = USER_CCFLAGS
$ CCDISABLEWARNINGS = ""
$ IF F$TYPE(USER_CCDISABLEWARNINGS) .NES. "" THEN -
	CCDISABLEWARNINGS = USER_CCDISABLEWARNINGS
$!
$!  Check To See If The User Entered A Valid Paramter.
$!
$ IF (P3.EQS."VAXC").OR.(P3.EQS."DECC").OR.(P3.EQS."GNUC")
$ THEN
$!
$!  Check To See If The User Wanted DECC.
$!
$   IF (P3.EQS."DECC")
$   THEN
$!
$!    Looks Like DECC, Set To Use DECC.
$!
$     COMPILER = "DECC"
$!
$!    Tell The User We Are Using DECC.
$!
$     WRITE SYS$OUTPUT "Using DECC 'C' Compiler."
$!
$!    Use DECC...
$!
$     CC = "CC"
$     IF ARCH.EQS."VAX" .AND. F$TRNLNM("DECC$CC_DEFAULT").NES."/DECC" -
	 THEN CC = "CC/DECC"
$     CC = CC + "/''CC_OPTIMIZE'/''DEBUGGER'/STANDARD=ANSI89" + -
           "/NOLIST/PREFIX=ALL" + -
	   "/INCLUDE=(SYS$DISK:[-.CRYPTO],SYS$DISK:[.SOURCE])" + CCEXTRAFLAGS
$!
$!    Define The Linker Options File Name.
$!
$     OPT_FILE = "SYS$DISK:[]VAX_DECC_OPTIONS.OPT"
$!
$!  End DECC Check.
$!
$   ENDIF
$!
$!  Check To See If We Are To Use VAXC.
$!
$   IF (P3.EQS."VAXC")
$   THEN
$!
$!    Looks Like VAXC, Set To Use VAXC.
$!
$     COMPILER = "VAXC"
$!
$!    Tell The User We Are Using VAX C.
$!
$     WRITE SYS$OUTPUT "Using VAXC 'C' Compiler."
$!
$!    Compile Using VAXC.
$!
$     CC = "CC"
$     IF ARCH.EQS."AXP"
$     THEN
$	WRITE SYS$OUTPUT "There is no VAX C on Alpha!"
$	EXIT
$     ENDIF
$     IF F$TRNLNM("DECC$CC_DEFAULT").EQS."/DECC" THEN CC = "CC/VAXC"
$     CC = CC + "/''CC_OPTIMIZE'/''DEBUGGER'/NOLIST" + -
	   "/INCLUDE=(SYS$DISK:[-.CRYPTO],SYS$DISK:[.SOURCE])" + CCEXTRAFLAGS
$     CCDEFS = CCDEFS + ",""VAXC"""
$!
$!    Define <sys> As SYS$COMMON:[SYSLIB]
$!
$     DEFINE/NOLOG SYS SYS$COMMON:[SYSLIB]
$!
$!    Define The Linker Options File Name.
$!
$     OPT_FILE = "SYS$DISK:[]VAX_VAXC_OPTIONS.OPT"
$!
$!  End VAXC Check
$!
$   ENDIF
$!
$!  Check To See If We Are To Use GNU C.
$!
$   IF (P3.EQS."GNUC")
$   THEN
$!
$!    Looks Like GNUC, Set To Use GNUC.
$!
$     COMPILER = "GNUC"
$!
$!    Tell The User We Are Using GNUC.
$!
$     WRITE SYS$OUTPUT "Using GNU 'C' Compiler."
$!
$!    Use GNU C...
$!
$     IF F$TYPE(GCC) .EQS. "" THEN GCC := GCC
$     CC = GCC+"/NOCASE_HACK/''GCC_OPTIMIZE'/''DEBUGGER'/NOLIST" + -
	   "/INCLUDE=(SYS$DISK:[-.CRYPTO],SYS$DISK:[.SOURCE])" + CCEXTRAFLAGS
$!
$!    Define The Linker Options File Name.
$!
$     OPT_FILE = "SYS$DISK:[]VAX_GNUC_OPTIONS.OPT"
$!
$!  End The GNU C Check.
$!
$   ENDIF
$!
$!  Set up default defines
$!
$   CCDEFS = """FLAT_INC=1""," + CCDEFS
$   CCDEFS = CCDEFS + ",""RSAref=1"""
$!
$!  Finish up the definition of CC.
$!
$   IF COMPILER .EQS. "DECC"
$   THEN
$     IF CCDISABLEWARNINGS .NES. ""
$     THEN
$       CCDISABLEWARNINGS = "/WARNING=(DISABLE=(" + CCDISABLEWARNINGS + "))"
$     ENDIF
$   ELSE
$     CCDISABLEWARNINGS = ""
$   ENDIF
$   CC = CC + "/DEFINE=(" + CCDEFS + ")" + CCDISABLEWARNINGS
$!
$!  Show user the result
$!
$   WRITE SYS$OUTPUT "Main Compiling Command: ",CC
$!
$!  Else The User Entered An Invalid Arguement.
$!
$ ELSE
$!
$!  Tell The User We Don't Know What They Want.
$!
$   WRITE SYS$OUTPUT ""
$   WRITE SYS$OUTPUT "The Option ",P3," Is Invalid.  The Valid Options Are:"
$   WRITE SYS$OUTPUT ""
$   WRITE SYS$OUTPUT "    VAXC  :  To Compile With VAX C."
$   WRITE SYS$OUTPUT "    DECC  :  To Compile With DEC C."
$   WRITE SYS$OUTPUT "    GNUC  :  To Compile With GNU C."
$   WRITE SYS$OUTPUT ""
$!
$!  Time To EXIT.
$!
$   EXIT
$!
$! End The P3 Check.
$!
$ ENDIF
$!
$!  Time To RETURN...
$!
$ RETURN
$!
$ INITIALISE:
$!
$! Save old value of the logical name OPENSSL
$!
$ __SAVE_OPENSSL = F$TRNLNM("OPENSSL","LNM$PROCESS_TABLE")
$!
$! Save directory information
$!
$ __HERE = F$PARSE(F$PARSE("A.;",F$ENVIRONMENT("PROCEDURE"))-"A.;","[]A.;") - "A.;"
$ __TOP = __HERE - "RSAREF]"
$ __INCLUDE = __TOP + "INCLUDE.OPENSSL]"
$!
$! Set up the logical name OPENSSL to point at the include directory
$!
$ DEFINE OPENSSL/NOLOG '__INCLUDE'
$!
$! Done
$!
$ RETURN
$!
$ CLEANUP:
$!
$! Restore the logical name OPENSSL if it had a value
$!
$ IF __SAVE_OPENSSL .EQS. ""
$ THEN
$   DEASSIGN OPENSSL
$ ELSE
$   DEFINE/NOLOG OPENSSL '__SAVE_OPENSSL'
$ ENDIF
$!
$! Done
$!
$ RETURN
