$!
$! MAKEVMS.COM
$! Original Author:  UNKNOWN
$! Rewritten By:  Robert Byer
$!                Vice-President
$!                A-Com Computing, Inc.
$!                byer@mail.all-net.net
$!
$! Changes by Richard Levitte <richard@levitte.org>
$!
$! This procedure creates the SSL libraries of "[.xxx.EXE.CRYPTO]LIBCRYPTO.OLB"
$! "[.xxx.EXE.SSL]LIBSSL.OLB" and if specified "[.xxx.EXE.RSAREF]LIBRSAGLUE.OLB".
$! The "xxx" denotes the machine architecture of AXP or VAX.
$!
$! This procedures accepts two command line options listed below.
$!
$! Specify one of the following build options for P1.
$!
$!      ALL       Just build "everything".
$!      BUILDINF  Just build the "[.CRYPTO]BUILDINF.H" file.
$!      SOFTLINKS Just fix the Unix soft links.
$!      RSAREF    Just build the "[.xxx.EXE.RSAREF]LIBRSAGLUE.OLB" library.
$!      CRYPTO    Just build the "[.xxx.EXE.CRYPTO]LIBCRYPTO.OLB" library.
$!      SSL       Just build the "[.xxx.EXE.SSL]LIBSSL.OLB" library.
$!      SSL_TASK  Just build the "[.xxx.EXE.SSL]SSL_TASK.EXE" program.
$!      TEST      Just build the "[.xxx.EXE.TEST]" test programs for OpenSSL.
$!      APPS      Just build the "[.xxx.EXE.APPS]" application programs for OpenSSL.
$!
$!
$! Specify RSAREF as P2 to compile using the RSAREF Library.
$! If you specify NORSAREF, it will compile without using RSAREF.
$! (If in the United States, You Must Compile Using RSAREF).
$!
$! Note: The RSAREF libraries are NOT INCLUDED and you have to
$!       download it from "ftp://ftp.rsa.com/rsaref".  You have to
$!       get the ".tar-Z" file as the ".zip" file dosen't have the
$!       directory structure stored.  You have to extract the file
$!       into the [.RSAREF] directory as that is where the scripts
$!       will look for the files.
$!
$! Speficy DEBUG or NODEBUG as P3 to compile with or without debugging
$! information.
$!
$! Specify which compiler at P4 to try to compile under.
$!
$!	  VAXC	 For VAX C.
$!	  DECC	 For DEC C.
$!	  GNUC	 For GNU C.
$!	  LINK   To only link the programs from existing object files.
$!               (not yet implemented)
$!
$! If you don't speficy a compiler, it will try to determine which
$! "C" compiler to use.
$!
$!  P5, if defined, sets a TCP/IP library to use, through one of the following
$!  keywords:
$!
$!	UCX		for UCX or UCX emulation
$!	SOCKETSHR	for SOCKETSHR+NETLIB
$!
$! P6, if defined, sets a compiler thread NOT needed on OpenVMS 7.1 (and up)
$!
$!
$! Check Which Architecture We Are Using.
$!
$ IF (F$GETSYI("CPU").GE.128)
$ THEN
$!
$!  The Architecture Is AXP.
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
$! Check To See What We Are To Do.
$!
$ IF (BUILDALL.EQS."TRUE")
$ THEN
$!
$!  Since Nothing Special Was Specified, Do Everything.
$!  First, Fix The Unix Softlinks.
$!
$   GOSUB SOFTLINKS
$!
$!  Create The "BUILDINF.H" Include File.
$!
$   GOSUB BUILDINF
$!
$!  Check To See If We Are Going To Be Building The 
$!  [.xxx.EXE.RSAREF]LIBRSAGLUE.OLB Library.
$!
$   IF (RSAREF.EQS."RSAREF")
$   THEN
$!
$!    Build The [.xxx.EXE.RSAREF]LIBRSAGLUE.OLB Library.
$!
$     GOSUB RSAREF
$!
$!  End The RSAREF Check.
$!
$   ENDIF
$!
$!  Build The [.xxx.EXE.CRYPTO]LIBCRYPTO.OLB Library.
$!
$   GOSUB CRYPTO
$!
$!  Build The [.xxx.EXE.SSL]LIBSSL.OLB Library.
$!
$   GOSUB SSL
$!
$!  Build The [.xxx.EXE.SSL]SSL_TASK.EXE DECNet SSL Engine.
$!
$   GOSUB SSL_TASK
$!
$!  Build The [.xxx.EXE.TEST] OpenSSL Test Utilities.
$!
$   GOSUB TEST
$!
$!  Build The [.xxx.EXE.APPS] OpenSSL Application Utilities.
$!
$   GOSUB APPS
$!
$! Else...
$!
$ ELSE
$!
$!    Build Just What The User Wants Us To Build.
$!
$     GOSUB 'BUILDALL'
$ ENDIF
$!
$! Time To EXIT.
$!
$ EXIT   
$!
$! Rebuild The "[.CRYPTO]BUILDINF.H" file.
$!
$ BUILDINF:
$!
$! Tell The User We Are Creating The [.CRYPTO]BUILDINF.H File.
$!
$ WRITE SYS$OUTPUT "Creating [.CRYPTO]BUILDINF.H Include File."
$!
$! Create The [.CRYPTO]BUILDINF.H File.
$!
$ OPEN/WRITE H_FILE SYS$DISK:[.CRYPTO]BUILDINF.H
$!
$! Get The Current Date & Time.
$!
$ TIME = F$TIME()
$!
$! Write The [.CRYPTO]BUILDINF.H File.
$!
$ WRITE H_FILE "#define CFLAGS """" /* Not filled in for now */"
$ WRITE H_FILE "#define PLATFORM ""VMS"""
$ WRITE H_FILE "#define DATE ""''TIME'"" "
$!
$! Close The [.CRYPTO]BUILDINF.H File.
$!
$ CLOSE H_FILE
$!
$! That's All, Time To RETURN.
$!
$ RETURN
$!
$! Copy a lot of files around.
$!
$ SOFTLINKS: 
$!
$! Tell The User We Are Partly Rebuilding The [.TEST] Directory.
$!
$ WRITE SYS$OUTPUT "Rebuilding The '[.APPS]MD5.C' And '[.APPS]RMD160.C' Files."
$!
$ DELETE SYS$DISK:[.APPS]MD5.C;*,RMD160.C;*
$!
$! Copy MD5.C from [.CRYPTO.MD5] into [.APPS]
$!
$ COPY SYS$DISK:[.CRYPTO.MD5]MD5.C SYS$DISK:[.APPS]
$!
$! Copy RMD160.C from [.CRYPTO.RIPEMD] into [.APPS]
$!
$ COPY SYS$DISK:[.CRYPTO.RIPEMD]RMD160.C SYS$DISK:[.APPS]
$!
$! Tell The User We Are Partly Rebuilding The [.TEST] Directory.
$!
$ WRITE SYS$OUTPUT "Rebuilding The '[.TEST]*.C' Files."
$!
$! First, We Have To "Rebuild" The "[.TEST]" Directory, So Delete
$! All The "C" Files That Are Currently There Now.
$!
$ DELETE SYS$DISK:[.TEST]*.C;*
$!
$! Copy all the *TEST.C files from [.CRYPTO...] into [.TEST]
$!
$ COPY SYS$DISK:[.CRYPTO.*]%*TEST.C SYS$DISK:[.TEST]
$!
$! Copy all the *TEST.C files from [.SSL...] into [.TEST]
$!
$ COPY SYS$DISK:[.SSL]%*TEST.C SYS$DISK:[.TEST]
$!
$! Tell The User We Are Rebuilding The [.INCLUDE.OPENSSL] Directory.
$!
$ WRITE SYS$OUTPUT "Rebuilding The '[.INCLUDE.OPENSSL]' Directory."
$!
$! First, make sure the directory exists
$!
$ IF F$PARSE("SYS$DISK:[.INCLUDE.OPENSSL]") .EQS. "" THEN -
     CREATE/DIRECTORY SYS$DISK:[.INCLUDE.OPENSSL]
$!
$! Copy All The ".H" Files From The Main Directory.
$!
$ EXHEADER := e_os.h,e_os2.h
$ COPY 'EXHEADER' SYS$DISK:[.INCLUDE.OPENSSL]
$!
$! Copy All The ".H" Files From The [.CRYPTO] Directory Tree.
$!
$ SDIRS := ,MD2,MD5,SHA,MDC2,HMAC,RIPEMD,-
   DES,RC2,RC4,RC5,IDEA,BF,CAST,-
   BN,RSA,DSA,DH,-
   BUFFER,BIO,STACK,LHASH,RAND,ERR,OBJECTS,-
   EVP,ASN1,PEM,X509,X509V3,-
   CONF,TXT_DB,PKCS7,PKCS12,COMP
$ EXHEADER_ := crypto.h,tmdiff.h,opensslv.h,opensslconf.h,ebcdic.h
$ EXHEADER_MD2 := md2.h
$ EXHEADER_MD5 := md5.h
$ EXHEADER_SHA := sha.h
$ EXHEADER_MDC2 := mdc2.h
$ EXHEADER_HMAC := hmac.h
$ EXHEADER_RIPEMD := ripemd.h
$ EXHEADER_DES := des.h
$ EXHEADER_RC2 := rc2.h
$ EXHEADER_RC4 := rc4.h
$ EXHEADER_RC5 := rc5.h
$ EXHEADER_IDEA := idea.h
$ EXHEADER_BF := blowfish.h
$ EXHEADER_CAST := cast.h
$ EXHEADER_BN := bn.h
$ EXHEADER_RSA := rsa.h
$ EXHEADER_DSA := dsa.h
$ EXHEADER_DH := dh.h
$ EXHEADER_BUFFER := buffer.h
$ EXHEADER_BIO := bio.h
$ EXHEADER_STACK := stack.h,safestack.h
$ EXHEADER_LHASH := lhash.h
$ EXHEADER_RAND := rand.h
$ EXHEADER_ERR := err.h
$ EXHEADER_OBJECTS := objects.h
$ EXHEADER_EVP := evp.h
$ EXHEADER_ASN1 := asn1.h,asn1_mac.h
$ EXHEADER_PEM := pem.h,pem2.h
$ EXHEADER_X509 := x509.h,x509_vfy.h
$ EXHEADER_X509V3 := x509v3.h
$ EXHEADER_CONF := conf.h
$ EXHEADER_TXT_DB := txt_db.h
$ EXHEADER_PKCS7 := pkcs7.h
$ EXHEADER_PKCS12 := pkcs12.h
$ EXHEADER_COMP := comp.h
$
$ I = 0
$ LOOP_SDIRS: 
$ D = F$EDIT(F$ELEMENT(I, ",", SDIRS),"TRIM")
$ I = I + 1
$ IF D .EQS. "," THEN GOTO LOOP_SDIRS_END
$ tmp = EXHEADER_'D'
$ IF D .EQS. ""
$ THEN
$   COPY [.CRYPTO]'tmp' SYS$DISK:[.INCLUDE.OPENSSL] /LOG
$ ELSE
$   COPY [.CRYPTO.'D']'tmp' SYS$DISK:[.INCLUDE.OPENSSL] /LOG
$ ENDIF
$ GOTO LOOP_SDIRS
$ LOOP_SDIRS_END:
$!
$! Copy All The ".H" Files From The [.RSAREF] Directory.
$!
$ EXHEADER := rsaref.h
$ COPY SYS$DISK:[.RSAREF]'EXHEADER' SYS$DISK:[.INCLUDE.OPENSSL]
$!
$! Copy All The ".H" Files From The [.SSL] Directory.
$!
$ EXHEADER := ssl.h,ssl2.h,ssl3.h,ssl23.h,tls1.h
$ COPY SYS$DISK:[.SSL]'EXHEADER' SYS$DISK:[.INCLUDE.OPENSSL]
$!
$! Copy All The ".H" Files From The [.VMS] Directory.
$!
$ EXHEADER := vms_idhacks.h
$ COPY SYS$DISK:[.VMS]'EXHEADER' SYS$DISK:[.INCLUDE.OPENSSL]
$!
$! Purge all doubles
$!
$ PURGE SYS$DISK:[.INCLUDE.OPENSSL]*.H
$!
$! That's All, Time To RETURN.
$!
$ RETURN
$!
$! Build The "[.xxx.EXE.CRYPTO]LIBCRYPTO.OLB" Library.
$!
$ CRYPTO:
$!
$! Tell The User What We Are Doing.
$!
$ WRITE SYS$OUTPUT ""
$ WRITE SYS$OUTPUT "Building The [.",ARCH,".EXE.CRYPTO]LIBCRYPTO.OLB Library."
$!
$! Go To The [.CRYPTO] Directory.
$!
$ SET DEFAULT SYS$DISK:[.CRYPTO]
$!
$! Build The [.xxx.EXE.CRYPTO]LIBCRYPTO.OLB Library.
$!  
$ @CRYPTO-LIB 'RSAREF' 'DEBUGGER' "''COMPILER'" "''TCPIP_TYPE'" 'ISSEVEN'
$!
$! Go Back To The Main Directory.
$!
$ SET DEFAULT [-]
$!
$! Time To RETURN.
$!
$ RETURN
$!
$! Build The [.xxx.EXE.RSAREF]LIBRSAGLUE Library.
$!
$ RSAREF:
$!
$! Tell The User What We Are Doing.
$!
$ WRITE SYS$OUTPUT ""
$ WRITE SYS$OUTPUT "Building The [.",ARCH,".EXE.RSAREF]LIBRSAGLUE.OLB Library."
$!
$! Go To The [.RSAREF] Directory.
$!
$ SET DEFAULT SYS$DISK:[.RSAREF]
$!
$! Build The [.xxx.EXE.RSAREF]LIBRSAGLUE.OLB Library.
$!
$ @RSAREF-LIB LIBRARY 'DEBUGGER' "''COMPILER'" 'ISSEVEN'
$!
$! Go Back To The Main Directory.
$!
$ SET DEFAULT [-]
$!
$! Time To Return.
$!
$ RETURN
$!
$! Build The "[.xxx.EXE.SSL]LIBSSL.OLB" Library.
$!
$ SSL:
$!
$! Tell The User What We Are Doing.
$!
$ WRITE SYS$OUTPUT ""
$ WRITE SYS$OUTPUT "Building The [.",ARCH,".EXE.SSL]LIBSSL.OLB Library."
$!
$! Go To The [.SSL] Directory.
$!
$ SET DEFAULT SYS$DISK:[.SSL]
$!
$! Build The [.xxx.EXE.SSL]LIBSSL.OLB Library.
$!
$ @SSL-LIB LIBRARY 'RSAREF' 'DEBUGGER' "''COMPILER'" "''TCPIP_TYPE'" 'ISSEVEN'
$!
$! Go Back To The Main Directory.
$!
$ SET DEFAULT [-]
$!
$! Time To Return.
$!
$ RETURN
$!
$! Build The "[.xxx.EXE.SSL]SSL_TASK.EXE" Program.
$!
$ SSL_TASK:
$!
$! Tell The User What We Are Doing.
$!
$ WRITE SYS$OUTPUT ""
$ WRITE SYS$OUTPUT "Building DECNet Based SSL Engine, [.",ARCH,".EXE.SSL]SSL_TASK.EXE"
$!
$! Go To The [.SSL] Directory.
$!
$ SET DEFAULT SYS$DISK:[.SSL]
$!
$! Build The [.xxx.EXE.SSL]SSL_TASK.EXE
$!
$ @SSL-LIB SSL_TASK 'RSAREF' 'DEBUGGER' "''COMPILER'" "''TCPIP_TYPE'" 'ISSEVEN'
$!
$! Go Back To The Main Directory.
$!
$ SET DEFAULT [-]
$!
$! That's All, Time To RETURN.
$!
$ RETURN
$!
$! Build The OpenSSL Test Programs.
$!
$ TEST:
$!
$! Tell The User What We Are Doing.
$!
$ WRITE SYS$OUTPUT ""
$ WRITE SYS$OUTPUT "Building The OpenSSL [.",ARCH,".EXE.TEST] Test Utilities."
$!
$! Go To The [.TEST] Directory.
$!
$ SET DEFAULT SYS$DISK:[.TEST]
$!
$! Build The Test Programs.
$!
$ @MAKETESTS 'RSAREF' 'DEBUGGER' "''COMPILER'" "''TCPIP_TYPE'" 'ISSEVEN'
$!
$! Go Back To The Main Directory.
$!
$ SET DEFAULT [-]
$!
$! That's All, Time To RETURN.
$!
$ RETURN
$!
$! Build The OpenSSL Application Programs.
$!
$ APPS:
$!
$! Tell The User What We Are Doing.
$!
$ WRITE SYS$OUTPUT ""
$ WRITE SYS$OUTPUT "Building OpenSSL [.",ARCH,".EXE.APPS] Applications."
$!
$! Go To The [.APPS] Directory.
$!
$ SET DEFAULT SYS$DISK:[.APPS]
$!
$! Build The Application Programs.
$!
$ @MAKEAPPS 'RSAREF' 'DEBUGGER' "''COMPILER'" "''TCPIP_TYPE'" 'ISSEVEN'
$!
$! Go Back To The Main Directory.
$!
$ SET DEFAULT [-]
$!
$! That's All, Time To RETURN.
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
$!   P1 Is ALL, So Build Everything.
$!
$    BUILDALL = "TRUE"
$!
$! Else...
$!
$ ELSE
$!
$!  Else, Check To See If P1 Has A Valid Arguement.
$!
$   IF (P1.EQS."BUILDINF").OR.(P1.EQS."SOFTLINKS").OR.(P1.EQS."CRYPTO") -
       .OR.(P1.EQS."SSL").OR.(P1.EQS."RSAREF").OR.(P1.EQS."SSL_TASK") -
       .OR.(P1.EQS."TEST").OR.(P1.EQS."APPS")
$   THEN
$!
$!    A Valid Arguement.
$!
$     BUILDALL = P1
$!
$!  Else...
$!
$   ELSE
$!
$!    Tell The User We Don't Know What They Want.
$!
$     WRITE SYS$OUTPUT ""
$     WRITE SYS$OUTPUT "The Option ",P1," Is Invalid.  The Valid Options Are:"
$     WRITE SYS$OUTPUT ""
$     WRITE SYS$OUTPUT "    ALL      :  Just Build Everything."
$     WRITE SYS$OUTPUT "    BUILDINF :  Just build the [.CRYPTO]BUILDINF.H file."
$     WRITE SYS$OUTPUT "    SOFTLINKS:  Just Fix The Unix soft links."
$     WRITE SYS$OUTPUT "    RSAREF   :  To Build Just The [.xxx.EXE.RSAREF]LIBRSAGLUE.OLB Library."
$     WRITE SYS$OUTPUT "    CRYPTO   :  To Build Just The [.xxx.EXE.CRYPTO]LIBCRYPTO.OLB Library."
$     WRITE SYS$OUTPUT "    SSL      :  To Build Just The [.xxx.EXE.SSL]LIBSSL.OLB Library."
$     WRITE SYS$OUTPUT "    SSL_TASK :  To Build Just The [.xxx.EXE.SSL]SSL_TASK.EXE Program."
$     WRITE SYS$OUTPUT "    TEST     :  To Build Just The OpenSSL Test Programs."
$     WRITE SYS$OUTPUT "    APPS     :  To Build Just The OpenSSL Application Programs."
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
$!  End The Valid Argument Check.
$!
$   ENDIF
$!
$! End The P1 Check.
$!
$ ENDIF
$!
$! Check To See If P2 Is Blank.
$!
$ IF (P2.EQS."NORSAREF")
$ THEN
$!
$!   P2 Is NORSAREF, So Compile Without RSAREF.
$!
$    RSAREF = "NORSAREF"
$!
$! Else...
$!
$ ELSE
$!
$!  Check To See If We Are To Compile Using The RSAREF Library.
$!
$   IF (P2.EQS."RSAREF")
$   THEN
$!
$!    Compile With RSAREF Library.
$!
$     RSAREF = "RSAREF"
$!
$!  Else...
$!
$   ELSE
$!
$!    Tell The User Entered An Invalid Option..
$!
$     WRITE SYS$OUTPUT ""
$     WRITE SYS$OUTPUT "The Option ",P2," Is Invalid.  The Valid Options Are:"
$     WRITE SYS$OUTPUT ""
$     WRITE SYS$OUTPUT "    RSAREF   :  To Compile With The RSAREF Library."
$     WRITE SYS$OUTPUT "    NORSAREF :  To Compile With The Regular RSA Library."
$     WRITE SYS$OUTPUT ""
$!
$!    Time To EXIT.
$!
$     EXIT
$!
$!  End The Valid Arguemnt Check.
$!
$   ENDIF
$!
$! End The P2 Check.
$!
$ ENDIF
$!
$! Check To See If P3 Is Blank.
$!
$ IF (P3.EQS."NODEBUG")
$ THEN
$!
$!   P3 Is NODEBUG, So Compile Without Debugger Information.
$!
$    DEBUGGER = "NODEBUG"
$!
$! Else...
$!
$ ELSE
$!
$!  Check To See If We Are To Compile With Debugger Information.
$!
$   IF (P3.EQS."DEBUG")
$   THEN
$!
$!    Compile With Debugger Information.
$!
$     DEBUGGER = "DEBUG"
$!
$!  Else...
$!
$   ELSE
$!
$!    Tell The User Entered An Invalid Option..
$!
$     WRITE SYS$OUTPUT ""
$     WRITE SYS$OUTPUT "The Option ",P3," Is Invalid.  The Valid Options Are:"
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
$! End The P3 Check.
$!
$ ENDIF
$!
$! Check To See If P4 Is Blank.
$!
$ IF (P4.EQS."")
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
$!    Tell The User We Are Using GNUC.
$!
$     WRITE SYS$OUTPUT "Using GNU 'C' Compiler."
$!
$!  End The GNU C Compiler Check.
$!
$   ENDIF
$!
$!  Check To See If We Have VAXC Or DECC.
$!
$   IF (F$GETSYI("CPU").GE.128).OR.(F$TRNLNM("DECC$CC_DEFAULT").EQS."/DECC")
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
$!  Else...
$!
$   ELSE
$!
$!    Looks Like VAXC, Set To Use VAXC.
$!
$     COMPILER = "VAXC"
$!
$!    Tell The User We Are Using VAX C.
$!
$     WRITE SYS$OUTPUT "Using VAXC 'C' Compiler."
$!
$!  End The DECC & VAXC Compiler Check.
$!
$   ENDIF
$!
$! Else...
$!
$ ELSE
$!
$!  Check To See If The User Entered A Valid Paramter.
$!
$   IF (P4.EQS."VAXC").OR.(P4.EQS."DECC").OR.(P4.EQS."GNUC")!.OR.(P4.EQS."LINK")
$   THEN
$!
$!    Check To See If The User Wanted To Just LINK.
$!
$     IF (P4.EQS."LINK")
$     THEN
$!
$!      Looks Like LINK-only
$!
$       COMPILER = "LINK"
$!
$!      Tell The User We Are Only Linking.
$!
$       WRITE SYS$OUTPUT "LINK Only.  This actually NOT YET SUPPORTED!"
$!
$!    End LINK Check.
$!
$     ENDIF
$!
$!    Check To See If The User Wanted DECC.
$!
$     IF (P4.EQS."DECC")
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
$!    End DECC Check.
$!
$     ENDIF
$!
$!    Check To See If We Are To Use VAXC.
$!
$     IF (P4.EQS."VAXC")
$     THEN
$!
$!      Looks Like VAXC, Set To Use VAXC.
$!
$       COMPILER = "VAXC"
$!
$!      Tell The User We Are Using VAX C.
$!
$       WRITE SYS$OUTPUT "Using VAXC 'C' Compiler."
$!
$!    End VAXC Check
$!
$     ENDIF
$!
$!    Check To See If We Are To Use GNU C.
$!
$     IF (P4.EQS."GNUC")
$     THEN
$!
$!      Looks Like GNUC, Set To Use GNUC.
$!
$       COMPILER = "GNUC"
$!
$!      Tell The User We Are Using GNUC.
$!
$       WRITE SYS$OUTPUT "Using GNU 'C' Compiler."
$!
$!    End The GNU C Check.
$!
$     ENDIF
$!
$!  Else The User Entered An Invalid Arguement.
$!
$   ELSE
$!
$!    Tell The User We Don't Know What They Want.
$!
$     WRITE SYS$OUTPUT ""
$     WRITE SYS$OUTPUT "The Option ",P4," Is Invalid.  The Valid Options Are:"
$     WRITE SYS$OUTPUT ""
$     WRITE SYS$OUTPUT "    VAXC  :  To Compile With VAX C."
$     WRITE SYS$OUTPUT "    DECC  :  To Compile With DEC C."
$     WRITE SYS$OUTPUT "    GNUC  :  To Compile With GNU C."
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
$! End The P4 Check.
$!
$ ENDIF
$!
$! Time to check the contents of P5, and to make sure we get the correct library.
$!
$ IF P5.EQS."SOCKETSHR" .OR. P5.EQS."MULTINET" .OR. P5.EQS."UCX"
$ THEN
$!
$!  Check to see if SOCKETSHR was chosen
$!
$   IF P5.EQS."SOCKETSHR"
$   THEN
$!
$!    Set the library to use SOCKETSHR
$!
$     TCPIP_LIB = "[-.VMS]SOCKETSHR_SHR.OPT/OPT"
$!
$!    Tell the user
$!
$     WRITE SYS$OUTPUT "Using SOCKETSHR for TCP/IP"
$!
$!    Done with SOCKETSHR
$!
$   ENDIF
$!
$!  Check to see if MULTINET was chosen
$!
$   IF P5.EQS."MULTINET"
$   THEN
$!
$!    Set the library to use UCX emulation.
$!
$     P5 = "UCX"
$!
$!    Tell the user
$!
$     WRITE SYS$OUTPUT "Using MultiNet via UCX emulation for TCP/IP"
$!
$!    Done with MULTINET
$!
$   ENDIF
$!
$!  Check to see if UCX was chosen
$!
$   IF P5.EQS."UCX"
$   THEN
$!
$!    Set the library to use UCX.
$!
$     TCPIP_LIB = "[-.VMS]UCX_SHR_DECC.OPT/OPT"
$!
$!    Tell the user
$!
$     WRITE SYS$OUTPUT "Using UCX or an emulation thereof for TCP/IP"
$!
$!    Done with UCX
$!
$   ENDIF
$!
$!  Set the TCPIP_TYPE symbol
$!
$   TCPIP_TYPE = P5
$!
$!  Print info
$!
$   WRITE SYS$OUTPUT "TCP/IP library spec: ", TCPIP_LIB
$!
$!  Else The User Entered An Invalid Arguement.
$!
$ ELSE
$   IF P5 .NES. ""
$   THEN
$!
$!    Tell The User We Don't Know What They Want.
$!
$     WRITE SYS$OUTPUT ""
$     WRITE SYS$OUTPUT "The Option ",P5," Is Invalid.  The Valid Options Are:"
$     WRITE SYS$OUTPUT ""
$     WRITE SYS$OUTPUT "    SOCKETSHR  :  To link with SOCKETSHR TCP/IP library."
$     WRITE SYS$OUTPUT "    UCX        :  To link with UCX TCP/IP library."
$     WRITE SYS$OUTPUT ""
$!
$!    Time To EXIT.
$!
$     EXIT
$   ELSE
$!
$!    Set the TCPIP_TYPE symbol
$!
$     TCPIP_TYPE = P5
$   ENDIF
$!
$!  Done with TCP/IP libraries
$!
$ ENDIF
$!
$! Special Threads For OpenVMS v7.1 Or Later
$!
$! Written By:  Richard Levitte
$!              richard@levitte.org
$!
$!
$! Check To See If We Have A Option For P6.
$!
$ IF (P6.EQS."")
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
$! End The P6 Check.
$!
$ ENDIF
$!
$!  Time To RETURN...
$!
$ RETURN
