$!
$!------------------------------------------------------------------------------
$! SSL$HASH_CERT.COM - SSL Hash Certificate procedure
$!------------------------------------------------------------------------------
$!
$ Verify = F$VERIFY (0)
$ Set NoOn
$ Set NoControl=Y
$!
$!------------------------------------------------------------------------------
$! Description 
$!------------------------------------------------------------------------------
$!
$! This procedure prompts the user through hashing Certificates.
$!
$! The parameters used are:
$!
$! 	P1	- Certificate or Certificate Revocation List (i.e. "CRT" or "CRL")
$!
$!------------------------------------------------------------------------------
$! Define symbols
$!------------------------------------------------------------------------------
$!
$ DELETE := DELETE
$ SAY := WRITE SYS$OUTPUT
$ ASK := READ SYS$COMMAND /END_OF_FILE=EXIT /PROMPT=
$ On Control_Y THEN GOTO EXIT
$ Set Control=Y
$!
$ TT_ROWS = F$GETDVI ("TT:","TT_PAGE")
$ TT_COLS = F$GETDVI ("TT:","DEVBUFSIZ")
$!
$ INIT_TERM := @SSL$COM:SSL$INIT_TERM
$!
$ ESC[0,8] = 27 	! Set the Escape Character
$ BELL[0,8] = 7 	! Ring the terminal Bell
$ RED = 1		! Color - Red
$ FGD = 30		! Foreground
$ BGD = 0		! Background
$ CSCR = ESC + "[2J"	! Clear the Screen 
$ CEOS = ESC + "[0J"	! Clear to the End of the Screen 
$ CEOL = ESC + "[0K"	! Clear to the End of the Line
$ NORM = ESC + "[0m"	! Turn Attributes off
$ BLNK = ESC + "[5m"    ! Turn on BLINK Attribute
$ WIDE = ESC + "#6"     ! Turn on WIDE Attribute
$!
$!------------------------------------------------------------------------------
$! Run the SSL setup if it hasn't been run yet
$!------------------------------------------------------------------------------
$!
$ IF F$TRNLNM ("SSL$ROOT") .EQS. ""
$ THEN
$     IF F$SEARCH ("SSL$COM:SSL$INIT_ENV.COM") .NES. ""
$     THEN 
$         @SSL$COM:SSL$INIT_ENV.COM
$     ELSE
$         SAY BELL, "Unable to locate SSL$COM:SSL$INIT_ENV.COM ..."
$	  GOTO EXIT
$     ENDIF
$ ENDIF
$!
$!------------------------------------------------------------------------------
$! Display the Page Header
$!------------------------------------------------------------------------------
$!
$ INIT_TERM
$ BCOLOR = BGD
$ FCOLOR = FGD + RED
$ COLOR = ESC + "[''BCOLOR';''FCOLOR'm"
$!
$ TEXT = "SSL Certificate Tool"
$ COL = (TT_COLS - (F$LENGTH (TEXT) * 2)) / 4
$!
$ SAY ESC + "[01;01H", CSCR
$ SAY ESC + "[02;''COL'H", COLOR, WIDE, TEXT, NORM
$!
$ IF P1 .EQS. "CRT"
$ THEN 
$     TEXT = "Hash Certification Authorities"
$ ELSE
$     TEXT = "Hash Certificate Revocations"
$ ENDIF
$ COL = (TT_COLS - F$LENGTH (TEXT)) / 2
$!
$ SAY ESC + "[04;01H"
$ SAY ESC + "[04;''COL'H", COLOR, TEXT, NORM
$!
$ CTR = 1
$ ROW = 6
$ COL = 2
$ TOP_ROW = ROW
$ MSG_ROW = TT_ROWS - 1
$!
$!------------------------------------------------------------------------------
$! Initialize the Request Data
$!------------------------------------------------------------------------------
$!
$ IF P1 .EQS. "CRT"
$ THEN 
$     PRM = "Certificate Path:"
$     DEF = "SSL$CRT:*.CRT"
$ ENDIF
$!
$ IF P1 .EQS. "CRL"
$ THEN 
$     PRM = "Certificate Revocation Path:"
$     DEF = "SSL$CRT:*.CRL"
$ ENDIF
$!
$ SAY ESC + "[''MSG_ROW';01H", CEOS
$!
$!------------------------------------------------------------------------------
$! Confirm/Update the SSL Configuration Data
$!------------------------------------------------------------------------------
$!
$PROMPT_LOOP:
$!
$ PROMPT = ESC + "[''ROW';''COL'H''PRM' ? [''DEF'] ''CEOL'"
$ ASK "''PROMPT'" _hash_path_name
$ _hash_path_name = F$EDIT (_hash_path_name,"TRIM")
$ IF _hash_path_name .EQS. "" THEN _hash_path_name = DEF
$!
$ HASH_DEV = F$PARSE (_hash_path_name,DEF,,"DEVICE")
$ HASH_DIR = F$PARSE (_hash_path_name,DEF,,"DIRECTORY")
$ HASH_NAM = F$PARSE (_hash_path_name,DEF,,"NAME")
$ HASH_TYP = F$PARSE (_hash_path_name,DEF,,"TYPE")
$ _hash_path_name = HASH_DEV + HASH_DIR + HASH_NAM + HASH_TYP
$!
$!------------------------------------------------------------------------------
$! Create the Certificiate Hashes 
$!------------------------------------------------------------------------------
$!
$ IF P1 .EQS. "CRT"
$ THEN 
$     SAY ESC + "[''MSG_ROW';01H", BLNK, " Hashing Certificate Authorities ...", NORM, CEOL
$ ENDIF
$!
$ IF P1 .EQS. "CRL"
$ THEN 
$     SAY ESC + "[''MSG_ROW';01H", BLNK, " Hashing Certificate Revocations ...", NORM, CEOL
$ ENDIF
$!
$ IF F$SEARCH ("''HASH_DEV'''HASH_DIR'DELETE_HASH_FILES.COM") .NES. ""
$ THEN 
$    @'HASH_DEV''HASH_DIR'DELETE_HASH_FILES.COM
$    DELETE 'HASH_DEV''HASH_DIR'DELETE_HASH_FILES.COM;*
$ ENDIF
$!
$ CTR = 0
$!     
$ OPEN /WRITE OFILE 'HASH_DEV''HASH_DIR'DELETE_HASH_FILES.COM
$!
$CERT_LOOP:
$!
$ CERT_FILE = F$SEARCH ("''_hash_path_name'", 1)
$ IF CERT_FILE .EQS. "" THEN GOTO CERT_END
$ CTR = CTR + 1
$!
$ CALL HASH_CERT 'P1' 'CERT_FILE'
$!
$ GOTO CERT_LOOP
$!
$CERT_END:
$!
$ CLOSE OFILE
$!
$ IF CTR .EQ. 0 
$ THEN 
$     TEXT = "No files found, Press return to continue"
$ ELSE
$     TEXT = "Press return to continue"
$ ENDIF
$ COL = (TT_COLS - F$LENGTH (TEXT)) / 2
$!
$ IF CTR .EQ. 0 
$ THEN 
$     SAY BELL, ESC + "[''MSG_ROW';01H", CEOS
$ ELSE
$     SAY ESC + "[''MSG_ROW';01H", CEOS
$ ENDIF
$ PROMPT = ESC + "[''MSG_ROW';''COL'H''TEXT'"
$ ASK "''PROMPT'" OPT
$!
$ GOTO EXIT
$!
$!------------------------------------------------------------------------------
$! Hash Certificate Subroutine
$!------------------------------------------------------------------------------
$!
$HASH_CERT: SUBROUTINE
$!
$ IF P1 .EQS. "CRT"
$ THEN 
$     HASH_SUFF = ""
$     HASH_FUNC = "$SSL$EXE:OPENSSL X509 -HASH -NOOUT -IN"
$ ELSE
$     HASH_SUFF = "R"
$     HASH_FUNC = "$SSL$EXE:OPENSSL CRL -HASH -NOOUT -IN"
$ ENDIF
$!
$ PIPE HASH_FUNC 'P2' | (READ SYS$INPUT VAL ; DEFINE/NOLOG/JOB HASH_VAL &VAL)
$ HASH_VAL = F$TRNLNM ("HASH_VAL")
$ DEASSIGN /JOB HASH_VAL
$!
$ IDX = 0
$!
$IDX_LOOP:
$!
$ HASH_FILE = "''HASH_DEV'''HASH_DIR'''HASH_VAL'.''HASH_SUFF'''IDX'"
$ IF F$SEARCH ("''HASH_FILE'") .NES. ""
$ THEN
$     IDX = IDX + 1
$     GOTO IDX_LOOP
$ ENDIF
$!
$ COPY 'P2' 'HASH_FILE'
$ WRITE OFILE "$ DELETE ''HASH_FILE';*"
$!
$ EXIT
$!
$ ENDSUBOUTINE
$!
$!------------------------------------------------------------------------------
$! Exit the procedure
$!------------------------------------------------------------------------------
$!
$EXIT:
$!
$ DEFINE /USER /NOLOG SYS$ERROR  NL:
$ DEFINE /USER /NOLOG SYS$OUTPUT NL:
$ CLOSE OFILE
$!
$ Verify = F$VERIFY (Verify)
$!
$ EXIT
