$!
$!------------------------------------------------------------------------------
$! SSL$VIEW_CERT.COM - SSL View Certificate procedure
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
$! This procedure prompts the user through creating a Server Certificate.
$!
$! The parameters used are:
$!
$! 	P1	- Certificate or Certificate Request (i.e. "CRT" or "CSR")
$!
$!------------------------------------------------------------------------------
$! Define symbols
$!------------------------------------------------------------------------------
$!
$ DELETE := DELETE
$ SAY := WRITE SYS$OUTPUT
$ ASK := READ SYS$COMMAND /END_OF_FILE=EXIT /PROMPT=
$ PID = F$GETJPI ("","PID")
$ TT_NOECHO = F$GETDVI ("TT:","TT_NOECHO")
$ On Control_Y THEN GOTO EXIT
$ Set Control=Y
$!
$ TT_ROWS = F$GETDVI ("TT:","TT_PAGE")
$ TT_COLS = F$GETDVI ("TT:","DEVBUFSIZ")
$!
$ INIT_TERM := @SSL$COM:SSL$INIT_TERM
$ PICK_FILE := @SSL$COM:SSL$PICK_FILE 
$ SHOW_FILE := @SSL$COM:SSL$SHOW_FILE 
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
$ IF P1 .EQS. "CSR"
$ THEN 
$     TEXT = "View Certificate Request"
$ ELSE
$     TEXT = "View Certificate"
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
$ IF P1 .NES. "CRT" .AND. P1 .NES. "CSR"
$ THEN 
$     PRM = "Display File:"
$     DEF = "*.*"
$ ENDIF
$!
$ IF P1 .EQS. "CRT"
$ THEN 
$     PRM = "Display Certificate File:"
$     DEF = "SSL$CRT:*.CRT"
$ ENDIF
$!
$ IF P1 .EQS. "CSR"
$ THEN 
$     PRM = "Display Certificate Request File:"
$     DEF = "SSL$CSR:*.CSR"
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
$ ASK "''PROMPT'" _view_file_name
$ _view_file_name = F$EDIT (_view_file_name,"TRIM")
$ IF _view_file_name .EQS. "" THEN _view_file_name = DEF
$!
$ X1 = 2
$ Y1 = TOP_ROW
$ X2 = TT_COLS - 2
$ Y2 = MSG_ROW - 1
$!
$PICK_FILE:
$!
$ PICK_FILE "''_view_file_name'" 'X1' 'Y1' 'X2' 'Y2' "< Select a File >" 
$!
$ SAY ESC + "[''TOP_ROW';01H", CEOS
$! 
$ IF SSL_FILE_NAME .EQS. "" THEN GOTO EXIT
$!
$!------------------------------------------------------------------------------
$! Create the Certificiate Authority
$!------------------------------------------------------------------------------
$!
$ SAY ESC + "[''MSG_ROW';01H", BLNK, " Generating Output ...", NORM, CEOL
$!
$ IF P1 .EQS. "CRT"
$ THEN 
$     OPEN /WRITE OFILE SYS$LOGIN:SSL_X509_'PID'.COM
$     WRITE OFILE "$ DEFINE /USER /NOLOG SYS$ERROR   SYS$LOGIN:SSL_X509_''PID'.LOG"
$     WRITE OFILE "$ DEFINE /USER /NOLOG SYS$OUTPUT  SYS$LOGIN:SSL_X509_''PID'.LOG"
$     WRITE OFILE "$ DEFINE /USER /NOLOG SYS$COMMAND SYS$INPUT"
$     WRITE OFILE "$ OPENSSL x509 -noout -text -in ''SSL_FILE_NAME'"
$     CLOSE OFILE
$!
$     @SYS$LOGIN:SSL_X509_'PID'.COM
$!
$     DELETE/NOLOG/NOCONFIRM SYS$LOGIN:SSL_X509_'PID'.COM;*
$!
$     DEFINE /USER /NOLOG SYS$ERROR  NL:
$     DEFINE /USER /NOLOG SYS$OUTPUT NL:
$     SEARCH SYS$LOGIN:SSL_X509_'PID'.LOG /OUT=SYS$LOGIN:SSL_X509_'PID'.ERR ":error:"
$     IF F$SEARCH ("SYS$LOGIN:SSL_X509_''PID'.ERR") .NES. "" 
$     THEN 
$         IF F$FILE_ATTRIBUTE ("SYS$LOGIN:SSL_X509_''PID'.ERR","ALQ") .NE. 0
$         THEN 
$             DELETE /NOLOG /NOCONFIRM SYS$LOGIN:SSL_X509_'PID'.ERR;*
$             SAY ESC + "[''MSG_ROW';01H''BELL'''CEOS'"
$             SHOW_FILE "SYS$LOGIN:SSL_X509_''PID'.LOG" 'X1' 'Y1' 'X2' 'Y2' "< ERROR >" 
$             DELETE /NOLOG /NOCONFIRM SYS$LOGIN:SSL_X509_'PID'.LOG;*
$             GOTO EXIT
$         ENDIF
$         DELETE /NOLOG /NOCONFIRM SYS$LOGIN:SSL_X509_'PID'.ERR;*
$     ENDIF
$!
$     SAY ESC + "[''MSG_ROW';01H''CEOS'"
$     SHOW_FILE "SYS$LOGIN:SSL_X509_''PID'.LOG" 'X1' 'Y1' 'X2' 'Y2' "< ''SSL_FILE_NAME' >" 
$     DELETE /NOLOG /NOCONFIRM SYS$LOGIN:SSL_X509_'PID'.LOG;*
$     GOTO PICK_FILE
$ ENDIF
$!
$ IF P1 .EQS. "CSR"
$ THEN 
$     OPEN /WRITE OFILE SYS$LOGIN:SSL_REQ_'PID'.COM
$     WRITE OFILE "$ DEFINE /USER /NOLOG SYS$ERROR   SYS$LOGIN:SSL_REQ_''PID'.LOG"
$     WRITE OFILE "$ DEFINE /USER /NOLOG SYS$OUTPUT  SYS$LOGIN:SSL_REQ_''PID'.LOG"
$     WRITE OFILE "$ DEFINE /USER /NOLOG SYS$COMMAND SYS$INPUT"
$     WRITE OFILE "$ OPENSSL req -noout -text -in ''SSL_FILE_NAME'"
$     CLOSE OFILE
$!
$     @SYS$LOGIN:SSL_REQ_'PID'.COM
$!
$     DELETE/NOLOG/NOCONFIRM SYS$LOGIN:SSL_REQ_'PID'.COM;*
$!
$     DEFINE /USER /NOLOG SYS$ERROR  NL:
$     DEFINE /USER /NOLOG SYS$OUTPUT NL:
$     SEARCH SYS$LOGIN:SSL_REQ_'PID'.LOG /OUT=SYS$LOGIN:SSL_REQ_'PID'.ERR ":error:"
$     IF F$SEARCH ("SYS$LOGIN:SSL_REQ_''PID'.ERR") .NES. "" 
$     THEN 
$         IF F$FILE_ATTRIBUTE ("SYS$LOGIN:SSL_REQ_''PID'.ERR","ALQ") .NE. 0
$         THEN 
$             DELETE /NOLOG /NOCONFIRM SYS$LOGIN:SSL_REQ_'PID'.ERR;*
$             SAY ESC + "[''MSG_ROW';01H''BELL'''CEOS'"
$             SHOW_FILE "SYS$LOGIN:SSL_REQ_''PID'.LOG" 'X1' 'Y1' 'X2' 'Y2' "< ERROR >" 
$             DELETE /NOLOG /NOCONFIRM SYS$LOGIN:SSL_REQ_'PID'.LOG;*
$             GOTO EXIT
$         ENDIF
$         DELETE /NOLOG /NOCONFIRM SYS$LOGIN:SSL_REQ_'PID'.ERR;*
$     ENDIF
$!
$     SAY ESC + "[''MSG_ROW';01H''CEOS'"
$     SHOW_FILE "SYS$LOGIN:SSL_REQ_''PID'.LOG" 'X1' 'Y1' 'X2' 'Y2' "< ''SSL_FILE_NAME' >" 
$     DELETE /NOLOG /NOCONFIRM SYS$LOGIN:SSL_REQ_'PID'.LOG;*
$     GOTO PICK_FILE
$ ENDIF
$!
$ SAY ESC + "[''MSG_ROW';01H''CEOS'"
$ SHOW_FILE "''SYS$LOGIN:SSL_FILE_NAME'" 'X1' 'Y1' 'X2' 'Y2' "< ''SSL_FILE_NAME' >"
$ GOTO PICK_FILE
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
$ IF F$TYPE (SSL_FILE_NAME) .NES. "" THEN DELETE /SYMBOL /GLOBAL SSL_FILE_NAME
$!
$ IF F$GETDVI ("TT:","TT_NOECHO") .AND. .NOT. TT_NOECHO THEN SET TERMINAL /ECHO
$!
$ IF F$SEARCH ("SYS$LOGIN:SSL_REQ_''PID'.%%%;*") .NES. "" THEN DELETE /NOLOG /NOCONFIRM SYS$LOGIN:SSL_REQ_'PID'.%%%;*
$ IF F$SEARCH ("SYS$LOGIN:SSL_X509_''PID'.%%%;*") .NES. "" THEN DELETE /NOLOG /NOCONFIRM SYS$LOGIN:SSL_X509_'PID'.%%%;*
$!
$ Verify = F$VERIFY (Verify)
$!
$ EXIT
