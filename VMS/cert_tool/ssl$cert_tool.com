$!
$!------------------------------------------------------------------------------
$! SSL$CERT_TOOL.COM - SSL Certificate Tool procedure
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
$! This procedure provides the user a menu from which they can choose desired 
$! SSL Certificate processing.
$!
$! There are no parameters used.
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
$ TT_ROWS = f$getdvi ("TT:","TT_PAGE")
$ TT_COLS = f$getdvi ("TT:","DEVBUFSIZ")
$!
$ SET_MENU_DATA := CALL SET_MENU_DATA
$ DEL_MENU_DATA := CALL DEL_MENU_DATA
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
$ BOLD = ESC + "[1m"    ! Turn on BOLD Attribute
$ WIDE = ESC + "#6"     ! Turn on WIDE Attribute
$!
$!------------------------------------------------------------------------------
$! Run the SSL setup if it hasn't been run yet
$!------------------------------------------------------------------------------
$!
$ IF F$TRNLNM ("SSL$CA_CONF") .EQS. ""
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
$! Initialize the Menu Items
$!------------------------------------------------------------------------------
$!
$ SET_MENU_DATA "View a Certificate#@SSL$COM:SSL$VIEW_CERT.COM CRT"
$ SET_MENU_DATA "View a Certificate Signing Request#@SSL$COM:SSL$VIEW_CERT.COM CSR"
$ SET_MENU_DATA "Create a Certificate Signing Request#@SSL$COM:SSL$RQST_CERT.COM"
$ SET_MENU_DATA "Create a Self-Signed Certificate#@SSL$COM:SSL$SELF_CERT.COM"
$ SET_MENU_DATA "Create a CA (Certification Authority) Certificate#@SSL$COM:SSL$AUTH_CERT.COM"
$ SET_MENU_DATA "Sign a Certificate Signing Request#@SSL$COM:SSL$SIGN_CERT.COM"
$ SET_MENU_DATA "Hash Certificates#@SSL$COM:SSL$HASH_CERT.COM CRT"
$ SET_MENU_DATA "Hash Certificate Revocations#@SSL$COM:SSL$HASH_CERT.COM CRL"
$ SET_MENU_DATA "Exit#GOTO EXIT"
$!
$!------------------------------------------------------------------------------
$! Display the Page Header
$!------------------------------------------------------------------------------
$!
$PAGE_LOOP:
$!
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
$ TEXT = "Main Menu"
$ COL = (TT_COLS - F$LENGTH (TEXT)) / 2
$!
$ SAY ESC + "[04;01H"
$ SAY ESC + "[04;''COL'H", COLOR, TEXT, NORM
$!
$ CTR = 1
$ ROW = 6
$ COL = (TT_COLS - (SSL_MENU_ITEM_MAX + 4)) / 2
$ TOP_ROW = ROW
$ SEP_ROWS = 2
$ MSG_ROW = TT_ROWS - 1
$!
$!------------------------------------------------------------------------------
$! Process the menu options
$!------------------------------------------------------------------------------
$!
$MENU_LOOP: 
$!
$ IF CTR .LE. SSL_MENU_DATA_MAX
$ THEN
$     OPT = F$ELEMENT (0,"#",SSL_MENU_DATA_'CTR') ! Option String
$     CMD = F$ELEMENT (1,"#",SSL_MENU_DATA_'CTR') ! Command String
$     IF ROW .GE. (MSG_ROW - (SEP_ROWS + 2)) .AND. SEP_ROWS .GT. 1
$     THEN
$         SAY ESC + "[''TOP_ROW';01H", CEOS
$	  ROW = TOP_ROW
$         SEP_ROWS = 1
$         CTR = 1
$     ELSE
$	  NUM = F$FAO ("!2SL", CTR)
$         SAY ESC + "[''ROW';''COL'H", BOLD, "''NUM'. ", NORM, "''OPT'"
$         ROW = ROW + SEP_ROWS
$         CTR = CTR + 1
$     ENDIF	   
$     GOTO MENU_LOOP
$ ENDIF    
$!
$ ROW = ROW + 1
$!
$!------------------------------------------------------------------------------
$! Prompt the user for input
$!------------------------------------------------------------------------------
$!
$PROMPT_LOOP:
$!
$ PROMPT = ESC + "[''ROW';''COL'HEnter Option: ''CEOL'"
$ ASK "''PROMPT'" OPT /END_OF_FILE=EXIT
$ OPT = F$EDIT (OPT, "TRIM")
$ IF OPT .EQS. ""  THEN GOTO PROMPT_LOOP
$!
$ IF F$TYPE (OPT) .NES. "INTEGER" .OR. -
     F$INTEGER (OPT) .LE. 0 .OR. -
     F$INTEGER (OPT) .GT. SSL_MENU_DATA_MAX
$ THEN 
$     CALL INVALID_OPTION
$     GOTO PROMPT_LOOP
$ ENDIF
$!
$ CMD = F$ELEMENT (1,"#",SSL_MENU_DATA_'OPT')
$!
$ 'CMD'
$!
$ GOTO PAGE_LOOP
$!
$!------------------------------------------------------------------------------
$! Set the Menu Data
$!------------------------------------------------------------------------------
$!
$SET_MENU_DATA: SUBROUTINE
$!
$ IF F$TYPE (SSL_MENU_DATA_MAX) .EQS. ""
$ THEN
$     SSL_MENU_DATA_MAX == 1
$     SSL_MENU_ITEM_MAX == 0
$ ELSE
$     SSL_MENU_DATA_MAX == SSL_MENU_DATA_MAX + 1
$ ENDIF
$!
$ SSL_MENU_DATA_'SSL_MENU_DATA_MAX' == "''P1'"
$!
$ MENU_ITEM = F$ELEMENT (0,"#",SSL_MENU_DATA_'SSL_MENU_DATA_MAX')
$ IF F$LENGTH (MENU_ITEM) .GT. SSL_MENU_ITEM_MAX THEN SSL_MENU_ITEM_MAX == F$LENGTH (MENU_ITEM)
$!
$ EXIT
$!
$ ENDSUBROUTINE
$!
$!------------------------------------------------------------------------------
$! Delete the Menu Data
$!------------------------------------------------------------------------------
$!
$DEL_MENU_DATA: SUBROUTINE
$!
$ IF F$TYPE (SSL_MENU_DATA_MAX) .EQS. "" THEN GOTO DEL_MENU_DATA_END
$!
$DEL_MENU_DATA_LOOP:
$!
$ IF F$TYPE (SSL_MENU_DATA_'SSL_MENU_DATA_MAX') .NES. "" 
$ THEN
$     DELETE /SYMBOL /GLOBAL SSL_MENU_DATA_'SSL_MENU_DATA_MAX'
$     SSL_MENU_DATA_MAX == SSL_MENU_DATA_MAX - 1
$     GOTO DEL_MENU_DATA_LOOP
$ ENDIF
$!
$ DELETE /SYMBOL /GLOBAL SSL_MENU_DATA_MAX
$!
$DEL_MENU_DATA_END:
$!
$ IF F$TYPE (SSL_MENU_ITEM_MAX) .NES. "" THEN DELETE /SYMBOL /GLOBAL SSL_MENU_ITEM_MAX
$!
$ EXIT
$!
$ ENDSUBROUTINE
$!
$!------------------------------------------------------------------------------
$! Display the invalid entry 
$!------------------------------------------------------------------------------
$!
$INVALID_OPTION: SUBROUTINE
$!
$ SAY ESC + "[''MSG_ROW';01H", BELL, " Invalid Option, Try again ...''CEOL'"
$ Wait 00:00:01.5
$ SAY ESC + "[''MSG_ROW';01H", CEOL
$!
$ EXIT
$!
$ ENDSUBROUTINE
$!
$!------------------------------------------------------------------------------
$! Exit
$!------------------------------------------------------------------------------
$!
$EXIT:
$!
$ DEL_MENU_DATA
$!
$ Verify = F$VERIFY (Verify)
$!
$ EXIT
