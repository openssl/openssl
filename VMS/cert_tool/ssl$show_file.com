$!
$!------------------------------------------------------------------------------
$! SSL$SHOW_FILE.COM - SSL Show File procedure
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
$! This procedure display the contents of a given file in a box size specified.
$!
$! The parameters used are:
$!
$! 	P1	- File to View
$! 	P2	- X1 coordinate
$! 	P3	- Y1 coordinate
$! 	P4	- X2 coordinate
$! 	P5	- Y3 coordinate
$! 	P6	- File Box Title (Optional)
$!
$!------------------------------------------------------------------------------
$! Define symbols
$!------------------------------------------------------------------------------
$!
$ SAY := WRITE SYS$OUTPUT
$ ASK := READ SYS$COMMAND /END_OF_FILE=EXIT /PROMPT=
$ On Control_Y THEN GOTO EXIT
$ Set Control=Y
$!
$ DRAW_BOX := @SSL$COM:SSL$DRAW_BOX
$ FILL_BOX := @SSL$COM:SSL$FILL_BOX
$!
$ ESC[0,8] = 27 	! Set the Escape Character
$ CEOL = ESC + "[0K"	! Clear to the End of the Line
$ NORM = ESC + "[0m"	! Turn Attributes off
$ BOLD = ESC + "[1m"    ! Turn on BOLD Attribute
$!
$!------------------------------------------------------------------------------
$! Display the Page Header
$!------------------------------------------------------------------------------
$!
$ REC_MAX = 0
$ OPEN /READ IFILE 'P1' 
$!
$READ_LOOP:
$!
$ READ /END_OF_FILE=READ_END IFILE IREC
$ REC_MAX = REC_MAX + 1
$ REC_'REC_MAX' = IREC
$ GOTO READ_LOOP
$!
$READ_END:
$!
$ CLOSE IFILE
$!
$ IF REC_MAX .EQ. 0
$ THEN 
$     DRAW_BOX 'P2' 'P3' 'P4' 'P5' "''P6'" " ** End-of-File **, Press Return to Exit "
$     INPUT_ROW = P5 + 1
$     PROMPT = ESC + "[''INPUT_ROW';01H ''CEOL'"
$     ASK "''PROMPT'" OPT
$     GOTO EXIT
$ ENDIF
$!
$ COL = P2 + 2
$ ROW = P3 + 2
$ TOP_ROW = ROW
$ INPUT_ROW = P5 + 1
$ BOX_WIDTH = P4 - (P2 + 2)
$ BOX_HEIGHT = P5 - (P3 + 3)
$!
$ REC_CTR = 1
$ PAGE_CTR = 1
$ PAGE_'PAGE_CTR'_REC_CTR = REC_CTR
$ RECS_PER_PAGE = BOX_HEIGHT
$ PAGE_MAX = REC_MAX / RECS_PER_PAGE
$ IF PAGE_MAX * RECS_PER_PAGE .LT. REC_MAX THEN PAGE_MAX = PAGE_MAX + 1
$!
$ DRAW_BOX 'P2' 'P3' 'P4' 'P5' "''P6'" " Enter B for Back, N for Next, Ctrl-Z to Exit "
$ PAGE_TXT = F$FAO (" Page !UL of !UL ", PAGE_CTR, PAGE_MAX)
$ _COL = P2 + (BOX_WIDTH - F$LENGTH (PAGE_TXT)) + 2
$ SAY ESC + "[''P3';''_COL'H''BOLD'''PAGE_TXT'''NORM'"
$!
$DISPLAY_LOOP:
$!
$ IF REC_CTR .LE. REC_MAX .AND. F$TYPE (REC_'REC_CTR') .NES. ""
$ THEN 
$     REC = REC_'REC_CTR'
$ ENDIF
$ WRAP_IN_PROGRESS = 0
$!
$WRAP_LOOP:
$!
$ IF ROW .LE. (P5 - 2) .AND. -
     REC_CTR .LE. PAGE_CTR * RECS_PER_PAGE
$ THEN
$     IF F$LENGTH (REC) .GT. BOX_WIDTH  
$     THEN 
$ 	  IF WRAP_IN_PROGRESS .EQ. 0
$	  THEN
$	      WRAP_IN_PROGRESS = 1
$	      _COL = COL
$	  ELSE
$	      _COL = COL - 1
$	  ENDIF
$	  REC_SEG = F$EXTRACT (0, BOX_WIDTH, REC)
$         SAY ESC + "[''ROW';''_COL'H", REC_SEG
$         REC = ">" + F$EXTRACT (BOX_WIDTH, F$LENGTH (REC)-BOX_WIDTH, REC)
$         ROW = ROW + 1
$	  GOTO WRAP_LOOP
$     ELSE
$         IF REC_CTR .LE. REC_MAX .AND. F$TYPE (REC_'REC_CTR') .NES. ""
$         THEN 
$ 	      IF WRAP_IN_PROGRESS .EQ. 1
$	      THEN
$		  _COL = COL - 1
$	      ELSE
$		  _COL = COL
$	      ENDIF
$             SAY ESC + "[''ROW';''_COL'H", REC
$	  ENDIF
$     ENDIF
$ ELSE
$!
$RETRY:
$!
$     PROMPT = ESC + "[''INPUT_ROW';01H ''CEOL'"
$     ASK "''PROMPT'" OPT
$     IF F$EDIT (OPT,"TRIM,UPCASE") .NES. "B" .AND. -
	 F$EDIT (OPT,"TRIM,UPCASE") .NES. "N" 
$     THEN
$         CALL INVALID_ENTRY
$	  GOTO RETRY
$     ENDIF
$     IF F$EDIT (OPT,"TRIM,UPCASE") .EQS. "B"
$     THEN
$	  IF PAGE_CTR .GT. 1
$	  THEN
$ 	      ROW = TOP_ROW
$	      PAGE_CTR = PAGE_CTR - 1
$ 	      REC_CTR = PAGE_'PAGE_CTR'_REC_CTR
$             PAGE_TXT = F$FAO (" Page !UL of !UL ", PAGE_CTR, PAGE_MAX)
$             _COL = P2 + (BOX_WIDTH - F$LENGTH (PAGE_TXT)) + 2
$             SAY ESC + "[''P3';''_COL'H''BOLD'''PAGE_TXT'''NORM'"
$             FILL_BOX 'P2' 'P3' 'P4' 'P5'
$	      GOTO DISPLAY_LOOP
$	  ELSE
$             CALL INVALID_ENTRY
$	      GOTO RETRY
$         ENDIF
$     ENDIF
$     IF F$EDIT (OPT,"TRIM,UPCASE") .EQS. "N"
$     THEN
$	  IF PAGE_CTR .LT. PAGE_MAX
$	  THEN
$	      PAGE_CTR = PAGE_CTR + 1
$ 	      PAGE_'PAGE_CTR'_REC_CTR = REC_CTR
$             PAGE_TXT = F$FAO (" Page !UL of !UL ", PAGE_CTR, PAGE_MAX)
$             _COL = P2 + (BOX_WIDTH - F$LENGTH (PAGE_TXT)) + 2
$             SAY ESC + "[''P3';''_COL'H''BOLD'''PAGE_TXT'''NORM'"
$             FILL_BOX 'P2' 'P3' 'P4' 'P5'
$	  ELSE
$             CALL INVALID_ENTRY
$	      GOTO RETRY
$         ENDIF
$     ENDIF
$     FILL_BOX 'P2' 'P3' 'P4' 'P5'
$     ROW = TOP_ROW
$     GOTO WRAP_LOOP
$ ENDIF
$ REC_CTR = REC_CTR + 1
$ ROW = ROW + 1
$ GOTO DISPLAY_LOOP
$!
$!------------------------------------------------------------------------------
$! Display the invalid entry 
$!------------------------------------------------------------------------------
$!
$INVALID_ENTRY: SUBROUTINE
$!
$ SAY ESC + "[''INPUT_ROW';01H", BELL, " Invalid Entry, Try again ...''CEOL'"
$ Wait 00:00:01.5
$ SAY ESC + "[''INPUT_ROW';01H", CEOL
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
$ DEFINE /USER /NOLOG SYS$ERROR  NL:
$ DEFINE /USER /NOLOG SYS$OUTPUT NL:
$ CLOSE IFILE
$!
$ Verify = F$VERIFY (Verify)
$!
$ EXIT
