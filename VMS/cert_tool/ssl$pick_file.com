$!
$!------------------------------------------------------------------------------
$! SSL$PICK_FILE.COM - SSL Pick File procedure
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
$! 	P1	- File Spec to Parse
$! 	P2	- X1 coordinate
$! 	P3	- Y1 coordinate
$! 	P4	- X2 coordinate
$! 	P5	- Y3 coordinate
$! 	P6	- File Pick Header (Optional)
$!
$!------------------------------------------------------------------------------
$! Define symbols
$!------------------------------------------------------------------------------
$!
$ SSL_FILE_NAME == ""
$ SAY := WRITE SYS$OUTPUT
$ ASK := READ SYS$COMMAND /END_OF_FILE=EXIT /PROMPT=
$ On Control_Y THEN GOTO EXIT
$ Set Control=Y
$!
$ DRAW_BOX := @SSL$COM:SSL$DRAW_BOX
$ FILL_BOX := @SSL$COM:SSL$FILL_BOX
$!
$ ESC[0,8] = 27 	! Set the Escape Character
$ BELL[0,8] = 7 	! Ring the terminal Bell
$ CEOL = ESC + "[0K"	! Clear to the End of the Line
$ NORM = ESC + "[0m"	! Turn Attributes off
$ BOLD = ESC + "[1m"    ! Turn on BOLD Attribute
$!
$!------------------------------------------------------------------------------
$! Display the Page Header
$!------------------------------------------------------------------------------
$!
$ P1 = F$EDIT (P1, "TRIM")
$ P2 = F$INTEGER (P2)
$ P3 = F$INTEGER (P3)
$ P4 = F$INTEGER (P4)
$ P5 = F$INTEGER (P5)
$ FILE_MAX = 0
$!
$SEARCH_LOOP:
$!
$ FILE = F$SEARCH ("''P1'",1)
$ IF FILE .NES. ""
$ THEN 
$     IF FILE_MAX .EQ. 1
$     THEN
$         IF FILE_1 .EQS. FILE THEN GOTO SEARCH_END
$     ENDIF
$     FILE_MAX = FILE_MAX + 1
$     FILE_'FILE_MAX' = FILE
$     GOTO SEARCH_LOOP
$ ENDIF
$!
$SEARCH_END:
$!
$ IF FILE_MAX .EQ. 0 
$ THEN 
$     DRAW_BOX 'P2' 'P3' 'P4' 'P5' "''P6'" " No Files Found, Press Return to Exit "
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
$ FILE_CTR = 1
$ PAGE_CTR = 1
$ PAGE_'PAGE_CTR'_FILE_CTR = FILE_CTR
$ FILES_PER_PAGE = BOX_HEIGHT
$ PAGE_MAX = FILE_MAX / FILES_PER_PAGE
$ IF PAGE_MAX * FILES_PER_PAGE .LT. FILE_MAX THEN PAGE_MAX = PAGE_MAX + 1
$!
$ DRAW_BOX 'P2' 'P3' 'P4' 'P5' "''P6'" " Enter B for Back, N for Next, Ctrl-Z to Exit or Enter a File Number "
$ PAGE_TXT = F$FAO (" Page !UL of !UL ", PAGE_CTR, PAGE_MAX)
$ _COL = P2 + (BOX_WIDTH - F$LENGTH (PAGE_TXT)) + 2
$ SAY ESC + "[''P3';''_COL'H''BOLD'''PAGE_TXT'''NORM'"
$!
$DISPLAY_LOOP:
$!
$ IF FILE_CTR .LE. FILE_MAX .AND. F$TYPE (FILE_'FILE_CTR') .NES. ""
$ THEN 
$     FILE = FILE_'FILE_CTR'
$ ELSE
$     FILE = ""
$ ENDIF
$ WRAP_IN_PROGRESS = 0
$!
$WRAP_LOOP:
$!
$ IF ROW .LE. (P5 - 2) .AND. -
     FILE_CTR .LE. PAGE_CTR * FILES_PER_PAGE
$ THEN
$     IF F$LENGTH (FILE) .GT. BOX_WIDTH 
$     THEN 
$ 	  IF WRAP_IN_PROGRESS .EQ. 0
$	  THEN 
$	      CTR_TXT = F$FAO ("!3UL. ",FILE_CTR)
$	      WRAP_IN_PROGRESS = 1
$	  ELSE
$	      CTR_TXT = "     "
$         ENDIF
$	  FILE_SEG = F$EXTRACT (0, BOX_WIDTH - F$LENGTH (CTR_TXT), FILE)
$         SAY ESC + "[''ROW';''COL'H''BOLD'''CTR_TXT'''NORM'''FILE_SEG'"
$         FILE = F$EXTRACT (BOX_WIDTH - F$LENGTH (CTR_TXT), F$LENGTH (FILE) - (BOX_WIDTH + F$LENGTH (CTR_TXT)), FILE)
$         ROW = ROW + 1
$	  GOTO WRAP_LOOP
$     ELSE
$	  IF FILE .NES. ""
$	  THEN
$ 	      IF WRAP_IN_PROGRESS .EQ. 0
$	      THEN 
$	          CTR_TXT = F$FAO ("!3UL. ",FILE_CTR)
$	      ELSE
$	          CTR_TXT = "     "
$             ENDIF
$             SAY ESC + "[''ROW';''COL'H''BOLD'''CTR_TXT'''NORM'''FILE'"
$	  ENDIF
$     ENDIF
$ ELSE
$!
$RETRY:
$!
$     PROMPT = ESC + "[''INPUT_ROW';01H ''CEOL'"
$     ASK "''PROMPT'" OPT
$     IF F$TYPE (OPT) .NES. "INTEGER" .AND. -
         F$EDIT (OPT,"TRIM,UPCASE") .NES. "B" .AND. -
	 F$EDIT (OPT,"TRIM,UPCASE") .NES. "N" 
$     THEN
$         CALL INVALID_ENTRY
$	  GOTO RETRY
$     ENDIF
$     IF F$TYPE (OPT) .EQS. "INTEGER" 
$     THEN
$	  IF OPT .GT. 0 .AND. -
  	     OPT .LE. FILE_MAX .AND. -
	     OPT .LE. (FILE_CTR - 1) .AND. -
	     OPT .GE. (FILE_CTR - 1 - FILES_PER_PAGE)
$	  THEN 
$	      SSL_FILE_NAME == FILE_'OPT'
$	      GOTO EXIT
$	  ELSE
$             CALL INVALID_ENTRY
$	      GOTO RETRY
$	  ENDIF
$     ENDIF
$     IF F$EDIT (OPT,"TRIM,UPCASE") .EQS. "B"
$     THEN
$	  IF PAGE_CTR .GT. 1
$	  THEN
$ 	      ROW = TOP_ROW
$	      PAGE_CTR = PAGE_CTR - 1
$ 	      FILE_CTR = PAGE_'PAGE_CTR'_FILE_CTR
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
$ 	      PAGE_'PAGE_CTR'_FILE_CTR = FILE_CTR
$ 	      FILE_CTR = PAGE_'PAGE_CTR'_FILE_CTR
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
$ FILE_CTR = FILE_CTR + 1
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
$ Verify = F$VERIFY (Verify)
$!
$ EXIT
