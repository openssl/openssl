$!
$!------------------------------------------------------------------------------
$! SSL$DRAW_BOX.COM - SSL Draw Box procedure
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
$! This procedure draws a box with the specified coordinates.
$!
$! The parameters used are:
$!
$! 	P1	- X1 coordinate
$! 	P2	- Y1 coordinate
$! 	P3	- X2 coordinate
$! 	P4	- Y3 coordinate
$! 	P5	- Box Header (Optional)
$! 	P6	- Box Footer (Optional)
$! 	P7	- Fill Box (Optional)
$!
$!------------------------------------------------------------------------------
$! Define symbols
$!------------------------------------------------------------------------------
$!
$ SAY := WRITE SYS$OUTPUT
$ On Control_Y THEN GOTO EXIT
$ Set Control=Y
$!
$ FILL_BOX := @SSL$COM:SSL$FILL_BOX
$!
$ ESC[0,8] = 27 	! Set the Escape Character
$ GRPH_ON[0,8] = 14	! Turn GRAPHICS mode On 
$ GRPH_OFF[0,8] = 15	! Turn GRAPHICS mode Off
$ NORM = ESC + "[0m"	! Turn Attributes off
$ BOLD = ESC + "[1m"    ! Turn on BOLD Attribute
$!
$!------------------------------------------------------------------------------
$! Draw the box
$!------------------------------------------------------------------------------
$!
$ X1 = F$INTEGER (P1)
$ Y1 = F$INTEGER (P2)
$ X2 = F$INTEGER (P3)
$ Y2 = F$INTEGER (P4)
$!
$ ROW = Y1 + 1
$ COL = X1 + 1
$ SIDE1 = X1
$ SIDE2 = X2 + 1
$ TOP = "l" + F$FAO("!#*q", x2 - x1) + "k"
$ BOT = "m" + F$FAO("!#*q", x2 - x1) + "j"
$!
$ SAY ESC + "[''Y1';''X1'H", BOLD, GRPH_ON, TOP, GRPH_OFF, NORM
$!
$SIDES:
$!
$ SAY ESC + "[''ROW';''SIDE1'H",BOLD,GRPH_ON,"x",GRPH_OFF,NORM
$ SAY ESC + "[''ROW';''SIDE2'H",BOLD,GRPH_ON,"x",GRPH_OFF,NORM
$!
$ IF ROW .LT. Y2
$ THEN
$     ROW = ROW + 1
$     GOTO SIDES
$ ENDIF  
$!
$ SAY ESC + "[''Y2';''X1'H", BOLD, GRPH_ON, BOT, GRPH_OFF, NORM
$!
$ IF P5 .NES. "" 
$ THEN 
$     IF F$LENGTH(P5) .GT. X2 - X1
$     THEN 
$	  HEADER = F$EXTRACT (0, (X2 - X1 - 4), P5)
$     ELSE
$	  HEADER = P5
$     ENDIF
$     COL = X1 + ((X2 - X1 - F$LENGTH(HEADER)) / 2)
$     SAY ESC + "[''Y1';''COL'H''BOLD'''HEADER'''NORM'"
$ ENDIF
$!
$ IF P6 .NES. "" 
$ THEN 
$     IF F$LENGTH(P6) .GT. X2 - X1
$     THEN 
$	  FOOTER = F$EXTRACT (0, (X2 - X1 - 4), P6)
$     ELSE
$	  FOOTER = P6
$     ENDIF
$     COL = X1 + ((X2 - X1 - F$LENGTH(FOOTER)) / 2)
$     SAY ESC + "[''Y2';''COL'H''BOLD'''FOOTER'''NORM'"
$ ENDIF
$!
$ IF P7 .EQS. "" .OR. P7 .EQS. "Y" THEN FILL_BOX 'X1' 'Y1' 'X2' 'Y2'
$!
$ GOTO EXIT
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
