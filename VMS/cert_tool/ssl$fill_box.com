$!
$!------------------------------------------------------------------------------
$! SSL$FILL_BOX.COM - SSL Fill Box procedure
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
$! 	P4	- Y2 coordinate
$!
$!------------------------------------------------------------------------------
$! Define symbols
$!------------------------------------------------------------------------------
$!
$ SAY := WRITE SYS$OUTPUT
$ On Control_Y THEN GOTO EXIT
$ Set Control=Y
$!
$ ESC[0,8] = 27 	! Set the Escape Character
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
$ FILL = F$FAO("!#* ", X2 - X1)
$!
$FILL_LOOP:
$!
$ IF ROW .LT. Y2
$ THEN
$     SAY ESC + "[''ROW';''COL'H",FILL
$     ROW = ROW + 1
$     GOTO FILL_LOOP
$ ENDIF  
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
