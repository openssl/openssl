$!
$!------------------------------------------------------------------------------
$! SSL$CONF_UTIL.COM - SSL Configuration Utility procedure
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
$! This procedure gets or sets a given key item in a SSL configuration file.
$! The parameters used are:
$!
$! 	P1	- SSL Configuration File
$! 	P2	- SSL Configuration Function (i.e. GET/SET)
$! 	P3	- SSL Configuration Key/Item (delimited by '#')
$! 	P4	- SSL Configuration Key/Item Value (for SET function only)
$!
$!------------------------------------------------------------------------------
$! Define symbols
$!------------------------------------------------------------------------------
$!
$ SSL_CONF_DATA == ""
$ SAY := WRITE SYS$OUTPUT
$ ASK := READ SYS$COMMAND /END_OF_FILE=EXIT /PROMPT=
$ On Control_Y THEN GOTO EXIT
$ Set Control=Y
$!
$!------------------------------------------------------------------------------
$! Process parameters
$!------------------------------------------------------------------------------
$!
$ KEY_FOUND = 0
$ ITM_FOUND = 0
$ P1 = F$EDIT (P1,"TRIM")
$ P2 = F$EDIT (P2,"TRIM,UPCASE")
$ KEY = F$ELEMENT (0,"#",P3)
$ ITM = F$ELEMENT (1,"#",P3)
$!
$!------------------------------------------------------------------------------
$! Process the configuration function
$!------------------------------------------------------------------------------
$!
$ IF P2 .EQS. "GET" THEN GOSUB GET_CONF_DATA
$ IF P2 .EQS. "SET" THEN GOSUB SET_CONF_DATA
$!
$ GOTO EXIT
$!
$!------------------------------------------------------------------------------
$! Get the configuration data
$!------------------------------------------------------------------------------
$!
$GET_CONF_DATA:
$!
$ OPEN /READ /ERROR=OPEN_ERROR IFILE 'P1'
$!
$GET_CONF_DATA_LOOP:
$!
$ READ /ERROR=READ_ERROR /END_OF_FILE=GET_CONF_DATA_END IFILE IREC
$!
$ SREC = IREC
$ IPOS = F$LOCATE ("#",IREC)
$ IF IPOS .NE. F$LENGTH (IREC) THEN IREC = F$EXTRACT (0,IPOS,IREC)
$ IREC = F$EDIT (IREC,"COLLAPSE")

$ IF IREC .EQS. "" THEN GOTO GET_CONF_DATA_LOOP
$!
$ IF IREC .EQS. KEY 
$ THEN
$     KEY_FOUND = 1
$     GOTO GET_CONF_DATA_LOOP
$ ENDIF
$!
$ IF KEY_FOUND .EQ. 1
$ THEN 
$     IF F$EXTRACT (0,1,IREC) .EQS. "[" .AND. F$EXTRACT (F$LENGTH (IREC)-1,1,IREC) .EQS. "]"
$     THEN
$         SSL_CONF_DATA == ""
$         GOTO GET_CONF_DATA_END
$     ENDIF
$!
$     IF ITM .EQS. F$EDIT (F$ELEMENT (0,"=",IREC),"TRIM")
$     THEN 
$         VAL = F$EDIT (F$ELEMENT (1,"=",SREC),"TRIM")
$         SSL_CONF_DATA == "''VAL'"
$         GOTO GET_CONF_DATA_END
$     ENDIF
$ ENDIF
$!
$ GOTO GET_CONF_DATA_LOOP
$!
$GET_CONF_DATA_END:
$!
$ CLOSE /ERROR=CLOSE_ERROR IFILE
$!
$ RETURN
$!
$!------------------------------------------------------------------------------
$! Set the configuration data
$!------------------------------------------------------------------------------
$!
$SET_CONF_DATA:
$!
$ IF F$SEARCH ("''P1'") .EQS. "" THEN CREATE /NOLOG 'P1'
$!
$ OPEN /READ  /ERROR=OPEN_ERROR IFILE 'P1'
$ OPEN /WRITE /ERROR=OPEN_ERROR OFILE 'P1'
$!
$SET_CONF_DATA_LOOP:
$!
$ READ /ERROR=READ_ERROR /END_OF_FILE=SET_CONF_DATA_END IFILE IREC
$!
$ IF ITM_FOUND .EQ. 1
$ THEN 
$     WRITE /ERROR=WRITE_ERROR OFILE IREC
$     GOTO SET_CONF_DATA_LOOP
$ ENDIF
$!
$ SREC = IREC
$ IPOS = F$LOCATE ("#",IREC)
$ IF IPOS .NE. F$LENGTH (IREC) THEN IREC = F$EXTRACT (0,IPOS,IREC)
$ IREC = F$EDIT (IREC,"COLLAPSE")
$!
$ IF IREC .EQS. ""
$ THEN
$     WRITE /ERROR=WRITE_ERROR OFILE SREC
$     GOTO SET_CONF_DATA_LOOP
$ ENDIF
$!
$ IF IREC .EQS. KEY 
$ THEN
$     KEY_FOUND = 1
$     WRITE /ERROR=WRITE_ERROR OFILE SREC
$     GOTO SET_CONF_DATA_LOOP
$ ENDIF
$!
$ IF KEY_FOUND .EQ. 1
$ THEN 
$     IF F$EXTRACT (0,1,IREC) .EQS. "[" .AND. F$EXTRACT (F$LENGTH (IREC)-1,1,IREC) .EQS. "]"
$     THEN
$         WRITE /ERROR=WRITE_ERROR OFILE "''ITM' = ''P4'"
$         WRITE /ERROR=WRITE_ERROR OFILE SREC
$         ITM_FOUND = 1
$         GOTO SET_CONF_DATA_LOOP
$     ENDIF
$!
$     IF ITM .EQS. F$EDIT (F$ELEMENT (0,"=",IREC),"TRIM")
$     THEN 
$         WRITE /ERROR=WRITE_ERROR OFILE "''ITM' = ''P4'"
$         ITM_FOUND = 1
$         GOTO SET_CONF_DATA_LOOP
$     ENDIF
$ ENDIF
$!
$ WRITE /ERROR=WRITE_ERROR OFILE SREC
$!
$ GOTO SET_CONF_DATA_LOOP
$!
$SET_CONF_DATA_END:
$!
$ IF KEY_FOUND .EQ. 0 
$ THEN
$     WRITE /ERROR=WRITE_ERROR OFILE "''KEY'"
$     WRITE /ERROR=WRITE_ERROR OFILE "''ITM' = ''P4'"
$ ENDIF
$!
$ IF KEY_FOUND .EQ. 1 .AND. ITM_FOUND .EQ. 0
$ THEN
$     WRITE /ERROR=WRITE_ERROR OFILE "''ITM' = ''P4'"
$ ENDIF
$!
$ CLOSE IFILE
$ CLOSE OFILE
$!
$ RETURN
$!
$!------------------------------------------------------------------------------
$! File Errors
$!------------------------------------------------------------------------------
$!
$OPEN_ERROR:
$!
$ SAY "Open error for file ''P1' ... aborting ''P2'"
$ GOTO EXIT
$!
$READ_ERROR:
$!
$ SAY "Read error for file ''P1' ... aborting ''P2'"
$ GOTO EXIT
$!
$WRITE_ERROR:
$!
$ SAY "Write error for file ''P1' ... aborting ''P2'"
$ GOTO EXIT
$!
$CLOSE_ERROR:
$!
$ SAY "Close error for file ''P1' ... aborting ''P2'"
$ GOTO EXIT
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
$ DEFINE /USER /NOLOG SYS$ERROR  NL:
$ DEFINE /USER /NOLOG SYS$OUTPUT NL:
$ CLOSE OFILE
$!
$ Verify = F$VERIFY (Verify)
$!
$ EXIT 1
