$!
$!------------------------------------------------------------------------------
$! SSL$SIGN_CERT.COM - SSL Sign Certificate Request procedure
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
$! There are no parameters used.
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
$ GET_USER_DATA := CALL GET_USER_DATA
$ SET_USER_DATA := CALL SET_USER_DATA
$ DEL_USER_DATA := CALL DEL_USER_DATA
$ INIT_TERM := @SSL$COM:SSL$INIT_TERM
$ SHOW_FILE := @SSL$COM:SSL$SHOW_FILE 
$ SSL_CONF_FILE = F$TRNLMN ("SSL$CA_CONF")
$ GET_CONF_DATA := @SSL$COM:SSL$CONF_UTIL 'SSL_CONF_FILE' GET
$ SET_CONF_DATA := @SSL$COM:SSL$CONF_UTIL 'SSL_CONF_FILE' SET
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
$ TEXT = "Sign Certificate Request"
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
$ IF F$SEARCH ("''SSL_CONF_FILE'") .NES. ""
$ THEN 
$     SAY ESC + "[''MSG_ROW';01H", BLNK, " Reading Configuration ...", NORM
$ ELSE
$     SAY ESC + "[''MSG_ROW';01H", BLNK, " Initializing Configuration ...", NORM
$ ENDIF
$!
$ _ca = "ca"
$!
$ _default_ca = "CA_default_ca"
$ _default_ca_upd = "Y"
$!
$ _default_serfile = "SSL$DB:SERIAL.TXT"
$ _default_serfile_upd = "Y"
$!
$ _default_idxfile = "SSL$DB:INDEX.TXT"
$ _default_idxfile_upd = "Y"
$!
$ _default_crtfile = "SSL$CRT:SERVER_CA.CRT"
$ _default_crtfile_upd = "Y"
$!
$ _default_keyfile = "SSL$KEY:SERVER_CA.KEY"
$ _default_keyfile_upd = "Y"
$!
$ _default_csrfile = "SSL$CSR:SERVER.CSR"
$ _default_csrfile_upd = "Y"
$!
$ _default_sgnfile = "SSL$CRT:SIGNED.CRT"
$ _default_sgnfile_upd = "Y"
$!
$ _default_newcert = "SSL$CRT"
$ _default_newcert_upd = "Y"
$!
$ _default_md = "md5"
$ _default_md_upd = "Y"
$!
$ _default_days = "365"
$ _default_days_upd = "Y"
$!
$ _default_policy = "policy_anything"
$ _default_policy_upd = "Y"
$!
$ _policy_countryName = "optional"
$ _policy_countryName_upd = "Y"
$!
$ _policy_stateOrProvinceName = "optional"
$ _policy_stateOrProvinceName_upd = "Y"
$!
$ _policy_localityName = "optional"
$ _policy_localityName_upd = "Y"
$!
$ _policy_organizationName = "optional"
$ _policy_organizationName_upd = "Y"
$!
$ _policy_organizationalUnitName = "optional"
$ _policy_organizationalUnitName_upd = "Y"
$!
$ _policy_commonName = "supplied"
$ _policy_commonName_upd = "Y"
$!
$ _policy_emailAddress = "optional"
$ _policy_emailAddress_upd = "Y"
$!
$ _default_x509_extensions = "CA_x509_extensions"
$ _default_x509_extensions_upd = "Y"
$!
$ _x509_basicContraints = "CA:FALSE"
$ _x509_basicContraints_upd = "Y"
$!
$ _x509_nsCertType = "client,email,objsign,server"
$ _x509_nsCertType_upd = "Y"
$!
$ _x509_nsComment = "SSL Generated Certificate"
$ _x509_nsComment_upd = "Y"
$!
$ _x509_subjectKeyIdentifier = "hash"
$ _x509_subjectKeyIdentifier_upd = "Y"
$!
$ _x509_authorityKeyIdentifier = "keyid,issuer:always"
$ _x509_authorityKeyIdentifier_upd = "Y"
$!
$ IF F$SEARCH ("''SSL_CONF_FILE'") .NES. ""
$ THEN 
$     GET_CONF_DATA "[''_ca']#default_ca"
$     IF SSL_CONF_DATA .NES. ""
$     THEN 
$         _default_ca = SSL_CONF_DATA
$         _default_ca_upd = "N"
$     ENDIF
$!
$     GET_CONF_DATA "[''_default_ca']#serial"
$     IF SSL_CONF_DATA .NES. ""
$     THEN
$         _default_serfile = F$PARSE (SSL_CONF_DATA,"SSL$ROOT:",,"DEVICE") + -
 		             F$PARSE (SSL_CONF_DATA,"[DB]",,"DIRECTORY") + -
 		             F$PARSE (SSL_CONF_DATA,"SERIAL",,"NAME") + -
 		             F$PARSE (SSL_CONF_DATA,".TXT",,"TYPE") 
$         _default_serfile_upd = "N"
$     ENDIF
$!
$     GET_CONF_DATA "[''_default_ca']#database"
$     IF SSL_CONF_DATA .NES. ""
$     THEN
$         _default_idxfile = F$PARSE (SSL_CONF_DATA,"SSL$ROOT:",,"DEVICE") + -
 		             F$PARSE (SSL_CONF_DATA,"[DB]",,"DIRECTORY") + -
 		             F$PARSE (SSL_CONF_DATA,"INDEX",,"NAME") + -
 		             F$PARSE (SSL_CONF_DATA,".TXT",,"TYPE") 
$         _default_idxfile_upd = "N"
$     ENDIF
$!
$     GET_CONF_DATA "[''_default_ca']#certificate"
$     IF SSL_CONF_DATA .NES. ""
$     THEN
$         _default_crtfile = F$PARSE (SSL_CONF_DATA,"SSL$ROOT:",,"DEVICE") + -
 		             F$PARSE (SSL_CONF_DATA,"[CRT]",,"DIRECTORY") + -
 		             F$PARSE (SSL_CONF_DATA,"SERVER_CA",,"NAME") + -
 		             F$PARSE (SSL_CONF_DATA,".CRT",,"TYPE") 
$         _default_crtfile_upd = "N"
$     ENDIF
$!
$     GET_CONF_DATA "[''_default_ca']#private_key"
$     IF SSL_CONF_DATA .NES. ""
$     THEN
$         _default_keyfile = F$PARSE (SSL_CONF_DATA,"SSL$ROOT:",,"DEVICE") + -
 		             F$PARSE (SSL_CONF_DATA,"[KEY]",,"DIRECTORY") + -
 		             F$PARSE (SSL_CONF_DATA,"SERVER_CA",,"NAME") + -
 		             F$PARSE (SSL_CONF_DATA,".KEY",,"TYPE") 
$         _default_keyfile_upd = "N"
$     ENDIF
$!
$     GET_CONF_DATA "[''_default_ca']#new_certs_dir"
$     IF SSL_CONF_DATA .NES. ""
$     THEN
$         _default_newcert = SSL_CONF_DATA
$         _default_newcert_upd = "N"
$     ENDIF
$!
$     GET_CONF_DATA "[''_default_ca']#default_md"
$     IF SSL_CONF_DATA .NES. ""
$     THEN
$         _default_md = SSL_CONF_DATA
$         _default_md_upd = "N"
$     ENDIF
$!
$     GET_CONF_DATA "[''_default_ca']#default_days"
$     IF SSL_CONF_DATA .NES. ""
$     THEN
$         _default_days = SSL_CONF_DATA
$         _default_days_upd = "N"
$     ENDIF
$!
$     GET_CONF_DATA "[''_default_ca']#policy"
$     IF SSL_CONF_DATA .NES. ""
$     THEN
$         _default_policy = SSL_CONF_DATA
$         _default_policy_upd = "N"
$     ENDIF
$!
$     GET_CONF_DATA "[''_default_policy']#countryName"
$     IF SSL_CONF_DATA .NES. ""
$     THEN
$         _policy_countryName = SSL_CONF_DATA
$         _policy_countryName_upd = "N"
$     ENDIF
$!
$     GET_CONF_DATA "[''_default_policy']#stateOrProvinceName"
$     IF SSL_CONF_DATA .NES. ""
$     THEN
$         _policy_stateOrProvinceName = SSL_CONF_DATA
$         _policy_stateOrProvinceName_upd = "N"
$     ENDIF
$!
$     GET_CONF_DATA "[''_default_policy']#localityName"
$     IF SSL_CONF_DATA .NES. ""
$     THEN
$         _policy_localityName = SSL_CONF_DATA
$         _policy_localityName_upd = "N"
$     ENDIF
$!
$     GET_CONF_DATA "[''_default_policy']#organizationName"
$     IF SSL_CONF_DATA .NES. ""
$     THEN
$         _policy_organizationName = SSL_CONF_DATA
$         _policy_organizationName_upd = "N"
$     ENDIF
$!
$     GET_CONF_DATA "[''_default_policy']#organizationalUnitName"
$     IF SSL_CONF_DATA .NES. ""
$     THEN
$         _policy_organizationalUnitName = SSL_CONF_DATA
$         _policy_organizationalUnitName_upd = "N"
$     ENDIF
$!
$     GET_CONF_DATA "[''_default_policy']#commonName"
$     IF SSL_CONF_DATA .NES. ""
$     THEN
$         _policy_commonName = SSL_CONF_DATA
$         _policy_commonName_upd = "N"
$     ENDIF
$!
$     GET_CONF_DATA "[''_default_policy']#emailAddress"
$     IF SSL_CONF_DATA .NES. ""
$     THEN
$         _policy_emailAddress = SSL_CONF_DATA
$         _policy_emailAddress_upd = "N"
$     ENDIF
$!
$     GET_CONF_DATA "[''_default_ca']#x509_extensions"
$     IF SSL_CONF_DATA .NES. ""
$     THEN
$         _default_x509_extensions = SSL_CONF_DATA
$         _default_x509_extensions_upd = "N"
$     ENDIF
$!
$     GET_CONF_DATA "[''_default_x509_extensions']#basicConstraints"
$     IF SSL_CONF_DATA .NES. ""
$     THEN
$         _x509_basicConstraints = SSL_CONF_DATA
$         _x509_basicConstraints_upd = "N"
$     ENDIF
$!
$     GET_CONF_DATA "[''_default_x509_extensions']#nsCertType"
$     IF SSL_CONF_DATA .NES. ""
$     THEN
$         _x509_nsCertType = SSL_CONF_DATA
$         _x509_nsCertType_upd = "N"
$     ENDIF
$!
$     GET_CONF_DATA "[''_default_x509_extensions']#nsComment"
$     IF SSL_CONF_DATA .NES. ""
$     THEN
$         _x509_nsComment = SSL_CONF_DATA
$         _x509_nsComment_upd = "N"
$     ENDIF
$!
$     GET_CONF_DATA "[''_default_x509_extensions']#subjectKeyIdentifier"
$     IF SSL_CONF_DATA .NES. ""
$     THEN
$         _x509_subjectKeyIdentifier = SSL_CONF_DATA
$         _x509_subjectKeyIdentifier_upd = "N"
$     ENDIF
$!
$     GET_CONF_DATA "[''_default_x509_extensions']#authorityKeyIdentifier"
$     IF SSL_CONF_DATA .NES. ""
$     THEN
$         _x509_authorityKeyIdentifier = SSL_CONF_DATA
$         _x509_authorityKeyIdentifier_upd = "N"
$     ENDIF
$ ENDIF
$!
$ SET_USER_DATA "[''_ca']#default_ca#D#''_default_ca'##S###''_default_ca_upd'#N#N"
$ SET_USER_DATA "[''_default_ca']#serial#D#''_default_serfile'#Serial File ?#F###''_default_serfile_upd'#N#N"
$ SET_USER_DATA "[''_default_ca']#database#D#''_default_idxfile'#Database File ?#F###''_default_idxfile_upd'#N#N"
$ SET_USER_DATA "[''_default_ca']#certificate#D#''_default_crtfile'#CA Certificate File ?#F###''_default_crtfile_upd'#Y#N"
$ SET_USER_DATA "[''_default_ca']#private_key#D#''_default_keyfile'#CA Certificate Key File ?#F###''_default_keyfile_upd'#Y#N"
$ SET_USER_DATA "[]#default_csrfile#-#''_default_csrfile'#Certificate Request File ?#F###''_default_csrfile_upd'#Y#N"
$ SET_USER_DATA "[]#default_sgnfile#-#''_default_sgnfile'#Signed Certificate File ?#F###''_default_sgnfile_upd'#Y#N"
$ SET_USER_DATA "[''_default_ca']#new_certs_dir#D#''_default_newcert'#New Certificate Directory ?#S###''_default_newcert_upd'#N#N"
$ SET_USER_DATA "[''_default_ca']#default_md#D#''_default_md'#Default Digest ?#I###''_default_md_upd'#N#N"
$ SET_USER_DATA "[''_default_ca']#default_days#D#''_default_days'#Default Days ?#I###''_default_days_upd'#Y#N"
$ SET_USER_DATA "[''_default_ca']#policy#D#''_default_policy'#Default Policy ?#S###''_default_policy_upd'#N#N"
$ SET_USER_DATA "[''_default_policy']#countryName#D#''_policy_countryName'#Country Name Policy ?#S###''_policy_countryName_upd'#N#N"
$ SET_USER_DATA "[''_default_policy']#stateOrProvinceName#D#''_policy_stateOrProvinceName'#State or Province Name Policy ?#S###''_policy_stateOrProvinceName_upd'#N#N"
$ SET_USER_DATA "[''_default_policy']#localityName#D#''_policy_localityName'#Locality Name Policy ?#S###''_policy_localityName_upd'#N#N"
$ SET_USER_DATA "[''_default_policy']#organizationName#D#''_policy_organizationName'#Organization Name Policy ?#S###''_policy_organizationName_upd'#N#N"
$ SET_USER_DATA "[''_default_policy']#organizationalUnitName#D#''_policy_organizationalUnitName'#Organization Unit Name Policy ?#S###''_policy_organizationalUnitName_upd'#N#N"
$ SET_USER_DATA "[''_default_policy']#commonName#D#''_policy_commonName'#Common Name Policy ?#S###''_policy_commonName_upd'#N#N"
$ SET_USER_DATA "[''_default_policy']#emailAddress#D#''_policy_emailAddress'#Email Address Policy ?#S###''_policy_emailAddress_upd'#N#N"
$ SET_USER_DATA "[''_default_ca']#x509_extensions#D#''_default_x509_extensions'#X509 Extensions ?#S###''_default_x509_extensions_upd'#N#N"
$ SET_USER_DATA "[''_default_x509_extensions']#basicConstraints#D#''_x509_basicConstraints'#X509 Basic Constraints ?#S###''_x509_basicConstraints_upd'#N#N"
$ SET_USER_DATA "[''_default_x509_extensions']#nsCertType#D#''_x509_nsCertType'#X509 NS Cert Type ?#S###''_x509_nsCertType_upd'#N#N"
$ SET_USER_DATA "[''_default_x509_extensions']#nsComment#D#''_x509_nsComment'#X509 NS Comment ?#S###''_x509_nsComment_upd'#N#N"
$ SET_USER_DATA "[''_default_x509_extensions']#subjectKeyIdentifier#D#''_x509_subjectKeyIdentifier'#X509 Subject Key Identifier ?#S###''_x509_subjectKeyIdentifier_upd'#N#N"
$ SET_USER_DATA "[''_default_x509_extensions']#authorityKeyIdentifier#D#''_x509_authorityKeyIdentifier'#X509 Authority Key Identifier ?#S###''_x509_authorityKeyIdentifier_upd'#N#N"
$ SET_USER_DATA "[]#pem_pass_phrase#-##PEM Pass Phrase ?#P#1###Y#N"
$ SET_USER_DATA "[]#display_certificate#-#N#Display the Certificate ?#S##1##Y#N"
$!
$ SAY ESC + "[''MSG_ROW';01H", CEOS
$!
$!------------------------------------------------------------------------------
$! Confirm/Update the SSL Configuration Data
$!------------------------------------------------------------------------------
$!
$PROMPT_LOOP:
$!
$ IF CTR .LE. SSL_USER_DATA_MAX
$ THEN 
$     KEY = F$ELEMENT (0,"#",SSL_USER_DATA_'CTR') ! Key Name
$     ITM = F$ELEMENT (1,"#",SSL_USER_DATA_'CTR') ! Item Name
$     VAL = F$ELEMENT (2,"#",SSL_USER_DATA_'CTR') ! Item Value Contains Default or Prompt
$     DEF = F$ELEMENT (3,"#",SSL_USER_DATA_'CTR') ! Default Value
$     PRM = F$ELEMENT (4,"#",SSL_USER_DATA_'CTR') ! Prompt Value
$     TYP = F$ELEMENT (5,"#",SSL_USER_DATA_'CTR') ! Value Type
$     MIN = F$ELEMENT (6,"#",SSL_USER_DATA_'CTR') ! Value Minimum Length
$     MAX = F$ELEMENT (7,"#",SSL_USER_DATA_'CTR') ! Value Maximum Length
$     UPD = F$ELEMENT (8,"#",SSL_USER_DATA_'CTR') ! Entry Updated ?
$     REQ = F$ELEMENT (9,"#",SSL_USER_DATA_'CTR') ! Entry Required for Input ?
$     CFM = F$ELEMENT (10,"#",SSL_USER_DATA_'CTR')! Confirm Input  ?
$     CONFIRMED = 0
$     IF REQ .EQS. "N"
$     THEN 
$         CTR = CTR + 1
$         GOTO PROMPT_LOOP
$     ENDIF
$     IF ROW .GT. MSG_ROW - 2
$     THEN 
$         SAY ESC + "[''TOP_ROW';01H", CEOS
$	  ROW = TOP_ROW
$     ENDIF
$!
$CONFIRM_LOOP:
$!
$     IF PRM .EQS. "" 
$     THEN 
$         PROMPT = ESC + "[''ROW';''COL'H''ITM' ? [''DEF'] ''CEOL'"
$     ELSE
$         PROMPT = ESC + "[''ROW';''COL'H''PRM' [''DEF'] ''CEOL'"
$     ENDIF
$     IF TYP .EQS. "P" THEN SET TERMINAL /NOECHO
$     ASK "''PROMPT'" ANS /END_OF_FILE=EXIT
$     IF TYP .EQS. "P" THEN SET TERMINAL /ECHO
$     ANS = F$EDIT (ANS,"TRIM")
$     IF ANS .EQS. "" THEN ANS = DEF
$     IF TYP .EQS. "F"
$     THEN
$         ANS = F$PARSE ("''ANS'","''DEF'",,,"SYNTAX_ONLY")
$     ENDIF
$     IF TYP .EQS. "I" .AND. F$TYPE (ANS) .NES. "INTEGER"
$     THEN 
$         CALL INVALID_ENTRY
$         SAY ESC + "[''ROW';01H", CEOS
$         GOTO PROMPT_LOOP
$     ENDIF
$     IF (TYP .EQS. "S" .OR. TYP .EQS. "P") .AND. -
         ((MIN .NES. "" .AND. F$LENGTH (ANS) .LT. F$INTEGER(MIN)) .OR. -
          (MAX .NES. "" .AND. F$LENGTH (ANS) .GT. F$INTEGER(MAX)))
$     THEN 
$         CALL INVALID_ENTRY
$         SAY ESC + "[''ROW';01H", CEOS
$	  IF TYP .EQS. "S" THEN GOTO PROMPT_LOOP
$         IF TYP .EQS. "P" THEN GOTO CONFIRM_LOOP
$     ENDIF
$     ROW = ROW + 1
$     IF CFM .EQS. "Y"
$     THEN
$         IF CONFIRMED .EQ. 0
$	  THEN
$	      CONFIRMED = 1
$	      CONFIRMED_ANS = ANS
$	      PRM = "Confirm ''PRM'"
$	      GOTO CONFIRM_LOOP
$         ELSE
$	      IF ANS .NES. CONFIRMED_ANS
$	      THEN 
$                 CALL INVALID_ENTRY
$		  ROW = ROW - 2
$                 SAY ESC + "[''ROW';01H", CEOS
$                 GOTO PROMPT_LOOP
$	      ENDIF
$         ENDIF
$     ENDIF
$     IF ANS .NES. DEF THEN SSL_USER_DATA_'CTR' = "''KEY'#''ITM'#''VAL'#''ANS'#''PRM'#''TYP'#''MIN'#''MAX'#Y#''REQ'#''CFM'"
$     CTR = CTR + 1
$     GOTO PROMPT_LOOP
$ ENDIF
$!
$!------------------------------------------------------------------------------
$! Save the SSL Configuration Data
$!------------------------------------------------------------------------------
$!
$ CTR = 1
$ SAY ESC + "[''MSG_ROW';01H", BLNK, " Saving Configuration ...", NORM
$!
$SAVE_CONF_LOOP:
$!
$ IF CTR .LE. SSL_USER_DATA_MAX
$ THEN 
$     KEY = F$ELEMENT (0,"#",SSL_USER_DATA_'CTR') ! Key Name
$     ITM = F$ELEMENT (1,"#",SSL_USER_DATA_'CTR') ! Item Name
$     VAL = F$ELEMENT (2,"#",SSL_USER_DATA_'CTR') ! Item Value Contains Default or Prompt
$     DEF = F$ELEMENT (3,"#",SSL_USER_DATA_'CTR') ! Default Value
$     PRM = F$ELEMENT (4,"#",SSL_USER_DATA_'CTR') ! Prompt Value
$     TYP = F$ELEMENT (5,"#",SSL_USER_DATA_'CTR') ! Value Type
$     MIN = F$ELEMENT (6,"#",SSL_USER_DATA_'CTR') ! Value Minimum Length
$     MAX = F$ELEMENT (7,"#",SSL_USER_DATA_'CTR') ! Value Maximum Length
$     UPD = F$ELEMENT (8,"#",SSL_USER_DATA_'CTR') ! Entry Updated ?
$     REQ = F$ELEMENT (9,"#",SSL_USER_DATA_'CTR') ! Entry Required for Input ?
$     CFM = F$ELEMENT (10,"#",SSL_USER_DATA_'CTR')! Confirm Input ?
$     IF UPD .NES. "Y" .OR. VAL .EQS. "-"
$     THEN 
$         CTR = CTR + 1
$         GOTO SAVE_CONF_LOOP
$     ENDIF
$     IF VAL .EQS. "D"
$     THEN 
$         SET_CONF_DATA "''KEY'#''ITM'" "''DEF'"
$     ELSE
$         SET_CONF_DATA "''KEY'#''ITM'" "''PRM'"
$         SET_CONF_DATA "''KEY'#''ITM'_default" "''DEF'"
$     ENDIF
$     IF MIN .NES. "" THEN SET_CONF_DATA "''KEY'#''ITM'_min" "''MIN'"
$     IF MAX .NES. "" THEN SET_CONF_DATA "''KEY'#''ITM'_max" "''MAX'"
$     CTR = CTR + 1
$     GOTO SAVE_CONF_LOOP
$ ENDIF
$!
$ PURGE /NOLOG /NOCONFIRM 'SSL_CONF_FILE'
$ RENAME 'SSL_CONF_FILE'; ;1
$!
$ SAY ESC + "[''MSG_ROW';01H", CEOS
$!
$!------------------------------------------------------------------------------
$! Create the Certificiate Authority
$!------------------------------------------------------------------------------
$!
$SKIP:
$!
$ SAY ESC + "[''MSG_ROW';01H", BLNK, " Signing Certificate Request ...", NORM
$!
$ X1 = 2
$ Y1 = TOP_ROW
$ X2 = TT_COLS - 2
$ Y2 = MSG_ROW - 1
$!
$ GET_USER_DATA "[]#pem_pass_phrase"
$ _pem_pass_phrase = SSL_USER_DATA
$ GET_USER_DATA "[''_default_ca']#database"
$ _default_idxfile = SSL_USER_DATA
$ GET_USER_DATA "[''_default_ca']#serial"
$ _default_serfile = SSL_USER_DATA
$ GET_USER_DATA "[]#default_csrfile"
$ _default_csrfile = SSL_USER_DATA
$ GET_USER_DATA "[]#default_sgnfile"
$ _default_sgnfile = SSL_USER_DATA
$ GET_USER_DATA "[]#display_certificate"
$ _display_certificate = SSL_USER_DATA
$!
$ IF F$SEARCH ("''_default_idxfile'") .EQS. ""
$ THEN
$     OPEN /WRITE OFILE '_default_idxfile'
$     CLOSE OFILE
$ ENDIF
$!
$ IF F$SEARCH ("''_default_serfile'") .EQS. ""
$ THEN
$     OPEN /WRITE OFILE '_default_serfile'
$     WRITE OFILE "01"
$     CLOSE OFILE
$ ENDIF
$!
$ DEFINE /USER /NOLOG SYS$ERROR  NL:
$ DEFINE /USER /NOLOG SYS$OUTPUT NL:
$ SHOW SYSTEM /FULL /OUT=SYS$LOGIN:SSL_CA_'PID'.RND
$!
$ OPEN /WRITE OFILE SYS$LOGIN:SSL_CA_'PID'.COM
$ WRITE OFILE "$ SET NOON"
$ WRITE OFILE "$ SET MESSAGE /NOFACILITY /NOIDENTIFICATION /NOSEVERITY /NOTEXT"
$ WRITE OFILE "$ DEFINE /USER /NOLOG RANDFILE    SYS$LOGIN:SSL_CA_''PID'.RND"
$ WRITE OFILE "$ DEFINE /USER /NOLOG SYS$ERROR   SYS$LOGIN:SSL_CA_''PID'.LOG"
$ WRITE OFILE "$ DEFINE /USER /NOLOG SYS$OUTPUT  SYS$LOGIN:SSL_CA_''PID'.LOG"
$ WRITE OFILE "$ DEFINE /USER /NOLOG SYS$COMMAND SYS$INPUT"
$ WRITE OFILE "$ OPENSSL ca -config ''SSL_CONF_FILE' -out ''_default_sgnfile' -infiles ''_default_csrfile'"
$ WRITE OFILE "''_pem_pass_phrase'"
$ WRITE OFILE "y"
$ WRITE OFILE "y"
$ WRITE OFILE "$ SET MESSAGE /FACILITY /IDENTIFICATION /SEVERITY /TEXT"
$ CLOSE OFILE
$!
$ @SYS$LOGIN:SSL_CA_'PID'.COM
$!
$ DELETE/NOLOG/NOCONFIRM SYS$LOGIN:SSL_CA_'PID'.RND;*
$ DELETE/NOLOG/NOCONFIRM SYS$LOGIN:SSL_CA_'PID'.COM;*
$!
$ DEFINE /USER /NOLOG SYS$ERROR  NL:
$ DEFINE /USER /NOLOG SYS$OUTPUT NL:
$ SEARCH SYS$LOGIN:SSL_CA_'PID'.LOG /OUT=SYS$LOGIN:SSL_CA_'PID'.ERR "error:"
$ IF F$SEARCH ("SYS$LOGIN:SSL_CA_''PID'.ERR") .NES. "" 
$ THEN 
$     IF F$FILE_ATTRIBUTE ("SYS$LOGIN:SSL_CA_''PID'.ERR","ALQ") .NE. 0
$     THEN 
$         DELETE /NOLOG /NOCONFIRM SYS$LOGIN:SSL_CA_'PID'.ERR;*
$         SAY ESC + "[''MSG_ROW';01H''BELL'''CEOS'"
$         SHOW_FILE "SYS$LOGIN:SSL_CA_''PID'.LOG" 'X1' 'Y1' 'X2' 'Y2' "< ERROR >" 
$         DELETE /NOLOG /NOCONFIRM SYS$LOGIN:SSL_CA_'PID'.LOG;*
$         GOTO EXIT
$     ENDIF
$     DELETE /NOLOG /NOCONFIRM SYS$LOGIN:SSL_CA_'PID'.ERR;*
$ ENDIF
$!
$ DELETE /NOLOG /NOCONFIRM SYS$LOGIN:SSL_CA_'PID'.LOG;*
$! 
$ IF F$EDIT (_display_certificate,"TRIM,UPCASE") .EQS. "Y"
$ THEN 
$     SAY ESC + "[''MSG_ROW';01H", BLNK, " Generating Output ...", NORM, CEOL
$!
$     OPEN /WRITE OFILE SYS$LOGIN:SSL_X509_'PID'.COM
$     WRITE OFILE "$ DEFINE /USER /NOLOG SYS$ERROR   SYS$LOGIN:SSL_X509_''PID'.LOG"
$     WRITE OFILE "$ DEFINE /USER /NOLOG SYS$OUTPUT  SYS$LOGIN:SSL_X509_''PID'.LOG"
$     WRITE OFILE "$ DEFINE /USER /NOLOG SYS$COMMAND SYS$INPUT"
$     WRITE OFILE "$ OPENSSL x509 -noout -text -in ''_default_sgnfile'"
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
$     SHOW_FILE "SYS$LOGIN:SSL_X509_''PID'.LOG" 'X1' 'Y1' 'X2' 'Y2' "< ''_default_sgnfile' >" 
$     DELETE /NOLOG /NOCONFIRM SYS$LOGIN:SSL_X509_'PID'.LOG;*
$     GOTO EXIT
$ ENDIF
$!
$ TEXT = "Press return to continue"
$ COL = (TT_COLS - F$LENGTH (TEXT)) / 2
$!
$ SAY ESC + "[''MSG_ROW';01H", CEOS
$ PROMPT = ESC + "[''MSG_ROW';''COL'H''TEXT'"
$ ASK "''PROMPT'" OPT
$!
$GOTO EXIT
$!
$!------------------------------------------------------------------------------
$! Set the User Data
$!------------------------------------------------------------------------------
$!
$SET_USER_DATA: SUBROUTINE
$!
$ IF F$TYPE (SSL_USER_DATA_MAX) .EQS. ""
$ THEN
$     SSL_USER_DATA_MAX == 1
$ ELSE
$     SSL_USER_DATA_MAX == SSL_USER_DATA_MAX + 1
$ ENDIF
$!
$ SSL_USER_DATA_'SSL_USER_DATA_MAX' == "''P1'"
$!
$ EXIT
$!
$ ENDSUBROUTINE
$!
$!------------------------------------------------------------------------------
$! Find the Request Data
$!------------------------------------------------------------------------------
$!
$GET_USER_DATA: SUBROUTINE
$!
$ CTR = 1
$ USER_KEY = F$ELEMENT (0,"#",P1)
$ USER_ITM = F$ELEMENT (1,"#",P1)
$!
$GET_USER_DATA_LOOP:
$!
$ IF CTR .LE. SSL_USER_DATA_MAX
$ THEN
$     KEY = F$ELEMENT (0,"#",SSL_USER_DATA_'CTR') ! Key Name
$     ITM = F$ELEMENT (1,"#",SSL_USER_DATA_'CTR') ! Item Name
$     VAL = F$ELEMENT (2,"#",SSL_USER_DATA_'CTR') ! Item Value Contains Default or Prompt
$     DEF = F$ELEMENT (3,"#",SSL_USER_DATA_'CTR') ! Default Value
$     PRM = F$ELEMENT (4,"#",SSL_USER_DATA_'CTR') ! Prompt Value
$     IF USER_KEY .NES. KEY .OR. USER_ITM .NES. ITM
$     THEN 
$         CTR = CTR + 1
$         GOTO GET_USER_DATA_LOOP
$     ENDIF
$     IF VAL .EQS. "-" THEN SSL_USER_DATA == "''DEF'"
$     IF VAL .EQS. "D" THEN SSL_USER_DATA == "''DEF'"
$     IF VAL .EQS. "P" THEN SSL_USER_DATA == "''PRM'"
$ ENDIF
$!
$ EXIT
$!
$ ENDSUBROUTINE
$!
$!------------------------------------------------------------------------------
$! Delete the User Data
$!------------------------------------------------------------------------------
$!
$DEL_USER_DATA: SUBROUTINE
$!
$ IF F$TYPE (SSL_USER_DATA_MAX) .EQS. "" THEN GOTO DEL_USER_DATA_END
$!
$DEL_USER_DATA_LOOP:
$!
$ IF F$TYPE (SSL_USER_DATA_'SSL_USER_DATA_MAX') .NES. "" 
$ THEN
$     DELETE /SYMBOL /GLOBAL SSL_USER_DATA_'SSL_USER_DATA_MAX'
$     SSL_USER_DATA_MAX == SSL_USER_DATA_MAX - 1
$     GOTO DEL_USER_DATA_LOOP
$ ENDIF
$!
$ DELETE /SYMBOL /GLOBAL SSL_USER_DATA_MAX
$!
$DEL_USER_DATA_END:
$!
$ IF F$TYPE (SSL_USER_DATA) .NES. "" THEN DELETE /SYMBOL /GLOBAL SSL_USER_DATA
$!
$ EXIT
$!
$ ENDSUBROUTINE
$!
$!------------------------------------------------------------------------------
$! Display the invalid entry 
$!------------------------------------------------------------------------------
$!
$INVALID_ENTRY: SUBROUTINE
$!
$ SAY ESC + "[''MSG_ROW';01H", BELL, " Invalid Entry, Try again ...''CEOL'"
$ Wait 00:00:01.5
$ SAY ESC + "[''MSG_ROW';01H", CEOL
$!
$ EXIT
$!
$ ENDSUBROUTINE
$!
$!------------------------------------------------------------------------------
$! Exit the procedure
$!------------------------------------------------------------------------------
$!
$EXIT:
$!
$ DEFINE /USER /NOLOG SYS$ERROR  NL:
$ DEFINE /USER /NOLOG SYS$OUTPUT NL:
$ DEASSIGN SYS$OUTPUT
$!
$ DEFINE /USER /NOLOG SYS$ERROR  NL:
$ DEFINE /USER /NOLOG SYS$OUTPUT NL:
$ DEASSIGN SYS$ERROR
$!
$ DEFINE /USER /NOLOG SYS$ERROR  NL:
$ DEFINE /USER /NOLOG SYS$OUTPUT NL:
$ CLOSE OFILE
$!
$ DEL_USER_DATA
$!
$ IF F$TYPE (SSL_CONF_DATA) .NES. "" THEN DELETE /SYMBOL /GLOBAL SSL_CONF_DATA
$!
$ IF F$GETDVI ("TT:","TT_NOECHO") .AND. .NOT. TT_NOECHO THEN SET TERMINAL /ECHO
$!
$ IF F$SEARCH ("SYS$LOGIN:SSL_CA_''PID'.%%%;*") .NES. "" THEN DELETE /NOLOG /NOCONFIRM SYS$LOGIN:SSL_CA_'PID'.%%%;*
$ IF F$SEARCH ("SYS$LOGIN:SSL_X509_''PID'.%%%;*") .NES. "" THEN DELETE /NOLOG /NOCONFIRM SYS$LOGIN:SSL_X509_'PID'.%%%;*
$!
$ Verify = F$VERIFY (Verify)
$!
$ EXIT
