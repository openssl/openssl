$! --- VMS.com ---
$!
$ GoSub defines
$ GoSub linker_options
$ If (P1 .nes. "")
$ Then 
$   GoSub 'P1'
$ Else
$   GoSub lib
$   GoSub destest
$   GoSub rpw
$   GoSub speed
$   GoSub des
$ EndIF
$!
$ Exit
$!
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
$!
$DEFINES:
$ OPT_FILE := "VAX_LINKER_OPTIONS.OPT"
$!
$ CC_OPTS := "/NODebug/OPTimize/NOWarn"
$!
$ LINK_OPTS := "/NODebug/NOTraceback/Contiguous"
$!
$ OBJS  = "cbc_cksm.obj,cbc_enc.obj,ecb_enc.obj,pcbc_enc.obj," + -
          "qud_cksm.obj,rand_key.obj,read_pwd.obj,set_key.obj,"      + -
          "str2key.obj,enc_read.obj,enc_writ.obj,fcrypt.obj,"           + -
	  "cfb_enc.obj,ecb3_enc.obj,ofb_enc.obj"
	   
	   
$!
$ LIBDES = "cbc_cksm.c,cbc_enc.c,ecb_enc.c,enc_read.c,"           + -
           "enc_writ.c,pcbc_enc.c,qud_cksm.c,rand_key.c,"         + -
           "read_pwd.c,set_key.c,str2key.c,fcrypt.c,"                + -
	   "cfb_enc.c,ecb3_enc.c,ofb_enc.c"
$ Return
$!
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
$!
$LINKER_OPTIONS:
$ If (f$search(OPT_FILE) .eqs. "")
$ Then
$   Create 'OPT_FILE'
$DECK
! Default system options file to link against the sharable C runtime library
!
Sys$Share:VAXcRTL.exe/Share
$EOD
$ EndIF
$ Return
$!
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
$!
$LIB:
$ CC 'CC_OPTS' 'LIBDES'
$ If (f$search("LIBDES.OLB") .nes. "")
$ Then Library /Object /Replace libdes 'OBJS'
$ Else Library /Create /Object  libdes 'OBJS'
$ EndIF
$ Return
$!
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
$!
$DESTEST:
$ CC 'CC_OPTS' destest
$ Link 'link_opts' /Exec=destest destest.obj,libdes/LIBRARY,'opt_file'/Option
$ Return
$!
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
$!
$RPW:
$ CC 'CC_OPTS' rpw
$ Link 'link_opts' /Exec=rpw  rpw.obj,libdes/LIBRARY,'opt_file'/Option
$ Return
$!
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
$!
$SPEED:
$ CC 'CC_OPTS' speed
$ Link 'link_opts' /Exec=speed speed.obj,libdes/LIBRARY,'opt_file'/Option
$ Return
$!
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
$!
$DES:
$ CC 'CC_OPTS' des
$ Link 'link_opts' /Exec=des des.obj,libdes/LIBRARY,'opt_file'/Option
$ Return
