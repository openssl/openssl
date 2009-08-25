$! TESTCA.COM
$
$	__arch := VAX
$	if f$getsyi("cpu") .ge. 128 then -
	   __arch = f$edit( f$getsyi( "ARCH_NAME"), "UPCASE")
$	if __arch .eqs. "" then __arch := UNK
$
$	openssl := mcr 'exe_dir'openssl
$
$	SSLEAY_CONFIG="-config ""CAss.cnf"""
$
$	set noon
$	if f$search("demoCA.dir") .nes. ""
$	then
$	    call deltree [.demoCA]*.*
$	    set file/prot=(S:RWED,O:RWED,G:RWED,W:RWED) demoCA.dir;*
$	    delete demoCA.dir;*
$	endif
$	set on
$	open/read sys$ca_input VMSca-response.1
$	@[-.apps]CA.com -input sys$ca_input -newca
$	close sys$ca_input
$	if $severity .ne. 1 then exit 3
$
$
$	SSLEAY_CONFIG="-config ""Uss.cnf"""
$	@[-.apps]CA.com -newreq
$	if $severity .ne. 1 then exit 3
$
$
$	SSLEAY_CONFIG="-config [-.apps]openssl-vms.cnf"
$	open/read sys$ca_input VMSca-response.2
$	@[-.apps]CA.com -input sys$ca_input -sign
$	close sys$ca_input
$	if $severity .ne. 1 then exit 3
$
$
$	@[-.apps]CA.com -verify newcert.pem
$	if $severity .ne. 1 then exit 3
$
$	set noon
$	call deltree [.demoCA]*.*
$	set file/prot=(S:RWED,O:RWED,G:RWED,W:RWED) demoCA.dir;*
$	delete demoCA.dir;*
$	if f$search("newcert.pem") .nes. "" then delete newcert.pem;*
$	if f$search("newcert.pem") .nes. "" then delete newreq.pem;*
$	set on
$!	#usage: CA -newcert|-newreq|-newca|-sign|-verify
$
$	exit
$
$ deltree: subroutine ! P1 is a name of a directory
$	on control_y then goto dt_STOP
$	on warning then goto dt_exit
$	_dt_def = f$trnlnm("SYS$DISK")+f$directory()
$	if f$parse(p1) .eqs. "" then exit
$	set default 'f$parse(p1,,,"DEVICE")''f$parse(p1,,,"DIRECTORY")'
$	p1 = f$parse(p1,,,"NAME") + f$parse(p1,,,"TYPE")
$	_fp = f$parse(".DIR",p1)
$ dt_loop:
$	_f = f$search(_fp)
$	if _f .eqs. "" then goto dt_loopend
$	call deltree [.'f$parse(_f,,,"NAME")']*.*
$	goto dt_loop
$ dt_loopend:
$	_fp = f$parse(p1,".;*")
$	if f$search(_fp) .eqs. "" then goto dt_exit
$	set noon
$	set file/prot=(S:RWED,O:RWED,G:RWED,W:RWED) '_fp'
$	set on
$	delete/nolog '_fp'
$ dt_exit:
$	set default '_dt_def'
$	exit
$ dt_STOP:
$	set default '_dt_def'
$	stop/id=""
$	exit
$	endsubroutine
