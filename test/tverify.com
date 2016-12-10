$! TVERIFY.COM
$
$	__arch := VAX
$	if f$getsyi("cpu") .ge. 128 then __arch := AXP
$	exe_dir := sys$disk:[-.'__arch'.exe.apps]
$
$	copy/concatenate [-.certs]*.pem certs.tmp
$
$	old_f :=
$ loop_certs:
$	verify := NO
$	more := YES
$	certs :=
$ loop_certs2:
$	f = f$search("[-.certs]*.pem")
$	if f .nes. "" .and. f .nes. old_f
$	then
$	    certs = certs + " [-.certs]" + f$parse(f,,,"NAME") + ".pem"
$	    verify := YES
$	    if f$length(certs) .lt. 180 then goto loop_certs2
$	else
$	    more := NO
$	endif
$	certs = certs - " "
$
$	if verify then mcr 'exe_dir'openssl verify "-CAfile" certs.tmp 'certs'
$	if more then goto loop_certs
$
$	delete certs.tmp;*
