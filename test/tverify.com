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
$	c := NO
$	certs :=
$ loop_certs2:
$	f = f$search("[-.certs]*.pem")
$	if f .nes. "" .and. f .nes. old_f
$	then
$	    certs = certs + " [-.certs]" + f$parse(f,,,"NAME") + ".pem"
$	    if f$length(certs) .lt. 180 then goto loop_certs2
$	    c := YES
$	endif
$	certs = certs - " "
$
$	mcr 'exe_dir'openssl verify "-CAfile" certs.tmp 'certs'
$	if c then goto loop_certs
$
$	delete certs.tmp;*
