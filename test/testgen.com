$! TETSGEN.COM
$
$	__arch := VAX
$	if f$getsyi("cpu") .ge. 128 then __arch := AXP
$	exe_dir := sys$disk:[-.'__arch'.exe.apps]
$
$	T := testcert
$	KEY = 512
$	CA := [-.certs]testca.pem
$
$	set noon
$	if f$search(T+".1;*") .nes. "" then delete 'T'.1;*
$	if f$search(T+".2;*") .nes. "" then delete 'T'.2;*
$	if f$search(T+".key;*") .nes. "" then delete 'T'.key;*
$	set on
$
$	write sys$output "generating certificate request"
$
$	write sys$output "There should be a 2 sequences of .'s and some +'s."
$	write sys$output "There should not be more that at most 80 per line"
$	write sys$output "This could take some time."
$
$	mcr 'exe_dir'openssl req -config test.cnf -new -out testreq.pem
$	if $severity .ne. 1
$	then
$	    write sys$output "problems creating request"
$	    exit 3
$	endif
$
$	mcr 'exe_dir'openssl req -verify -in testreq.pem -noout
$	if $severity .ne. 1
$	then
$	    write sys$output "signature on req is wrong"
$	    exit 3
$	endif
