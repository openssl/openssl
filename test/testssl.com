$! TESTSSL.COM
$
$	__arch := VAX
$	if f$getsyi("cpu") .ge. 128 then __arch := AXP
$	exe_dir := sys$disk:[-.'__arch'.exe.test]
$
$	copy/concatenate [-.certs]*.pem certs.tmp
$
$	write sys$output "test sslv2"
$	mcr 'exe_dir'ssltest -ssl2
$	if $severity .ne. 1 then goto exit3
$
$	write sys$output "test sslv2 with server authentication"
$	mcr 'exe_dir'ssltest -ssl2 -server_auth "-CAfile" certs.tmp
$	if $severity .ne. 1 then goto exit3
$
$	write sys$output "test sslv2 with client authentication"
$	mcr 'exe_dir'ssltest -ssl2 -client_auth "-CAfile" certs.tmp
$	if $severity .ne. 1 then goto exit3
$
$	write sys$output "test sslv2 with both client and server authentication"
$	mcr 'exe_dir'ssltest -ssl2 -server_auth -client_auth "-CAfile" certs.tmp
$	if $severity .ne. 1 then goto exit3
$
$	write sys$output "test sslv3"
$	mcr 'exe_dir'ssltest -ssl3
$	if $severity .ne. 1 then goto exit3
$
$	write sys$output "test sslv3 with server authentication"
$	mcr 'exe_dir'ssltest -ssl3 -server_auth "-CAfile" certs.tmp
$	if $severity .ne. 1 then goto exit3
$
$	write sys$output "test sslv3 with client authentication"
$	mcr 'exe_dir'ssltest -ssl3 -client_auth "-CAfile" certs.tmp
$	if $severity .ne. 1 then goto exit3
$
$	write sys$output "test sslv3 with both client and server authentication"
$	mcr 'exe_dir'ssltest -ssl3 -server_auth -client_auth "-CAfile" certs.tmp
$	if $severity .ne. 1 then goto exit3
$
$	write sys$output "test sslv2/sslv3"
$	mcr 'exe_dir'ssltest
$	if $severity .ne. 1 then goto exit3
$
$	write sys$output "test sslv2/sslv3 with server authentication"
$	mcr 'exe_dir'ssltest -server_auth "-CAfile" certs.tmp
$	if $severity .ne. 1 then goto exit3
$
$	write sys$output "test sslv2/sslv3 with client authentication"
$	mcr 'exe_dir'ssltest -client_auth "-CAfile" certs.tmp
$	if $severity .ne. 1 then goto exit3
$
$	write sys$output "test sslv2/sslv3 with both client and server authentication"
$	mcr 'exe_dir'ssltest -server_auth -client_auth "-CAfile" certs.tmp
$	if $severity .ne. 1 then goto exit3
$
$	write sys$output "test sslv2 via BIO pair"
$	mcr 'exe_dir'ssltest -bio_pair -ssl2 
$	if $severity .ne. 1 then goto exit3
$
$	write sys$output "test sslv2 with server authentication via BIO pair"
$	mcr 'exe_dir'ssltest -bio_pair -ssl2 -server_auth "-CAfile" certs.tmp 
$	if $severity .ne. 1 then goto exit3
$
$	write sys$output "test sslv2 with client authentication via BIO pair"
$	mcr 'exe_dir'ssltest -bio_pair -ssl2 -client_auth "-CAfile" certs.tmp 
$	if $severity .ne. 1 then goto exit3
$
$	write sys$output "test sslv2 with both client and server authentication via BIO pair"
$	mcr 'exe_dir'ssltest -bio_pair -ssl2 -server_auth -client_auth "-CAfile" certs.tmp 
$	if $severity .ne. 1 then goto exit3
$
$	write sys$output "test sslv3 via BIO pair"
$	mcr 'exe_dir'ssltest -bio_pair -ssl3 
$	if $severity .ne. 1 then goto exit3
$
$	write sys$output "test sslv3 with server authentication via BIO pair"
$	mcr 'exe_dir'ssltest -bio_pair -ssl3 -server_auth "-CAfile" certs.tmp 
$	if $severity .ne. 1 then goto exit3
$
$	write sys$output "test sslv3 with client authentication via BIO pair"
$	mcr 'exe_dir'ssltest -bio_pair -ssl3 -client_auth "-CAfile" certs.tmp 
$	if $severity .ne. 1 then goto exit3
 
$	write sys$output "test sslv3 with both client and server authentication via BIO pair"
$	mcr 'exe_dir'ssltest -bio_pair -ssl3 -server_auth -client_auth "-CAfile" certs.tmp 
$	if $severity .ne. 1 then goto exit3
$
$	write sys$output "test sslv2/sslv3 via BIO pair"
$	mcr 'exe_dir'ssltest 
$	if $severity .ne. 1 then goto exit3
$
$	write sys$output "test sslv2/sslv3 with server authentication"
$	mcr 'exe_dir'ssltest -bio_pair -server_auth "-CAfile" certs.tmp 
$	if $severity .ne. 1 then goto exit3
$
$	write sys$output "test sslv2/sslv3 with client authentication via BIO pair"
$	mcr 'exe_dir'ssltest -bio_pair -client_auth "-CAfile" certs.tmp 
$	if $severity .ne. 1 then goto exit3
$
$	write sys$output "test sslv2/sslv3 with both client and server authentication via BIO pair"
$	mcr 'exe_dir'ssltest -bio_pair -server_auth -client_auth "-CAfile" certs.tmp 
$	if $severity .ne. 1 then goto exit3
$
$	RET = 1
$	goto exit
$ exit3:
$	RET = 3
$ exit:
$	delete certs.tmp;*
$	exit 'RET'
