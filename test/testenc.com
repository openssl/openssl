$! TESTENC.COM  --  Test encoding and decoding
$
$	__arch := VAX
$	if f$getsyi("cpu") .ge. 128 then __arch := AXP
$	exe_dir := sys$disk:[-.'__arch'.exe.apps]
$
$	testsrc := makefile.ssl
$	test := p.txt
$	cmd := mcr 'exe_dir'openssl
$
$	copy 'testsrc' 'test'
$
$	write sys$output "cat"
$	'cmd' enc -in 'test' -out 'test'-cipher
$	'cmd' enc -in 'test'-cipher -out 'test'-clear
$	difference/output=nl: 'test' 'test'-clear
$	if $severity .ne. 1 then exit 3
$	delete 'test'-cipher;*,'test'-clear;*
$
$	write sys$output "base64"
$	'cmd' enc -a -e -in 'test' -out 'test'-cipher
$	'cmd' enc -a -d -in 'test'-cipher -out 'test'-clear
$	difference/output=nl: 'test' 'test'-clear
$	if $severity .ne. 1 then exit 3
$	delete 'test'-cipher;*,'test'-clear;*
$
$	define/user sys$output 'test'-cipher-commands
$	'cmd' list-cipher-commands
$	open/read f 'test'-cipher-commands
$ loop_cipher_commands:
$	read/end=loop_cipher_commands_end f i
$	write sys$output i
$	'cmd' 'i' -bufsize 113 -e -k test -in 'test' -out 'test'-'i'-cipher
$	'cmd' 'i' -bufsize 157 -d -k test -in 'test'-'i'-cipher -out 'test'-'i'-clear
$	difference/output=nl: 'test' 'test'-'i'-clear
$	if $severity .ne. 1 then exit 3
$	delete 'test'-'i'-cipher;*,'test'-'i'-clear;*
$
$	write sys$output i," base64"
$	'cmd' 'i' -bufsize 113 -a -e -k test -in 'test' -out 'test'-'i'-cipher
$	'cmd' 'i' -bufsize 157 -a -d -k test -in 'test'-'i'-cipher -out 'test'-'i'-clear
$	difference/output=nl: 'test' 'test'-'i'-clear
$	if $severity .ne. 1 then exit 3
$	delete 'test'-'i'-cipher;*,'test'-'i'-clear;*
$
$	goto loop_cipher_commands
$ loop_cipher_commands_end:
$	close f
$	delete 'test'-cipher-commands;*
$	delete 'test';*
