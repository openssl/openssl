This is a quick high level summery of how things work now.

Each SSLv2 and SSLv3 cipher is composed of 4 major attributes plus a few extra
minor ones.

They are 'The key exchange algorithm', which is RSA for SSLv2 but can also
be Diffle-Hellman for SSLv3.

An 'Authenticion algorithm', which can be RSA, Diffle-Helman, DSS or
none.

The cipher

The MAC digest.

A cipher can also be an export cipher and is either an SSLv2 or a
SSLv3 ciphers.

To specify which ciphers to use, one can either specify all the ciphers,
one at a time, or use 'aliases' to specify the preference and order for
the ciphers.

There are a large number of aliases, but the most importaint are
kRSA, kDHr, kDHd and kEDH for key exchange types.

aRSA, aDSS, aNULL and aDH for authentication
DES, 3DES, RC4, RC2, IDEA and eNULL for ciphers
MD5, SHA0 and SHA1 digests

Now where this becomes interesting is that these can be put together to
specify the order and ciphers you wish to use.

To speed this up there are also aliases for certian groups of ciphers.
The main ones are
SSLv2	- all SSLv2 ciphers
SSLv3	- all SSLv3 ciphers
EXP	- all export ciphers
LOW	- all low strngth ciphers (no export ciphers, normally single DES)
MEDIUM	- 128 bit encryption
HIGH	- Triple DES

These aliases can be joined in a : separated list which specifies to
add ciphers, move them to the current location and delete them.

A simpler way to look at all of this is to use the 'ssleay ciphers -v' command.
The default library cipher spec is
!ADH:RC4+RSA:HIGH:MEDIUM:LOW:EXP:+SSLv2:+EXP
which means, first, remove from consideration any ciphers that do not
authenticate.  Next up, use ciphers using RC4 and RSA.  Next include the HIGH,
MEDIUM and the LOW security ciphers.  Finish up by adding all the export
ciphers on the end, then 'pull' all the SSLv2 and export ciphers to
the end of the list.

The results are
$ ssleay ciphers -v '!ADH:RC4+RSA:HIGH:MEDIUM:LOW:EXP:+SSLv2:+EXP'

RC4-SHA                 SSLv3 Kx=RSA      Au=RSA  Enc=RC4(128)  Mac=SHA1
RC4-MD5                 SSLv3 Kx=RSA      Au=RSA  Enc=RC4(128)  Mac=MD5 
EDH-RSA-DES-CBC3-SHA    SSLv3 Kx=DH       Au=RSA  Enc=3DES(168) Mac=SHA1
EDH-DSS-DES-CBC3-SHA    SSLv3 Kx=DH       Au=DSS  Enc=3DES(168) Mac=SHA1
DES-CBC3-SHA            SSLv3 Kx=RSA      Au=RSA  Enc=3DES(168) Mac=SHA1
IDEA-CBC-MD5            SSLv3 Kx=RSA      Au=RSA  Enc=IDEA(128) Mac=SHA1
EDH-RSA-DES-CBC-SHA     SSLv3 Kx=DH       Au=RSA  Enc=DES(56)   Mac=SHA1
EDH-DSS-DES-CBC-SHA     SSLv3 Kx=DH       Au=DSS  Enc=DES(56)   Mac=SHA1
DES-CBC-SHA             SSLv3 Kx=RSA      Au=RSA  Enc=DES(56)   Mac=SHA1
DES-CBC3-MD5            SSLv2 Kx=RSA      Au=RSA  Enc=3DES(168) Mac=MD5 
DES-CBC-MD5             SSLv2 Kx=RSA      Au=RSA  Enc=DES(56)   Mac=MD5 
IDEA-CBC-MD5            SSLv2 Kx=RSA      Au=RSA  Enc=IDEA(128) Mac=MD5 
RC2-CBC-MD5             SSLv2 Kx=RSA      Au=RSA  Enc=RC2(128)  Mac=MD5 
RC4-MD5                 SSLv2 Kx=RSA      Au=RSA  Enc=RC4(128)  Mac=MD5 
EXP-EDH-RSA-DES-CBC     SSLv3 Kx=DH(512)  Au=RSA  Enc=DES(40)   Mac=SHA1 export
EXP-EDH-DSS-DES-CBC-SHA SSLv3 Kx=DH(512)  Au=DSS  Enc=DES(40)   Mac=SHA1 export
EXP-DES-CBC-SHA         SSLv3 Kx=RSA(512) Au=RSA  Enc=DES(40)   Mac=SHA1 export
EXP-RC2-CBC-MD5         SSLv3 Kx=RSA(512) Au=RSA  Enc=RC2(40)   Mac=MD5  export
EXP-RC4-MD5             SSLv3 Kx=RSA(512) Au=RSA  Enc=RC4(40)   Mac=MD5  export
EXP-RC2-CBC-MD5         SSLv2 Kx=RSA(512) Au=RSA  Enc=RC2(40)   Mac=MD5  export
EXP-RC4-MD5             SSLv2 Kx=RSA(512) Au=RSA  Enc=RC4(40)   Mac=MD5  export

I would recoment people use the 'ssleay ciphers -v "text"'
command to check what they are going to use.

Anyway, I'm falling asleep here so I'll do some more tomorrow.

eric
