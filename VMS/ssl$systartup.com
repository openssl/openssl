$!
$!
$!  Add logical to aid random number generators.  --  http://www.free.lp.se/openssl/docs/openssl3.html#ss3.1
$!
$ DEFINE/SYSTEM/EXEC  RANDFILE		SSL$ROOT:[PRIVATE]RANDFILE.;
$ DEFINE/SYSTEM/EXEC  SSL$RANDFILE	SSL$ROOT:[PRIVATE]RANDFILE.;
$!
