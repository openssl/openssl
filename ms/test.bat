@echo=off

set bin=..\out
set test=.

echo destest
%bin%\destest
if errorlevel 1 goto done

echo ideatest
%bin%\ideatest
if errorlevel 1 goto done

echo bftest
%bin%\bftest
if errorlevel 1 goto done

echo shatest
%bin%\shatest
if errorlevel 1 goto done

echo sha1test
%bin%\sha1test
if errorlevel 1 goto done

echo md5test
%bin%\md5test
if errorlevel 1 goto done

echo md2test
%bin%\md2test
if errorlevel 1 goto done

echo mdc2test
%bin%\mdc2test
if errorlevel 1 goto done

echo rc2test
%bin%\rc2test
if errorlevel 1 goto done

echo rc4test
%bin%\rc4test
if errorlevel 1 goto done

echo randtest
%bin%\randtest
if errorlevel 1 goto done

echo dhtest
%bin%\dhtest
if errorlevel 1 goto done

echo exptest
%bin%\exptest
if errorlevel 1 goto done

echo dsatest
%bin%\dsatest
if errorlevel 1 goto done

echo testenc
call %test%\testenc %bin%\ssleay
if errorlevel 1 goto done

echo testpem
call %test%\testpem %bin%\ssleay
if errorlevel 1 goto done

echo verify
copy ..\certs\*.pem cert.tmp >nul
%bin%\ssleay verify -CAfile cert.tmp ..\certs\*.pem

echo testss
call %test%\testss %bin%\ssleay
if errorlevel 1 goto done

echo test sslv2
%bin%\ssltest -ssl2
if errorlevel 1 goto done

echo test sslv2 with server authentication
%bin%\ssltest -ssl2 -server_auth -CAfile cert.tmp
if errorlevel 1 goto done

echo test sslv2 with client authentication 
%bin%\ssltest -ssl2 -client_auth -CAfile cert.tmp
if errorlevel 1 goto done

echo test sslv2 with beoth client and server authentication
%bin%\ssltest -ssl2 -server_auth -client_auth -CAfile cert.tmp
if errorlevel 1 goto done

echo test sslv3
%bin%\ssltest -ssl3
if errorlevel 1 goto done

echo test sslv3 with server authentication
%bin%\ssltest -ssl3 -server_auth -CAfile cert.tmp
if errorlevel 1 goto done

echo test sslv3 with client authentication 
%bin%\ssltest -ssl3 -client_auth -CAfile cert.tmp
if errorlevel 1 goto done

echo test sslv3 with beoth client and server authentication
%bin%\ssltest -ssl3 -server_auth -client_auth -CAfile cert.tmp
if errorlevel 1 goto done

echo test sslv2/sslv3
%bin%\ssltest
if errorlevel 1 goto done

echo test sslv2/sslv3 with server authentication
%bin%\ssltest -server_auth -CAfile cert.tmp
if errorlevel 1 goto done

echo test sslv2/sslv3 with client authentication 
%bin%\ssltest -client_auth -CAfile cert.tmp
if errorlevel 1 goto done

echo test sslv2/sslv3 with beoth client and server authentication
%bin%\ssltest -server_auth -client_auth -CAfile cert.tmp
if errorlevel 1 goto done


del cert.tmp

echo passed all tests
goto end
:done
echo problems.....
:end
