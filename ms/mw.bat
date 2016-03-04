@rem OpenSSL with Mingw32
@rem --------------------

@rem Makefile
perl util\mkfiles.pl >MINFO
perl util\mk1mf.pl Mingw32 >ms\mingw32.mak
@rem DLL definition files
perl util\mkdef.pl 32 libcrypto >ms\libcrypto32.def
if errorlevel 1 goto end
perl util\mkdef.pl 32 libssl >ms\libssl32.def
if errorlevel 1 goto end

@rem Build the libraries
make -f ms/mingw32.mak
if errorlevel 1 goto end

@rem Generate the DLLs and input libraries
dllwrap --dllname libcrypto32.dll --output-lib out/libcrypto32.a --def ms/libcrypto32.def out/libcrypto.a -lws2_32 -lgdi32
if errorlevel 1 goto end
dllwrap --dllname libssl32.dll --output-lib out/libssl32.a --def ms/libssl32.def out/libssl.a out/libcrypto32.a
if errorlevel 1 goto end

echo Done compiling OpenSSL

:end

