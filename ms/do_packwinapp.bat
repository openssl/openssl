     @echo off
     if exist vsout\package rd /s /q vsout\package
     mkdir vsout\package
     mkdir vsout\package\include
     mkdir vsout\package\lib
     mkdir vsout\package\bin
     xcopy inc32 vsout\package\include /h /k /r /e /i /y >nul

     call :pack Phone 8.0 Dll    Unicode Debug   Win32
     call :pack Phone 8.0 Dll    Unicode Debug   arm
     call :pack Phone 8.0 Dll    Unicode Release Win32
     call :pack Phone 8.0 Dll    Unicode Release arm
     call :pack Phone 8.0 Static Unicode Debug   Win32
     call :pack Phone 8.0 Static Unicode Debug   arm
     call :pack Phone 8.0 Static Unicode Release Win32
     call :pack Phone 8.0 Static Unicode Release arm
     call :pack Phone 8.1 Dll    Unicode Debug   Win32
     call :pack Phone 8.1 Dll    Unicode Debug   arm
     call :pack Phone 8.1 Dll    Unicode Release Win32
     call :pack Phone 8.1 Dll    Unicode Release arm
     call :pack Phone 8.1 Static Unicode Debug   Win32
     call :pack Phone 8.1 Static Unicode Debug   arm
     call :pack Phone 8.1 Static Unicode Release Win32
     call :pack Phone 8.1 Static Unicode Release arm
     call :pack Store 8.1 Dll    Unicode Debug   Win32
     call :pack Store 8.1 Dll    Unicode Debug   arm
     call :pack Store 8.1 Dll    Unicode Debug   x64
     call :pack Store 8.1 Dll    Unicode Release Win32
     call :pack Store 8.1 Dll    Unicode Release arm
     call :pack Store 8.1 Dll    Unicode Release x64
     call :pack Store 8.1 Static Unicode Debug   Win32
     call :pack Store 8.1 Static Unicode Debug   arm
     call :pack Store 8.1 Static Unicode Debug   x64
     call :pack Store 8.1 Static Unicode Release Win32
     call :pack Store 8.1 Static Unicode Release arm
     call :pack Store 8.1 Static Unicode Release x64

     :pack
     echo %1 %2 %3 %4 %5 %6
     if not exist vsout\package\lib\%1\%2\%3\%4\%5\%6 mkdir vsout\package\lib\%1\%2\%3\%4\%5\%6 > nul
     copy vsout\NT-%1-%2-%3-%4\%5\%6\bin\libeay32.lib vsout\package\lib\%1\%2\%3\%4\%5\%6\libeay32.lib
     copy vsout\NT-%1-%2-%3-%4\%5\%6\bin\ssleay32.lib vsout\package\lib\%1\%2\%3\%4\%5\%6\ssleay32.lib
     if "%3"=="Static" goto :eof
     if not exist vsout\package\bin\%1\%2\%3\%4\%5\%6 mkdir vsout\package\bin\%1\%2\%3\%4\%5\%6 > nul
     copy vsout\NT-%1-%2-%3-%4\%5\%6\bin\libeay32.dll vsout\package\bin\%1\%2\%3\%4\%5\%6\libeay32.dll
     copy vsout\NT-%1-%2-%3-%4\%5\%6\bin\ssleay32.dll vsout\package\bin\%1\%2\%3\%4\%5\%6\ssleay32.dll
     goto :eof
