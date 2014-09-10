@echo off
call:set_%1
exit /b
:set_wp8.1arm
	call:setVar _VS12VC VisualStudio12VC
	call:setVar _WPKITS81 WindowsPhoneKits8.1
	call "%_VS12VC%\vcvarsall" x86_arm
	set PATH=%_VS12VC\Bin%;%PATH%
	set INCLUDE=%_WPKITS81%\Include;%_WPKITS81%\Include\abi;%_WPKITS81%\Include\mincore;%_WPKITS81%\Include\minwin;%_WPKITS81%\Include\wrl;%INCLUDE%
	set LIB=%_WPKITS81%\lib\ARM;%_VS12VC%\lib\ARM;
	set LIBPATH=%LIBPATH%;%_VS12VC%\vcpackages;%WindowsSDK_ExecutablePath_x86%\..\..\Tools\MDILXAPCompile\WinMDs
	goto :eof

:set_wp8.1Win32
	call:setVar _VS12VC VisualStudio12VC
	call:setVar _WPKITS81 WindowsPhoneKits8.1
	call "%_VS12VC%\vcvarsall" x86
	set INCLUDE=%_WPKITS81%\Include;%_WPKITS81%\Include\abi;%_WPKITS81%\Include\mincore;%_WPKITS81%\Include\minwin;%_WPKITS81%\Include\wrl;%INCLUDE%
	set LIB=%_WPKITS81%\lib\x86;%_VS12VC%\lib\store;
	set LIBPATH=%LIBPATH%;%_VS12VC%\vcpackages;%WindowsSDK_ExecutablePath_x86%\..\..\Tools\MDILXAPCompile\WinMDs
	goto :eof

:set_wp8.0arm
	call:setVar _VS11VC VisualStudio11VC
	call:setVar _WPKITS80 WindowsPhoneKits8.0
	call "%_VS11VC%\WPSDK\WP80\vcvarsphoneall.bat" x86_arm
	goto :eof

:set_wp8.0Win32
	call:setVar _VS11VC VisualStudio11VC
	call:setVar _WPKITS80 WindowsPhoneKits8.0
	call "%_VS11VC%\WPSDK\WP80\vcvarsphoneall.bat" x86
	goto :eof

:set_ws8.1Win32
	call:setVar _VS12VC VisualStudio12VC
	call:setVar _WSKITS81 WindowsKits8.1
	call "%_VS12VC%\vcvarsall" x86
	set INCLUDE=%_VS12VC%\include;%_VS12VC%\atlmfc\include;%_WSKITS81%\Include\um;%_WSKITS81%\Include\shared;%_WSKITS81%\Include\winrt;
	set LIB=%_VS12VC%\lib\store;%_VS12VC%\atlmfc\lib;%_WSKITS81%\lib\winv6.3\um\x86;
	set LIBPATH=%_WSKITS81%\References\CommonConfiguration\Neutral;%_VS12VC%\atlmfc\lib;%_VS12VC%\lib;%_VS12VC%\vcpackages;%WindowsSDK_ExecutablePath_x86%\..\..\Tools\MDILXAPCompile\WinMDs
	goto :eof

:set_ws8.1x64
	call:setVar _VS12VC VisualStudio12VC
	call:setVar _WSKITS81 WindowsKits8.1
	call "%_VS12VC%\vcvarsall" x64
	set INCLUDE=%_VS12VC%\include;%_VS12VC%\atlmfc\include;%_WSKITS81%\Include\um;%_WSKITS81%\Include\shared;%_WSKITS81%\Include\winrt;
	set LIB=%_VS12VC%\lib\amd64;%_VS12VC%\atlmfc\lib\amd64;%_WSKITS81%\lib\winv6.3\um\x64;
	set LIBPATH=%_WSKITS81%\References\CommonConfiguration\Neutral;%_VS12VC%\atlmfc\lib\amd64;%_VS12VC%\lib;%_VS12VC%\vcpackages;%WindowsSDK_ExecutablePath_x86%\..\..\Tools\MDILXAPCompile\WinMDs
	goto :eof

:set_ws8.1arm
	call:setVar _VS12VC VisualStudio12VC
	call:setVar _WSKITS81 WindowsKits8.1
	call "%_VS12VC%\vcvarsall" x86_arm
	set INCLUDE=%_VS12VC%\include;%_VS12VC%\atlmfc\include;%_WSKITS81%\Include\um;%_WSKITS81%\Include\shared;%_WSKITS81%\Include\winrt;
	set LIB=%_VS12VC%\lib\arm;%_VS12VC%\atlmfc\lib\arm;%_WSKITS81%\lib\winv6.3\um\arm;
	set LIBPATH=%_WSKITS81%\References\CommonConfiguration\Neutral;%_VS12VC%\atlmfc\lib\arm;%_VS12VC%\lib;%_VS12VC%\vcpackages;%WindowsSDK_ExecutablePath_x86%\..\..\Tools\MDILXAPCompile\WinMDs
	goto :eof

:setVar
	call:set%1
	if "!%1!"=="" echo warning: could not locate %2
	goto :eof

:setRegVar
	for /F "usebackq tokens=2*" %%A IN (`reg query %1 /v %2 2^>nul`) do (
	set %3=%%B
	)
	goto :eof

:setAppend
	if exist %1%2 set %3=%1%2
	goto :eof

:set_VS11VC
	if not "%_VS11VC%"=="" goto :eof
	call:setRegVar "HKEY_CURRENT_USER\Software\Microsoft\VisualStudio\11.0_Config\Setup\VC" ProductDir _VS11VC
	if not "%_VS11VC%"=="" goto :eof
	call:setRegVar "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\VisualStudio\11.0\Setup\VC" ProductDir _VS11VC
	if not "%_VS11VC%"=="" goto :eof
	call:setAppend VSSDK110Install \..\VC _VS11VC
	if not "%_VS11VC%"=="" goto :eof
	call:setAppend VS110COMNTOOLS \..\..\VC _VS11VC
	goto :eof

:set_VS12VC
	if not "%_VS12VC%"=="" goto :eof
	call:setRegVar "HKEY_CURRENT_USER\Software\Microsoft\VisualStudio\12.0_Config\Setup\VC" ProductDir _VS12VC
	if not "%_VS12VC%"=="" goto :eof
	call:setRegVar "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\VisualStudio\12.0\Setup\VC" ProductDir _VS12VC
	if not "%_VS12VC%"=="" goto :eof
	call:setAppend VSSDK120Install \..\VC _VS12VC
	if not "%_VS12VC%"=="" goto :eof
	call:setAppend VS120COMNTOOLS \..\..\VC _VS12VC
	goto :eof

:set_WPKITS80
	if not "%_WPKITS80%"=="" goto :eof
	call:setRegVar "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Microsoft SDKs\Windows Phone\v8.0" InstallationFolder _WPKITS80
	if not "%_WPKITS80%"=="" goto :eof
	goto :eof

:set_WPKITS81
	if not "%_WPKITS81%"=="" goto :eof
	call:setRegVar "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Microsoft SDKs\Windows Phone\v8.1" InstallationFolder _WPKITS81
	if not "%_WPKITS81%"=="" goto :eof
	goto :eof

:set_WSKITS81
	if not "%_WSKITS81%"=="" goto :eof
	call:setRegVar "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Kits\Installed Roots" KitsRoot81 _WSKITS81
	if not "%_WSKITS81%"=="" goto :eof
	goto :eof
:end

