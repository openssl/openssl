
######################################################
# NSIS windows installer script file
# Requirements: NSIS 3.0 must be installed with the MUI plugin
# Usage notes:
# This script expects to be executed from the directory it is
# currently stored in.  It expects a 32 bit and 64 bit windows openssl
# build to be present in the ..\${BUILD32} and ..\${BUILD64} directories
# respectively
# ####################################################

!include "MUI.nsh"

!define PRODUCT_NAME "OpenSSL"

# The name of the output file we create when building this
# NOTE version is passed with the /D option on the command line
OutFile "openssl-${VERSION}-installer.exe"

# The name that will appear in the installer title bar
NAME "${PRODUCT_NAME} ${VERSION}"

ShowInstDetails show

Function .onInit
	StrCpy $INSTDIR "C:\Program Files\openssl-${VERSION}"
FunctionEnd

# This section is run if installation of 32 bit binaries are selected
!ifdef BUILD32
Section "32 Bit Binaries"
	SetOutPath $INSTDIR\x32
	File ..\${BUILD32}\libcrypto-3.dll
	File ..\${BUILD32}\libssl-3.dll
	File ..\${BUILD32}\apps\openssl.exe
	SetOutPath $INSTDIR\x32\providers
	File ..\${BUILD32}\providers\fips.dll
	File ..\${BUILD32}\providers\legacy.dll
SectionEnd
!endif

!ifdef BUILD64
# This section is run if installation of the 64 bit binaries are selectd
Section "64 Bit Binaries"
	SetOutPath $INSTDIR\x64
	File ..\${BUILD64}\libcrypto-3-x64.dll
	File ..\${BUILD64}\libssl-3-x64.dll
	File ..\${BUILD64}\apps\\openssl.exe
	SetOutPath $INSTDIR\x64\providers
	File ..\${BUILD64}\providers\fips.dll
	File ..\${BUILD64}\providers\legacy.dll
SectionEnd
!endif

# Optionally install x64 development headers
!ifdef BUILD64
Section "x64 Development Headers"
	SetOutPath $INSTDIR\x64\include\openssl
	!tempfile headerlist
	!system 'FOR /R "..\${BUILD64}\include\openssl" %A IN (*.h) DO @( >> "${headerlist}" echo.File "%~A" )'
	!include "${headerlist}"
	!delfile "${headerlist}"
	!undef headerlist

	SetOutPath $INSTDIR\x64\include\crypto
	!tempfile headerlist
	!system 'FOR /R "..\${BUILD64}\include\crypto" %A IN (*.h) DO @( >> "${headerlist}" echo.File "%~A" )'
	!include "${headerlist}"
	!delfile "${headerlist}"
	!undef headerlist

	SetOutPath $INSTDIR\x64\include\internal
	!tempfile headerlist
	!system 'FOR /R "..\${BUILD64}\include\internal" %A IN (*.h) DO @( >> "${headerlist}" echo.File "%~A" )'
	!include "${headerlist}"
	!delfile "${headerlist}"
	!undef headerlist
SectionEnd
!endif

# Optionally install x64 development headers
!ifdef BUILD32
Section "x32 Development Headers"
	SetOutPath $INSTDIR\x32\include\openssl
	!tempfile headerlist
	!system 'FOR /R "..\${BUILD32}\include\openssl" %A IN (*.h) DO @( >> "${headerlist}" echo.File "%~A" )'
	!include "${headerlist}"
	!delfile "${headerlist}"
	!undef headerlist

	SetOutPath $INSTDIR\x32\include\crypto
	!tempfile headerlist
	!system 'FOR /R "..\${BUILD32}\include\crypto" %A IN (*.h) DO @( >> "${headerlist}" echo.File "%~A" )'
	!include "${headerlist}"
	!delfile "${headerlist}"
	!undef headerlist

	SetOutPath $INSTDIR\x32\include\internal
	!tempfile headerlist
	!system 'FOR /R "..\${BUILD32}\include\internal" %A IN (*.h) DO @( >> "${headerlist}" echo.File "%~A" )'
	!include "${headerlist}"
	!delfile "${headerlist}"
	!undef headerlist
SectionEnd
!endif

# Always install the uninstaller
Section 
	WriteUninstaller $INSTDIR\uninstall.exe
SectionEnd

# This is run on uninstall
Section "Uninstall"
	RMDIR /r $INSTDIR
SectionEnd

!insertmacro MUI_PAGE_WELCOME

!insertmacro MUI_PAGE_LICENSE ../LICENSE.TXT

!insertmacro MUI_PAGE_COMPONENTS

!define MUI_DIRECTORYPAGE_TEXT_DESTINATION "Installation Directory"
!insertmacro MUI_PAGE_DIRECTORY

!insertmacro MUI_PAGE_INSTFILES

!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

!ifdef SIGN
!define OutFileSignSHA1 "SignTool.exe sign /f ${SIGN} /p ${SIGNPASS} /fd sha1 /t http://timestamp.comodoca.com /v"
!define OutFileSignSHA256 "SignTool.exe sign /f ${SIGN} /p ${SIGNPASS} /fd sha256 /tr http://timestamp.comodoca.com?td=sha256 /td sha256 /v"

!finalize "${OutFileSignSHA1} .\openssl-${VERSION}-installer.exe"
!finalize "${OutFileSignSHA256} .\openssl-${VERSION}-installer.exe"
!endif
