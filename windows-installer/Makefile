
openssl-installer: openssl.nsi
	makensis.exe /DVERSION=testversion /DBUILD32=_build32 /DBUILD64=_build64 .\openssl.nsi

signed-openssl-installer: openssl.nsi
	makecert.exe /n "CN=TestCompany" /r /h 0 /eku "1.3.6.1.5.5.7.3.3,1.3.6.1.4.1.311.10.3.13" /sv testcert.pvk testcert.cer
	pvk2pfx.exe /pvk testcert.pvk /pi testpass /spc testcert.cer /pfx testcert.pfx /po testpass
	makensis.exe /DVERSION=testversion /DBUILD32=_build32 /DBUILD64=_build64 /DSIGN=testcert.pfx /DSIGNPASS=testpass .\openssl.nsi

clean:
	del .\*.exe .\test*.*

