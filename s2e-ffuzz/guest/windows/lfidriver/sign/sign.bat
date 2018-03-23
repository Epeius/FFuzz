REM run from the Visual Studio Developer console
REM put the relative or absolute path to the sys file of the lfi driver

signtool sign /v /f CyberHaven_SPC.pfx /t http://timestamp.verisign.com/scripts/timestamp.dll %1


