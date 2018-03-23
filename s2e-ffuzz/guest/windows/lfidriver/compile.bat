@echo off
REM The build results are put in the .\deployment folder.
REM Upload the content of the folder to the live servce.

goto begin

:setddk
REM ==== BEGIN USER EDITABLE ====
set DDK_ROOT=D:\Tools\WinDDK\7600.16385.1
REM ==== END USER EDITABLE ====
goto end

:resetenv
call resetenv.vbs
call %TEMP%\resetvars.bat
call :setddk
set DDK_BIN=%DDK_ROOT%\bin
set LFI_ROOT=%cd%
goto end

:winxp
echo ==========================================
echo BUILDING WINDOWS XP DRIVER AND TOOLS
echo ==========================================
call :resetenv
call %DDK_BIN%\setenv.bat %DDK_ROOT% fre x86 WXP
cd %LFI_ROOT%
build /c

cd %LFI_ROOT%\nictester\50
build /c
cd %LFI_ROOT%

copy driver\obj%BUILD_ALT_DIR%\i386\lfidriver.sys deployment\winxp\lfidriver.sys
copy testctl\obj%BUILD_ALT_DIR%\i386\testctl.exe deployment\winxp\testctl.exe
copy nictester\test\obj%BUILD_ALT_DIR%\i386\nictester.exe deployment\winxp\nictester.exe
copy nictester\50\obj%BUILD_ALT_DIR%\i386\nettickler.sys deployment\winxp\nettickler.sys
copy nictester\nettickler.inf deployment\winxp\nettickler.inf

copy lfidriver.inf deployment\winxp

goto end

:win7_64
echo ==========================================
echo BUILDING WINDOWS 7 x64 DRIVERS AND TOOLS
echo ==========================================
call :resetenv
call %DDK_BIN%\setenv.bat %DDK_ROOT% chk x64 WIN7
cd %LFI_ROOT%
build

cd %LFI_ROOT%\nictester\60
build /c
cd %LFI_ROOT%

rem 864 means Windows 8 64-bits
rem For now, we use the Win7 build system, close enough to win8.
rem We'll have to think about it when actually useing Win8-specific features

copy driver\obj%BUILD_ALT_DIR%\amd64\lfidriver.sys deployment\win8_64\lfidriver.sys
copy driver\obj%BUILD_ALT_DIR%\amd64\lfidriver.pdb deployment\win8_64\lfidriver.pdb
copy testctl\obj%BUILD_ALT_DIR%\amd64\testctl.exe deployment\win8_64\testctl.exe
copy nictester\test\obj%BUILD_ALT_DIR%\amd64\nictester.exe deployment\win8_64\nictester.exe
copy nictester\60\obj%BUILD_ALT_DIR%\amd64\nettickler.sys deployment\win8_64\nettickler.sys
copy nictester\nettickler.inf deployment\win8_64\nettickler.inf

copy lfidriver.inf deployment\win8_64


cd sign
call sign.bat ..\deployment\win8_64\lfidriver.sys
cd ..

goto end


REM ==========================================
REM Build starts here
:begin

md deployment\winxp
md deployment\win8_32
md deployment\win8_64

call :winxp
call :win7_64

:end