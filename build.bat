@echo off
rem =====================================================================
rem  build.bat  -  compile TlsFragProxy.exe with the C# compiler that ships
rem                with the .NET Framework (no Visual Studio needed)
rem
rem  This file is intentionally ASCII-only: non-ASCII bytes in a .bat get
rem  mis-parsed by cmd.exe once the code page changes mid-file.
rem =====================================================================
setlocal

set "ROOT=%~dp0"
set "SRC=%ROOT%src\TlsFragProxy.cs"
set "OUT=%ROOT%TlsFragProxy.exe"
set "ICON=%ROOT%assets\TlsFragProxy.ico"

set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" (
    echo [x] csc.exe not found. .NET Framework 4.x is required.
    echo     Expected at %%WINDIR%%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
    pause
    exit /b 1
)

if not exist "%SRC%" (
    echo [x] source not found: %SRC%
    pause
    exit /b 1
)

if not exist "%ICON%" (
    echo [x] icon not found: %ICON%
    pause
    exit /b 1
)

echo Compiler : %CSC%
echo Source   : %SRC%
echo Output   : %OUT%
echo.

"%CSC%" /nologo /target:winexe /platform:anycpu /optimize+ ^
    /r:System.dll /r:System.Core.dll ^
    /r:System.Windows.Forms.dll /r:System.Drawing.dll ^
    /win32icon:"%ICON%" /out:"%OUT%" "%SRC%"

if errorlevel 1 (
    echo.
    echo [x] build failed.
    pause
    exit /b 1
)

echo.
for %%F in ("%OUT%") do echo [ok] built  %%~nxF  (%%~zF bytes)
echo.
echo Run it:  TlsFragProxy.exe
echo Options: --delay 800  --port 8899  --no-proxy  --reset-policy
echo.
pause
endlocal
