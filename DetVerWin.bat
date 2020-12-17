@echo off

REM KB106203 means we have to check NT 3.10 first!
echo A|find "B"
if errorlevel 1 goto notNT310
ver | findstr " 3.10" > nul
if not errorlevel 1 echo.Windows NT 3.10
goto finosdet
:notNT310
REM Does not try to detect DOS!
ver|find "DOS " > nul
if not errorlevel 1 goto nodos
ver|find " 3.50" > nul
if not errorlevel 1 echo.Windows NT 3.50
ver|find " 3.51" > nul
if not errorlevel 1 echo.Windows NT 3.51
ver | find " 4.00.95" > nul
if not errorlevel 1 echo.Windows 95
ver | find " 4.00.111" > nul
if not errorlevel 1 echo.Windows 95 OSR2
ver | find " 4.03." > nul
if not errorlevel 1 echo.Windows 95 OSR2.x
ver | find " 4.10.1" > nul
if not errorlevel 1 echo.Windows 98
ver | find " 4.10.2" > nul
if not errorlevel 1 echo.Windows 98 SE
ver | find " 4.90" > nul
if not errorlevel 1 echo.Windows ME
ver | find " NT " > nul
if errorlevel 1 goto notNT4
ver | find " 4.0" > nul
if not errorlevel 1 echo.Windows NT 4
:notNT4
ver | find " 5.0" > nul
if not errorlevel 1 echo.Windows 2000
ver | find " 5.1." > nul
if not errorlevel 1 echo.Windows XP
REM TODO: XP x64 is also 2003
ver | find " 5.2." > nul
if not errorlevel 1 echo.Windows 2003
ver|find " 6.0." > nul
if not errorlevel 1 echo.Windows Vista / Server 2008
ver|find " 6.1.7" > nul
if not errorlevel 1 echo.Windows 7 / Server 2008 R2
ver|find " 6.1.8" > nul
if not errorlevel 1 echo.Windows Home Server 2011
ver|find " 6.2" > nul
if not errorlevel 1 echo.Windows 8.0 / Server 2012
ver|find " 6.3" > nul
if not errorlevel 1 echo.Windows 8.1 / Server 2012 R2
ver|find " 10." > nul
if not errorlevel 1 echo.Windows 10
ver | find " (" > nul
if not errorlevel 1 echo.Wine
ver | find "ReactOS" > nul
if not errorlevel 1 echo.ReactOS
:finosdet

REM %~0 is not 95/98/ME compatible
if not exist "%~0\..\DetVerWin.exe" goto noexe
echo.Do you want to run the .exe? Press Enter to continue or Ctrl+C to abort...
pause > nul
"%~0\..\DetVerWin.exe"
:noexe
goto end

:nodos
echo.Unknown OS!
goto end

:end
REM EOF
