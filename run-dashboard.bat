@echo off
rem DOUBLEBLIND dashboard -- double-click this file to start it.
rem
rem The dashboard is a process on this machine, not a website. It is reachable
rem at 127.0.0.1:8800 only for as long as this window stays open. Closing this
rem window stops it, which is why it died when the editor that launched it was
rem closed.
rem
rem Deliberately bound to 127.0.0.1: the API has endpoints that edit the audit
rem log on disk and restart the stack, and there is no authentication on it.
rem Do not serve it to a venue network. Share your screen instead.

setlocal
cd /d "%~dp0"

title DOUBLEBLIND dashboard -- keep this window open

echo ======================================================================
echo   DOUBLEBLIND dashboard
echo ======================================================================
echo.

call :find_python
if not defined PY goto :no_python

echo   Python   : %PY%
echo   Folder   : %CD%
echo   Address  : http://127.0.0.1:8800
echo.
echo   Your browser will open in a few seconds.
echo.
echo   KEEP THIS WINDOW OPEN while you are demonstrating.
echo   Press Ctrl+C, or close this window, to stop the dashboard.
echo.
echo ----------------------------------------------------------------------
echo.

rem Opened from a short-lived background window, so the page is requested
rem after the server is actually listening rather than before.
start "" /min cmd /c "timeout /t 3 >nul & start http://127.0.0.1:8800"

%PY% -m doubleblind.api

echo.
echo   The dashboard has stopped.
echo.
pause
exit /b 0

:find_python
set "PY="
py -3.12 --version >nul 2>&1
if %errorlevel%==0 (
  set "PY=py -3.12"
  goto :eof
)
py -3 -c "import sys; sys.exit(0 if sys.version_info[:2]>=(3,12) else 1)" >nul 2>&1
if %errorlevel%==0 (
  set "PY=py -3"
  goto :eof
)
python -c "import sys; sys.exit(0 if sys.version_info[:2]>=(3,12) else 1)" >nul 2>&1
if %errorlevel%==0 (
  set "PY=python"
  goto :eof
)
goto :eof

:no_python
echo   Python 3.12 or newer was not found on this machine.
echo.
echo   DOUBLEBLIND needs 3.12 and has no other dependencies.
echo   Install it from https://www.python.org/downloads/ , tick
echo   "Add python.exe to PATH" during setup, then run this file again.
echo.
pause
exit /b 1
