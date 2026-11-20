@echo off
rem DOUBLEBLIND demonstration -- double-click this file to run the seven acts.
rem
rem This one runs and exits; it leaves nothing listening. It starts real
rem gateway and model processes on free ports, runs the acts, and stops them.
rem Takes about twenty seconds.

setlocal
cd /d "%~dp0"

title DOUBLEBLIND demonstration

echo ======================================================================
echo   DOUBLEBLIND -- seven acts, about twenty seconds
echo ======================================================================
echo.

call :find_python
if not defined PY goto :no_python

%PY% scripts\demo.py
set "RC=%errorlevel%"

echo.
echo ----------------------------------------------------------------------
if "%RC%"=="0" (
  echo   All acts passed. Artefacts are in the artifacts\ folder.
) else (
  echo   An act FAILED -- exit code %RC%. Scroll up: the act that failed
  echo   printed its claim and what it saw instead.
)
echo ----------------------------------------------------------------------
echo.
pause
exit /b %RC%

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
