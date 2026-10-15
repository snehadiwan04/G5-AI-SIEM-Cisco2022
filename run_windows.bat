@echo off
REM G5 AI-SIEM prototype - one-click run on Windows
REM Needs Python 3.9+ installed (tick "Add Python to PATH" during install).
cd /d "%~dp0"
echo Installing required Python packages (first run only)...
python -m pip install --quiet -r requirements.txt
if errorlevel 1 (
  echo.
  echo Could not install packages. Check that Python 3.9+ is installed and on PATH.
  pause
  exit /b 1
)
python main.py %*
pause
