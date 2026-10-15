@echo off
REM Builds a standalone Windows executable: dist\G5_AI_SIEM.exe
REM Run this once on a Windows PC with Python 3.9+ installed.
cd /d "%~dp0"
python -m pip install --quiet -r requirements.txt pyinstaller
python -m PyInstaller --noconfirm --onefile --name G5_AI_SIEM ^
  --add-data "siem_prototype.py;." ^
  --add-data "make_figures.py;." ^
  --collect-submodules sklearn ^
  main.py
echo.
echo Built: dist\G5_AI_SIEM.exe  (double-click it; results appear in a "results" folder next to it)
pause
