@echo off
setlocal
cd /d "%~dp0"

echo.
echo === TITAN IOC Converter (Generic) - build EXE ===
echo This machine needs Python 3.10+ (64-bit). Run once, then share the EXE.
echo.

where python >nul 2>&1
if errorlevel 1 (
  where py >nul 2>&1
  if errorlevel 1 (
    echo Python was not found. Install Python 3 from https://www.python.org/downloads/
    echo Check "Add python.exe to PATH" during setup.
    pause
    exit /b 1
  )
  set PY=py
) else (
  set PY=python
)

echo Installing dependencies...
%PY% -m pip install --upgrade pip
%PY% -m pip install -r requirements.txt
if errorlevel 1 (
  echo pip install failed.
  pause
  exit /b 1
)

echo.
echo Building TitanIOCConverter_Generic.exe ...
%PY% -m PyInstaller --noconfirm --clean --onefile --windowed --name TitanIOCConverter_Generic --hidden-import openpyxl --hidden-import pyxlsb --hidden-import converter app.py

if not exist "dist\TitanIOCConverter_Generic.exe" (
  echo Build failed. See the log above.
  pause
  exit /b 1
)

echo.
echo OK. EXE is here:
echo   %cd%\dist\TitanIOCConverter_Generic.exe
echo.
echo Copy TitanIOCConverter_Generic.exe to a shared folder. Generated import
echo files are written next to the EXE.
echo.
pause
