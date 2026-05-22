@echo off
setlocal

:: Build ual-timeliner.exe with PyInstaller in a local venv (.venv).
:: Creates the venv if missing, installs requirements + pyinstaller, then builds.
:: Output: dist\ual-timeliner.exe

cd /d "%~dp0"

set VENV_DIR=.venv
set VENV_PY=%VENV_DIR%\Scripts\python.exe

if not exist "%VENV_PY%" (
    echo Creating venv at %VENV_DIR%...
    where py >nul 2>&1
    if errorlevel 1 (
        python -m venv "%VENV_DIR%" || goto :fail
    ) else (
        py -3 -m venv "%VENV_DIR%" || goto :fail
    )
)

echo Upgrading pip...
"%VENV_PY%" -m pip install --upgrade pip >nul || goto :fail

echo Installing requirements...
"%VENV_PY%" -m pip install -r requirements.txt || goto :fail

echo Ensuring pyinstaller is installed...
"%VENV_PY%" -m pip install pyinstaller || goto :fail

if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist ual-timeliner.spec del /q ual-timeliner.spec

echo Generating version_info.txt from __version__...
"%VENV_PY%" _make_version_info.py version_info.txt || goto :fail

"%VENV_PY%" -m PyInstaller --onefile --name ual-timeliner ^
    --version-file version_info.txt ^
    --collect-all polars ^
    --collect-all libesedb ^
    --collect-all openpyxl ^
    ual_timeliner.py || goto :fail

echo.
echo Built: dist\ual-timeliner.exe
exit /b 0

:fail
echo.
echo Build failed.
exit /b 1
