@echo off
REM Builds the HIDENTIFY desktop app into dist\HIDENTIFY\ using PyInstaller.
REM Run from a regular (non-admin) Command Prompt - admin is only needed later, to RUN it.

if not exist venv (
    python -m venv venv
)
call venv\Scripts\activate.bat
pip install -q -r requirements.txt

echo Building HIDENTIFY desktop executable...
pyinstaller --noconfirm build.spec

echo.
echo Build complete.
echo Executable: dist\HIDENTIFY\HIDENTIFY.exe
echo Right-click it and choose "Run as administrator" for packet capture to work.
