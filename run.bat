@echo off
REM HIDENTIFY launcher for Windows
REM Run this from an Administrator Command Prompt / PowerShell.
REM Requires Npcap (https://npcap.com/) installed with "WinPcap API-compatible mode".

if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)

call venv\Scripts\activate.bat
pip install -q -r requirements.txt

echo Launching HIDENTIFY...
python app.py
