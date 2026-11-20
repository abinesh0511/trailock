@echo off
title Trailock server
cd /d "%~dp0"
where python >nul 2>nul || (echo Python is not installed. Download it from https://www.python.org/downloads/ and tick "Add python.exe to PATH". & pause & exit /b 1)
if not exist .venv (
  echo Creating virtual environment...
  python -m venv .venv
)
call .venv\Scripts\activate.bat
echo Installing requirements...
pip install -q -r requirements.txt
echo.
echo  ==================================================
echo    Trailock is running:  http://localhost:8000
echo    Keep this window open. Verification codes and
echo    security alerts will appear here.
echo    Press Ctrl+C to stop.
echo  ==================================================
echo.
start "" http://localhost:8000
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
pause
