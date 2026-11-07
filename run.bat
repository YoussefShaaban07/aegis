@echo off
REM Aegis one-click launcher for Windows. Needs Python 3.10+ from python.org ("py" launcher).
cd /d %~dp0
if not exist .venv (
  echo Creating virtual environment...
  py -3 -m venv .venv || (echo Python 3.10+ not found. Install it from python.org and tick "Add to PATH". & pause & exit /b 1)
)
call .venv\Scripts\activate.bat
python -m pip install -q -r requirements.txt
if not exist .env copy .env.example .env >nul
echo.
echo Aegis is starting: open http://127.0.0.1:8000   (Engineer PIN 2468)
echo Press Ctrl+C to stop.
start "" http://127.0.0.1:8000
python -m aegis.server
