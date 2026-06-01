@echo off
setlocal
cd /d "%~dp0"

set "PYTHON_EXE=C:\Users\admin\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"

if not exist "%PYTHON_EXE%" (
  echo Bundled Python was not found at:
  echo %PYTHON_EXE%
  echo.
  echo Install Python or update PYTHON_EXE inside start_web_server.bat.
  pause
  exit /b 1
)

echo Initializing database and admin account...
"%PYTHON_EXE%" scripts\seed_admin.py
if errorlevel 1 (
  echo Database initialization failed.
  pause
  exit /b 1
)

if not exist "ml\random_forest_ids.joblib" (
  echo Training Random Forest IDS model...
  "%PYTHON_EXE%" ml\train_model.py
  if errorlevel 1 (
    echo Model training failed.
    pause
    exit /b 1
  )
)

echo.
echo Flask SIEM IDS server is starting.
echo Open http://127.0.0.1:5000/login in your browser.
echo Keep this window open while using the site.
echo.
"%PYTHON_EXE%" run.py

echo.
echo Server stopped.
pause
