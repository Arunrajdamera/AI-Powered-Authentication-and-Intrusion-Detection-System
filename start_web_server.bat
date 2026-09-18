@echo off
setlocal
cd /d "%~dp0"

echo Initializing database and admin account...
py scripts\seed_admin.py
if errorlevel 1 (
    echo Database initialization failed.
    pause
    exit /b 1
)

if not exist "ml\random_forest_ids.joblib" (
    echo Training Random Forest IDS model...
    py ml\train_model.py
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

py run.py

echo.
echo Server stopped.
pause
