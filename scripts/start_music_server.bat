@echo off
REM start_music_server.bat - Start the BDFFHD music conversion server (Windows)
REM
REM This server handles MP3/WAV/OGG/FLAC -> HCA conversion for the
REM BDFFHD mod web UI. The browser uploads files directly to this server
REM on port 8889, bypassing Wine's HttpListener limitations with large files.
REM
REM Requirements:
REM   - Python 3.10+
REM   - ffmpeg (in PATH)
REM   - PyCriCodecs (pip install PyCriCodecs)
REM
REM Usage:
REM   scripts\start_music_server.bat

setlocal

set "SCRIPT_DIR=%~dp0"
set "PROJECT_DIR=%SCRIPT_DIR%.."

REM Check for Python
where python >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found in PATH.
    echo Install Python 3.10+ from https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Check for ffmpeg
where ffmpeg >nul 2>&1
if errorlevel 1 (
    echo WARNING: ffmpeg not found in PATH.
    echo Audio conversion will fail without ffmpeg.
    echo Download from https://ffmpeg.org/download.html
    echo.
)

REM Check for PyCriCodecs
python -c "import PyCriCodecs" >nul 2>&1
if errorlevel 1 (
    echo PyCriCodecs not found. Installing...
    pip install PyCriCodecs
    if errorlevel 1 (
        echo ERROR: Failed to install PyCriCodecs.
        pause
        exit /b 1
    )
)

echo Starting BDFFHD Music Conversion Server...
echo Press Ctrl+C to stop.
echo.

cd /d "%PROJECT_DIR%"
python scripts\music_server.py

pause
