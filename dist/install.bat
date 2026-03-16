@echo off
REM install.bat - BravelyMod installer for Windows
REM
REM Downloads MelonLoader, installs mod DLLs to BDFFHD game directory.
REM Run as Administrator if your game is in Program Files.
REM
REM Usage:
REM   install.bat
REM   install.bat "D:\Steam\steamapps\common\BDFFHD"

setlocal enabledelayedexpansion

echo.
echo ============================================
echo   BravelyMod v0.5.9 Installer (Windows)
echo ============================================
echo.

set "SCRIPT_DIR=%~dp0"
set "MELONLOADER_URL=https://github.com/LavaGang/MelonLoader/releases/latest/download/MelonLoader.x64.zip"

REM --- Determine game directory ---

if not "%~1"=="" (
    set "GAME_DIR=%~1"
    goto :validate_dir
)

REM Try common Steam paths
set "GAME_DIR="

if exist "C:\Program Files (x86)\Steam\steamapps\common\BDFFHD\BDFFHD.exe" (
    set "GAME_DIR=C:\Program Files (x86)\Steam\steamapps\common\BDFFHD"
    goto :found_dir
)

if exist "C:\Program Files\Steam\steamapps\common\BDFFHD\BDFFHD.exe" (
    set "GAME_DIR=C:\Program Files\Steam\steamapps\common\BDFFHD"
    goto :found_dir
)

if exist "D:\Steam\steamapps\common\BDFFHD\BDFFHD.exe" (
    set "GAME_DIR=D:\Steam\steamapps\common\BDFFHD"
    goto :found_dir
)

if exist "D:\SteamLibrary\steamapps\common\BDFFHD\BDFFHD.exe" (
    set "GAME_DIR=D:\SteamLibrary\steamapps\common\BDFFHD"
    goto :found_dir
)

if exist "E:\SteamLibrary\steamapps\common\BDFFHD\BDFFHD.exe" (
    set "GAME_DIR=E:\SteamLibrary\steamapps\common\BDFFHD"
    goto :found_dir
)

REM Not found automatically
echo Could not auto-detect BDFFHD installation.
echo.
echo Common locations:
echo   C:\Program Files (x86)\Steam\steamapps\common\BDFFHD\
echo   D:\SteamLibrary\steamapps\common\BDFFHD\
echo.
set /p "GAME_DIR=Enter your BDFFHD game directory: "

:validate_dir
if not exist "%GAME_DIR%" (
    echo ERROR: Directory not found: %GAME_DIR%
    goto :error_exit
)

:found_dir
echo [BravelyMod] Game directory: %GAME_DIR%
echo.

REM --- Step 1: MelonLoader ---

if exist "%GAME_DIR%\version.dll" (
    if exist "%GAME_DIR%\MelonLoader" (
        echo [BravelyMod] MelonLoader already installed. Skipping download.
        goto :install_mods
    )
)

echo [BravelyMod] Downloading MelonLoader...

set "ML_ZIP=%SCRIPT_DIR%MelonLoader.x64.zip"

REM Use PowerShell to download (available on all modern Windows)
powershell -Command "try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '%MELONLOADER_URL%' -OutFile '%ML_ZIP%' -UseBasicParsing } catch { Write-Error $_.Exception.Message; exit 1 }"

if not exist "%ML_ZIP%" (
    echo ERROR: Failed to download MelonLoader.
    echo Please download manually from:
    echo   https://github.com/LavaGang/MelonLoader/releases
    goto :error_exit
)

echo [BravelyMod] Extracting MelonLoader to game directory...

REM Use PowerShell to extract
powershell -Command "Expand-Archive -Path '%ML_ZIP%' -DestinationPath '%GAME_DIR%' -Force"

del /q "%ML_ZIP%" 2>nul

if exist "%GAME_DIR%\version.dll" (
    echo [BravelyMod] MelonLoader installed successfully.
) else (
    echo ERROR: MelonLoader extraction failed.
    goto :error_exit
)

:install_mods
REM --- Step 2: Install Mod DLLs ---

set "MODS_DIR=%GAME_DIR%\Mods"
if not exist "%MODS_DIR%" mkdir "%MODS_DIR%"

echo [BravelyMod] Installing mod files...

if exist "%SCRIPT_DIR%Mods\BravelyMod.dll" (
    copy /y "%SCRIPT_DIR%Mods\BravelyMod.dll" "%MODS_DIR%\BravelyMod.dll" >nul
    echo   Installed: BravelyMod.dll
) else (
    echo ERROR: Missing file: %SCRIPT_DIR%Mods\BravelyMod.dll
    goto :error_exit
)

if exist "%SCRIPT_DIR%Mods\YamlDotNet.dll" (
    copy /y "%SCRIPT_DIR%Mods\YamlDotNet.dll" "%MODS_DIR%\YamlDotNet.dll" >nul
    echo   Installed: YamlDotNet.dll
) else (
    echo ERROR: Missing file: %SCRIPT_DIR%Mods\YamlDotNet.dll
    goto :error_exit
)

REM --- Step 3: Create CustomBGM directory ---

set "STREAMING=%GAME_DIR%\BDFFHD_Data\StreamingAssets"
if exist "%STREAMING%" (
    if not exist "%STREAMING%\CustomBGM" mkdir "%STREAMING%\CustomBGM"
    echo [BravelyMod] CustomBGM directory created.
)

REM --- Done ---

echo.
echo ============================================
echo   Installation complete!
echo ============================================
echo.
echo First launch:
echo   1. Start BDFFHD from Steam
echo   2. MelonLoader will generate assemblies (takes a few minutes)
echo   3. Once loaded, open http://localhost:8888 for the config UI
echo.
echo To use custom music conversion, run:
echo   scripts\start_music_server.bat
echo.
pause
goto :eof

:error_exit
echo.
echo Installation failed. See errors above.
pause
exit /b 1
