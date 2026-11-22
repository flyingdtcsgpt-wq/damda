@echo off
rem Damda launcher for Windows. Downloads Node.js into this folder if missing.
cd /d "%~dp0"
set "NODE=node"
where node >nul 2>nul
if errorlevel 1 (
  if not exist "runtime\node.exe" (
    echo Downloading Node.js, first run only...
    powershell -NoProfile -Command "$ProgressPreference='SilentlyContinue'; New-Item -ItemType Directory -Force runtime | Out-Null; Invoke-WebRequest 'https://nodejs.org/dist/v22.12.0/win-x64/node.exe' -OutFile 'runtime\node.exe'"
  )
  set "NODE=runtime\node.exe"
)
if not exist "%NODE%" if not "%NODE%"=="node" ( echo Download failed. Check your internet connection. & pause & exit /b 1 )
set "DATA_DIR=%~dp0data"
start "" http://localhost:8787
"%NODE%" server\server.js
pause
