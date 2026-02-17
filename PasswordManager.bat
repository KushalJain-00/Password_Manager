@echo off
title 🔐 Secure Password Manager
color 0A

:: Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo ❌ Python is not installed or not in PATH!
    echo    Please install Python from https://python.org
    echo.
    pause
    exit
)

:: Check if cryptography library is installed
python -c "import cryptography" >nul 2>&1
if errorlevel 1 (
    echo.
    echo 📦 Installing required libraries...
    pip install cryptography
    echo.
)

:: Run the password manager
python password_manager.py

:: If program exits/crashes, show message
echo.
echo Press any key to close...
pause >nul
