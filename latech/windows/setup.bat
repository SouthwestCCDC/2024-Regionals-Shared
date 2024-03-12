@echo off
setlocal enabledelayedexpansion

rem Define the .NET SDK version
set DOTNET_VERSION=7.0

rem Define the download URL
set DOTNET_URL=https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/sdk-7.0.402-windows-x64-installer

rem Define the installation directory
set INSTALL_DIR=%SystemDrive%\dotnet

echo Installing .NET SDK %DOTNET_VERSION%...

rem Create a temporary directory for downloading the installer
set TEMP_DIR=%TEMP%\dotnet_installer
if not exist "%TEMP_DIR%" mkdir "%TEMP_DIR%"

rem Download the .NET SDK installer
echo Downloading .NET SDK installer...
curl -o "%TEMP_DIR%\dotnet-sdk-installer.exe" %DOTNET_URL%
if %errorlevel% neq 0 (
    echo Failed to download .NET SDK installer. Please check your internet connection.
    exit /b 1
)

rem Install .NET SDK
echo Installing .NET SDK...
"%TEMP_DIR%\dotnet-sdk-installer.exe" /install /quiet /norestart

if %errorlevel% neq 0 (
    echo Failed to install .NET SDK.
    exit /b 1
)

rem Check the installation
dotnet --version

rem Clean up
echo Cleaning up...
rmdir /s /q "%TEMP_DIR%"

echo .NET SDK %DOTNET_VERSION% has been successfully installed.

rem Define the path to WindowsHard
set PS_SCRIPT_PATH=%USERPROFILE%\Downloads\WindowsHard.ps1

rem Run WindowsHard
echo Running PowerShell script...
powershell -ExecutionPolicy Bypass -File "%PS_SCRIPT_PATH%"

endlocal

