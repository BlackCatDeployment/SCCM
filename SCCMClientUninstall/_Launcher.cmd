@echo off
pushd "%~dp0"
setlocal

powershell.exe -NoLogo -NoProfile -ExecutionPolicy ByPass -File .\bin\Deploy.ps1 -File "%~dp0List.txt"

popd
endlocal
pause