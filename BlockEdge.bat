@echo off
setlocal
setlocal enabledelayedexpansion
TAKEOWN /F "%WinDir%\WinSxS\*amd64_microsoft-windows-m..osoftedge.appxsetup*" /a /r /d y
FOR /d /r "%WinDir%\WinSxS\" %%d IN (*amd64_microsoft-windows-m..osoftedge.appxsetup*) DO @IF EXIST "%%d" copy C:\Windows\Modules\Updates\AppxBlockMap.xml "%%d" >nul
FOR /d /r "%WinDir%\WinSxS\" %%d IN (*amd64_microsoft-windows-m..osoftedge.appxsetup*) DO @IF EXIST "%%d" copy C:\Windows\Modules\Updates\AppxManifest.xml "%%d" >nul
endlocal
exit