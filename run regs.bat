@Echo off 
Title Reg Updater
setlocal EnableDelayedExpansion

regedit.exe /s C:\Windows\Modules\Updates\HKCU.Reg
regedit.exe /s C:\Windows\Modules\Updates\HKCR.reg
C:\PostInstall\Tweaks\Nsudo.exe -U:T -P:E regedit.exe /s C:\Windows\Modules\Updates\HKLM.reg
del %0