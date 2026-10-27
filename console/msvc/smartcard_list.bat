@echo off
setlocal enabledelayedexpansion
rem Lists every reader slot, its token (label, manufacturer, model, PIN
rem flags) and the certs and keys on it (ID, label, RSA or EC), through
rem ActivClient and OpenSC. No login is made and no PIN is used.
rem Run at the computer or VM console, or in an RDP session with smart
rem card redirection turned off, with the cards inserted.
set AC=C:\Program Files\HID Global\ActivClient\acpkcs211.dll
set OSC=C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll
set TOOL=C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe
set LOG=%TEMP%\smartcard_list.log
echo Smart card listing %DATE% %TIME%, no login, no PIN used > "%LOG%"
for %%M in ("%AC%" "%OSC%") do (
  if exist %%M (
    echo. >> "%LOG%"
    echo ================ Module %%~M >> "%LOG%"
    call "%TOOL%" --module %%M --list-token-slots >> "%LOG%" 2>&1
    for /f "tokens=3" %%S in ('call "%TOOL%" --module %%M --list-token-slots 2^>nul ^| findstr /b /c:"Slot "') do (
      set SLOTID=%%S
      set SLOTID=!SLOTID:(=!
      set SLOTID=!SLOTID:^)=!
      set SLOTID=!SLOTID::=!
      echo. >> "%LOG%"
      echo ---- Objects in slot ID !SLOTID! ^(use --smartcard-slot=!SLOTID!^) >> "%LOG%"
      call "%TOOL%" --module %%M --slot !SLOTID! --list-objects >> "%LOG%" 2>&1
    )
  )
)
type "%LOG%"
echo.
echo Written to %LOG%. No PIN was used.
pause
