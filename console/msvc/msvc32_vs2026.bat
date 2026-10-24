@echo off

:: Set the C/C++ env for VS 2026 for 32-bit x86 builds for legacy systems
:: 10/24/2026: The default build in msvc.bat is now 64-bit x64.
call  "C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvars32.bat"

