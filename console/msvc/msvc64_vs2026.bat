@echo off

:: Set the C/C++ env for VS 2026 for 64-bit x64 builds (the default)
:: 10/24/2026: Was vcvarsamd64_x86.bat, which runs the 64-bit hosted
:: compiler but builds 32-bit x86 programs.
call  "C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvars64.bat"

