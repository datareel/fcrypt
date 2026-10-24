@echo off

REM Set the path to your OpenSSL build for Windows below
REM 10/24/2026: The default is now the 64-bit x64 OpenSSL build. For
REM 32-bit legacy builds use e:\3plibs\openssl32 with vcvars32.bat.
REM Use only OpenSSL 3.5.x LTS builds, see ..\README_windows_openssl.txt
SET OPENSSLdir=e:\3plibs\openssl64

if "%1"=="" (
    echo ERROR: Enter the file name of the program to build
    exit /b 1
)

cl -I%OPENSSLdir%\include %1 /link %OPENSSLdir%\lib\libcrypto.lib %OPENSSLdir%\lib\libssl.lib advapi32.lib user32.lib crypt32.lib wsock32.lib

