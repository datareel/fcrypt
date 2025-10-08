@echo off

REM Set the path to your OpenSSL build for Windows below
SET OPENSSLdir=e:\3plibs\openssl32

if "%1"=="" (
    echo ERROR: Enter the file name of the program to build
    exit /b 1
)

cl -I%OPENSSLdir%\include %1 /link %OPENSSLdir%\lib\libcrypto.lib %OPENSSLdir%\lib\libssl.lib advapi32.lib user32.lib crypt32.lib wsock32.lib

