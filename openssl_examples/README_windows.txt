Collection of OpenSSL example programs used to testing and
development.

OpenSSL online documentation:

https://wiki.openssl.org/index.php/Main_Page

To compile C example programs using Visual Studio 2026:

Open a command prompt and at the command line setup the following
Visual Studio environment: 

> "C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvars64.bat"

To compile a program:

> cl -Ie:\3plibs\openssl64\include simple1.c /link e:\3plibs\openssl64\lib\libcrypto.lib e:\3plibs\openssl64\lib\libssl.lib advapi32.lib user32.lib crypt32.lib wsock32.lib

Where "e:\3plibs\openssl64\lib" is the path to your 64-bit openssl
build for Windows. 64-bit x64 is the default build. For 32-bit x86
legacy builds use vcvars32.bat and your 32-bit openssl build, for
example e:\3plibs\openssl32. Use only OpenSSL 3.5.x LTS builds, see
..\README_windows_openssl.txt.

For Windows smartcard testing you will need to download the OpenSC
pkcs11 driver from: 

https://github.com/OpenSC/OpenSC

Once installed the driver path is:

"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"

fcrypt does not use the pkcs11 engine. Builds with OpenSSL 3, which
includes all Windows builds using OpenSSL 3.5.x LTS, load the OpenSC
PKCS#11 module directly, see SMART CARD REQUIREMENTS AND OPENSSL 3 in
..\README.txt.

The smartcard_encrypt.cpp and smartcard_read_public_key.cpp examples in
this directory use the OpenSSL ENGINE API. They need an OpenSSL build
with engine support and the libp11 pkcs11 engine:

https://github.com/OpenSC/libp11

The OpenSSL 3.5.x LTS builds used for fcrypt do not need libp11.
