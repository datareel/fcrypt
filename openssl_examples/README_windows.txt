Collection of OpenSSL example programs used to testing and
development.

OpenSSL online documentation:

https://wiki.openssl.org/index.php/Main_Page

To compile C example programs using Visual Studio 2026:

Open a command prompt and at the command line setup the following
Visual Studio environment: 

> "C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvars32.bat"

To compile a program:

> cl -Ie:\3plibs\openssl32\include simple1.c /link e:\3plibs\openssl32\lib\libcrypto.lib e:\3plibs\openssl32\lib\libssl.lib advapi32.lib user32.lib crypt32.lib wsock32.lib

Where "e:\3plibs\openssl32\lib" is the path to your openssl build
for Windows.

For Windows smartcard testing you will need to download the OpenSC
pkcs11 driver from: 

https://github.com/OpenSC/OpenSC

Once installed the driver path is:

"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"

For the pkcs11 engine module you will need to download the proveriders
package from: 

https://github.com/OpenSC/libp11

Add the pkcs11 providers DLL to your OpenSSL engines path.
