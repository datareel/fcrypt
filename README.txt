File encryption and decryption utility

Release 2026.101

Supports Window 10, Windows 11, and Windows 2025 server
Supports Red Hat Enterprise Linux 6, 7, 8, 9, and 10 

Built with the DataReel C++ library version 6.0, included under the
3plibs/datareel directory.

This source code is used to build the fcrypt and fdecrypt utilities
that are used to encrypt existing files using the AES CBC 256 bit
encryption algorithm based on the OpenSSL implementation.

In the distribution example programs used for OpenSSL development and
testing are under the following directory: 

openssl_examples

Example programs for the AES encryption routines are under the
following directory: 

aesdb_examples

The fcrypt and fdecrypt programs provide a comprehensive symmetric
encryption tool kit for encrypting and decrypting files.

FEATURES:

	AES 256 bit symmetric file encryption
	File encryption using a password or key file
	Multi user access to encrypted files using RSA keys
	Multi user access to encrypted files using a smart card
	Supports DOD CAC smart cards
	
SECURITY UPDATE IN RELEASE 2025.105
-----------------------------------
Release 2025.105 fixes security problems found in a code review. All
users should upgrade. The file format is unchanged: files encrypted by
older releases decrypt with this release, and files encrypted by this
release decrypt with older releases.

* fdecrypt no longer accepts forged files. Older releases accepted a
  specially made file under any password.

* Restored file paths. Without --outfile, fdecrypt restores the path
  stored in the encrypted file relative to the current directory or
  --outdir. Leading /, drive letters and UNC prefixes are removed, and
  stored paths with .. are rejected. To restore the exact stored path,
  for example a full restore from a backup, use --absolute-path. To
  restore only the file name use --no-path.

  Example: a file encrypted as /home/user/docs/report.txt is restored to
  ./home/user/docs/report.txt by default, to /home/user/docs/report.txt
  with --absolute-path, and to ./report.txt with --no-path.

* fdecrypt does not overwrite existing files unless -o is given.

* Decrypted files are created readable only by their owner, and are
  written to a temp file that is renamed only after the whole file
  decrypts and passes its integrity checks. Nothing is left behind if a
  file fails to decrypt.

* Files encrypted with this release carry a whole-file integrity check,
  so removed, reordered, added or truncated data blocks are detected.
  Files from older releases are still checked block by block.

* Files encrypted with mode 0 (no encryption, for testing) need the
  fdecrypt --allow-unencrypted switch.

* fcrypt --iter must be at least 1000.

* Memory safety fixes for long file names, RSA user data stored in the
  encrypted file, console input and key file reads.

Run console/linux/run_security_tests.sh and run_compat_tests.sh to test
a build.

TO BUILD THE FCRYPT AND FDECRYPT PROGRAMS FOR WINDOWS
-----------------------------------------------------
For Windows the current release supports Microsoft Visual Studio 2022 or 2026. 

For instructions on how to install Microsoft Visual Studio 2022 please
see the following readme file: README_VisualStudio_2022.txt 

For instructions on how to install Microsoft Visual Studio 2026 please
see the following readme file: README_VisualStudio.txt 

The Windows build requires the OpenSSL library. 

For instructions on how to build OpenSSL for Windows please see the
following readme file: README_windows_openssl.txt 

For instructions on how to build Windows 11 or 2025 server development
VM please see the following readme file: README_windows_setup.txt 

To build the Windows executables download the latest release or clone
the GIT repo. In the Windows build example below this document will
assume we placed the code on a data drive in a git directory.  

On the data drive change your directory to the fcrypt build subdirectory:  
> E:
> cd E:\git\fcrypt\console\msvc

Setup your Visual Studio environment for a 64-bit x64 build, which is
the default:

> msvc.bat

For a 32-bit x86 build for legacy systems use msvc32_vs2026.bat
instead of msvc.bat. Use a new command prompt and run "nmake clean"
when you switch between 32-bit and 64-bit builds. Files encrypted by
the 32-bit and 64-bit builds use the same file format, so either build
decrypts files from the other and from older releases.

Edit the msvc.env file to setup the path to your OpenSSL and ZLIB
builds. The 64-bit paths are used by default and the 32-bit paths are
used when the ENV is set with msvc32_vs2026.bat:

> notepad msvc.env

!IF "$(VSCMD_ARG_TGT_ARCH)" == "x86"
# Setup path to ZLIB
ZCODE_DIR = ../../../../3plibs/zlib32-1.3.1

# Setup path to OPENSSL library
OPENSSL_DIR = ../../../../3plibs/openssl32
!ELSE
# Setup path to ZLIB
ZCODE_DIR = ../../../../3plibs/zlib64-1.3.1

# Setup path to OPENSSL library
OPENSSL_DIR = ../../../../3plibs/openssl64
!ENDIF

Run nmake to build the executables:

> nmake

To run a simple test of the utilities:

> fcrypt.exe testfile.txt

The above command will encrypt the input file and create a .enc file
with the same file name. 

To decrypt the file:

> fdecrypt.exe testfile.enc 

This will decrypt the file creating the unencrypted file using the
original file name.  


TO BUILD THE FCRYPT AND FDECRYPT PROGRAMS FOR LINUX
---------------------------------------------------
$ mkdir -pv ${HOME}/git
$ cd ${HOME}/git
$ git clone https://github.com/datareel/fcrypt.git
$ cd fcrypt/console/linux
$ make

To run a simple test of the utilities:

$ ./fcrypt testfile.txt

The above command will encrypt the input file and create a .enc file with the same file name.

To decrypt the file:

$ ./fdecrypt testfile.enc 

This will decrypt the file creating the unencrypted file using the original file name. 
If the file was encrypted with a directory path, the path is recreated
under the current directory. Use -o to overwrite an existing file.

USING A MASTER KEY FOR AES SYMMETRIC FILE ENCRYPTION
----------------------------------------------------
Create a master file encryption key:

$ dd if=/dev/urandom of=master.key bs=1 count=128
$ chmod 600 master.key

Encrypt the file:

> ./fcrypt --key=master.key testfile.txt

Decrypt the file:

> ./fdecrypt --key=master.key testfile.enc

USING RSA KEYS FOR MULTI USER ACCESS TO THE ENCRYPTED FILE
----------------------------------------------------------
Use openssl to make some test keys:

> mkdir ${HOME}/.keys
> chmod 700 ${HOME}/.keys
> openssl genrsa -aes256 -out ${HOME}/.keys/private.pem 2048
> chmod 600 ${HOME}/.keys/private.pem
> openssl rsa -in ${HOME}/.keys/private.pem -outform PEM -pubout -out ${HOME}/.keys/public.pem

Create a master file encryption key:

> dd if=/dev/urandom of=${HOME}/.keys/master.key bs=1 count=128
> chmod 600 ${HOME}/.keys/master.key

Encrypt a file:

> ./fcrypt --key=${HOME}/.keys/master.key testfile.txt

Add your RSA key:

> ./fcrypt --key=${HOME}/.keys/master.key --add-rsa-key=${HOME}/.keys/public.pem --rsa-key-username=testuser testfile.enc

Decrypt the file using your private key that is passphrase protected
and ensure you private key is never shared with anyone:

> ./fdecrypt --rsa-key=${HOME}/.keys/private.pem --rsa-key-username=testuser testfile.enc

USING SSH-RSA FOR MULTI USER ACCESS TO THE ENCRYPTED FILE
---------------------------------------------------------
Create a temp key to encrypt the file

> mkdir ${HOME}/.keys
> chmod 700 ${HOME}/.keys
> dd if=/dev/urandom of=${HOME}/.keys/temp.key bs=1 count=128
> chmod 600 ${HOME}/.keys/temp.key

Encrypt a file:

> ./fcrypt --key=${HOME}/.keys/temp.key testfile.txt

Add your SSH-RSA key to the encrypted file:

> ssh-keygen -f ~/.ssh/id_rsa.pub -m 'PKCS8' -e | ./fcrypt --key=${HOME}/.keys/temp.key --add-rsa-key --rsa-key-username=testuser testfile.enc

Decrypt the file using your SSH-RSA private key:

> ./fdecrypt --rsa-key=${HOME}/.ssh/id_rsa --rsa-key-username=testuser testfile.enc

Have your users that need access to the encrypted file give you a copy
of their public ~/.ssh/id_rsa.pub SSH-RSA key.

Once you have a copy of all the public RSA keys that need access to the
encrypted file add each key. After all the user are added you can remove
the file encrytion key:

> rm -fv ${HOME}/.keys/temp.key


All users will only be able to decrypt the file using their SSH-RSA
private key. All user should ensure their private key is passphrase
protected and never shared with anyone.  

For users that do not have passphrase protected keys a passphrase can be
added with the following command:

> ssh-keygen -p -f ~/.ssh/id_rsa

USING A SMART CARD FOR MULTI USER ACCESS TO THE ENCRYPTED FILE
--------------------------------------------------------------
Create a temp key to encrypt the file

> mkdir ${HOME}/.keys
> chmod 700 ${HOME}/.keys
> dd if=/dev/urandom of=${HOME}/.keys/temp.key bs=1 count=128
> chmod 600 ${HOME}/.keys/temp.key

Encrypt a file:

> ./fcrypt --key=${HOME}/.keys/temp.key testfile.txt

Make sure your smart card is in the card reader and you know the ID
number for the cert you are using. You can list the smart card objects
with the 'pkcs11-tool --list-objects' command. 

Add your smart card cert to the encrypted file:

> ./fcrypt --key=${HOME}/.keys/temp.key --add-smartcard-cert --smartcard-cert-id=01 --smartcard-username=testuser testfile.enc

Decrypt the file using your smart card:

> ./fdecrypt --smartcard-cert --smartcard-cert-id=01 --smartcard-username=testuser testfile.enc

You will be prompted to enter your smart card pin.

Have your users that need access to the encrypted file add their smart
card cert. 

Once you have all the users added that need access to the encrypt file
add each key. After all the user are added you can remove 
the file encryption key:

> rm -fv ${HOME}/.keys/temp.key

All users will only be able to decrypt the file using their smart
card.

USING A SMART CARD EXPORTED CERT file FOR MULTI USER ACCESS TO THE ENCRYPTED FILE
---------------------------------------------------------------------------------
Create a temp key to encrypt the file

> mkdir ${HOME}/.keys
> chmod 700 ${HOME}/.keys
> dd if=/dev/urandom of=${HOME}/.keys/temp.key bs=1 count=128
> chmod 600 ${HOME}/.keys/temp.key

Encrypt a file:

> ./fcrypt --key=${HOME}/.keys/temp.key testfile.txt

For all users that need access each user will need to use the p11tool
to export a PEM formated X509 cert that contains the public key. 

Add your cert file to the encrypted file:

> ./fcrypt --key=${HOME}/.keys/temp.key --add-smartcard-cert-file=/usr/local/sc_certs/testuser_cert.pem  --smartcard-username=testuser testfile.enc

Decrypt the file using your smart card:

> ./fdecrypt --smartcard-cert --smartcard-cert-id=01 --smartcard-username=testuser testfile.enc

You will be prompted to enter your smart card pin.

Add all your users that need access to the encrypted file.

Once you have all the users added that need access to the encrypt file
add each key. After all the user are added you can remove 
the file encryption key:

> rm -fv ${HOME}/.keys/temp.key

All users will only be able to decrypt the file using their smart
card.
