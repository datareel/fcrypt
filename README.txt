File encryption and decryption utility

Release 2026.105

Supports Window 10, Windows 11, and Windows 2025 server
Supports Red Hat Enterprise Linux 8, 9, and 10 (RHEL 10 is the default
Linux build). RHEL 6 and 7 are no longer supported.

Built with the DataReel C++ library version 6.1, included under the
3plibs/datareel directory.

This source code is used to build the fcrypt and fdecrypt utilities
that are used to encrypt existing files using the AES CBC 256 bit
encryption algorithm based on the OpenSSL implementation. Every
algorithm used for new files is FIPS 140-3 approved, and the programs
can run with only the OpenSSL FIPS provider.

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
	FIPS 140-3 mode using the OpenSSL FIPS provider
	File encryption using a password or key file
	Multi user access to encrypted files using RSA keys
	Multi user access to encrypted files using a smart card
	Supports DOD CAC smart cards
	
SMART CARD SAFEGUARDS IN RELEASE 2026.105
-----------------------------------------
Tested with a DoD CAC through ActivClient (Windows) and OpenSC (RHEL
10 and Windows), and with a YubiKey PIV key through OpenSC.

* PIN safeguards, so testing or a typing mistake does not lock a CAC
  or PIV card (they lock after 3 wrong PINs):
  - The PIN is sent to the card once per decrypt and never retried.
    After any failed card login no more logins are made until the
    program is run again, not for the next file and not by any
    fallback.
  - The PIN is not sent when it is empty, too long (it is no longer
    cut short), has a control character such as a tab or carriage
    return, or is outside the card's PIN length.
  - The card's PIN flags are read first. A locked PIN is refused.
    When the card reports one PIN try left or low PIN tries, the PIN
    is only sent with --smartcard-allow-final-try or
    --smartcard-allow-pin-count-low. Some modules, possibly
    ActivClient, do not report the PIN tries.
  - After a wrong PIN the error says one PIN try was used and what
    the card reports about the tries left.
* --smartcard-slot=N uses only the card in PKCS#11 slot N. With more
  than one card inserted (a CAC and a YubiKey both have ID 03 with
  OpenSC), a cert ID found on more than one card, or on no card, is
  refused and no PIN is sent. The error lists the slots.
* smartcard_list.sh (Linux) and smartcard_list.bat (Windows) list the
  readers, cards, PIN flags and every cert and key with its ID, label
  and type, without a PIN, so you can find the slot and the cert ID.
* The encrypted file format is unchanged.

SECURITY FIXES IN RELEASE 2026.104
----------------------------------
* fcrypt, fdecrypt and fmigrate refuse a --key file or a private
  --rsa-key file that is not a regular file owned by you with no group
  or other access, like ssh does for private keys. Run chmod 600 on
  the file.

* The * echo of password, passphrase and PIN prompts is written to
  stderr instead of stdout, so it is not mixed with program output.

* The bundled DataReel 6.1 library stops B-tree walks that would loop
  on a damaged or crafted index file, guards its data file scans
  against zero block lengths, and adds gxDatabase::SetWriteHook(). See
  3plibs/datareel/RELEASE_NOTES_6.1.txt.

* The PBKDF2, KBKDF and AES-256-CBC functions of the 2026102 file
  format are exported as FC_pbkdf2_sha256(), FC_kbkdf_sha256(),
  FC_aes256_cbc() and FC_rand_bytes() for other programs, such as the
  Encrypted Password Database.

* The encrypted file format is unchanged.

SECURITY FIXES IN RELEASE 2026.103
----------------------------------
* The bundled DataReel library is updated to version 6.1. DataReel 6.1
  checks the B-tree node key counts, B-tree header key size and node
  order, and the object member counts and lengths that it reads from
  database and index files. Damaged or crafted files are rejected
  instead of overflowing memory. See 3plibs/datareel/RELEASE_NOTES_6.1.txt.

* fcrypt, fdecrypt and fmigrate no longer loop forever at 100% CPU when
  a password, passphrase or PIN prompt reaches the end of its input,
  for example when stdin is /dev/null or a closed pipe in a script.
  Input that ends without a newline is used as typed, and empty input
  is an error.

* The encrypted file format is unchanged. Files made by 2026.102 and
  2026.103 are the same, and fdecrypt still decrypts files from every
  earlier release.

REMOVED RHEL 6 AND 7 SUPPORT
----------------------------
Release 2026.103:

* RHEL 6 and RHEL 7 builds are no longer supported. makefile_rhel6 and
  makefile_rhel7 are removed, along with the RHEL 6 and 7 cases in
  linux.env, smart_card.cpp and run_build_tests.sh. Both releases are
  past the end of Red Hat support and ship OpenSSL 1.0.x, which no
  longer gets security fixes.

* Supported Linux builds are RHEL 8, 9 and 10, with RHEL 10 the
  default.

* Backwards compatibility is unchanged: fdecrypt still decrypts files
  encrypted by every earlier fcrypt release, including files made on
  RHEL 6 and 7, and fmigrate still converts them to the 2026102 format.
  Copy such files to a RHEL 8, 9 or 10 host to decrypt them.

FIPS 140-3 MODE AND FILE FORMAT 2026102 IN RELEASE 2026.102
----------------------------------------------------------
Release 2026.102 adds FIPS 140-3 mode and a new encrypted file format,
version 2026102, that uses only FIPS approved algorithms:

	PBKDF2-HMAC-SHA256 (SP 800-132), 600000 iterations by default
	A random 256 bit key for each file
	AES-256 Key Wrap (SP 800-38F) for the password or key file
	RSA-OAEP with SHA-256 for RSA keys and smart cards, 2048 bit
	minimum
	KBKDF with HMAC-SHA256 (SP 800-108) for the file's working keys
	AES-256-CBC with HMAC-SHA256 on every 64 KB record
	(encrypt-then-MAC)

Every record and the header, including the list of users, is
authenticated, so changed, removed, reordered, added or truncated data
is detected before any output is kept.

Backwards compatibility:

* fdecrypt still decrypts files from every older release. No switches
  are needed outside FIPS mode.

* fcrypt writes only the 2026102 format. Older releases cannot decrypt
  these files, so upgrade fdecrypt everywhere the files are read.

* fcrypt --add-rsa-key and --add-smartcard-cert still work on files
  from older releases, outside FIPS mode.

* fdecrypt --iter applies only to files from older releases. New files
  store their iteration count.

FIPS mode is on when:

* --fips is given, or
* FCRYPT_FIPS=1 is set, or
* the system is in FIPS mode: /proc/sys/crypto/fips_enabled is 1 on
  Linux, the "System cryptography: Use FIPS compliant algorithms"
  policy is enabled on Windows, or the OpenSSL configuration sets
  fips=yes.

In FIPS mode every crypto operation uses only the OpenSSL FIPS
provider. If the FIPS provider cannot be loaded or fails its self-test,
the programs stop with an error. "fcrypt --version" shows the mode and
the provider in use.

In FIPS mode fdecrypt refuses files from older releases, because their
format uses algorithms that are not FIPS approved. To decrypt one, run
fdecrypt with --no-fips, which turns FIPS mode off for that run, even
on a system in FIPS mode:

$ ./fdecrypt --no-fips --password testfile.enc

To convert old files to the 2026102 format, use fmigrate. See
CONVERTING OLD FILES WITH FMIGRATE below.

In FIPS mode a private RSA key with a passphrase must be in PKCS#8
format, since the older PEM format derives its key with MD5. To convert
a key, including an SSH-RSA key:

$ openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -in ~/.ssh/id_rsa -out ~/.keys/id_rsa_pkcs8.pem
$ chmod 600 ~/.keys/id_rsa_pkcs8.pem

FIPS mode needs OpenSSL 3.0 or later with a FIPS provider:

* RHEL 9 and 10: enable FIPS mode with "fips-mode-setup --enable" and
  reboot. The system OpenSSL FIPS provider is used.

* RHEL 8: OpenSSL 1.1.1 has no FIPS provider. RHEL 8 builds refuse
  --fips, and run outside FIPS mode on a host in FIPS mode.

* Windows: build the OpenSSL 3.5.x LTS FIPS provider, see FIPS MODE ON
  WINDOWS in README_windows_openssl.txt.

For FIPS 140-3 compliance the FIPS provider version must have a CMVP
certificate. On Linux use the FIPS provider that comes with the OS. On
Windows use the FIPS provider from the OpenSSL 3.5.x LTS release used
for the build, and check the validated versions at
https://openssl-library.org/source/ before relying on FIPS mode for
compliance.

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

* fcrypt --iter must be at least 1000. (Release 2026.102: 1000 to
  10000000, default 600000.)

* Memory safety fixes for long file names, RSA user data stored in the
  encrypted file, console input and key file reads.

Run console/linux/run_security_tests.sh, run_compat_tests.sh and
run_migrate_tests.sh to test a build. Give run_compat_tests.sh and
run_migrate_tests.sh the console/linux directories of older release
builds. Set FCRYPT_FIPS=1 to run them in FIPS mode.

TO BUILD THE FCRYPT AND FDECRYPT PROGRAMS FOR WINDOWS
-----------------------------------------------------
For Windows the current release supports Microsoft Visual Studio 2022 or 2026. 

For instructions on how to install Microsoft Visual Studio 2022 please
see the following readme file: README_VisualStudio_2022.txt 

For instructions on how to install Microsoft Visual Studio 2026 please
see the following readme file: README_VisualStudio.txt 

The Windows build requires the OpenSSL library. Use only an OpenSSL
3.5.x LTS release, built as 64-bit x64 (and as 32-bit x86 only for
legacy builds). The build stops with an error for any other OpenSSL
version. FIPS mode also needs the OpenSSL 3.5.x FIPS provider,
fips.dll, see FIPS MODE ON WINDOWS in README_windows_openssl.txt.

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

nmake also builds fmigrate.exe, which converts files from older
releases to the 2026102 format. See CONVERTING OLD FILES WITH FMIGRATE.


TO BUILD THE FCRYPT AND FDECRYPT PROGRAMS FOR LINUX
---------------------------------------------------
$ mkdir -pv ${HOME}/git
$ cd ${HOME}/git
$ wget https://datareel.com/downloads/fcrypt/fcrypt-<version>.tar.gz
$ tar xzf fcrypt-<version>.tar.gz
$ mv fcrypt-<version> fcrypt
$ cd fcrypt/console/linux
$ make

The default Linux build is for RHEL 10 and uses the operating system's
OpenSSL (sudo dnf install gcc-c++ make openssl-devel). For an older
RHEL release use the makefile for that release:

$ make -f makefile_rhel9     (or makefile_rhel8)

RHEL 6 and 7 builds are no longer supported, see REMOVED RHEL 6 AND 7
SUPPORT below.

Run "make clean" first when you switch between RHEL builds.

To run a simple test of the utilities:

$ ./fcrypt testfile.txt

The above command will encrypt the input file and create a .enc file with the same file name.

To decrypt the file:

$ ./fdecrypt testfile.enc 

This will decrypt the file creating the unencrypted file using the original file name. 
If the file was encrypted with a directory path, the path is recreated
under the current directory. Use -o to overwrite an existing file.

The build also makes fmigrate, see CONVERTING OLD FILES WITH FMIGRATE.

CONVERTING OLD FILES WITH FMIGRATE
----------------------------------
fmigrate converts files encrypted by releases before 2026.102 to the
2026102 file format. Using it is optional: fdecrypt still decrypts old
files outside FIPS mode. Convert old files to use them in FIPS mode,
or to give them the stronger protection of the new format.

The old file is decrypted in memory and encrypted again as it is read,
so the plaintext is never written to disk. The new file is written to a
private temp file and decrypted again to check it against a SHA-256
hash of the data. Only then does it replace the old file. If anything
fails, the old file is left as it was.

The new file keeps the stored file name and opens with the same
password or key file as the old one.

To find old files:

$ ./fmigrate --check *.enc
$ ./fmigrate --check -R ${HOME}/encrypted_files

To convert files in place:

$ ./fmigrate --password testfile.enc
$ ./fmigrate --key=${HOME}/.keys/master.key -R ${HOME}/encrypted_files

To keep the old files and write the new files to another directory:

$ ./fmigrate --key=${HOME}/.keys/master.key --outdir=${HOME}/new_files testfile.enc

Files whose only access is an RSA key, for example after the temp key
was removed, can be converted with that key:

$ ./fmigrate --rsa-key=${HOME}/.ssh/id_rsa --rsa-key-username=testuser testfile.enc

The RSA user who converts the file keeps RSA access to the new file.
Other RSA and smart card users of the old file cannot be carried over,
because the old file holds only their encrypted copy of the key, not
their public key. fmigrate lists them. Add each one again with fcrypt
--add-rsa-key or --add-smartcard-cert, using the same password or key
file as the old file. Files converted with an RSA key keep the
password or key file the old file was encrypted with.

If the old files were encrypted with fcrypt --iter, give fmigrate the
same --iter. Use --new-iter to set the PBKDF2 iterations of the new
files, 600000 by default.

Reading the old format needs algorithms FIPS mode does not allow, so on
a system in FIPS mode run fmigrate with --no-fips. The new files can
then be decrypted in FIPS mode.

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

SMART CARD REQUIREMENTS AND OPENSSL 3
-------------------------------------
Builds that use OpenSSL 3, which includes RHEL 9, RHEL 10 and Windows,
load the smart card PKCS#11 module directly. The OpenSSL pkcs11 engine
(libp11 or the openssl-pkcs11 package) is not used or needed. The
OpenSSL ENGINE API is deprecated in OpenSSL 3 and is not built into
RHEL 10 or the OpenSSL 3.5.x LTS builds used for Windows. Builds that
use OpenSSL 1.x, such as RHEL 8, still use the pkcs11 engine.

Files given smart card access by earlier fcrypt releases still decrypt
with the same card. The smart card key data stored in the file has not
changed.

Linux, RHEL 9 and RHEL 10, using the operating system's OpenSSL:

> sudo dnf install opensc pcsc-lite
> sudo systemctl enable --now pcscd

The default PKCS#11 module is /usr/lib64/opensc-pkcs11.so. Use
--smartcard-provider to select a different PKCS#11 module.

Windows, using only an OpenSSL 3.5.x LTS build, see
README_windows_openssl.txt:

Install OpenSC from https://github.com/OpenSC/OpenSC/releases using
the 64-bit installer for the default 64-bit build (the 32-bit installer
is only for 32-bit legacy builds). The default PKCS#11 module is:

"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"

With OpenSSL 3 builds --smartcard-engine is accepted for older scripts
but is ignored.

The --smartcard-cert-id value can be the hex ID of the key and cert on
the card, such as 01, or any of these forms:

  id_01                Hex ID
  label_name           Object label
  4:01, slot_4-id_01   PKCS#11 slot ID and hex ID
  slot_4-label_name    PKCS#11 slot ID and object label
  "pkcs11:id=%01"      PKCS#11 URI with id= and/or object=

With more than one card or token inserted (for example a CAC and a
YubiKey, which both have ID 03 with OpenSC), select the card with
--smartcard-slot=N, the slot ID shown in parentheses by
pkcs11-tool --list-token-slots (decimal or 0x hex). Only that slot is
used. Without it, a cert ID found on more than one card, or on no card
when several are inserted, is refused and no PIN is sent.

List the objects on the card with:

> pkcs11-tool --list-objects

Cards that cannot do RSA-OAEP with SHA-256 themselves, such as PIV
cards, are supported by decrypting with raw RSA on the card and
removing the OAEP padding in fcrypt.

DOD CAC and PIV cards: OpenSC supports CAC and PIV cards. With OpenSC
the PIV Authentication key is ID 01, Digital Signature is ID 02 and
Key Management (encryption) is ID 03. Use the encryption key, ID 03,
for files you need to keep, since DOD can recover escrowed encryption
keys when a card is replaced and the other keys cannot be recovered.
Add access for a new card before the old card expires. A wrong PIN is
never retried, CAC cards lock after three wrong PINs. After any failed
card login no more logins are made in that run. The PIN is not sent
when it is empty or too long, or when the card reports its PIN is
locked; when the card reports low PIN tries or one try left, use
--smartcard-allow-pin-count-low or --smartcard-allow-final-try to send
it. Some modules do not report the PIN tries, check them with the card
software first. Keys that ask
for the PIN before every use are supported. On Windows, if ActivClient
is installed, fcrypt uses the ActivClient PKCS#11 module by default:

"C:\Program Files\HID Global\ActivClient\acpkcs211.dll"

otherwise it uses OpenSC. Use --smartcard-provider to pick one. The
key IDs from ActivClient are not the same as the OpenSC IDs above, so
list them with the OpenSC pkcs11-tool and use that ID or label_name:

> pkcs11-tool --module "C:\Program Files\HID Global\ActivClient\acpkcs211.dll" --list-objects

ActivClient uses a long hex ID, for example a 64 character SHA-256
hash, and labels such as "Encryption - name". Quote a label with
spaces:

> fdecrypt --smartcard-cert --smartcard-username=testuser "--smartcard-cert-id=label_Encryption - name" testfile.enc

Smart card access added on Linux with OpenSC works on Windows with
ActivClient for the same card and key, only the cert ID may differ.
ActivClient does not do RSA-OAEP with SHA-256 on the card, fcrypt uses
raw RSA on the card for it. A YubiKey used with ActivClient needs the
PIV CHUID and CCC objects, which ykman can write:

> ykman piv objects generate chuid
> ykman piv objects generate ccc

FINDING THE SLOT AND CERT ID WITHOUT A PIN
------------------------------------------
List the readers, cards and certs without a PIN:

  Linux:   console/scripts/smartcard_list.sh [module]
           (the default module is /usr/lib64/opensc-pkcs11.so)
  Windows: smartcard_list.bat (in the Windows package, or
           console/msvc/smartcard_list.bat), lists the cards through
           ActivClient and OpenSC and writes smartcard_list.log in
           %TEMP%

Each slot is shown as "Slot n (0xID)": use the 0xID with
--smartcard-slot. Under each slot, use the ID or label of the
encryption cert:

  OpenSC (CAC, PIV, YubiKey):  ID 03, "Certificate for Key Management"
  ActivClient (CAC):           the long hex ID, or the label
                               "Encryption - LAST.FIRST.MIDDLE.1234567890"
                               as label_Encryption - LAST.FIRST...

Do not use ID 01 (PIV Authentication), 02 (Digital Signature) or 04
(Card Authentication). For a YubiKey, ID 03 is PIV slot 9D.

The card key must be RSA. EC keys (P-256 or P-384, found on some PIV
cards and YubiKey slots) are refused, the file key is wrapped with RSA.

Remote Desktop: when smart card redirection is on in the RDP client
(Local Resources, More, Smart cards), programs in the RDP session see
only the client's cards, not the readers of the remote computer or
VM. Turn it off or use the computer's own console to use its readers.
