File encryption and decryption utility

This source code is used to build the fcrypt and fecrypt utilities
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

TO BUILD THE FCRYPT AND FDECRYPT PROGRAMS FOR LINUX
---------------------------------------------------
$ mkdir -pv ${HOME}/git
$ cd ${HOME}/git
$ git clone https://github.com/datareel/fcrypt.git
$ cd fcrypt/console/linux
$ make

To run a simple test of the utilites:

$ ./fcrypt testfile.txt

The above command will encrypt the input file and creates a .enc file with the same file name.

To decrypt the file:

$ ./fdecrypt testfile.enc 

This will decrypt the file creating the unencrypted file using the original file name. 


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


> openssl genrsa -aes256 -out private.pem 2048
> chmod 600 private.pem
> openssl rsa -in private.pem -outform PEM -pubout -out public.pem

Create a master file encryption key:

> dd if=/dev/urandom of=master.key bs=1 count=128
> chmod 600 master.key

Encrypt a file:

> ./fcrypt --key=master.key testfile.txt

Add your RSA key:

> ./fcrypt --key=master.key --add-rsa-key=public.pem --rsa-key-username=testuser testfile.enc

Decrypt the file:

> ./fdecrypt --rsa-key=private.pem testfile.enc

