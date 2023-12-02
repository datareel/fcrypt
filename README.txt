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

> mkdir ${HOME}/.keys
> chmod 700 ${HOME}/.keys
> openssl genrsa -aes256 -outp ${HOME}/.keys/private.pem 2048
> chmod 600 ${HOME}/.keys/private.pem
> openssl rsa -in private.pem -outform PEM -pubout -out ${HOME}/.keys/public.pem

Create a master file encryption key:

> dd if=/dev/urandom of=${HOME}/.keys/master.key bs=1 count=128
> chmod 600 ${HOME}/.keys/master.key

Encrypt a file:

> ./fcrypt --key=${HOME}/.keys/master.key testfile.txt

Add your RSA key:

> ./fcrypt --key=${HOME}/.keys/master.key --add-rsa-key=${HOME}/.keys/public.pem --rsa-key-username=testuser testfile.enc

Decrypt the file using your private key that is passpharse protected
and ensure you private key is never shared with anyone:

> ./fdecrypt --rsa-key=${HOME}/.keys/private.pem testfile.enc

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

> ./fdecrypt --rsa-key=${HOME}/.ssh/id_rsa testfile.enc

Have your users that need access to the encrypted file give you a copy
of their public ~/.ssh/id_rsa.pub SSH-RSA key.

Once you have a copy of all the public RSA keys that need access the
encrypt file add each key. After all the user are added you can remove
the file encrytion key:

> rm -fv ${HOME}/.keys/temp.key


All users will only be able to decrypt the file using their SSH-RSA
prviate key. All user should ensure their private key is passphrase
protected and never shared with anyone.  

For users that do not have passphare protected keys a passpharse can be
added with the following command:

> ssh-keygen -p -f ~/.ssh/id_rsa


