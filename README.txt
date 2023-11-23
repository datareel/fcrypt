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

To build the fcrypt and fdecrypt programs for Linux:

$ mkdir -pv ${HOME}/git
$ cd ${HOME}/git
$ git clone https://github.com/datareel/fcrypt.git
$ cd fcrypt/console/linux
$ make

To run the utilites:

$ ./fcrypt filename

The above command will encrypt the input file and creates a .enc file with the same file name.

To decrypt the file:

$ ./fdecrypt filename.enc 

This will decrypt the file creating the unencrypted file using the original file name. 

