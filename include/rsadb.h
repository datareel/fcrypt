// ------------------------------- //
// -------- Start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- //
// C++ Header File
// Compiler Used: MSVC, BCC32, GCC, HPUX aCC, SOLARIS CC
// Produced By: DataReel Software Development Team
// File Creation Date: 06/15/2003
// Date Last Modified: 11/25/2023
// Copyright (c) 2001-2023 DataReel Software Development
// ----------------------------------------------------------- // 
// ---------- Include File Description and Details  ---------- // 
// ----------------------------------------------------------- // 
/*
This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.
 
This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  
USA

RSA encryption and decryption routines.
*/
// ----------------------------------------------------------- //   
#ifndef __RSA_CRYPT_DB_HPP__
#define __RSA_CRYPT_DB_HPP__

// OpenSSL include files
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

// Constants
const int RSA_padding = RSA_PKCS1_PADDING;
const int RSA_keysize = 2048;
const unsigned int RSA_passphrase_len = 32;
const unsigned int RSA_error_string_len = 1024;
const unsigned int RSA_max_keybuf_len = 65536;

// Enumerations
enum {
  RSA_NO_ERROR = 0,
  RSA_INVALID_ERROR,
  RSA_ERROR_NULL_POINTER,
  RSA_ERROR_BUFFER_OVERFLOW,
  RSA_ERROR_BAD_BUFFER_LEN,
  RSA_ERROR_OUT_OF_MEMORY,
  RSA_ERROR_NEW,
  RSA_ERROR_EVP_KEY_CREATE,
  RSA_ERROR_CONTEXT_CREATE,
  RSA_ERROR_BIG_NUMBER_CREATE,
  RSA_ERROR_BIG_NUMBER_INIT,
  RSA_ERROR_GEN_KEY,
  RSA_ERROR_PRIVATE_KEY_WRITE_FILE,
  RSA_ERROR_PRIVATE_KEY_READ_FILE,
  RSA_ERROR_PRIVATE_KEY_READ,
  RSA_ERROR_PUBLIC_KEY_WRITE_FILE,
  RSA_ERROR_PUBLIC_KEY_READ_FILE,
  RSA_ERROR_PUBLIC_KEY_READ,
  RSA_ERROR_PRIVATE_KEY_ENCRYPT,
  RSA_ERROR_PRIVATE_KEY_DECRYPT,
  RSA_ERROR_PUBLIC_KEY_ENCRYPT,
  RSA_ERROR_PUBLIC_KEY_DECRYPT,
  RSA_ERROR_KEY_FILE_OPEN,
  RSA_ERROR_KEY_FILE_WRITE,
  RSA_ERROR_KEY_FILE_READ,
  RSA_ERROR_KEY_BUFFER_OVERFLOW,
  RSA_ERROR_NEW_BIO_MEM_BUF
};

// Data structures used with RSA lirbary

// Standalone functions
int RSA_openssl_init();
int RSA_fillrand(unsigned char *buf, unsigned int len);
const char *RSA_err_string(int err);
char *RSA_get_last_openssl_error(int &error_level);
int RSA_passphrase_callback(char *buf, int size, int rwflag, void *userdata);
int RSA_gen_key_files(const char *private_key_fname, const char *public_key_fname, int keysize = RSA_keysize,
		      char *passphrase = 0, int passphrase_len = 0);
int RSA_read_key_file(const char *fname, char keybuf[], const unsigned keybuf_len, unsigned *keybuf_final_len);

int RSA_public_key_encrypt(const unsigned char key[], unsigned key_len,
			   const unsigned char plaintext[], unsigned int plaintext_len,
			   unsigned char ciphertext[], unsigned int ciphertext_len,
			   unsigned *encrypted_data_len,
			   int padding = RSA_padding, char *passphrase = 0);

int RSA_private_key_decrypt(const unsigned char key[], unsigned key_len,
			    const unsigned char ciphertext[], unsigned int ciphertext_len,
			    unsigned char plaintext[], unsigned int plaintext_len,
			    unsigned *unencrypted_data_len,
			    int padding = RSA_padding, char *passphrase = 0);


int RSA_private_key_encrypt(const unsigned char key[], unsigned key_len,
			    const unsigned char plaintext[], unsigned int plaintext_len,
			    unsigned char ciphertext[], unsigned int ciphertext_len,
			    unsigned *encrypted_data_len,
			    int padding = RSA_padding, char *passphrase = 0);

int RSA_public_key_decrypt(const unsigned char key[], unsigned key_len,
			   const unsigned char ciphertext[], unsigned int ciphertext_len,
			   unsigned char plaintext[], unsigned int plaintext_len,
			   unsigned *unencrypted_data_len,
			   int padding = RSA_padding, char *passphrase = 0);

#endif // __RSA_CRYPT_DB_HPP__
// ----------------------------------------------------------- // 
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
