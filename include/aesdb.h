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

AES encryption and decryption routines.
AES encryption routes used encrypt/decrypt file buffers and memory
buffers.

AES encryption routes used generate encryption certificates.
*/
// ----------------------------------------------------------- //   
#ifndef __AES_CRYPT_DB_HPP__
#define __AES_CRYPT_DB_HPP__

// OpenSSL include files
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

// Constants
const unsigned int AES_DEF_ITERATIONS = 1000;
const unsigned int AES_MIN_SECRET_LEN = 8;
const unsigned int AES_MAX_SECRET_LEN = 65536;
const unsigned int AES_MIN_KEY_LEN = 32;
const unsigned int AES_MAX_KEY_LEN = EVP_MAX_KEY_LENGTH;
const unsigned int AES_MAX_IV_LEN = EVP_MAX_IV_LENGTH;
const unsigned int AES_MAX_SALT_LEN = 8;
const unsigned int AES_MAX_HMAC_LEN = 32;
const unsigned int AES_256_KEY_SIZE = 32;
const unsigned int AES_CBC_BLOCK_SIZE = 16;
const unsigned int AES_PLAINTEXT_BUF_SIZE = 1024;
const unsigned int AES_CIPHERTEXT_BUF_SIZE = 2048;
const unsigned int AES_CIPHER_STREAM_BUF_SIZE = 2048;
const unsigned int AES_MAX_NAME_LEN = 1024;
const unsigned int AES_MAX_VERIFIER_LEN = 16;
const unsigned int AES_MAX_MODE_LEN = 4;
const unsigned int AES_INPUT_BUF_LEN = 512;
const unsigned int AES_MAX_INPUT_BUF_LEN = 768;

// Enumerations
enum {
  AES_NO_ERROR = 0,
  AES_INVALID_ERROR,
  AES_ERROR_SECRET_MIN_LENGTH,
  AES_ERROR_OUT_OF_MEMORY,
  AES_ERROR_BAD_SECRET,
  AES_ERROR_AUTH_FAILED,
  AES_ERROR_KEY_LENGTH,
  AES_ERROR_BAD_SALT,
  AES_ERROR_BAD_KEY,
  AES_ERROR_BAD_VERIFIER,
  AES_ERROR_BAD_MAC,
  AES_ERROR_BAD_MODE,
  AES_ERROR_SECRET_MAX_LENGTH,
  AES_ERROR_KEY_MAX_LENGTH,
  AES_ERROR_IV_MAX_LENGTH,
  AES_ERROR_SALT_MAX_LENGTH,
  AES_ERROR_HMAC_MAX_LENGTH,
  AES_ERROR_BUFFER_OVERFLOW,
  AES_ERROR_BAD_BUFFER_LEN,
  AES_ERROR_NO_INIT,
  AES_ERROR_INIT,
  AES_ERROR_NO_SUCH_CIPHER,
  AES_ERROR_NO_SUCH_DIGEST,
  AES_ERROR_DERIVE_KEY_GEN_FAILED,
  AES_ERROR_HMAC_INIT_FAILED,
  AES_ERROR_HMAC_UPDATE_FAILED,
  AES_ERROR_HMAC_FINAL_FAILED,
  AES_ERROR_EVP_CTX_NEW,
  AES_ERROR_EVP_CIPHER_INIT,
  AES_ERROR_EVP_ENCRYPT_CIPHER_UPDATE,
  AES_ERROR_EVP_ENCRYPT_CIPHER_FINAL,
  AES_ERROR_EVP_DECRYPT_CIPHER_UPDATE,
  AES_ERROR_EVP_DECRYPT_CIPHER_FINAL,
  AES_ERROR_SALT_INIT_FAILED,
  AES_ERROR_NULL_POINTER
};

// Data structures used with AES lirbary
struct AES_buf_t { // AES encrypted/decrypted buffer type
  AES_buf_t() { Reset(1); }
  ~AES_buf_t() { 
    // Clear any buffer information before releasing this 
    // header so that no sensitive data is left in memory.
    Clear();
  }

  // NOTE: All encrypted/decrypted buffers should be cleared immediately 
  // after use so that no sensitive data is left in memory while other 
  // data is being processed. 
  void Clear();
  
  void Reset(int all = 0) {
    mode = -1; // Default to 256-bit encryption key
    key_iterations =  AES_DEF_ITERATIONS;
    if(all) Clear();
  }

  int mode;
  unsigned int key_iterations;
  
  char buf[AES_CIPHER_STREAM_BUF_SIZE];
  unsigned int buf_len;
  unsigned char salt[AES_MAX_SALT_LEN];
  unsigned char verifier[AES_MAX_VERIFIER_LEN];
  unsigned char hmac[AES_MAX_HMAC_LEN];
  unsigned char iv[AES_MAX_IV_LEN];
  unsigned char key[AES_MAX_KEY_LEN];
  unsigned char secret[AES_MAX_SECRET_LEN];
  unsigned secret_len;
  
private:
  AES_buf_t(const AES_buf_t &ob) { }
  void operator=(const AES_buf_t &ob) { }
};

class AESStreamCrypt
{
public:
  AESStreamCrypt() { }
  ~AESStreamCrypt() { b.Clear(); } 

public: // Encryption functions
  int Encrypt(void *buf, unsigned int *buf_len);
  int Encrypt();
  
public: // Decryption functions
  int Decrypt(void *buf, unsigned int *buf_len);
  int Decrypt();

public: // Helper functions
  void Reset() { b.Reset(); }
  void Clear() { b.Clear(); }

public:
  AES_buf_t b;
};

// Standalone functions
const char *AES_err_string(int err); 
unsigned int AES_file_enctryption_overhead();
int AES_openssl_init();
int AES_fillrand(unsigned char *buf, unsigned int len);
int AES_derive_key(const unsigned char secret[], unsigned int secret_len,
		   const unsigned char salt[], unsigned int salt_len,
		   unsigned char key[], unsigned int key_len,
		   unsigned char iv[], unsigned int iv_len,
		   unsigned int key_iterations = AES_DEF_ITERATIONS);
int AES_HMAC(const unsigned char key[], unsigned int key_len,
	     const unsigned char data[], unsigned int data_len,
	     unsigned char hash[], unsigned int hash_len);
int AES_256_CBC_encrypt(const unsigned char key[], const unsigned char iv[],
			const unsigned char plaintext[], unsigned int plaintext_len, 
			unsigned char ciphertext[], unsigned int ciphertext_len,
			unsigned *encrypted_data_len,
			int cipher_block_size = AES_CBC_BLOCK_SIZE);
int AES_256_CBC_decrypt(const unsigned char key[], const unsigned char iv[],
			const unsigned char ciphertext[], unsigned int ciphertext_len,
			unsigned char plaintext[], unsigned int plaintext_len, 
			unsigned *unencrypted_data_len);
int AES_init_salt(unsigned char *salt, unsigned int salt_len);
int AES_Encrypt(char *buf, unsigned int *buf_len, const unsigned char secret[], unsigned secret_len,
		unsigned char SALT[], unsigned int SALT_len,
		unsigned char KEY[], unsigned int KEY_len,
		unsigned char IV[], unsigned int IV_len,
		unsigned char VERIFIER[], unsigned VERIFIER_len,
		unsigned char HMAC[], unsigned HMAC_len,
		int mode = -1,
		unsigned int key_iterations = AES_DEF_ITERATIONS);
int AES_Encrypt(char *buf, unsigned int *buf_len, const unsigned char secret[], unsigned secret_len,
		int mode = -1, unsigned int key_iterations = AES_DEF_ITERATIONS);
int AES_Decrypt(char *buf, unsigned int *buf_len, const unsigned char secret[], unsigned secret_len,
		unsigned char SALT[], unsigned int SALT_len,
		unsigned char KEY[], unsigned int KEY_len,
		unsigned char IV[], unsigned int IV_len,
		unsigned char VERIFIER[], unsigned VERIFIER_len,
		unsigned char r_HMAC[], unsigned r_HMAC_len,
		int mode = -1,
		unsigned int key_iterations = AES_DEF_ITERATIONS);
int AES_Decrypt(char *buf, unsigned int *buf_len, const unsigned char secret[], unsigned secret_len,
		int mode = -1,
		unsigned int key_iterations = AES_DEF_ITERATIONS);
int AES_encrypt_buf(AES_buf_t *b);
int AES_decrypt_buf(AES_buf_t *b);
int AES_encrypt_buf(AES_buf_t *b, void *buf, unsigned int *buf_len);
int AES_decrypt_buf(AES_buf_t *b, void *buf, unsigned int *buf_len);

#endif // __AES_CRYPT_DB_HPP__
// ----------------------------------------------------------- // 
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
