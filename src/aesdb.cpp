// ------------------------------- //
// -------- start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- // 
// C++ Source Code File
// Compiler Used: MSVC, BCC32, GCC, HPUX aCC, SOLARIS CC
// Produced By: DataReel Software Development Team
// File Creation Date: 06/15/2003
// Date Last Modified: 12/06/2023
// Copyright (c) 2001-2024 DataReel Software Development
// ----------------------------------------------------------- // 
// ------------- Program Description and Details ------------- // 
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
*/
// ----------------------------------------------------------- // 
#include <aesdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

const int NUM_AES_ERRORS = 35;
const char *AES_err_strings[NUM_AES_ERRORS] =
{
 "AES_NO_ERROR",                        // AES_NO_ERROR
 "AES_INVALID_ERROR,",                  // AES_INVALID_ERROR,
 "AES_ERROR_SECRET_MIN_LENGTH",         // AES_ERROR_SECRET_MIN_LENGTH
 "AES_ERROR_OUT_OF_MEMORY",             // AES_ERROR_OUT_OF_MEMORY
 "AES_ERROR_BAD_SECRET",                // AES_ERROR_BAD_SECRET
 "AES_ERROR_AUTH_FAILED",               // AES_ERROR_AUTH_FAILED
 "AES_ERROR_KEY_LENGTH",                // AES_ERROR_KEY_LENGTH
 "AES_ERROR_BAD_SALT",                  // AES_ERROR_BAD_SALT
 "AES_ERROR_BAD_KEY",                   // AES_ERROR_BAD_KEY
 "AES_ERROR_BAD_VERIFIER",              // AES_ERROR_BAD_VERIFIER
 "AES_ERROR_BAD_MAC",                   // AES_ERROR_BAD_MAC
 "AES_ERROR_BAD_MODE",                  // AES_ERROR_BAD_MODE
 "AES_ERROR_SECRET_MAX_LENGTH",         // AES_ERROR_SECRET_MAX_LENGTH
 "AES_ERROR_KEY_MAX_LENGTH",            // AES_ERROR_KEY_MAX_LENGTH
 "AES_ERROR_IV_MAX_LENGTH",             // AES_ERROR_IV_MAX_LENGTH
 "AES_ERROR_SALT_MAX_LENGTH",           // AES_ERROR_SALT_MAX_LENGTH
 "AES_ERROR_HMAC_MAX_LENGTH",           // AES_ERROR_HMAC_MAX_LENGTH
 "AES_ERROR_BUFFER_OVERFLOW",           // AES_ERROR_BUFFER_OVERFLOW
 "AES_ERROR_BAD_BUFFER_LEN",            // AES_ERROR_BAD_BUFFER_LEN
 "AES_ERROR_NO_INIT",                   // AES_ERROR_NO_INIT
 "AES_ERROR_INIT",                      // AES_ERROR_INIT
 "AES_ERROR_NO_SUCH_CIPHER",            // AES_ERROR_NO_SUCH_CIPHER
 "AES_ERROR_NO_SUCH_DIGEST",            // AES_ERROR_NO_SUCH_DIGEST
 "AES_ERROR_DERIVE_KEY_GEN_FAILED",     // AES_ERROR_DERIVE_KEY_GEN_FAILED
 "AES_ERROR_HMAC_INIT_FAILED",          // AES_ERROR_HMAC_INIT_FAILED
 "AES_ERROR_HMAC_UPDATE_FAILED",        // AES_ERROR_HMAC_UPDATE_FAILED
 "AES_ERROR_HMAC_FINAL_FAILED",         // AES_ERROR_HMAC_FINAL_FAILED
 "AES_ERROR_EVP_CTX_NEW",               // AES_ERROR_EVP_CTX_NEW
 "AES_ERROR_EVP_CIPHER_INIT",           // AES_ERROR_EVP_CIPHER_INIT
 "AES_ERROR_EVP_ENCRYPT_CIPHER_UPDATE", // AES_ERROR_EVP_ENCRYPT_CIPHER_UPDATE
 "AES_ERROR_EVP_ENCRYPT_CIPHER_FINAL",  // AES_ERROR_EVP_ENCRYPT_CIPHER_FINAL
 "AES_ERROR_EVP_DECRYPT_CIPHER_UPDATE", // AES_ERROR_EVP_DECRYPT_CIPHER_UPDATE
 "AES_ERROR_EVP_DECRYPT_CIPHER_FINAL",  // AES_ERROR_EVP_DECRYPT_CIPHER_FINAL
 "AES_ERROR_SALT_INIT_FAILED",          // AES_ERROR_SALT_INIT_FAILED
 "AES_ERROR_NULL_POINTER"               // AES_ERROR_NULL_POINTER
};

int AES_openssl_init()
{
  OpenSSL_add_all_algorithms();
  return 0;
}

unsigned int AES_file_enctryption_overhead()
{
  unsigned enctryption_overhead = 0;
  enctryption_overhead += AES_MAX_MODE_LEN;
  enctryption_overhead += AES_MAX_SALT_LEN;
  enctryption_overhead += AES_MAX_VERIFIER_LEN;
  enctryption_overhead += AES_CBC_BLOCK_SIZE;
  enctryption_overhead += AES_MAX_HMAC_LEN;
  return enctryption_overhead;
}

// Standalone functions
const char *AES_err_string(int err) 
{
  if(err < 0) return AES_err_strings[1];
  
  if(err > (NUM_AES_ERRORS-1)) {
    return AES_err_strings[1];
  }
  return AES_err_strings[err];
};

int AES_fillrand(unsigned char *buf, unsigned int len)
// Generates num random bytes using OpenSSL cryptographically secure pseudo random generator.
// Return the number of bytes filled or -1 for errors
{
  // RAND_bytes() and RAND_priv_bytes() return 1 on success, -1 if not supported by the current RAND method, or 0 on other failure.
  if(RAND_bytes(buf, len) != 1) return -1;
  return len;
}

int AES_derive_key(const unsigned char secret[], unsigned int secret_len,
		   const unsigned char salt[], unsigned int salt_len,
		   unsigned char key[], unsigned int key_len,
		   unsigned char iv[], unsigned int iv_len,
		   unsigned int key_iterations)
// Derive the key and initialization vector from a secret and salt
{
  if(secret_len < AES_MIN_SECRET_LEN) return AES_ERROR_SECRET_MIN_LENGTH;
  if(salt_len > AES_MAX_SALT_LEN) return AES_ERROR_SALT_MAX_LENGTH;
  if(key_len > AES_MAX_KEY_LEN) return AES_ERROR_KEY_MAX_LENGTH; 
  if(iv_len > AES_MAX_IV_LEN) return AES_ERROR_KEY_MAX_LENGTH; 

  OpenSSL_add_all_algorithms();
  
  // Clear the key and IV
  memset(key, 0, key_len);
  memset(iv, 0, iv_len);

  const EVP_CIPHER *cipher;
  const EVP_MD *dgst = 0;

  cipher = EVP_get_cipherbyname("aes-256-cbc");
  if(!cipher) return AES_ERROR_NO_SUCH_CIPHER;

  dgst = EVP_get_digestbyname("sha256");
  if(!dgst) return AES_ERROR_NO_SUCH_DIGEST;

  if(!EVP_BytesToKey(cipher, dgst, salt, (unsigned char *)secret, secret_len, key_iterations, key, iv)) {
    return AES_ERROR_DERIVE_KEY_GEN_FAILED;
  }

  return AES_NO_ERROR;
}

int AES_HMAC(const unsigned char key[], unsigned int key_len,
	     const unsigned char data[], unsigned int data_len,
	     unsigned char hash[], unsigned int hash_len)
// Generate message access control for authentication based on a hash function
{
  if(hash_len > AES_MAX_HMAC_LEN) return AES_ERROR_HMAC_MAX_LENGTH; 
  if(hash_len < AES_MAX_HMAC_LEN) return AES_ERROR_HMAC_MAX_LENGTH; 
  if(key_len < AES_256_KEY_SIZE) return AES_ERROR_KEY_LENGTH;
  
  // grep OPENSSL_VERSION_NUMBER /usr/include/openssl/opensslv.h
#if OPENSSL_VERSION_NUMBER < 0x101010bfL
  HMAC_CTX hmac_ob;
  HMAC_CTX *hmac = &hmac_ob;
  HMAC_CTX_init(hmac);
#else
  HMAC_CTX *hmac = HMAC_CTX_new();
  if(!hmac) {
    return AES_ERROR_HMAC_INIT_FAILED;
  }
#endif

  // 10/24/2026: Check every HMAC return value so a failed HMAC is never
  // written to a file or accepted as a match.
  int rv = AES_NO_ERROR;
  unsigned int len = hash_len;
  if(!HMAC_Init_ex(hmac, key, AES_256_KEY_SIZE, EVP_sha256(), 0)) {
    rv = AES_ERROR_HMAC_INIT_FAILED;
  }
  else if(!HMAC_Update(hmac, data, data_len)) {
    rv = AES_ERROR_HMAC_UPDATE_FAILED;
  }
  else if(!HMAC_Final(hmac, hash, &len) || len != hash_len) {
    rv = AES_ERROR_HMAC_FINAL_FAILED;
  }

#if OPENSSL_VERSION_NUMBER < 0x101010bfL
  HMAC_CTX_cleanup(hmac);
#else  
  HMAC_CTX_free(hmac);
#endif

  if(rv != AES_NO_ERROR) OPENSSL_cleanse(hash, hash_len);
  return rv;
}

int AES_256_CBC_encrypt(const unsigned char key[], const unsigned char iv[],
			const unsigned char plaintext[], unsigned int plaintext_len, 
			unsigned char ciphertext[], unsigned int ciphertext_len,
			unsigned *encrypted_data_len,
			int cipher_block_size)
{
  *(encrypted_data_len) = 0;
  if(plaintext_len == 0) return AES_NO_ERROR;

  if(ciphertext_len < (plaintext_len+AES_CBC_BLOCK_SIZE)) {
    return AES_ERROR_BAD_BUFFER_LEN;
  }

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if(!ctx){
    return  AES_ERROR_EVP_CTX_NEW;
  }

  int c_len = 0;
  int f_len = 0;

  if(!EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), 0, key, iv, 1)){
    EVP_CIPHER_CTX_free(ctx);
    return AES_ERROR_EVP_CIPHER_INIT;
  }

  // Check key and IV lengths 
  if((EVP_CIPHER_CTX_key_length(ctx) != (int)AES_256_KEY_SIZE) ||
     (EVP_CIPHER_CTX_iv_length(ctx) != (int)AES_CBC_BLOCK_SIZE)) {
    EVP_CIPHER_CTX_free(ctx);
    return AES_ERROR_EVP_CIPHER_INIT;
  }

  if(!EVP_CipherUpdate(ctx, ciphertext, &c_len, plaintext, plaintext_len)){
    EVP_CIPHER_CTX_free(ctx);
    return AES_ERROR_EVP_ENCRYPT_CIPHER_UPDATE;
  }

  // With padding enabled (the default) the final block is written here
  if(!EVP_CipherFinal_ex(ctx, ciphertext+c_len, &f_len)){
    EVP_CIPHER_CTX_free(ctx);
    return AES_ERROR_EVP_ENCRYPT_CIPHER_FINAL;
  }

  *(encrypted_data_len) = c_len + f_len;
  EVP_CIPHER_CTX_free(ctx);
  return AES_NO_ERROR;
}

int AES_256_CBC_decrypt(const unsigned char key[], const unsigned char iv[],
			const unsigned char ciphertext[], unsigned int ciphertext_len,
			unsigned char plaintext[], unsigned int plaintext_len, 
			unsigned *unencrypted_data_len)
// 10/24/2026: The plaintext buffer must be at least as long as the
// ciphertext. This is checked before decrypting so a long ciphertext
// can no longer overflow the plaintext buffer.
{
  *(unencrypted_data_len) = 0;
  if(ciphertext_len == 0) return AES_NO_ERROR;
  if((ciphertext_len % AES_CBC_BLOCK_SIZE) != 0) return AES_ERROR_BAD_BUFFER_LEN;
  if(plaintext_len < ciphertext_len) return AES_ERROR_BUFFER_OVERFLOW;

  int f_len = 0;
  int p_len = 0;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if(!ctx){
    return  AES_ERROR_EVP_CTX_NEW;
  }

  if(!EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), 0, key, iv, 0)){
    EVP_CIPHER_CTX_free(ctx);
    return AES_ERROR_EVP_CIPHER_INIT;
  }

  if((EVP_CIPHER_CTX_key_length(ctx) != (int)AES_256_KEY_SIZE) ||
     (EVP_CIPHER_CTX_iv_length(ctx) != (int)AES_CBC_BLOCK_SIZE)) {
    EVP_CIPHER_CTX_free(ctx);
    return AES_ERROR_EVP_CIPHER_INIT;
  }

  if(!EVP_CipherUpdate(ctx, plaintext, &p_len, ciphertext, ciphertext_len)) {
    EVP_CIPHER_CTX_free(ctx);
    return AES_ERROR_EVP_DECRYPT_CIPHER_UPDATE;
  }

  if(!EVP_CipherFinal_ex(ctx, plaintext+p_len, &f_len)){
    EVP_CIPHER_CTX_free(ctx);
    return AES_ERROR_EVP_DECRYPT_CIPHER_FINAL;
  }
  
  *(unencrypted_data_len) = p_len + f_len;

  EVP_CIPHER_CTX_free(ctx);
  return AES_NO_ERROR;
}

int AES_init_salt(unsigned char *salt, unsigned int salt_len)
{
  if(RAND_bytes(salt, salt_len) != 1) return AES_ERROR_SALT_INIT_FAILED;
  return AES_NO_ERROR;
}

int AES_Encrypt(char *buf, unsigned int *buf_len, const unsigned char secret[], unsigned secret_len,
		unsigned char SALT[], unsigned int SALT_len,
		unsigned char KEY[], unsigned int KEY_len,
		unsigned char IV[], unsigned int IV_len,
		unsigned char VERIFIER[], unsigned VERIFIER_len,
		unsigned char HMAC[], unsigned HMAC_len,
		int mode, 
		unsigned int key_iterations)
// NOTE: The "buf" variable must be large enough to hold the encrypted
// buffer, which is *buf_len plus AES_file_enctryption_overhead() bytes.
{
  // 
  // Mode -> salt -> verifier -> ciphertext -> hmac 
  // Mode     = 4 bytes
  // Salt     = 8 bytes
  // Verifier = 16 bytes
  // --       = 28 bytes of overhead
  // Ciphertext = encrypted data plus encryption overhead 
  // HMAC     = 32 bytes
  
  // Mode 0 = Plain text, no encryption (debugging only)
  // For now all others using = 256-bit AES
  // Other cipher modes will be added in the future

  unsigned len = *(buf_len);
  if(len == 0) return AES_NO_ERROR;

  if(mode == 0) { // Signal non-encrypted buffer and return
    return AES_NO_ERROR;
  }

  if(secret_len < AES_MIN_SECRET_LEN) return AES_ERROR_SECRET_MIN_LENGTH;
  if(secret_len > AES_MAX_SECRET_LEN) return AES_ERROR_SECRET_MAX_LENGTH;
  if(SALT_len != AES_MAX_SALT_LEN || VERIFIER_len != AES_MAX_VERIFIER_LEN ||
     HMAC_len != AES_MAX_HMAC_LEN || KEY_len < AES_256_KEY_SIZE || IV_len < AES_CBC_BLOCK_SIZE) {
    return AES_ERROR_BAD_BUFFER_LEN;
  }

  // 10/24/2026: The mode bytes must never be all zero. Older versions
  // treated all-zero mode bytes as an unencrypted block, and a failed
  // RAND_bytes() call could leave them uninitialized.
  unsigned char MODE[AES_MAX_MODE_LEN];
  memset(MODE, 0, sizeof(MODE));
  if(AES_fillrand(MODE, sizeof(MODE)) != (int)sizeof(MODE)) return AES_ERROR_SALT_INIT_FAILED;
  if(MODE[0] == 0 && MODE[1] == 0 && MODE[2] == 0 && MODE[3] == 0) MODE[0] = 1;

  // Encrypt into a separate buffer, then build the output in buf
  unsigned ciphertext_len = len + AES_CBC_BLOCK_SIZE;
  unsigned char *ciphertext = new unsigned char[ciphertext_len];
  if(!ciphertext) return AES_ERROR_OUT_OF_MEMORY;

  int rv = AES_init_salt(SALT, SALT_len);
  if(rv == AES_NO_ERROR) {
    rv = AES_derive_key((const unsigned char*)secret, secret_len, SALT, SALT_len, KEY, KEY_len, IV, IV_len, key_iterations);
  }

  unsigned encrypted_data_len = 0;
  if(rv == AES_NO_ERROR) {
    rv = AES_256_CBC_encrypt(KEY, IV, (const unsigned char*)buf, len, ciphertext, ciphertext_len, &encrypted_data_len);
  }
  if(rv == AES_NO_ERROR) {
    rv = AES_HMAC(KEY, KEY_len, ciphertext, encrypted_data_len, HMAC, HMAC_len);
  }

  if(rv == AES_NO_ERROR) {
    // Clear the plaintext and write the encrypted block
    OPENSSL_cleanse(buf, len);
    unsigned offset = 0;
    memmove(buf, MODE, sizeof(MODE));
    offset += sizeof(MODE);
    memmove((buf+offset), SALT, SALT_len);
    offset += SALT_len;
    memmove((buf+offset), VERIFIER, VERIFIER_len);
    offset += VERIFIER_len;
    memmove((buf+offset), ciphertext, encrypted_data_len);
    offset += encrypted_data_len;
    memmove((buf+offset), HMAC, HMAC_len);
    offset += HMAC_len;
    *(buf_len) = offset;
  }

  OPENSSL_cleanse(ciphertext, ciphertext_len);
  delete[] ciphertext;
  return rv;
}

int AES_Encrypt(char *buf, unsigned int *buf_len, const unsigned char secret[], unsigned secret_len,
		int mode, unsigned int key_iterations)
// Encrypt a specified buffer of size "buf_len" with a secret key/password/passphrase ranging 
// from 8 bytes to 128 bytes. NOTE: The "buf" variable must be large enough to hold the
// encrypted buffer plus the encryption overhead. Returns 0 if successful or a non-zero
// value to indicate an error condition. If mode == -1, not set and defaults to AES256.
{
  unsigned char SALT[AES_MAX_SALT_LEN];
  unsigned char VERIFIER[AES_MAX_VERIFIER_LEN];
  unsigned char HMAC[AES_MAX_HMAC_LEN];
  unsigned char IV[AES_MAX_IV_LEN];
  unsigned char KEY[AES_MAX_KEY_LEN];

  // 10/24/2026: The verifier was written to the file without being set,
  // which copied uninitialized stack memory into every file header.
  memset(VERIFIER, 0, sizeof(VERIFIER));

  int rv = AES_Encrypt(buf, buf_len, secret, secret_len,
		       SALT, sizeof(SALT),
		       KEY, sizeof(KEY),
		       IV, sizeof(IV),
		       VERIFIER, sizeof(VERIFIER),
		       HMAC, sizeof(HMAC),
		       mode, key_iterations);

  // Clear all buffers and return
  OPENSSL_cleanse(SALT, sizeof(SALT));
  OPENSSL_cleanse(VERIFIER, sizeof(VERIFIER));
  OPENSSL_cleanse(HMAC, sizeof(HMAC));
  OPENSSL_cleanse(KEY, sizeof(KEY));
  OPENSSL_cleanse(IV, sizeof(IV));

  return rv;
}

int AES_Decrypt(char *buf, unsigned int *buf_len, const unsigned char secret[], unsigned secret_len,
		unsigned char SALT[], unsigned int SALT_len,
		unsigned char KEY[], unsigned int KEY_len,
		unsigned char IV[], unsigned int IV_len,
		unsigned char VERIFIER[], unsigned VERIFIER_len,
		unsigned char r_HMAC[], unsigned r_HMAC_len,
		int mode,
		unsigned int key_iterations)
// Decrypt a specified buffer of size "buf_len" with a secret key/password/passphrase
// ranging from 8 bytes to 128 bytes. Returns 0 if successful or a non-zero value to
// indicate an error condition.
// 10/24/2026: All lengths are checked before use, the HMAC is verified
// with a constant time compare before anything is decrypted, and blocks
// with all-zero mode bytes are rejected. Older versions returned those
// blocks as plaintext without checking the secret or the HMAC, which let
// anyone forge a file that decrypted under any password.
{
  unsigned len = *(buf_len);
  if(len == 0) return AES_NO_ERROR;

  // Check the mode setting passed to this function
  if(mode == 0) { // Signal non-encrypted buffer and return
    return AES_NO_ERROR;
  }

  if(secret_len < AES_MIN_SECRET_LEN) return AES_ERROR_SECRET_MIN_LENGTH;
  if(secret_len > AES_MAX_SECRET_LEN) return AES_ERROR_SECRET_MAX_LENGTH;
  if(SALT_len != AES_MAX_SALT_LEN || VERIFIER_len != AES_MAX_VERIFIER_LEN ||
     r_HMAC_len != AES_MAX_HMAC_LEN || KEY_len < AES_256_KEY_SIZE || IV_len < AES_CBC_BLOCK_SIZE) {
    return AES_ERROR_BAD_BUFFER_LEN;
  }

  // Mode -> salt -> verifier -> ciphertext (at least one block) -> hmac 
  unsigned header_len = AES_MAX_MODE_LEN + SALT_len + VERIFIER_len;
  if(len < (header_len + AES_CBC_BLOCK_SIZE + r_HMAC_len)) return AES_ERROR_BAD_BUFFER_LEN;
  unsigned ciphertext_len = len - header_len - r_HMAC_len;
  if((ciphertext_len % AES_CBC_BLOCK_SIZE) != 0) return AES_ERROR_BAD_BUFFER_LEN;

  const unsigned char *ubuf = (const unsigned char *)buf;
  const unsigned char *r_MODE = ubuf;
  if(r_MODE[0] == 0 && r_MODE[1] == 0 && r_MODE[2] == 0 && r_MODE[3] == 0) {
    return AES_ERROR_BAD_MODE;
  }

  unsigned offset = AES_MAX_MODE_LEN;
  memmove(SALT, ubuf+offset, SALT_len);
  offset += SALT_len;
  memmove(VERIFIER, ubuf+offset, VERIFIER_len);
  offset += VERIFIER_len;
  const unsigned char *ciphertext = ubuf+offset;
  memmove(r_HMAC, ubuf+offset+ciphertext_len, r_HMAC_len);

  int rv = AES_derive_key((unsigned char *)secret, secret_len, SALT, SALT_len, KEY, KEY_len, IV, IV_len, key_iterations);
  if(rv != AES_NO_ERROR) return rv;

  // Authenticate the ciphertext before decrypting it
  unsigned char HMAC[AES_MAX_HMAC_LEN];
  rv = AES_HMAC(KEY, KEY_len, ciphertext, ciphertext_len, HMAC, sizeof(HMAC));
  if(rv != AES_NO_ERROR) return rv;
  if(CRYPTO_memcmp(HMAC, r_HMAC, r_HMAC_len) != 0) {
    OPENSSL_cleanse(HMAC, sizeof(HMAC));
    return AES_ERROR_AUTH_FAILED;
  }
  OPENSSL_cleanse(HMAC, sizeof(HMAC));

  unsigned char *plaintext = new unsigned char[ciphertext_len];
  if(!plaintext) return AES_ERROR_OUT_OF_MEMORY;
  unsigned unencrypted_data_len = 0;
  rv = AES_256_CBC_decrypt(KEY, IV, ciphertext, ciphertext_len, plaintext, ciphertext_len, &unencrypted_data_len);
  if(rv == AES_NO_ERROR) {
    // The plaintext is always shorter than the encrypted block
    memmove(buf, plaintext, unencrypted_data_len);
    OPENSSL_cleanse(buf+unencrypted_data_len, len-unencrypted_data_len);
    *(buf_len) = unencrypted_data_len;
  }
  OPENSSL_cleanse(plaintext, ciphertext_len);
  delete[] plaintext;
  return rv;
}

int AES_Decrypt(char *buf, unsigned int *buf_len, const unsigned char secret[], unsigned secret_len,
		int mode, unsigned int key_iterations)
// Decrypt a specified buffer of size "buf_len" with a secret key/password/passphrase
// ranging from 8 bytes to 128 bytes. Returns 0 if successful or a non-zero value to
// indicate an error condition.
{
  unsigned char SALT[AES_MAX_SALT_LEN];
  unsigned char VERIFIER[AES_MAX_VERIFIER_LEN];
  unsigned char HMAC[AES_MAX_HMAC_LEN];
  unsigned char IV[AES_MAX_IV_LEN];
  unsigned char KEY[AES_MAX_KEY_LEN];

  int rv = AES_Decrypt(buf, buf_len, secret, secret_len,
		       SALT, sizeof(SALT),
		       KEY, sizeof(KEY),
		       IV, sizeof(IV),
		       VERIFIER, sizeof(VERIFIER),
		       HMAC, sizeof(HMAC),
		       mode,
		       key_iterations);

  // Clear all buffers and return
  OPENSSL_cleanse(SALT, sizeof(SALT));
  OPENSSL_cleanse(VERIFIER, sizeof(VERIFIER));
  OPENSSL_cleanse(HMAC, sizeof(HMAC));
  OPENSSL_cleanse(KEY, sizeof(KEY));
  OPENSSL_cleanse(IV, sizeof(IV));

  return rv;
}

int AES_encrypt_buf(AES_buf_t *b)
{
  if(!b) return AES_ERROR_NULL_POINTER;
  
  unsigned int buf_len = b->buf_len;
  int rv = AES_Encrypt(b->buf, &buf_len, (const unsigned char *)b->secret, b->secret_len,
		       b->salt, sizeof(b->salt),
		       b->key, sizeof(b->key),
		       b->iv, sizeof(b->iv),
		       b->verifier, sizeof(b->verifier),
		       b->hmac, sizeof(b->hmac),
		       b->mode, b->key_iterations);
  b->buf_len = buf_len;
  return rv;
}

int AES_decrypt_buf(AES_buf_t *b)
{
  unsigned int buf_len = b->buf_len;
  int rv = AES_Decrypt(b->buf, &buf_len, (const unsigned char *)b->secret, b->secret_len,
		       b->salt, sizeof(b->salt),
		       b->key, sizeof(b->key),
		       b->iv, sizeof(b->iv),
		       b->verifier, sizeof(b->verifier),
		       b->hmac, sizeof(b->hmac),
		       b->mode,
		       b->key_iterations);
  b->buf_len = buf_len;
  return rv;
}

int AES_encrypt_buf(AES_buf_t *b, void *buf, unsigned int *buf_len)
{
  if(!b) return AES_ERROR_NULL_POINTER;
  b->buf_len = 0;
  int rv = AES_Encrypt((char *)buf, buf_len, (const unsigned char *)b->secret, b->secret_len,
		       b->salt, sizeof(b->salt),
		       b->key, sizeof(b->key),
		       b->iv, sizeof(b->iv),
		       b->verifier, sizeof(b->verifier),
		       b->hmac, sizeof(b->hmac),
		       b->mode, b->key_iterations);

  return rv;
}

int AES_decrypt_buf(AES_buf_t *b, void *buf, unsigned int *buf_len)
{
  b->buf_len = 0;
  int rv = AES_Decrypt((char *)buf, buf_len, (const unsigned char *)b->secret, b->secret_len,
		       b->salt, sizeof(b->salt),
		       b->key, sizeof(b->key),
		       b->iv, sizeof(b->iv),
		       b->verifier, sizeof(b->verifier),
		       b->hmac, sizeof(b->hmac),
		       b->mode,
		       b->key_iterations);
  return rv;
}

void AES_buf_t::Clear()
// 10/24/2026: Use OPENSSL_cleanse() so the compiler cannot remove the wipe
{
  OPENSSL_cleanse(buf, AES_CIPHER_STREAM_BUF_SIZE);
  buf_len = 0;
  OPENSSL_cleanse(salt, AES_MAX_SALT_LEN);
  OPENSSL_cleanse(verifier, AES_MAX_VERIFIER_LEN);
  OPENSSL_cleanse(hmac, AES_MAX_HMAC_LEN);
  OPENSSL_cleanse(iv, AES_MAX_IV_LEN);
  OPENSSL_cleanse(key, AES_MAX_KEY_LEN);
  OPENSSL_cleanse(secret, AES_MAX_SECRET_LEN);
  secret_len = 0;
}

int AESStreamCrypt::Encrypt(void *buf, unsigned int *buf_len) 
{
  if(*(buf_len) == 0) return AES_NO_ERROR;
  if(!buf) return AES_NO_ERROR;
  return AES_encrypt_buf(&b, buf, buf_len);
}

int AESStreamCrypt::Decrypt(void *buf, unsigned int *buf_len) 
{
  if(*(buf_len) == 0) return AES_NO_ERROR;
  if(!buf) return AES_NO_ERROR;
  return AES_decrypt_buf(&b, buf, buf_len);
}

int AESStreamCrypt::Encrypt()
{
  return AES_encrypt_buf(&b);
}

int AESStreamCrypt::Decrypt()
{
  return AES_decrypt_buf(&b);
}
// ----------------------------------------------------------- // 
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
    
