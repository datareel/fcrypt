// ------------------------------- //
// -------- start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- // 
// C++ Source Code File
// Compiler Used: MSVC, BCC32, GCC, HPUX aCC, SOLARIS CC
// Produced By: DataReel Software Development Team
// File Creation Date: 06/15/2003
// Date Last Modified: 11/18/2023
// Copyright (c) 2001-2023 DataReel Software Development
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
AES encryption routes used encrypt/decrypt file buffers and memory              
buffers.                                                                        
AES encryption routes used create password file hashes.                         
AES encryption routes used generate encryption certificates and                 
authenticate users.       
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
  // NOTE: For security reasons all exceptions are represented by number error codes
 "Clib exception error code 55000", // AES_NO_ERROR
 "Clib exception error code 55001", // AES_INVALID_ERROR,
 "Clib exception error code 55002", // AES_ERROR_SECRET_LENGTH
 "Clib exception error code 55003", // AES_ERROR_OUT_OF_MEMORY
 "Clib exception error code 55004", // AES_ERROR_BAD_SECRET
 "Clib exception error code 55005", // AES_ERROR_AUTH_FAILED
 "Clib exception error code 55006", // AES_ERROR_KEY_LENGTH
 "Clib exception error code 55007", // AES_ERROR_BAD_SALT
 "Clib exception error code 55008", // AES_ERROR_BAD_KEY
 "Clib exception error code 55009", // AES_ERROR_BAD_VERIFIER
 "Clib exception error code 55010", // AES_ERROR_BAD_MAC
 "Clib exception error code 55011", // AES_ERROR_BAD_MODE
 "Clib exception error code 55012", // AES_ERROR_SECRET_MAX_LENGTH
 "Clib exception error code 55013", // AES_ERROR_KEY_MAX_LENGTH
 "Clib exception error code 55014", // AES_ERROR_IV_MAX_LENGTH
 "Clib exception error code 55015", // AES_ERROR_SALT_MAX_LENGTH
 "Clib exception error code 55016", // AES_ERROR_HMAC_MAX_LENGTH
 "Clib exception error code 55017", // AES_ERROR_BUFFER_OVERFLOW
 "Clib exception error code 55018", // AES_ERROR_BAD_BUFFER_LEN
 "Clib exception error code 55019", // AES_ERROR_NO_INIT
 "Clib exception error code 55020", // AES_ERROR_INIT
 "Clib exception error code 55021", // AES_ERROR_NO_SUCH_CIPHER
 "Clib exception error code 55022", // AES_ERROR_NO_SUCH_DIGEST
 "Clib exception error code 55023", // AES_ERROR_DERIVE_KEY_GEN_FAILED
 "Clib exception error code 55024", // AES_ERROR_HMAC_INIT_FAILED
 "Clib exception error code 55025", // AES_ERROR_HMAC_UPDATE_FAILED
 "Clib exception error code 55026", // AES_ERROR_HMAC_FINAL_FAILED
 "Clib exception error code 55027", // AES_ERROR_EVP_CTX_NEW
 "Clib exception error code 55028", // AES_ERROR_EVP_CIPHER_INIT
 "Clib exception error code 55029", // AES_ERROR_EVP_ENCRYPT_CIPHER_UPDATE
 "Clib exception error code 55030", // AES_ERROR_EVP_ENCRYPT_CIPHER_FINAL
 "Clib exception error code 55031", // AES_ERROR_EVP_DECRYPT_CIPHER_UPDATE
 "Clib exception error code 55032", // AES_ERROR_EVP_DECRYPT_CIPHER_FINAL
 "Clib exception error code 55033", // AES_ERROR_SALT_INIT_FAILED
 "Clib exception error code 55034"  // AES_ERROR_NULL_POINTER
};

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
  if(secret_len < AES_MIN_SECRET_LEN) return AES_ERROR_SECRET_LENGTH;
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
  
  const EVP_CIPHER *cipher;
  cipher = EVP_get_cipherbyname("aes-256-cbc");
  if(!cipher) return AES_ERROR_NO_SUCH_CIPHER;

  HMAC_CTX *hmac = HMAC_CTX_new();
  if(!hmac) {
    return AES_ERROR_HMAC_INIT_FAILED;
  }
  
  HMAC_Init_ex(hmac, key, EVP_CIPHER_key_length(cipher), EVP_sha256(), 0);
  HMAC_Update(hmac, data, data_len);
  
  unsigned int len = hash_len;
  HMAC_Final(hmac, hash, &len);
  
  HMAC_CTX_free(hmac);
  return AES_NO_ERROR;
}

int AES_encrypt(const unsigned char key[], const unsigned char iv[],
		const unsigned char plaintext[], unsigned int plaintext_len, 
		unsigned char ciphertext[], unsigned int ciphertext_len,
		unsigned *encrypted_data_len,
		int cipher_block_size)
{
  if(plaintext_len == 0) return AES_NO_ERROR;

  if(ciphertext_len < (plaintext_len+AES_CBC_BLOCK_SIZE)) {
    return AES_ERROR_BAD_BUFFER_LEN;
  }

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if(!ctx){
    return  AES_ERROR_EVP_CTX_NEW;
  }

  const EVP_CIPHER *null_cipher_type = 0;
  ENGINE *null_impl = 0;
  const unsigned char *null_key = 0;
  const unsigned char *null_iv = 0;

  int c_len = ciphertext_len;
  int f_len = 0;

  // Not setting key or IV here
  if(!EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), null_impl, null_key, null_iv, 1)){
    EVP_CIPHER_CTX_free(ctx);
    return AES_ERROR_EVP_CIPHER_INIT;
  }

  // Check key and IV lengths 
  OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == AES_256_KEY_SIZE);
  OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == AES_CBC_BLOCK_SIZE);

  // Set the key and IV
  if(!EVP_CipherInit_ex(ctx, null_cipher_type, null_impl, key, iv, 1)){
    EVP_CIPHER_CTX_free(ctx);
    return AES_ERROR_EVP_CIPHER_INIT;
  }

  // Encrypts plaintext buffer and writes the encrypted cipher text. Can be called multiple times to encrypt successive blocks of data
  if(!EVP_CipherUpdate(ctx, ciphertext, &c_len, plaintext, plaintext_len)){
    EVP_CIPHER_CTX_free(ctx);
    return AES_ERROR_EVP_ENCRYPT_CIPHER_UPDATE;
  }

  if(c_len > ciphertext_len) {
    EVP_CIPHER_CTX_free(ctx);
    return AES_ERROR_BUFFER_OVERFLOW;
  }
  
  // If padding is enabled (the default) then EVP_EncryptFinal_ex() encrypts the final data
  if(!EVP_CipherFinal_ex(ctx, ciphertext+c_len, &f_len)){
    EVP_CIPHER_CTX_free(ctx);
    return AES_ERROR_EVP_ENCRYPT_CIPHER_FINAL;
  }

  *(encrypted_data_len) = c_len + f_len;
  EVP_CIPHER_CTX_free(ctx);
  return AES_NO_ERROR;
}

int AES_decrypt(const unsigned char key[], const unsigned char iv[],
		const unsigned char ciphertext[], unsigned int ciphertext_len,
		unsigned char plaintext[], unsigned int plaintext_len, 
		unsigned *unencrypted_data_len)
{
  if(ciphertext_len == 0) return AES_NO_ERROR;

  int f_len = 0;
  int p_len = 0;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if(!ctx){
    return  AES_ERROR_EVP_CTX_NEW;
  }

  const EVP_CIPHER *null_cipher_type = 0;
  ENGINE *null_impl = 0;
  const unsigned char *null_key = 0;
  const unsigned char *null_iv = 0;

  // Not setting key or IV here
  if(!EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), null_impl, null_key, null_iv, 0)){
    EVP_CIPHER_CTX_free(ctx);
    return AES_ERROR_EVP_CIPHER_INIT;
  }

  // Check key and IV lengths 
  OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == AES_256_KEY_SIZE);
  OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == AES_CBC_BLOCK_SIZE);

  // Set the key and IV
  if(!EVP_CipherInit_ex(ctx, null_cipher_type, null_impl, key, iv, 0)){
    EVP_CIPHER_CTX_free(ctx);
    return AES_ERROR_EVP_CIPHER_INIT;
  }

  if(!EVP_CipherUpdate(ctx, plaintext, &p_len, (const unsigned char*)ciphertext, ciphertext_len)) {
    EVP_CIPHER_CTX_free(ctx);
    return AES_ERROR_EVP_DECRYPT_CIPHER_UPDATE;
  }

  if(p_len > plaintext_len) {
    EVP_CIPHER_CTX_free(ctx);
    return AES_ERROR_BUFFER_OVERFLOW;
  }

  // If padding is enabled (the default) then EVP_EncryptFinal_ex() encrypts the final data
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
  // All others using = 256-bit AES
  
  unsigned len = *(buf_len);
  if(len == 0) return AES_NO_ERROR;

  unsigned char MODE[AES_MAX_MODE_LEN];
  AES_fillrand(MODE, sizeof(MODE));

  if(mode == 0) { // Signal non-encrypted buffer and return
    memset(MODE, 0, sizeof(MODE));
    memmove((buf+sizeof(MODE)), buf, len);
    memmove(buf, MODE, sizeof(MODE));
    len+=sizeof(MODE);
    *(buf_len) = len;
    return AES_NO_ERROR;
  }
  
  if(secret_len < 8) return AES_ERROR_SECRET_LENGTH;
  if(secret_len > 128) return AES_ERROR_SECRET_MAX_LENGTH;

  // Make a copy of the plaintext contents current passed in the buf variable
  char *new_buf = new char[len];
  if(!new_buf) return AES_ERROR_OUT_OF_MEMORY;
  memmove(new_buf, buf, len);

  AES_fillrand((unsigned char *)buf, len); // Clear the buffer

  // Set the salt
  int rv = AES_init_salt(SALT, SALT_len);
  if(rv != AES_NO_ERROR) {
    delete new_buf;
    return rv;
  }

  unsigned offset = 0;
  memmove(buf, MODE, sizeof(MODE));
  offset += sizeof(MODE);
  memmove((buf+offset), SALT, SALT_len);
  offset += SALT_len;

  memmove((buf+offset), VERIFIER, VERIFIER_len);
  offset += VERIFIER_len;

  rv = AES_derive_key((const unsigned char*)secret, secret_len, SALT, SALT_len, KEY, KEY_len, IV, IV_len, key_iterations);
  if(rv != AES_NO_ERROR) {
    delete new_buf;
    return rv;
  }

  unsigned encrypted_data_len = 0;
  unsigned char ciphertext[AES_CIPHERTEXT_BUF_SIZE];
  rv = AES_encrypt(KEY, IV, (const unsigned char*)new_buf, len, ciphertext, sizeof(ciphertext), &encrypted_data_len);
  if(rv != AES_NO_ERROR) {
    delete new_buf;
    return rv;
  }

  memmove((buf+offset), ciphertext, encrypted_data_len);
  offset += encrypted_data_len;

  rv = AES_HMAC(KEY, KEY_len, ciphertext, encrypted_data_len, HMAC, HMAC_len);
  if(rv != AES_NO_ERROR) {
    delete new_buf;
    return rv;
  }
  
  memmove((buf+offset), HMAC, HMAC_len);
  offset += HMAC_len;

  // Set the new buffer length
  *(buf_len) = offset;
  
  return AES_NO_ERROR;
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

  int rv = AES_Encrypt(buf, buf_len, secret, secret_len,
		       SALT, sizeof(SALT),
		       KEY, sizeof(KEY),
		       IV, sizeof(IV),
		       VERIFIER, sizeof(VERIFIER),
		       HMAC, sizeof(HMAC),
		       mode, key_iterations);

  // Clear all buffers and return
  AES_fillrand(SALT, sizeof(SALT));
  AES_fillrand(VERIFIER, sizeof(VERIFIER));
  AES_fillrand(HMAC, sizeof(HMAC));
  AES_fillrand(KEY, sizeof(KEY));
  AES_fillrand(IV, sizeof(IV));

  return rv;
}

int AES_Decrypt(char *buf, unsigned int *buf_len, const unsigned char secret[], unsigned secret_len,
		unsigned char SALT[], unsigned int SALT_len,
		unsigned char KEY[], unsigned int KEY_len,
		unsigned char IV[], unsigned int IV_len,
		unsigned char VERIFIER[], unsigned VERIFIER_len,
		unsigned char r_HMAC[], unsigned r_HMAC_len,
		unsigned int key_iterations)
// Decrypt a specified buffer of size "buf_len" with a secret key/password/passphrase
// ranging from 8 bytes to 128 bytes. Returns 0 if successful or a non-zero value to
// indicate an error condition.
{
  unsigned len = *(buf_len);
  if(len == 0) return AES_NO_ERROR;

  
  unsigned char MODE[AES_MAX_MODE_LEN];
  unsigned char r_MODE[AES_MAX_MODE_LEN]; // Recovered mode
  unsigned char HMAC[AES_MAX_HMAC_LEN];

  // Clear all buffers 
  AES_fillrand(MODE, sizeof(MODE));
  AES_fillrand(r_MODE, sizeof(r_MODE));
  AES_fillrand(SALT, SALT_len);
  AES_fillrand(VERIFIER, VERIFIER_len);
  AES_fillrand(r_HMAC, r_HMAC_len);
  AES_fillrand(HMAC, sizeof(HMAC));
  AES_fillrand(KEY, KEY_len);
  AES_fillrand(IV, IV_len);
  
  int rv = 0;
  unsigned offset = 0;
  memmove(r_MODE, buf, sizeof(r_MODE));
  offset += sizeof(r_MODE);

  // Mode 0 = Plain text, no encryption (debugging only)
  // All others using = 256-bit AES
  memset(MODE, 0, sizeof(MODE)); // Check for mode 0
  if(memcmp(MODE, r_MODE, sizeof(MODE)) == 0) { // Non-encrypted buffer for testing only 
    len -=  sizeof(MODE); 
    memmove(buf, (buf+offset), len);
    *(buf_len) = len;
    return AES_NO_ERROR;
  }
  
  if(secret_len < 8) return AES_ERROR_SECRET_LENGTH;
  if(secret_len > 128) return AES_ERROR_SECRET_MAX_LENGTH;
  
   // Recover the salt
  if(*(buf_len) < SALT_len) {
    return AES_ERROR_BUFFER_OVERFLOW;
  }
  memmove(SALT, (buf+offset), SALT_len);
  offset += SALT_len;

  rv = AES_derive_key((unsigned char *)secret, secret_len, SALT, SALT_len, KEY, KEY_len, IV, IV_len);
  if(rv != AES_NO_ERROR) {
    return rv;
  }

  // Recover the verifier
  if(*(buf_len) < (offset+VERIFIER_len)) {
    return AES_ERROR_BUFFER_OVERFLOW;
  }
  memmove(VERIFIER, (buf+offset), VERIFIER_len);
  offset += VERIFIER_len;

  // Recover the ciphertext, excluding the HMAC
  len -= (offset+r_HMAC_len);
  char *new_buf = new char[len];
  if(!new_buf) return AES_ERROR_OUT_OF_MEMORY;

  if(*(buf_len) < (offset+len)) {
    return AES_ERROR_BUFFER_OVERFLOW;
  }
  memmove(new_buf, (buf+offset), len);
  offset += len;

  // Unencrypt the data and verifiy it's contents
  rv = AES_HMAC(KEY, KEY_len, (const unsigned char*)new_buf, len, HMAC, sizeof(HMAC));
  if(rv != AES_NO_ERROR) {
    delete new_buf;
    return rv;
  }
 
  unsigned char plaintext[AES_PLAINTEXT_BUF_SIZE];
  unsigned unencrypted_data_len = 0;
  rv = AES_decrypt(KEY, IV, (const unsigned char*)new_buf, len, plaintext, sizeof(plaintext), &unencrypted_data_len);
  if(rv != AES_NO_ERROR) {
    delete new_buf;
    return rv;
  }
  
  // Recover and test the MAC value
  if(*(buf_len) < (offset+r_HMAC_len)) {
    return AES_ERROR_BUFFER_OVERFLOW;
  }

  memmove(r_HMAC, (buf+offset), r_HMAC_len);
  if(memcmp(HMAC, r_HMAC, r_HMAC_len) != 0) {
    delete new_buf;
    return AES_ERROR_AUTH_FAILED;
  }

  // Set the new buffer length and the buffer data
  *(buf_len) = unencrypted_data_len;
  memmove(buf, plaintext, unencrypted_data_len);
  memset(new_buf, 0, len);
  delete new_buf;

  return AES_NO_ERROR;
}

int AES_Decrypt(char *buf, unsigned int *buf_len, const unsigned char secret[], unsigned secret_len,
		unsigned int key_iterations)
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
		       key_iterations);

  // Clear all buffers and return
  AES_fillrand(SALT, sizeof(SALT));
  AES_fillrand(VERIFIER, sizeof(VERIFIER));
  AES_fillrand(HMAC, sizeof(HMAC));
  AES_fillrand(KEY, sizeof(KEY));
  AES_fillrand(IV, sizeof(IV));

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
		       b->key_iterations);
  return rv;
}

void AES_buf_t::Clear()
{
  memset(buf, 0, AES_CIPHER_STREAM_BUF_SIZE);
  buf_len = 0;
  memset(salt, 0, AES_MAX_SALT_LEN);
  memset(verifier, 0, AES_MAX_VERIFIER_LEN);
  memset(hmac, 0, AES_MAX_HMAC_LEN);
  memset(iv, 0, AES_MAX_IV_LEN);
  memset(key, 0, AES_MAX_KEY_LEN);
  memset(secret, 0, AES_MAX_SECRET_LEN);
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
    
