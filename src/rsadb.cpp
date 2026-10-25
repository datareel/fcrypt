// ------------------------------- //
// -------- start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- // 
// C++ Source Code File
// Compiler Used: MSVC, BCC32, GCC, HPUX aCC, SOLARIS CC
// Produced By: DataReel Software Development Team
// File Creation Date: 06/15/2003
// Date Last Modified: 10/24/2026
// Copyright (c) 2001-2026 DataReel Software Development
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

RSA encryption and decryption routines.
*/
// ----------------------------------------------------------- // 
#include <rsadb.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#if !defined (__WIN32__)
#include <unistd.h>
#endif

const int NUM_RSA_ERRORS = 27;
const char *RSA_err_strings[NUM_RSA_ERRORS] =
{
 "RSA_NO_ERROR",                     // RSA_NO_ERROR
 "RSA_INVALID_ERROR",                // RSA_INVALID_ERROR
 "RSA_ERROR_NULL_POINTER",           // RSA_ERROR_NULL_POINTER
 "RSA_ERROR_BUFFER_OVERFLOW",        // RSA_ERROR_BUFFER_OVERFLOW
 "RSA_ERROR_BAD_BUFFER_LEN",         // RSA_ERROR_BAD_BUFFER_LEN
 "RSA_ERROR_OUT_OF_MEMORY",          // RSA_ERROR_OUT_OF_MEMORY
 "RSA_ERROR_NEW",                    // RSA_ERROR_NEW
 "RSA_ERROR_EVP_KEY_CREATE",         // RSA_ERROR_EVP_KEY_CREATE
 "RSA_ERROR_CONTEXT_CREATE",         // RSA_ERROR_CONTEXT_CREATE
 "RSA_ERROR_BIG_NUMBER_CREATE",      // RSA_ERROR_BIG_NUMBER_CREATE
 "RSA_ERROR_BIG_NUMBER_INIT",        // RSA_ERROR_BIG_NUMBER_INIT
 "RSA_ERROR_GEN_KEY",                // RSA_ERROR_GEN_KEY
 "RSA_ERROR_PRIVATE_KEY_WRITE_FILE", // RSA_ERROR_PRIVATE_KEY_WRITE_FILE
 "RSA_ERROR_PRIVATE_KEY_READ_FILE",  // RSA_ERROR_PRIVATE_KEY_READ_FILE
 "RSA_ERROR_PRIVATE_KEY_READ",       // RSA_ERROR_PRIVATE_KEY_READ
 "RSA_ERROR_PUBLIC_KEY_WRITE_FILE",  // RSA_ERROR_PUBLIC_KEY_WRITE_FILE
 "RSA_ERROR_PUBLIC_KEY_READ_FILE",   // RSA_ERROR_PUBLIC_KEY_READ_FILE
 "RSA_ERROR_PUBLIC_KEY_READ",        // RSA_ERROR_PUBLIC_KEY_READ
 "RSA_ERROR_PRIVATE_KEY_ENCRYPT",    // RSA_ERROR_PRIVATE_KEY_ENCRYPT
 "RSA_ERROR_PRIVATE_KEY_DECRYPT",    // RSA_ERROR_PRIVATE_KEY_DECRYPT
 "RSA_ERROR_PUBLIC_KEY_ENCRYPT",     // RSA_ERROR_PUBLIC_KEY_ENCRYPT
 "RSA_ERROR_PUBLIC_KEY_DECRYPT",     // RSA_ERROR_PUBLIC_KEY_DECRYPT
 "RSA_ERROR_KEY_FILE_OPEN",          // RSA_ERROR_KEY_FILE_OPEN
 "RSA_ERROR_KEY_FILE_WRITE",         // RSA_ERROR_KEY_FILE_WRITE
 "RSA_ERROR_KEY_FILE_READ",          // RSA_ERROR_KEY_FILE_READ
 "RSA_ERROR_KEY_BUFFER_OVERFLOW",    // RSA_ERROR_KEY_BUFFER_OVERFLOW
 "RSA_ERROR_NEW_BIO_MEM_BUF"         // RSA_ERROR_NEW_BIO_MEM_BUF
};

const char *RSA_err_string(int err)
{
  if(err < 0) return RSA_err_strings[1];
  
  if(err > (NUM_RSA_ERRORS-1)) {
    return RSA_err_strings[1];
  }
  return RSA_err_strings[err];
  
}

int RSA_fillrand(unsigned char *buf, unsigned int len)
// Generates num random bytes using OpenSSL cryptographically secure pseudo random generator.
// Return the number of bytes filled or -1 for errors
{
  // RAND_bytes() and RAND_priv_bytes() return 1 on success, -1 if not supported by the current RAND method, or 0 on other failure.
  if(RAND_bytes(buf, len) != 1) return -1;
  return len;
}

int RSA_openssl_init()
{
  // OpenSSL 1.1.0 and later load all algorithms automatically
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  OpenSSL_add_all_algorithms();
#endif
  return 0;
}

char *RSA_get_last_openssl_error(int &error_level)
{
  char *err = new char[RSA_error_string_len];
  if(!err) {
    error_level = -1;
    return 0;
  }
  
  memset(err, 0, RSA_error_string_len);

  ERR_load_crypto_strings();
  ERR_error_string(ERR_get_error(), err);
  error_level = ERR_get_error();
  return err;
}

int RSA_passphrase_callback(char *buf, int size, int rwflag, void *userdata)
{
  // buf is the buffer to write the passphrase to                                                              
  // size is the maximum length of the passphrase                                                              
  // rwflag is a flag which is set to 0 when reading and 1 when writing                                        
  // The u parameter has the same value as the u parameter passed to the PEM routine.                          
  // It allows arbitrary data to be passed to the callback by the application                                  

  // In this callback funciton the passphrase string is passed in userdata.
  // buf must be large enough to hold the passphrase
  // userdata must be a null terminate string

  // 10/24/2026: Never write more than size bytes to buf
  if(!userdata || !buf || size <= 0) return 0;
  char *passphrase = (char *)userdata;
  size_t len = strlen(passphrase);
  if(len > (size_t)size) return 0;

  memcpy(buf, userdata, len);
  return (int)len;
}

// 10/25/2026: All RSA operations use the EVP_PKEY interface so they run
// through the loaded OpenSSL provider, including the FIPS provider. The
// low-level RSA_* calls are deprecated in OpenSSL 3 and bypass providers.
static EVP_PKEY *RSA_load_public_key(const unsigned char key[], unsigned key_len, char *passphrase)
{
  if(!key || key_len == 0 || key_len > RSA_max_keybuf_len) return 0;
  BIO *keybio = BIO_new_mem_buf((const void *)key, (int)key_len);
  if(!keybio) return 0;
  EVP_PKEY *pkey;
  if(!passphrase) {
    pkey = PEM_read_bio_PUBKEY(keybio, 0, 0, 0);
  }
  else {
    pkey = PEM_read_bio_PUBKEY(keybio, 0, RSA_passphrase_callback, passphrase);
  }
  BIO_free(keybio);
  return pkey;
}

static EVP_PKEY *RSA_load_private_key(const unsigned char key[], unsigned key_len, char *passphrase)
{
  if(!key || key_len == 0 || key_len > RSA_max_keybuf_len) return 0;
  BIO *keybio = BIO_new_mem_buf((const void *)key, (int)key_len);
  if(!keybio) return 0;
  EVP_PKEY *pkey;
  if(!passphrase) {
    pkey = PEM_read_bio_PrivateKey(keybio, 0, 0, 0);
  }
  else {
    pkey = PEM_read_bio_PrivateKey(keybio, 0, RSA_passphrase_callback, passphrase);
  }
  BIO_free(keybio);
  return pkey;
}

// RSA operations on an EVP_PKEY
enum { RSA_OP_ENCRYPT = 0, RSA_OP_DECRYPT, RSA_OP_SIGN, RSA_OP_VERIFY_RECOVER };

static int RSA_evp_op(int op, EVP_PKEY *pkey, int padding,
		      const unsigned char in[], unsigned int in_len,
		      unsigned char out[], unsigned int out_len,
		      unsigned *final_len)
// Returns 1 on success or 0 for errors. The result is written to a work
// buffer the size of the key first, so out only needs to hold the result.
{
  if(!pkey || !in || !out || !final_len) return 0;
  *(final_len) = 0;
  int key_size = EVP_PKEY_size(pkey);
  if(key_size <= 0) return 0;
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, 0);
  if(!ctx) return 0;

  int rv = 0;
  switch(op) {
    case RSA_OP_ENCRYPT: rv = EVP_PKEY_encrypt_init(ctx); break;
    case RSA_OP_DECRYPT: rv = EVP_PKEY_decrypt_init(ctx); break;
    case RSA_OP_SIGN: rv = EVP_PKEY_sign_init(ctx); break;
    case RSA_OP_VERIFY_RECOVER: rv = EVP_PKEY_verify_recover_init(ctx); break;
    default: break;
  }
  if(rv > 0) rv = EVP_PKEY_CTX_set_rsa_padding(ctx, padding);

  unsigned char *work = 0;
  size_t work_len = (size_t)key_size;
  if(rv > 0) {
    work = new unsigned char[work_len];
    if(!work) rv = 0;
  }
  if(rv > 0) {
    switch(op) {
      case RSA_OP_ENCRYPT: rv = EVP_PKEY_encrypt(ctx, work, &work_len, in, in_len); break;
      case RSA_OP_DECRYPT: rv = EVP_PKEY_decrypt(ctx, work, &work_len, in, in_len); break;
      case RSA_OP_SIGN: rv = EVP_PKEY_sign(ctx, work, &work_len, in, in_len); break;
      case RSA_OP_VERIFY_RECOVER: rv = EVP_PKEY_verify_recover(ctx, work, &work_len, in, in_len); break;
      default: rv = 0; break;
    }
  }
  if(rv > 0 && work_len > out_len) rv = 0;
  if(rv > 0) {
    memmove(out, work, work_len);
    *(final_len) = (unsigned)work_len;
  }
  if(work) {
    OPENSSL_cleanse(work, (size_t)key_size);
    delete[] work;
  }
  EVP_PKEY_CTX_free(ctx);
  return rv > 0 ? 1 : 0;
}

int RSA_pkey_encrypt(EVP_PKEY *pkey, const unsigned char plaintext[], unsigned int plaintext_len,
		     unsigned char ciphertext[], unsigned int ciphertext_len,
		     unsigned *encrypted_data_len, int padding)
{
  if(!RSA_evp_op(RSA_OP_ENCRYPT, pkey, padding, plaintext, plaintext_len,
		 ciphertext, ciphertext_len, encrypted_data_len)) {
    return RSA_ERROR_PUBLIC_KEY_ENCRYPT;
  }
  return RSA_NO_ERROR;
}

int RSA_pkey_decrypt(EVP_PKEY *pkey, const unsigned char ciphertext[], unsigned int ciphertext_len,
		     unsigned char plaintext[], unsigned int plaintext_len,
		     unsigned *unencrypted_data_len, int padding)
{
  if(!RSA_evp_op(RSA_OP_DECRYPT, pkey, padding, ciphertext, ciphertext_len,
		 plaintext, plaintext_len, unencrypted_data_len)) {
    return RSA_ERROR_PRIVATE_KEY_DECRYPT;
  }
  return RSA_NO_ERROR;
}

static FILE *RSA_open_key_file(const char *fname, int is_private)
// Private key files are created readable only by the owner
{
  if(!fname) return 0;
#if defined (__WIN32__)
  return fopen(fname, "w");
#else
  if(!is_private) return fopen(fname, "w");
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
  int fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, S_IRUSR | S_IWUSR);
  if(fd < 0) return 0;
  fchmod(fd, S_IRUSR | S_IWUSR);
  FILE *fp = fdopen(fd, "w");
  if(!fp) close(fd);
  return fp;
#endif
}

int RSA_gen_key_files(const char *private_key_fname, const char *public_key_fname, int keysize,
		      char *passphrase, int passphrase_len)
{
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, 0);
  if(!ctx) {
    return RSA_ERROR_CONTEXT_CREATE;
  }
  // The public exponent defaults to 65537 (RSA_F4)
  EVP_PKEY *key = 0;
  if(EVP_PKEY_keygen_init(ctx) <= 0 ||
     EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keysize) <= 0 ||
     EVP_PKEY_keygen(ctx, &key) <= 0 || !key) {
    EVP_PKEY_CTX_free(ctx);
    if(key) EVP_PKEY_free(key);
    return RSA_ERROR_GEN_KEY;
  }
  EVP_PKEY_CTX_free(ctx);

  FILE *fp = RSA_open_key_file(private_key_fname, 1);
  if(!fp) {
    EVP_PKEY_free(key);
    return RSA_ERROR_PRIVATE_KEY_WRITE_FILE;
  }

  int ok;
  if(passphrase) 
    ok = PEM_write_PrivateKey(fp, key, EVP_aes_256_cbc(), (unsigned char*)passphrase, passphrase_len, 0, 0);
  else {
    ok = PEM_write_PrivateKey(fp, key, 0, 0, 0, 0, 0);
  }
  if(fclose(fp) != 0) ok = 0;
  if(!ok) {
    EVP_PKEY_free(key);
    return RSA_ERROR_PRIVATE_KEY_WRITE_FILE;
  }

  fp = RSA_open_key_file(public_key_fname, 0);
  if(!fp) {
    EVP_PKEY_free(key);
    return RSA_ERROR_PUBLIC_KEY_WRITE_FILE;
  }

  // Same "BEGIN PUBLIC KEY" format PEM_write_RSA_PUBKEY wrote
  ok = PEM_write_PUBKEY(fp, key);
  if(fclose(fp) != 0) ok = 0;
  EVP_PKEY_free(key);
  if(!ok) return RSA_ERROR_PUBLIC_KEY_WRITE_FILE;

  return RSA_NO_ERROR;
}

int RSA_public_key_encrypt(const unsigned char key[], unsigned key_len,
			   const unsigned char plaintext[], unsigned int plaintext_len,
			   unsigned char ciphertext[], unsigned int ciphertext_len,
			   unsigned *encrypted_data_len, int padding, char *passphrase)
{
  EVP_PKEY *pkey = RSA_load_public_key(key, key_len, passphrase);
  if(!pkey) return RSA_ERROR_PUBLIC_KEY_READ;
  int rv = RSA_NO_ERROR;
  if(!RSA_evp_op(RSA_OP_ENCRYPT, pkey, padding, plaintext, plaintext_len,
		 ciphertext, ciphertext_len, encrypted_data_len)) {
    rv = RSA_ERROR_PUBLIC_KEY_ENCRYPT;
  }
  EVP_PKEY_free(pkey);
  return rv;
}

int RSA_private_key_decrypt(const unsigned char key[], unsigned key_len,
			    const unsigned char ciphertext[], unsigned int ciphertext_len,
			    unsigned char plaintext[], unsigned int plaintext_len,
			    unsigned *unencrypted_data_len,
			    int padding, char *passphrase)
{
  EVP_PKEY *pkey = RSA_load_private_key(key, key_len, passphrase);
  if(!pkey) return RSA_ERROR_PRIVATE_KEY_READ;
  int rv = RSA_NO_ERROR;
  if(!RSA_evp_op(RSA_OP_DECRYPT, pkey, padding, ciphertext, ciphertext_len,
		 plaintext, plaintext_len, unencrypted_data_len)) {
    rv = RSA_ERROR_PRIVATE_KEY_DECRYPT;
  }
  EVP_PKEY_free(pkey);
  return rv;
}

int RSA_private_key_encrypt(const unsigned char key[], unsigned key_len,
			    const unsigned char plaintext[], unsigned int plaintext_len,
			    unsigned char ciphertext[], unsigned int ciphertext_len,
			    unsigned *encrypted_data_len,
			    int padding, char *passphrase)
// Raw private key operation, same as the old RSA_private_encrypt()
{
  EVP_PKEY *pkey = RSA_load_private_key(key, key_len, passphrase);
  if(!pkey) return RSA_ERROR_PRIVATE_KEY_READ;
  int rv = RSA_NO_ERROR;
  if(!RSA_evp_op(RSA_OP_SIGN, pkey, padding, plaintext, plaintext_len,
		 ciphertext, ciphertext_len, encrypted_data_len)) {
    rv = RSA_ERROR_PRIVATE_KEY_ENCRYPT;
  }
  EVP_PKEY_free(pkey);
  return rv;
}

int RSA_public_key_decrypt(const unsigned char key[], unsigned key_len,
			   const unsigned char ciphertext[], unsigned int ciphertext_len,
			   unsigned char plaintext[], unsigned int plaintext_len,
			   unsigned *unencrypted_data_len,
			   int padding, char *passphrase)
// Raw public key operation, same as the old RSA_public_decrypt()
{
  EVP_PKEY *pkey = RSA_load_public_key(key, key_len, passphrase);
  if(!pkey) return RSA_ERROR_PUBLIC_KEY_READ;
  int rv = RSA_NO_ERROR;
  if(!RSA_evp_op(RSA_OP_VERIFY_RECOVER, pkey, padding, ciphertext, ciphertext_len,
		 plaintext, plaintext_len, unencrypted_data_len)) {
    rv = RSA_ERROR_PUBLIC_KEY_DECRYPT;
  }
  EVP_PKEY_free(pkey);
  return rv;
}

int RSA_read_key_file(const char *fname, char keybuf[], const unsigned keybuf_len, unsigned *keybuf_final_len, int *has_passphrase)
{
  memset(keybuf, 0, keybuf_len);

  FILE *fp;
  fp = fopen(fname, "rb");
  if(!fp) {
    return RSA_ERROR_KEY_FILE_OPEN;
  }

  char read_buf[1024];
  unsigned input_bytes_read = 0;
  unsigned offset = 0;
  
  while(!feof(fp)) {
    memset(read_buf, 0, sizeof(read_buf));
    input_bytes_read = fread((unsigned char *)read_buf, 1, sizeof(read_buf), fp);
    if(input_bytes_read < 0) {
      fclose(fp);
      return RSA_ERROR_KEY_FILE_READ;
    }
    // 10/24/2026: Check the space left before copying
    if(input_bytes_read > keybuf_len || offset > (keybuf_len - input_bytes_read)) {
      memset(read_buf, 0, sizeof(read_buf));
      fclose(fp);
      return RSA_ERROR_KEY_BUFFER_OVERFLOW;
    }
    memmove(keybuf+offset, read_buf, input_bytes_read);
    offset += input_bytes_read;
  }

  *(keybuf_final_len) = offset;
  
  memset(read_buf, 0, sizeof(read_buf));  

  if(has_passphrase) { // Check the key for a passpharse
    *(has_passphrase) = 0;
    const char *pattern1 = "ENCRYPTED";
    const char *pattern2 = "encrypted";
    
    if((RSA_find_pattern(keybuf, *(keybuf_final_len), pattern1, strlen(pattern1)) != -1) ||
       (RSA_find_pattern(keybuf, *(keybuf_final_len), pattern2, strlen(pattern2)) != -1)) {
      *(has_passphrase) = 1;
    }
  }
  
  fclose(fp);
  
  return RSA_NO_ERROR;
}

int RSA_find_pattern(const void *buf, int buf_len, const void *token, int token_len, int offset)
{
  if(!buf) return -1;
  if(offset > buf_len) return -1;
  if(token_len > buf_len) return -1;

  unsigned char *start = (unsigned char *)buf + offset; // Start of buf data
  unsigned char *next = start; // Next buffer element
  unsigned char *pattern = (unsigned char *)token; // Next pattern element
  int i = offset, j = 1; // Buffer and pattern indexes
  
  while(i < buf_len && j <= token_len) {
    if (*next == *pattern) {   // Matching character
      if(j == token_len) return i; // Entire match was found
      next++; pattern++; j++;
    }
    else { // Try next spot in buffer
      i++;
      start++;
      next = start;
      pattern = (unsigned char *)token; j = 1;
    }
  }
  return -1; // No match was found

}
// ----------------------------------------------------------- // 
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
    
