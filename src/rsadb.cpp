// ------------------------------- //
// -------- start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- // 
// C++ Source Code File
// Compiler Used: MSVC, BCC32, GCC, HPUX aCC, SOLARIS CC
// Produced By: DataReel Software Development Team
// File Creation Date: 06/15/2003
// Date Last Modified: 11/25/2023
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

RSA encryption and decryption routines.
*/
// ----------------------------------------------------------- // 
#include <rsadb.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  OpenSSL_add_all_algorithms();
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

  char *passphrase = (char *)userdata;
  int len = strlen(passphrase);

  memcpy(buf, userdata, len);
  return len;
}

int RSA_gen_key_files(const char *private_key_fname, const char *public_key_fname, int keysize,
		      char *passphrase, int passphrase_len)
{
  EVP_PKEY *key = EVP_PKEY_new();;
  if(!key) {
    return RSA_ERROR_EVP_KEY_CREATE;
  }
  
  RSA *rsa = RSA_new();
  if(!rsa) {
    EVP_PKEY_free(key);
    return RSA_ERROR_CONTEXT_CREATE;
  }

  BIGNUM *m_bignumber = BN_new(); 
  if(!m_bignumber) {
    EVP_PKEY_free(key);
    RSA_free(rsa);
    return RSA_ERROR_BIG_NUMBER_CREATE;
  }

  if(!BN_set_word(m_bignumber, RSA_F4)) { // init bignumber
    EVP_PKEY_free(key);
    RSA_free(rsa);
    BN_free(m_bignumber);
    return RSA_ERROR_BIG_NUMBER_INIT;
  }
  
  if(!RSA_generate_key_ex(rsa, keysize, m_bignumber, 0)) {
    EVP_PKEY_free(key);
    RSA_free(rsa);
    BN_free(m_bignumber);
    return RSA_ERROR_GEN_KEY;
  }

  EVP_PKEY_set1_RSA(key, rsa);

  FILE *fp = fopen(private_key_fname, "w");
  if(!fp) {
    EVP_PKEY_free(key);
    RSA_free(rsa);
    BN_free(m_bignumber);
    return RSA_ERROR_PRIVATE_KEY_WRITE_FILE;
  }

  if(passphrase) 
    PEM_write_PrivateKey(fp, key, EVP_aes_256_cbc(), (unsigned char*)passphrase, passphrase_len, 0, 0);
  else {
    PEM_write_PrivateKey(fp, key, 0, 0, 0, 0, 0);
  }
  fclose(fp);

  fp = fopen(public_key_fname, "w");
  if(!fp) {
    EVP_PKEY_free(key);
    RSA_free(rsa);
    BN_free(m_bignumber);
    return RSA_ERROR_PUBLIC_KEY_WRITE_FILE;
  }

  PEM_write_RSA_PUBKEY(fp, rsa);
  
  fclose(fp);

  EVP_PKEY_free(key);
  RSA_free(rsa);
  BN_free(m_bignumber);

  return RSA_NO_ERROR;
}

int RSA_public_key_encrypt(const unsigned char key[], unsigned key_len,
			   const unsigned char plaintext[], unsigned int plaintext_len,
			   unsigned char ciphertext[], unsigned int ciphertext_len,
			   unsigned *encrypted_data_len, int padding, char *passphrase)
{
  RSA *rsa = RSA_new();
  if(!rsa) {
    return RSA_ERROR_NEW;
  }
  
  BIO *keybio = BIO_new_mem_buf((const void *)key, (int)key_len);
  if(!keybio) {
    RSA_free(rsa);
    return  RSA_ERROR_NEW_BIO_MEM_BUF;
  }

  if(!passphrase) {
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, 0, 0);
  }
  else {
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, RSA_passphrase_callback, passphrase);
  }

  if(!rsa) {
    BIO_free(keybio);
    return RSA_ERROR_PUBLIC_KEY_READ;
  }
  
  int len = RSA_public_encrypt(plaintext_len, plaintext, ciphertext, rsa, padding);
  if(len == -1) {
    BIO_free(keybio);
    RSA_free(rsa);
    return RSA_ERROR_PUBLIC_KEY_ENCRYPT;
  }
  *(encrypted_data_len) = len;

  BIO_free(keybio);
  RSA_free(rsa);
  return RSA_NO_ERROR;
}

int RSA_private_key_decrypt(const unsigned char key[], unsigned key_len,
			    const unsigned char ciphertext[], unsigned int ciphertext_len,
			    unsigned char plaintext[], unsigned int plaintext_len,
			    unsigned *unencrypted_data_len,
			    int padding, char *passphrase)
{
  RSA *rsa = RSA_new();
  if(!rsa) {
    return RSA_ERROR_NEW;
  }
  
  BIO *keybio = BIO_new_mem_buf((const void *)key, (int)key_len);
  if(!keybio) {
    RSA_free(rsa);
    return  RSA_ERROR_NEW_BIO_MEM_BUF;
  }

  if(!passphrase) {
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, 0, 0);
  }
  else {
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, RSA_passphrase_callback, passphrase);
  }

  if(!rsa) {
    BIO_free(keybio);
    return RSA_ERROR_PRIVATE_KEY_READ;
  }

  int len = RSA_private_decrypt(ciphertext_len, ciphertext, plaintext, rsa, padding);
  if(len == -1)	{
    BIO_free(keybio);
    RSA_free(rsa);

    return RSA_ERROR_PRIVATE_KEY_DECRYPT;
  }
  
  *(unencrypted_data_len) = len;
  
  BIO_free(keybio);
  RSA_free(rsa);
  return RSA_NO_ERROR;
}

int RSA_private_key_encrypt(const unsigned char key[], unsigned key_len,
			    const unsigned char plaintext[], unsigned int plaintext_len,
			    unsigned char ciphertext[], unsigned int ciphertext_len,
			    unsigned *encrypted_data_len,
			    int padding, char *passphrase)
{
  RSA *rsa = RSA_new();
  if(!rsa) {
    return RSA_ERROR_NEW;
  }
  
  BIO *keybio = BIO_new_mem_buf((const void *)key, (int)key_len);
  if(!keybio) {
    RSA_free(rsa);
    return  RSA_ERROR_NEW_BIO_MEM_BUF;
  }

  if(!passphrase) {
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, 0, 0);
  }
  else {
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, RSA_passphrase_callback, passphrase);
  }

  if(!rsa) {
    BIO_free(keybio);
    return RSA_ERROR_PRIVATE_KEY_READ;
  }
  
  int len = RSA_private_encrypt(plaintext_len, plaintext, ciphertext, rsa, padding);
  if(len == -1) {
    BIO_free(keybio);
    RSA_free(rsa);
    return RSA_ERROR_PRIVATE_KEY_ENCRYPT;
  }
  *(encrypted_data_len) = len;

  BIO_free(keybio);
  RSA_free(rsa);
  return RSA_NO_ERROR;
}

int RSA_public_key_decrypt(const unsigned char key[], unsigned key_len,
			   const unsigned char ciphertext[], unsigned int ciphertext_len,
			   unsigned char plaintext[], unsigned int plaintext_len,
			   unsigned *unencrypted_data_len,
			   int padding, char *passphrase)
{
  RSA *rsa = RSA_new();
  if(!rsa) {
    return RSA_ERROR_NEW;
  }
  
  BIO *keybio = BIO_new_mem_buf((const void *)key, (int)key_len);
  if(!keybio) {
    RSA_free(rsa);
    return  RSA_ERROR_NEW_BIO_MEM_BUF;
  }

  if(!passphrase) {
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, 0, 0);
  }
  else {
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, RSA_passphrase_callback, passphrase);
  }

  if(!rsa) {
    BIO_free(keybio);
    return RSA_ERROR_PUBLIC_KEY_READ;
  }

  int len = RSA_public_decrypt(ciphertext_len, ciphertext, plaintext, rsa, padding);
  if(len == -1)	{
    BIO_free(keybio);
    RSA_free(rsa);
    return RSA_ERROR_PUBLIC_KEY_DECRYPT;
  }
  
  *(unencrypted_data_len) = len;
  
  BIO_free(keybio);
  RSA_free(rsa);
  return RSA_NO_ERROR;
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
    if(offset > keybuf_len) {
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
    
