// OpenSSL example program

#include <iostream>
using namespace std;

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// OpenSSL include files
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

const unsigned AES_256_KEY_SIZE = 32;
const unsigned DEF_BUF_SIZE = 1024;

int main(int argc, char *argv[])
{
  const EVP_CIPHER *cipher;
  const EVP_MD *dgst = 0;
  int encrypt = 1;
  int decrypt = 0;
  
  unsigned char key[EVP_MAX_KEY_LENGTH];
  unsigned char iv[EVP_MAX_IV_LENGTH];
  unsigned char salt[8];
  unsigned int i =  0;
  int key_iterations = 1000;
  
  RAND_bytes(salt, sizeof(salt)); // Set the salt valus

  // Clear all buffers
  RAND_bytes(key, sizeof(key));
  RAND_bytes(iv, sizeof(iv));
    
  OpenSSL_add_all_algorithms();

  const char *password = "password";
  
  cipher = EVP_get_cipherbyname("aes-256-cbc");
  if(!cipher) {
    fprintf(stderr, "no such cipher\n"); return 1;
  }

  dgst = EVP_get_digestbyname("sha256");
  if(!dgst) {
    fprintf(stderr, "no such digest\n"); return 1;
  }

  if(!EVP_BytesToKey(cipher, dgst, salt, (unsigned char *) password, strlen(password), key_iterations, key, iv)) {
    fprintf(stderr, "EVP_BytesToKey failed\n");
    return 1;
  }

  cout << "Key len = " <<  EVP_CIPHER_key_length(cipher) << "\n";
  cout << "IV len = " <<  EVP_CIPHER_iv_length(cipher) << "\n";
  cout << "Salt len = " <<  sizeof(salt) << "\n";
  
  printf("Key: "); for(i=0; i < EVP_CIPHER_key_length(cipher); ++i) { printf("%02x", key[i]); } printf("\n");
  printf("IV: "); for(i=0; i <EVP_CIPHER_iv_length(cipher) ; ++i) { printf("%02x", iv[i]); } printf("\n");
  printf("Salt: "); for(i=0; i <  sizeof(salt); ++i) { printf("%02x", salt[i]); } printf("\n");
  
  unsigned char hash[32];
  char data[256];
  memset(data, 0, 255);
  strcpy(data, "The quick brown fox jumps over the lazy dog 0123456789");

  cout << "\n";
  cout << "Data: " <<  data << "\n";
  cout << "Data len: " << strlen(data) << "\n";
  
  HMAC_CTX *hmac = HMAC_CTX_new();
  HMAC_Init_ex(hmac, key, EVP_CIPHER_key_length(cipher), EVP_sha256(), 0);
  HMAC_Update(hmac, (const unsigned char *)data, strlen(data));
  unsigned int len = 32;
  HMAC_Final(hmac, hash, &len);
  HMAC_CTX_free(hmac);

  cout << "\n";
  printf("HMAC: "); for(i = 0; i <  sizeof(hash); ++i) { printf("%02x", hash[i]); } printf("\n");

  int cipher_block_size = EVP_CIPHER_block_size(cipher);

  int c_len = DEF_BUF_SIZE + cipher_block_size;
  int f_len = 0;

  unsigned char *ciphertext = new unsigned char[c_len];
  
  cout << "cipher_block_size: " << cipher_block_size  << "\n";
  cout << "Crypt buf len: " << c_len << "\n";
  
  EVP_CIPHER_CTX *e_ctx = 0;
  EVP_CIPHER_CTX *d_ctx = 0;
  
  e_ctx = EVP_CIPHER_CTX_new();
  if(!e_ctx){
    fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), 0));
    return -1;
  }

  const EVP_CIPHER *null_cipher_type = 0;
  ENGINE *null_impl = 0;
  const unsigned char *null_key = 0;
  const unsigned char *null_iv = 0;
  
  // Don't set key or IV right away; we want to check lengths 
  if(!EVP_CipherInit_ex(e_ctx, cipher, null_impl, null_key, null_iv, encrypt)){
    fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), 0));
    return -1;
  }
  
  OPENSSL_assert(EVP_CIPHER_CTX_key_length(e_ctx) == AES_256_KEY_SIZE);
  OPENSSL_assert(EVP_CIPHER_CTX_iv_length(e_ctx) == AES_BLOCK_SIZE);

  // Now we can set key and IV
  if(!EVP_CipherInit_ex(e_ctx, null_cipher_type, null_impl, key, iv, encrypt)){
    fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), 0));
    EVP_CIPHER_CTX_cleanup(e_ctx);
    return -1;
  }
  
  // Encrypts buffer in and writes the encrypted version. This function can be called multiple times to encrypt successive blocks of data
  if(!EVP_CipherUpdate(e_ctx, ciphertext, &c_len, (const unsigned char*)data, strlen(data))){
    fprintf(stderr, "ERROR: EVP_CipherUpdate failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), 0));
    EVP_CIPHER_CTX_cleanup(e_ctx);
    return -1;
  }

  
  // If padding is enabled (the default) then EVP_EncryptFinal_ex() encrypts the final data
  if(!EVP_CipherFinal_ex(e_ctx, ciphertext+c_len, &f_len)){
     fprintf(stderr, "ERROR: EVP_CipherFinal_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), 0));
    EVP_CIPHER_CTX_cleanup(e_ctx);
    return -1;
  }

  unsigned encrypted_data_len = c_len + f_len;
  
  cout << "\n";
  cout << "Encrypted Data Length: " << encrypted_data_len << "\n";

  printf("Encrypted Data: "); for(i = 0; i <  encrypted_data_len; ++i) { printf("%02x",ciphertext[i]); } printf("\n");

  
  EVP_CIPHER_CTX_cleanup(e_ctx);
  unsigned char *plaintext = new unsigned char[DEF_BUF_SIZE];
  f_len = 0;
  int p_len = 0;
  
  d_ctx = EVP_CIPHER_CTX_new();
  if(!d_ctx){
    fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), 0));
    return -1;
  }
  
  // Don't set key or IV right away; we want to check lengths 
  if(!EVP_CipherInit_ex(d_ctx, cipher, null_impl, null_key, null_iv, decrypt)){
    fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), 0));
    return -1;
  }
  
  OPENSSL_assert(EVP_CIPHER_CTX_key_length(d_ctx) == AES_256_KEY_SIZE);
  OPENSSL_assert(EVP_CIPHER_CTX_iv_length(d_ctx) == AES_BLOCK_SIZE);
  
  // Now we can set key and IV
  if(!EVP_CipherInit_ex(d_ctx, null_cipher_type, null_impl, key, iv, decrypt)){
    fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), 0));
    EVP_CIPHER_CTX_cleanup(d_ctx);
    return -1;
  }
  
  
  if(!EVP_CipherUpdate(d_ctx, plaintext, &p_len, (const unsigned char*)ciphertext, encrypted_data_len)) {
    fprintf(stderr, "ERROR: EVP_CipherUpdate failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), 0));
    EVP_CIPHER_CTX_cleanup(d_ctx);
    return -1;
  }
  
  // If padding is enabled (the default) then EVP_EncryptFinal_ex() encrypts the final data
  if(!EVP_CipherFinal_ex(d_ctx, plaintext+p_len, &f_len)){
    fprintf(stderr, "ERROR: EVP_CipherFinal_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), 0));
    EVP_CIPHER_CTX_cleanup(d_ctx);
    return -1;
  }
  
  unsigned unencrypted_data_len = p_len + f_len;

  cout << "\n";
  cout << "Unencrypted data len: " << unencrypted_data_len << "\n";

  unsigned char d_hash[32];
  HMAC_CTX *d_hmac = HMAC_CTX_new();
  HMAC_Init_ex(d_hmac, key, EVP_CIPHER_key_length(cipher), EVP_sha256(), 0);
  HMAC_Update(d_hmac, (const unsigned char *)plaintext, unencrypted_data_len);
  len = 32;
  HMAC_Final(d_hmac, d_hash, &len);
  HMAC_CTX_free(d_hmac);

  cout << "\n";
  printf("HMAC: "); for(i = 0; i <  sizeof(d_hash); ++i) { printf("%02x", d_hash[i]); } printf("\n");

  plaintext[unencrypted_data_len] = 0;
  cout << "Unencrypted data: " <<  plaintext << "\n";

  EVP_CIPHER_CTX_cleanup(d_ctx);

  delete[] ciphertext;
  delete[] plaintext;
  return 0;
}
    
