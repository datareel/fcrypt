// Openssl example program

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

int main(int argc, char *argv[])
{
  const EVP_CIPHER *cipher;
  const EVP_MD *dgst = 0;
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
  
  const EVP_CIPHER *cipher2;
  
  RAND_bytes(key, sizeof(key));
  RAND_bytes(iv, sizeof(iv));
  
  cipher2 = EVP_get_cipherbyname("aes-256-cbc");
  if(!cipher2) { fprintf(stderr, "no such cipher\n"); return 1; }
  
  if(!EVP_BytesToKey(cipher2, dgst, salt, (unsigned char *) password, strlen(password), key_iterations, key, iv)) {
    fprintf(stderr, "EVP_BytesToKey failed\n");
    return 1;
  }
  
  printf("Key from password and salt: "); for(i=0; i < EVP_CIPHER_key_length(cipher2); ++i) { printf("%02x", key[i]); } printf("\n");
  printf("IV from password and salt: "); for(i=0; i <EVP_CIPHER_iv_length(cipher2) ; ++i) { printf("%02x", iv[i]); } printf("\n");

  unsigned char hash[32], hash2[32];
  char data[256];
  memset(data, 0, 255);
  strcpy(data, "The quick brown fox jumps over the lazy dog 0123456789");

  HMAC_CTX *hmac = 0;
  // grep OPENSSL_VERSION_NUMBER /usr/include/openssl/opensslv.h
#if OPENSSL_VERSION_NUMBER < 0x101010bfL
  std::cout << "Calling HMAC_CTX_init()" << "\n";
  HMAC_CTX hmac_ob;
  hmac = &hmac_ob;
  HMAC_CTX_init(hmac);
#else  
  std::cout << "Calling HMAC_CTX_new()" << "\n";
  hmac = HMAC_CTX_new();
#endif

  HMAC_Init_ex(hmac, key, EVP_CIPHER_key_length(cipher2), EVP_sha256(), 0);
  HMAC_Update(hmac, (const unsigned char *)data, strlen(data));
  unsigned int len = 32;
  HMAC_Final(hmac, hash, &len);
#if OPENSSL_VERSION_NUMBER < 0x101010bfL
  std::cout << "Calling HMAC_CTX_cleanup()" << "\n";
  HMAC_CTX_cleanup(hmac);
#else
  std::cout << "Calling HMAC_CTX_free()" << "\n";
  HMAC_CTX_free(hmac);
#endif

  cout << "\n";
  
  printf("HMAC: "); for(i = 0; i <  sizeof(hash); ++i) { printf("%02x", hash[i]); } printf("\n");
  HMAC_CTX *hmac2 = 0;
#if OPENSSL_VERSION_NUMBER < 0x101010bfL
  HMAC_CTX hmac_ob2;
  hmac2 = &hmac_ob2;
  HMAC_CTX_init(hmac2);
#else
  HMAC_CTX *hmac2 = HMAC_CTX_new();
#endif

  HMAC_Init_ex(hmac2, key, EVP_CIPHER_key_length(cipher2), EVP_sha256(), 0);
  HMAC_Update(hmac2, (const unsigned char *)data, strlen(data));
  len = 32;
  HMAC_Final(hmac2, hash2, &len);
#if OPENSSL_VERSION_NUMBER < 0x101010bfL
  HMAC_CTX_cleanup(hmac2);
#else
  HMAC_CTX_free(hmac2);
#endif

  printf("HMAC from key: "); for(i = 0; i <  sizeof(hash2); ++i) { printf("%02x", hash2[i]); } printf("\n");
  
  return 0;
}
    
