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

  std::cout << "Key len = " <<  EVP_CIPHER_key_length(cipher) << "\n";
  std::cout << "IV len = " <<  EVP_CIPHER_iv_length(cipher) << "\n";
  std::cout << "Salt len = " <<  sizeof(salt) << "\n";
  
  printf("Derived Key: "); for(i=0; i < EVP_CIPHER_key_length(cipher); ++i) { printf("%02x", key[i]); } printf("\n");
  printf("Initialization Vector: "); for(i=0; i <EVP_CIPHER_iv_length(cipher) ; ++i) { printf("%02x", iv[i]); } printf("\n");
  printf("Stored Salt: "); for(i=0; i <  sizeof(salt); ++i) { printf("%02x", salt[i]); } printf("\n");
  
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
  
  return 0;
}
    
