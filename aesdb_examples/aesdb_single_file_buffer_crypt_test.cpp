// Test AES encryption code by encrypting and decrypting a single file buffer

#include <iostream>
using namespace std;

#include <aesdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int main(int argc, char *argv[])
{
  FILE *f_src, *f_enc, *f_dec;
  char fname[256];
  memset(fname, 0, 256);
  strcpy(fname, "testfile1.txt");

  char ecfname[256];
  memset(ecfname, 0, 256);
  strcpy(ecfname, "testfile1.enc");
  
  char dcfname[256];
  memset(dcfname, 0, 256);
  strcpy(dcfname, "testfile1.dec");

  cout << "Source file: " << fname << "\n";
  f_src = fopen(fname, "rb");
  if (!f_src) {
    fprintf(stderr, "ERROR: Cannot open file : %s\n", fname);
    fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
    return errno;
  }

  cout << "Encrypted file: " << ecfname << "\n";
  f_enc = fopen(ecfname, "wb");
  if (!f_enc) {
    fprintf(stderr, "ERROR: Cannot open file : %s\n", ecfname);
    fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
    return errno;
  }

  unsigned int i =  0;
  int rv = 0;

  const char *password = "password";
  unsigned password_len = strlen(password);

  unsigned num_bytes_read = 0;
  char buf[AES_CIPHERTEXT_BUF_SIZE];
  unsigned int buf_len = 0;
  
  // Reading in the whole file for testing only
  num_bytes_read = fread(buf, sizeof(unsigned char), AES_PLAINTEXT_BUF_SIZE, f_src);
  if(ferror(f_src)) {
    fprintf(stderr, "ERROR: Read error: %s\n", fname);
    fprintf(stderr, "ERROR: fread error: %s\n", strerror(errno));
    return errno;
  }
  buf_len = num_bytes_read;
  
  unsigned char SALT[AES_MAX_SALT_LEN];
  unsigned char VERIFIER[AES_MAX_VERIFIER_LEN];
  unsigned char HMAC[AES_MAX_HMAC_LEN];
  unsigned char IV[AES_MAX_IV_LEN];
  unsigned char KEY[AES_MAX_KEY_LEN];
  int key_iterations = AES_DEF_ITERATIONS;
  int mode = -1;

  rv = AES_Encrypt(buf, &buf_len, (const unsigned char *)password, strlen(password),
		   SALT, sizeof(SALT),
		   KEY, sizeof(KEY),
		   IV, sizeof(IV),
		   VERIFIER, sizeof(VERIFIER),
		   HMAC, sizeof(HMAC),
		   mode, key_iterations);

  if(rv != AES_NO_ERROR) {
    cout << AES_err_string(rv) << "\n";
    return rv;
  }
    
  cout << "Key len = " <<  EVP_CIPHER_key_length(EVP_get_cipherbyname("aes-256-cbc")) << "\n";
  cout << "IV len = " <<  EVP_CIPHER_iv_length(EVP_get_cipherbyname("aes-256-cbc")) << "\n";
  cout << "Salt len = " <<  sizeof(SALT) << "\n";
  cout << "HMAC len = " <<  sizeof(HMAC) << "\n";
  
  cout << "\n";
  printf("Key: "); for(i=0; i < EVP_CIPHER_key_length(EVP_get_cipherbyname("aes-256-cbc")); ++i) { printf("%02x", KEY[i]); } printf("\n");
  printf("IV: "); for(i=0; i < EVP_CIPHER_iv_length(EVP_get_cipherbyname("aes-256-cbc")); ++i) { printf("%02x", IV[i]); } printf("\n");
  printf("Salt: "); for(i=0; i <  sizeof(SALT); ++i) { printf("%02x", SALT[i]); } printf("\n");
  printf("HMAC: "); for(i = 0; i <  sizeof(HMAC); ++i) { printf("%02x", HMAC[i]); } printf("\n");

  cout << "Encrypted Stream Length: " << buf_len << "\n";
  printf("Encrypted Stream: "); for(i = 0; i <  buf_len; ++i) { printf("%02x",buf[i]); } printf("\n");
  
  fwrite((const void*)buf, sizeof(unsigned char), buf_len, f_enc);
  if(ferror(f_enc)) {
    fprintf(stderr, "ERROR: Error writing encrypted message stream to file: %s\n", ecfname);
    fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
    return errno;
  }

  // Clear the buffer
  AES_fillrand((unsigned char *)buf, AES_CIPHERTEXT_BUF_SIZE);
  AES_fillrand(SALT, sizeof(SALT));
  AES_fillrand(VERIFIER, sizeof(VERIFIER));
  AES_fillrand(HMAC, sizeof(HMAC));
  AES_fillrand(KEY, sizeof(KEY));
  AES_fillrand(IV, sizeof(IV));

  fclose(f_src);
  fclose(f_enc);
  
  f_enc = fopen(ecfname, "rb");
  if (!f_enc) {
    fprintf(stderr, "ERROR: Cannot open file : %s\n", ecfname);
    fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
    return errno;
  }

  cout << "\n";
  cout << "Decrypted file: " << dcfname << "\n";
  f_dec = fopen(dcfname, "wb");
  if (!f_dec) {
    fprintf(stderr, "ERROR: Cannot open file : %s\n", dcfname);
    fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
    return errno;
  }

  num_bytes_read = fread(buf, sizeof(unsigned char), AES_CIPHERTEXT_BUF_SIZE, f_enc);
  if (ferror(f_enc)){
    fprintf(stderr, "ERROR: Read error: %s\n", ecfname);
    fprintf(stderr, "ERROR: fread error: %s\n", strerror(errno));
    return errno;
  }

  buf_len = num_bytes_read;

  rv = AES_Decrypt(buf, &buf_len, (unsigned char *)password, strlen(password),
		   SALT, sizeof(SALT),
		   KEY, sizeof(KEY),
		   IV, sizeof(IV),
		   VERIFIER, sizeof(VERIFIER),
		   HMAC, sizeof(HMAC),
		   key_iterations);
  
  if(rv != AES_NO_ERROR) {
    cout << AES_err_string(rv) << "\n";
    return rv;
  }
    
  cout << "\n";
  cout << "Bytes read " <<  num_bytes_read << "\n";
  cout << "Decrypted buf len " << buf_len << "\n";
  printf("Salt from file: "); for(i=0; i <  sizeof(SALT); ++i) { printf("%02x", SALT[i]); } printf("\n");
  
  printf("Derypt Key: "); for(i=0; i < EVP_CIPHER_key_length(EVP_get_cipherbyname("aes-256-cbc")); ++i) { printf("%02x", KEY[i]); } printf("\n");
  printf("Decrypt IV: "); for(i=0; i < EVP_CIPHER_iv_length(EVP_get_cipherbyname("aes-256-cbc")); ++i) { printf("%02x", IV[i]); } printf("\n");
  printf("HMAC from file: "); for(i=0; i <  sizeof(HMAC); ++i) { printf("%02x", HMAC[i]); } printf("\n");
  
  cout << "\n";
  cout << "Unencrypted data len: " << buf_len << "\n";

  fwrite((const void*)buf, sizeof(unsigned char), buf_len, f_dec);
  if (ferror(f_enc)) {
    fprintf(stderr, "ERROR: Error writing decrypted data buffer to file: %s\n", dcfname);
    fprintf(stderr, "ERROR: Write error: %s\n", strerror(errno));
    return errno;
  }

  fclose(f_dec);
  fclose(f_enc);

  buf[buf_len] = 0;
  cout << "Unencrypted data: " << buf << "\n";

  return 0;
}
