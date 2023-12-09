#include <stdio.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#if OPENSSL_VERSION_NUMBER >= 0x00907000
#include <openssl/conf.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#endif

#include <iostream>

enum {
  X509_NO_ERROR = 0,
  X509_INVALID_ERROR,
  X509_ERROR_FILE_OPEN,
  X509_ERROR_FILE_READ,
  X509_ERROR_BUFFER_OVERFLOW
};

int X509_read_x509_file(const char *fname, char x509_file_buf[], const unsigned x509_file_buf_len, unsigned *x509_file_buf_final_len)
{
  memset(x509_file_buf, 0, x509_file_buf_len);

  FILE *fp;
  fp = fopen(fname, "rb");
  if(!fp) {
    return X509_ERROR_FILE_OPEN;
  }

  char read_buf[1024];
  unsigned input_bytes_read = 0;
  unsigned offset = 0;
  
  while(!feof(fp)) {
    memset(read_buf, 0, sizeof(read_buf));
    input_bytes_read = fread((unsigned char *)read_buf, 1, sizeof(read_buf), fp);
    if(input_bytes_read < 0) {
      fclose(fp);
      return X509_ERROR_FILE_READ;
    }
    if(offset > x509_file_buf_len) {
      return X509_ERROR_BUFFER_OVERFLOW;
    }
    memmove(x509_file_buf+offset, read_buf, input_bytes_read);
    offset += input_bytes_read;
  }

  *(x509_file_buf_final_len) = offset;
  
  memset(read_buf, 0, sizeof(read_buf));  

  fclose(fp);
  
  return X509_NO_ERROR;
}

int main(int argc, char *argv[])
{
  char fname[256];
  memset(fname, 0, 256);

  if(argc < 2) {
    printf("ERROR - You must specify an x509 PEM formatted input file to read\n");
    return 1;
  }

  strncpy(fname, argv[1], (sizeof(fname)-1));
  
  OpenSSL_add_all_algorithms();

  char x509_file_buf[8192];
  unsigned x509_file_buf_len = sizeof(x509_file_buf);
  unsigned x509_file_buf_final_len = 0;

  int rv = X509_read_x509_file((const char *)fname, x509_file_buf, x509_file_buf_len, &x509_file_buf_final_len);

  if(rv != X509_NO_ERROR) {
    std::cout << "ERROR: Error opening file " << fname << "\n";
  }

  BIO *keybio = BIO_new_mem_buf((const void *)x509_file_buf, x509_file_buf_final_len);
  X509 *x509 = PEM_read_bio_X509(keybio, NULL, NULL, NULL);

  EVP_PKEY *pkey=X509_get_pubkey(x509);
  
  // Write the public key in the X509 cert
  PEM_write_PUBKEY(stdout, pkey);

  EVP_PKEY_free(pkey);
  BIO_free(keybio);
  X509_free(x509);
    
  return 0;
}
