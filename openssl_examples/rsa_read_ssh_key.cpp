#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <iostream>
#include <stdio.h>
#include <string.h>

// Command to convert an openssh pubkey to pem format
// ssh-keygen -f ~/.ssh/id_rsa.pub -m 'PEM' -e

// OpenSSL command to convert an openssh private key to a pem format and write a pub key
// openssl rsa -in ~/.ssh/id_rsa -outform pem
// openssl rsa -in ~/.ssh/id_rsa -outform PEM -pubout

int print_last_error(char *message = 0, int error_level = -1)
{
  char err[1024];
  memset(err, 0, sizeof(err));
  ERR_load_crypto_strings();
  ERR_error_string(ERR_get_error(), err);
  if(message) std::cout << "ERROR: " << message << "\n";
  std::cout << err << "\n";
  return error_level;
}

int main(int argc, char *argv[])
{
  if(argc < 2) {
    std::cout << "ERROR: You must input file names for the private ssh-rsa key" << "\n"; 
    std::cout << "USEAGE: " << argv[0] << " ${HOME}/.ssh/id_rsa" << "\n"; 
    return 1;
  }

  char ssh_private_key_fname[256];
  memset(ssh_private_key_fname, 0, 256);
  strncpy(ssh_private_key_fname, argv[1], (sizeof(ssh_private_key_fname)-1));
  
  std::cout << "Reading the private key" << "\n";
  FILE *fp = fopen(ssh_private_key_fname,"rb");
  if(!fp) {
    std::cout << "Cannot open private key file " << ssh_private_key_fname << "\n";
    return -1;    
  }

  EVP_PKEY *private_key = EVP_PKEY_new();

  if(!PEM_read_PrivateKey(fp, &private_key, NULL, NULL)) {
    print_last_error();
    return 1;
  }

  RSA *rsa_private = RSA_new() ;
  rsa_private = EVP_PKEY_get1_RSA(private_key);
  if(!RSA_check_key(rsa_private)) {
    print_last_error();
    return 1;
  }

  // RSA_print_fp(stdout, rsa_private, 3);
  PEM_write_PrivateKey(stdout, private_key, NULL, NULL, 0, 0, NULL);
  PEM_write_PUBKEY(stdout, private_key);

  EVP_PKEY_free(private_key);
  RSA_free(rsa_private);
  fclose(fp);

  return 0;
}
