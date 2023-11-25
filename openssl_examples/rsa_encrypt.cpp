#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <iostream>
#include <stdio.h>
#include <string.h>

const int padding = RSA_PKCS1_PADDING;
const int keysize = 2048;
const unsigned int passphrase_len = 32;

int print_last_error(char *message = 0, int error_level = -1)
{
  char err[1024];
  memset(err, 0, sizeof(err));
  ERR_load_crypto_strings();
  ERR_error_string(ERR_get_error(), err);
  if(ERR_get_error() == 0) return 0;
  if(message) std::cout << "ERROR: " << message << "\n";
  std::cout << err << "\n";
  return error_level;
}

int passphrase_callback(char *buf, int size, int rwflag, void *userdata)
{
  // buf is the buffer to write the passphrase to
  // size is the maximum length of the passphrase
  // rwflag is a flag which is set to 0 when reading and 1 when writing
  // The u parameter has the same value as the u parameter passed to the PEM routine.
  // It allows arbitrary data to be passed to the callback by the application 
  
  std::cout << "In the passphrase_callback() function" << "\n";
  std::cout << "Max size = " << size << "\n";
  std::cout << "R/W flag = " << rwflag << "\n";

  // In this example program the passphrase string is passed in userdata
  char *passphrase = (char *)userdata;
  int len = strlen(passphrase);
  
  memcpy(buf, userdata, len);
  return len;
}

int gen_key_files(const char *private_key_fname, char *public_key_fname, char *passphrase, int passphrase_len)
{
  EVP_PKEY *key = EVP_PKEY_new();;
  if(!key) {
    return print_last_error("Error creating EVP key");
  }
  
  RSA *rsa = RSA_new();
  if(!rsa) {
    return print_last_error("Error creating RSA context");
  }

  BIGNUM *m_bignumber = BN_new(); 
  if(!m_bignumber) {
    return print_last_error("Error creating big number");
  }

  if(!BN_set_word(m_bignumber, RSA_F4)) { // init bignumber
    return print_last_error("Error init big number");
  }
  
  if(!RSA_generate_key_ex(rsa, keysize, m_bignumber, 0)) {
    return print_last_error("Error creating RSA key");
  }

  EVP_PKEY_set1_RSA(key, rsa);


  FILE *fp = fopen(private_key_fname, "w");
  if(!fp) {
    return -1;
  }

  if(passphrase) 
    PEM_write_PrivateKey(fp, key, EVP_aes_256_cbc(), (unsigned char*)passphrase, passphrase_len, 0, 0);
  else {
    PEM_write_PrivateKey(fp, key, 0, 0, 0, 0, 0);
  }
  fclose(fp);

  fp = fopen(public_key_fname, "w");
  if(!fp) {
    return -1;
  }

  PEM_write_RSA_PUBKEY(fp, rsa);
  
  fclose(fp);

  EVP_PKEY_free(key);
  RSA_free(rsa);
  BN_free(m_bignumber);
  return 0;
}

int main()
{
  OpenSSL_add_all_algorithms();
  int i = 0;
  int rv = 0;
  
  char *private_key_fname = "rsa_key.pem";
  char *public_key_fname = "rsa_pubkey.pem";
  
  std::cout << "Creating RSA public and private keys" << "\n";
  
  rv = gen_key_files(private_key_fname, public_key_fname, 0, 0);
  if(rv != 0) {
    std::cout << "ERROR: Could not write RSA key files " << private_key_fname << " and " << public_key_fname << "\n";
  }
  
  std::cout << "Reading the private key" << "\n";
  FILE *fp = fopen(private_key_fname,"rb");
  if(!fp) {
    std::cout << "Cannot open private key file " << private_key_fname << "\n";
    return -1;    
  }
  RSA *rsa_private = RSA_new() ;
  
  rsa_private = PEM_read_RSAPrivateKey(fp, &rsa_private, 0, 0);
  
  fclose(fp);
  
  std::cout << "Reading the public key" << "\n";
  fp = fopen(public_key_fname,"rb");
  if(!fp) {
    std::cout << "Cannot open public key file " << public_key_fname << "\n";
    return -1;    
  }
  
  RSA *rsa_public = RSA_new() ;
  rsa_public = PEM_read_RSA_PUBKEY(fp, &rsa_public, 0, 0);
  
  fclose(fp);
  
  char data[256];
  memset(data, 0, 255);
  strcpy(data, "The quick brown fox jumps over the lazy dog 0123456789");
  int data_len = strlen(data);
  
  std::cout << "Data: " << data << "\n";
  std::cout << "Size: " << data_len << "\n";
  
  unsigned char plaintext[1024];
  unsigned char ciphertext[2048];
  
  memset(plaintext, 0, sizeof(plaintext));
  memset(ciphertext, 0, sizeof(ciphertext));
  
  int encrypted_data_len, decrypted_data_len;
  
  std::cout << "\n";
  std::cout << "Public key encrypt" << "\n";
  encrypted_data_len = RSA_public_encrypt(data_len, (unsigned char *)data, ciphertext, rsa_public, padding);
  if(encrypted_data_len == -1) {
    std::cout << "Public key encrypt failed" << "\n";
    return -1;
  }
  std::cout << "Encrypted length = " << encrypted_data_len << "\n";
  
  printf("Encrypted Data: "); for(i = 0; i <  encrypted_data_len; ++i) { printf("%02x",ciphertext[i]); } printf("\n");
  
  std::cout << "\n";
  std::cout << "Private key decrypt" << "\n";
  decrypted_data_len = RSA_private_decrypt(encrypted_data_len, ciphertext, plaintext, rsa_private, padding);
  
  if(decrypted_data_len == -1) {
    std::cout << "Private key decrypt failed" << "\n";
    return -1;
  }
  std::cout << "Decrypted text: " << plaintext << "\n";
  std::cout << "Decrypted Length = " << decrypted_data_len << "\n";
  
  
  memset(plaintext, 0, sizeof(plaintext));
  memset(ciphertext, 0, sizeof(ciphertext));
  
  std::cout << "\n";
  std::cout << "Private key encrypt" << "\n";
  encrypted_data_len = RSA_private_encrypt(data_len, (unsigned char *)data, ciphertext, rsa_private, padding);
  if(encrypted_data_len == -1) {
    std::cout << "Private key encrypt failed" << "\n";
    return -1;
  }
  std::cout << "Encrypted length = " << encrypted_data_len << "\n";
  
  printf("Encrypted Data: "); for(i = 0; i <  encrypted_data_len; ++i) { printf("%02x",ciphertext[i]); } printf("\n");
  
  std::cout << "\n";
  std::cout << "Public key decrypt" << "\n";
  decrypted_data_len = RSA_public_decrypt(encrypted_data_len, ciphertext, plaintext, rsa_public, padding);

  if(decrypted_data_len == -1) {
    std::cout << "Public key decrypt failed" << "\n";
    return -1;
  }
  std::cout << "Decrypted text: " << plaintext << "\n";
  std::cout << "Decrypted Length = " << decrypted_data_len << "\n";
  
  RSA_free(rsa_private);
  RSA_free(rsa_public);
  
  char passphrase[passphrase_len];
  memset(passphrase, 0, sizeof(passphrase));
  strcpy(passphrase, "password");
  int my_passphrase_len = strlen(passphrase);
  
  char *private_key2_fname = "rsa_key2.pem";
  char *public_key2_fname = "rsa_pubkey2.pem";

  std::cout << "\n";
  std::cout << "Creating RSA public key and passphrase protected private key" << "\n";
  
  rv = gen_key_files(private_key2_fname, public_key2_fname, passphrase, my_passphrase_len);
  if(rv != 0) {
    std::cout << "ERROR: Could not write RSA key files " << private_key_fname << " and " << public_key_fname << "\n";
  }

  std::cout << "Reading the passphrase protected private key" << "\n";
  fp = fopen(private_key2_fname,"rb");
  if(!fp) {
    std::cout << "Cannot open private key file " << private_key2_fname << "\n";
    return -1;    
  }
  rsa_private = RSA_new() ;

  // For testing with incorrect passphrase
  // memset(passphrase, 0, sizeof(passphrase));
  // strcpy(passphrase, "bad_password");

  rsa_private = PEM_read_RSAPrivateKey(fp, &rsa_private, passphrase_callback, passphrase);
  if(!rsa_private) return print_last_error();

  fclose(fp);

  std::cout << "Reading the public key" << "\n";
  fp = fopen(public_key2_fname,"rb");
  if(!fp) {
    std::cout << "Cannot open public key file " << public_key2_fname << "\n";
    return -1;    
  }
  
  rsa_public = RSA_new() ;
  rsa_public = PEM_read_RSA_PUBKEY(fp, &rsa_public, 0, 0);
  if(!rsa_public) return print_last_error();

  fclose(fp);

  memset(plaintext, 0, sizeof(plaintext));
  memset(ciphertext, 0, sizeof(ciphertext));

  std::cout << "\n";
  std::cout << "Public key encrypt" << "\n";
  encrypted_data_len = RSA_public_encrypt(data_len, (unsigned char *)data, ciphertext, rsa_public, padding);
  if(encrypted_data_len == -1) {
    std::cout << "Public key encrypt failed" << "\n";
    return -1;
  }
  std::cout << "Encrypted length = " << encrypted_data_len << "\n";
  
  printf("Encrypted Data: "); for(i = 0; i <  encrypted_data_len; ++i) { printf("%02x",ciphertext[i]); } printf("\n");
  
  std::cout << "\n";
  std::cout << "Private key decrypt" << "\n";
  decrypted_data_len = RSA_private_decrypt(encrypted_data_len, ciphertext, plaintext, rsa_private, padding);
  
  if(decrypted_data_len == -1) {
    std::cout << "Private key decrypt failed" << "\n";
    return -1;
  }
  std::cout << "Decrypted text: " << plaintext << "\n";
  std::cout << "Decrypted Length = " << decrypted_data_len << "\n";

  RSA_free(rsa_private);
  RSA_free(rsa_public);

  return 0;
}
