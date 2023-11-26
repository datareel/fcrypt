// Test RSA encryption code by encrypting and decrypting a single file buffer

#include <iostream>
using namespace std;

#include <rsadb.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int print_last_error(int RSADB_error_num = RSA_NO_ERROR, int error_level = -1)
{
  if(RSADB_error_num != RSA_NO_ERROR) {
    std::cerr << "ERROR: " << RSA_err_string(RSADB_error_num) << "\n" << std::flush;
  }

  int openssl_error_level;
  char *err = RSA_get_last_openssl_error(openssl_error_level);
  if(err) {
    if(openssl_error_level != 0) {
      std::cerr << err << "\n" << std::flush;
    }
    delete err;
  }

  return error_level;
}

int main(int argc, char *argv[])
{
  RSA_openssl_init();

  unsigned int i = 0;
  int rv = 0;
  
  const char *private_key_fname = "rsa_key.pem";
  const char *public_key_fname = "rsa_pubkey.pem";
  
  std::cout << "Creating RSA public and private keys" << "\n";
  
  rv = RSA_gen_key_files(private_key_fname, public_key_fname);
  if(rv != RSA_NO_ERROR) {
    return print_last_error(rv);
  }
  
  std::cout << "Reading the private key file" << "\n";

  char private_key[RSA_max_keybuf_len];
  unsigned private_key_len = 0;
  rv = RSA_read_key_file(private_key_fname, private_key, sizeof(private_key), &private_key_len);
  if(rv != RSA_NO_ERROR) {
    return print_last_error(rv);
  }

  cout << private_key << "\n";
  
  std::cout << "Reading the public key file" << "\n";
  char public_key[RSA_max_keybuf_len];
  unsigned public_key_len = 0;
  rv = RSA_read_key_file(public_key_fname, public_key, sizeof(public_key), &public_key_len);
  if(rv != RSA_NO_ERROR) {
    return print_last_error(rv);
  }

  cout << public_key << "\n";

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
  
  unsigned int encrypted_data_len, decrypted_data_len;
  
  std::cout << "\n";
  std::cout << "Public key encrypt" << "\n";

  rv = RSA_public_key_encrypt((const unsigned char *)public_key, public_key_len,
			      (unsigned char *)data, data_len, ciphertext, sizeof(ciphertext), &encrypted_data_len);
  if(rv != RSA_NO_ERROR) {
    return print_last_error(rv);
  }
  
  std::cout << "Encrypted length = " << encrypted_data_len << "\n";
  
  printf("Encrypted Data: "); for(i = 0; i <  encrypted_data_len; ++i) { printf("%02x",ciphertext[i]); } printf("\n");

  
  std::cout << "\n";
  std::cout << "Private key decrypt" << "\n";

  rv = RSA_private_key_decrypt((const unsigned char *)private_key, private_key_len,
			       ciphertext, encrypted_data_len, plaintext, sizeof(plaintext), &decrypted_data_len);
  if(rv != RSA_NO_ERROR) {
    return print_last_error(rv);
  }

  std::cout << "Decrypted text: " << plaintext << "\n";
  std::cout << "Decrypted Length = " << decrypted_data_len << "\n";
  
  memset(plaintext, 0, sizeof(plaintext));
  memset(ciphertext, 0, sizeof(ciphertext));

  std::cout << "\n";
  std::cout << "Private key encrypt" << "\n";
  rv = RSA_private_key_encrypt((const unsigned char *)private_key, private_key_len,
			       (unsigned char *)data, data_len, ciphertext, sizeof(ciphertext), &encrypted_data_len);
  if(rv != RSA_NO_ERROR) {
    return print_last_error(rv);
  }

  std::cout << "Encrypted length = " << encrypted_data_len << "\n";
  printf("Encrypted Data: "); for(i = 0; i <  encrypted_data_len; ++i) { printf("%02x",ciphertext[i]); } printf("\n");
  
  std::cout << "\n";
  std::cout << "Public key decrypt" << "\n";

  rv = RSA_public_key_decrypt((const unsigned char *)public_key, public_key_len,
			      ciphertext, encrypted_data_len, plaintext, sizeof(plaintext), &decrypted_data_len);
  if(rv != RSA_NO_ERROR) {
    return print_last_error(rv);
  }

  std::cout << "Decrypted text: " << plaintext << "\n";
  std::cout << "Decrypted Length = " << decrypted_data_len << "\n";
  
  char passphrase[RSA_passphrase_len];
  memset(passphrase, 0, sizeof(passphrase));
  strcpy(passphrase, "password");
  int my_passphrase_len = strlen(passphrase);
  
  char *private_key2_fname = "rsa_key2.pem";
  char *public_key2_fname = "rsa_pubkey2.pem";

  std::cout << "\n";
  std::cout << "Creating RSA public key and passphrase protected private key" << "\n";

  rv = RSA_gen_key_files(private_key2_fname, public_key2_fname, RSA_keysize, passphrase, my_passphrase_len);
  if(rv != 0) {
    std::cout << "ERROR: Could not write RSA key files " << private_key_fname << " and " << public_key_fname << "\n";
  }

  std::cout << "Reading the passphrase protected private key" << "\n";
  rv = RSA_read_key_file(private_key2_fname, private_key, sizeof(private_key), &private_key_len);
  if(rv != RSA_NO_ERROR) {
    return print_last_error(rv);
  }

  cout << private_key << "\n";
  
  std::cout << "Reading the public key" << "\n";
  rv = RSA_read_key_file(public_key2_fname, public_key, sizeof(public_key), &public_key_len);
  if(rv != RSA_NO_ERROR) {
    return print_last_error(rv);
  }

  cout << public_key << "\n";
  
  memset(plaintext, 0, sizeof(plaintext));
  memset(ciphertext, 0, sizeof(ciphertext));

  std::cout << "\n";
  std::cout << "Public key encrypt" << "\n";
  rv = RSA_public_key_encrypt((const unsigned char *)public_key, public_key_len,
			      (unsigned char *)data, data_len, ciphertext, sizeof(ciphertext), &encrypted_data_len);
  if(rv != RSA_NO_ERROR) {
    return print_last_error(rv);
  }

  std::cout << "Encrypted length = " << encrypted_data_len << "\n";
  
  printf("Encrypted Data: "); for(i = 0; i <  encrypted_data_len; ++i) { printf("%02x",ciphertext[i]); } printf("\n");
  
  std::cout << "\n";
  std::cout << "Private key decrypt with a passphrase provided" << "\n";
  rv = RSA_private_key_decrypt((const unsigned char *)private_key, private_key_len,
			       ciphertext, encrypted_data_len, plaintext, sizeof(plaintext), &decrypted_data_len,
			       RSA_padding, passphrase);
  if(rv != RSA_NO_ERROR) {
    return print_last_error(rv);
  }

  std::cout << "Decrypted text: " << plaintext << "\n";
  std::cout << "Decrypted Length = " << decrypted_data_len << "\n";

  std::cout << "Private key decrypt without a passphrase provided" << "\n";
  rv = RSA_private_key_decrypt((const unsigned char *)private_key, private_key_len,
			       ciphertext, encrypted_data_len, plaintext, sizeof(plaintext), &decrypted_data_len);
  if(rv != RSA_NO_ERROR) {
    return print_last_error(rv);
  }
  
  return 0;
}
