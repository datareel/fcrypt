#include <iostream>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include <string.h>
#include <stdio.h>

using namespace std;

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

int main()
{
    OpenSSL_add_all_algorithms();
    ENGINE_load_builtin_engines();
    ENGINE_register_all_complete();
    
    // Setup OpenSSL engine
    ENGINE* engine = ENGINE_by_id("pkcs11");
    if(!engine) {
      return print_last_error("Error engine error selecting pkcs11");
    }

    char *enginePath = "/usr/lib64/engines-1.1/pkcs11.so";
    char *modulePath = "/usr/lib64/opensc-pkcs11.so";
   
    ENGINE_ctrl_cmd_string(engine, "SO_PATH", enginePath, 0);
    ENGINE_ctrl_cmd_string(engine, "LIST_ADD", "1", 0);
    ENGINE_ctrl_cmd_string(engine, "LOAD", NULL, 0);
    ENGINE_ctrl_cmd_string(engine, "MODULE_PATH", modulePath, 0);

    if(!ENGINE_init(engine)) {
      ENGINE_free(engine);
      return print_last_error("Error engine init");
    }

    ENGINE_ctrl_cmd_string(engine, "VERBOSE", 0, 0);
    
    // TODO: Set your key ID here from> p11tool --list-all-certs 'URL'
    EVP_PKEY *public_key = ENGINE_load_public_key(engine, "01", NULL, NULL);
    if(!public_key) {
      return print_last_error("Error engine loading public key");
    }


    RSA *rsa_public = EVP_PKEY_get1_RSA(public_key);
    if(!rsa_public) {
      return print_last_error("Error creating RSA public key");
    }

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
    int i;
    
    std::cout << "\n";
    std::cout << "Public key encrypt" << "\n";
    encrypted_data_len = RSA_public_encrypt(data_len, (unsigned char *)data, ciphertext, rsa_public, RSA_PKCS1_PADDING);
    if(encrypted_data_len == -1) {
      return print_last_error("Public key encrypt failed");
    }
    std::cout << "Encrypted length = " << encrypted_data_len << "\n";
    
    printf("Encrypted Data: "); for(i = 0; i <  encrypted_data_len; ++i) { printf("%02x",ciphertext[i]); } printf("\n");

    // TODO: Set your smartcard pin for tesing
    char *pin = "00000000";

    ENGINE_ctrl_cmd_string(engine, "PIN", pin, 0);

    // TODO: Set your key ID here from> p11tool --list-all-certs 'URL'
    EVP_PKEY *private_key = ENGINE_load_private_key(engine, "01", 0, 0);
    if(!private_key) {
      return print_last_error("Error engine loading private key");
    }

    RSA *rsa_private = EVP_PKEY_get1_RSA(private_key);
    if(!rsa_private) {
      return print_last_error("Error creating RSA private key");
    }

    std::cout << "\n";
    std::cout << "Private key decrypt" << "\n";
    decrypted_data_len = RSA_private_decrypt(encrypted_data_len, ciphertext, plaintext, rsa_private, RSA_PKCS1_PADDING);
    
    if(decrypted_data_len == -1) {
      return print_last_error("Private key decrypt failed");
    }
    std::cout << "Decrypted text: " << plaintext << "\n";
    std::cout << "Decrypted Length = " << decrypted_data_len << "\n";
    
    RSA_free(rsa_public);
    RSA_free(rsa_private);
    EVP_PKEY_free(public_key);
    ENGINE_finish(engine);
    ENGINE_free(engine);
    ENGINE_cleanup();
    
    return  print_last_error(0, 0);
}
