#include <iostream>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
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
    EVP_PKEY *pkey = ENGINE_load_public_key(engine, "01", NULL, NULL);
    if(!pkey) {
      return print_last_error("Error engine loading public key");
    }

    PEM_write_PUBKEY(stdout, pkey);
    EVP_PKEY_free(pkey);
    
    ENGINE_finish(engine);
    ENGINE_free(engine);
    ENGINE_cleanup();
    
    return  print_last_error(0, 0);
}
