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

#include <smart_card.h>

using namespace std;

#ifdef __ENABLE_SMART_CARD__

SmartCardOB sc;
int use_cert_file = 0;

int print_last_error(char *message = 0, int error_level = -1)
{
  char err[1024];
  memset(err, 0, sizeof(err));
  ERR_load_crypto_strings();
  ERR_error_string(ERR_get_error(), err);
  if(message) std::cerr << "ERROR: " << message << "\n";
  std::cerr << sc.err_string << "\n";
  std::cerr << "Openssl " << err << "\n";
  return error_level;
}

int main(int argc, char *argv[])
{
  if(argc < 3) {
    std::cerr << "ERROR - You must provide your smartcard PIN and cert ID number" << "\n";
    std::cerr << "USEAGE 1: " << argv[0] << " 12345 01" << "\n";
    std::cerr << "To view your smartcard cert use the p11tool or the pcsk11-tool" << "\n";
    std::cerr << "USEAGE 2: " << argv[0] << " 12345 01 cert_file.pem" << "\n";
    std::cerr << "cert_file.pem is an X509 cert in PEM format exported using the p11tool" << "\n";
    return 1;
  }

  sc.SetPin(argv[1]);
  sc.SetCertID(argv[2]);
  
  sc.verbose_mode = 1;

  if(argc >= 4) {
    use_cert_file = 1;
    if(SC_read_cert_file(&sc, argv[3]) != 0) {
      return print_last_error(0, 0);
    }

    std::cout << "Using exported smart card cert file for public key encryption" << "\n";
    std::cout.write(sc.cert_file_buf, sc.cert_file_buf_len);
  }

  // For RHEL 9
  // sc.SetEnginePath("/usr/lib64/engines-3/pkcs11.so");
  
  std::cout << "Openssl engine ID = " << sc.engine_ID << "\n";
  std::cout << "Engine path = " << sc.enginePath << "\n";
  std::cout << "Module path = " << sc.modulePath << "\n";
  std::cout << "Smart Card cert ID = " << sc.cert_id << "\n";
  // For testing only
  // std::cout << "Smart Card PIN = " << sc.pin << "\n";
  
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
  
  unsigned encrypted_data_len, decrypted_data_len;
  int rv, i;
  
  std::cout << "\n";
  std::cout << "Public key encrypt" << "\n";

  if(use_cert_file) {
    rv =  SC_cert_file_public_key_encrypt(&sc, (unsigned char *)data, data_len, ciphertext, sizeof(ciphertext), &encrypted_data_len);
  }
  else {
    rv =  SC_public_key_encrypt(&sc, (unsigned char *)data, data_len, ciphertext, sizeof(ciphertext), &encrypted_data_len);
  }
  if(rv != 0) {
      return print_last_error("Public key encrypt failed");
  }
  std::cout << "Encrypted length = " << encrypted_data_len << "\n";
  
  printf("Encrypted Data: "); for(i = 0; i <  encrypted_data_len; ++i) { printf("%02x",ciphertext[i]); } printf("\n");

  std::cout << "\n";
  std::cout << "Private key decrypt" << "\n";
  rv = SC_private_key_decrypt(&sc, ciphertext, encrypted_data_len, plaintext, sizeof(plaintext), &decrypted_data_len);
  
  if(rv != 0) {
    return print_last_error("Private key decrypt failed");
  }
  std::cout << "Decrypted text: " << plaintext << "\n";
  std::cout << "Decrypted Length = " << decrypted_data_len << "\n";
  
  return print_last_error(0, 0);
}

#else
int main()
{
  std::cerr << "This build is not smart card enabled" << "\n" << endl;
  return 1;
}
#endif // __ENABLE_SMART_CARD__
