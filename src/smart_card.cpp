// ------------------------------- //
// -------- start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- // 
// C++ Source Code File
// Compiler Used: MSVC, BCC32, GCC, HPUX aCC, SOLARIS CC
// Produced By: DataReel Software Development Team
// File Creation Date: 12/08/2023
// Date Last Modified: 12/10/2023
// Copyright (c) 2023 DataReel Software Development
// ----------------------------------------------------------- // 
// ------------- Program Description and Details ------------- // 
// ----------------------------------------------------------- // 
/*
This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.
 
This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  
USA

Smartcard encryption and decryption routines.
*/
// ----------------------------------------------------------- // 
#include <smart_card.h>

#ifdef __ENABLE_SMART_CARD__

#include <smart_card.h>


const char *SC_default_enginePath = "/usr/lib64/engines-1.1/pkcs11.so";
const char *SC_default_modulePath = "/usr/lib64/opensc-pkcs11.so";
const char *SC_default_engine_ID = "pkcs11";
const char *SC_default_error_message = "No smart card object errors reported";
const char *SC_default_cert_id = "01";

const char *SC_get_default_enginePath() { return SC_default_enginePath; }
const char *SC_get_default_modulePath() { return SC_default_modulePath; }
const char *SC_get_default_engine_ID() { return SC_default_engine_ID; }
const char *SC_get_default_cert_id() { return SC_default_cert_id; }

SmartCardOB::SmartCardOB()
{
  memset(pin, 0, sizeof(pin));
  memset(cert_id, 0, sizeof(cert_id));
  memset(engine_ID, 0, sizeof(engine_ID));
  memset(enginePath, 0, sizeof(enginePath));
  memset(modulePath, 0, sizeof(modulePath));
  memset(err_string, 0, sizeof(err_string));
  strncpy(engine_ID, SC_default_engine_ID, (sizeof(engine_ID)-1));
  strncpy(enginePath, SC_default_enginePath, (sizeof(enginePath)-1));
  strncpy(modulePath, SC_default_modulePath, (sizeof(modulePath)-1));
  strncpy(err_string, SC_default_error_message, (sizeof(err_string)-1));
  strncpy(cert_id, SC_default_cert_id, (sizeof(cert_id)-1));
  verbose_mode = 0;
  error_level = 0;
  memset(cert_file_buf, 0, SC_max_cert_file_len);
  cert_file_buf_len = 0;
}

SmartCardOB::~SmartCardOB()
{
  memset(pin, 0, sizeof(pin));
  memset(cert_file_buf, 0, SC_max_cert_file_len);
}

int SmartCardOB::SetError(char *message, int level)
{
  if(message) strncpy(err_string, message, (sizeof(err_string)-1));
  error_level = level;
  return level;
}

int SC_public_key_encrypt(SmartCardOB *sc,
			  const unsigned char plaintext[], unsigned int plaintext_len,
			  unsigned char ciphertext[], unsigned int ciphertext_len,
			  unsigned *encrypted_data_len, int padding)
{
  OpenSSL_add_all_algorithms();
  ENGINE_load_builtin_engines();
  ENGINE_register_all_complete();

  ENGINE* engine = ENGINE_by_id(sc->engine_ID);
  if(!engine) {
    return sc->SetError("Error smart card engine error selecting pkcs11");
  }
  
  ENGINE_ctrl_cmd_string(engine, "SO_PATH", sc->enginePath, 0);
  ENGINE_ctrl_cmd_string(engine, "LIST_ADD", "1", 0);
  ENGINE_ctrl_cmd_string(engine, "LOAD", 0, 0);
  ENGINE_ctrl_cmd_string(engine, "MODULE_PATH", sc->modulePath, 0);

  if(!ENGINE_init(engine)) {
    ENGINE_free(engine);
    return sc->SetError("Smart card engine init error");
  }

  if(sc->verbose_mode) ENGINE_ctrl_cmd_string(engine, "VERBOSE", 0, 0);

  EVP_PKEY *evkey = ENGINE_load_public_key(engine, sc->cert_id, 0, 0);
  if(!evkey) {
    ENGINE_free(engine);
    return  sc->SetError("Error loading smart card public key");
  }
  
  RSA *rsa = EVP_PKEY_get1_RSA(evkey);
  if(!rsa) {
    ENGINE_free(engine);
    EVP_PKEY_free(evkey);
    return sc->SetError("Error creating RSA public key");
  }
  
  int len = RSA_public_encrypt(plaintext_len, plaintext, ciphertext, rsa, padding);
  if(len == -1) {
    ENGINE_free(engine);
    EVP_PKEY_free(evkey);
    RSA_free(rsa);
    return sc->SetError("Public key encrypt failed");
  }
  *(encrypted_data_len) = len;

  EVP_PKEY_free(evkey);
  RSA_free(rsa);
  ENGINE_finish(engine);
  ENGINE_free(engine);
  ENGINE_cleanup();

  return 0;
}

int SC_private_key_decrypt(SmartCardOB *sc,
			   const unsigned char ciphertext[], unsigned int ciphertext_len,
			   unsigned char plaintext[], unsigned int plaintext_len,
			   unsigned *unencrypted_data_len,
			   int padding)
{
  OpenSSL_add_all_algorithms();
  ENGINE_load_builtin_engines();
  ENGINE_register_all_complete();

  ENGINE* engine = ENGINE_by_id(sc->engine_ID);
  if(!engine) {
    return sc->SetError("Error smart card engine error selecting pkcs11");
  }
  
  ENGINE_ctrl_cmd_string(engine, "SO_PATH", sc->enginePath, 0);
  ENGINE_ctrl_cmd_string(engine, "LIST_ADD", "1", 0);
  ENGINE_ctrl_cmd_string(engine, "LOAD", 0, 0);
  ENGINE_ctrl_cmd_string(engine, "MODULE_PATH", sc->modulePath, 0);

  if(!ENGINE_init(engine)) {
    ENGINE_free(engine);
    return sc->SetError("Smart card engine init error");
  }

  if(sc->verbose_mode) ENGINE_ctrl_cmd_string(engine, "VERBOSE", 0, 0);

  // Set the users pin
  ENGINE_ctrl_cmd_string(engine, "PIN", sc->pin, 0);
  
  EVP_PKEY *evkey = ENGINE_load_private_key(engine, sc->cert_id, 0, 0);
  if(!evkey) {
    ENGINE_free(engine);
    return  sc->SetError("Error loading smart card private key");
  }
  
  RSA *rsa = EVP_PKEY_get1_RSA(evkey);
  if(!rsa) {
    ENGINE_free(engine);
    EVP_PKEY_free(evkey);
    return sc->SetError("Error creating RSA private key");
  }

  int len = RSA_private_decrypt(ciphertext_len, ciphertext, plaintext, rsa, padding);
  if(len == -1)	{
    ENGINE_free(engine);
    EVP_PKEY_free(evkey);
    RSA_free(rsa);
    return sc->SetError("Private key decrypt failed");
  }
  
  *(unencrypted_data_len) = len;

  EVP_PKEY_free(evkey);
  RSA_free(rsa);
  ENGINE_finish(engine);
  ENGINE_free(engine);
  ENGINE_cleanup();

  return 0;
}

int SC_read_cert_file(SmartCardOB *sc, const char *fname)
{
  memset(sc->cert_file_buf, 0, SC_max_cert_file_len);

  FILE *fp;
  fp = fopen(fname, "rb");
  if(!fp) {
    return sc->SetError("Error opening smart card cert file");
  }

  char read_buf[1024];
  unsigned input_bytes_read = 0;
  unsigned offset = 0;
  
  while(!feof(fp)) {
    memset(read_buf, 0, sizeof(read_buf));
    input_bytes_read = fread((unsigned char *)read_buf, 1, sizeof(read_buf), fp);
    if(input_bytes_read < 0) {
      fclose(fp);
      memset(read_buf, 0, sizeof(read_buf));  
      return sc->SetError("Error reading from smart card cert file");
    }
    if(offset > SC_max_cert_file_len) {
      fclose(fp);
      memset(read_buf, 0, sizeof(read_buf));  
      return sc->SetError("Smart card cert file exceeds max buffer length");
    }
    memmove(sc->cert_file_buf+offset, read_buf, input_bytes_read);
    offset += input_bytes_read;
  }

  sc-> cert_file_buf_len = offset;
  
  memset(read_buf, 0, sizeof(read_buf));  
  fclose(fp);
  
  return 0;
}

int SC_cert_file_public_key_encrypt(SmartCardOB *sc,
				    const unsigned char plaintext[], unsigned int plaintext_len,
				    unsigned char ciphertext[], unsigned int ciphertext_len,
				    unsigned *encrypted_data_len, int padding)
{
  if(sc->cert_file_buf_len == 0) {
    return sc->SetError("Error no smart card cert file is loaded");
  }

  BIO *keybio = BIO_new_mem_buf((const void *)sc->cert_file_buf, sc->cert_file_buf_len);
  if(!keybio) {
    return sc->SetError("Error creating bio object for smart card cert file");
  }
  X509 *x509 = PEM_read_bio_X509(keybio, NULL, NULL, NULL);
  if(!x509) {
    BIO_free(keybio);
    return sc->SetError("Error creating x509 object for smart card cert file");
  }

 EVP_PKEY *evkey=X509_get_pubkey(x509);
 if(!evkey) {
   BIO_free(keybio);
   X509_free(x509);
   return sc->SetError("Error creating public key object for smart card cert file");
 }
 
 RSA *rsa = EVP_PKEY_get1_RSA(evkey);
 if(!rsa) {
   BIO_free(keybio);
   X509_free(x509);
   EVP_PKEY_free(evkey);
   return sc->SetError("Error creating RSA public key");
 }
 
 int len = RSA_public_encrypt(plaintext_len, plaintext, ciphertext, rsa, padding);
 if(len == -1) {
   BIO_free(keybio);
   X509_free(x509);
   EVP_PKEY_free(evkey);
   return sc->SetError("Public key encrypt failed");
 }
 *(encrypted_data_len) = len;

 BIO_free(keybio);
 X509_free(x509);
 EVP_PKEY_free(evkey);
  
  return 0;
}

#endif // __ENABLE_SMART_CARD__
// ----------------------------------------------------------- // 
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
    
