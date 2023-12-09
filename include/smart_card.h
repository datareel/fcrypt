// ------------------------------- //
// -------- Start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- //
// C++ Header File
// Compiler Used: MSVC, BCC32, GCC, HPUX aCC, SOLARIS CC
// Produced By: DataReel Software Development Team
// File Creation Date: 12/08/2023
// Date Last Modified: 12/08/2023
// Copyright (c) 2023 DataReel Software Development
// ----------------------------------------------------------- // 
// ---------- Include File Description and Details  ---------- // 
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
#ifndef __SMART_CARD_HPP__
#define __SMART_CARD_HPP__

#define __ENABLE_SMART_CARD__

#ifdef __ENABLE_SMART_CARD__

// OpenSSL include files
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const unsigned SC_max_pin_size = 32;
const unsigned SC_max_cert_id_size = 32;
const unsigned SC_max_engine_id_size = 32;
const unsigned SC_max_path_size = 64;
const unsigned SC_err_string_size = 255;
const int SC_RSA_padding = RSA_PKCS1_PADDING;

struct SmartCardOB
{
  SmartCardOB();
  ~SmartCardOB() {
    memset(pin, 0, sizeof(pin));
  }

  void SetEnginePath(char *p) { strncpy(enginePath, p, (sizeof(enginePath)-1)); }
  void SetModulePath(char *p) { strncpy(modulePath, p, (sizeof(modulePath)-1)); }
  void SetEngineID(char *id) { strncpy(engine_ID, id, (sizeof(engine_ID)-1)); }
  void SetPin(char *p) { strncpy(pin, p, (sizeof(pin)-1)); }
  void SetCertID(char *id) { strncpy(cert_id, id, (sizeof(cert_id)-1)); }
  int SetError(char *message =  0, int level = -1);
  
  int verbose_mode;
  int error_level;
  char err_string[SC_err_string_size];
  char pin[SC_max_pin_size];
  char cert_id[SC_max_cert_id_size];
  char engine_ID[SC_max_engine_id_size];
  char enginePath[SC_max_path_size];
  char modulePath[SC_max_path_size];
};

int SC_public_key_encrypt(SmartCardOB *sc,
			  const unsigned char plaintext[], unsigned int plaintext_len,
			  unsigned char ciphertext[], unsigned int ciphertext_len,
			  unsigned *encrypted_data_len, int padding = SC_RSA_padding);
int SC_private_key_decrypt(SmartCardOB *sc,
			   const unsigned char ciphertext[], unsigned int ciphertext_len,
			   unsigned char plaintext[], unsigned int plaintext_len,
			   unsigned *unencrypted_data_len,
			   int padding = SC_RSA_padding);

#endif // __ENABLE_SMART_CARD__

#endif //__SMART_CARD_HPP__
// ----------------------------------------------------------- // 
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
