// ------------------------------- //
// -------- Start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- //
// C++ Header File
// Compiler Used: MSVC, BCC32, GCC, HPUX aCC, SOLARIS CC
// Produced By: DataReel Software Development Team
// File Creation Date: 12/08/2023
// Date Last Modified: 10/25/2026
// Copyright (c) 2003-2026 DataReel Software Development
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

#ifdef __ENABLE_SMART_CARD__

// OpenSSL include files
#include <openssl/opensslv.h>

// 10/25/2026: OpenSSL 3 builds talk to the smart card directly through
// the PKCS#11 module (OpenSC). The OpenSSL ENGINE API is deprecated in
// OpenSSL 3 and removed from the RHEL 10 and OpenSSL 3.5 LTS builds.
// OpenSSL 1.x builds keep using the pkcs11 engine. Define __SC_USE_ENGINE__
// to force the engine code on an OpenSSL 3 build that still has engines.
#if !defined (__SC_USE_ENGINE__) && !defined (__SC_USE_PKCS11__)
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#define __SC_USE_ENGINE__
#else
#define __SC_USE_PKCS11__
#endif
#endif

#if defined (__SC_USE_ENGINE__)
#include <openssl/engine.h>
#endif
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
const unsigned SC_max_cert_id_size = 256; // Room for long IDs and pkcs11: URIs
const unsigned SC_max_engine_id_size = 32;
const unsigned SC_max_path_size = 255;
const unsigned SC_err_string_size = 512;
const int SC_RSA_padding = RSA_PKCS1_PADDING;

// 10/26/2026: PIN safeguards. CAC and PIV cards lock after a few wrong
// PINs, so the PIN is sent to the card at most once per program run
// after a failure, never empty or cut short, and not at all when the
// card reports it is locked, on its final try or (without permission)
// low on tries. These error levels tell the caller what happened.
const int SC_ERROR = -1;                 // Other errors, no PIN was sent
const int SC_ERROR_PIN_INCORRECT = -2;   // The card refused the PIN, one try was used
const int SC_ERROR_PIN_LOCKED = -3;      // The card PIN is locked
const int SC_ERROR_PIN_FINAL_TRY = -4;   // Not sent, the card has one try left
const int SC_ERROR_PIN_COUNT_LOW = -5;   // Not sent, the card is low on tries
const int SC_ERROR_PIN_INVALID = -6;     // Not sent, the PIN is empty or the wrong length
const int SC_ERROR_PIN_BLOCKED = -7;     // Not sent, a login already failed in this run
const int SC_ERROR_LOGIN = -8;           // The card login failed for another reason
const unsigned SC_max_cert_file_len = 8192;

struct SmartCardOB
{
  SmartCardOB();
  ~SmartCardOB();

  void SetEnginePath(char *p) { strncpy(enginePath, p, (sizeof(enginePath)-1)); }
  void SetModulePath(char *p) { strncpy(modulePath, p, (sizeof(modulePath)-1)); }
  void SetEngineID(char *id) { strncpy(engine_ID, id, (sizeof(engine_ID)-1)); }
  // 10/26/2026: A PIN that does not fit is not cut short (sending a cut
  // PIN uses up a card PIN try), it is refused before the login
  void SetPin(char *p) {
    memset(pin, 0, sizeof(pin));
    pin_too_long = (p && strlen(p) >= sizeof(pin));
    if(p && !pin_too_long) strncpy(pin, p, (sizeof(pin)-1));
  }
  void SetCertID(char *id) { strncpy(cert_id, id, (sizeof(cert_id)-1)); }
  int SetError(const char *message =  0, int level = -1);
  
  int verbose_mode;
  int error_level;
  int pin_too_long; // 10/26/2026: Set by SetPin() for a PIN that does not fit
  int has_slot;          // 10/26/2026: 1 to use only the PKCS#11 slot slot_id
  unsigned long slot_id;
  void SetSlot(unsigned long id) { has_slot = 1; slot_id = id; }
  int allow_pin_count_low; // 10/26/2026: Set to log in when the card is low on PIN tries
  int allow_pin_final_try; // 10/26/2026: Set to log in when the card has one PIN try left
  unsigned long token_flags; // PKCS#11 token flags read before the last login
  int token_flags_known;     // 1 if token_flags was read
  char err_string[SC_err_string_size];
  char pin[SC_max_pin_size];
  char cert_id[SC_max_cert_id_size];
  char engine_ID[SC_max_engine_id_size];
  char enginePath[SC_max_path_size];
  char modulePath[SC_max_path_size];
  char cert_file_buf[SC_max_cert_file_len];
  unsigned cert_file_buf_len;
};

const char *SC_get_default_enginePath();
const char *SC_get_default_modulePath();
const char *SC_get_default_engine_ID();
const char *SC_get_default_cert_id();
int SC_uses_engine(); // Returns 1 if the OpenSSL pkcs11 engine is used
// 10/26/2026: Returns 1 if the error level is a PIN error. After
// SC_ERROR_PIN_INCORRECT, SC_ERROR_PIN_LOCKED or SC_ERROR_LOGIN no more
// logins are made in this program run (SC_login_blocked() returns 1).
int SC_is_pin_error(int level);
int SC_login_blocked();
// 10/26/2026: Parses a PKCS#11 slot ID, decimal or 0x hex. Returns 1 if valid.
int SC_parse_slot(const char *s, unsigned long *slot);
// Text for the PIN tries the card reports in sc->token_flags
const char *SC_pin_tries_string(SmartCardOB *sc);

int SC_public_key_encrypt(SmartCardOB *sc,
			  const unsigned char plaintext[], unsigned int plaintext_len,
			  unsigned char ciphertext[], unsigned int ciphertext_len,
			  unsigned *encrypted_data_len, int padding = SC_RSA_padding);
int SC_private_key_decrypt(SmartCardOB *sc,
			   const unsigned char ciphertext[], unsigned int ciphertext_len,
			   unsigned char plaintext[], unsigned int plaintext_len,
			   unsigned *unencrypted_data_len,
			   int padding = SC_RSA_padding);
int SC_read_cert_file(SmartCardOB *sc, const char *fname);
int SC_cert_file_public_key_encrypt(SmartCardOB *sc,
				    const unsigned char plaintext[], unsigned int plaintext_len,
				    unsigned char ciphertext[], unsigned int ciphertext_len,
				    unsigned *encrypted_data_len, int padding =SC_RSA_padding);
#endif // __ENABLE_SMART_CARD__

#endif //__SMART_CARD_HPP__
// ----------------------------------------------------------- // 
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
