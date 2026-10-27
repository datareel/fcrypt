// ------------------------------- //
// -------- start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- // 
// C++ Source Code File
// Compiler Used: MSVC, BCC32, GCC, HPUX aCC, SOLARIS CC
// Produced By: DataReel Software Development Team
// File Creation Date: 12/08/2023
// Date Last Modified: 10/25/2026
// Copyright (c) 2003-2026 DataReel Software Development
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
#include <rsadb.h>
#include <ctype.h>

#ifdef __ENABLE_SMART_CARD__

#include <smart_card.h>
#include <rsadb.h>

// In RHEL 10 the openssl-pkcs11 package is replaced with pkcs11-provider
#if defined (__RHEL8__)
const char *SC_default_enginePath = "/usr/lib64/engines-1.1/pkcs11.so";
#elif defined (__RHEL9__)
const char *SC_default_enginePath = "/usr/lib64/engines-3/pkcs11.so";
#elif defined (__RHEL10__)
const char *SC_default_enginePath = "/usr/lib64/ossl-modules/pkcs11.so";
#elif defined (__WIN32__)
const char *SC_default_enginePath = "pkcs11.dll";
#else
const char *SC_default_enginePath = "/usr/lib64/engines/pkcs11.so";
#endif

#if defined (__WIN32__)
const char *SC_default_modulePath = "C:\\Program Files\\OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll";
#elif defined (__LINUX__)
const char *SC_default_modulePath = "/usr/lib64/opensc-pkcs11.so";
#else
const char *SC_default_modulePath = "/usr/lib64/opensc-pkcs11.so";
#endif

const char *SC_default_engine_ID = "pkcs11";
const char *SC_default_error_message = "No smart card object errors reported";
const char *SC_default_cert_id = "01";

const char *SC_get_default_enginePath() { return SC_default_enginePath; }
#if defined (__WIN32__)
// 10/25/2026: Use the ActivClient PKCS#11 module when ActivClient is
// installed to manage CAC logins, otherwise use OpenSC. A 32-bit build
// needs the 32-bit modules from Program Files (x86).
static const char *SC_windows_modules[] = {
#if defined (_WIN64)
  "C:\\Program Files\\HID Global\\ActivClient\\acpkcs211.dll",
  "C:\\Program Files\\ActivIdentity\\ActivClient\\acpkcs211.dll",
#else
  "C:\\Program Files (x86)\\HID Global\\ActivClient\\acpkcs211.dll",
  "C:\\Program Files (x86)\\ActivIdentity\\ActivClient\\acpkcs211.dll",
  "C:\\Program Files (x86)\\OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll",
#endif
  0
};

const char *SC_get_default_modulePath()
{
  for(int i = 0; SC_windows_modules[i]; i++) {
    FILE *fp = fopen(SC_windows_modules[i], "rb");
    if(fp) {
      fclose(fp);
      return SC_windows_modules[i];
    }
  }
  return SC_default_modulePath;
}
#else
const char *SC_get_default_modulePath() { return SC_default_modulePath; }
#endif
const char *SC_get_default_engine_ID() { return SC_default_engine_ID; }
const char *SC_get_default_cert_id() { return SC_default_cert_id; }

#if defined (__SC_USE_ENGINE__)
int SC_uses_engine() { return 1; }
#else
int SC_uses_engine() { return 0; }
#endif

// 10/26/2026: Set after a failed card login. No more logins are made in
// this program run, so a wrong PIN is never sent again by a loop over
// files, keys, sessions or fallbacks.
static int SC_login_failed = 0;

int SC_login_blocked() { return SC_login_failed; }

int SC_parse_slot(const char *s, unsigned long *slot)
// 10/26/2026: A PKCS#11 slot ID, decimal or 0x hex. Returns 1 if valid.
{
  if(!s || !*s || strlen(s) > 20) return 0;
  int hex = (strncmp(s, "0x", 2) == 0 || strncmp(s, "0X", 2) == 0);
  const char *p = hex ? s + 2 : s;
  if(!*p) return 0;
  for(const char *q = p; *q; q++) {
    if(hex ? !isxdigit((unsigned char)*q) : !isdigit((unsigned char)*q)) return 0;
  }
  *(slot) = strtoul(p, 0, hex ? 16 : 10);
  return 1;
}

int SC_is_pin_error(int level)
{
  return (level == SC_ERROR_PIN_INCORRECT || level == SC_ERROR_PIN_LOCKED ||
	  level == SC_ERROR_PIN_FINAL_TRY || level == SC_ERROR_PIN_COUNT_LOW ||
	  level == SC_ERROR_PIN_INVALID || level == SC_ERROR_PIN_BLOCKED ||
	  level == SC_ERROR_LOGIN);
}

const char *SC_pin_tries_string(SmartCardOB *sc)
{
  if(!sc->token_flags_known) return "The card did not report its PIN tries";
  if(sc->token_flags & (1UL << 18)) return "The card reports the PIN is locked";        // CKF_USER_PIN_LOCKED
  if(sc->token_flags & (1UL << 17)) return "The card reports one PIN try is left";      // CKF_USER_PIN_FINAL_TRY
  if(sc->token_flags & (1UL << 16)) return "The card reports it is low on PIN tries";   // CKF_USER_PIN_COUNT_LOW
  return "The card does not report low PIN tries (some modules, such as ActivClient, may not report them)";
}

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
  strncpy(modulePath, SC_get_default_modulePath(), (sizeof(modulePath)-1));
  strncpy(err_string, SC_default_error_message, (sizeof(err_string)-1));
  strncpy(cert_id, SC_default_cert_id, (sizeof(cert_id)-1));
  verbose_mode = 0;
  error_level = 0;
  pin_too_long = 0;
  has_slot = 0;
  slot_id = 0;
  allow_pin_count_low = 0;
  allow_pin_final_try = 0;
  token_flags = 0;
  token_flags_known = 0;
  memset(cert_file_buf, 0, SC_max_cert_file_len);
  cert_file_buf_len = 0;
}

SmartCardOB::~SmartCardOB()
{
  memset(pin, 0, sizeof(pin));
  memset(cert_file_buf, 0, SC_max_cert_file_len);
}

int SmartCardOB::SetError(const char *message, int level)
{
  if(message) strncpy(err_string, message, (sizeof(err_string)-1));
  error_level = level;
  return level;
}

#if defined (__SC_USE_ENGINE__)
int SC_public_key_encrypt(SmartCardOB *sc,
			  const unsigned char plaintext[], unsigned int plaintext_len,
			  unsigned char ciphertext[], unsigned int ciphertext_len,
			  unsigned *encrypted_data_len, int padding)
{
  RSA_openssl_init();
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
  
  // 10/25/2026: Use EVP_PKEY instead of the deprecated RSA_* calls
  if(RSA_pkey_encrypt(evkey, plaintext, plaintext_len, ciphertext, ciphertext_len,
		      encrypted_data_len, padding) != RSA_NO_ERROR) {
    ENGINE_free(engine);
    EVP_PKEY_free(evkey);
    return sc->SetError("Public key encrypt failed");
  }

  EVP_PKEY_free(evkey);
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
  RSA_openssl_init();
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

  // 10/26/2026: Never send an empty PIN or a PIN after a failed login
  if(SC_login_failed) {
    ENGINE_free(engine);
    return sc->SetError("Smart card PIN not sent, a card login already failed in this run", SC_ERROR_PIN_BLOCKED);
  }
  if(sc->pin[0] == 0 || sc->pin_too_long) {
    ENGINE_free(engine);
    return sc->SetError("Smart card PIN not sent, the PIN is empty or too long", SC_ERROR_PIN_INVALID);
  }

  // Set the users pin
  ENGINE_ctrl_cmd_string(engine, "PIN", sc->pin, 0);
  
  EVP_PKEY *evkey = ENGINE_load_private_key(engine, sc->cert_id, 0, 0);
  if(!evkey) {
    // The engine does not say if the PIN was wrong, treat it as a login
    // failure so the PIN is not sent again
    SC_login_failed = 1;
    ENGINE_free(engine);
    return  sc->SetError("Error loading smart card private key, the PIN may be wrong. The PIN will not be sent again in this run", SC_ERROR_LOGIN);
  }
  
  // 10/25/2026: Use EVP_PKEY instead of the deprecated RSA_* calls
  if(RSA_pkey_decrypt(evkey, ciphertext, ciphertext_len, plaintext, plaintext_len,
		      unencrypted_data_len, padding) != RSA_NO_ERROR) {
    ENGINE_free(engine);
    EVP_PKEY_free(evkey);
    return sc->SetError("Private key decrypt failed");
  }

  EVP_PKEY_free(evkey);
  ENGINE_finish(engine);
  ENGINE_free(engine);
  ENGINE_cleanup();

  return 0;
}

int SC_list_tokens(const char *module_path, std::vector<SC_TokenInfo> &out, std::string &err)
// 10/27/2026: The pkcs11 engine has no way to list cards without a login
{
  out.clear();
  err = "Listing smart cards is not supported by this build, it uses the OpenSSL pkcs11 engine. "
    "Use smartcard_list or pkcs11-tool --list-token-slots";
  return SC_ERROR;
}

#else // __SC_USE_PKCS11__
// 10/25/2026: Smart card access through the PKCS#11 module for OpenSSL 3.
// The card does the RSA private key operation, so the wrapped keys are
// the same RSA PKCS#1 v1.5 (or OAEP) data the pkcs11 engine produced and
// files encrypted by earlier releases decrypt with the same card.
#ifndef CRYPTOKI_COMPAT
#define CRYPTOKI_COMPAT
#endif
#include <pkcs11.h>
#include <aesdb.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#if defined (__WIN32__)
// Leave out wincrypt.h, its X509 names clash with OpenSSL
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#endif

const unsigned SC_max_key_id_len = 128;
const unsigned SC_max_label_len = 128;
const unsigned SC_max_rsa_len = 1024; // Room for an 8192-bit RSA key

struct SC_key_id
{
  CK_BYTE id[SC_max_key_id_len];
  CK_ULONG id_len;
  char label[SC_max_label_len];
  int has_slot;
  CK_SLOT_ID slot;
};

struct SC_p11_session
{
  void *lib;
  CK_FUNCTION_LIST_PTR fl;
  int initialized;
  int has_session;
  int logged_in;
  CK_SESSION_HANDLE session;
  CK_FLAGS token_flags;
  CK_SLOT_ID slot;
};

static int SC_hex_value(char c)
{
  if(c >= '0' && c <= '9') return c - '0';
  if(c >= 'a' && c <= 'f') return c - 'a' + 10;
  if(c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int SC_hex_to_bin(const char *hex, unsigned hex_len, CK_BYTE out[], CK_ULONG *out_len)
// Returns 1 on success or 0 for errors
{
  if((hex_len % 2) != 0 || (hex_len / 2) > SC_max_key_id_len) return 0;
  for(unsigned i = 0; i < hex_len; i += 2) {
    int hi = SC_hex_value(hex[i]);
    int lo = SC_hex_value(hex[i+1]);
    if(hi < 0 || lo < 0) return 0;
    out[i/2] = (CK_BYTE)((hi << 4) | lo);
  }
  *(out_len) = hex_len / 2;
  return 1;
}

static int SC_percent_decode(const char *in, unsigned in_len, CK_BYTE out[], unsigned out_size, unsigned *out_len)
// Returns 1 on success or 0 for errors
{
  unsigned n = 0;
  for(unsigned i = 0; i < in_len; i++) {
    if(n >= out_size) return 0;
    if(in[i] == '%') {
      if((i + 2) >= in_len) return 0;
      int hi = SC_hex_value(in[i+1]);
      int lo = SC_hex_value(in[i+2]);
      if(hi < 0 || lo < 0) return 0;
      out[n++] = (CK_BYTE)((hi << 4) | lo);
      i += 2;
    }
    else {
      out[n++] = (CK_BYTE)in[i];
    }
  }
  *(out_len) = n;
  return 1;
}

static int SC_parse_cert_id(const char *cert_id, SC_key_id *kid)
// Accepts the key ID formats used with the pkcs11 engine: a hex ID such
// as 01, id_01, label_name, slot:01, slot_N-id_01, slot_N-label_name
// or a pkcs11: URI with id= and/or object= attributes.
// Returns 1 on success or 0 for errors.
{
  memset(kid, 0, sizeof(SC_key_id));
  if(!cert_id || !*cert_id) return 0;

  if(strncmp(cert_id, "pkcs11:", 7) == 0) {
    const char *p = cert_id + 7;
    while(*p && *p != '?') {
      const char *end = p;
      while(*end && *end != ';' && *end != '?') end++;
      unsigned len = (unsigned)(end - p);
      unsigned out_len = 0;
      if(len > 3 && strncmp(p, "id=", 3) == 0) {
	if(!SC_percent_decode(p+3, len-3, kid->id, SC_max_key_id_len, &out_len)) return 0;
	kid->id_len = out_len;
      }
      else if(len > 7 && strncmp(p, "object=", 7) == 0) {
	if(!SC_percent_decode(p+7, len-7, (CK_BYTE *)kid->label, SC_max_label_len-1, &out_len)) return 0;
	kid->label[out_len] = 0;
      }
      p = (*end == ';') ? end + 1 : end;
    }
    return (kid->id_len > 0 || kid->label[0] != 0);
  }

  const char *p = cert_id;
  if(strncmp(p, "slot_", 5) == 0) {
    char *end = 0;
    unsigned long slot = strtoul(p+5, &end, (strncmp(p+5, "0x", 2) == 0) ? 16 : 10);
    if(!end || end == p+5 || *end != '-') return 0;
    kid->has_slot = 1;
    kid->slot = (CK_SLOT_ID)slot;
    p = end + 1;
  }
  else {
    const char *colon = strchr(p, ':');
    if(colon) {
      char *end = 0;
      unsigned long slot = strtoul(p, &end, 10);
      if(!end || end != colon || end == p) return 0;
      kid->has_slot = 1;
      kid->slot = (CK_SLOT_ID)slot;
      p = colon + 1;
    }
  }
  if(strncmp(p, "label_", 6) == 0) {
    strncpy(kid->label, p+6, SC_max_label_len-1);
    return kid->label[0] != 0;
  }
  if(strncmp(p, "id_", 3) == 0) p += 3;
  return SC_hex_to_bin(p, (unsigned)strlen(p), kid->id, &kid->id_len);
}

static void SC_p11_close(SC_p11_session *p)
{
  if(p->fl) {
    if(p->logged_in) p->fl->C_Logout(p->session);
    if(p->has_session) p->fl->C_CloseSession(p->session);
    if(p->initialized) p->fl->C_Finalize(0);
  }
  if(p->lib) {
#if defined (__WIN32__)
    FreeLibrary((HMODULE)p->lib);
#else
    dlclose(p->lib);
#endif
  }
  memset(p, 0, sizeof(SC_p11_session));
}

static int SC_p11_load(SmartCardOB *sc, SC_p11_session *p)
{
  memset(p, 0, sizeof(SC_p11_session));
  CK_C_GetFunctionList get_function_list = 0;
#if defined (__WIN32__)
  HMODULE h = LoadLibraryA(sc->modulePath);
  if(h) get_function_list = (CK_C_GetFunctionList)GetProcAddress(h, "C_GetFunctionList");
  p->lib = (void *)h;
#else
  p->lib = dlopen(sc->modulePath, RTLD_NOW | RTLD_LOCAL);
  if(p->lib) get_function_list = (CK_C_GetFunctionList)dlsym(p->lib, "C_GetFunctionList");
#endif
  if(!p->lib) {
    return sc->SetError("Error loading the smart card PKCS#11 provider module");
  }
  if(!get_function_list || get_function_list(&p->fl) != CKR_OK || !p->fl) {
    SC_p11_close(p);
    return sc->SetError("Error smart card provider is not a PKCS#11 module");
  }

  CK_C_INITIALIZE_ARGS init_args;
  memset(&init_args, 0, sizeof(init_args));
  init_args.flags = CKF_OS_LOCKING_OK;
  CK_RV rv = p->fl->C_Initialize(&init_args);
  if(rv == CKR_OK) {
    p->initialized = 1;
  }
  else if(rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
    SC_p11_close(p);
    return sc->SetError("Error initializing the smart card PKCS#11 module");
  }
  return 0;
}

static int SC_p11_find(SC_p11_session *p, CK_OBJECT_CLASS obj_class, const SC_key_id *kid,
		       CK_OBJECT_HANDLE *obj)
// Returns 1 if the object was found or 0 if not found
{
  CK_ATTRIBUTE tmpl[3];
  CK_ULONG count = 0;
  tmpl[count].type = CKA_CLASS;
  tmpl[count].pValue = &obj_class;
  tmpl[count].ulValueLen = sizeof(obj_class);
  count++;
  if(kid->id_len > 0) {
    tmpl[count].type = CKA_ID;
    tmpl[count].pValue = (void *)kid->id;
    tmpl[count].ulValueLen = kid->id_len;
    count++;
  }
  if(kid->label[0] != 0) {
    tmpl[count].type = CKA_LABEL;
    tmpl[count].pValue = (void *)kid->label;
    tmpl[count].ulValueLen = (CK_ULONG)strlen(kid->label);
    count++;
  }

  if(p->fl->C_FindObjectsInit(p->session, tmpl, count) != CKR_OK) return 0;
  CK_ULONG found = 0;
  CK_RV rv = p->fl->C_FindObjects(p->session, obj, 1, &found);
  p->fl->C_FindObjectsFinal(p->session);
  return (rv == CKR_OK && found == 1);
}

static void SC_p11_slot_names(SC_p11_session *p, CK_SLOT_ID slots[], CK_ULONG num_slots,
			      char out[], unsigned out_size)
// 10/26/2026: "1 = 0x1 (CAC label), 4 = 0x4 (YubiKey label)" for error messages.
// Reads the token labels only, no login.
{
  out[0] = 0;
  unsigned len = 0;
  for(CK_ULONG i = 0; i < num_slots && len < out_size; i++) {
    CK_TOKEN_INFO ti;
    memset(&ti, 0, sizeof(ti));
    char label[33];
    memset(label, 0, sizeof(label));
    if(p->fl->C_GetTokenInfo(slots[i], &ti) == CKR_OK) {
      memmove(label, ti.label, 32);
      for(int k = 31; k >= 0 && (label[k] == ' ' || label[k] == 0); k--) label[k] = 0;
    }
    int n = snprintf(out + len, out_size - len, "%s%lu = 0x%lx (%s)", (i ? ", " : ""), (unsigned long)slots[i],
		     (unsigned long)slots[i], label[0] ? label : "no label");
    if(n < 0) break;
    len += (unsigned)n;
  }
  if(len >= out_size) out[out_size-1] = 0;
}

static int SC_p11_open_token(SmartCardOB *sc, SC_p11_session *p, const SC_key_id *kid_in)
// Open a session on the token that holds the key. Private keys can be
// hidden until login, so if no token shows the key ID and only one
// token is present that token is used. 10/26/2026: With a slot set in
// sc (SetSlot) or in the cert ID, only that slot is used, no other slot
// is opened.
{
  SC_key_id kid_buf;
  memmove(&kid_buf, kid_in, sizeof(kid_buf));
  SC_key_id *kid = &kid_buf;
  if(sc->has_slot) {
    if(kid->has_slot && kid->slot != (CK_SLOT_ID)sc->slot_id) {
      return sc->SetError("Error the smart card slot and the slot in the cert ID are not the same");
    }
    kid->has_slot = 1;
    kid->slot = (CK_SLOT_ID)sc->slot_id;
  }

  CK_ULONG num_slots = 0;
  if(p->fl->C_GetSlotList(CK_TRUE, 0, &num_slots) != CKR_OK || num_slots == 0) {
    return sc->SetError("Error no smart card found in any reader");
  }
  CK_SLOT_ID *slots = new CK_SLOT_ID[num_slots];
  if(p->fl->C_GetSlotList(CK_TRUE, slots, &num_slots) != CKR_OK) {
    delete[] slots;
    return sc->SetError("Error listing the smart card readers");
  }

  int have_first = 0;
  CK_SLOT_ID first_slot = 0;
  CK_ULONG num_candidates = 0;
  int found = 0;
  CK_SLOT_ID found_slot = 0;
  // 10/26/2026: Look at every card. A cert ID found on more than one
  // card (such as ID 03 on both a CAC and a YubiKey) is refused, the PIN
  // could be sent to the wrong card.
  for(CK_ULONG i = 0; i < num_slots; i++) {
    if(kid->has_slot && slots[i] != kid->slot) continue;
    num_candidates++;
    if(!have_first) {
      have_first = 1;
      first_slot = slots[i];
    }
    if(p->fl->C_OpenSession(slots[i], CKF_SERIAL_SESSION, 0, 0, &p->session) != CKR_OK) continue;
    p->has_session = 1;
    CK_OBJECT_HANDLE obj;
    if(SC_p11_find(p, CKO_PRIVATE_KEY, kid, &obj) || SC_p11_find(p, CKO_PUBLIC_KEY, kid, &obj) ||
       SC_p11_find(p, CKO_CERTIFICATE, kid, &obj)) {
      if(!found) found_slot = slots[i];
      found++;
    }
    p->fl->C_CloseSession(p->session);
    p->has_session = 0;
  }

  char names[256];
  if(found > 1 || (!found && num_candidates > 1)) SC_p11_slot_names(p, slots, num_slots, names, sizeof(names));
  delete[] slots;

  if(found > 1) {
    char msg[SC_err_string_size];
    snprintf(msg, sizeof(msg), "Error the smart card cert ID was found on %d cards, the PIN was not sent. "
	     "Cards in slots: %s. Remove the other cards or select the slot (--smartcard-slot=N)", found, names);
    return sc->SetError(msg);
  }
  if(!found) {
    if(!have_first) {
      if(kid->has_slot) {
	char msg[SC_err_string_size];
	snprintf(msg, sizeof(msg), "Error no smart card found in slot %lu", (unsigned long)kid->slot);
	return sc->SetError(msg);
      }
      return sc->SetError("Error no smart card found in the selected reader slot");
    }
    // 10/26/2026: Do not guess the card when the cert ID is not on any
    // card and more than one card is present, the PIN could be sent to
    // the wrong card
    if(num_candidates > 1) {
      char msg[SC_err_string_size];
      snprintf(msg, sizeof(msg), "Error the smart card cert ID was not found on any card and more than one card "
	       "is present, the PIN was not sent. Cards in slots: %s. Remove the other cards or select the slot "
	       "(--smartcard-slot=N)", names);
      return sc->SetError(msg);
    }
    found_slot = first_slot;
  }
  if(p->fl->C_OpenSession(found_slot, CKF_SERIAL_SESSION, 0, 0, &p->session) != CKR_OK) {
    return sc->SetError("Error opening a smart card session");
  }
  p->has_session = 1;
  p->slot = found_slot;

  CK_TOKEN_INFO token_info;
  memset(&token_info, 0, sizeof(token_info));
  if(p->fl->C_GetTokenInfo(found_slot, &token_info) == CKR_OK) p->token_flags = token_info.flags;
  return 0;
}

static int SC_p11_get_attr(SC_p11_session *p, CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_TYPE type,
			   unsigned char **value, CK_ULONG *value_len)
// Returns 1 on success or 0 for errors. The caller frees the value.
{
  *(value) = 0;
  *(value_len) = 0;
  CK_ATTRIBUTE attr;
  attr.type = type;
  attr.pValue = 0;
  attr.ulValueLen = 0;
  if(p->fl->C_GetAttributeValue(p->session, obj, &attr, 1) != CKR_OK) return 0;
  if(attr.ulValueLen == 0 || attr.ulValueLen == (CK_ULONG)-1) return 0;
  attr.pValue = new unsigned char[attr.ulValueLen];
  if(p->fl->C_GetAttributeValue(p->session, obj, &attr, 1) != CKR_OK) {
    delete[] (unsigned char *)attr.pValue;
    return 0;
  }
  *(value) = (unsigned char *)attr.pValue;
  *(value_len) = attr.ulValueLen;
  return 1;
}

static EVP_PKEY *SC_p11_rsa_public_key(SC_p11_session *p, CK_OBJECT_HANDLE obj)
{
  unsigned char *mod = 0, *exp = 0;
  CK_ULONG mod_len = 0, exp_len = 0;
  if(!SC_p11_get_attr(p, obj, CKA_MODULUS, &mod, &mod_len)) return 0;
  if(!SC_p11_get_attr(p, obj, CKA_PUBLIC_EXPONENT, &exp, &exp_len)) {
    delete[] mod;
    return 0;
  }

  EVP_PKEY *pkey = 0;
  BIGNUM *n = BN_bin2bn(mod, (int)mod_len, 0);
  BIGNUM *e = BN_bin2bn(exp, (int)exp_len, 0);
  OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
  OSSL_PARAM *params = 0;
  if(n && e && bld &&
     OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) &&
     OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e)) {
    params = OSSL_PARAM_BLD_to_param(bld);
  }
  if(params) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(AES_get_libctx(), "RSA", 0);
    if(ctx) {
      if(EVP_PKEY_fromdata_init(ctx) <= 0 ||
	 EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
	pkey = 0;
      }
      EVP_PKEY_CTX_free(ctx);
    }
    OSSL_PARAM_free(params);
  }
  OSSL_PARAM_BLD_free(bld);
  BN_free(n);
  BN_free(e);
  delete[] mod;
  delete[] exp;
  return pkey;
}

static X509 *SC_p11_cert_x509(SC_p11_session *p, CK_OBJECT_HANDLE obj)
// The caller frees the cert
{
  unsigned char *der = 0;
  CK_ULONG der_len = 0;
  if(!SC_p11_get_attr(p, obj, CKA_VALUE, &der, &der_len)) return 0;
  const unsigned char *dp = der;
  X509 *x509 = d2i_X509(0, &dp, (long)der_len);
  delete[] der;
  return x509;
}

static EVP_PKEY *SC_p11_cert_public_key(SC_p11_session *p, CK_OBJECT_HANDLE obj)
{
  X509 *x509 = SC_p11_cert_x509(p, obj);
  if(!x509) return 0;
  EVP_PKEY *pkey = X509_get_pubkey(x509);
  X509_free(x509);
  return pkey;
}

static int SC_mgf1_sha256(EVP_MD *md, const unsigned char seed[], unsigned seed_len,
			 unsigned char mask[], unsigned mask_len)
// XOR the MGF1 mask over mask[]. Returns 1 on success or 0 for errors.
{
  unsigned char cnt[4];
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int digest_len = 0;
  unsigned done = 0;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if(!ctx) return 0;
  for(unsigned long i = 0; done < mask_len; i++) {
    cnt[0] = (unsigned char)((i >> 24) & 0xFF);
    cnt[1] = (unsigned char)((i >> 16) & 0xFF);
    cnt[2] = (unsigned char)((i >> 8) & 0xFF);
    cnt[3] = (unsigned char)(i & 0xFF);
    if(!EVP_DigestInit_ex(ctx, md, 0) || !EVP_DigestUpdate(ctx, seed, seed_len) ||
       !EVP_DigestUpdate(ctx, cnt, sizeof(cnt)) || !EVP_DigestFinal_ex(ctx, digest, &digest_len)) {
      EVP_MD_CTX_free(ctx);
      return 0;
    }
    for(unsigned j = 0; j < digest_len && done < mask_len; j++) mask[done++] ^= digest[j];
  }
  OPENSSL_cleanse(digest, sizeof(digest));
  EVP_MD_CTX_free(ctx);
  return 1;
}

static int SC_oaep_sha256_decode(unsigned char em[], unsigned em_len,
				 unsigned char out[], unsigned out_size, unsigned *out_len)
// RFC 8017 EME-OAEP decoding with SHA-256, MGF1-SHA256 and an empty label,
// used when the card can only do raw RSA. em[] is overwritten.
// Returns 1 on success or 0 for errors.
{
  EVP_MD *md = EVP_MD_fetch(AES_get_libctx(), "SHA256", 0);
  if(!md) return 0;
  const unsigned h_len = 32;
  if(em_len < (2 * h_len) + 2) {
    EVP_MD_free(md);
    return 0;
  }
  unsigned char *seed = em + 1;
  unsigned char *db = em + 1 + h_len;
  unsigned db_len = em_len - h_len - 1;
  unsigned char l_hash[EVP_MAX_MD_SIZE];
  unsigned int l_hash_len = 0;
  int ok = EVP_Digest("", 0, l_hash, &l_hash_len, md, 0) &&
    SC_mgf1_sha256(md, db, db_len, seed, h_len) &&
    SC_mgf1_sha256(md, seed, h_len, db, db_len);
  EVP_MD_free(md);
  if(!ok) return 0;

  // Check every byte before reporting a single padding error
  unsigned bad = em[0];
  for(unsigned i = 0; i < h_len; i++) bad |= (unsigned)(db[i] ^ l_hash[i]);
  unsigned msg_start = 0;
  unsigned looking = 1;
  for(unsigned i = h_len; i < db_len; i++) {
    unsigned is_one = (db[i] == 0x01);
    unsigned is_zero = (db[i] == 0x00);
    if(looking && is_one) msg_start = i + 1;
    if(looking && !is_one && !is_zero) bad |= 1;
    if(is_one) looking = 0;
  }
  if(looking) bad |= 1;
  if(bad) return 0;
  unsigned msg_len = db_len - msg_start;
  if(msg_len > out_size) return 0;
  memmove(out, db + msg_start, msg_len);
  *(out_len) = msg_len;
  return 1;
}

int SC_public_key_encrypt(SmartCardOB *sc,
			  const unsigned char plaintext[], unsigned int plaintext_len,
			  unsigned char ciphertext[], unsigned int ciphertext_len,
			  unsigned *encrypted_data_len, int padding)
{
  RSA_openssl_init();

  SC_key_id kid;
  if(!SC_parse_cert_id(sc->cert_id, &kid)) {
    return sc->SetError("Error bad smart card cert ID");
  }

  SC_p11_session p;
  if(SC_p11_load(sc, &p) != 0) return sc->error_level;
  if(SC_p11_open_token(sc, &p, &kid) != 0) {
    SC_p11_close(&p);
    return sc->error_level;
  }

  // Use the public key object, or the public key in the cert
  EVP_PKEY *evkey = 0;
  CK_OBJECT_HANDLE obj;
  if(SC_p11_find(&p, CKO_PUBLIC_KEY, &kid, &obj)) evkey = SC_p11_rsa_public_key(&p, obj);
  if(!evkey && SC_p11_find(&p, CKO_CERTIFICATE, &kid, &obj)) evkey = SC_p11_cert_public_key(&p, obj);
  SC_p11_close(&p);
  if(!evkey) {
    return sc->SetError("Error loading smart card public key");
  }

  if(RSA_pkey_encrypt(evkey, plaintext, plaintext_len, ciphertext, ciphertext_len,
		      encrypted_data_len, padding) != RSA_NO_ERROR) {
    EVP_PKEY_free(evkey);
    return sc->SetError("Public key encrypt failed");
  }

  EVP_PKEY_free(evkey);
  return 0;
}

static int SC_p11_pin_error(CK_RV rv)
{
  return (rv == CKR_PIN_INCORRECT || rv == CKR_PIN_LOCKED || rv == CKR_PIN_EXPIRED ||
	  rv == CKR_USER_NOT_LOGGED_IN);
}

static int SC_p11_pin_pad(SmartCardOB *sc, SC_p11_session *p)
// A PIN pad reader takes the PIN itself when no PIN is given
{
  return (sc->pin[0] == 0 && (p->token_flags & CKF_PROTECTED_AUTHENTICATION_PATH));
}

static void SC_p11_read_flags(SmartCardOB *sc, SC_p11_session *p)
{
  CK_TOKEN_INFO token_info;
  memset(&token_info, 0, sizeof(token_info));
  sc->token_flags_known = 0;
  if(p->fl->C_GetTokenInfo(p->slot, &token_info) == CKR_OK) {
    sc->token_flags = (unsigned long)token_info.flags;
    sc->token_flags_known = 1;
    p->token_flags = token_info.flags;
  }
}

static int SC_p11_check_pin(SmartCardOB *sc, SC_p11_session *p)
// 10/26/2026: Checks made before the PIN is sent to the card. Returns 0
// if the PIN can be sent. Modules that do not report the PIN tries,
// such as ActivClient may, pass these checks, so they are not a promise
// the card has tries left.
{
  if(SC_login_failed) {
    return sc->SetError("Smart card PIN not sent, a card login already failed in this run. "
			"Check the PIN and the PIN tries left before running again", SC_ERROR_PIN_BLOCKED);
  }
  CK_TOKEN_INFO token_info;
  memset(&token_info, 0, sizeof(token_info));
  sc->token_flags_known = 0;
  sc->token_flags = 0;
  if(p->fl->C_GetTokenInfo(p->slot, &token_info) == CKR_OK) {
    sc->token_flags = (unsigned long)token_info.flags;
    sc->token_flags_known = 1;
    p->token_flags = token_info.flags;
  }
  if(sc->token_flags_known) {
    if(token_info.flags & CKF_USER_PIN_LOCKED) {
      return sc->SetError("Smart card PIN is locked, the PIN was not sent. The card must be unlocked "
			  "by its issuer (for a CAC, a DEERS/RAPIDS or local registration office)", SC_ERROR_PIN_LOCKED);
    }
    if((token_info.flags & CKF_USER_PIN_FINAL_TRY) && !sc->allow_pin_final_try) {
      return sc->SetError("Smart card PIN not sent, the card reports ONE PIN try is left and a wrong PIN "
			  "will lock it. Override only if you are sure of the PIN", SC_ERROR_PIN_FINAL_TRY);
    }
    if((token_info.flags & CKF_USER_PIN_COUNT_LOW) && !sc->allow_pin_count_low) {
      return sc->SetError("Smart card PIN not sent, the card reports it is low on PIN tries "
			  "(a wrong PIN was entered before). Override only if you are sure of the PIN", SC_ERROR_PIN_COUNT_LOW);
    }
  }
  if(sc->pin_too_long) {
    return sc->SetError("Smart card PIN not sent, the PIN is too long", SC_ERROR_PIN_INVALID);
  }
  if(SC_p11_pin_pad(sc, p)) return 0;
  size_t len = strlen(sc->pin);
  if(len == 0) {
    return sc->SetError("Smart card PIN not sent, the PIN is empty", SC_ERROR_PIN_INVALID);
  }
  for(size_t i = 0; i < len; i++) {
    if((unsigned char)sc->pin[i] < 0x20 || (unsigned char)sc->pin[i] == 0x7F) {
      return sc->SetError("Smart card PIN not sent, the PIN has a control character such as a "
			  "tab or carriage return", SC_ERROR_PIN_INVALID);
    }
  }
  if(sc->token_flags_known && token_info.ulMaxPinLen != CK_UNAVAILABLE_INFORMATION &&
     token_info.ulMaxPinLen > 0 && token_info.ulMaxPinLen <= 1024 &&
     token_info.ulMinPinLen <= token_info.ulMaxPinLen &&
     (len < token_info.ulMinPinLen || len > token_info.ulMaxPinLen)) {
    char msg[SC_err_string_size];
    snprintf(msg, sizeof(msg), "Smart card PIN not sent, the card PIN must be %lu to %lu characters",
	     (unsigned long)token_info.ulMinPinLen, (unsigned long)token_info.ulMaxPinLen);
    return sc->SetError(msg, SC_ERROR_PIN_INVALID);
  }
  return 0;
}

static CK_RV SC_p11_login(SmartCardOB *sc, SC_p11_session *p, CK_USER_TYPE user_type)
// 10/26/2026: The only place the PIN is sent to the card. Any failure
// blocks every later login in this program run.
{
  CK_RV rv;
  if(SC_login_failed) return CKR_PIN_INCORRECT;
  if(SC_p11_pin_pad(sc, p)) {
    rv = p->fl->C_Login(p->session, user_type, 0, 0);
  }
  else {
    rv = p->fl->C_Login(p->session, user_type, (CK_UTF8CHAR_PTR)sc->pin, (CK_ULONG)strlen(sc->pin));
  }
  if(rv != CKR_OK && !(user_type == CKU_USER && rv == CKR_USER_ALREADY_LOGGED_IN)) SC_login_failed = 1;
  return rv;
}

static int SC_p11_login_error(SmartCardOB *sc, SC_p11_session *p, CK_RV rv)
// Sets the error after a failed login. Call before closing the session.
{
  SC_p11_read_flags(sc, p);
  char msg[SC_err_string_size];
  if(rv == CKR_PIN_INCORRECT) {
    snprintf(msg, sizeof(msg), "Smart card PIN is incorrect, ONE PIN try was used. %s. "
	     "The PIN will not be sent again in this run, check the PIN tries left before trying again",
	     SC_pin_tries_string(sc));
    return sc->SetError(msg, SC_ERROR_PIN_INCORRECT);
  }
  if(rv == CKR_PIN_LOCKED) {
    return sc->SetError("Smart card PIN is locked. The card must be unlocked by its issuer", SC_ERROR_PIN_LOCKED);
  }
  snprintf(msg, sizeof(msg), "Smart card login failed, PKCS#11 error 0x%lx. %s. "
	   "The PIN will not be sent again in this run", (unsigned long)rv, SC_pin_tries_string(sc));
  return sc->SetError(msg, SC_ERROR_LOGIN);
}

int SC_private_key_decrypt(SmartCardOB *sc,
			   const unsigned char ciphertext[], unsigned int ciphertext_len,
			   unsigned char plaintext[], unsigned int plaintext_len,
			   unsigned *unencrypted_data_len,
			   int padding)
{
  *(unencrypted_data_len) = 0;
  RSA_openssl_init();

  CK_RSA_PKCS_OAEP_PARAMS oaep_params;
  memset(&oaep_params, 0, sizeof(oaep_params));
  CK_MECHANISM mech;
  memset(&mech, 0, sizeof(mech));
  if(padding == RSA_PKCS1_PADDING) {
    mech.mechanism = CKM_RSA_PKCS;
  }
  else if(padding == RSA_PKCS1_OAEP_PADDING) {
    // Matches the SHA-256 OAEP used by RSA_pkey_encrypt()
    oaep_params.hashAlg = CKM_SHA256;
    oaep_params.mgf = CKG_MGF1_SHA256;
    oaep_params.source = CKZ_DATA_SPECIFIED;
    mech.mechanism = CKM_RSA_PKCS_OAEP;
    mech.pParameter = &oaep_params;
    mech.ulParameterLen = sizeof(oaep_params);
  }
  else {
    return sc->SetError("Error unsupported smart card RSA padding");
  }

  SC_key_id kid;
  if(!SC_parse_cert_id(sc->cert_id, &kid)) {
    return sc->SetError("Error bad smart card cert ID");
  }

  SC_p11_session p;
  if(SC_p11_load(sc, &p) != 0) return sc->error_level;
  if(SC_p11_open_token(sc, &p, &kid) != 0) {
    SC_p11_close(&p);
    return sc->error_level;
  }

  // 10/26/2026: Check the card PIN flags and the PIN before sending it,
  // then log in once
  if(SC_p11_check_pin(sc, &p) != 0) {
    SC_p11_close(&p);
    return sc->error_level;
  }
  CK_RV rv = SC_p11_login(sc, &p, CKU_USER);
  if(rv == CKR_OK) {
    p.logged_in = 1;
  }
  else if(rv != CKR_USER_ALREADY_LOGGED_IN) {
    int level = SC_p11_login_error(sc, &p, rv);
    SC_p11_close(&p);
    return level;
  }

  CK_OBJECT_HANDLE key;
  if(!SC_p11_find(&p, CKO_PRIVATE_KEY, &kid, &key)) {
    SC_p11_close(&p);
    return sc->SetError("Error loading smart card private key");
  }

  // Keys such as a PIV or CAC signature key ask for the PIN again
  // before each use
  CK_BBOOL always_auth = CK_FALSE;
  CK_ATTRIBUTE always_attr;
  always_attr.type = CKA_ALWAYS_AUTHENTICATE;
  always_attr.pValue = &always_auth;
  always_attr.ulValueLen = sizeof(always_auth);
  if(p.fl->C_GetAttributeValue(p.session, key, &always_attr, 1) != CKR_OK) always_auth = CK_FALSE;

  // Decrypt to a work buffer the size of the largest key, then copy
  unsigned char work[SC_max_rsa_len];
  CK_ULONG work_len = sizeof(work);
  int oaep_raw = 0;
  int context_login_failed = 0;
  rv = p.fl->C_DecryptInit(p.session, &mech, key);
  if(rv == CKR_OK && always_auth) {
    rv = SC_p11_login(sc, &p, CKU_CONTEXT_SPECIFIC);
    if(rv != CKR_OK) context_login_failed = 1;
  }
  if(rv == CKR_OK) {
    rv = p.fl->C_Decrypt(p.session, (CK_BYTE_PTR)ciphertext, ciphertext_len, work, &work_len);
  }
  CK_RV first_rv = rv;
  CK_RV raw_rv = CKR_OK;
  // Never retry after a PIN error, CAC and PIV cards lock after a few
  // 10/26/2026: No fallback after any failed login, the PIN is sent once
  if(rv != CKR_OK && !SC_p11_pin_error(rv) && !context_login_failed && !SC_login_failed &&
     padding == RSA_PKCS1_OAEP_PADDING && ciphertext_len <= sizeof(work)) {
    // Many cards and SoftHSM have no SHA-256 OAEP, use raw RSA and
    // remove the OAEP padding here
    CK_MECHANISM raw_mech;
    memset(&raw_mech, 0, sizeof(raw_mech));
    raw_mech.mechanism = CKM_RSA_X_509;
    work_len = sizeof(work);
    rv = p.fl->C_DecryptInit(p.session, &raw_mech, key);
    if(rv == CKR_OPERATION_ACTIVE) {
      // Some modules, such as ActivClient, leave the failed decrypt
      // active. Move to a new session, the login stays while a session
      // is open and the key handle is valid in every session.
      CK_SESSION_HANDLE new_session;
      if(p.fl->C_OpenSession(p.slot, CKF_SERIAL_SESSION, 0, 0, &new_session) == CKR_OK) {
	p.fl->C_CloseSession(p.session);
	p.session = new_session;
	rv = p.fl->C_DecryptInit(p.session, &raw_mech, key);
      }
    }
    if(rv == CKR_OK && always_auth) {
      rv = SC_p11_login(sc, &p, CKU_CONTEXT_SPECIFIC);
      if(rv != CKR_OK) context_login_failed = 1;
    }
    if(rv == CKR_OK) {
      rv = p.fl->C_Decrypt(p.session, (CK_BYTE_PTR)ciphertext, ciphertext_len, work, &work_len);
    }
    raw_rv = rv;
    oaep_raw = 1;
  }
  if(context_login_failed) {
    int level = SC_p11_login_error(sc, &p, rv);
    SC_p11_close(&p);
    return level;
  }
  SC_p11_close(&p);
  if(rv == CKR_PIN_INCORRECT || rv == CKR_PIN_LOCKED || rv == CKR_USER_NOT_LOGGED_IN) {
    // A PIN error from the decrypt itself, do not log in again
    SC_login_failed = 1;
    return sc->SetError("Smart card PIN error during the decrypt. The PIN will not be sent again in this run", SC_ERROR_LOGIN);
  }

  int ok = (rv == CKR_OK);
  unsigned out_len = (unsigned)work_len;
  if(ok && oaep_raw) {
    // Put back leading zero bytes some modules drop from the raw result
    if(work_len > ciphertext_len) {
      ok = 0;
    }
    else if(work_len < ciphertext_len) {
      unsigned pad = ciphertext_len - (unsigned)work_len;
      memmove(work + pad, work, work_len);
      memset(work, 0, pad);
    }
    if(ok) ok = SC_oaep_sha256_decode(work, ciphertext_len, plaintext, plaintext_len, &out_len);
  }
  else if(ok) {
    if(work_len > plaintext_len) ok = 0;
    else memmove(plaintext, work, work_len);
  }
  OPENSSL_cleanse(work, sizeof(work));
  if(!ok) {
    // Show the PKCS#11 return codes to help with card and module problems
    char msg[SC_err_string_size];
    if(rv == CKR_OK) {
      snprintf(msg, sizeof(msg), "Private key decrypt failed, the decrypted data is not valid");
    }
    else if(oaep_raw) {
      snprintf(msg, sizeof(msg), "Private key decrypt failed, PKCS#11 error 0x%lx (OAEP) and 0x%lx (raw RSA)",
	       (unsigned long)first_rv, (unsigned long)raw_rv);
    }
    else {
      snprintf(msg, sizeof(msg), "Private key decrypt failed, PKCS#11 error 0x%lx", (unsigned long)rv);
    }
    return sc->SetError(msg);
  }
  *(unencrypted_data_len) = out_len;
  return 0;
}

// ----------------------------------------------------------- //
// 10/27/2026: Smart card listing. No C_Login, no PIN: C_GetSlotList,
// C_GetSlotInfo, C_GetTokenInfo and a public session that finds the
// certificate and public key objects the card shows before login.
// ----------------------------------------------------------- //
static std::string SC_p11_text(const CK_UTF8CHAR *text, unsigned len)
// PKCS#11 info fields are blank padded and not null terminated
{
  std::string s((const char *)text, len);
  size_t end = s.find_last_not_of(" \t");
  s.erase((end == std::string::npos) ? 0 : end + 1);
  size_t nul = s.find('\0');
  if(nul != std::string::npos) s.erase(nul);
  return s;
}

static std::string SC_hex_string(const unsigned char *buf, unsigned len)
{
  static const char hexd[] = "0123456789abcdef";
  std::string s;
  for(unsigned i = 0; i < len; i++) {
    s += hexd[(buf[i] >> 4) & 0x0F];
    s += hexd[buf[i] & 0x0F];
  }
  return s;
}

static unsigned SC_p11_find_all(SC_p11_session *p, CK_OBJECT_CLASS obj_class,
				CK_OBJECT_HANDLE objs[], unsigned max_objs)
// Returns the number of objects of this class found
{
  CK_ATTRIBUTE tmpl[1];
  tmpl[0].type = CKA_CLASS;
  tmpl[0].pValue = &obj_class;
  tmpl[0].ulValueLen = sizeof(obj_class);
  if(p->fl->C_FindObjectsInit(p->session, tmpl, 1) != CKR_OK) return 0;
  unsigned total = 0;
  while(total < max_objs) {
    CK_ULONG found = 0;
    if(p->fl->C_FindObjects(p->session, objs + total, (CK_ULONG)(max_objs - total), &found) != CKR_OK) break;
    if(found == 0) break;
    total += (unsigned)found;
  }
  p->fl->C_FindObjectsFinal(p->session);
  return total;
}

static std::string SC_name_cn(X509_NAME *name)
{
  char cn[256];
  memset(cn, 0, sizeof(cn));
  if(!name || X509_NAME_get_text_by_NID(name, NID_commonName, cn, sizeof(cn)) < 0) return std::string();
  return std::string(cn);
}

static void SC_key_info(EVP_PKEY *pkey, SC_CertInfo &ci)
{
  if(!pkey) return;
  ci.key_bits = EVP_PKEY_get_bits(pkey);
  ci.is_rsa = (EVP_PKEY_get_base_id(pkey) == EVP_PKEY_RSA);
  unsigned char *der = 0;
  int der_len = i2d_PUBKEY(pkey, &der);
  if(der_len > 0) {
    unsigned char md[32];
    unsigned int md_len = 0;
    if(EVP_Digest(der, (size_t)der_len, md, &md_len, EVP_sha256(), 0)) ci.spki_sha256 = SC_hex_string(md, md_len);
  }
  OPENSSL_free(der);
}

static void SC_p11_object_id(SC_p11_session *p, CK_OBJECT_HANDLE obj, SC_CertInfo &ci)
{
  unsigned char *value = 0;
  CK_ULONG value_len = 0;
  if(SC_p11_get_attr(p, obj, CKA_ID, &value, &value_len)) {
    ci.id_hex = SC_hex_string(value, (unsigned)value_len);
    delete[] value;
  }
  if(SC_p11_get_attr(p, obj, CKA_LABEL, &value, &value_len)) {
    ci.label = SC_p11_text(value, (unsigned)value_len);
    delete[] value;
  }
}

static void SC_p11_list_objects(SC_p11_session *p, SC_TokenInfo &ti)
{
  const unsigned max_objs = 64;
  CK_OBJECT_HANDLE objs[max_objs];
  unsigned n = SC_p11_find_all(p, CKO_CERTIFICATE, objs, max_objs);
  for(unsigned i = 0; i < n; i++) {
    SC_CertInfo ci;
    SC_p11_object_id(p, objs[i], ci);
    X509 *x509 = SC_p11_cert_x509(p, objs[i]);
    if(x509) {
      ci.has_cert = 1;
      ci.subject_cn = SC_name_cn(X509_get_subject_name(x509));
      ci.issuer_cn = SC_name_cn(X509_get_issuer_name(x509));
      struct tm tm;
      memset(&tm, 0, sizeof(tm));
      if(ASN1_TIME_to_tm(X509_get0_notAfter(x509), &tm)) {
	char buf[32];
	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
	ci.not_after = buf;
      }
      EVP_PKEY *pkey = X509_get_pubkey(x509);
      SC_key_info(pkey, ci);
      EVP_PKEY_free(pkey);
      X509_free(x509);
    }
    ti.certs.push_back(ci);
  }

  // Public key objects with no cert of the same ID, such as a key made
  // on the card before a cert was loaded
  n = SC_p11_find_all(p, CKO_PUBLIC_KEY, objs, max_objs);
  for(unsigned i = 0; i < n; i++) {
    SC_CertInfo ci;
    SC_p11_object_id(p, objs[i], ci);
    int have = 0;
    for(size_t k = 0; k < ti.certs.size(); k++) {
      if(ti.certs[k].has_cert && ti.certs[k].id_hex == ci.id_hex) have = 1;
    }
    if(have) continue;
    unsigned char *value = 0;
    CK_ULONG value_len = 0;
    CK_KEY_TYPE key_type = CKK_RSA;
    if(SC_p11_get_attr(p, objs[i], CKA_KEY_TYPE, &value, &value_len)) {
      if(value_len == sizeof(CK_KEY_TYPE)) memmove(&key_type, value, sizeof(CK_KEY_TYPE));
      delete[] value;
    }
    if(key_type == CKK_RSA) {
      EVP_PKEY *pkey = SC_p11_rsa_public_key(p, objs[i]);
      SC_key_info(pkey, ci);
      EVP_PKEY_free(pkey);
    }
    ti.certs.push_back(ci);
  }
}

int SC_list_tokens(const char *module_path, std::vector<SC_TokenInfo> &out, std::string &err)
{
  out.clear();
  err.clear();
  RSA_openssl_init();

  // SC_p11_load() only uses the module path and the error string
  SmartCardOB sc;
  if(module_path && *module_path) {
    if(strlen(module_path) >= sizeof(sc.modulePath)) {
      err = "Error the smart card provider module path is too long";
      return SC_ERROR;
    }
    sc.SetModulePath((char *)module_path);
  }
  SC_p11_session p;
  if(SC_p11_load(&sc, &p) != 0) {
    err = sc.err_string;
    return SC_ERROR;
  }

  CK_ULONG num_slots = 0;
  if(p.fl->C_GetSlotList(CK_TRUE, 0, &num_slots) != CKR_OK) {
    SC_p11_close(&p);
    err = "Error listing the smart card readers";
    return SC_ERROR;
  }
  if(num_slots == 0) {
    SC_p11_close(&p);
    return 0;
  }
  CK_SLOT_ID *slots = new CK_SLOT_ID[num_slots];
  if(p.fl->C_GetSlotList(CK_TRUE, slots, &num_slots) != CKR_OK) {
    delete[] slots;
    SC_p11_close(&p);
    err = "Error listing the smart card readers";
    return SC_ERROR;
  }

  for(CK_ULONG i = 0; i < num_slots; i++) {
    SC_TokenInfo ti;
    ti.slot_id = (unsigned long)slots[i];
    CK_SLOT_INFO si;
    memset(&si, 0, sizeof(si));
    if(p.fl->C_GetSlotInfo(slots[i], &si) == CKR_OK) {
      ti.slot_description = SC_p11_text(si.slotDescription, sizeof(si.slotDescription));
    }
    CK_TOKEN_INFO tk;
    memset(&tk, 0, sizeof(tk));
    if(p.fl->C_GetTokenInfo(slots[i], &tk) == CKR_OK) {
      ti.token_label = SC_p11_text(tk.label, sizeof(tk.label));
      ti.manufacturer = SC_p11_text(tk.manufacturerID, sizeof(tk.manufacturerID));
      ti.model = SC_p11_text(tk.model, sizeof(tk.model));
      ti.serial = SC_p11_text(tk.serialNumber, sizeof(tk.serialNumber));
      ti.flags = (unsigned long)tk.flags;
      ti.token_initialized = (tk.flags & CKF_TOKEN_INITIALIZED) != 0;
      ti.login_required = (tk.flags & CKF_LOGIN_REQUIRED) != 0;
      ti.protected_auth_path = (tk.flags & CKF_PROTECTED_AUTHENTICATION_PATH) != 0;
      ti.user_pin_initialized = (tk.flags & CKF_USER_PIN_INITIALIZED) != 0;
      ti.user_pin_locked = (tk.flags & CKF_USER_PIN_LOCKED) != 0;
      ti.user_pin_final_try = (tk.flags & CKF_USER_PIN_FINAL_TRY) != 0;
      ti.user_pin_count_low = (tk.flags & CKF_USER_PIN_COUNT_LOW) != 0;
      ti.user_pin_to_be_changed = (tk.flags & CKF_USER_PIN_TO_BE_CHANGED) != 0;
      // Some modules report CK_UNAVAILABLE_INFORMATION or nonsense lengths
      if(tk.ulMaxPinLen != CK_UNAVAILABLE_INFORMATION && tk.ulMaxPinLen > 0 && tk.ulMaxPinLen <= 1024 &&
	 tk.ulMinPinLen <= tk.ulMaxPinLen) {
	ti.min_pin_len = (unsigned long)tk.ulMinPinLen;
	ti.max_pin_len = (unsigned long)tk.ulMaxPinLen;
      }
    }
    // A read-only public session, objects marked private stay hidden
    if(p.fl->C_OpenSession(slots[i], CKF_SERIAL_SESSION, 0, 0, &p.session) == CKR_OK) {
      p.has_session = 1;
      p.slot = slots[i];
      SC_p11_list_objects(&p, ti);
      ti.objects_listed = 1;
      p.fl->C_CloseSession(p.session);
      p.has_session = 0;
    }
    out.push_back(ti);
  }
  delete[] slots;
  SC_p11_close(&p);
  return 0;
}
#endif // __SC_USE_ENGINE__

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
    // 10/25/2026: Check the space left before copying
    if(input_bytes_read > SC_max_cert_file_len || offset > (SC_max_cert_file_len - input_bytes_read)) {
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
 
 // 10/25/2026: Use EVP_PKEY instead of the deprecated RSA_* calls
 if(RSA_pkey_encrypt(evkey, plaintext, plaintext_len, ciphertext, ciphertext_len,
		     encrypted_data_len, padding) != RSA_NO_ERROR) {
   BIO_free(keybio);
   X509_free(x509);
   EVP_PKEY_free(evkey);
   return sc->SetError("Public key encrypt failed");
 }

 BIO_free(keybio);
 X509_free(x509);
 EVP_PKEY_free(evkey);
  
  return 0;
}

// ----------------------------------------------------------- //
// 10/27/2026: Key fingerprints and card matching, no card access
// ----------------------------------------------------------- //
SC_TokenInfo::SC_TokenInfo()
{
  slot_id = 0;
  flags = 0;
  token_initialized = login_required = protected_auth_path = user_pin_initialized = 0;
  user_pin_locked = user_pin_final_try = user_pin_count_low = user_pin_to_be_changed = 0;
  min_pin_len = max_pin_len = 0;
  objects_listed = 0;
}

static EVP_PKEY *SC_read_any_public_key(const unsigned char *buf, unsigned len)
// DER or PEM SubjectPublicKeyInfo or X.509 cert
{
  if(!buf || len == 0) return 0;
  const unsigned char *dp = buf;
  EVP_PKEY *pkey = d2i_PUBKEY(0, &dp, (long)len);
  if(pkey) return pkey;
  dp = buf;
  X509 *x509 = d2i_X509(0, &dp, (long)len);
  if(!x509) {
    BIO *bio = BIO_new_mem_buf(buf, (int)len);
    if(!bio) return 0;
    x509 = PEM_read_bio_X509(bio, 0, 0, 0);
    if(!x509) {
      BIO_free(bio);
      bio = BIO_new_mem_buf(buf, (int)len);
      if(!bio) return 0;
      pkey = PEM_read_bio_PUBKEY(bio, 0, 0, 0);
    }
    BIO_free(bio);
    ERR_clear_error();
    if(pkey) return pkey;
    if(!x509) return 0;
  }
  pkey = X509_get_pubkey(x509);
  X509_free(x509);
  return pkey;
}

int SC_spki_sha256(const unsigned char *buf, unsigned len, std::string &hex)
{
  hex.clear();
  EVP_PKEY *pkey = SC_read_any_public_key(buf, len);
  if(!pkey) return SC_ERROR;
  unsigned char *der = 0;
  int der_len = i2d_PUBKEY(pkey, &der);
  EVP_PKEY_free(pkey);
  if(der_len <= 0) return SC_ERROR;
  unsigned char md[32];
  unsigned int md_len = 0;
  int ok = EVP_Digest(der, (size_t)der_len, md, &md_len, EVP_sha256(), 0);
  OPENSSL_free(der);
  if(!ok) return SC_ERROR;
  static const char hexd[] = "0123456789abcdef";
  for(unsigned i = 0; i < md_len; i++) {
    hex += hexd[(md[i] >> 4) & 0x0F];
    hex += hexd[md[i] & 0x0F];
  }
  return 0;
}

unsigned SC_match_public_keys(const std::vector<SC_TokenInfo> &tokens,
			      const std::vector<std::string> &keys,
			      std::vector<SC_CertMatch> &matches)
{
  matches.clear();
  for(size_t k = 0; k < keys.size(); k++) {
    std::string fp;
    if(SC_spki_sha256((const unsigned char *)keys[k].data(), (unsigned)keys[k].size(), fp) != 0) continue;
    for(size_t t = 0; t < tokens.size(); t++) {
      for(size_t c = 0; c < tokens[t].certs.size(); c++) {
	const SC_CertInfo &ci = tokens[t].certs[c];
	if(ci.spki_sha256.empty() || ci.spki_sha256 != fp) continue;
	int dup = 0; // A key on the card as a cert and a public key object
	for(size_t m = 0; m < matches.size(); m++) {
	  if(matches[m].key_index == (unsigned)k && matches[m].slot_id == tokens[t].slot_id &&
	     matches[m].id_hex == ci.id_hex) dup = 1;
	}
	if(dup) continue;
	SC_CertMatch cm;
	cm.slot_id = tokens[t].slot_id;
	cm.token_label = tokens[t].token_label;
	cm.id_hex = ci.id_hex;
	cm.key_index = (unsigned)k;
	matches.push_back(cm);
      }
    }
  }
  return (unsigned)matches.size();
}

#endif // __ENABLE_SMART_CARD__
// ----------------------------------------------------------- // 
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
    
