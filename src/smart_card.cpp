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
#elif defined (__RHEL7__)
const char *SC_default_enginePath = "/usr/lib64/openssl/engines/pkcs11.so";
#elif defined (__RHEL6__)
const char *SC_default_enginePath = "/usr/lib64/openssl/engines/pkcs11.so";
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

  // Set the users pin
  ENGINE_ctrl_cmd_string(engine, "PIN", sc->pin, 0);
  
  EVP_PKEY *evkey = ENGINE_load_private_key(engine, sc->cert_id, 0, 0);
  if(!evkey) {
    ENGINE_free(engine);
    return  sc->SetError("Error loading smart card private key");
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
    unsigned long slot = strtoul(p+5, &end, 10);
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

static int SC_p11_open_token(SmartCardOB *sc, SC_p11_session *p, const SC_key_id *kid)
// Open a session on the token that holds the key. Private keys can be
// hidden until login, so if no token shows the key ID the first token
// is used.
{
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
  int found = 0;
  CK_SLOT_ID found_slot = 0;
  for(CK_ULONG i = 0; i < num_slots && !found; i++) {
    if(kid->has_slot && slots[i] != kid->slot) continue;
    if(!have_first) {
      have_first = 1;
      first_slot = slots[i];
    }
    if(p->fl->C_OpenSession(slots[i], CKF_SERIAL_SESSION, 0, 0, &p->session) != CKR_OK) continue;
    p->has_session = 1;
    CK_OBJECT_HANDLE obj;
    if(SC_p11_find(p, CKO_PRIVATE_KEY, kid, &obj) || SC_p11_find(p, CKO_PUBLIC_KEY, kid, &obj) ||
       SC_p11_find(p, CKO_CERTIFICATE, kid, &obj)) {
      found = 1;
      found_slot = slots[i];
    }
    p->fl->C_CloseSession(p->session);
    p->has_session = 0;
  }
  delete[] slots;

  if(!found) {
    if(!have_first) return sc->SetError("Error no smart card found in the selected reader slot");
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

static EVP_PKEY *SC_p11_cert_public_key(SC_p11_session *p, CK_OBJECT_HANDLE obj)
{
  unsigned char *der = 0;
  CK_ULONG der_len = 0;
  if(!SC_p11_get_attr(p, obj, CKA_VALUE, &der, &der_len)) return 0;
  const unsigned char *dp = der;
  X509 *x509 = d2i_X509(0, &dp, (long)der_len);
  delete[] der;
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

static CK_RV SC_p11_context_login(SC_p11_session *p, SmartCardOB *sc)
{
  if(sc->pin[0] == 0 && (p->token_flags & CKF_PROTECTED_AUTHENTICATION_PATH)) {
    return p->fl->C_Login(p->session, CKU_CONTEXT_SPECIFIC, 0, 0);
  }
  return p->fl->C_Login(p->session, CKU_CONTEXT_SPECIFIC, (CK_UTF8CHAR_PTR)sc->pin, (CK_ULONG)strlen(sc->pin));
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

  // Set the users pin, a PIN pad reader takes the PIN itself
  CK_RV rv;
  if(sc->pin[0] == 0 && (p.token_flags & CKF_PROTECTED_AUTHENTICATION_PATH)) {
    rv = p.fl->C_Login(p.session, CKU_USER, 0, 0);
  }
  else {
    rv = p.fl->C_Login(p.session, CKU_USER, (CK_UTF8CHAR_PTR)sc->pin, (CK_ULONG)strlen(sc->pin));
  }
  if(rv == CKR_OK) {
    p.logged_in = 1;
  }
  else if(rv != CKR_USER_ALREADY_LOGGED_IN) {
    SC_p11_close(&p);
    if(rv == CKR_PIN_INCORRECT) return sc->SetError("Smart card PIN is incorrect");
    if(rv == CKR_PIN_LOCKED) return sc->SetError("Smart card PIN is locked");
    return sc->SetError("Smart card login failed");
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
  rv = p.fl->C_DecryptInit(p.session, &mech, key);
  if(rv == CKR_OK && always_auth) rv = SC_p11_context_login(&p, sc);
  if(rv == CKR_OK) {
    rv = p.fl->C_Decrypt(p.session, (CK_BYTE_PTR)ciphertext, ciphertext_len, work, &work_len);
  }
  CK_RV first_rv = rv;
  CK_RV raw_rv = CKR_OK;
  // Never retry after a PIN error, CAC and PIV cards lock after a few
  if(rv != CKR_OK && !SC_p11_pin_error(rv) && padding == RSA_PKCS1_OAEP_PADDING &&
     ciphertext_len <= sizeof(work)) {
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
    if(rv == CKR_OK && always_auth) rv = SC_p11_context_login(&p, sc);
    if(rv == CKR_OK) {
      rv = p.fl->C_Decrypt(p.session, (CK_BYTE_PTR)ciphertext, ciphertext_len, work, &work_len);
    }
    raw_rv = rv;
    oaep_raw = 1;
  }
  SC_p11_close(&p);
  if(rv == CKR_PIN_INCORRECT) return sc->SetError("Smart card PIN is incorrect");
  if(rv == CKR_PIN_LOCKED) return sc->SetError("Smart card PIN is locked");

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

#endif // __ENABLE_SMART_CARD__
// ----------------------------------------------------------- // 
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
    
