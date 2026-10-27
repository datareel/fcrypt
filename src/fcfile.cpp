// ------------------------------- //
// -------- Start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- //
// C++ Source Code File Name: fcfile.cpp
// Compiler Used: MSVC, GCC
// Produced By: DataReel Software Development Team
// File Creation Date: 10/25/2026
// Date Last Modified: 10/25/2026
// Copyright (c) 2001-2026 DataReel Software Development
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

fcrypt file format version 2026102. See fcfile.h for the layout.
*/
// ----------------------------------------------------------- //
#include "fcfile.h"
#include "fcfips.h"
#include "cryptdb.h"
#include "futils.h"
#include "fckeymgmt.h"

#include <string.h>
#include <stdlib.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#endif

static const unsigned char FC_FILE_MAGIC[FC_MAGIC_LEN] = { 'F', 'C', 'R', 'Y', 'P', 'T', 0x1A, 0x04 };
static const char *FC_LABEL_HDR_MAC = "fcrypt 2026102 header MAC";
static const char *FC_LABEL_ENC = "fcrypt 2026102 data encryption";
static const char *FC_LABEL_MAC = "fcrypt 2026102 data MAC";
static const unsigned char FC_HDR_EXT_MAGIC[4] = { 'F', 'C', 'X', '1' };

// ----------------------------------------------------------- //
// Little endian helpers
// ----------------------------------------------------------- //
static void fc_put32(unsigned char *p, unsigned v)
{
  p[0] = (unsigned char)(v & 0xFF); p[1] = (unsigned char)((v >> 8) & 0xFF);
  p[2] = (unsigned char)((v >> 16) & 0xFF); p[3] = (unsigned char)((v >> 24) & 0xFF);
}

static unsigned fc_get32(const unsigned char *p)
{
  return (unsigned)p[0] | ((unsigned)p[1] << 8) | ((unsigned)p[2] << 16) | ((unsigned)p[3] << 24);
}

static void fc_put64(unsigned char *p, FAU_t v)
{
  for(int i = 0; i < 8; i++) { p[i] = (unsigned char)(v & 0xFF); v >>= 8; }
}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
static void fc_put32_be(unsigned char *p, unsigned v)
{
  p[0] = (unsigned char)((v >> 24) & 0xFF); p[1] = (unsigned char)((v >> 16) & 0xFF);
  p[2] = (unsigned char)((v >> 8) & 0xFF); p[3] = (unsigned char)(v & 0xFF);
}
#endif

// ----------------------------------------------------------- //
// Crypto helpers. Every fetch uses the library context from
// FC_crypto_init(), so in FIPS mode only the FIPS provider is used.
// ----------------------------------------------------------- //
static int fc_rand(unsigned char *buf, unsigned len, int priv)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  if(priv) return RAND_priv_bytes_ex(AES_get_libctx(), buf, len, 0) == 1;
  return RAND_bytes_ex(AES_get_libctx(), buf, len, 0) == 1;
#elif OPENSSL_VERSION_NUMBER >= 0x10101000L
  if(priv) return RAND_priv_bytes(buf, len) == 1;
  return RAND_bytes(buf, len) == 1;
#else
  return RAND_bytes(buf, len) == 1;
#endif
}

static int fc_pbkdf2(const unsigned char *secret, unsigned secret_len,
		     const unsigned char *salt, unsigned salt_len,
		     unsigned iterations, unsigned char *out, unsigned out_len)
// PBKDF2-HMAC-SHA256 (SP 800-132)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  EVP_KDF *kdf = EVP_KDF_fetch(AES_get_libctx(), "PBKDF2", 0);
  if(!kdf) return 0;
  EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
  EVP_KDF_free(kdf);
  if(!kctx) return 0;
  char digest[] = "SHA256";
  OSSL_PARAM params[5];
  params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (void *)secret, secret_len);
  params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, salt_len);
  params[2] = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iterations);
  params[3] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0);
  params[4] = OSSL_PARAM_construct_end();
  int ok = EVP_KDF_derive(kctx, out, out_len, params) == 1;
  EVP_KDF_CTX_free(kctx);
  if(!ok) OPENSSL_cleanse(out, out_len);
  return ok;
#else
  return PKCS5_PBKDF2_HMAC((const char *)secret, secret_len, salt, salt_len, iterations,
			   EVP_sha256(), out_len, out) == 1;
#endif
}

static int fc_kbkdf(const unsigned char key[FC_KEY_LEN], const char *label,
		    const unsigned char *context, unsigned context_len,
		    unsigned char out[FC_KEY_LEN])
// KBKDF in counter mode with HMAC-SHA256 (SP 800-108), one 256-bit key:
// HMAC(key, [1]32 || label || 0x00 || context || [256]32)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  EVP_KDF *kdf = EVP_KDF_fetch(AES_get_libctx(), "KBKDF", 0);
  if(!kdf) return 0;
  EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
  EVP_KDF_free(kdf);
  if(!kctx) return 0;
  char mode[] = "COUNTER";
  char mac[] = "HMAC";
  char digest[] = "SHA256";
  OSSL_PARAM params[7];
  params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, mode, 0);
  params[1] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC, mac, 0);
  params[2] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0);
  params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)key, FC_KEY_LEN);
  params[4] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)label, strlen(label));
  params[5] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)context, context_len);
  params[6] = OSSL_PARAM_construct_end();
  int ok = EVP_KDF_derive(kctx, out, FC_KEY_LEN, params) == 1;
  EVP_KDF_CTX_free(kctx);
  if(!ok) OPENSSL_cleanse(out, FC_KEY_LEN);
  return ok;
#else
  unsigned char counter[4], length[4], zero = 0;
  fc_put32_be(counter, 1);
  fc_put32_be(length, FC_KEY_LEN * 8);
  AES_hmac_ctx *h = AES_hmac_new(key, FC_KEY_LEN);
  if(!h) return 0;
  int ok = AES_hmac_update(h, counter, 4) &&
    AES_hmac_update(h, (const unsigned char *)label, strlen(label)) &&
    AES_hmac_update(h, &zero, 1) &&
    AES_hmac_update(h, context, context_len) &&
    AES_hmac_update(h, length, 4) &&
    AES_hmac_final(h, out, FC_KEY_LEN);
  AES_hmac_free(h);
  return ok;
#endif
}

static EVP_CIPHER *fc_fetch_cipher(const char *name)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  return EVP_CIPHER_fetch(AES_get_libctx(), name, 0);
#else
  // Older OpenSSL releases do not know the AES-256-WRAP name
  if(strcmp(name, "AES-256-WRAP") == 0) return (EVP_CIPHER *)EVP_aes_256_wrap();
  return (EVP_CIPHER *)EVP_get_cipherbyname(name);
#endif
}

static void fc_free_cipher(EVP_CIPHER *c)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  EVP_CIPHER_free(c);
#endif
}

static int fc_key_wrap(int wrap, const unsigned char kek[FC_KEY_LEN],
		       const unsigned char *in, unsigned in_len,
		       unsigned char *out, unsigned *out_len)
// AES-256 Key Wrap (SP 800-38F, RFC 3394). Unwrapping fails when the KEK
// is wrong or the wrapped key was changed.
{
  *(out_len) = 0;
  EVP_CIPHER *cipher = fc_fetch_cipher("AES-256-WRAP");
  if(!cipher) return 0;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if(!ctx) {
    fc_free_cipher(cipher);
    return 0;
  }
  EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
  int len = 0, flen = 0;
  int ok = EVP_CipherInit_ex(ctx, cipher, 0, kek, 0, wrap) == 1;
  if(ok) ok = EVP_CipherUpdate(ctx, out, &len, in, in_len) == 1 && len > 0;
  if(ok) ok = EVP_CipherFinal_ex(ctx, out+len, &flen) == 1;
  if(ok) *(out_len) = (unsigned)(len + flen);
  EVP_CIPHER_CTX_free(ctx);
  fc_free_cipher(cipher);
  return ok;
}

static int fc_cbc(int enc, const unsigned char key[FC_KEY_LEN], const unsigned char iv[FC_IV_LEN],
		  const unsigned char *in, unsigned in_len, unsigned char *out, unsigned *out_len)
// AES-256-CBC with PKCS#7 padding. out must hold in_len + 16 bytes.
{
  *(out_len) = 0;
  EVP_CIPHER *cipher = fc_fetch_cipher("AES-256-CBC");
  if(!cipher) return 0;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if(!ctx) {
    fc_free_cipher(cipher);
    return 0;
  }
  int len = 0, flen = 0;
  int ok = EVP_CipherInit_ex(ctx, cipher, 0, key, iv, enc) == 1;
  if(ok && in_len > 0) ok = EVP_CipherUpdate(ctx, out, &len, in, in_len) == 1;
  if(ok) ok = EVP_CipherFinal_ex(ctx, out+len, &flen) == 1;
  if(ok) *(out_len) = (unsigned)(len + flen);
  EVP_CIPHER_CTX_free(ctx);
  fc_free_cipher(cipher);
  return ok;
}

static int fc_record_tag(const unsigned char mac_key[FC_KEY_LEN], const unsigned char file_id[FC_FILE_ID_LEN],
			 FAU_t index, int last, const unsigned char *rec, unsigned rec_len,
			 unsigned char tag[FC_TAG_LEN])
// rec is the ciphertext length, IV and ciphertext as written to the file
{
  unsigned char pos[9];
  fc_put64(pos, index);
  pos[8] = (unsigned char)(last ? 1 : 0);
  AES_hmac_ctx *h = AES_hmac_new(mac_key, FC_KEY_LEN);
  if(!h) return 0;
  int ok = AES_hmac_update(h, file_id, FC_FILE_ID_LEN) &&
    AES_hmac_update(h, pos, sizeof(pos)) &&
    AES_hmac_update(h, rec, rec_len) &&
    AES_hmac_final(h, tag, FC_TAG_LEN);
  AES_hmac_free(h);
  return ok;
}

static int fc_read_exact(FILE *fp, unsigned char *buf, unsigned len)
{
  return fread(buf, 1, len, fp) == len;
}

static int fc_write_exact(FILE *fp, const unsigned char *buf, unsigned len)
{
  return fwrite(buf, 1, len, fp) == len;
}

// ----------------------------------------------------------- //
// Standalone functions
// ----------------------------------------------------------- //
int FC_file_format(const char *fname)
{
  if(!fname) return FC_FORMAT_OPEN_ERROR;
  FILE *fp = fopen(fname, "rb");
  if(!fp) return FC_FORMAT_OPEN_ERROR;
  unsigned char magic[FC_MAGIC_LEN];
  int n = (int)fread(magic, 1, sizeof(magic), fp);
  fclose(fp);
  if(n == (int)sizeof(magic) && memcmp(magic, FC_FILE_MAGIC, sizeof(magic)) == 0) {
    return FC_FORMAT_2026102;
  }
  return FC_FORMAT_LEGACY;
}

const char *FC_slot_type_name(unsigned type)
{
  switch(type) {
    case FC_SLOT_SECRET: return "Password or key";
    case FC_SLOT_RSA: return "RSA key";
    case FC_SLOT_SMARTCARD: return "Smart Card";
    default: break;
  }
  return "Unknown";
}

// ----------------------------------------------------------- //
// FCryptFile
// ----------------------------------------------------------- //
FCryptFile::FCryptFile()
{
  iterations = FC_DEF_ITERATIONS;
  slot_area_len = FC_DEF_SLOT_AREA_LEN;
  overwrite = 0;
  path_mode = CRYPT_PATH_RELATIVE;
  en_dot_ext = ".enc";
  bytes_wrote = (FAU_t)0;
  file_iterations = 0;
  slot_area = 0;
  chunk_size = FC_CHUNK_SIZE;
  file_slot_area_len = 0;
  data_offset = (FAU_t)0;
  unlocked = 0;
  data_sink = 0;
  enc_out = 0;
  enc_pend = 0;
  enc_pend_len = 0;
  enc_index = (FAU_t)0;
  preset_key = 0;
  preset_no_secret = 0;
  key_generation = 0;
  rekey_time = 0;
  rekey_started = 0;
  memset(new_file_key, 0, sizeof(new_file_key));
  memset(header, 0, sizeof(header));
  memset(header_mac, 0, sizeof(header_mac));
  memset(salt, 0, sizeof(salt));
  memset(file_id, 0, sizeof(file_id));
  memset(file_key, 0, sizeof(file_key));
  memset(hdr_mac_key, 0, sizeof(hdr_mac_key));
  memset(enc_key, 0, sizeof(enc_key));
  memset(mac_key, 0, sizeof(mac_key));
}

FCryptFile::~FCryptFile()
{
  AbortEncrypt();
}

void FCryptFile::Wipe()
{
  OPENSSL_cleanse(file_key, sizeof(file_key));
  OPENSSL_cleanse(new_file_key, sizeof(new_file_key));
  rekey_started = 0;
  OPENSSL_cleanse(hdr_mac_key, sizeof(hdr_mac_key));
  OPENSSL_cleanse(enc_key, sizeof(enc_key));
  OPENSSL_cleanse(mac_key, sizeof(mac_key));
  if(slot_area) {
    OPENSSL_cleanse(slot_area, file_slot_area_len);
    delete[] slot_area;
    slot_area = 0;
  }
  unlocked = 0;
}

int FCryptFile::DeriveKeys()
{
  if(!fc_kbkdf(file_key, FC_LABEL_HDR_MAC, file_id, sizeof(file_id), hdr_mac_key) ||
     !fc_kbkdf(file_key, FC_LABEL_ENC, file_id, sizeof(file_id), enc_key) ||
     !fc_kbkdf(file_key, FC_LABEL_MAC, file_id, sizeof(file_id), mac_key)) {
    err << clear << "Key derivation (KBKDF) failed";
    return 0;
  }
  return 1;
}

int FCryptFile::BuildSlotArea(unsigned char *area, gxString &e)
// Write the key slots into a zeroed area of file_slot_area_len bytes
{
  memset(area, 0, file_slot_area_len);
  unsigned pos = 0;
  gxListNode<FCKeySlot> *ptr = slots.GetHead();
  while(ptr) {
    unsigned name_len = ptr->data.username.length();
    unsigned wrapped_len = ptr->data.wrapped.length();
    unsigned len = 16 + name_len + wrapped_len;
    if(len > file_slot_area_len - pos) {
      e << clear << "No space left in the key slot area, encrypt the file with a larger --static-data-size";
      return 0;
    }
    fc_put32(area+pos, ptr->data.type);
    fc_put32(area+pos+4, len);
    fc_put32(area+pos+8, name_len);
    if(name_len) memmove(area+pos+12, ptr->data.username.GetSPtr(), name_len);
    fc_put32(area+pos+12+name_len, wrapped_len);
    memmove(area+pos+16+name_len, ptr->data.wrapped.m_buf(), wrapped_len);
    pos += len;
    ptr = ptr->next;
  }
  return 1;
}

int FCryptFile::WriteHeader(FILE *fp)
// Write the fixed header, key slot area and header MAC at the current
// file position. The header MAC is recomputed from the slots.
{
  unsigned char *area = new unsigned char[file_slot_area_len];
  if(!area) {
    err << clear << "Out of memory";
    return 0;
  }
  if(!BuildSlotArea(area, err)) {
    delete[] area;
    return 0;
  }
  AES_hmac_ctx *h = AES_hmac_new(hdr_mac_key, FC_KEY_LEN);
  int ok = h && AES_hmac_update(h, header, sizeof(header)) &&
    AES_hmac_update(h, area, file_slot_area_len) &&
    AES_hmac_final(h, header_mac, sizeof(header_mac));
  AES_hmac_free(h);
  if(!ok) {
    err << clear << "Header MAC failed";
    delete[] area;
    return 0;
  }
  ok = fc_write_exact(fp, header, sizeof(header)) &&
    fc_write_exact(fp, area, file_slot_area_len) &&
    fc_write_exact(fp, header_mac, sizeof(header_mac));
  OPENSSL_cleanse(area, file_slot_area_len);
  delete[] area;
  if(!ok) err << clear << "Error writing the file header to " << ofname;
  return ok;
}

int FCryptFile::WriteRecord(FILE *fp, FAU_t index, int last, const unsigned char *plain, unsigned len)
{
  unsigned rec_len = 4 + FC_IV_LEN + len + FC_IV_LEN; // Padding adds up to 16 bytes
  unsigned char *rec = new unsigned char[rec_len + FC_TAG_LEN];
  if(!rec) {
    err << clear << "Out of memory";
    return 0;
  }
  unsigned ct_len = 0;
  int ok = fc_rand(rec+4, FC_IV_LEN, 0);
  if(!ok) err << clear << "Random number generator failed";
  if(ok) {
    ok = fc_cbc(1, enc_key, rec+4, plain, len, rec+4+FC_IV_LEN, &ct_len);
    if(!ok) err << clear << "AES-256-CBC encryption failed";
  }
  if(ok) {
    fc_put32(rec, ct_len);
    rec_len = 4 + FC_IV_LEN + ct_len;
    ok = fc_record_tag(mac_key, file_id, index, last, rec, rec_len, rec+rec_len);
    if(!ok) err << clear << "Record MAC failed";
  }
  if(ok) {
    ok = fc_write_exact(fp, rec, rec_len + FC_TAG_LEN);
    if(!ok) err << clear << "Error writing to " << ofname;
    else bytes_wrote += rec_len + FC_TAG_LEN;
  }
  delete[] rec;
  return ok;
}

int FCryptFile::MakeEncryptOutputName()
// Same output name rules as FCryptCache::OpenOutputFile()
{
  ofname = filename;
  if((ofname.length() > 3 && ofname[ofname.length()-3] == '.') ||
     (ofname.length() > 4 && ofname[ofname.length()-4] == '.')) {
    ofname.DeleteAfterLastIncluding(".");
  }
  ofname << en_dot_ext;

  if(!output_dir_name.is_null()) {
    gxString dir = output_dir_name;
#if defined (__WIN32__)
    futils_makeDOSpath(dir.c_str());
    if(dir[dir.length()-1] != '\\') dir << '\\';
#else
    if(dir[dir.length()-1] != '/') dir << '/';
#endif
    if(futils_exists(dir.c_str()) && !futils_isdirectory(dir.c_str())) {
      err << clear << "Output DIR is a file name " << output_dir_name;
      return 0;
    }
    if(!futils_exists(dir.c_str()) && !cryptdb_makedirs(dir)) {
      err << clear << "Error making output DIR " << output_dir_name;
      return 0;
    }
    dir << ofname;
    ofname = dir;
  }

  if(!output_file_name.is_null()) ofname = output_file_name;

  if(!overwrite && futils_exists(ofname.c_str())) { // Find a unique name
    int offset = ofname.Find(".");
    if(offset == -1) offset = ofname.length();
    gxString base = ofname;
    for(int i = 1; ; i++) {
      gxString sbuf;
      sbuf << i;
      ofname = base;
      ofname.InsertAt(offset, sbuf);
      if(!futils_exists(ofname.c_str())) break;
    }
  }
  return 1;
}

int FCryptFile::EncryptFile(const char *fname, const MemoryBuffer &secret)
{
  err.Clear();
  ofname.Clear();
  bytes_wrote = (FAU_t)0;

  if(!fname) {
    err << clear << "Null input file name";
    return 0;
  }
  filename = fname;
  gxString name = stored_name_override.is_null() ? filename : stored_name_override;

  FILE *in = fopen(fname, "rb");
  if(!in) {
    err << clear << "Error opening " << fname;
    return 0;
  }
  if(!MakeEncryptOutputName()) {
    fclose(in);
    return 0;
  }
  gxString out_name = ofname;
  if(!BeginEncrypt(secret, name.c_str(), out_name.c_str())) {
    fclose(in);
    return 0;
  }

  unsigned char *buf = new unsigned char[chunk_size];
  int ok = (buf != 0);
  if(!ok) err << clear << "Out of memory";
  while(ok) {
    unsigned len = (unsigned)fread(buf, 1, chunk_size, in);
    if(ferror(in)) {
      err << clear << "Error reading " << filename;
      ok = 0;
      break;
    }
    if(len == 0) break;
    ok = WriteData(buf, len);
  }
  if(buf) { OPENSSL_cleanse(buf, chunk_size); delete[] buf; }
  fclose(in);

  if(ok) return FinishEncrypt();
  AbortEncrypt();
  return 0;
}

int FCryptFile::BeginEncrypt(const MemoryBuffer &secret, const char *stored_name, const char *out_name)
{
  AbortEncrypt();
  err.Clear();
  bytes_wrote = (FAU_t)0;
  Wipe();
  slots.ClearList();

  if(!stored_name || !*stored_name || !out_name || !*out_name) {
    err << clear << "Null file name";
    return 0;
  }
  ofname = out_name;
  gxString name = stored_name;
  if(!preset_no_secret && (secret.length() < AES_MIN_SECRET_LEN || secret.length() > AES_MAX_SECRET_LEN)) {
    err << clear << "The password or key must be " << AES_MIN_SECRET_LEN << " to " << AES_MAX_SECRET_LEN << " bytes";
    return 0;
  }
  if(iterations < FC_MIN_ITERATIONS || iterations > FC_MAX_ITERATIONS) {
    err << clear << "Key iterations must be " << FC_MIN_ITERATIONS << " to " << FC_MAX_ITERATIONS;
    return 0;
  }
  if(slot_area_len < FC_MIN_SLOT_AREA_LEN || slot_area_len > FC_MAX_SLOT_AREA_LEN) {
    err << clear << "The key slot area must be " << FC_MIN_SLOT_AREA_LEN << " to " << FC_MAX_SLOT_AREA_LEN << " bytes";
    return 0;
  }
  if(name.length() > FC_MAX_STORED_NAME_LEN) {
    err << clear << "File name longer than " << FC_MAX_STORED_NAME_LEN
	<< " bytes, use a shorter path or --decrypted-outfile";
    return 0;
  }

  // Keys and the password slot
  unsigned char kek[FC_KEY_LEN];
  unsigned char wrapped[FC_WRAPPED_KEY_LEN + 16];
  unsigned wrapped_len = 0;
  int ok = fc_rand(salt, sizeof(salt), 0) && fc_rand(file_id, sizeof(file_id), 0);
  // 10/27/2026: A rekey sets the new file key, see BeginRekey()
  if(ok) {
    if(preset_key) memmove(file_key, preset_key, sizeof(file_key));
    else ok = fc_rand(file_key, sizeof(file_key), 1);
  }
  if(!ok) err << clear << "Random number generator failed";
  if(ok && !preset_no_secret) {
    ok = fc_pbkdf2(secret.m_buf(), secret.length(), salt, sizeof(salt), iterations, kek, sizeof(kek));
    if(!ok) err << clear << "Password key derivation (PBKDF2) failed";
    if(ok) {
      ok = fc_key_wrap(1, kek, file_key, sizeof(file_key), wrapped, &wrapped_len);
      if(!ok) err << clear << "AES key wrap failed";
    }
  }
  OPENSSL_cleanse(kek, sizeof(kek));
  if(ok) ok = DeriveKeys();
  if(ok && !preset_no_secret) {
    FCKeySlot slot;
    slot.type = FC_SLOT_SECRET;
    slot.wrapped.Load(wrapped, wrapped_len);
    slots.Add(slot);
  }
  if(ok && preset_key) { // RSA and smart card slots wrapped with the new key
    gxListNode<FCKeySlot> *pp = preset_slots.GetHead();
    while(pp) {
      slots.Add(pp->data);
      pp = pp->next;
    }
  }
  OPENSSL_cleanse(wrapped, sizeof(wrapped));
  if(!ok) {
    Wipe();
    return 0;
  }

  // Fixed header
  memset(header, 0, sizeof(header));
  memmove(header, FC_FILE_MAGIC, FC_MAGIC_LEN);
  fc_put32(header+8, FC_FILE_VERSION);
  fc_put32(header+12, FC_HEADER_LEN);
  fc_put32(header+16, 0);
  fc_put32(header+20, FC_KDF_PBKDF2_SHA256);
  fc_put32(header+24, iterations);
  fc_put32(header+28, FC_CIPHER_AES256_CBC_HMAC_SHA256);
  fc_put32(header+32, FC_CHUNK_SIZE);
  fc_put32(header+36, slot_area_len);
  memmove(header+40, salt, sizeof(salt));
  memmove(header+72, file_id, sizeof(file_id));
  // 10/27/2026: Key generation and rekey time in the reserved bytes,
  // which older versions write as zero and never read
  if(key_generation) {
    memmove(header+FC_HDR_EXT_OFFSET, FC_HDR_EXT_MAGIC, 4);
    fc_put32(header+FC_HDR_EXT_OFFSET+4, key_generation);
    fc_put64(header+FC_HDR_EXT_OFFSET+8, (FAU_t)rekey_time);
  }
  file_slot_area_len = slot_area_len;
  chunk_size = FC_CHUNK_SIZE;

  // Write to a private temp file and rename it when done
  unsigned char rnd[8];
  if(!fc_rand(rnd, sizeof(rnd), 0)) {
    err << clear << "Random number generator failed";
    Wipe();
    return 0;
  }
  const char *hex = "0123456789abcdef";
  gxString tmp = ofname;
  tmp << ".fcrypt_";
  for(unsigned i = 0; i < sizeof(rnd); i++) tmp << hex[(rnd[i] >> 4) & 0xF] << hex[rnd[i] & 0xF];
  tmp << ".tmp";
  if(!cryptdb_create_private_file(tmp.c_str())) {
    err << clear << "Error creating " << tmp;
    Wipe();
    return 0;
  }
  enc_out = fopen(tmp.c_str(), "wb");
  if(!enc_out) {
    err << clear << "Error opening " << tmp;
    futils_remove(tmp.c_str());
    Wipe();
    return 0;
  }
  enc_tmp = tmp;

  ok = WriteHeader(enc_out);
  if(ok) {
    bytes_wrote = FC_HEADER_LEN + file_slot_area_len + FC_TAG_LEN;
    // Record 0: the stored file name
    MemoryBuffer meta;
    unsigned char v[4];
    fc_put32(v, 1); meta.Cat(v, 4);                // Record 0 version
    fc_put32(v, name.length()); meta.Cat(v, 4);
    meta.Cat(name.GetSPtr(), name.length());
    ok = WriteRecord(enc_out, 0, 0, meta.m_buf(), meta.length());
    meta.Clear(1);
  }
  if(ok) {
    enc_pend = new unsigned char[chunk_size];
    if(!enc_pend) {
      err << clear << "Out of memory";
      ok = 0;
    }
  }
  if(!ok) {
    if(err.is_null()) err << clear << "Error writing " << ofname;
    AbortEncrypt();
    return 0;
  }
  enc_pend_len = 0;
  enc_index = 1;
  return 1;
}

int FCryptFile::WriteData(const unsigned char *buf, unsigned len)
// Records 1 to N hold the file data. A full record is written only when
// more data follows, so FinishEncrypt() knows which record is the last.
{
  if(!enc_out || !enc_pend) {
    err << clear << "Encryption was not started";
    return 0;
  }
  while(len > 0) {
    if(enc_pend_len == chunk_size) {
      if(!WriteRecord(enc_out, enc_index++, 0, enc_pend, enc_pend_len)) return 0;
      enc_pend_len = 0;
    }
    unsigned n = chunk_size - enc_pend_len;
    if(n > len) n = len;
    memmove(enc_pend + enc_pend_len, buf, n);
    enc_pend_len += n;
    buf += n;
    len -= n;
  }
  return 1;
}

int FCryptFile::FinishEncrypt()
{
  if(!enc_out || !enc_pend) {
    err << clear << "Encryption was not started";
    return 0;
  }
  // The last record, which is empty for an empty file
  int ok = WriteRecord(enc_out, enc_index++, 1, enc_pend, enc_pend_len);
  OPENSSL_cleanse(enc_pend, chunk_size);
  delete[] enc_pend;
  enc_pend = 0;
  enc_pend_len = 0;

  if(fflush(enc_out) != 0) ok = 0;
  if(fclose(enc_out) != 0) ok = 0;
  enc_out = 0;
  if(ok && !cryptdb_rename_file(enc_tmp.c_str(), ofname.c_str(), overwrite)) {
    if(!overwrite && futils_exists(ofname.c_str())) {
      err << clear << "Output file " << ofname << " exists, use -o to overwrite";
    }
    else {
      err << clear << "Error renaming " << enc_tmp << " to " << ofname;
    }
    ok = 0;
  }
  if(!ok) {
    if(err.is_null()) err << clear << "Error writing " << ofname;
    futils_remove(enc_tmp.c_str());
  }
  enc_tmp.Clear();
  Wipe();
  return ok;
}

void FCryptFile::AbortEncrypt()
{
  if(enc_pend) {
    OPENSSL_cleanse(enc_pend, chunk_size);
    delete[] enc_pend;
    enc_pend = 0;
  }
  enc_pend_len = 0;
  if(enc_out) {
    fclose(enc_out);
    enc_out = 0;
  }
  if(!enc_tmp.is_null()) {
    futils_remove(enc_tmp.c_str());
    enc_tmp.Clear();
  }
  Wipe();
}

int FCryptFile::LoadHeader(const char *fname)
{
  err.Clear();
  Wipe();
  slots.ClearList();
  stored_name.Clear();
  if(!fname) {
    err << clear << "Null input file name";
    return 0;
  }
  filename = fname;
  FILE *fp = fopen(fname, "rb");
  if(!fp) {
    err << clear << "Error opening " << fname;
    return 0;
  }
  if(!fc_read_exact(fp, header, sizeof(header))) {
    err << clear << fname << " is too short to be an encrypted file";
    fclose(fp);
    return 0;
  }
  if(memcmp(header, FC_FILE_MAGIC, FC_MAGIC_LEN) != 0) {
    err << clear << fname << " is not a version " << FC_FILE_VERSION << " encrypted file";
    fclose(fp);
    return 0;
  }
  unsigned version = fc_get32(header+8);
  if(version != FC_FILE_VERSION) {
    err << clear << "Bad file version " << (unsigned long)version << " in " << fname
	<< ", this program reads version " << FC_FILE_VERSION;
    fclose(fp);
    return 0;
  }
  file_iterations = fc_get32(header+24);
  chunk_size = fc_get32(header+32);
  file_slot_area_len = fc_get32(header+36);
  if(fc_get32(header+12) != FC_HEADER_LEN ||
     fc_get32(header+20) != FC_KDF_PBKDF2_SHA256 ||
     fc_get32(header+28) != FC_CIPHER_AES256_CBC_HMAC_SHA256 ||
     file_iterations < FC_MIN_ITERATIONS || file_iterations > FC_MAX_ITERATIONS ||
     chunk_size < FC_MIN_CHUNK_SIZE || chunk_size > FC_MAX_CHUNK_SIZE || (chunk_size % 16) != 0 ||
     file_slot_area_len < FC_MIN_SLOT_AREA_LEN || file_slot_area_len > FC_MAX_SLOT_AREA_LEN) {
    err << clear << "Bad or unsupported file header in " << fname;
    fclose(fp);
    return 0;
  }
  memmove(salt, header+40, sizeof(salt));
  memmove(file_id, header+72, sizeof(file_id));

  slot_area = new unsigned char[file_slot_area_len];
  if(!slot_area) {
    err << clear << "Out of memory";
    fclose(fp);
    return 0;
  }
  if(!fc_read_exact(fp, slot_area, file_slot_area_len) ||
     !fc_read_exact(fp, header_mac, sizeof(header_mac))) {
    err << clear << fname << " is too short, the encrypted file was truncated";
    fclose(fp);
    Wipe();
    return 0;
  }
  fclose(fp);
  data_offset = FC_HEADER_LEN + file_slot_area_len + FC_TAG_LEN;

  // Parse the key slots. They are not authenticated yet, so check every length.
  unsigned pos = 0;
  while(file_slot_area_len - pos >= 16) {
    unsigned type = fc_get32(slot_area+pos);
    if(type == FC_SLOT_END) break;
    unsigned len = fc_get32(slot_area+pos+4);
    unsigned name_len = fc_get32(slot_area+pos+8);
    if(len < 16 || len > file_slot_area_len - pos ||
       name_len > FC_MAX_USERNAME_LEN || name_len > len - 16) {
      err << clear << "Bad key slot in " << fname;
      Wipe();
      return 0;
    }
    unsigned wrapped_len = fc_get32(slot_area+pos+12+name_len);
    if(wrapped_len == 0 || wrapped_len > FC_MAX_WRAPPED_LEN || wrapped_len != len - 16 - name_len) {
      err << clear << "Bad key slot in " << fname;
      Wipe();
      return 0;
    }
    FCKeySlot slot;
    slot.type = type;
    if(name_len) slot.username.SetString((const char *)slot_area+pos+12, name_len);
    slot.wrapped.Load(slot_area+pos+16+name_len, wrapped_len);
    slots.Add(slot);
    pos += len;
  }
  return 1;
}

FCKeySlot *FCryptFile::FindSlot(unsigned type, const char *username)
{
  gxListNode<FCKeySlot> *ptr = slots.GetHead();
  while(ptr) {
    if(ptr->data.type == type) {
      if(!username || ptr->data.username == username) return &ptr->data;
    }
    ptr = ptr->next;
  }
  return 0;
}

int FCryptFile::VerifyHeaderMAC()
{
  unsigned char mac[FC_TAG_LEN];
  AES_hmac_ctx *h = AES_hmac_new(hdr_mac_key, FC_KEY_LEN);
  int ok = h && AES_hmac_update(h, header, sizeof(header)) &&
    AES_hmac_update(h, slot_area, file_slot_area_len) &&
    AES_hmac_final(h, mac, sizeof(mac));
  AES_hmac_free(h);
  if(ok) ok = CRYPTO_memcmp(mac, header_mac, sizeof(mac)) == 0;
  OPENSSL_cleanse(mac, sizeof(mac));
  return ok;
}

int FCryptFile::UnlockWithFileKey(const unsigned char key[FC_KEY_LEN])
{
  if(!slot_area) {
    err << clear << "No encrypted file header is loaded";
    return 0;
  }
  memmove(file_key, key, FC_KEY_LEN);
  if(!DeriveKeys()) {
    OPENSSL_cleanse(file_key, sizeof(file_key));
    return 0;
  }
  if(!VerifyHeaderMAC()) {
    err << clear << "File header authentication failed, the encrypted file header was modified";
    OPENSSL_cleanse(file_key, sizeof(file_key));
    OPENSSL_cleanse(hdr_mac_key, sizeof(hdr_mac_key));
    OPENSSL_cleanse(enc_key, sizeof(enc_key));
    OPENSSL_cleanse(mac_key, sizeof(mac_key));
    return 0;
  }
  unlocked = 1;
  return 1;
}

int FCryptFile::UnlockWithSecret(const MemoryBuffer &secret)
{
  FCKeySlot *slot = FindSlot(FC_SLOT_SECRET, 0);
  if(!slot) {
    err << clear << "The encrypted file has no password or key slot";
    return 0;
  }
  if(secret.length() < AES_MIN_SECRET_LEN || secret.length() > AES_MAX_SECRET_LEN) {
    err << clear << "Bad password or key";
    return 0;
  }
  unsigned char kek[FC_KEY_LEN];
  unsigned char key[FC_MAX_WRAPPED_LEN];
  unsigned key_len = 0;
  int ok = fc_pbkdf2(secret.m_buf(), secret.length(), salt, sizeof(salt), file_iterations, kek, sizeof(kek));
  if(!ok) err << clear << "Password key derivation (PBKDF2) failed";
  if(ok) {
    ok = fc_key_wrap(0, kek, slot->wrapped.m_buf(), slot->wrapped.length(), key, &key_len) &&
      key_len == FC_KEY_LEN;
    if(!ok) err << clear << "Bad password or key";
  }
  OPENSSL_cleanse(kek, sizeof(kek));
  if(ok) ok = UnlockWithFileKey(key);
  OPENSSL_cleanse(key, sizeof(key));
  return ok;
}

int FCryptFile::UnlockWithRSAKey(const char *username, const char *private_key, unsigned private_key_len,
				 char *passphrase)
{
  FCKeySlot *slot = FindSlot(FC_SLOT_RSA, username);
  if(!slot) {
    err << clear << "No RSA key slot for user " << username;
    return 0;
  }
  unsigned char key[FC_MAX_WRAPPED_LEN];
  unsigned key_len = 0;
  EVP_PKEY *pkey = RSA_load_private_key((const unsigned char *)private_key, private_key_len, passphrase);
  if(!pkey) {
    err << clear << "Cannot read the private RSA key";
    if(passphrase && FC_fips_mode()) {
      err << ". In FIPS mode a private key with a passphrase must be in PKCS#8 format, see README.txt";
    }
    return 0;
  }
  int rv = RSA_pkey_decrypt(pkey, slot->wrapped.m_buf(), slot->wrapped.length(),
			    key, sizeof(key), &key_len, RSA_PKCS1_OAEP_PADDING);
  EVP_PKEY_free(pkey);
  int ok = (rv == RSA_NO_ERROR && key_len == FC_KEY_LEN);
  if(!ok) err << clear << "The private RSA key for user " << username << " cannot open this file";
  if(ok) ok = UnlockWithFileKey(key);
  OPENSSL_cleanse(key, sizeof(key));
  return ok;
}

int FCryptFile::AddWrappedKey(unsigned type, const char *username, const unsigned char *wrapped, unsigned wrapped_len)
{
  if(!unlocked) {
    err << clear << "The encrypted file is not unlocked";
    return 0;
  }
  if(!username || !*username || strlen(username) > FC_MAX_USERNAME_LEN) {
    err << clear << "User names must be 1 to " << FC_MAX_USERNAME_LEN << " characters";
    return 0;
  }
  if(wrapped_len == 0 || wrapped_len > FC_MAX_WRAPPED_LEN) {
    err << clear << "Bad wrapped key length";
    return 0;
  }
  if(FindSlot(type, username)) {
    err << clear << "User " << username << " already has " << FC_slot_type_name(type) << " access to " << filename;
    return 0;
  }
  FCKeySlot slot;
  slot.type = type;
  slot.username = username;
  slot.wrapped.Load(wrapped, wrapped_len);
  slots.Add(slot);

  // Check it fits before touching the file
  unsigned char *area = new unsigned char[file_slot_area_len];
  if(!area) {
    err << clear << "Out of memory";
    return 0;
  }
  int ok = BuildSlotArea(area, err);
  if(ok) memmove(slot_area, area, file_slot_area_len);
  delete[] area;
  if(!ok) {
    slots.Remove(slots.GetTail());
    return 0;
  }

  FILE *fp = fopen(filename.c_str(), "r+b");
  if(!fp) {
    err << clear << "Error opening " << filename << " for writing";
    return 0;
  }
  ofname = filename;
  ok = WriteHeader(fp);
  if(fflush(fp) != 0) ok = 0;
  if(fclose(fp) != 0) ok = 0;
  if(!ok && err.is_null()) err << clear << "Error writing " << filename;
  return ok;
}

int FCryptFile::AddRSAKey(const char *username, const char *public_key, unsigned public_key_len,
			  char *passphrase)
{
  if(!unlocked) {
    err << clear << "The encrypted file is not unlocked";
    return 0;
  }
  EVP_PKEY *pkey = RSA_load_public_key((const unsigned char *)public_key, public_key_len, passphrase);
  if(!pkey) {
    err << clear << "Cannot read the public RSA key";
    return 0;
  }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  int bits = EVP_PKEY_get_bits(pkey);
  int is_rsa = EVP_PKEY_is_a(pkey, "RSA");
#else
  int bits = EVP_PKEY_bits(pkey);
  int is_rsa = (EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA);
#endif
  if(!is_rsa || bits < (int)FC_MIN_RSA_BITS) {
    EVP_PKEY_free(pkey);
    err << clear << "The public key must be an RSA key of at least " << FC_MIN_RSA_BITS << " bits";
    return 0;
  }
  unsigned char wrapped[FC_MAX_WRAPPED_LEN];
  unsigned wrapped_len = 0;
  int rv = RSA_pkey_encrypt(pkey, file_key, FC_KEY_LEN, wrapped, sizeof(wrapped), &wrapped_len,
			    RSA_PKCS1_OAEP_PADDING);
  EVP_PKEY_free(pkey);
  if(rv != RSA_NO_ERROR) {
    err << clear << "RSA-OAEP encryption of the file key failed";
    return 0;
  }
  return AddWrappedKey(FC_SLOT_RSA, username, wrapped, wrapped_len);
}

int FCryptFile::ReadRecord(FILE *fp, FAU_t index, MemoryBuffer &plain, int &last)
// Read, authenticate and decrypt one record. last is set when the record
// is the last one in the file, and must match the flag in its tag.
{
  plain.Clear(1);
  last = 0;
  unsigned char lenbuf[4];
  if(!fc_read_exact(fp, lenbuf, 4)) {
    err << clear << "File integrity check failed, the encrypted file was truncated";
    return 0;
  }
  unsigned ct_len = fc_get32(lenbuf);
  if(ct_len < 16 || (ct_len % 16) != 0 || ct_len > chunk_size + 16) {
    err << clear << "File integrity check failed, bad record length";
    return 0;
  }
  unsigned rec_len = 4 + FC_IV_LEN + ct_len;
  unsigned char *rec = new unsigned char[rec_len + FC_TAG_LEN];
  unsigned char *pt = new unsigned char[ct_len];
  if(!rec || !pt) {
    if(rec) delete[] rec;
    if(pt) delete[] pt;
    err << clear << "Out of memory";
    return 0;
  }
  memmove(rec, lenbuf, 4);
  int ok = fc_read_exact(fp, rec+4, rec_len - 4 + FC_TAG_LEN);
  if(!ok) err << clear << "File integrity check failed, the encrypted file was truncated";
  if(ok) {
    int c = fgetc(fp);
    if(c == EOF) last = 1;
    else ungetc(c, fp);
    unsigned char tag[FC_TAG_LEN];
    ok = fc_record_tag(mac_key, file_id, index, last, rec, rec_len, tag) &&
      CRYPTO_memcmp(tag, rec+rec_len, FC_TAG_LEN) == 0;
    if(!ok) err << clear << "File integrity check failed, the encrypted file was modified, truncated or is incomplete";
  }
  unsigned pt_len = 0;
  if(ok) {
    ok = fc_cbc(0, enc_key, rec+4, rec+4+FC_IV_LEN, ct_len, pt, &pt_len);
    if(!ok) err << clear << "AES-256-CBC decryption failed";
  }
  if(ok) plain.Load(pt, pt_len);
  OPENSSL_cleanse(pt, ct_len);
  delete[] pt;
  delete[] rec;
  return ok;
}

int FCryptFile::DecryptStoredName(gxString &name)
{
  name.Clear();
  if(!unlocked) {
    err << clear << "The encrypted file is not unlocked";
    return 0;
  }
  FILE *fp = fopen(filename.c_str(), "rb");
  if(!fp) {
    err << clear << "Error opening " << filename;
    return 0;
  }
  if(fseek(fp, (long)data_offset, SEEK_SET) != 0) {
    err << clear << "Error reading " << filename;
    fclose(fp);
    return 0;
  }
  MemoryBuffer meta;
  int last = 0;
  int ok = ReadRecord(fp, 0, meta, last);
  fclose(fp);
  if(ok && last) {
    err << clear << "File integrity check failed, the encrypted file has no data";
    ok = 0;
  }
  if(ok) {
    unsigned name_len = (meta.length() >= 8) ? fc_get32(meta.m_buf()+4) : 0;
    if(meta.length() < 8 || fc_get32(meta.m_buf()) != 1 || name_len == 0 ||
       name_len > FC_MAX_STORED_NAME_LEN || name_len > meta.length() - 8) {
      err << clear << "Invalid file name stored in encrypted file";
      ok = 0;
    }
    else {
      name.SetString((const char *)meta.m_buf()+8, name_len);
      stored_name = name;
    }
  }
  meta.Clear(1);
  return ok;
}

int FCryptFile::OpenDecryptOutput(FILE **fp)
// Create a private temp file next to the output file, the same way as
// FCryptCache::OpenDecryptOutputFile()
{
  *fp = 0;
  if(futils_exists(ofname.c_str())) {
    if(futils_isdirectory(ofname.c_str())) {
      err << clear << "Output file " << ofname << " is a directory";
      return 0;
    }
    if(!overwrite) {
      err << clear << "Output file " << ofname << " exists, use -o to overwrite";
      return 0;
    }
  }
  gxString dir = ofname;
  int sep = -1;
  for(int i = (int)dir.length()-1; i >= 0; i--) {
    if(dir[i] == '/' || dir[i] == '\\') { sep = i; break; }
  }
  if(sep > 0) {
    dir.DeleteAt(sep, dir.length()-sep);
    if(!futils_exists(dir.c_str())) {
      if(!cryptdb_makedirs(dir)) {
	err << clear << "Error making DIR " << dir;
	return 0;
      }
    }
    else if(!futils_isdirectory(dir.c_str())) {
      err << clear << "Output DIR is a file name " << dir;
      return 0;
    }
  }
  unsigned char rnd[8];
  if(!fc_rand(rnd, sizeof(rnd), 0)) {
    err << clear << "Random number generator failed";
    return 0;
  }
  const char *hex = "0123456789abcdef";
  gxString tmp = ofname;
  tmp << ".fdecrypt_";
  for(unsigned i = 0; i < sizeof(rnd); i++) tmp << hex[(rnd[i] >> 4) & 0xF] << hex[rnd[i] & 0xF];
  tmp << ".tmp";
  if(!cryptdb_create_private_file(tmp.c_str())) {
    err << clear << "Error creating " << tmp;
    return 0;
  }
  tmp_ofname = tmp;
  *fp = fopen(tmp.c_str(), "wb");
  if(!*fp) {
    futils_remove(tmp.c_str());
    tmp_ofname.Clear();
    err << clear << "Error opening " << tmp;
    return 0;
  }
  return 1;
}

int FCryptFile::FinishDecryptOutput(FILE *fp, int ok)
{
  if(fflush(fp) != 0) ok = 0;
  if(fclose(fp) != 0) ok = 0;
  if(ok && !cryptdb_rename_file(tmp_ofname.c_str(), ofname.c_str(), overwrite)) {
    if(!overwrite && futils_exists(ofname.c_str())) {
      err << clear << "Output file " << ofname << " exists, use -o to overwrite";
    }
    else {
      err << clear << "Error renaming " << tmp_ofname << " to " << ofname;
    }
    ok = 0;
  }
  if(!ok) futils_remove(tmp_ofname.c_str());
  tmp_ofname.Clear();
  return ok;
}

int FCryptFile::DecryptFile(const char *outfile_name)
{
  bytes_wrote = (FAU_t)0;
  ofname.Clear();
  if(!unlocked) {
    err << clear << "The encrypted file is not unlocked";
    return 0;
  }
  FILE *in = fopen(filename.c_str(), "rb");
  if(!in) {
    err << clear << "Error opening " << filename;
    return 0;
  }
  if(fseek(in, (long)data_offset, SEEK_SET) != 0) {
    err << clear << "Error reading " << filename;
    fclose(in);
    return 0;
  }

  // Record 0: the stored file name
  MemoryBuffer meta;
  int last = 0;
  int ok = ReadRecord(in, 0, meta, last);
  if(ok && last) {
    err << clear << "File integrity check failed, the encrypted file has no data";
    ok = 0;
  }
  if(ok) {
    unsigned name_len = (meta.length() >= 8) ? fc_get32(meta.m_buf()+4) : 0;
    if(meta.length() < 8 || fc_get32(meta.m_buf()) != 1 || name_len == 0 ||
       name_len > FC_MAX_STORED_NAME_LEN || name_len > meta.length() - 8) {
      err << clear << "Invalid file name stored in encrypted file";
      ok = 0;
    }
    else {
      stored_name.SetString((const char *)meta.m_buf()+8, name_len);
    }
  }
  meta.Clear(1);
  if(!ok) {
    fclose(in);
    return 0;
  }

  // Pick the output, the same way as FCryptCache::DecryptFile()
  int to_console = 0;
  if(data_sink) outfile_name = "stdout";
  int use_output_dir = 1;
  gxString sbuf;
  if(outfile_name) {
    sbuf = outfile_name;
    if(sbuf == "stdout" || sbuf == "stderr") to_console = 1;
    ofname = sbuf;
  }
  else if(stored_name == "stdout" || stored_name == "stderr") {
    ofname = stored_name;
    to_console = 1;
  }
  else {
    if(!cryptdb_make_restore_path(stored_name, path_mode, ofname, err)) {
      fclose(in);
      return 0;
    }
    if(path_mode == CRYPT_PATH_ABSOLUTE) use_output_dir = 0;
  }
  if(!output_dir_name.is_null() && !to_console && use_output_dir) {
    gxString dir = output_dir_name;
#if defined (__WIN32__)
    futils_makeDOSpath(dir.c_str());
    if(dir[dir.length()-1] != '\\') dir << '\\';
#else
    if(dir[dir.length()-1] != '/') dir << '/';
#endif
    dir << ofname;
    ofname = dir;
  }

  FILE *out = 0;
  if(to_console) {
    out = (ofname == "stderr") ? stderr : stdout;
  }
  else if(!OpenDecryptOutput(&out)) {
    fclose(in);
    return 0;
  }

  // Records 1 to N
  FAU_t index = 1;
  MemoryBuffer plain;
  while(ok) {
    ok = ReadRecord(in, index++, plain, last);
    if(!ok) break;
    if(plain.length() && data_sink) {
      if(!data_sink->WriteData(plain.m_buf(), plain.length())) {
	if(err.is_null()) err << clear << "Error writing decrypted data";
	ok = 0;
	break;
      }
    }
    else if(plain.length() && !fc_write_exact(out, plain.m_buf(), plain.length())) {
      err << clear << "Error writing to " << ofname;
      ok = 0;
      break;
    }
    bytes_wrote += plain.length();
    if(last) break;
  }
  plain.Clear(1);
  fclose(in);

  if(data_sink) {
    // Nothing to close
  }
  else if(to_console) {
    if(fflush(out) != 0) ok = 0;
  }
  else {
    ok = FinishDecryptOutput(out, ok);
  }
  return ok;
}
// ----------------------------------------------------------- //
// 10/27/2026: Key management, see fcfile.h
// ----------------------------------------------------------- //
class FCHmacSink : public CryptDataSink
// HMAC of the decrypted data, to check a rewritten file holds the same
// data without keeping it
{
public:
  FCHmacSink(const unsigned char key[FC_KEY_LEN]) { h = AES_hmac_new(key, FC_KEY_LEN); len = (FAU_t)0; }
  ~FCHmacSink() { if(h) AES_hmac_free(h); }
  int WriteData(const unsigned char *buf, unsigned n) {
    len += n;
    return h && AES_hmac_update(h, buf, n);
  }
  int Final(unsigned char out[FC_TAG_LEN]) {
    unsigned char l[8];
    fc_put64(l, len);
    int ok = h && AES_hmac_update(h, l, sizeof(l)) && AES_hmac_final(h, out, FC_TAG_LEN);
    return ok;
  }
  AES_hmac_ctx *h;
  FAU_t len;
};

class FCReencryptSink : public CryptDataSink
{
public:
  FCReencryptSink(FCryptFile *f, FCHmacSink *m) { nf = f; mac = m; }
  int WriteData(const unsigned char *buf, unsigned n) {
    return mac->WriteData(buf, n) && nf->WriteData(buf, n);
  }
  FCryptFile *nf;
  FCHmacSink *mac;
};

static unsigned fc_count_slots(gxList<FCKeySlot> &l)
{
  unsigned n = 0;
  for(gxListNode<FCKeySlot> *p = l.GetHead(); p; p = p->next) n++;
  return n;
}

unsigned FCryptFile::NumSlots()
{
  return fc_count_slots(slots);
}

gxString FCryptFile::FileIDHex() const
{
  return FC_hex(file_id, sizeof(file_id));
}

unsigned FCryptFile::KeyGeneration() const
{
  if(memcmp(header+FC_HDR_EXT_OFFSET, FC_HDR_EXT_MAGIC, 4) != 0) return 0;
  return fc_get32(header+FC_HDR_EXT_OFFSET+4);
}

unsigned long long FCryptFile::RekeyTime() const
{
  if(memcmp(header+FC_HDR_EXT_OFFSET, FC_HDR_EXT_MAGIC, 4) != 0) return 0;
  unsigned long long v = 0;
  for(int i = 7; i >= 0; i--) v = (v << 8) | header[FC_HDR_EXT_OFFSET+8+i];
  return v;
}

int FCryptFile::WriteCopy(const char *out_name, gxString &e)
// Writes the header with the current slots, then the records of the
// original file unchanged
{
  if(!cryptdb_create_private_file(out_name)) {
    e << clear << "Cannot create " << out_name << " (remove it if it is left from an earlier run)";
    return 0;
  }
  FILE *out = fopen(out_name, "wb");
  FILE *in = fopen(filename.c_str(), "rb");
  int ok = (out && in);
  if(!ok) e << clear << "Cannot open " << out_name;
  gxString keep_ofname = ofname;
  ofname = out_name;
  if(ok) ok = WriteHeader(out);
  ofname = keep_ofname;
  if(!ok && e.is_null()) e = err;
  if(ok && fseek(in, (long)data_offset, SEEK_SET) != 0) ok = 0;
  unsigned char buf[65536];
  size_t n;
  while(ok && (n = fread(buf, 1, sizeof(buf), in)) > 0) ok = fc_write_exact(out, buf, (unsigned)n);
  if(ok && ferror(in)) ok = 0;
  if(in) fclose(in);
  if(out && fclose(out) != 0) ok = 0;
  if(!ok) {
    if(e.is_null()) e << clear << "Error writing " << out_name;
    futils_remove(out_name);
  }
  return ok;
}

int FCryptFile::VerifyCopy(const char *fname, const unsigned char key[FC_KEY_LEN], MemoryBuffer *digest, gxString &e)
// Opens fname with key and decrypts every record. With digest set the
// HMAC of the data is compared with it.
{
  FCryptFile chk;
  if(!chk.LoadHeader(fname) || !chk.UnlockWithFileKey(key)) {
    e << clear << "The rewritten file does not open: " << chk.err;
    return 0;
  }
  unsigned char hkey[FC_KEY_LEN], tag[FC_TAG_LEN];
  if(digest) memmove(hkey, digest->m_buf(), FC_KEY_LEN);
  else if(!fc_rand(hkey, sizeof(hkey), 0)) return 0;
  FCHmacSink sink(hkey);
  chk.data_sink = &sink;
  int ok = chk.DecryptFile(0);
  if(!ok) e << clear << "The rewritten file does not decrypt: " << chk.err;
  if(ok && digest) {
    ok = sink.Final(tag) && CRYPTO_memcmp(tag, (unsigned char *)digest->m_buf() + FC_KEY_LEN, FC_TAG_LEN) == 0;
    if(!ok) e << clear << "The rewritten file does not hold the same data";
  }
  OPENSSL_cleanse(hkey, sizeof(hkey));
  return ok;
}

int FCryptFile::KeepBackup(gxString &backup_file)
{
  gxString ext;
  int dot = FC_find_last(filename.c_str(), ".");
  int slash = FC_find_last(filename.c_str(), "/");
  int bslash = FC_find_last(filename.c_str(), "\\");
  if(dot > slash && dot > bslash && dot > 0) ext = filename.c_str() + dot;
  backup_file = FC_backup_name(filename.c_str(), "backup", ext.is_null() ? 0 : ext.c_str());
  gxString e;
  if(FC_copy_private(filename.c_str(), backup_file.c_str(), e) != 0) {
    err = e;
    backup_file.Clear();
    return 0;
  }
  return 1;
}

int FCryptFile::RemoveSlot(unsigned type, const char *username, int keep_backup, gxString &backup_file)
{
  backup_file.Clear();
  if(!unlocked) {
    err << clear << "The encrypted file is not unlocked";
    return 0;
  }
  if(type != FC_SLOT_RSA && type != FC_SLOT_SMARTCARD) {
    err << clear << "Only RSA key and smart card users can be removed";
    return 0;
  }
  gxListNode<FCKeySlot> *node = slots.GetHead();
  while(node && !(node->data.type == type && node->data.username == username)) node = node->next;
  if(!node) {
    err << clear << "User " << username << " has no " << FC_slot_type_name(type) << " access to " << filename;
    return 0;
  }
  if(fc_count_slots(slots) <= 1) {
    err << clear << "User " << username << " holds the last key slot of " << filename
	<< ", removing it would leave a file nothing can open";
    return 0;
  }

  // Digest of the data before the change
  unsigned char hkey[FC_KEY_LEN], tag[FC_TAG_LEN];
  if(!fc_rand(hkey, sizeof(hkey), 0)) {
    err << clear << "Random number generator failed";
    return 0;
  }
  MemoryBuffer digest;
  {
    FCHmacSink sink(hkey);
    CryptDataSink *keep = data_sink;
    data_sink = &sink;
    int ok = DecryptFile(0);
    data_sink = keep;
    if(!ok || !sink.Final(tag)) {
      OPENSSL_cleanse(hkey, sizeof(hkey));
      return 0;
    }
    digest.Cat(hkey, sizeof(hkey));
    digest.Cat(tag, sizeof(tag));
  }
  OPENSSL_cleanse(hkey, sizeof(hkey));

  FCKeySlot removed = node->data;
  slots.Remove(node);
  unsigned char *area = new unsigned char[file_slot_area_len];
  int ok = BuildSlotArea(area, err);
  if(ok) memmove(slot_area, area, file_slot_area_len);
  delete[] area;
  gxString tmp, e;
  tmp << filename << ".remove-user.tmp";
  if(ok) ok = WriteCopy(tmp.c_str(), e);
  if(ok) ok = VerifyCopy(tmp.c_str(), file_key, &digest, e);
  if(ok && keep_backup) {
    ok = KeepBackup(backup_file);
    if(!ok) e = err;
  }
  if(ok) ok = (FC_replace_file(tmp.c_str(), filename.c_str(), e) == 0);
  digest.Clear(1);
  if(!ok) {
    futils_remove(tmp.c_str());
    if(!backup_file.is_null()) futils_remove(backup_file.c_str());
    backup_file.Clear();
    slots.Add(removed); // The original file is unchanged
    err << clear << "The file was not changed: " << e;
    return 0;
  }
  return 1;
}

int FCryptFile::BeginRekey()
{
  if(!unlocked) {
    err << clear << "The encrypted file is not unlocked";
    return 0;
  }
  rekey_slots.ClearList();
  if(!fc_rand(new_file_key, sizeof(new_file_key), 1)) {
    err << clear << "Random number generator failed";
    return 0;
  }
  rekey_started = 1;
  return 1;
}

int FCryptFile::AddRekeySlot(unsigned type, const char *username, const unsigned char *wrapped, unsigned wrapped_len)
{
  if(!rekey_started) {
    err << clear << "The rekey was not started";
    return 0;
  }
  if((type != FC_SLOT_RSA && type != FC_SLOT_SMARTCARD) || !username || !*username ||
     strlen(username) > FC_MAX_USERNAME_LEN || wrapped_len == 0 || wrapped_len > FC_MAX_WRAPPED_LEN) {
    err << clear << "Bad key slot for the rekey";
    return 0;
  }
  FCKeySlot slot;
  slot.type = type;
  slot.username = username;
  slot.wrapped.Load(wrapped, wrapped_len);
  rekey_slots.Add(slot);
  return 1;
}

int FCryptFile::FinishRekey(const MemoryBuffer *new_secret, int keep_backup, gxString &backup_file)
{
  backup_file.Clear();
  if(!unlocked || !rekey_started) {
    err << clear << "The rekey was not started";
    return 0;
  }
  if(!new_secret && fc_count_slots(rekey_slots) == 0) {
    err << clear << "The rekey would leave no key slot, nothing could open " << filename;
    return 0;
  }
  gxString name;
  if(!DecryptStoredName(name)) return 0;

  gxString tmp, e;
  tmp << filename << ".rekey.tmp";
  if(futils_exists(tmp.c_str())) {
    err << clear << tmp << " exists from an earlier rekey that did not finish, check it and remove it";
    return 0;
  }
  unsigned char hkey[FC_KEY_LEN], tag[FC_TAG_LEN];
  if(!fc_rand(hkey, sizeof(hkey), 0)) {
    err << clear << "Random number generator failed";
    return 0;
  }
  MemoryBuffer digest;
  int ok;
  {
    FCryptFile nf;
    nf.iterations = file_iterations;
    nf.slot_area_len = file_slot_area_len;
    nf.overwrite = 1;
    nf.preset_key = new_file_key;
    nf.preset_no_secret = new_secret ? 0 : 1;
    gxListNode<FCKeySlot> *p = rekey_slots.GetHead();
    while(p) {
      nf.preset_slots.Add(p->data);
      p = p->next;
    }
    nf.key_generation = KeyGeneration() + 1;
    nf.rekey_time = (unsigned long long)time(0);
    MemoryBuffer none;
    ok = nf.BeginEncrypt(new_secret ? *new_secret : none, name.c_str(), tmp.c_str());
    if(!ok) e = nf.err;
    FCHmacSink mac(hkey);
    if(ok) {
      FCReencryptSink sink(&nf, &mac);
      CryptDataSink *keep = data_sink;
      data_sink = &sink;
      ok = DecryptFile(0);
      data_sink = keep;
      if(!ok) e = err.is_null() ? nf.err : err;
    }
    if(ok) {
      ok = nf.FinishEncrypt();
      if(!ok) e = nf.err;
    }
    else {
      nf.AbortEncrypt();
    }
    if(ok && mac.Final(tag)) {
      digest.Cat(hkey, sizeof(hkey));
      digest.Cat(tag, sizeof(tag));
    }
    else if(ok) {
      ok = 0;
      e << clear << "Cannot compute the data check";
    }
  }
  OPENSSL_cleanse(hkey, sizeof(hkey));
  if(ok) ok = VerifyCopy(tmp.c_str(), new_file_key, &digest, e);
  if(ok && new_secret) { // The password slot opens the new file
    FCryptFile chk;
    ok = chk.LoadHeader(tmp.c_str()) && chk.UnlockWithSecret(*new_secret);
    if(!ok) e << clear << "The password slot of the rewritten file does not open it: " << chk.err;
  }
  if(ok && keep_backup) {
    ok = KeepBackup(backup_file);
    if(!ok) e = err;
  }
  if(ok) ok = (FC_replace_file(tmp.c_str(), filename.c_str(), e) == 0);
  digest.Clear(1);
  if(!ok) {
    futils_remove(tmp.c_str());
    if(!backup_file.is_null()) futils_remove(backup_file.c_str());
    backup_file.Clear();
    err << clear << "The file was not changed: " << e;
    return 0;
  }
  rekey_started = 0;
  OPENSSL_cleanse(new_file_key, sizeof(new_file_key));
  return 1;
}

// 10/25/2026: The crypto primitives of the 2026102 format, exported so
// other programs built on fcrypt, such as the Encrypted Password
// Database, use the same FIPS approved implementation. Each returns 1
// if successful or 0 on failure, and runs in the library context set up
// by FC_crypto_init(), or OpenSSL's default context.
int FC_rand_bytes(unsigned char *buf, unsigned len, int priv)
{
  return fc_rand(buf, len, priv);
}

int FC_pbkdf2_sha256(const unsigned char *secret, unsigned secret_len,
		     const unsigned char *salt, unsigned salt_len,
		     unsigned iterations, unsigned char *out, unsigned out_len)
{
  return fc_pbkdf2(secret, secret_len, salt, salt_len, iterations, out, out_len);
}

int FC_kbkdf_sha256(const unsigned char key[FC_KEY_LEN], const char *label,
		    const unsigned char *context, unsigned context_len,
		    unsigned char out[FC_KEY_LEN])
{
  return fc_kbkdf(key, label, context, context_len, out);
}

int FC_aes256_cbc(int enc, const unsigned char key[FC_KEY_LEN], const unsigned char iv[FC_IV_LEN],
		  const unsigned char *in, unsigned in_len, unsigned char *out, unsigned *out_len)
{
  return fc_cbc(enc, key, iv, in, in_len, out, out_len);
}

// ----------------------------------------------------------- //
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
