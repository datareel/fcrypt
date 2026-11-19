// ------------------------------- //
// -------- Start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- //
// C++ Header File Name: fcfile.h
// Compiler Used: MSVC, GCC
// Produced By: DataReel Software Development Team
// File Creation Date: 10/25/2026
// Date Last Modified: 10/25/2026
// Copyright (c) 2001-2026 DataReel Software Development
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

fcrypt file format version 2026102. Every algorithm it uses is FIPS
140-3 approved, and every crypto operation goes through the OpenSSL
library context set up by FC_crypto_init() (fcfips.h).

All integers are little endian.

Fixed header, 128 bytes, not encrypted:
  0  magic "FCRYPT\x1A\x04"     8 bytes
  8  file version (2026102)      4
  12 header length (128)         4
  16 flags (0)                   4
  20 KDF ID (1 = PBKDF2-HMAC-SHA256, SP 800-132)  4
  24 KDF iterations              4
  28 cipher ID (1 = AES-256-CBC with HMAC-SHA256, encrypt-then-MAC)  4
  32 chunk size (65536)          4
  36 key slot area length        4
  40 PBKDF2 salt                 32
  72 file ID                     16
  88 reserved (0)                40
     Since 2026.106 a file that was rekeyed has, in the reserved
     bytes (older versions write zeros and never read them, and the
     header MAC covers them):
     88 "FCX1"  4, 92 key generation  4, 96 rekey time, UTC seconds  8

Key slot area, key slot area length bytes, not encrypted. Each slot:
  type (1 = password or key file, 2 = RSA key, 3 = smart card;
        since 2026.110: 4 = RSA key + ML-KEM-1024, 5 = smart card +
        ML-KEM-1024, 6 = hybrid part, see MakeHybridSlots())  4
  slot length, including these 12 bytes   4
  user name length                         4
  user name
  wrapped file key length                  4
  wrapped file key
A slot type of 0, or the end of the area, ends the list.

Header MAC, 32 bytes: HMAC-SHA256 over the fixed header and the whole
key slot area, so slots cannot be added, removed or changed without a
key that can open the file.

Every file has a random 256-bit file key. Slot 1 wraps it with AES-256
Key Wrap (SP 800-38F) under PBKDF2(password, salt, iterations). RSA and
smart card slots wrap it with RSA-OAEP using SHA-256. The header MAC
key and the data encryption and MAC keys are derived from the file key
with KBKDF in counter mode with HMAC-SHA256 (SP 800-108), using the
file ID as the context.

Records follow the header MAC. Record 0 holds the stored file name and
records 1 to N hold the file data, up to one chunk each:
  ciphertext length    4
  IV                   16
  ciphertext (AES-256-CBC, PKCS#7 padding)
  tag                  32
The tag is HMAC-SHA256 over the file ID, the record number (8 bytes),
a last-record flag (1 byte), the ciphertext length, the IV and the
ciphertext. The last record of a file has the flag set, so a file cut
short, records moved or records from another file are detected.
*/
// ----------------------------------------------------------- //
#ifndef __FC_FILE_HPP__
#define __FC_FILE_HPP__

#include "gxdlcode.h"
#include "gxstring.h"
#include "membuf.h"
#include "gxlist.h"
#include "gxheader.h"
#include "aesdb.h"
#include "rsadb.h"
#include "cryptdb.h"

#include <stdio.h>

const unsigned FC_FILE_VERSION = 2026102;
const unsigned FC_MAGIC_LEN = 8;
const unsigned FC_HEADER_LEN = 128;
const unsigned FC_SALT_LEN = 32;
const unsigned FC_FILE_ID_LEN = 16;
const unsigned FC_KEY_LEN = 32;
const unsigned FC_WRAPPED_KEY_LEN = 40;  // AES Key Wrap of a 32-byte key
const unsigned FC_IV_LEN = 16;
const unsigned FC_TAG_LEN = 32;
const unsigned FC_CHUNK_SIZE = 65536;
const unsigned FC_MIN_CHUNK_SIZE = 4096;
const unsigned FC_MAX_CHUNK_SIZE = 1048576;
const unsigned FC_DEF_SLOT_AREA_LEN = 16384;
const unsigned FC_MIN_SLOT_AREA_LEN = 2048;
const unsigned FC_MAX_SLOT_AREA_LEN = 65535;
const unsigned FC_DEF_ITERATIONS = 600000;
const unsigned FC_MIN_ITERATIONS = 1000;
const unsigned FC_MAX_ITERATIONS = 10000000;
const unsigned FC_MAX_STORED_NAME_LEN = 4096;
const unsigned FC_MAX_USERNAME_LEN = 255;
const unsigned FC_MAX_WRAPPED_LEN = 1024; // RSA keys up to 8192 bits
const unsigned FC_MIN_RSA_BITS = 2048;
const unsigned FC_KDF_PBKDF2_SHA256 = 1;
const unsigned FC_CIPHER_AES256_CBC_HMAC_SHA256 = 1;
const unsigned FC_HDR_EXT_OFFSET = 88; // 10/27/2026: Key generation, see above

enum { // Key slot types
  FC_SLOT_END = 0,
  FC_SLOT_SECRET = 1,    // Password or key file
  FC_SLOT_RSA = 2,       // RSA public key, RSA-OAEP with SHA-256
  FC_SLOT_SMARTCARD = 3, // Smart card cert, RSA-OAEP with SHA-256
  // 11/18/2026: Release 2026.110 hybrid (quantum-resistant) users, see
  // FCryptFile::MakeHybridSlots(). Releases 2026.102 to 2026.109 refuse a
  // file with a slot over FC_MAX_WRAPPED_LEN bytes, so the hybrid data is
  // split into slots of at most 1024 bytes: older releases keep the
  // unknown slots and still open the file with the password, key file or
  // an RSA-only user.
  FC_SLOT_RSA_HYBRID = 4,       // RSA key + ML-KEM-1024 key
  FC_SLOT_SMARTCARD_HYBRID = 5, // Smart card cert + ML-KEM-1024 key
  FC_SLOT_HYBRID_PART = 6       // Part of a hybrid user's ciphertexts
};

enum { // File formats found by FC_file_format()
  FC_FORMAT_OPEN_ERROR = -1,
  FC_FORMAT_LEGACY = 0,  // Versions 2023102 and 2023103
  FC_FORMAT_2026102 = 1
};

// Returns the format of an encrypted file
int FC_file_format(const char *fname);

// 10/25/2026: Exported primitives, see fcfile.cpp. Return 1 if successful.
int FC_rand_bytes(unsigned char *buf, unsigned len, int priv = 0);
int FC_pbkdf2_sha256(const unsigned char *secret, unsigned secret_len,
		     const unsigned char *salt, unsigned salt_len,
		     unsigned iterations, unsigned char *out, unsigned out_len);
int FC_kbkdf_sha256(const unsigned char key[FC_KEY_LEN], const char *label,
		    const unsigned char *context, unsigned context_len,
		    unsigned char out[FC_KEY_LEN]);
int FC_aes256_cbc(int enc, const unsigned char key[FC_KEY_LEN], const unsigned char iv[FC_IV_LEN],
		  const unsigned char *in, unsigned in_len, unsigned char *out, unsigned *out_len);

// Name of a key slot type for messages
const char *FC_slot_type_name(unsigned type);
// 11/18/2026: Hybrid slot helpers. FC_slot_base_type() gives FC_SLOT_RSA
// or FC_SLOT_SMARTCARD for a plain or hybrid user slot, 0 otherwise.
unsigned FC_slot_base_type(unsigned type);
int FC_slot_is_hybrid(unsigned type);
unsigned FC_hybrid_type(unsigned base_type);
// True for a slot that can open a file (not a hybrid part)
int FC_slot_is_user(unsigned type);

// 11/18/2026: ML-KEM-1024 (NIST FIPS 203) user keys for hybrid users.
// The private key file is PKCS#8 PEM encrypted with the passphrase
// (AES-256-CBC, PBKDF2), mode 600; the public key is file.pub.pem.
const unsigned FC_HYBRID_SECRET_LEN = 32;   // The RSA half, r
const unsigned FC_MLKEM1024_CT_LEN = 1568;
const unsigned FC_HYBRID_PART_LEN = 1000;   // Ciphertext bytes per part slot
const unsigned FC_HYBRID_VERSION = 1;
const unsigned FC_HYBRID_KEM_MLKEM1024 = 1024;
// 11/19/2026 (dougg): the RHEL system crypto policy. The OpenSSL 3.5
// built into the RHEL 8 rhel8_openssl35 build does not read it, so fcrypt
// reads /etc/crypto-policies/state/current itself (FC_CRYPTO_POLICY_FILE
// in the environment overrides it, for tests). FUTURE asks for RSA keys of
// at least 3072 bits. Empty when there is no policy (Windows, other Linux).
gxString FC_crypto_policy();
// The smallest RSA key fcrypt gives new access to: FC_MIN_RSA_BITS, or
// more when the crypto policy asks for it
unsigned FC_min_rsa_bits();
// "Crypto policy: NAME (...)" for --version, empty without a policy
gxString FC_crypto_policy_status();

// 1 if this OpenSSL can make ML-KEM-1024 keys (OpenSSL 3.5 and later)
int FC_pq_available(gxString &err);
// Writes priv_file (mode 600) and priv_file.pub.pem. Returns 1 if successful.
int FC_pq_generate_key(const char *priv_file, const MemoryBuffer &passphrase, gxString &pub_file, gxString &err);
// Load a public key (any PEM file with an ML-KEM-1024 public key) or the
// private key file. The caller frees the key with EVP_PKEY_free().
EVP_PKEY *FC_pq_load_public_key(const char *fname, gxString &err);
EVP_PKEY *FC_pq_load_private_key(const char *fname, const MemoryBuffer &passphrase, gxString &err);

struct GXDLCODE_API FCKeySlot
{
  FCKeySlot() { type = 0; }
  ~FCKeySlot() { wrapped.Clear(1); }
  FCKeySlot(const FCKeySlot &ob) { Copy(ob); }
  FCKeySlot &operator=(const FCKeySlot &ob) {
    if(&ob != this) Copy(ob);
    return *this;
  }
  void Copy(const FCKeySlot &ob) {
    type = ob.type; username = ob.username; wrapped = ob.wrapped;
  }
  unsigned type;
  gxString username;
  MemoryBuffer wrapped;
};

class GXDLCODE_API FCryptFile
{
public:
  FCryptFile();
  ~FCryptFile();

public: // Encrypt
  // Encrypt fname to a new 2026102 file. The output name follows the same
  // rules as before: the dot extension, output DIR, output file name and
  // a unique name unless overwrite is set.
  int EncryptFile(const char *fname, const MemoryBuffer &secret);

  // Encrypt data given in pieces, for fmigrate. BeginEncrypt() writes the
  // header to a private temp file, WriteData() adds the data, and
  // FinishEncrypt() writes the last record and renames the temp file to
  // out_name. AbortEncrypt() removes the temp file.
  int BeginEncrypt(const MemoryBuffer &secret, const char *stored_name, const char *out_name);
  int WriteData(const unsigned char *buf, unsigned len);
  int FinishEncrypt();
  void AbortEncrypt();

public: // Open an encrypted file
  // Read the header and key slots. Nothing is authenticated until one of
  // the Unlock functions succeeds.
  int LoadHeader(const char *fname);
  int UnlockWithSecret(const MemoryBuffer &secret);
  int UnlockWithRSAKey(const char *username, const char *private_key, unsigned private_key_len,
		       char *passphrase = 0);
  // Unlock with a file key the caller unwrapped, for example with a smart card
  int UnlockWithFileKey(const unsigned char file_key[FC_KEY_LEN]);
  FCKeySlot *FindSlot(unsigned type, const char *username);

public: // After an Unlock
  // Decrypt to outfile_name, "stdout", or the stored name when null.
  // With data_sink set the data goes to the sink instead.
  int DecryptFile(const char *outfile_name = 0);
  int DecryptStoredName(gxString &name);
  // Give another user access. 11/18/2026: The file is rewritten to a
  // temp file, checked, flushed and renamed over the original, as for
  // RemoveSlot(); with add_keep_backup set a backup copy is kept in
  // last_backup_file. The caller takes the file lock.
  int AddRSAKey(const char *username, const char *public_key, unsigned public_key_len,
		char *passphrase = 0);
  int AddWrappedKey(unsigned type, const char *username, const unsigned char *wrapped, unsigned wrapped_len);
  // Adds several slots in one checked rewrite (a hybrid user). Each slot
  // must not hold more than FC_MAX_WRAPPED_LEN bytes.
  int AddSlots(gxList<FCKeySlot> &new_slots);
  // 11/18/2026: Hybrid users. The caller makes r (FC_HYBRID_SECRET_LEN
  // random bytes, FC_hybrid_random()) and encrypts it with the user's RSA
  // public key or card cert (RSA-OAEP SHA-256), giving ct_rsa.
  // MakeHybridSlots() encapsulates with the ML-KEM-1024 public key,
  // derives KEK = KBKDF-HMAC-SHA384(ss || r, label, type || user ||
  // SHA-384(ct_rsa || ct_kem)) and wraps key with AES-256 Key Wrap. The
  // slots are added to out: one FC_SLOT_*_HYBRID slot and the parts.
  int MakeHybridSlots(unsigned type, const char *username, const unsigned char key[FC_KEY_LEN],
		      const unsigned char *ct_rsa, unsigned ct_rsa_len,
		      const unsigned char r[FC_HYBRID_SECRET_LEN], EVP_PKEY *kem_public,
		      gxList<FCKeySlot> &out);
  // The RSA ciphertext of a hybrid user's slot (to decrypt with the RSA
  // key or the card), and the unlock with r and the ML-KEM private key
  int HybridRSACiphertext(unsigned type, const char *username, MemoryBuffer &ct_rsa);
  int UnlockWithHybrid(unsigned type, const char *username, const unsigned char r[FC_HYBRID_SECRET_LEN],
		       EVP_PKEY *kem_private);
  // RSA key file + ML-KEM key for an FC_SLOT_RSA_HYBRID user
  int UnlockWithRSAHybrid(const char *username, const char *private_key, unsigned private_key_len,
			  char *passphrase, EVP_PKEY *kem_private);
  int FC_hybrid_random(unsigned char r[FC_HYBRID_SECRET_LEN]);
  // The file key, for wrapping it with a smart card
  const unsigned char *FileKey() const { return unlocked ? file_key : 0; }
  const unsigned char *FileID() const { return file_id; }
  gxString FileIDHex() const;

public: // 10/27/2026: Key management. The file is rewritten to a temp
        // file, checked, flushed to disk and renamed over the original.
  // Removes the RSA or smart card slot of a user. A backup copy of the
  // original is kept as backup_file unless keep_backup is 0. Refuses to
  // remove the last slot. Returns 1 if successful.
  int RemoveSlot(unsigned type, const char *username, int keep_backup, gxString &backup_file, int dry_run = 0);
  // Number of slots that can open the file
  unsigned NumSlots();
  // Rekey: BeginRekey() makes a new random file key, the caller wraps it
  // for each RSA and smart card slot to keep (AddRekeySlot()), then
  // FinishRekey() writes the file again with a new salt, file ID and
  // key. new_secret is the password or key for the password slot, or
  // null for a file without one. Every record is decrypted with the old
  // keys and encrypted with the new ones, and the new file must decrypt
  // to the same data before it replaces the original.
  int BeginRekey();
  const unsigned char *NewFileKey() const { return rekey_started ? new_file_key : 0; }
  int AddRekeySlot(unsigned type, const char *username, const unsigned char *wrapped, unsigned wrapped_len);
  int AddRekeySlots(gxList<FCKeySlot> &new_slots); // Hybrid users
  int FinishRekey(const MemoryBuffer *new_secret, int keep_backup, gxString &backup_file, int dry_run = 0);
  // With dry_run the new file is written and checked, then removed
  unsigned KeyGeneration() const; // 0 if the file was never rekeyed
  unsigned long long RekeyTime() const;

public: // Settings
  unsigned iterations;
  unsigned slot_area_len;
  int overwrite;
  int path_mode;                 // CRYPT_PATH_* from cryptdb.h
  gxString en_dot_ext;
  gxString output_dir_name;
  gxString output_file_name;
  gxString stored_name_override; // fcrypt --decrypted-outfile
  CryptDataSink *data_sink;      // Decrypt to this instead of a file
  int add_keep_backup;           // AddSlots(): keep a backup copy (default 0: the
                                 // temp file and rename already make it all or nothing)
  int add_dry_run;               // AddSlots(): check the change, leave the file

public: // Results
  gxString err;
  gxString filename;  // Input file
  gxString ofname;    // Output file
  FAU_t bytes_wrote;
  gxString stored_name;
  gxList<FCKeySlot> slots;
  unsigned file_iterations; // Iterations stored in the loaded file
  gxString last_backup_file; // Backup copy kept by AddSlots()

private:
  int MakeEncryptOutputName();
  int BuildSlotArea(unsigned char *area, gxString &e);
  int WriteHeader(FILE *fp);
  int DeriveKeys();
  int VerifyHeaderMAC();
  int ReadRecord(FILE *fp, FAU_t index, MemoryBuffer &plain, int &last);
  int WriteRecord(FILE *fp, FAU_t index, int last, const unsigned char *plain, unsigned len);
  int OpenDecryptOutput(FILE **fp);
  int FinishDecryptOutput(FILE *fp, int ok);
  void Wipe();

private:
  unsigned char header[FC_HEADER_LEN];
  unsigned char *slot_area;
  unsigned char header_mac[FC_TAG_LEN];
  unsigned char salt[FC_SALT_LEN];
  unsigned char file_id[FC_FILE_ID_LEN];
  unsigned char file_key[FC_KEY_LEN];
  unsigned char hdr_mac_key[FC_KEY_LEN];
  unsigned char enc_key[FC_KEY_LEN];
  unsigned char mac_key[FC_KEY_LEN];
  unsigned chunk_size;
  unsigned file_slot_area_len;
  FAU_t data_offset;
  int unlocked;
  gxString tmp_ofname;
  FILE *enc_out;          // BeginEncrypt() to FinishEncrypt()
  gxString enc_tmp;
  unsigned char *enc_pend; // Data for the next record
  unsigned enc_pend_len;
  FAU_t enc_index;

private: // 10/27/2026: Key management
  const unsigned char *preset_key; // Set by FinishRekey() for the new file
  gxList<FCKeySlot> preset_slots;
  int preset_no_secret;
  unsigned key_generation;
  unsigned long long rekey_time;
  int rekey_started;
  unsigned char new_file_key[FC_KEY_LEN];
  gxList<FCKeySlot> rekey_slots;
  int WriteCopy(const char *out_name, gxString &e); // New header, same records
  int VerifyCopy(const char *fname, const unsigned char key[FC_KEY_LEN], MemoryBuffer *digest, gxString &e);
  int KeepBackup(gxString &backup_file);
  // Writes the current slots to a temp file with the records unchanged,
  // checks that it decrypts to the same data, keeps a backup and renames
  // it over the original. With dry_run the temp file is checked and
  // removed. On failure (or a dry run) slot_area is restored; the caller
  // restores the slot list. Returns 1 if successful.
  int CommitSlotArea(const char *tag, int keep_backup, gxString &backup_file, int dry_run, gxString &e);

private: // Disallow copying
  FCryptFile(const FCryptFile &ob) { }
  void operator=(const FCryptFile &ob) { }
};

#endif // __FC_FILE_HPP__
// ----------------------------------------------------------- //
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
