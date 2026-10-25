// ------------------------------- //
// -------- Start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- //
// C++ Header File
// Compiler Used: MSVC, BCC32, GCC, HPUX aCC, SOLARIS CC
// Produced By: DataReel Software Development Team
// File Creation Date: 06/15/2003
// Date Last Modified: 10/24/2026
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

General-purpose encryption and decryption routines.                             
Encryption routes used encrypt/decrypt file buffers and memory buffers.         
Encryption routes used create password file hashes.                             
Encryption routes generate encryption certificates and authenticate users.
*/
// ----------------------------------------------------------- //   

#ifndef __GX_S_CRYPT_DB_HPP__
#define __GX_S_CRYPT_DB_HPP__

#include "aesdb.h"
#include "rsadb.h"
#include "smart_card.h"

// DataReel include files
#include "gxdlcode.h"
#include "membuf.h"
#include "gxstring.h"
#include "gxuint32.h"
#include "gxuint16.h"
#include "gxstream.h"
#include "devcache.h"
#include "dfileb.h"
#include "gxlist.h"
#include "gxs_b64.h"

const unsigned DEFAULT_STATIC_DATA_AREA_SIZE = 16384;
const unsigned MIN_STATIC_DATA_AREA_SIZE = 1;
const unsigned MAX_STATIC_DATA_AREA_SIZE = 65535;
const unsigned MAX_FILENAME_LEN = 256;
// 10/24/2026: Longest file name stored in a file header. Names longer than
// MAX_FILENAME_LEN continue into CryptFileHdr::reserved, which is how
// older versions stored and read them back.
const unsigned MAX_STORED_FILENAME_LEN = MAX_FILENAME_LEN + 32;
const unsigned MAX_USERNAME_LEN = 64;
const gxUINT32 STATIC_DATA_VERSION = 2023103;
const gxUINT32 STATIC_DATA_BLOCK_VERSION = 2023103;
const gxUINT32 CRYPT_FILE_VERSION = 2023103;

struct GXDLCODE_API StaticDataHeader
{
  StaticDataHeader() { FormatHeader(); }
  ~StaticDataHeader() { WipeHeader(); }
  StaticDataHeader(const StaticDataHeader &ob) { Copy(ob); }
  StaticDataHeader &operator=(const StaticDataHeader &ob) {
    if(&ob == this) return *this;
    Copy(ob);
    return *this;
  }
  
  int FormatHeader() { // Setup header to be written 
    version = STATIC_DATA_VERSION;
    start_checkword = 0xABAB;
    end_checkword = 0xFEFE;
    static_area_len = start_of_static_data = (gxUINT32)0;
    AES_fillrand(reserved, sizeof(reserved));
    return 0;
  }
  int WipeHeader() { // Clear header to be read
    version = start_checkword = end_checkword = (gxUINT32)0;
    static_area_len = start_of_static_data = (gxUINT32)0;
    memset(reserved, 0, sizeof(reserved));
    return 0;
  }
  int Copy(const StaticDataHeader &ob) {
    WipeHeader();
    version = ob.version;
    start_checkword = ob.start_checkword;
    end_checkword = ob.end_checkword;
    static_area_len = ob.static_area_len;
    start_of_static_data = ob.start_of_static_data;
    memmove(reserved, ob.reserved, sizeof(reserved));
    return 0;
  }
  
  gxUINT32 version;
  gxUINT32 start_checkword;
  gxUINT32 static_area_len;
  gxUINT32 start_of_static_data;
  unsigned char reserved[256]; // Reserved for future use
  gxUINT32 end_checkword;
};

struct GXDLCODE_API StaticDataBlockHdr
{
  StaticDataBlockHdr() { FormatHeader(); }
  ~StaticDataBlockHdr() { WipeHeader(); }
  StaticDataBlockHdr(const StaticDataBlockHdr &ob) { Copy(ob); }
  StaticDataBlockHdr &operator=(const StaticDataBlockHdr &ob) {
    if(&ob == this) return *this;
    Copy(ob);
    return *this;
  }
  
  int FormatHeader() { // Setup header to be written 
    version = STATIC_DATA_BLOCK_VERSION;
    checkword = 0xFEFE;
    block_len = block_type = block_status = ciphertext_len = username_len = (gxUINT32)0;
    AES_fillrand(reserved, sizeof(reserved));
    return 0;
  }
  int WipeHeader() { // Clear header to be read
    version = checkword = 0;
    block_len = block_type = block_status = ciphertext_len = username_len = (gxUINT32)0;
    memset(reserved, 0, sizeof(reserved));
    return 0;
  }
  int Copy(const StaticDataBlockHdr &ob) {
    WipeHeader();
    version = ob.version;
    checkword = ob.checkword;
    block_type = ob.block_type;
    block_status = ob.block_status;
    block_len = ob.block_len;
    ciphertext_len = ob.ciphertext_len;
    username_len = ob.username_len;
    memmove(reserved, ob.reserved, sizeof(reserved));
    return 0;
  }
  
  gxUINT32 version;        // Header version number
  gxUINT32 checkword;      // Header checkword
  gxUINT32 block_type;     // Application specific block type (1 = RSA key, 2 = Smart card cert)
  gxUINT32 block_status;   // Application specific block status
  gxUINT32 block_len;      // Variable length of this data block excluding this header
  gxUINT32 ciphertext_len; // Variable length of the encrypted data
  gxUINT32 username_len;   // Variable length of optional username
  unsigned char reserved[32]; // Reserved for future use
};

struct GXDLCODE_API StaticDataBlock // For in memory copies
{
 // Block header -> ciphertext -> hmac -> username
  StaticDataBlock() { Clear(); }
  ~StaticDataBlock() { Wipe(); }
  StaticDataBlock(const StaticDataBlock &ob) { Copy(ob); }
  StaticDataBlock &operator=(const StaticDataBlock &ob) {
    if(&ob == this) return *this;
    Copy(ob);
    return *this;
  }

  int Copy(const StaticDataBlock &ob) {
    Wipe();
    block_header = ob.block_header;
    rsa_ciphertext = ob.rsa_ciphertext;
    rsa_plaintext = ob.rsa_plaintext;
    hmac = ob.hmac;
    username = ob.username;
    username_encoded = ob.username_encoded;
    return 0; 
  }

  int Wipe() {
    block_header.WipeHeader();
    rsa_ciphertext.Clear(1);
    rsa_plaintext.Clear(1);
    hmac.Clear(1);
    username.Clear(1);
    username_encoded.Clear(1);
    return 0;
  }

  int Clear() {
    block_header.FormatHeader();
    rsa_ciphertext.Clear();
    rsa_plaintext.Clear();
    hmac.Clear();
    username.Clear();
    username_encoded.Clear();
    return 0;
  }
  
  StaticDataBlockHdr block_header;
  MemoryBuffer rsa_ciphertext;
  MemoryBuffer rsa_plaintext;
  MemoryBuffer hmac;
  gxString username;
  gxString username_encoded;
};

struct GXDLCODE_API CryptFileHdr
{
  CryptFileHdr() {
    version = CRYPT_FILE_VERSION;
    checkword = 0xFEFE; 
    name_len = (gxUINT32)0;
    memset(fname, 0, sizeof(fname));
    memset(reserved, 0, sizeof(reserved));
    mode = 3;
  }
  ~CryptFileHdr() { }

  gxUINT32 version;   // Header version number
  gxUINT32 checkword; // Header checkword
  gxUINT32 mode;      // Encryption mode
                      // 0 = No encryption
                      // 3 = AES 256-bit encryption 

  gxUINT32 name_len; // Variable length of encrypted file name or DIR list
  char fname[MAX_FILENAME_LEN]; // Name of the file that was encrypted or DIR list
  unsigned char reserved[32]; // Reserved for future use
};

// 10/24/2026: Whole-file integrity record. It is stored in the encrypted
// file header, right after CryptFileHdr, in the random padding that every
// fcrypt version writes there and ignores on decrypt. Files with this
// record are protected against truncated, reordered, removed or spliced
// data blocks. Older fcrypt versions can still decrypt these files.
const char CRYPT_FILE_INTEGRITY_MAGIC[8] = { 'F', 'C', 'I', 'N', 'T', '0', '1', 0 };
const unsigned CRYPT_FILE_INTEGRITY_KEY_LEN = 32;
const unsigned CRYPT_FILE_INTEGRITY_MAC_LEN = 32;

struct GXDLCODE_API CryptFileIntegrity
{
  CryptFileIntegrity() { Wipe(); }
  ~CryptFileIntegrity() { Wipe(); }
  void Wipe() {
    OPENSSL_cleanse(magic, sizeof(magic));
    OPENSSL_cleanse(mac_key, sizeof(mac_key));
    OPENSSL_cleanse(data_len, sizeof(data_len));
    OPENSSL_cleanse(plaintext_len, sizeof(plaintext_len));
    OPENSSL_cleanse(file_mac, sizeof(file_mac));
  }
  int IsSet() const { return memcmp(magic, CRYPT_FILE_INTEGRITY_MAGIC, sizeof(magic)) == 0; }

  char magic[8];
  unsigned char mac_key[CRYPT_FILE_INTEGRITY_KEY_LEN]; // Random per file
  unsigned char data_len[8];      // Little endian length of all data after the header
  unsigned char plaintext_len[8]; // Little endian length of the original file
  unsigned char file_mac[CRYPT_FILE_INTEGRITY_MAC_LEN]; // HMAC-SHA256 over the data
};

// 10/24/2026: How decrypt uses the file name stored in the file header
enum {
  CRYPT_PATH_RELATIVE = 0, // Default: stored path under the current or output DIR
  CRYPT_PATH_ABSOLUTE,     // Restore the exact stored path
  CRYPT_PATH_NONE          // File name only, in the current or output DIR
};

// Cached file encryption class
class GXDLCODE_API FCryptCache : public gxDeviceCache
{
public:
  FCryptCache(unsigned CacheSize = 1024, unsigned size_of_static_data_area = DEFAULT_STATIC_DATA_AREA_SIZE);
  ~FCryptCache();

public: // Encrypt functions
  int EncryptFile(const char *fname, const MemoryBuffer &secret);

public: // Decrypt fucntions
  int DecryptFileHeader(CryptFileHdr &hdr, const char *fname, const MemoryBuffer &secret, gxUINT32 &version);
  int DecryptFile(const char *fname, const MemoryBuffer &secret, gxUINT32 &version, char *outfile_name = 0);
  int DecryptOnlyTheFileName(const char *fname, const MemoryBuffer &secret, gxUINT32 &version, gxString &crypt_file_name);

public: // RSA key functions
  int TestStaticDataHeader(const StaticDataHeader &sd_header_read);
  int CheckStaticDataHeader(const StaticDataHeader &sd_header_read, FAU_t file_length);
  int UpdateStaticData();
  int WriteStaticDataAreaToFile(const char *fname);
  int AddRSAKeyToStaticArea(const char *fname, const MemoryBuffer &secret,
			    char public_key[], unsigned public_key_len,
			    const char *rsa_key_username, char *passphrase = 0);
  int LoadStaticDataBlocks(const char *fname);
  int LoadStaticDataBlocks(const char *fname, unsigned &num_blocks, unsigned &next_write_address);
  int LoadStaticDataBlocks();

#ifdef __ENABLE_SMART_CARD__
public: // Smart card functions 
  int AddSmartCardCertToStaticArea(SmartCardOB *sc, int use_cert_file,
				   const char *fname, const MemoryBuffer &secret, const char *smartcard_cert_username);
#endif
  
public: // Helper functions
  void Flush() { cache.Flush(); } // Flush the cache buckets
  unsigned BucketsInUse() { return cache.BucketsInUse(); }
  char *OutFileName() { return ofname.c_str(); }
  char *InFileName() { return filename.c_str(); }
  void SetOverWrite(int m) { overwrite = m; }
  void SetBufSize(__ULWORD__ m) { buf_size = m; }
  void SetDotExt(const char *s) { en_dot_ext = s; }
  void SetDir(const char *s) { output_dir_name = s; }
  void SetOutputFileName(const char *s) { output_file_name = s; }
  void SetPathMode(int m) { path_mode = m; }
  void SetAllowUnencrypted(int m) { allow_unencrypted = m; }
  int HasIntegrity() const { return has_integrity; }
  const gxString &StoredFileName() const { return stored_name; }
  FAU_t BytesWrote() { return bytes_wrote; }
  FAU_t BytesRead() { return bytes_read; }
  
private: // Internal processing functions
  void CloseOutputFile() {  
    outfile.df_Close(); 
  }
  void CloseInputFile() { 
    infile.df_Close(); 
  }
  int OpenInputFile(const char *fname);
  int OpenOutputFile();
  int LoadFile(gxDeviceCachePtr p);
  int TestVersion(CryptFileHdr hdr, gxUINT32 &version);
  int WriteIntegrityHeader();
  int VerifyIntegrity();
  int StartIntegrity();
  int OpenDecryptOutputFile();
  int FinishDecryptOutputFile(int ok);
  void IntegrityUpdate(const void *buf, unsigned len);

private: // Base class interface
  void Read(void *buf, unsigned Bytes, gxDeviceTypes dev);
  void Write(const void *buf, unsigned Bytes, gxDeviceTypes dev);

private: // Device objects
  DiskFileB outfile; // File used to output data
  DiskFileB infile;  // File used to input data
  
private: // Device cache
  gxDeviceBucketCache cache;
  gxUINT32 buf_size;
  int overwrite;
  gxString filename;
  gxString ofname;
  gxString en_dot_ext;
  gxString output_dir_name;
  gxString output_file_name;
  int crypt_stream;
  FAU_t bytes_wrote;
  FAU_t bytes_read;
  int path_mode;
  int has_integrity;
  CryptFileIntegrity integrity;
  AES_hmac_ctx *integrity_ctx;
  FAU_t integrity_data_len;
  FAU_t integrity_plaintext_len;
  FAU_t header_offset;
  FAU_t data_offset;
  unsigned header_crypt_len;
  unsigned char header_plain[AES_MAX_INPUT_BUF_LEN];
  gxString tmp_ofname;   // Temp file decrypted data is written to
  gxString stored_name;  // File name stored in the encrypted file header
  int allow_unencrypted; // Allow decrypting mode 0 (unencrypted) files

public: // Functions used to get the current device cache
  gxDeviceBucketCache *GetCache() { return &cache; }
  DiskFileB *GetOutFile() { return &outfile; }
  DiskFileB *GetInFile() { return &infile; }

public:
  int ERROR_LEVEL;
  int mode;
  unsigned key_iterations;
  gxString err;
  //  CryptSecretHdr cp;
  MemoryBuffer cryptdb_secret;
  AESStreamCrypt aesdb;
  unsigned char *static_data;
  unsigned int static_data_size;
  gxList<StaticDataBlock> static_block_list;
  gxString decrypted_output_filename;
  unsigned static_data_bytes_used;
  unsigned num_static_data_blocks;
};

// Standalone functions
// -------------------------------------------------------------
int cryptdb_makedirs(const gxString &path);
int cryptdb_make_restore_path(const gxString &stored_name, int path_mode,
			      gxString &path, gxString &err);
int cryptdb_create_private_file(const char *fname);
int cryptdb_rename_file(const char *from, const char *to, int overwrite);
int read_key_file(const char *fname, MemoryBuffer &key, gxString &err, int expected_key_len = 0);
int cryptdb_gethomedir(gxString &home_dir);
int cryptdb_makeabspath(gxString &path);
int cryptdb_getdircontents(gxString &path, gxString &err, 
			   gxList<gxString> &file_list,
			   int &num_files, int &num_dirs);

// Internal standalone functions
// -------------------------------------------------------------
int cryptdb_buildfilelist(gxString &path, gxString &err, 
			  gxList<gxString> &file_list,
			  gxList<gxString> &dir_list, 
			  int &num_files, int &num_dirs);

#endif // __GX_S_CRYPT_DB_HPP__
// ----------------------------------------------------------- // 
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //


