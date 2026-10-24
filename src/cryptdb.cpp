// ------------------------------- //
// -------- start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- // 
// C++ Source Code File
// Compiler Used: MSVC, BCC32, GCC, HPUX aCC, SOLARIS CC
// Produced By: DataReel Software Development Team
// File Creation Date: 06/15/2003
// Date Last Modified: 01/09/2023
// Copyright (c) 2001-2024 DataReel Software Development
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

General-purpose encryption and decryption routines.                             
Encryption routes used encrypt/decrypt file buffers and memory buffers.         
Encryption routes used create password file hashes.                             
Encryption routes generate encryption certificates and authenticate users.
*/
// ----------------------------------------------------------- // 
#include "gxdlcode.h"

#include "cryptdb.h"
#include "gxcrc32.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <openssl/crypto.h>
#if defined (__WIN32__)
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

// 10/24/2026: HMAC context helpers for every supported OpenSSL version
static HMAC_CTX *cryptdb_hmac_new()
{
#if OPENSSL_VERSION_NUMBER < 0x101010bfL
  HMAC_CTX *ctx = new HMAC_CTX;
  HMAC_CTX_init(ctx);
  return ctx;
#else
  return HMAC_CTX_new();
#endif
}

static void cryptdb_hmac_free(HMAC_CTX *ctx)
{
  if(!ctx) return;
#if OPENSSL_VERSION_NUMBER < 0x101010bfL
  HMAC_CTX_cleanup(ctx);
  delete ctx;
#else
  HMAC_CTX_free(ctx);
#endif
}

FCryptCache::FCryptCache(unsigned CacheSize, unsigned size_of_static_data_area) : cache(CacheSize) 
{ 
  ready_for_writing = 1; 
  ready_for_reading = 1;
  cache.Connect(this); 
  buf_size = 1024;
  overwrite = 0;
  mode = 3;
  key_iterations =  AES_DEF_ITERATIONS;
  en_dot_ext = ".enc";
  bytes_wrote = (FAU_t)0;
  bytes_read = (FAU_t)0;
  crypt_stream = 1;
  ERROR_LEVEL = 0;
  static_data = new unsigned char[size_of_static_data_area];
  static_data_size = size_of_static_data_area;
  static_data_bytes_used = 0;
  num_static_data_blocks = 0;
  AES_fillrand(static_data, size_of_static_data_area);
  path_mode = CRYPT_PATH_RELATIVE;
  has_integrity = 0;
  integrity_ctx = 0;
  integrity_data_len = (FAU_t)0;
  integrity_plaintext_len = (FAU_t)0;
  header_offset = data_offset = (FAU_t)0;
  header_crypt_len = 0;
  memset(header_plain, 0, sizeof(header_plain));
  allow_unencrypted = 0;
}

FCryptCache::~FCryptCache()
{
  cryptdb_secret.Clear(1);
  
  if(static_data) {
    OPENSSL_cleanse(static_data, static_data_size);
    delete[] static_data;
  }
  static_data_size = 0;
  static_data = 0;
  cryptdb_hmac_free(integrity_ctx);
  integrity_ctx = 0;
  integrity.Wipe();
  OPENSSL_cleanse(header_plain, sizeof(header_plain));
  // Never leave a partial decrypted file behind
  if(!tmp_ofname.is_null()) {
    outfile.df_Close();
    futils_remove(tmp_ofname.c_str());
  }
}

static void cryptdb_put_le64(unsigned char out[8], FAU_t v)
{
  unsigned long long u = (unsigned long long)v;
  for(int i = 0; i < 8; i++) { out[i] = (unsigned char)(u & 0xFF); u >>= 8; }
}

static FAU_t cryptdb_get_le64(const unsigned char in[8])
{
  unsigned long long u = 0;
  for(int i = 7; i >= 0; i--) { u = (u << 8) | in[i]; }
  return (FAU_t)u;
}

void FCryptCache::IntegrityUpdate(const void *buf, unsigned len)
{
  if(!integrity_ctx || len == 0) return;
  if(!HMAC_Update(integrity_ctx, (const unsigned char *)buf, len)) {
    ERROR_LEVEL = -1;
    err << clear << "File integrity HMAC update failed";
  }
  integrity_data_len += len;
}

void FCryptCache::Read(void *buf, unsigned Bytes, gxDeviceTypes dev) 
{
  switch(dev) {
    case gxDEVICE_DISK_FILE:
      if(!infile) { 
	ERROR_LEVEL = -1;
	err << clear << filename << " file not ready for reading";
	ready_for_reading = 0; 
	return; 
      }
      else { 
	ready_for_reading = 1; 
      }
      infile.df_Read((char *)buf, Bytes);
      if(infile.df_GetError() != DiskFileB::df_NO_ERROR) {
	ERROR_LEVEL = -1;
	err << clear << "Fatal read error " << filename;
	ready_for_reading = 0; 
	return;
      }
      break;

    default:
      break;
  }
}

void FCryptCache::Write(const void *buf, unsigned Bytes, gxDeviceTypes dev) 
// 10/24/2026: Stop writing after the first error so no data that failed
// to decrypt or authenticate reaches the output, and check that the
// block fits in the work buffer before copying it.
{
  int rv = AES_NO_ERROR;
  char fbuf[AES_CIPHERTEXT_BUF_SIZE];
  unsigned buf_len;

  if(ERROR_LEVEL != 0) return;
  if(Bytes > (sizeof(fbuf) - AES_file_enctryption_overhead())) {
    ERROR_LEVEL = -1;
    err << clear << "File buf crypt error block too large";
    return;
  }

  aesdb.b.mode = mode;
  aesdb.b.key_iterations  = key_iterations;
  
  memmove(fbuf, buf, Bytes);
  if(crypt_stream) { // Encrypt the file buffer
    integrity_plaintext_len += Bytes;
    buf_len = Bytes;
    rv = aesdb.Encrypt(fbuf, &buf_len);
    Bytes = buf_len;
    if(rv == AES_NO_ERROR) IntegrityUpdate(fbuf, Bytes);
  }
  else { // Decrypt the file buffer
    IntegrityUpdate(fbuf, Bytes); // The file MAC covers the encrypted data
    buf_len = Bytes;
    rv = aesdb.Decrypt(fbuf, &buf_len);
    Bytes = buf_len;
    if(rv == AES_NO_ERROR) integrity_plaintext_len += Bytes;
  }

  if(rv != AES_NO_ERROR) {
    OPENSSL_cleanse(fbuf, sizeof(fbuf));
    ERROR_LEVEL = rv;
    err << clear << "File buf crypt error " << AES_err_string(rv);
    return;
  }
  if(ERROR_LEVEL != 0) {
    OPENSSL_cleanse(fbuf, sizeof(fbuf));
    return;
  }

  switch(dev) {
    case gxDEVICE_DISK_FILE:
      outfile.df_Write(fbuf, Bytes);
      if(outfile.df_GetError() != DiskFileB::df_NO_ERROR) {
	ERROR_LEVEL = -1;
	err << clear << "Fatal file buf write error " << ofname;
	break;
      } 
      bytes_wrote += Bytes;
      break;
    case gxDEVICE_CONSOLE:
      if(ofname == "stderr") {
	std::cerr.write((char *)fbuf, Bytes);
      }
      else {
	std::cout.write((char *)fbuf, Bytes);
      }
      bytes_wrote += Bytes;
    default:
      break;
  }
  OPENSSL_cleanse(fbuf, sizeof(fbuf));
}

int FCryptCache::EncryptFile(const char *fname, const MemoryBuffer &secret)
// 10/24/2026: The output file is removed if encryption fails, and a
// whole-file integrity record is written to the file header when done.
{
  err.Clear();
  filename.Clear();
  ofname.Clear();
  bytes_wrote = (FAU_t)0;
  bytes_read = (FAU_t)0;
  crypt_stream = 1;

  if(!cache) {
    ERROR_LEVEL = -1;
    err << clear << "No cache buffers available";
    cryptdb_secret.Clear(1);
    return 0;
  }
  if(secret.length() > AES_MAX_SECRET_LEN) {
    ERROR_LEVEL = -1;
    err << clear << "Secret is longer than " << AES_MAX_SECRET_LEN << " bytes";
    return 0;
  }

  if(!OpenInputFile(fname)) return 0;
  cryptdb_secret = secret; 
  if(!OpenOutputFile()) {
    cryptdb_secret.Clear(1);
    CloseInputFile();
    return 0;
  }
  
  memmove(aesdb.b.secret, secret.m_buf(), secret.length());
  aesdb.b.secret_len = secret.length();
  
  gxDeviceTypes o_device = gxDEVICE_DISK_FILE; // Output device
  gxDeviceTypes i_device = gxDEVICE_NULL;      // No input buffering

  // Setup a pointer to the cache buckets
  gxDeviceCachePtr p(cache, o_device, i_device); 
  int ok = LoadFile(p);  // Load the file into the cache 
  Flush(); // Ensure all the buckets a written to the output device
  if(ok && ERROR_LEVEL == 0 && bytes_read != infile.df_Length()) {
    ERROR_LEVEL = -1;
    err << clear << "Error reading " << filename;
    ok = 0;
  }
  if(ok && ERROR_LEVEL == 0) ok = WriteIntegrityHeader();

  cryptdb_secret.Clear(1);
  aesdb.Clear();
  CloseOutputFile();
  CloseInputFile();

  if(!ok || ERROR_LEVEL != 0) {
    if(ERROR_LEVEL == 0) ERROR_LEVEL = -1;
    if(err.is_null()) err << clear << "Error encrypting " << filename;
    futils_remove(ofname.c_str()); // Do not leave an incomplete file
    return 0;
  }

  return 1;
}

int FCryptCache::StartIntegrity()
// Start the whole-file HMAC using the key in the integrity record.
{
  cryptdb_hmac_free(integrity_ctx);
  integrity_ctx = cryptdb_hmac_new();
  integrity_data_len = integrity_plaintext_len = (FAU_t)0;
  if(!integrity_ctx) {
    ERROR_LEVEL = -1;
    err << clear << "File integrity HMAC init failed";
    return 0;
  }
  if(!HMAC_Init_ex(integrity_ctx, integrity.mac_key, sizeof(integrity.mac_key), EVP_sha256(), 0)) {
    ERROR_LEVEL = -1;
    err << clear << "File integrity HMAC init failed";
    return 0;
  }
  return 1;
}

static int cryptdb_integrity_final(HMAC_CTX *ctx, FAU_t data_len, FAU_t plaintext_len,
				   unsigned char mac[CRYPT_FILE_INTEGRITY_MAC_LEN])
// Finish the whole-file HMAC. The lengths are included so that the MAC
// also covers where the file ends.
{
  if(!ctx) return 0;
  unsigned char trailer[16];
  cryptdb_put_le64(trailer, data_len);
  cryptdb_put_le64(trailer+8, plaintext_len);
  unsigned mac_len = CRYPT_FILE_INTEGRITY_MAC_LEN;
  if(!HMAC_Update(ctx, trailer, sizeof(trailer))) return 0;
  if(!HMAC_Final(ctx, mac, &mac_len)) return 0;
  return mac_len == CRYPT_FILE_INTEGRITY_MAC_LEN;
}

int FCryptCache::WriteIntegrityHeader()
// Complete the integrity record and rewrite the encrypted file header in
// place. The header block has a fixed size, so nothing else moves.
{
  if(!integrity_ctx || !integrity.IsSet()) {
    ERROR_LEVEL = -1;
    err << clear << "File integrity record was not started";
    return 0;
  }
  if(!cryptdb_integrity_final(integrity_ctx, integrity_data_len, integrity_plaintext_len, integrity.file_mac)) {
    ERROR_LEVEL = -1;
    err << clear << "File integrity HMAC failed";
    return 0;
  }
  cryptdb_put_le64(integrity.data_len, integrity_data_len);
  cryptdb_put_le64(integrity.plaintext_len, integrity_plaintext_len);
  memmove(header_plain+sizeof(CryptFileHdr), &integrity, sizeof(integrity));

  char crypt_buf[AES_CIPHERTEXT_BUF_SIZE];
  memmove(crypt_buf, header_plain, AES_MAX_INPUT_BUF_LEN);
  unsigned len = AES_MAX_INPUT_BUF_LEN;
  int crypt_mode = (mode == 0) ? -1 : mode; // The header is always encrypted
  int rv = AES_Encrypt(crypt_buf, &len, cryptdb_secret.m_buf(), cryptdb_secret.length(), crypt_mode, key_iterations);
  OPENSSL_cleanse(header_plain, sizeof(header_plain));
  if(rv != AES_NO_ERROR || len != header_crypt_len) {
    OPENSSL_cleanse(crypt_buf, sizeof(crypt_buf));
    ERROR_LEVEL = -1;
    err << clear << "File header crypt error " << AES_err_string(rv);
    return 0;
  }

  outfile.df_Flush();
  if(outfile.df_Seek(header_offset) != DiskFileB::df_NO_ERROR) {
    ERROR_LEVEL = -1;
    err << clear << "Error seeking to header in " << ofname;
    return 0;
  }
  outfile.df_Write(crypt_buf, len);
  if(outfile.df_GetError() != DiskFileB::df_NO_ERROR || outfile.df_Flush() != DiskFileB::df_NO_ERROR) {
    ERROR_LEVEL = -1;
    err << clear << "Error writing header to file " << ofname;
    return 0;
  }
  return 1;
}

int FCryptCache::VerifyIntegrity()
// Check the whole-file HMAC and lengths after all blocks are decrypted.
{
  unsigned char mac[CRYPT_FILE_INTEGRITY_MAC_LEN];
  int ok = cryptdb_integrity_final(integrity_ctx, integrity_data_len, integrity_plaintext_len, mac);
  if(ok) ok = (CRYPTO_memcmp(mac, integrity.file_mac, sizeof(mac)) == 0);
  if(ok) ok = (integrity_data_len == cryptdb_get_le64(integrity.data_len));
  if(ok) ok = (integrity_plaintext_len == cryptdb_get_le64(integrity.plaintext_len));
  OPENSSL_cleanse(mac, sizeof(mac));
  if(!ok) {
    ERROR_LEVEL = -1;
    err << clear << "File integrity check failed, the encrypted file was modified, truncated or is incomplete";
  }
  return ok;
}

int FCryptCache::LoadFile(gxDeviceCachePtr p)
// Load a file from disk into the device cache.
{
  char read_buf[AES_PLAINTEXT_BUF_SIZE];
  
  unsigned read_len = AES_MAX_INPUT_BUF_LEN;
  if(crypt_stream == 0) read_len += AES_file_enctryption_overhead();

  while(!infile.df_EOF()) {
    if(infile.df_Read(read_buf, read_len) != DiskFileB::df_NO_ERROR) {
      if(infile.df_GetError() != DiskFileB::df_EOF_ERROR) {
	err << clear << "Fatal read error " << filename.c_str();
	ERROR_LEVEL = -1;
	return 0;
      }
    }
    p->Load(read_buf, infile.df_gcount());
    bytes_read += infile.df_gcount();
    if(ERROR_LEVEL != 0) break; // Stop at the first failed block
  }

  OPENSSL_cleanse(read_buf, sizeof(read_buf));
  return ERROR_LEVEL == 0;
}

int FCryptCache::OpenInputFile(const char *fname)
// Open the file if it exists. Returns false
// it the file cannot be opened or if it does
// not exist.
{
  if(!fname) {
    ERROR_LEVEL = -1;
    err << clear << "Null input file name";
    return 0;
  }
  filename.Clear();
  if(infile.df_Open(fname, DiskFileB::df_READONLY) != 
     DiskFileB::df_NO_ERROR) {
    ERROR_LEVEL = -1;
    err << clear << "Error opening " << fname;
    return 0;
  }
  filename = fname;
  if(infile.df_Length() == (FAU_t)0) {
    ERROR_LEVEL = -1;
    err << clear << "Zero file length " << fname;
    CloseInputFile();
    return 0;
  }
  return 1;
}

int FCryptCache::OpenOutputFile()
// Open the specified file for writing and truncate
// it. Returns false if the file cannot be opened.
{
  if(filename.is_null()) {
    ERROR_LEVEL = -1;
    err << clear << "No input file is open";
    return 0;
  }
  ofname = filename;
  
  if((ofname[ofname.length()-3] == '.') ||
     ofname[ofname.length()-4] == '.') {
    ofname.DeleteAfterLastIncluding(".");
  }

  ofname << en_dot_ext;

  if(!output_dir_name.is_null()) {
#if defined (__WIN32__) 
    futils_makeDOSpath(output_dir_name.c_str());
    if(output_dir_name[output_dir_name.length()-1] != '\\') {
      output_dir_name << '\\';
    }
    output_dir_name << ofname;
    ofname = output_dir_name;
    output_dir_name.DeleteAfterLastIncluding("\\");
#else
    if(output_dir_name[output_dir_name.length()-1] != '/') {
      output_dir_name << '/';
    }
    output_dir_name << ofname;
    ofname = output_dir_name;
    output_dir_name.DeleteAfterLastIncluding("/");
#endif

    // Check to see if the output DIR exists
    if(futils_exists(output_dir_name.c_str())) {
      if(!futils_isdirectory(output_dir_name.c_str())) {
	ERROR_LEVEL = -1;
	err << clear << "Output DIR is a file name " << output_dir_name;
	return 0;
      }
    }

    // If the output DIR does not exist try to make the DIR
    if(!futils_exists(output_dir_name.c_str())) {
      if(futils_mkdir(output_dir_name.c_str()) != 0) {
	ERROR_LEVEL = -1;
	err << clear << "Error making output DIR " << output_dir_name;
	return 0;
      }
    }
  }

  // If an output file name is specified override the file 
  // and DIR if specified
  if(!output_file_name.is_null()) {
    ofname << clear << output_file_name; 
  }

  int offset, i, rv;
  gxString sbuf;

  if(!overwrite) { // Find a unique name
    i = 0;
    if(futils_exists(ofname.c_str())) {
      offset = ofname.Find(".");
      if(offset == -1) {
	offset = ofname.length();
      }
      sbuf << clear << (++i);
      ofname.InsertAt(offset, sbuf);
      while(futils_exists(ofname.c_str())) {
	sbuf << clear << (++i);
	ofname.ReplaceAt(offset, sbuf);
	if(ofname[ofname.length()-4] != '.') ofname.InsertAt((ofname.length()-3), ".");   
      }
    }
  }

  // Setup the file header
  char enc_header[AES_MAX_INPUT_BUF_LEN];
  AES_fillrand((unsigned char *)enc_header, sizeof(enc_header));
 
  // Init the file header
  CryptFileHdr hdr;
  hdr.mode = mode;
  if(decrypted_output_filename.is_null()) decrypted_output_filename = filename;
  
  // 10/24/2026: The stored name was copied into the 256 byte fname field
  // with no length check. Names may continue into the reserved field,
  // which older versions also read back, but no further.
  hdr.name_len = decrypted_output_filename.length();
  if(hdr.name_len > MAX_STORED_FILENAME_LEN) {
    ERROR_LEVEL = -1;
    err << clear << "File name longer than " << MAX_STORED_FILENAME_LEN
	<< " bytes, use a shorter path or --decrypted-outfile";
    return 0;
  }
  memmove(enc_header, &hdr, sizeof(hdr));
  unsigned fname_offset = (unsigned)((char *)hdr.fname - (char *)&hdr);
  memmove(enc_header+fname_offset, decrypted_output_filename.GetSPtr(), hdr.name_len);

  // 10/24/2026: Add the whole-file integrity record after the header. The
  // file MAC and lengths are filled in when all data has been written.
  integrity.Wipe();
  memmove(integrity.magic, CRYPT_FILE_INTEGRITY_MAGIC, sizeof(integrity.magic));
  if(AES_fillrand(integrity.mac_key, sizeof(integrity.mac_key)) != (int)sizeof(integrity.mac_key)) {
    ERROR_LEVEL = -1;
    err << clear << "Random number generator failed";
    return 0;
  }
  memmove(enc_header+sizeof(CryptFileHdr), &integrity, sizeof(integrity));
  memmove(header_plain, enc_header, sizeof(enc_header));
  unsigned len = sizeof(enc_header);
  
  // Create a temp buffer to encrypt the file block with header
  char crypt_buf[AES_CIPHERTEXT_BUF_SIZE];
  memmove(crypt_buf, enc_header, sizeof(enc_header));
  OPENSSL_cleanse(enc_header, sizeof(enc_header));

  // If mode 0 is used for testing we will still encrypt the file header 
  int crypt_mode = (mode == 0) ? -1 : mode;
  
  rv =  AES_Encrypt(crypt_buf, &len, cryptdb_secret.m_buf(), cryptdb_secret.length(), crypt_mode, key_iterations);
  if(rv != AES_NO_ERROR) {
    ERROR_LEVEL = rv;
    err << clear << "File header crypt error " << AES_err_string(rv);
    return 0;
  }
  header_crypt_len = len;

  if(outfile.df_Create(ofname.c_str()) != DiskFileB::df_NO_ERROR) {
    ERROR_LEVEL = -1;
    err << clear << "Error opening " << ofname;
    return 0;
  }

  // Adding a static data area
  // Write the static data area to disk
  StaticDataHeader sd_header;
  sd_header.FormatHeader();
  sd_header.start_of_static_data = sizeof(sd_header);
  sd_header.static_area_len = static_data_size;

  outfile.df_Write(&sd_header, sizeof(sd_header));
  if(outfile.df_GetError() != DiskFileB::df_NO_ERROR) {
    ERROR_LEVEL = -1;
    err << clear << "Error writing static data header to file " << ofname;
    CloseOutputFile();
    return 0;
  } 
  bytes_wrote += sizeof(sd_header);

  outfile.df_Write(static_data, static_data_size);
  if(outfile.df_GetError() != DiskFileB::df_NO_ERROR) {
    ERROR_LEVEL = -1;
    err << clear << "Error writing static data area to file " << ofname;
    CloseOutputFile();
    return 0;
  } 
  bytes_wrote += static_data_size;
  
  // Adding a crypt file header with meta data
  // Write the crypt file header to disk
  header_offset = bytes_wrote;
  outfile.df_Write(crypt_buf, len);
  if(outfile.df_GetError() != DiskFileB::df_NO_ERROR) {
    ERROR_LEVEL = -1;
    err << clear << "Error writing header to file " << ofname;
    CloseOutputFile();
    return 0;
  } 
  bytes_wrote += len;

  return StartIntegrity();
}

int FCryptCache::TestVersion(CryptFileHdr hdr, gxUINT32 &version)
{
  err.Clear();
  
  // Select the correct file decrypt version
  switch((int)hdr.version) {
    case 2023102: // Previous version
      version = (gxUINT32)2023102;
      break;
    case 2023103: // Current version
      version = (gxUINT32)2023103;
      break;
    default:
      version = (gxUINT32)0;
      ERROR_LEVEL = -1;
      err << clear << "Bad file version";
      return 0;
  }

  return 1;
}

int FCryptCache::TestStaticDataHeader(const StaticDataHeader &sd_header_read)
{
  StaticDataHeader sd_header;
  sd_header.FormatHeader();

    if(sd_header_read.version != sd_header.version){
    ERROR_LEVEL = -1;
    err << clear << "Bad static data header version";
    return 0;
  }

  if(sd_header_read.start_checkword != sd_header.start_checkword){
    ERROR_LEVEL = -1;
    err << clear << "Bad static data header start checkword";
    return 0;
  }
  if(sd_header_read.end_checkword != sd_header.end_checkword){
    ERROR_LEVEL = -1;
    err << clear << "Bad static data header start checkword";
    return 0;
  }

  return 1;
}

int FCryptCache::DecryptFileHeader(CryptFileHdr &hdr, const char *fname, const MemoryBuffer &secret, gxUINT32 &version)
// 10/24/2026: Every length read from the file is checked before use, the
// stored file name is read from the decrypted header bounded by its
// length, and the whole-file integrity record is loaded if present.
{
  err.Clear();
  bytes_wrote = (FAU_t)0;
  bytes_read = (FAU_t)0;
  crypt_stream = 0;
  has_integrity = 0;
  stored_name.Clear();
  integrity.Wipe();
  cryptdb_hmac_free(integrity_ctx);
  integrity_ctx = 0;
  int rv;
  
  if(!cache) {
    ERROR_LEVEL = -1;
    err << clear << "No cache buffers available";
    cryptdb_secret.Clear(1);
    return 0;
  }
  if(secret.length() > AES_MAX_SECRET_LEN) {
    ERROR_LEVEL = -1;
    err << clear << "Secret is longer than " << AES_MAX_SECRET_LEN << " bytes";
    return 0;
  }

  cryptdb_secret = secret; 
  if(!OpenInputFile(fname)) return 0;

  // Read the static data area
  StaticDataHeader sd_header_read;
  sd_header_read.WipeHeader();

  if(infile.df_Read(&sd_header_read, sizeof(sd_header_read)) != DiskFileB::df_NO_ERROR) {
    ERROR_LEVEL = -1;
    err << clear << "Error reading static data area header";
    return 0;
  }
  if(infile.df_gcount() != sizeof(sd_header_read)) {
    ERROR_LEVEL = -1;
    err << clear << "Error reading file static data header";
    return 0;
  }

  if(!TestStaticDataHeader(sd_header_read)) return 0;
  if(!CheckStaticDataHeader(sd_header_read, infile.df_Length())) return 0;
  
  if(infile.df_Seek(sd_header_read.start_of_static_data) != DiskFileB::df_NO_ERROR) {
    ERROR_LEVEL = -1;
    err << clear << "File seek Error reading file static data area";
    return 0;
  }

  if(infile.df_Read(static_data, sd_header_read.static_area_len) != 
     DiskFileB::df_NO_ERROR) {
    ERROR_LEVEL = -1;
    err << clear << "Error reading file static data area";
    return 0;
  }

  if(infile.df_gcount() != sd_header_read.static_area_len) {
    ERROR_LEVEL = -1;
    err << clear << "Error reading file static data area";
    return 0;
  }
  
  memmove(aesdb.b.secret, secret.m_buf(), secret.length());
  aesdb.b.secret_len = secret.length();
    
  // Read the encrypted file header. Every version writes a 768 byte
  // header block, which is a fixed size once encrypted.
  unsigned read_len = AES_MAX_INPUT_BUF_LEN + AES_file_enctryption_overhead();
  char crypt_buf[AES_CIPHERTEXT_BUF_SIZE];
  header_offset = (FAU_t)sd_header_read.start_of_static_data + sd_header_read.static_area_len;

  CryptFileHdr null_hdr;
  if(infile.df_Read(crypt_buf, read_len) != 
     DiskFileB::df_NO_ERROR) {
    ERROR_LEVEL = -1;
    err << clear << "Error reading file header";
    return 0;
  }
  unsigned len = infile.df_gcount();
  if(len != read_len) {
    ERROR_LEVEL = -1;
    err << clear << "Incomplete or corrupt file";
    return 0;
  }
  data_offset = header_offset + read_len;

  rv =  AES_Decrypt(crypt_buf, &len, cryptdb_secret.m_buf(), cryptdb_secret.length(), mode, key_iterations);
  if(rv != AES_NO_ERROR) {
    OPENSSL_cleanse(crypt_buf, sizeof(crypt_buf));
    ERROR_LEVEL = -1;
    err << clear << "Decrypt file header error " << " " << AES_err_string(rv);
    return 0;
  }
  if(len != AES_MAX_INPUT_BUF_LEN) {
    OPENSSL_cleanse(crypt_buf, sizeof(crypt_buf));
    ERROR_LEVEL = -1;
    err << clear << "Invalid file header";
    return 0;
  }
  memmove(&hdr, crypt_buf, sizeof(hdr));

  if(hdr.checkword != null_hdr.checkword) {
    OPENSSL_cleanse(crypt_buf, sizeof(crypt_buf));
    ERROR_LEVEL = -1;
    err << clear << "Corrupt file bad checkword";
    return 0;
  }

  // Select the correct file decrypt version
  if(!TestVersion(hdr, version)) {
    OPENSSL_cleanse(crypt_buf, sizeof(crypt_buf));
    return 0;
  }
  
  if(hdr.name_len > MAX_STORED_FILENAME_LEN) {
    OPENSSL_cleanse(crypt_buf, sizeof(crypt_buf));
    ERROR_LEVEL = -1;
    err << clear << "Invalid file header";
    return 0;
  }
  unsigned fname_offset = (unsigned)((char *)hdr.fname - (char *)&hdr);
  if(hdr.name_len > 0) stored_name.SetString(crypt_buf+fname_offset, hdr.name_len);

  // Load the whole-file integrity record. Files from versions before
  // 10/24/2026 have random bytes here and are decrypted without it.
  memmove(&integrity, crypt_buf+sizeof(CryptFileHdr), sizeof(integrity));
  if(integrity.IsSet()) {
    has_integrity = 1;
    if((infile.df_Length() < data_offset) ||
       ((infile.df_Length() - data_offset) != cryptdb_get_le64(integrity.data_len))) {
      OPENSSL_cleanse(crypt_buf, sizeof(crypt_buf));
      ERROR_LEVEL = -1;
      err << clear << "File integrity check failed, the encrypted file was truncated or extended";
      return 0;
    }
  }
  else {
    integrity.Wipe();
  }
  OPENSSL_cleanse(crypt_buf, sizeof(crypt_buf));

  mode = hdr.mode;
 
  return 1;
}

int FCryptCache::CheckStaticDataHeader(const StaticDataHeader &sd_header_read, FAU_t file_length)
// 10/24/2026: Check the static data area bounds before reading it and
// size the in memory copy to match. A negative file length skips the
// file length check.
{
  if((sd_header_read.static_area_len < MIN_STATIC_DATA_AREA_SIZE) ||
     (sd_header_read.static_area_len > MAX_STATIC_DATA_AREA_SIZE) ||
     ((unsigned)sd_header_read.start_of_static_data < (unsigned)sizeof(StaticDataHeader)) ||
     (sd_header_read.start_of_static_data > MAX_STATIC_DATA_AREA_SIZE) ||
     ((file_length >= (FAU_t)0) &&
      (((FAU_t)(unsigned)sd_header_read.start_of_static_data + (FAU_t)(unsigned)sd_header_read.static_area_len) > file_length))) {
    ERROR_LEVEL = -1;
    err << clear << "Invalid static data area header";
    return 0;
  }

  if(sd_header_read.static_area_len != static_data_size) {
    if(static_data) {
      OPENSSL_cleanse(static_data, static_data_size);
      delete[] static_data;
    }
    static_data_size = sd_header_read.static_area_len;
    static_data = new unsigned char[static_data_size];
  }
  return 1;
}

int FCryptCache::DecryptFile(const char *fname, const MemoryBuffer &secret, gxUINT32 &version, char *outfile_name)
// 10/24/2026: The output path comes from the caller or from the stored
// name made safe by cryptdb_make_restore_path(). Decrypted data goes to
// a temp file that is renamed only after every block and the whole-file
// integrity check pass, and existing files are kept unless overwrite is
// set.
{
  filename.Clear();
  ofname.Clear();
  gxDeviceTypes o_device = gxDEVICE_DISK_FILE; // Output device
  gxDeviceTypes i_device = gxDEVICE_NULL;      // No input buffering

  CryptFileHdr hdr;
  if(!DecryptFileHeader(hdr, fname, secret, version)) {
    cryptdb_secret.Clear(1);
    CloseInputFile();
    return 0;
  }

  if(hdr.mode == 0 && !allow_unencrypted) {
    ERROR_LEVEL = -1;
    err << clear << "File data is not encrypted (mode 0), use --allow-unencrypted to decrypt it";
    cryptdb_secret.Clear(1);
    CloseInputFile();
    return 0;
  }
  
  gxString sbuf;
  int use_output_dir = 1;
  if(outfile_name) { // The caller has specified and output file
    sbuf << clear << outfile_name;
    if(sbuf == "stdout" || sbuf == "stderr") {
      ofname << clear << sbuf;
      o_device = gxDEVICE_CONSOLE;
    }
    else {
      ofname << clear << outfile_name;
    }
  }
  else if(stored_name == "stdout" || stored_name == "stderr") {
    // Set with fcrypt --decrypted-outfile=stdout
    ofname << clear << stored_name;
    o_device = gxDEVICE_CONSOLE;
  }
  else { 
    if(!cryptdb_make_restore_path(stored_name, path_mode, ofname, err)) {
      ERROR_LEVEL = -1;
      cryptdb_secret.Clear(1);
      CloseInputFile();
      return 0;
    }
    if(path_mode == CRYPT_PATH_ABSOLUTE) use_output_dir = 0;
  }
  
  if(!output_dir_name.is_null() && o_device == gxDEVICE_DISK_FILE && use_output_dir) {
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

  if(o_device == gxDEVICE_DISK_FILE) {
    if(!OpenDecryptOutputFile()) {
      cryptdb_secret.Clear(1);
      CloseInputFile();
      return 0;
    }
  }

  if(has_integrity && !StartIntegrity()) {
    FinishDecryptOutputFile(0);
    cryptdb_secret.Clear(1);
    CloseInputFile();
    return 0;
  }

  // Setup a pointer to the cache buckets
  gxDeviceCachePtr p(cache, o_device, i_device); 
  int ok = LoadFile(p);  // Load the file into the cache 
  Flush(); // Ensure all the buckets a written to the output device
  if(ok && ERROR_LEVEL == 0 && has_integrity) ok = VerifyIntegrity();
  if(ERROR_LEVEL != 0) ok = 0;

  cryptdb_secret.Clear(1);
  aesdb.Clear();
  CloseInputFile();
  if(o_device == gxDEVICE_DISK_FILE) ok = FinishDecryptOutputFile(ok);

  if(!ok) {
    if(ERROR_LEVEL == 0) ERROR_LEVEL = -1;
    if(err.is_null()) err << clear << "Error decrypting " << filename;
    return 0;
  }
  return 1;
}

int FCryptCache::OpenDecryptOutputFile()
// Create a private temp file next to the output file.
{
  if(futils_exists(ofname.c_str())) {
    if(futils_isdirectory(ofname.c_str())) {
      ERROR_LEVEL = -1;
      err << clear << "Output file " << ofname << " is a directory";
      return 0;
    }
    if(!overwrite) {
      ERROR_LEVEL = -1;
      err << clear << "Output file " << ofname << " exists, use -o to overwrite";
      return 0;
    }
  }

  // Make the parent directories if needed
  gxString dir = ofname;
  int sep = -1;
  for(int i = (int)dir.length()-1; i >= 0; i--) {
    if(dir[i] == '/' || dir[i] == '\\') { sep = i; break; }
  }
  if(sep > 0) {
    dir.DeleteAt(sep, dir.length()-sep);
    if(!futils_exists(dir.c_str())) {
      if(!cryptdb_makedirs(dir)) {
	ERROR_LEVEL = -1;
	err << clear << "Error making DIR " << dir;
	return 0;
      }
    }
    else if(!futils_isdirectory(dir.c_str())) {
      ERROR_LEVEL = -1;
      err << clear << "Output DIR is a file name " << dir;
      return 0;
    }
  }

  unsigned char rnd[8];
  if(AES_fillrand(rnd, sizeof(rnd)) != (int)sizeof(rnd)) {
    ERROR_LEVEL = -1;
    err << clear << "Random number generator failed";
    return 0;
  }
  const char *hex = "0123456789abcdef";
  gxString tmp = ofname;
  tmp << ".fdecrypt_";
  for(unsigned i = 0; i < sizeof(rnd); i++) {
    tmp << hex[(rnd[i] >> 4) & 0xF] << hex[rnd[i] & 0xF];
  }
  tmp << ".tmp";

  if(!cryptdb_create_private_file(tmp.c_str())) {
    ERROR_LEVEL = -1;
    err << clear << "Error creating " << tmp;
    return 0;
  }
  tmp_ofname = tmp;
  if(outfile.df_Open(tmp.c_str(), DiskFileB::df_READWRITE) != DiskFileB::df_NO_ERROR) {
    FinishDecryptOutputFile(0);
    ERROR_LEVEL = -1;
    err << clear << "Error opening " << tmp;
    return 0;
  }
  return 1;
}

int FCryptCache::FinishDecryptOutputFile(int ok)
// Move the temp file to the output file if ok, otherwise remove it.
{
  if(tmp_ofname.is_null()) return ok;
  if(outfile.df_Flush() != DiskFileB::df_NO_ERROR) ok = 0;
  CloseOutputFile();
  if(ok) {
    if(!cryptdb_rename_file(tmp_ofname.c_str(), ofname.c_str(), overwrite)) {
      ERROR_LEVEL = -1;
      if(!overwrite && futils_exists(ofname.c_str())) {
	err << clear << "Output file " << ofname << " exists, use -o to overwrite";
      }
      else {
	err << clear << "Error renaming " << tmp_ofname << " to " << ofname;
      }
      ok = 0;
    }
  }
  if(!ok) futils_remove(tmp_ofname.c_str());
  tmp_ofname.Clear();
  return ok;
}

int FCryptCache::DecryptOnlyTheFileName(const char *fname, const MemoryBuffer &secret,
					gxUINT32 &version, gxString &crypt_file_name)
{

  filename.Clear();
  ofname.Clear();
  
  crypt_file_name.Clear();

  CryptFileHdr hdr;
  if(!DecryptFileHeader(hdr, fname, secret, version)) {
    CloseInputFile();
    return 0;
  }

  // Set the unencrypted file name
  crypt_file_name = stored_name;

  CloseInputFile();
  return 1;
}

int cryptdb_makedirs(const gxString &path)
// 10/24/2026: Make a directory and any missing parent directories.
// Returns true if the directory exists when done.
{
  gxString p = path;
  gxString dir;
  for(unsigned i = 0; i < p.length(); i++) {
    char c = p[i];
    if((c == '/' || c == '\\') && i > 0) {
      dir.SetString(p.c_str(), i);
#if defined (__WIN32__)
      if(dir.length() == 2 && dir[1] == ':') continue; // Drive letter
#endif
      if(!futils_exists(dir.c_str())) futils_mkdir(dir.c_str());
    }
  }
  if(!futils_exists(p.c_str())) futils_mkdir(p.c_str());
  return futils_isdirectory(p.c_str());
}

int cryptdb_make_restore_path(const gxString &stored_name, int path_mode,
			      gxString &path, gxString &err)
// 10/24/2026: Make the output path for a file name stored in an encrypted
// file. The stored name is not trusted, so by default it is restored
// relative to the current or output directory:
//
// CRYPT_PATH_RELATIVE: Drive letters, UNC prefixes and leading path
// separators are removed, so the stored DIR tree is recreated under the
// current or output DIR. Names with .. components are rejected.
// CRYPT_PATH_ABSOLUTE: The stored name is used as is, for full restores.
// CRYPT_PATH_NONE: Only the base file name is used.
//
// Both / and \ are treated as path separators on all systems, so files
// encrypted on Windows restore the same way on Linux and the other way
// around.
{
  path.Clear();
  if(stored_name.is_null() || strlen(stored_name.c_str()) != stored_name.length()) {
    err << clear << "Invalid file name stored in encrypted file";
    return 0;
  }

#if defined (__WIN32__) 
  const char sepc = '\\';
#else
  const char sepc = '/';
#endif

  if(path_mode == CRYPT_PATH_ABSOLUTE) {
    path = stored_name;
#if defined (__WIN32__) 
    futils_makeDOSpath(path.c_str());
#endif
    return 1;
  }

  gxString name = stored_name;
  unsigned i;
  for(i = 0; i < name.length(); i++) {
    if(name[i] == '\\') name[i] = '/';
  }

  // Remove \\?\ and \\.\ device prefixes, drive letters and leading seps
  if(name.length() >= 4 && name[0] == '/' && name[1] == '/' &&
     (name[2] == '?' || name[2] == '.') && name[3] == '/') {
    name.DeleteAt(0, 4);
  }
  if(name.length() >= 2 && name[1] == ':' &&
     ((name[0] >= 'a' && name[0] <= 'z') || (name[0] >= 'A' && name[0] <= 'Z'))) {
    name.DeleteAt(0, 2);
  }

  // Split into path components
  gxList<gxString> parts;
  gxString part;
  int num_parts = 0;
  for(i = 0; i <= name.length(); i++) {
    if(i == name.length() || name[i] == '/') {
      if(!part.is_null() && part != ".") {
	if(part == ".." && path_mode != CRYPT_PATH_NONE) {
	  err << clear << "Stored file name " << stored_name
	      << " has .. in its path, use --no-path or --absolute-path to restore it";
	  return 0;
	}
#if defined (__WIN32__) 
	// Reject drive letters and alternate data streams inside the path
	if(part.Find(":") != -1) {
	  err << clear << "Stored file name " << stored_name << " is not a valid Windows path";
	  return 0;
	}
#endif
	parts.Add(part);
	num_parts++;
      }
      part.Clear();
    }
    else {
      part << name[i];
    }
  }
  if(num_parts == 0) {
    err << clear << "Invalid file name stored in encrypted file";
    return 0;
  }

  gxListNode<gxString> *ptr = parts.GetHead();
  if(path_mode == CRYPT_PATH_NONE) {
    if(parts.GetTail()->data == "..") {
      err << clear << "Invalid file name stored in encrypted file";
      return 0;
    }
    path = parts.GetTail()->data;
    return 1;
  }
  while(ptr) {
    if(!path.is_null()) path << sepc;
    path << ptr->data;
    ptr = ptr->next;
  }
  return 1;
}

int cryptdb_create_private_file(const char *fname)
// 10/24/2026: Create a new empty file that only the owner can read and
// write. Fails if the file already exists, and never follows a symlink.
{
#if defined (__WIN32__)
  int fd = _open(fname, _O_CREAT | _O_EXCL | _O_WRONLY | _O_BINARY, _S_IREAD | _S_IWRITE);
  if(fd < 0) return 0;
  _close(fd);
#else
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
  int fd = open(fname, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, S_IRUSR | S_IWUSR);
  if(fd < 0) return 0;
  close(fd);
#endif
  return 1;
}

int cryptdb_rename_file(const char *from, const char *to, int overwrite)
// 10/24/2026: Rename a file. Unless overwrite is set the rename fails if
// the destination exists, including one created after it was checked.
{
#if defined (__WIN32__)
  DWORD flags = MOVEFILE_COPY_ALLOWED | MOVEFILE_WRITE_THROUGH;
  if(overwrite) flags |= MOVEFILE_REPLACE_EXISTING;
  return MoveFileExA(from, to, flags) != 0;
#else
  if(overwrite) return rename(from, to) == 0;
  if(link(from, to) == 0) {
    unlink(from);
    return 1;
  }
  if(errno == EEXIST) return 0;
  // File systems without hard links
  if(futils_exists(to)) return 0;
  return rename(from, to) == 0;
#endif
}

int cryptdb_gethomedir(gxString &home_dir)
{
  home_dir.Clear(); // Null the string

  // Check the environment for the users home directory
  if(getenv("HOME")) {
    home_dir = getenv("HOME");
    if(home_dir == "") return 0;
    if(home_dir[home_dir.length()-1] == '/') {
      home_dir.DeleteAt((home_dir.length()-1), 1);
    }
    return 1;
  }

  // Check for lower case HOME variables
  if(getenv("home")) {
    home_dir = getenv("home");
    if(home_dir == "") return 0;
    if(home_dir[home_dir.length()-1] == '/') {
      home_dir.DeleteAt((home_dir.length()-1), 1);
    }
    return 1;
  }

  return 0; // Could not find home directory
}

int cryptdb_makeabspath(gxString &path)
{
  gxString path_sep;
  char path_sepc;

#if defined (__WIN32__)
  path_sep = "\\";
  path_sepc = '\\';
#else // Assume UNIX style path
  path_sep = "/";
  path_sepc = '/';
#endif

  // Keep all paths consistant for each operating system
#if defined (__WIN32__)
  futils_makeDOSpath(path.c_str());
#else // Assume UNIX style path
  futils_makeUNIXpath(path.c_str());
#endif

#ifdef __UNIX__
  // Accept ~/ path names under UNIX
  if(path.length() >= 2) {
    if(path[0] == '~') {
      if(path[1] == '/') {
	gxString home_dir;
	if(!cryptdb_gethomedir(home_dir)) return 0;
	path.DeleteAt(0, 2);
	path.InsertAt(0, "/", 1);
	path.InsertAt(0, home_dir);
      }
    }
  }
#endif

  gxString curr_dir;
  int is_abs_path = 0;
  char pwd[futils_MAX_DIR_LENGTH];
  if(futils_getcwd(pwd, futils_MAX_DIR_LENGTH) == 0) {
    curr_dir = pwd;
  }
  else {
    return 0;
  }

  if(path.is_null()) {
    path = pwd;
    return 1;
  }

  char new_path[futils_MAX_PATH_LENGTH];

#if defined (__WIN32__)
  futils_makeDOSpath(path.c_str());

  // Check for drive letters paths without a trailing path sep
  if(path.length() >= 2) {

    if(path[1] == ':') {
      if(path.length() == 2) {
	path += path_sep;
      }
      return 1;
    }
  }
#endif
  
  // Check for leading path seps
  if(path[0] == path_sepc) {
    is_abs_path = 1;
  }
  
  // Check for leading dots
  if(!is_abs_path) {
    if(path[0] == '.') {
      path.InsertAt(0, path_sep);
      path.InsertAt(0, curr_dir);
      is_abs_path = 1;
    }
  }

  // Check for DIR names with no path seps of leading dots
  if(!is_abs_path) {
    if(path[0] != path_sepc) {
      if(path[0] != '.') {
	path.InsertAt(0, path_sep);
	path.InsertAt(0, curr_dir);
      }
    }
  }

  // Collapse directory names containing .. path separators
  futils_pathsimplify(path.c_str(), new_path, path_sepc); 
  path << clear << new_path;
  if(path.is_null()) path = path_sep;

#if defined (__WIN32__)
  // Check for drive letters paths without a trailing path sep
  if(path.length() == 2) {
    if(path[1] == ':') {
      path += path_sep;
    }
  }
#endif

  return 1;
} 

int cryptdb_buildfilelist(gxString &path, gxString &err, 
			  gxList<gxString> &file_list,
			  gxList<gxString> &dir_list, 
			  int &num_files, int &num_dirs)
{
#if defined __WIN32__
  gxString path_sep("\\");
#else
  gxString path_sep("/");
#endif

  char pwd[futils_MAX_DIR_LENGTH];
  if(futils_getcwd(pwd, futils_MAX_DIR_LENGTH) != 0) {
    err << clear << "Error setting present working DIR";
    return 0;
  }

  err.Clear();
  gxString fname, dname;
  DIR* dirp;
  dirent* direntp;
  dirp = futils_opendir(path.c_str());
  num_files = num_dirs = 0;

  if(dirp == NULL) {
    err << clear << "Error opening " << path;
    return 0;
  } 
  else {
    for(;;) {
      dirent entry;
      direntp = futils_readdir(dirp, &entry);
      if(direntp == NULL) break; 
      if((strcmp(direntp->d_name, ".") == 0) || 
	 (strcmp(direntp->d_name, "..") == 0)) {
	continue;
      }
      if(futils_isdirectory(direntp->d_name)) {
	num_dirs++;
	dname << clear << path << path_sep << direntp->d_name;
	dir_list.Insert(dname);
      }
      else {
	num_files++;
	fname << clear << path << path_sep << direntp->d_name;
	file_list.Add(fname);
      }

    }
    futils_closedir(dirp); 
  }

  if(futils_chdir(pwd) != 0) {
    err << clear << "Error resetting previous working DIR";
    return 0;
  }

  return 1;
}

int cryptdb_getdircontents(gxString &path, gxString &err, 
			   gxList<gxString> &file_list,
			   int &num_files, int &num_dirs)
{
  gxList<gxString> dir_list;
  int tf, td;

  tf = td = 0;
  if(!cryptdb_buildfilelist(path, err, file_list, dir_list, tf, td)) {
    return 0;
  }

  gxString curr_dir;
  num_files += tf;
  num_dirs += td;
  while(!dir_list.IsEmpty()) {
    if(!dir_list.Extract(curr_dir)) break;
    if(!cryptdb_buildfilelist(curr_dir, err, file_list, dir_list, tf, td)) {
      return 0;
    }
    num_files += tf;
    num_dirs += td;
  }
  return 1;
}

int read_key_file(const char *fname, MemoryBuffer &key, gxString &err, int expected_key_len)
// Read in key file contents to key object and return in reference. 
{
  key.Clear(1);
  
  FILE *fp;
  fp = fopen(fname, "rb");
  if(!fp) {
    err << clear << "Error opening key file " << fname;
    return -1;
  }

  char read_buf[1024];
  unsigned input_bytes_read = 0;
  
  while(!feof(fp)) {
    memset(read_buf, 0, sizeof(read_buf));
    input_bytes_read = fread((unsigned char *)read_buf, 1, sizeof(read_buf), fp);
    if(input_bytes_read < 0) {
      fclose(fp);
      err << clear << "Error reading from key file " << fname;
      return -1;
    }
    key.Cat(read_buf, input_bytes_read);
  }
  
  memset(read_buf, 0, sizeof(read_buf));  
  fclose(fp);

  if(key.length() > AES_MAX_SECRET_LEN) {
    err << clear << "Input key length long. Max key length is " << AES_MAX_SECRET_LEN << " input key len is " << key.length();
    key.Clear(1);
    return -1;
  }

  
  if(expected_key_len > 0) {
    if(expected_key_len < key.length()) {
      err << clear << "Bad input key length " << " expecting " << expected_key_len << " input key len is " << key.length();
      key.Clear(1);
      return -1;
    }
  }
  
  return 0;
}

int FCryptCache::WriteStaticDataAreaToFile(const char *fname)
{
  ERROR_LEVEL = 0;
  FILE *fp;
  fp = fopen(fname, "rb+");
  if(!fp) {
    ERROR_LEVEL = -1;
    err << clear << "Error opening file " << fname;
    return 0;
  }
  
  rewind(fp);

  StaticDataHeader sd_header_read;
  sd_header_read.FormatHeader();

  unsigned num_bytes_read = fread((void*)&sd_header_read, sizeof(unsigned char), sizeof(sd_header_read), fp);
  if(num_bytes_read != sizeof(sd_header_read)) {
    ERROR_LEVEL = -1;
    err << clear << "Error reading static data header from file " << fname;
    fclose(fp);
    return 0;
  }

  if(!TestStaticDataHeader(sd_header_read)) {
    fclose(fp);
    return 0;
  }

  // 10/24/2026: The area in the file must be the size of the area in memory
  if(sd_header_read.static_area_len != static_data_size) {
    ERROR_LEVEL = -1;
    err << clear << "Static data area size does not match " << fname;
    fclose(fp);
    return 0;
  }

  if(fseek(fp, sd_header_read.start_of_static_data, SEEK_SET) != 0) {
    ERROR_LEVEL = -1;
    err << clear << "Error seeking to static data start " << fname;
    fclose(fp);
    return 0;
  }
  
  unsigned num_bytes = fwrite((const void*)static_data, sizeof(unsigned char), sd_header_read.static_area_len, fp);
  if(num_bytes != sd_header_read.static_area_len) {
    ERROR_LEVEL = -1;
    err << clear << "Error writing static data to file " << fname;
    fclose(fp);
    return 0;
  }

  fclose(fp);
  
  return 1;
}

int FCryptCache::UpdateStaticData()
{
  ERROR_LEVEL = 0;
  gxListNode<StaticDataBlock> *ptr = static_block_list.GetHead();
  unsigned offset = 0;
  MemoryBuffer mbuf;
  StaticDataBlockHdr static_data_block_header;
  
  if(!ptr) return 1;

  AES_fillrand(static_data, static_data_size);
  
  offset = 0;
  while(ptr) {
    mbuf.Clear(1);
    mbuf.Cat(&ptr->data.block_header, sizeof(static_data_block_header));
    mbuf.Cat(ptr->data.rsa_ciphertext.m_buf(), ptr->data.rsa_ciphertext.length());
    mbuf.Cat(ptr->data.hmac.m_buf(), ptr->data.hmac.length());
    mbuf.Cat(ptr->data.username_encoded.c_str(), ptr->data.username_encoded.length());
    if((static_data_size < mbuf.length()) || (offset > (static_data_size - mbuf.length()))) {
      ERROR_LEVEL = -1;
      err << clear << "Out of free space in static data area";
      mbuf.Clear(1);
      return 0;
    }
    memmove(static_data+offset, mbuf.m_buf(), mbuf.length());
    offset += mbuf.length();
    ptr = ptr->next;
  }

  mbuf.Clear(1);
  return 1;
}

int FCryptCache::LoadStaticDataBlocks(const char *fname)
{
  ERROR_LEVEL = 0;
  FILE *fp;
  fp = fopen(fname, "rb");
  if(!fp) {
    ERROR_LEVEL = -1;
    err << clear << "Error opening encrypted file " << fname;
    return 0;
  }

    StaticDataHeader sd_header_read;
    sd_header_read.FormatHeader();

  unsigned num_bytes_read = fread((void*)&sd_header_read, sizeof(unsigned char), sizeof(sd_header_read), fp);
  if(num_bytes_read != sizeof(sd_header_read)) {
    ERROR_LEVEL = -1;
    err << clear << "Error reading static data header from file " << fname;
    fclose(fp);
    return 0;
  }

  if(!TestStaticDataHeader(sd_header_read)) {
    fclose(fp);
    return 0;
  }

  // The file read below checks that the area is all there
  if(!CheckStaticDataHeader(sd_header_read, (FAU_t)-1)) {
    fclose(fp);
    return 0;
  }
  
  if(fseek(fp, sd_header_read.start_of_static_data, SEEK_SET) != 0) {
    ERROR_LEVEL = -1;
    err << clear << "Error seeking to static data start " << fname;
    fclose(fp);
    return 0;
  }
  
  unsigned input_bytes_read = fread(static_data, 1, sd_header_read.static_area_len, fp);
  fclose(fp);

  if(input_bytes_read != sd_header_read.static_area_len) {
    ERROR_LEVEL = -1;
    err << clear << "Error reading static data area from file " << fname;
    return 0;
  }

  return LoadStaticDataBlocks();
}

int FCryptCache::LoadStaticDataBlocks()
// 10/24/2026: The static data area is not authenticated, so every length
// read from it is checked against the space left in the area and the
// size of the buffer it is copied to. Older versions copied username_len
// bytes into a 1024 byte stack buffer and read ciphertext_len bytes past
// the end of the area.
{
  ERROR_LEVEL = 0;
  StaticDataBlockHdr static_data_block_header;
  StaticDataBlock static_data_block;
  const unsigned hdr_len = sizeof(static_data_block_header);
  const unsigned max_ciphertext_len = 8192;
  unsigned block_offset = 0;
  unsigned offset = 0;
  char username_buf[1024];
  char username[1024];
  
  num_static_data_blocks = 0;
  static_data_bytes_used = 0;
  static_block_list.Clear();

  if(!static_data) return 1;

  for(;;) {
    // Find the next block header
    int found_block = 0;
    for(block_offset = offset; (static_data_size >= hdr_len) && (block_offset <= (static_data_size - hdr_len)); block_offset += hdr_len) {
      static_data_block_header.WipeHeader(); // Clear all existing header data before read
      memmove(&static_data_block_header, static_data+block_offset, hdr_len);
      if((static_data_block_header.version == STATIC_DATA_BLOCK_VERSION) && (static_data_block_header.checkword == 0xFEFE)) {
	found_block = 1;
	break;
      }
    }
    if(!found_block) break;

    unsigned pos = block_offset + hdr_len;
    unsigned remaining = static_data_size - pos;
    unsigned ciphertext_len = static_data_block_header.ciphertext_len;
    unsigned username_len = static_data_block_header.username_len;
    if((ciphertext_len > max_ciphertext_len) || (ciphertext_len > remaining) ||
       (AES_MAX_HMAC_LEN > (remaining - ciphertext_len)) ||
       (username_len >= sizeof(username_buf)) ||
       (username_len > (remaining - ciphertext_len - AES_MAX_HMAC_LEN))) {
      ERROR_LEVEL = -1;
      err << clear << "Invalid block in static data area";
      static_block_list.Clear();
      num_static_data_blocks = 0;
      OPENSSL_cleanse(username_buf, sizeof(username_buf));
      OPENSSL_cleanse(username, sizeof(username));
      return 0;
    }

    num_static_data_blocks++;
    static_data_block.Wipe();
    static_data_block.block_header = static_data_block_header;
    static_data_block.rsa_ciphertext.Cat(static_data+pos, ciphertext_len);
    pos += ciphertext_len;
    static_data_block.hmac.Cat(static_data+pos, AES_MAX_HMAC_LEN);
    pos += AES_MAX_HMAC_LEN;
    memset(username_buf, 0, sizeof(username_buf));
    memset(username, 0, sizeof(username));
    if(username_len > 0) {
      memmove(username_buf, static_data+pos, username_len);
      static_data_block.username_encoded = username_buf;
      // The decoded name is never longer than the encoded name
      gxsBase64Decode(username_buf, username);
      username[sizeof(username)-1] = 0;
      static_data_block.username = username;
    }
    pos += username_len;
    static_block_list.Add(static_data_block);
    offset = pos;
  }

  static_data_bytes_used = (num_static_data_blocks == 0) ? 0 : offset;
  OPENSSL_cleanse(username_buf, sizeof(username_buf));
  OPENSSL_cleanse(username, sizeof(username));
  return 1;
}

int FCryptCache::AddRSAKeyToStaticArea(const char *fname, const MemoryBuffer &secret,
				       char public_key[], unsigned public_key_len,
				       const char *rsa_key_username, char *passphrase)
{
  gxString sbuf;
  gxUINT32 version;
  StaticDataBlockHdr static_data_block_header;
  char username_buf[1024];
  unsigned char rsa_ciphertext[8192];
  unsigned rsa_ciphertext_len;
  int rv;

  // 12/07/2023 - Bug fix for seg fault if file does not exist
  if(!futils_exists(fname) || !futils_isfile(fname)) {
    ERROR_LEVEL = -1;
    err << clear << "ERROR: Encrypted file " << fname << " does not exist or cannot be read";
    return 0;
  }
  
  if(!DecryptOnlyTheFileName(fname, secret, version, sbuf)) return 0;
  if(ERROR_LEVEL != 0) return 0;

  memset(rsa_ciphertext, 0, sizeof(rsa_ciphertext));
  RSA_openssl_init();  

  StaticDataBlock static_data_block;
  unsigned char SALT[AES_MAX_SALT_LEN];
  unsigned char IV[AES_MAX_IV_LEN];
  unsigned char KEY[AES_MAX_KEY_LEN];
  AES_init_salt(SALT, sizeof(SALT));
  
  rv = AES_derive_key((const unsigned char*)secret.m_buf(), secret.length(), SALT, sizeof(SALT), KEY, sizeof(KEY), IV, sizeof(IV), 1000);
  if(rv != AES_NO_ERROR) {
    ERROR_LEVEL = -1;
    err << clear << "Failed to generate derived key " << AES_err_string(rv);
    return 0;
  }
  MemoryBuffer p_secret;
  p_secret.Cat(SALT, AES_MAX_SALT_LEN);
  p_secret.Cat(secret.m_buf(), secret.length());
  
  rv = RSA_public_key_encrypt((const unsigned char *)public_key, public_key_len,
			      p_secret.m_buf(), p_secret.length(),
			      rsa_ciphertext, sizeof(rsa_ciphertext), &rsa_ciphertext_len,
			      RSA_padding, passphrase);
  if(rv != RSA_NO_ERROR) {
    ERROR_LEVEL = -1;
    err << clear << "RSA encrypt public key error " << RSA_err_string(rv);
    return 0;
  }

  if(!LoadStaticDataBlocks()) return 0;
  if(ERROR_LEVEL != 0) return 0;

  gxListNode<StaticDataBlock> *ptr = static_block_list.GetHead();

  while(ptr) {
    sbuf << clear << rsa_key_username;
    if((ptr->data.username == sbuf)  && (ptr->data.block_header.block_type == 1)) {
      ERROR_LEVEL = 1;
      err << clear << "An RSA key for username " << ptr->data.username.c_str() << " already exists";
      return 0;
    }
    ptr = ptr->next;
  }

  static_data_block_header.FormatHeader();
  unsigned char hash[AES_MAX_HMAC_LEN];
  memset(username_buf, 0, sizeof(username_buf));
  unsigned username_buf_len = 0;
  
  static_data_block_header.block_len = 0;
  static_data_block_header.block_type = 1;
  static_data_block_header.block_status = 1;
  
  static_data_block_header.ciphertext_len = rsa_ciphertext_len;
  static_data_block_header.block_len += rsa_ciphertext_len;
  static_data_block_header.block_len += sizeof(hash);

  gxsBase64Encode(rsa_key_username, username_buf, strlen(rsa_key_username));
  username_buf_len = strlen(username_buf);
  static_data_block_header.username_len = username_buf_len;
  
  static_data_block.block_header = static_data_block_header;
  static_data_block.rsa_ciphertext.Cat(rsa_ciphertext, rsa_ciphertext_len);
  rv = AES_HMAC(KEY, sizeof(KEY), rsa_ciphertext, rsa_ciphertext_len, hash, sizeof(hash));
  if(rv != AES_NO_ERROR) {
    ERROR_LEVEL = -1;
    err << clear << "Failed to generate HMAC for RSA ciphertext " << AES_err_string(rv);
    return 0;
  }

  static_data_block.hmac.Cat(hash, sizeof(hash));
  static_data_block.username = rsa_key_username;
  static_data_block.username_encoded = username_buf;

  static_block_list.Add(static_data_block);

  if(!UpdateStaticData()) return 0;
  if(ERROR_LEVEL != 0) return 0;

  if(!WriteStaticDataAreaToFile(fname)) return 0;

  return 1;
}

#ifdef __ENABLE_SMART_CARD__
int FCryptCache::AddSmartCardCertToStaticArea(SmartCardOB *sc, int use_cert_file,
					      const char *fname, const MemoryBuffer &secret, const char *smartcard_cert_username)
{
  gxString sbuf;
  gxUINT32 version;
  StaticDataBlockHdr static_data_block_header;
  char username_buf[1024];
  unsigned char ciphertext[8192];
  unsigned ciphertext_len;
  int rv;

  if(!futils_exists(fname) || !futils_isfile(fname)) {
    ERROR_LEVEL = -1;
    err << clear << "ERROR: Encrypted file " << fname << " does not exist or cannot be read";
    return 0;
  }
  
  if(!DecryptOnlyTheFileName(fname, secret, version, sbuf)) return 0;
  if(ERROR_LEVEL != 0) return 0;

  memset(ciphertext, 0, sizeof(ciphertext));

  StaticDataBlock static_data_block;
  unsigned char SALT[AES_MAX_SALT_LEN];
  unsigned char IV[AES_MAX_IV_LEN];
  unsigned char KEY[AES_MAX_KEY_LEN];
  AES_init_salt(SALT, sizeof(SALT));
  
  rv = AES_derive_key((const unsigned char*)secret.m_buf(), secret.length(), SALT, sizeof(SALT), KEY, sizeof(KEY), IV, sizeof(IV), 1000);
  if(rv != AES_NO_ERROR) {
    ERROR_LEVEL = -1;
    err << clear << "Failed to generate derived key " << AES_err_string(rv);
    return 0;
  }
  MemoryBuffer p_secret;
  p_secret.Cat(SALT, AES_MAX_SALT_LEN);
  p_secret.Cat(secret.m_buf(), secret.length());

  if(use_cert_file) {
    rv =  SC_cert_file_public_key_encrypt(sc, p_secret.m_buf(), p_secret.length(), ciphertext, sizeof(ciphertext), &ciphertext_len);
  }
  else {
    rv =  SC_public_key_encrypt(sc, p_secret.m_buf(), p_secret.length(), ciphertext, sizeof(ciphertext), &ciphertext_len);
  }
  
  if(rv != 0) {
    ERROR_LEVEL = -1;
    err << clear << "Smart card cert encrypt error " << sc->err_string;
    return 0;
  }

  if(!LoadStaticDataBlocks()) return 0;
  if(ERROR_LEVEL != 0) return 0;

  gxListNode<StaticDataBlock> *ptr = static_block_list.GetHead();

  while(ptr) {
    sbuf << clear << smartcard_cert_username;
    if((ptr->data.username == sbuf) && (ptr->data.block_header.block_type == 2)) {
      ERROR_LEVEL = 1;
      err << clear << "A smart card cert for username " << ptr->data.username.c_str() << " already exists";
      return 0;
    }
    ptr = ptr->next;
  }

  static_data_block_header.FormatHeader();
  unsigned char hash[AES_MAX_HMAC_LEN];
  memset(username_buf, 0, sizeof(username_buf));
  unsigned username_buf_len = 0;
  
  static_data_block_header.block_len = 0;
  static_data_block_header.block_type = 2;
  static_data_block_header.block_status = 1;
  
  static_data_block_header.ciphertext_len = ciphertext_len;
  static_data_block_header.block_len += ciphertext_len;
  static_data_block_header.block_len += sizeof(hash);

  gxsBase64Encode(smartcard_cert_username, username_buf, strlen(smartcard_cert_username));
  username_buf_len = strlen(username_buf);
  static_data_block_header.username_len = username_buf_len;
  
  static_data_block.block_header = static_data_block_header;
  static_data_block.rsa_ciphertext.Cat(ciphertext, ciphertext_len);
  rv = AES_HMAC(KEY, sizeof(KEY), ciphertext, ciphertext_len, hash, sizeof(hash));
  if(rv != AES_NO_ERROR) {
    ERROR_LEVEL = -1;
    err << clear << "Failed to generate HMAC for smart card ciphertext " << AES_err_string(rv);
    return 0;
  }

  static_data_block.hmac.Cat(hash, sizeof(hash));
  static_data_block.username = smartcard_cert_username;
  static_data_block.username_encoded = username_buf;

  static_block_list.Add(static_data_block);

  if(!UpdateStaticData()) return 0;
  if(ERROR_LEVEL != 0) return 0;

  if(!WriteStaticDataAreaToFile(fname)) return 0;

  return 1;
}
#endif
// ----------------------------------------------------------- // 
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
