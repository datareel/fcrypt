// ------------------------------- //
// -------- Start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- //
// C++ Header File
// Compiler Used: MSVC, BCC32, GCC, HPUX aCC, SOLARIS CC
// Produced By: DataReel Software Development Team
// File Creation Date: 06/15/2003
// Date Last Modified: 11/16/2023
// Copyright (c) 2001-2023 DataReel Software Development
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

struct GXDLCODE_API CryptFileHdr
{
  CryptFileHdr() {
    version = 2023102;
    checkword = 0xFEFE; 
    name_len = (gxUINT32)0;
    memset(fname, 0, sizeof(fname));
    mode = 3;
  }
  ~CryptFileHdr() { }

  gxUINT32 version;   // Header version number
  gxUINT32 checkword; // Header checkword
  gxUINT32 mode;      // Encryption mode
                      // 0 = No encryption
                      // 3 = AES 256-bit encryption 

  gxUINT32 name_len; // Variable length of encrypted file name or DIR list
  char fname[256];  // Name of the file that was encrypted or DIR list
};

struct GXDLCODE_API CryptPasswordHdr
{
  CryptPasswordHdr() { }
  ~CryptPasswordHdr() { Reset(); }
  CryptPasswordHdr(const CryptPasswordHdr &ob) { Copy(ob); }
  CryptPasswordHdr &operator=(const CryptPasswordHdr &ob) {
    if(&ob == this) return *this;
    Copy(ob);
    return *this;
  }

  void Reset() {
    password.Clear(1);
    cbuf.Clear(1);
  }
  void Copy(const CryptPasswordHdr &ob) {
    Reset();
    password = ob.password;
    cbuf = ob.cbuf;
  }

  gxString password;
  gxString cbuf;
};

// Cached file encryption class
class GXDLCODE_API FCryptCache : public gxDeviceCache
{
public:
  FCryptCache(unsigned CacheSize = 1024);
  ~FCryptCache() { }

public: // Encrypt functions
  int EncryptFile(const char *fname, const gxString &password);

public: // Decrypt fucntions
  int DecryptFile(const char *fname, const gxString &password, gxUINT32 &version);
  int DecryptOnlyTheFileName(const char *fname, const gxString &password,
			     gxUINT32 &version, gxString &crypt_file_name);

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
  FAU_t BytesWrote() { return bytes_wrote; }
  FAU_t BytesRead() { return bytes_read; }
  void GenFileNames();

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
  int gen_file_names;

public: // Functions used to get the current device cache
  gxDeviceBucketCache *GetCache() { return &cache; }
  DiskFileB *GetOutFile() { return &outfile; }
  DiskFileB *GetInFile() { return &infile; }

public:
  int ERROR_LEVEL;
  char mode;
  gxString err;
  CryptPasswordHdr cp;
  AESStreamCrypt aesdb;
};

// Standalone functions
// -------------------------------------------------------------
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


