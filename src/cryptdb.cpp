// ------------------------------- //
// -------- start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- // 
// C++ Source Code File
// Compiler Used: MSVC, BCC32, GCC, HPUX aCC, SOLARIS CC
// Produced By: DataReel Software Development Team
// File Creation Date: 06/15/2003
// Date Last Modified: 11/16/2023
// Copyright (c) 2001-2023 DataReel Software Development
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

FCryptCache::FCryptCache(unsigned CacheSize) : cache(CacheSize) 
{ 
  ready_for_writing = 1; 
  ready_for_reading = 1;
  cache.Connect(this); 
  buf_size = 1024;
  overwrite = 0;
  mode = 3;
  en_dot_ext = ".enc";
  bytes_wrote = (FAU_t)0;
  bytes_read = (FAU_t)0;
  crypt_stream = 1;
  gen_file_names = 0;
}

void FCryptCache::GenFileNames()
{
  if(!gen_file_names) {
    gen_file_names = 1;
  }
  else {
    gen_file_names = 0;
  }
}

void FCryptCache::Read(void *buf, unsigned Bytes, gxDeviceTypes dev) 
{
  switch(dev) {
    case gxDEVICE_DISK_FILE:
      if(!infile) { 
	err << clear << filename << " file not ready for reading";
	ready_for_reading = 0; 
	return; 
      }
      else { 
	ready_for_reading = 1; 
      }
      infile.df_Read((char *)buf, Bytes);
      if(infile.df_GetError() != DiskFileB::df_NO_ERROR) {
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
{
  int rv = AES_NO_ERROR;
  char *fbuf = new char[Bytes+1024];
  if(!fbuf) {
    err << clear << "File write error system out of memory";
    return;
  }

  // For testing without encrypting 
  // aesdb.b.mode = 0;
  
  unsigned buf_len;
  
  // Encrypt the file buffer
  memmove(fbuf, buf, Bytes);
  if(crypt_stream) {
    buf_len = Bytes;
    rv = aesdb.Encrypt(fbuf, &buf_len);
    Bytes = buf_len;
  }
  else {
    buf_len = Bytes;
    rv = aesdb.Decrypt(fbuf, &buf_len);
    Bytes = buf_len;
  }
  
  if(rv != AES_NO_ERROR) {
    err << clear << "File buf crypt error, " << AES_err_string(rv);
    memset(fbuf, 0, Bytes);
    delete fbuf;
    return;
  }

  switch(dev) {
    case gxDEVICE_CONSOLE:
#if defined (__CONSOLE__)
      GXSTD::cout.write((char *)buf, Bytes);
      bytes_wrote += Bytes;
#endif
      break;

    case gxDEVICE_DISK_FILE:
      if(!outfile) { 
	err << clear << ofname << " file not ready for writing";
	ready_for_writing = 0; 
	delete fbuf;
	return; 
      }
      else { 
	ready_for_writing = 1; 
      }

      outfile.df_Write(fbuf, Bytes);
      if(outfile.df_GetError() != DiskFileB::df_NO_ERROR) {
	err << clear << "Fatal file buf write error " << ofname;
	delete fbuf;
	return;
      } 
      bytes_wrote += Bytes;
      break;
      
    default:
      break;
  }

  memset(fbuf, 0, Bytes);
  delete fbuf;
}

int FCryptCache::EncryptFile(const char *fname, const gxString &password)
{
  err.Clear();
  filename.Clear();
  ofname.Clear();
  bytes_wrote = (FAU_t)0;
  bytes_read = (FAU_t)0;
  crypt_stream = 1;

  if(!cache) {
    err << clear << "No cache buffers available";
    cp.password.Clear(1);
    return 0;
  }

  if(!OpenInputFile(fname)) return 0;
  cp.password = password; 
  if(!OpenOutputFile()) {
    cp.password.Clear(1);
    return 0;
  }

  memmove(aesdb.b.secret, password.c_str(), password.length());
  aesdb.b.secret_len = password.length();

  gxDeviceTypes o_device = gxDEVICE_DISK_FILE; // Output device
  gxDeviceTypes i_device = gxDEVICE_NULL;      // No input buffering

  // Setup a pointer to the cache buckets
  gxDeviceCachePtr p(cache, o_device, i_device); 
  if(!LoadFile(p)) {  // Load the file into the cache 
    if(!err.is_null()) {
      err << clear << "Error encrypting " << filename;
    }
    cp.password.Clear(1);
    CloseInputFile();
    return 0;
  }
  Flush(); // Ensure all the buckets a written to the output device
  
  cp.password.Clear(1);
  CloseOutputFile();

  if(bytes_read != infile.df_Length()) {
    if(!err.is_null()) {
      err << clear << "Error encrypting " << filename;
    }
    CloseInputFile();
    return 0;
  }

  CloseInputFile();
  return 1;
}

int FCryptCache::LoadFile(gxDeviceCachePtr p)
// Load a file from disk into the device cache.
{
  infile.df_Rewind();
  char *fbuf = new char[buf_size+1024];
  if(!fbuf) {
    err << clear << "Out of system memory" << "\n";
    return 0;
  }

  while(!infile.df_EOF()) {
    if(infile.df_Read(fbuf, buf_size) != DiskFileB::df_NO_ERROR) {
      if(infile.df_GetError() != DiskFileB::df_EOF_ERROR) {
	err << clear << "Fatal read error " << filename.c_str();
	delete fbuf;
	return 0;
      }
    }
    p->Load(fbuf, infile.df_gcount());
    bytes_read += infile.df_gcount();
  }

  delete fbuf;
  return 1;
}

int FCryptCache::LoadCryptFile(gxDeviceCachePtr p)
// Load encrypted file from disk into the device cache.
{
  unsigned char HMAC[32];
  MemoryBuffer buf(buf_size);
  unsigned len;
  int rv;

  while(!infile.df_EOF()) {
    FAU_t bytes_left = infile.df_Length()-infile.df_Tell();
    if(bytes_left < (FAU_t)32) {
	err << clear << "Invalid MAC value";
	return 0;
    }

    if((FAU_t)buf_size > bytes_left) {
      len = (unsigned)bytes_left;
      buf.resize(len);
    } 
    else {
      len = buf_size;
    }

    if(infile.df_Read(buf.m_buf(), len) != DiskFileB::df_NO_ERROR) {
      err << clear << "Fatal file buf read error";
      return 0;
    }
    p->Load(buf.m_buf(), len);
    bytes_read += len;
  }

  return 1;
}


int FCryptCache::OpenInputFile(const char *fname)
// Open the file if it exists. Returns false
// it the file cannot be opened or if it does
// not exist.
{
  if(!fname) {
    err << clear << "Null input file name";
    return 0;
  }
  filename.Clear();
  if(infile.df_Open(fname, DiskFileB::df_READONLY) != 
     DiskFileB::df_NO_ERROR) {
    err << clear << "Error opening " << fname;
    return 0;
  }
  filename = fname;
  if(infile.df_Length() == (FAU_t)0) {
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
    err << clear << "No input file is open";
    return 0;
  }
  ofname = filename;

  if((ofname[ofname.length()-3] == '.') ||
     ofname[ofname.length()-4] == '.') {
    ofname.DeleteAfterLastIncluding(".");
  }
  ofname << en_dot_ext;

  if(gen_file_names) {
    unsigned long name_int = calcCRC32(ofname.c_str(), ofname.length());
    ofname << clear << name_int;
  }

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
	err << clear << "Output DIR is a file name " << output_dir_name;
	return 0;
      }
    }

    // If the output DIR does not exist try to make the DIR
    if(!futils_exists(output_dir_name.c_str())) {
      if(futils_mkdir(output_dir_name.c_str()) != 0) {
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
      }
    }
  }
  char nbuf[AES_MAX_NAME_LEN];
  CryptFileHdr hdr;
  memmove(nbuf, filename.GetSPtr(), filename.length());
  unsigned len = filename.length();

  rv =  AES_Encrypt(nbuf, &len, (char *)cp.password.GetSPtr(), 
		    cp.password.length(), mode);
  if(rv != AES_NO_ERROR) {
    err << clear << "HDR crypt error, " << AES_err_string(rv);
    return 0;
  }
  hdr.mode = mode;
  hdr.name_len = len;
  hdr.fname = nbuf;

  if(outfile.df_Create(ofname.c_str()) != DiskFileB::df_NO_ERROR) {
    err << clear << "Error opening " << ofname;
    return 0;
  }

  outfile.df_Write(&hdr, (sizeof(gxUINT32)*4));
  if(outfile.df_GetError() != DiskFileB::df_NO_ERROR) {
    err << clear << "Fatal HDR write error " << ofname;
    CloseOutputFile();
    return 0;
  } 
  bytes_wrote += sizeof(gxUINT32)*4;

  outfile.df_Write(hdr.fname, hdr.name_len);
  if(outfile.df_GetError() != DiskFileB::df_NO_ERROR) {
    err << clear << "Fatal HDR write error " << ofname;
    CloseOutputFile();
    return 0;
  } 
  bytes_wrote += hdr.name_len;

  return 1;
}

int FCryptCache::TestVersion(CryptFileHdr hdr, gxUINT32 &version)
{
  err.Clear();

  // Select the correct file decrypt version
  switch((int)hdr.version) {
    case 1002: // Current version
      version = (gxUINT32)1002;
      break;
    case 1001: // Version 1.0 - 1.1
      CloseInputFile();
      version = (gxUINT32)1001;
      return 0;
    default:
      version = (gxUINT32)0;
      err << clear << "Bad file version";
      return 0;
  }

  return 1;
}

int FCryptCache::DecryptFile(const char *fname, const gxString &password,
			     gxUINT32 &version)
{
  err.Clear();
  filename.Clear();
  ofname.Clear();
  bytes_wrote = (FAU_t)0;
  bytes_read = (FAU_t)0;
  crypt_stream = 0;

  if(!cache) {
    err << clear << "No cache buffers available";
    cp.password.Clear(1);
    return 0;
  }

  cp.password = password; 
  if(!OpenInputFile(fname)) return 0;

  if(infile.df_Length() < (sizeof(gxUINT32)*4)) {
    err << clear << "Bad file length";
    return 0;
  }

  memmove(aesdb.b.secret, password.c_str(), password.length());
  aesdb.b.secret_len = password.length();

  CryptFileHdr hdr, null_hdr;
  if(infile.df_Read(&hdr, (sizeof(gxUINT32)*4)) != 
     DiskFileB::df_NO_ERROR) {
    err << clear << "Error reading file header";
    return 0;
  }

  // Select the correct file decrypt version
  if(!TestVersion(hdr, version)) return 0;
  
  if(hdr.checkword != null_hdr.checkword) {
    err << clear << "Corrupt file bad checkword";
    return 0;
  }
  if(hdr.name_len > gxUINT32(infile.df_Length()-(sizeof(gxUINT32)*3))) {
    err << clear << "Incomplete or corrupt file";
    return 0;
  }
  if(hdr.name_len > AES_MAX_NAME_LEN) {
    err << clear << "Invalid file header";
    return 0;
  }

  char nbuf[AES_MAX_NAME_LEN];
  memset(nbuf, 0, AES_MAX_NAME_LEN);

  if(infile.df_Read(&nbuf, hdr.name_len) != 
     DiskFileB::df_NO_ERROR) {
    err << clear << "Error reading encrypted file name";
    return 0;
  }

  unsigned len = hdr.name_len;
  int rv =  AES_Decrypt(nbuf, &len, (char *)cp.password.GetSPtr(), 
			cp.password.length());
  if(rv != AES_NO_ERROR) {
    err << clear << "Decrypt file name error, " << "\n"
	<< AES_err_string(rv);
    return 0;
  }

  mode = (char)hdr.mode;

  gxString sbuf;
  ofname.SetString(nbuf, len);

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
    if(!futils_exists(output_dir_name.c_str())) {
      if(futils_mkdir(output_dir_name.c_str()) != 0) {
	err << clear << "Error making DIR " << output_dir_name;
	return 0;
      }
    }
  }

  MemoryBuffer mbuf;
  if(outfile.df_Create(ofname.c_str()) != DiskFileB::df_NO_ERROR) {
    err << clear << "Error opening " << ofname;
    return 0;
  }
  
  gxDeviceTypes o_device = gxDEVICE_DISK_FILE; // Output device
  gxDeviceTypes i_device = gxDEVICE_NULL;      // No input buffering

  // Setup a pointer to the cache buckets
  gxDeviceCachePtr p(cache, o_device, i_device); 
  if(!LoadCryptFile(p)) {  // Load the file into the cache 
    if(!err.is_null()) {
      err << clear << "Error decrypting " << filename;
    }
    cp.password.Clear(1);
    CloseInputFile();
    return 0;
  }

  Flush(); // Ensure all the buckets a written to the output device
  cp.password.Clear(1);
  CloseOutputFile();
  CloseInputFile();
  return 1;
}

int FCryptCache::DecryptFileName(const char *fname, const gxString &password,
				 gxUINT32 &version, gxString &crypt_file_name)
{
  err.Clear();
  filename.Clear();
  ofname.Clear();
  bytes_wrote = (FAU_t)0;
  bytes_read = (FAU_t)0;
  crypt_stream = 0;

  crypt_file_name.Clear();

  if(!cache) {
    err << clear << "No cache buffers available";
    cp.password.Clear(1);
    return 0;
  }

  cp.password = password; 
  if(!OpenInputFile(fname)) return 0;

  if(infile.df_Length() < (sizeof(gxUINT32)*4)) {
    err << clear << "Bad file length";
    return 0;
  }

  CryptFileHdr hdr, null_hdr;
  if(infile.df_Read(&hdr, (sizeof(gxUINT32)*4)) != 
     DiskFileB::df_NO_ERROR) {
    err << clear << "Error reading file header";
    return 0;
  }

  // Select the correct file decrypt version
  if(!TestVersion(hdr, version)) return 0;
  
  if(hdr.checkword != null_hdr.checkword) {
    err << clear << "Corrupt file bad checkword";
    return 0;
  }
  if(hdr.name_len > gxUINT32(infile.df_Length()-(sizeof(gxUINT32)*3))) {
    err << clear << "Incomplete or corrupt file";
    return 0;
  }
  if(hdr.name_len > AES_MAX_NAME_LEN) {
    err << clear << "Invalid file header";
    return 0;
  }

  char nbuf[AES_MAX_NAME_LEN];
  memset(nbuf, 0, AES_MAX_NAME_LEN);

  if(infile.df_Read(&nbuf, hdr.name_len) != 
     DiskFileB::df_NO_ERROR) {
    err << clear << "Error reading encrypted file name";
    return 0;
  }

  unsigned len = hdr.name_len;
  int rv =  AES_Decrypt(nbuf, &len, (char *)cp.password.GetSPtr(), 
			cp.password.length());
  if(rv != AES_NO_ERROR) {
    err << clear << "Decrypt file name error, " << "\n"
	<< AES_err_string(rv);
    return 0;
  }

  unsigned char salt[8], verifier[16];
  if(infile.df_Read(&buf_size, sizeof(buf_size)) != 
     DiskFileB::df_NO_ERROR) {
    err << clear << "Error reading embedded buf size";
    return 0;
  }
  if(infile.df_Read(salt, 8) != 
     DiskFileB::df_NO_ERROR) {
    err << clear << "Error reading embedded salt";
    return 0;
  }
  if(infile.df_Read(verifier, 16) != 
     DiskFileB::df_NO_ERROR) {
    err << clear << "Error reading embedded verifier";
    return 0;
  }

  mode = (char)hdr.mode;

  // Set the unencrypted file name
  crypt_file_name.SetString(nbuf, len);

  cp.password.Clear(1);
  CloseInputFile();
  return 1;
}

int FCryptCache::EncryptFile(const char *fname,
			     const MemoryBuffer &buf,
			     const gxString &password)
{
  err.Clear();
  filename.Clear();
  ofname.Clear();
  bytes_wrote = (FAU_t)0;
  bytes_read = (FAU_t)0;
  crypt_stream = 1;

  if(!cache) {
    err << clear << "No cache buffers available";
    cp.password.Clear(1);
    return 0;
  }

  // Set the a dummy input file name
  filename = fname;

  // Set the buffer size
  buf_size = buf.length();

  cp.password = password; 
  if(!OpenOutputFile()) {
    cp.password.Clear(1);
    return 0;
  }

  gxDeviceTypes o_device = gxDEVICE_DISK_FILE; // Output device
  gxDeviceTypes i_device = gxDEVICE_NULL;      // No input buffering

  // Setup a pointer to the cache buckets
  gxDeviceCachePtr p(cache, o_device, i_device); 
  p->Load(buf.m_buf(), buf_size);
  bytes_read += buf_size;
  Flush(); // Ensure all the buckets a written to the output device

  cp.password.Clear(1);
  CloseOutputFile();

  return 1;
}

int FCryptCache::DecryptFile(const char *fname, MemoryBuffer &buf,
			     const gxString &password, gxUINT32 &version)
{
  buf.Clear();
  err.Clear();
  filename.Clear();
  ofname.Clear();
  bytes_wrote = (FAU_t)0;
  bytes_read = (FAU_t)0;
  crypt_stream = 0;

  if(!cache) {
    err << clear << "No cache buffers available";
    cp.password.Clear(1);
    return 0;
  }

  if(!OpenInputFile(fname)) return 0;
  cp.password = password; 

  if(infile.df_Length() < (sizeof(gxUINT32)*4)) {
    err << clear << "Bad file length";
    return 0;
  }

  CryptFileHdr hdr, null_hdr;
  if(infile.df_Read(&hdr, (sizeof(gxUINT32)*4)) != 
     DiskFileB::df_NO_ERROR) {
    err << clear << "Error reading file header";
    return 0;
  }

  // Select the correct file decrypt version
  if(!TestVersion(hdr, version)) return 0;

  if(hdr.checkword != null_hdr.checkword) {
    err << clear << "Corrupt file bad checkword";
    return 0;
  }
  if(hdr.name_len > gxUINT32(infile.df_Length()-(sizeof(gxUINT32)*3))) {
    err << clear << "Incomplete or corrupt file";
    return 0;
  }
  if(hdr.name_len > AES_MAX_NAME_LEN) {
    err << clear << "Invalid file header";
    return 0;
  }

  char nbuf[AES_MAX_NAME_LEN];
  memset(nbuf, 0, AES_MAX_NAME_LEN);

  if(infile.df_Read(&nbuf, hdr.name_len) != 
     DiskFileB::df_NO_ERROR) {
    err << clear << "Error reading encrypted file name";
    return 0;
  }

  unsigned len = hdr.name_len;
  int rv =  AES_Decrypt(nbuf, &len, (char *)cp.password.GetSPtr(), 
			cp.password.length());
  if(rv != AES_NO_ERROR) {
    err << clear << "Decrypt file name error, " << "\n"
	<< AES_err_string(rv);
    return 0;
  }

  unsigned char salt[8], verifier[16];
  if(infile.df_Read(&buf_size, sizeof(buf_size)) != 
     DiskFileB::df_NO_ERROR) {
    err << clear << "Error reading embedded buf size";
    return 0;
  }
  buf.resize(buf_size);

  if(infile.df_Read(salt, 8) != 
     DiskFileB::df_NO_ERROR) {
    err << clear << "Error reading embedded salt";
    return 0;
  }
  if(infile.df_Read(verifier, 16) != 
     DiskFileB::df_NO_ERROR) {
    err << clear << "Error reading embedded verifier";
    return 0;
  }

  mode = (char)hdr.mode;

  unsigned char HMAC[32];

  while(!infile.df_EOF()) {
    FAU_t bytes_left = infile.df_Length()-infile.df_Tell();

    if(bytes_left == (FAU_t)32) { // Read MAC
      if(infile.df_Read(HMAC, 32) != DiskFileB::df_NO_ERROR) {
	err << clear << "Fatal file MAC read error";
	return 0;
      }
      break;
    }

    if(bytes_left < (FAU_t)32) {
	err << clear << "Invalid MAC value";
	return 0;
    }

    if((FAU_t)buf_size > bytes_left) {
      len = (unsigned)bytes_left-32;
      buf.resize(len);
    } 
    else {
      len = buf_size;
    }
    if(infile.df_Read(buf.m_buf(), len) != DiskFileB::df_NO_ERROR) {
      err << clear << "Fatal file buf read error";
      return 0;
    }

    unsigned buf_len = buf.length();
    rv = aesdb.Decrypt(buf, &buf_len);
    if(rv != AES_NO_ERROR) {
      err << clear << "File buf crypt error, " << AES_err_string(rv);
      return 0;
    }

    bytes_read += len;
  }

  cp.password.Clear(1);
  CloseInputFile();
  return 1;
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
// ----------------------------------------------------------- // 
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //

