// ------------------------------- //
// -------- start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- // 
// C++ Source Code File
// Compiler Used: MSVC, BCC32, GCC, HPUX aCC, SOLARIS CC
// Produced By: DataReel Software Development Team
// File Creation Date: 06/15/2003
// Date Last Modified: 11/18/2023
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
  ERROR_LEVEL = 0;
  use_key = 0;
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

int count = 0;

void FCryptCache::Write(const void *buf, unsigned Bytes, gxDeviceTypes dev) 
{
  int rv = AES_NO_ERROR;
  char fbuf[1024];
  if(!fbuf) {
    ERROR_LEVEL = -1;
    err << clear << "File write error system out of memory";
    return;
  }

  unsigned buf_len;
  unsigned i;
  
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
    ERROR_LEVEL = rv;
    err << clear << "File buf crypt error " << AES_err_string(rv);
    return;
  }

  outfile.df_Write(fbuf, Bytes);
  if(outfile.df_GetError() != DiskFileB::df_NO_ERROR) {
    ERROR_LEVEL = -1;
    err << clear << "Fatal file buf write error " << ofname;
    return;
  } 
  bytes_wrote += Bytes;

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
    ERROR_LEVEL = -1;
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

  if(use_key) {
    memmove(aesdb.b.secret, key.m_buf(), key.length());
    aesdb.b.secret_len = key.length();
  }
  else {
    memmove(aesdb.b.secret, password.c_str(), password.length());
    aesdb.b.secret_len = password.length();
  }
  
  gxDeviceTypes o_device = gxDEVICE_DISK_FILE; // Output device
  gxDeviceTypes i_device = gxDEVICE_NULL;      // No input buffering

  // Setup a pointer to the cache buckets
  gxDeviceCachePtr p(cache, o_device, i_device); 
  if(!LoadFile(p)) {  // Load the file into the cache 
    if(!err.is_null()) {
      ERROR_LEVEL = -1;
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
      ERROR_LEVEL = -1;
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
  char read_buf[AES_PLAINTEXT_BUF_SIZE];
  
  unsigned read_len = AES_MAX_INPUT_BUF_LEN;
  if(crypt_stream == 0) read_len += AES_file_enctryption_overhead();

  //  infile.df_Rewind();

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
  }

  return 1;
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
  
  // Adding a file header with meta data
  char enc_header[AES_MAX_INPUT_BUF_LEN];
  AES_fillrand((unsigned char *)enc_header, sizeof(enc_header));
 
  // Init the file header
  CryptFileHdr hdr;
  hdr.mode = mode;
  hdr.name_len = filename.length();
  if(hdr.name_len > AES_MAX_NAME_LEN) {
    ERROR_LEVEL = -1;
    err << clear << "File name greater than maximum length " << AES_MAX_NAME_LEN;
    return 0;
  }
  memmove(hdr.fname, filename.GetSPtr(), filename.length());

  // Encrypt the file header
  // Put the header in file block that will be written at the top of the file
  memmove(enc_header, &hdr, sizeof(hdr));
  unsigned len = sizeof(enc_header);
  
  // Create a temp buffer to encrypt the file block with header
  char crypt_buf[AES_CIPHERTEXT_BUF_SIZE];
  memmove(crypt_buf, enc_header, sizeof(enc_header));

  if(use_key) {
    rv = AES_Encrypt(crypt_buf, &len, (char *)key.m_buf(), key.length(), mode);
  }
  else {
    rv =  AES_Encrypt(crypt_buf, &len, (char *)cp.password.GetSPtr(), cp.password.length(), mode);
  }

  if(rv != AES_NO_ERROR) {
    ERROR_LEVEL = rv;
    err << clear << "File header crypt error " << AES_err_string(rv);
    return 0;
  }

  if(outfile.df_Create(ofname.c_str()) != DiskFileB::df_NO_ERROR) {
    ERROR_LEVEL = -1;
    err << clear << "Error opening " << ofname;
    return 0;
  }

  // Write the file header to disk
  outfile.df_Write(crypt_buf, len);
  if(outfile.df_GetError() != DiskFileB::df_NO_ERROR) {
    ERROR_LEVEL = -1;
    err << clear << "Error writing header to file " << ofname;
    CloseOutputFile();
    return 0;
  } 
  bytes_wrote += len;

  return 1;
}

int FCryptCache::TestVersion(CryptFileHdr hdr, gxUINT32 &version)
{
  err.Clear();

  // Select the correct file decrypt version
  switch((int)hdr.version) {
    case 2023102: // Current version
      version = (gxUINT32)2023102;
      break;
    default:
      version = (gxUINT32)0;
      ERROR_LEVEL = -1;
      err << clear << "Bad file version";
      return 0;
  }

  return 1;
}

int FCryptCache::DecryptFile(const char *fname, const gxString &password, gxUINT32 &version)
{
  err.Clear();
  filename.Clear();
  ofname.Clear();
  bytes_wrote = (FAU_t)0;
  bytes_read = (FAU_t)0;
  crypt_stream = 0;
  int rv;
  
  if(!cache) {
    ERROR_LEVEL = -1;
    err << clear << "No cache buffers available";
    cp.password.Clear(1);
    return 0;
  }

  cp.password = password; 
  if(!OpenInputFile(fname)) return 0;

  if(infile.df_Length() < (sizeof(gxUINT32)*4)) {
    ERROR_LEVEL = -1;
    err << clear << "Bad file length";
    return 0;
  }

  if(use_key) {
    memmove(aesdb.b.secret, key.m_buf(), key.length());
    aesdb.b.secret_len = key.length();
  }
  else {
    memmove(aesdb.b.secret, password.c_str(), password.length());
    aesdb.b.secret_len = password.length();
  }
    
  // Read the encrypted file header
  unsigned read_len = AES_MAX_INPUT_BUF_LEN + AES_file_enctryption_overhead();
  char crypt_buf[AES_CIPHERTEXT_BUF_SIZE];

  CryptFileHdr hdr, null_hdr;
  if(infile.df_Read(crypt_buf, read_len) != 
     DiskFileB::df_NO_ERROR) {
    ERROR_LEVEL = -1;
    err << clear << "Error reading file header";
    return 0;
  }
  unsigned len = infile.df_gcount();

  if(use_key) {
    rv =  AES_Decrypt(crypt_buf, &len, (char *)key.m_buf(), key.length());
  }
  else {
    rv =  AES_Decrypt(crypt_buf, &len, (char *)cp.password.GetSPtr(), cp.password.length());
  }

  if(rv != AES_NO_ERROR) {
    ERROR_LEVEL = -1;
    err << clear << "Decrypt file header error " << " " << AES_err_string(rv);
    return 0;
  }
  memmove(&hdr, crypt_buf, sizeof(hdr));

  if(hdr.checkword != null_hdr.checkword) {
    ERROR_LEVEL = -1;
    err << clear << "Corrupt file bad checkword";
    return 0;
  }

  // Select the correct file decrypt version
  if(!TestVersion(hdr, version)) return 0;
  
  if(hdr.name_len > gxUINT32(infile.df_Length()-(sizeof(gxUINT32)*3))) {
    ERROR_LEVEL = -1;
    err << clear << "Incomplete or corrupt file";
    return 0;
  }
  if(hdr.name_len > AES_MAX_NAME_LEN) {
    ERROR_LEVEL = -1;
    err << clear << "Invalid file header";
    return 0;
  }

  mode = (char)hdr.mode;
  
  gxString sbuf;
  ofname.SetString(hdr.fname, hdr.name_len);
    
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
	ERROR_LEVEL = -1;
	err << clear << "Error making DIR " << output_dir_name;
	return 0;
      }
    }
  }

  MemoryBuffer mbuf;
  if(outfile.df_Create(ofname.c_str()) != DiskFileB::df_NO_ERROR) {
    ERROR_LEVEL = -1;
    err << clear << "Error opening " << ofname;
    return 0;
  }
  
  gxDeviceTypes o_device = gxDEVICE_DISK_FILE; // Output device
  gxDeviceTypes i_device = gxDEVICE_NULL;      // No input buffering

  // Setup a pointer to the cache buckets
  gxDeviceCachePtr p(cache, o_device, i_device); 
  if(!LoadFile(p)) {  // Load the file into the cache 
    if(!err.is_null()) {
      ERROR_LEVEL = -1;
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

int FCryptCache::DecryptOnlyTheFileName(const char *fname, const gxString &password,
					gxUINT32 &version, gxString &crypt_file_name)
{
  err.Clear();
  filename.Clear();
  ofname.Clear();
  bytes_wrote = (FAU_t)0;
  bytes_read = (FAU_t)0;
  crypt_stream = 0;
  int rv;
  
  crypt_file_name.Clear();

  if(!cache) {
    ERROR_LEVEL = -1;
    err << clear << "No cache buffers available";
    cp.password.Clear(1);
    return 0;
  }

  cp.password = password; 
  if(!OpenInputFile(fname)) return 0;

  if(infile.df_Length() < (sizeof(gxUINT32)*4)) {
    ERROR_LEVEL = -1;
    err << clear << "Bad file length";
    return 0;
  }

  if(use_key) {
    memmove(aesdb.b.secret, key.m_buf(), key.length());
    aesdb.b.secret_len = key.length();
  }
  else {
    memmove(aesdb.b.secret, password.c_str(), password.length());
    aesdb.b.secret_len = password.length();
  }

  // Read the encrypted file header
  unsigned read_len = AES_MAX_INPUT_BUF_LEN + AES_file_enctryption_overhead();
  char crypt_buf[AES_CIPHERTEXT_BUF_SIZE];

  CryptFileHdr hdr, null_hdr;
  if(infile.df_Read(crypt_buf, read_len) != 
     DiskFileB::df_NO_ERROR) {
    ERROR_LEVEL = -1;
    err << clear << "Error reading file header";
    return 0;
  }
  unsigned len = infile.df_gcount();

  if(use_key) {
    rv =  AES_Decrypt(crypt_buf, &len, (char *)key.m_buf(), key.length());
  }
  else {
    rv =  AES_Decrypt(crypt_buf, &len, (char *)cp.password.GetSPtr(), cp.password.length());
  }
  
  if(rv != AES_NO_ERROR) {
    ERROR_LEVEL = -1;
    err << clear << "Decrypt file header error " << " " << AES_err_string(rv);
    return 0;
  }
  memmove(&hdr, crypt_buf, sizeof(hdr));

  
  if(hdr.checkword != null_hdr.checkword) {
    ERROR_LEVEL = -1;
    err << clear << "Corrupt file bad checkword";
    return 0;
  }

  // Select the correct file decrypt version
  if(!TestVersion(hdr, version)) return 0;
  
  if(hdr.name_len > gxUINT32(infile.df_Length()-(sizeof(gxUINT32)*3))) {
    ERROR_LEVEL = -1;
    err << clear << "Incomplete or corrupt file";
    return 0;
  }
  if(hdr.name_len > AES_MAX_NAME_LEN) {
    ERROR_LEVEL = -1;
    err << clear << "Invalid file header";
    return 0;
  }

  mode = (char)hdr.mode;

  // Set the unencrypted file name
  crypt_file_name.SetString(hdr.fname, hdr.name_len);

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

int read_key_file(const char *fname, MemoryBuffer &key, gxString &err, int expected_key_len)
// Read in key file contents to key object and return in reference. 
{
  FILE *fp;
  fp = fopen(fname, "rb");
  if(!fp) {
    err << clear << "Error opening key file " << fname;
    return -1;
  }

  char read_buf[1024];
  unsigned bytes_read = fread((unsigned char *)read_buf, 1, sizeof(read_buf), fp);
  if(bytes_read <= 0) {
    fclose(fp);
    err << clear << "Error reading from key file " << fname;
    return -1;
  }

  fclose(fp);
  
  if(expected_key_len > 0) {
    if(expected_key_len < bytes_read) {
      err << clear << "Bad input key length";
      return -1;
    }
  }
  
  key.Clear();
  key.Load(read_buf, bytes_read);

  return 0;
}
// ----------------------------------------------------------- // 
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //

