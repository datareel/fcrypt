// ------------------------------- //
// -------- start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- // 
// C++ Source Code File
// Compiler Used: MSVC, BCC32, GCC, HPUX aCC, SOLARIS CC
// Produced By: DataReel Software Development Team
// File Creation Date: 06/15/2003
// Date Last Modified: 11/29/2023
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
  key_iterations =  AES_DEF_ITERATIONS;
  en_dot_ext = ".enc";
  bytes_wrote = (FAU_t)0;
  bytes_read = (FAU_t)0;
  crypt_stream = 1;
  ERROR_LEVEL = 0;
  AES_fillrand(static_data, sizeof(static_data));
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

  aesdb.b.mode = mode;
  aesdb.b.key_iterations  = key_iterations;
  
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

  switch(dev) {
    case gxDEVICE_DISK_FILE:
      outfile.df_Write(fbuf, Bytes);
      if(outfile.df_GetError() != DiskFileB::df_NO_ERROR) {
	ERROR_LEVEL = -1;
	err << clear << "Fatal file buf write error " << ofname;
	return;
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
}

int FCryptCache::EncryptFile(const char *fname, const MemoryBuffer &secret)
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
    cp.secret.Clear(1);
    return 0;
  }

  if(!OpenInputFile(fname)) return 0;
  cp.secret = secret; 
  if(!OpenOutputFile()) {
    cp.secret.Clear(1);
    return 0;
  }
  
  memmove(aesdb.b.secret, secret.m_buf(), secret.length());
  aesdb.b.secret_len = secret.length();
  
  gxDeviceTypes o_device = gxDEVICE_DISK_FILE; // Output device
  gxDeviceTypes i_device = gxDEVICE_NULL;      // No input buffering

  // Setup a pointer to the cache buckets
  gxDeviceCachePtr p(cache, o_device, i_device); 
  if(!LoadFile(p)) {  // Load the file into the cache 
    if(!err.is_null()) {
      ERROR_LEVEL = -1;
      err << clear << "Error encrypting " << filename;
    }
    cp.secret.Clear(1);
    CloseInputFile();
    return 0;
  }
  Flush(); // Ensure all the buckets a written to the output device
  
  cp.secret.Clear(1);
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

  int crypt_mode = -1;
  if(mode == 0) {
    // If mode 0 is used for testing we will still encrypt the file header 
    crypt_mode = -1;
  }
  else {
    crypt_mode = mode;
  }
  
  rv =  AES_Encrypt(crypt_buf, &len, (char *)cp.secret.m_buf(), cp.secret.length(), crypt_mode, key_iterations);
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

  // Adding a static data area
  // Write the static data area to disk
  outfile.df_Write(static_data, sizeof(static_data));
  if(outfile.df_GetError() != DiskFileB::df_NO_ERROR) {
    ERROR_LEVEL = -1;
    err << clear << "Error writing static data area to file " << ofname;
    CloseOutputFile();
    return 0;
  } 
  bytes_wrote += sizeof(static_data);
  
  // Adding a file header with meta data
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

int FCryptCache::DecryptFileHeader(CryptFileHdr &hdr, const char *fname, const MemoryBuffer &secret, gxUINT32 &version)
{
  err.Clear();
  bytes_wrote = (FAU_t)0;
  bytes_read = (FAU_t)0;
  crypt_stream = 0;
  int rv;
  
  if(!cache) {
    ERROR_LEVEL = -1;
    err << clear << "No cache buffers available";
    cp.secret.Clear(1);
    return 0;
  }

  cp.secret = secret; 
  if(!OpenInputFile(fname)) return 0;

  if(infile.df_Length() < (sizeof(gxUINT32)*4)) {
    ERROR_LEVEL = -1;
    err << clear << "Bad file length";
    return 0;
  }

  // Read the static data area
  if(infile.df_Read(static_data, sizeof(static_data)) != 
     DiskFileB::df_NO_ERROR) {
    ERROR_LEVEL = -1;
    err << clear << "Error reading file static data area";
    return 0;
  }

  if(infile.df_gcount() != sizeof(static_data)) {
    ERROR_LEVEL = -1;
    err << clear << "Error reading file static data area";
    return 0;
  }
  
  memmove(aesdb.b.secret, secret.m_buf(), secret.length());
  aesdb.b.secret_len = secret.length();
    
  // Read the encrypted file header
  unsigned read_len = AES_MAX_INPUT_BUF_LEN + AES_file_enctryption_overhead();
  char crypt_buf[AES_CIPHERTEXT_BUF_SIZE];

  CryptFileHdr null_hdr;
  if(infile.df_Read(crypt_buf, read_len) != 
     DiskFileB::df_NO_ERROR) {
    ERROR_LEVEL = -1;
    err << clear << "Error reading file header";
    return 0;
  }
  unsigned len = infile.df_gcount();

  rv =  AES_Decrypt(crypt_buf, &len, (char *)cp.secret.m_buf(), cp.secret.length(), mode, key_iterations);
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
 
  return 1;
}

int FCryptCache::DecryptFile(const char *fname, const MemoryBuffer &secret, gxUINT32 &version, char *outfile_name)
{
  filename.Clear();
  ofname.Clear();
  int rv;
  gxDeviceTypes o_device = gxDEVICE_DISK_FILE; // Output device
  gxDeviceTypes i_device = gxDEVICE_NULL;      // No input buffering

  CryptFileHdr hdr;
  if(!DecryptFileHeader(hdr, fname, secret, version)) return 0;
  
  gxString sbuf;
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
  else { 
    ofname.SetString(hdr.fname, hdr.name_len);
  }
  
  if(!output_dir_name.is_null() && o_device == gxDEVICE_DISK_FILE) {
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

  if(o_device == gxDEVICE_DISK_FILE) {
    if(outfile.df_Create(ofname.c_str()) != DiskFileB::df_NO_ERROR) {
      ERROR_LEVEL = -1;
      err << clear << "Error opening " << ofname;
      return 0;
    }
  }

  // Setup a pointer to the cache buckets
  gxDeviceCachePtr p(cache, o_device, i_device); 
  if(!LoadFile(p)) {  // Load the file into the cache 
    if(!err.is_null()) {
      ERROR_LEVEL = -1;
      err << clear << "Error decrypting " << filename;
    }
    cp.secret.Clear(1);
    CloseInputFile();
    return 0;
  }

  Flush(); // Ensure all the buckets a written to the output device
  cp.secret.Clear(1);
  CloseOutputFile();
  CloseInputFile();
  return 1;
}

int FCryptCache::DecryptOnlyTheFileName(const char *fname, const MemoryBuffer &secret,
					gxUINT32 &version, gxString &crypt_file_name)
{

  filename.Clear();
  ofname.Clear();
  int rv;
  
  crypt_file_name.Clear();

  CryptFileHdr hdr;
  if(!DecryptFileHeader(hdr, fname, secret, version)) return 0;

     // Set the unencrypted file name
  crypt_file_name.SetString(hdr.fname, hdr.name_len);

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

  unsigned num_bytes = fwrite((const void*)static_data, sizeof(unsigned char), sizeof(static_data), fp);
  if(num_bytes != sizeof(static_data)) {
    ERROR_LEVEL = -1;
    err << clear << "Error writing static data to file " << fname;
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

  AES_fillrand(static_data, sizeof(static_data));

  offset = 0;
  while(ptr) {
    mbuf.Clear(1);
    mbuf.Cat(&ptr->data.block_header, sizeof(static_data_block_header));
    mbuf.Cat(ptr->data.rsa_ciphertext.m_buf(), ptr->data.rsa_ciphertext.length());
    mbuf.Cat(ptr->data.hmac.m_buf(), ptr->data.hmac.length());
    mbuf.Cat(ptr->data.username_encoded.c_str(), ptr->data.username_encoded.length());
    if(offset > (sizeof(static_data) - mbuf.length())) {
      ERROR_LEVEL = -11;
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
  unsigned num_blocks, next_write_address;
  return LoadStaticDataBlocks(fname, num_blocks, next_write_address);
}

int FCryptCache::LoadStaticDataBlocks(const char *fname, unsigned &num_blocks, unsigned &next_write_address)
{
  ERROR_LEVEL = 0;
  FILE *fp;
  fp = fopen(fname, "rb");
  if(!fp) {
    ERROR_LEVEL = -1;
    err << clear << "Error opening encrypted file " << fname;
    return 0;
  }

  unsigned input_bytes_read = fread(static_data, 1, sizeof(static_data), fp);
  fclose(fp);

  if(input_bytes_read != sizeof(static_data)) {
    ERROR_LEVEL = -1;
    err << clear << "Error reading static data area from file " << fname;
  }

  return LoadStaticDataBlocks(num_blocks, next_write_address);
}

int FCryptCache::LoadStaticDataBlocks(unsigned &num_blocks, unsigned &next_write_address)
{
  ERROR_LEVEL = 0;
  StaticDataBlockHdr static_data_block_header;
  StaticDataBlock static_data_block;
  unsigned block_offset = 0;
  unsigned offset = 0;
  int found_block = 0;
  int end_of_static_data = 0;
  int read_static_area = 1;
  char username_buf[1024];
  char username[1024];
  int rv;

  num_blocks = 0;
  next_write_address = 0;
  static_block_list.Clear();

  while(read_static_area) {
    if(offset >= (STATIC_DATA_AREA_SIZE-sizeof(static_data_block_header))) {
      end_of_static_data = 1;
      read_static_area = 0;
      break;
    }
    
    found_block = 0;
    block_offset = offset;
    while(!found_block) {
      if(block_offset >= (STATIC_DATA_AREA_SIZE-sizeof(static_data_block_header))) {
	end_of_static_data = 1;
	read_static_area = 0;
	break;
      }
      
      static_data_block_header.WipeHeader(); // Clear all existing header data before read
      memmove(&static_data_block_header, static_data+block_offset, sizeof(static_data_block_header));
      block_offset+=sizeof(static_data_block_header);
      if((static_data_block_header.version == STATIC_DATA_BLOCK_VERSION) && (static_data_block_header.checkword == 0xFEFE)) {
	// Found a valid block
	found_block = 1;
	num_blocks++;
	break;
      }
    }
    if(end_of_static_data) {
      read_static_area = 0;
      break;
    }
    if(found_block) {
      static_data_block.Wipe();
      static_data_block.block_header = static_data_block_header;
      
      offset+=sizeof(static_data_block_header);
      static_data_block.rsa_ciphertext.Cat(static_data+offset, static_data_block_header.ciphertext_len);
      offset+=static_data_block_header.ciphertext_len;
      static_data_block.hmac.Cat(static_data+offset, AES_MAX_HMAC_LEN);
      offset+=AES_MAX_HMAC_LEN;
      memset(username_buf, 0, sizeof(username_buf));
      memset(username, 0, sizeof(username));
      
      if(static_data_block_header.username_len > 0) {
	memmove(username_buf, static_data+offset, static_data_block_header.username_len);
	static_data_block.username_encoded = username_buf;
	gxsBase64Decode(username_buf, username);
	static_data_block.username = username;
      }
      offset+=static_data_block_header.username_len;
      static_block_list.Add(static_data_block);
    }
  }
  if(num_blocks == 0) offset = 0;
  next_write_address = offset;
  
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

  unsigned num_blocks = 0;
  unsigned next_write_address = 0;

  if(!LoadStaticDataBlocks(num_blocks, next_write_address)) return 0;
  if(ERROR_LEVEL != 0) return 0;

  gxListNode<StaticDataBlock> *ptr = static_block_list.GetHead();

  while(ptr) {
    sbuf << clear << rsa_key_username;
    if(ptr->data.username == sbuf) {
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
// ----------------------------------------------------------- // 
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
