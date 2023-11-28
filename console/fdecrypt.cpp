// ------------------------------- //
// -------- start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- // 
// C++ Source Code File
// Compiler Used: MSVC, BCC32, GCC, HPUX aCC, SOLARIS CC
// Produced By: DataReel Software Development Team
// File Creation Date: 07/21/2003
// Date Last Modified: 11/27/2023
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

File decryption program. 
*/
// ----------------------------------------------------------- // 
#include "gxdlcode.h"

#if defined (__USE_ANSI_CPP__) // Use the ANSI Standard C++ library
#include <iostream>
using namespace std; // Use unqualified names for Standard C++ library
#else // Use the old iostream library by default
#include <iostream.h>
#endif // __USE_ANSI_CPP__

#include "fcrypt.h"
#include "gxlist.h"
#include "gxs_b64.h"

#ifdef __MSVC_DEBUG__
#include "leaktest.h"
#endif

// Globals
gxString debug_message;
int debug_mode = 0;
int num_buckets = 1024;
gxList<gxString> file_list;
int remove_src_file = 0;
gxString output_dir_name;
int list_file_names = 0;
int recurse = 0;
int use_abs_path = 0;
CryptSecretHdr CommandLinePassword;
int use_input_arg_secret = 0;
int use_input_arg_key_file = 0;
gxString input_arg_key_file;
MemoryBuffer key;
unsigned key_iterations =  AES_DEF_ITERATIONS;
unsigned write_to_stdout = 0;
gxString user_defined_output_file;
unsigned use_ouput_file = 0;
gxString private_rsa_key_file;
int use_private_rsa_key = 0;
unsigned char rsa_ciphertext[8192];
unsigned rsa_ciphertext_len;
char private_key[RSA_max_keybuf_len];
unsigned private_key_len = 0;

void DisplayVersion()
{
  cerr << "\n" << flush;
  cerr << clientcfg->program_name.c_str() 
       << " version " << clientcfg->version_str.c_str();
  cerr << "\n" << flush;
  cerr << clientcfg->copyright.c_str() << " " 
       << clientcfg->copyright_dates.c_str() << "\n" << flush;
  cerr << "Produced by: " << clientcfg->produced_by << "\n" << flush;
  cerr << clientcfg->support_email.c_str() << "\n" << flush;
  cerr << clientcfg->default_url.c_str() << "\n" << flush;
}

void HelpMessage() 
{
  DisplayVersion();
  cout << "\n" << flush;
  cout << "Usage: " << clientcfg->executable_name.c_str() << " [switches] " 
       << "filename.enc" << "\n" << flush;
  cout << "Switches: -? = Display this help message and exit." << "\n" << flush;
  cout << "          -c[num] = Specify number of cache buckets" << "\n" << flush;
  cout << "          -d[name] = Specify output DIR for enc file(s)" << "\n" << flush;
  cout << "          -D[name] = Specify and make output DIR" << "\n" << flush;
  cout << "          -k = Supply a key used to decrypt" << "\n" << flush;
  cout << "          -l = List output file name(s) in enc file(s)" << "\n" << flush;
  cout << "          -p = Supply a password used to decrypt" << "\n" << flush;
  cout << "          -r = Remove encrypted source file" << "\n" << flush;
  cout << "          -R = Decrypt DIR including all files and subdirectories" << "\n" << flush;
  cout << "          -v = Enable verbose messages to the console" << "\n" << flush;
  cout << "\n" << flush;
  cout << "          --iter=num (To set the number of derived key iterations)" << "\n" << flush;
  cout << "          --stdout (Write decrypted output to the console)" << "\n" << flush;
  cout << "          --outfile=fname (Write decrypt output to specified file name)" << "\n" << flush;
  cout << "          --master-rsa-key=key.pem (Use a single RSA key for decryption" << "\n" << flush;
  cout << "\n"; // End of list
}

int ProcessDashDashArg(gxString &arg)
{
  gxString sbuf, equal_arg;
  int has_valid_args = 0;
  int rv = 0;
  
  if(arg.Find("=") != -1) {
    // Look for equal arguments
    // --log-file="/var/log/my_service.log"
    equal_arg = arg;
    equal_arg.DeleteBeforeIncluding("=");
    arg.DeleteAfterIncluding("=");
    equal_arg.TrimLeading(' '); equal_arg.TrimTrailing(' ');
    equal_arg.TrimLeading('\"'); equal_arg.TrimTrailing('\"');
    equal_arg.TrimLeading('\''); equal_arg.TrimTrailing('\'');
  }

  arg.ToLower();

  // Process all -- arguments here
  if(arg == "help") {
    HelpMessage();
    return 0; // Signal program to exit
  }
  if(arg == "?") {
    HelpMessage();
    return 0; // Signal program to exit
  }

  if((arg == "version") || (arg == "ver")) {
    DisplayVersion();
    return 0; // Signal program to exit
  }

  if(arg == "iter") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: The --iter switch requires an input argument" << "\n" << flush;
      return 0;
    }
    if(equal_arg.Atoi() <= 0) {
      cerr << "ERROR: Invalid value passed to the --iter switch" << "\n" << flush;
      return 0;
    }
    key_iterations = equal_arg.Atoi();
    has_valid_args = 1;
  }

  if(arg == "outfile") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: The --outfile switch requires an input argument" << "\n" << flush;
      return 0;
    }
    user_defined_output_file = equal_arg;
    use_ouput_file = 1;
    has_valid_args = 1;
  }
  if(arg == "master-rsa-key") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --master-rsa-key missing filename: --master-rsa-key=/$HOME/keys/rsa_key.pem" << "\n" << flush;
      return 0;
    }
    private_rsa_key_file = equal_arg;
    if(!futils_exists(private_rsa_key_file.c_str())) {
	cerr << "\n" << flush;
	cerr << "ERROR: Private RSA key file " << private_rsa_key_file.c_str() << " does not exist" <<  "\n" << flush;
	cerr << "\n" << flush;
	return 0;
    }
    rv = RSA_read_key_file(private_rsa_key_file.c_str(), private_key, sizeof(private_key), &private_key_len);
    if(rv != RSA_NO_ERROR) {
      cerr << "ERROR: " << RSA_err_string(rv) << "\n" << flush;
      return 0;
    }
    unsigned char file_encryption_key[128];
    AES_fillrand(file_encryption_key, sizeof(file_encryption_key));
    key.Cat(file_encryption_key, sizeof(file_encryption_key));
    CommandLinePassword.secret = key;
    use_private_rsa_key = 1;
    has_valid_args = 1;
  }

  
  if(arg == "stdout") {
    write_to_stdout = 1;
    has_valid_args = 1;
  }
  
  arg.Clear();
  return has_valid_args;
}

int ProcessArgs(char *arg)
{
  gxString sbuf;
  CryptSecretHdr cp;
  gxString ebuf;
  
  switch(arg[1]) {
    case 'c': 
      num_buckets = (gxsPort_t)atoi(arg+2); 
      if((num_buckets < 1) || (num_buckets > 65535)) {
	cerr << "\n" << flush;
	cerr << "Bad number of cache buckets specified" << "\n" << flush;
	cerr << "Valid range = 1 to 65535 bytes" << "\n" << flush;
	cerr << "\n" << flush;
	return 0;
      }
      break;

    case 'v':
      clientcfg->verbose_mode = 1;
      debug_mode = 1;
      break;
      
    case 'h': case 'H': case '?':
      HelpMessage();
      return 0;
      
    case 'l':
      list_file_names = 1;
      break;

    case 'r' :
      remove_src_file = 1;
      break;

    case 'R':
      recurse = 1;
      break;

    case 'd':
      output_dir_name = arg+2;
      if(!futils_exists(output_dir_name.c_str())) {
	cerr << "\n" << flush;
	cerr << "Bad output DIR specified" << "\n" << flush;
	cerr << output_dir_name.c_str() << " does not exist" << "\n" << flush;
	cerr << "\n" << flush;
	return 0;
      }
      if(!futils_isdirectory(output_dir_name.c_str())) {
	cerr << "\n" << flush;
	cerr << "Bad output DIR specified" << "\n" << flush;
	cerr << output_dir_name.c_str() << " is a file name" << "\n" << flush;
	cerr << "\n" << flush;
	return 0;
      }
      break;

    case 'D':
      output_dir_name = arg+2;
      if(!futils_exists(output_dir_name.c_str())) {
	if(futils_mkdir(output_dir_name.c_str()) != 0) {
	  cerr << "\n" << flush;
	  cerr << "Error making directory" << "\n" << flush;
	  cerr << "\n" << flush;
	  return 0;
	}
      }
      if(!futils_isdirectory(output_dir_name.c_str())) {
	cerr << "\n" << flush;
	cerr << "Bad output DIR specified" << "\n" << flush;
	cerr << output_dir_name.c_str() << " is a file name" << "\n" << flush;
	cerr << "\n" << flush;
	return 0;
      }
      break;

    case 'p':
      CommandLinePassword.secret.Load(arg+2, strlen(arg+2));
      use_input_arg_secret = 1;
      break;

    case 'k':
      input_arg_key_file = arg+2;
      if(!futils_exists(input_arg_key_file.c_str())) {
	cerr << "\n" << flush;
	cerr << "ERROR: Key file " << input_arg_key_file.c_str() << " does not exist" <<  "\n" << flush;
	cerr << "\n" << flush;
	return 0;
      }
      if(read_key_file(input_arg_key_file.c_str(), key, ebuf) != 0) {
	cerr << "\n" << flush;
	cerr << "ERROR: " << ebuf.c_str() << "\n" << flush;
	cerr << "\n" << flush;
	return 0;
      }
      CommandLinePassword.secret = key;
      use_input_arg_key_file  = 1;
      break;

    case '-':
      sbuf = arg+2; 
      // Add all -- prepend filters here
      sbuf.TrimLeading('-');
      if(!ProcessDashDashArg(sbuf)) return 0;
      break;

    default:
      cerr << "\n" << flush;
      cerr << "Unknown switch " << arg << "\n" << flush;
      cerr << "Exiting..." << "\n" << flush;
      cerr << "\n" << flush;
      return 0;
  }
  arg[0] = '\0';

  return 1; // All command line arguments were valid
}

int ExitMessage()
{
  if(debug_mode) {
    cerr << debug_message << "\n" << flush; 
  }
  cerr << "Error decrypting enc file" << "\n" << flush;
  return 1;
}

int ListFileNames(CryptSecretHdr &cp) 
{
  gxListNode<gxString> *ptr = file_list.GetHead();

  while(ptr) {
    FCryptCache fc(num_buckets);
    fc.key_iterations = key_iterations;
    gxString sbuf;
    gxUINT32 version;
    cout << "Encrypted name: " << ptr->data.c_str() << "\n" << flush;
    if(!fc.DecryptOnlyTheFileName(ptr->data.c_str(), cp.secret, version, sbuf)) {
      cerr << "File name decrypt failed" << "\n" << flush;
      debug_message << clear << "ERROR: " << fc.err;
      ExitMessage();
      ptr = ptr->next;
      continue;
    }
    if(fc.ERROR_LEVEL != 0) { // Check the ERROR level from the file caching ops
      cerr << "File decrypt failed" << "\n" << flush;
      debug_message << clear << "ERROR: " << fc.err;
      ExitMessage();
      ptr = ptr->next;
      continue;
    }
    cout << "Decrypted name: " << sbuf.c_str() << "\n" << flush;
    ptr = ptr->next;
  }

  return 0;
}

int main(int argc, char **argv)
{
#ifdef __MSVC_DEBUG__
  InitLeakTest();
#endif

  AES_openssl_init();
  
  // Set the program information
  clientcfg->executable_name = "fdecrypt";
  clientcfg->program_name = "File Decrypt";
  clientcfg->version_str = "2023.103";

  if(argc < 2) {
    HelpMessage();
    return 1;
  }

  clientcfg->executable_name = argv[0]; // Set the name of this executable
  int narg;
  char *arg = argv[narg = 1];
  gxString fn;
  int num_files = 0;
  int err;
  gxString err_str;
  int num_dirs = 0;

  char top_pwd[futils_MAX_DIR_LENGTH];
  char curr_pwd[futils_MAX_DIR_LENGTH];
  if(futils_getcwd(top_pwd, futils_MAX_DIR_LENGTH) != 0) {
    cerr << "\n" << flush;
    cerr << "Encountered fatal fcrypt error" << "\n";
    cerr << "Error setting top present working DIR" << "\n";
    return 1;
  }

  if(argc >= 2) {
    while (narg < argc) {
      if (arg[0] != '\0') {
	if (arg[0] == '-') { // Look for command line arguments
	  if(!ProcessArgs(arg)) return 1; // Exit if argument is not valid
	}
	else { 
	  fn = arg;
	  if(futils_isdirectory(fn.c_str())) {
	    if(recurse) {
	      if(use_abs_path) cryptdb_makeabspath(fn);
	      if(futils_getcwd(curr_pwd, futils_MAX_DIR_LENGTH) != 0) {
		cerr << "\n" << flush;
		cerr << "Encountered fatal decrypt error" << "\n";
		cerr << "Error setting current present working DIR" << "\n";
		return 1;
	      }      

	      num_dirs++;
	      if(!cryptdb_getdircontents(fn, err_str, file_list, 
					 num_files, num_dirs)) {
		cerr << "\n" << flush;
		cerr << "Encountered fatal decrypt error" << "\n";
		cerr << err_str.c_str() << "\n";
		return 1; 
	      }

	      if(futils_chdir(curr_pwd) != 0) {
		cerr << "\n" << flush;
		cerr << "Encountered fatal decrypt error" << "\n";
		cerr << "Error resetting current present working DIR" << "\n";
		return 1;
	      }

	    }
	  }
	  else {
	    num_files++;
	    if(use_abs_path) cryptdb_makeabspath(fn);
	    file_list.Add(fn);
	  }
	}
	arg = argv[++narg];
      }
    }
  }

  if(num_files == 0) {
    cerr << "\n" << flush;
    cerr << "Encountered fatal decrypt error" << "\n";
    cerr << "No file name specified" << "\n";
    return 1;
  }
  
  DisplayVersion();
  cerr << "\n" << flush;

  CryptSecretHdr cp;
  gxString password;
  
  if(use_input_arg_key_file) {
    cerr << "Using key file for decryption" << "\n" << flush;
  }

  if(use_private_rsa_key) {
    cerr << "Using private RSA key file for decryption" << "\n" << flush;
  }
  
  if(CommandLinePassword.secret.is_null()) {
    cout << "Password: " << flush;
    if(!consoleGetString(password, 1)) {
      password.Clear(1);
      cout << "Invalid entry!" << "\n" << flush;
      return 1;
    }
    cp.secret.Load(password.c_str(), password.length());
    password.Clear(1);
    cout << "\n" << flush;
  }
  else {
    cp.secret = CommandLinePassword.secret;
    CommandLinePassword.Reset();
  }
  
  // List the file names and return
  if(list_file_names) return ListFileNames(cp);

  gxListNode<gxString> *ptr = file_list.GetHead();
  err = 0;
  int rv = 0;
  
  while(ptr) {
    cerr << "Decrypting: " << ptr->data.c_str() << "\n" << flush;
    
    if(use_private_rsa_key) {
      FILE *fp;
      fp = fopen(ptr->data.c_str(), "rb");
      if(!fp) {
	cerr << "ERROR: Error opening file " << ptr->data.c_str() << "\n" << flush; ;
	ptr = ptr->next;
	continue;
      }
      unsigned char read_buf[STATIC_DATA_AREA_SIZE];
      unsigned input_bytes_read = 0;
      memset(read_buf, 0, sizeof(read_buf));
      input_bytes_read = fread((unsigned char *)read_buf, 1, sizeof(read_buf), fp);
      if(input_bytes_read != STATIC_DATA_AREA_SIZE) {
	fclose(fp);
	cerr << "ERROR: Error reading data area blocks from file " << ptr->data.c_str() << "\n" << flush; ;
	ptr = ptr->next;
	continue;
      }
      fclose(fp);
      int offset = 0;
      StaticDataBlockHdr static_data_block_header;
      unsigned char hash[AES_MAX_HMAC_LEN];
      unsigned char r_hash[AES_MAX_HMAC_LEN];
      char username_buf[1024];
      char username[1024];
      unsigned decrypted_data_len = 0;
      unsigned char rsa_decrypted_message[2048];
 
      memset(username_buf, 0, sizeof(username_buf));
      memset(username, 0, sizeof(username));
      memset(rsa_decrypted_message, 0, sizeof(rsa_decrypted_message));
      
      memmove(&static_data_block_header, read_buf, sizeof(static_data_block_header));
      offset+=sizeof(static_data_block_header);
      
      if(static_data_block_header.version != STATIC_DATA_BLOCK_VERSION) {
	cerr << "ERROR: Bad data block version in file " << ptr->data.c_str() << "\n" << flush; ;
	ptr = ptr->next;
	continue;
      }
      if(static_data_block_header.checkword != 0xFEFE) {
	cerr << "ERROR: Bad data block checkword in file " << ptr->data.c_str() << "\n" << flush; ;
	ptr = ptr->next;
	continue;
      }
      
      memmove(rsa_ciphertext, read_buf+offset, static_data_block_header.ciphertext_len);
      offset+=static_data_block_header.ciphertext_len;

      rv = RSA_private_key_decrypt((const unsigned char *)private_key, private_key_len,
				   rsa_ciphertext, static_data_block_header.ciphertext_len,
				   rsa_decrypted_message, sizeof(rsa_decrypted_message), &decrypted_data_len);
      if(rv != RSA_NO_ERROR) {
	cerr << "ERROR: " << RSA_err_string(rv) << "\n" << flush; 
	ptr = ptr->next;
	continue;
      }
      cp.secret.Clear(1);
      cp.secret.Cat(rsa_decrypted_message, decrypted_data_len);

      memmove(r_hash, read_buf+offset, sizeof(r_hash));
      offset+=sizeof(hash);
      
      rv = AES_HMAC(cp.secret.m_buf(), cp.secret.length(), rsa_ciphertext, static_data_block_header.ciphertext_len, hash, sizeof(hash));
      if(rv != AES_NO_ERROR) {
	cerr << "ERROR: Failed to generate HMAC for RSA ciphertext" << "\n" << flush;
	ptr = ptr->next;
	continue;
      }
      if(memcmp(hash, r_hash, sizeof(hash)) != 0) {
	cerr << "ERROR: Message authentication failed bad HMAC for RSA ciphertext" << "\n" << flush;
	ptr = ptr->next;
	continue;
      }

      if(static_data_block_header.username_len > 0) {
	if(static_data_block_header.username_len > MAX_USERNAME_LEN) {
	  cerr << "ERROR: Username length for RSA key has exceeded max lenght of " << MAX_USERNAME_LEN << "\n" << flush;
	  ptr = ptr->next;
	  continue;
	}
	memmove(username_buf, read_buf+offset, static_data_block_header.username_len);
	gxsBase64Decode(username_buf, username);
	cerr << "RSA key username " <<  username << "\n" << flush;
      }
      offset+=static_data_block_header.username_len;
    }

    FCryptCache fc(num_buckets);
    fc.key_iterations = key_iterations;
    if(!output_dir_name.is_null()) {
      fc.SetDir(output_dir_name.c_str());
    }
    gxString sbuf;
    gxUINT32 version;
    int rv = 0;

    if(write_to_stdout) {
      rv = fc.DecryptFile(ptr->data.c_str(), cp.secret, version, "stdout");
    }
    else {
      if(use_ouput_file) {
	rv = fc.DecryptFile(ptr->data.c_str(), cp.secret, version, user_defined_output_file.c_str());
      }
      else {
	rv = fc.DecryptFile(ptr->data.c_str(), cp.secret, version);
      }
    }
    
    if(!rv) {
      cerr << "File decrypt failed" << "\n" << flush;
      debug_message << clear << "ERROR: " << fc.err;
      err = ExitMessage();
      ptr = ptr->next;
      continue;
    }
    if(fc.ERROR_LEVEL != 0) { // Check the ERROR level from the file caching ops
      cerr << "File decrypt failed" << "\n" << flush;
      debug_message << clear << "ERROR: " << fc.err;
      err = ExitMessage();
      ptr = ptr->next;
      continue;
    }
    cerr << "File decrypt successful" << "\n" << flush;
    sbuf << clear << wn << fc.BytesWrote();
    cerr << "Wrote " << sbuf.c_str() << " bytes to "
	 << fc.OutFileName() << "\n" << flush;

    if(remove_src_file) {
      if(futils_remove(ptr->data.c_str()) != 0) {
	cerr << "ERROR: Error removing " << ptr->data.c_str() << " source file"
	     << "\n" << flush;
      }
    }
    ptr = ptr->next;
  }

  if(err == 0) {
    if(num_files > 1) {
      cerr << "Decrypted " << num_files << " files" 
	   << "\n" << flush;
    }
    if(num_dirs > 0) {
      cerr << "Traversed " << num_dirs << " directories"  
	   << "\n" << flush;
    }
  }

  return err;
}
// ----------------------------------------------------------- // 
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
