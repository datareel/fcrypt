// ------------------------------- //
// -------- start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- // 
// C++ Source Code File
// Compiler Used: MSVC, BCC32, GCC, HPUX aCC, SOLARIS CC
// Produced By: DataReel Software Development Team
// File Creation Date: 07/21/2003
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

File encryption program. 
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

#ifdef __MSVC_DEBUG__
#include "leaktest.h"
#endif

#include "devcache.h"
#include "memblock.h"
#include "gxlist.h"
#include "gxbstree.h"
#include "bstreei.h"
#include "gxs_b64.h"

// Globals
int num_buckets = 1024;
int overwrite = 0;
int mode = -1;
unsigned key_iterations =  AES_DEF_ITERATIONS;
int remove_src_file = 0;
gxList<gxString> file_list;
gxString en_dot_ext(".enc");
gxString output_file_name;
gxString output_dir_name;
int gen_file_names = 0;
int recurse = 0;
int use_abs_path = 0;
CryptSecretHdr CommandLinePassword;
int use_input_arg_secret = 0;
int use_input_arg_key_file = 0;
gxString input_arg_key_file;
MemoryBuffer key;
gxString public_rsa_key_file;
int add_rsa_key = 0;
unsigned char rsa_ciphertext[8192];
unsigned rsa_ciphertext_len;
gxString rsa_key_username;
char public_key[RSA_max_keybuf_len];
unsigned public_key_len = 0;

void DisplayVersion()
{
  cout << "\n" << flush;
  cout << clientcfg->program_name.c_str() 
       << " version " << clientcfg->version_str.c_str();
  cout << "\n" << flush;
  cout << clientcfg->copyright.c_str() << " " 
       << clientcfg->copyright_dates.c_str() << "\n" << flush;
  cout << "Produced by: " << clientcfg->produced_by << "\n" << flush;
  cout << clientcfg->support_email.c_str() << "\n" << flush;
  cout << clientcfg->default_url.c_str() << "\n" << flush;
}

void HelpMessage() 
{
  DisplayVersion();
  cout << "\n" << flush;
  cout << "Usage: " << clientcfg->executable_name.c_str() << " [switches] " << "filename" << "\n" << flush;
  cout << "Switches: -? = Display this help message and exit." << "\n" << flush;  
  cout << "          -0 = No encryption for testing only." << "\n" << flush;
  cout << "          -3 = 256-bit encryption (default)." << "\n" << flush;
  cout << "          -b[size] = Specify file buffer size in bytes" << "\n" << flush;
  cout << "          -c[num] = Specify number of cache buckets" << "\n" << flush;
  cout << "          -d[name] = Specify output DIR for enc file(s)" << "\n" << flush;
  cout << "          -D[name] = Specify and make output DIR" << "\n" << flush;
  cout << "          -f[name] = Specify output file and DIR name" << "\n" << flush;
  cout << "          -g = Generate hashed output file names" << "\n" << flush;
  cout << "          -k = Supply a key used to encrypt file" << "\n" << flush;
  cout << "          -o = Overwrite existing enc file(s)" << "\n" << flush;
  cout << "          -p = Supply a password used to encrypt" << "\n" << flush;
  cout << "          -r = Remove unencrypted source file(s)" << "\n" << flush;
  cout << "          -R = Encrypt DIR including all files and subdirectories" << "\n" << flush;
  cout << "          -v = Enable verbose messages to the console" << "\n" << flush;
  cout << "          -x[ext] = Specify enc file(s) dot extension" << "\n" << flush;
  cout << "\n" << flush;
  cout << "          --iter=num (Set the number of derived key iterations)" << "\n" << flush;
  cout << "          --add-rsa-key=pubkey.pem (Add access to an encrypted file for another users RSA key)" << "\n" << flush;
  cout << "          --rsa-key-username=name (Assign a name to the public RSA key)" << "\n" << flush;
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
      cout << "ERROR: --iter requires an input argument: --iter=10000" << "\n" << flush;
      return 0;
    }
    if(equal_arg.Atoi() <= 0) {
      cout << "ERROR: Invalid value passed to --iter" << "\n" << flush;
      return 0;
    }
    key_iterations = equal_arg.Atoi();
    has_valid_args = 1;
  }

  if(arg == "add-rsa-key") {
    if(equal_arg.is_null()) {
      cout << "ERROR: --add-rsa-key missing filename: --add-rsa-key=/$HOME/keys/rsa_pubkey.pem" << "\n" << flush;
      return 0;
    }
    public_rsa_key_file = equal_arg;
    if(!futils_exists(public_rsa_key_file.c_str())) {
        cout << "\n" << flush;
        cout << "ERROR: Public RSA key file " << public_rsa_key_file.c_str() << " does not exist" <<  "\n" << flush;
        cout << "\n" << flush;
        return 0;
    }
    rv = RSA_read_key_file(public_rsa_key_file.c_str(), public_key, sizeof(public_key), &public_key_len);
    if(rv != RSA_NO_ERROR) {
      std::cout << "ERROR: " << RSA_err_string(rv) << "\n" << std::flush;
      return 0;
    }
    add_rsa_key = 1;
    has_valid_args = 1;
  }
  
  if(arg == "rsa-key-username") {
    if(equal_arg.is_null()) {
      cout << "ERROR: --rsa-key-username missing name: --rsa-key-username=$(whoami)" << "\n" << flush;
      return 0;
    }
    rsa_key_username = equal_arg;
    has_valid_args = 1;
  }
  arg.Clear();
  return has_valid_args;
}

int ProcessArgs(char *arg)
{
  gxString sbuf;
  gxString ebuf;
  switch(arg[1]) {
    case 'c':
      num_buckets = (gxsPort_t)atoi(arg+2); 
      if((num_buckets < 1) || (num_buckets > 65535)) {
	cout << "\n" << flush;
	cout << "Bad number of cache buckets specified" << "\n" << flush;
	cout << "Valid range = 1 to 65535 bytes" << "\n" << flush;
	cout << "\n" << flush;
	return 0;
      }
      break;
      
    case 'x':
      en_dot_ext = arg+2;
      if(en_dot_ext[0] != '.') {
	en_dot_ext.InsertAt(0, ".", 1);
      }
      break;

    case 'd':
      output_dir_name = arg+2;
      if(!futils_exists(output_dir_name.c_str())) {
	cout << "\n" << flush;
	cout << "Bad output DIR specified" << "\n" << flush;
	cout << output_dir_name.c_str() << " does not exist" << "\n" << flush;
	cout << "\n" << flush;
	return 0;
      }
      if(!futils_isdirectory(output_dir_name.c_str())) {
	cout << "\n" << flush;
	cout << "Bad output DIR specified" << "\n" << flush;
	cout << output_dir_name.c_str() << " is a file name" << "\n" << flush;
	cout << "\n" << flush;
	return 0;
      }
      break;

    case 'p':
      CommandLinePassword.secret.Load(arg+2, strlen(arg+2));
      use_input_arg_secret = 1;
      break;

    case 'f':
      output_file_name = arg+2;
      break;

    case 'g':
      gen_file_names = 1;
      break;

    case 'D':
      output_dir_name = arg+2;
      if(!futils_exists(output_dir_name.c_str())) {
	if(futils_mkdir(output_dir_name.c_str()) != 0) {
	  cout << "\n" << flush;
	  cout << "Error making directory" << "\n" << flush;
	  cout << "\n" << flush;
	  return 0;
	}
      }
      if(!futils_isdirectory(output_dir_name.c_str())) {
	cout << "\n" << flush;
	cout << "Bad output DIR specified" << "\n" << flush;
	cout << output_dir_name.c_str() << " is a file name" << "\n" << flush;
	cout << "\n" << flush;
	return 0;
      }
      break;

    case '0': 
      mode = 0;
      break;

    case '3': 
      mode = 3;
      break;

    case 'o': case 'O':
      overwrite = 1;
      break;

    case 'r':
      remove_src_file = 1;
      break;

    case 'R':
      recurse = 1;
      break;

    case 'v': 
      clientcfg->verbose_mode = 1;
      break;

    case 'k':
      input_arg_key_file = arg+2;
      if(!futils_exists(input_arg_key_file.c_str())) {
	cout << "\n" << flush;
	cout << "ERROR: Key file " << input_arg_key_file.c_str() << " does not exist" <<  "\n" << flush;
	cout << "\n" << flush;
	return 0;
      }
      if(read_key_file(input_arg_key_file.c_str(), key, ebuf) != 0) {
	cout << "\n" << flush;
	cout << "ERROR: " << ebuf.c_str() << "\n" << flush;
	cout << "\n" << flush;
	return 0;
      }
      CommandLinePassword.secret = key;
      use_input_arg_key_file  = 1;
      break;
      
    case 'h': case 'H': case '?':
      HelpMessage();
      return 0;

    case '-':
      sbuf = arg+2; 
      // Add all -- prepend filters here
      sbuf.TrimLeading('-');
      if(!ProcessDashDashArg(sbuf)) return 0;
      break;
      
    default:
      cout << "\n" << flush;
      cout << "Unknown switch " << arg << "\n" << flush;
      cout << "Exiting..." << "\n" << flush;
      cout << "\n" << flush;
      return 0;
  }
  arg[0] = '\0';

  return 1; // All command line arguments were valid
}

int main(int argc, char **argv)
{
#ifdef __MSVC_DEBUG__
  InitLeakTest();
#endif

  AES_openssl_init();
  
  // Set the program information
  clientcfg->executable_name = "fcrypt";
  clientcfg->program_name = "File Encrypt";
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
  int rv, err;
  gxString err_str;
  int num_dirs = 0;

  char top_pwd[futils_MAX_DIR_LENGTH];
  char curr_pwd[futils_MAX_DIR_LENGTH];
  if(futils_getcwd(top_pwd, futils_MAX_DIR_LENGTH) != 0) {
    cout << "\n" << flush;
    cout << "Encountered fatal fcrypt error" << "\n";
    cout << "Error setting top present working DIR" << "\n";
    return 1;
  }

  if(argc >= 2) {
    while (narg < argc) {
      if (arg[0] != '\0') {
	if (arg[0] == '-') { // Look for command line arguments
	  if(!ProcessArgs(arg)) return 1; // Exit if argument is not valid
	}
	else { 
	  // Process the command line string after last - argument
	  fn = arg;
	  if(futils_isdirectory(fn.c_str())) {
	    if(recurse) {
	      if(use_abs_path) cryptdb_makeabspath(fn);
	      if(futils_getcwd(curr_pwd, futils_MAX_DIR_LENGTH) != 0) {
		cout << "\n" << flush;
		cout << "Encountered fatal fcrypt error" << "\n";
		cout << "Error setting current present working DIR" << "\n";
		return 1;
	      }      

	      num_dirs++;
	      if(!cryptdb_getdircontents(fn, err_str, file_list, 
					 num_files, num_dirs)) {
		cout << "\n" << flush;
		cout << "Encountered fatal fcrypt error" << "\n";
		cout << err_str.c_str() << "\n";
		return 1; 
	      }

	      if(futils_chdir(curr_pwd) != 0) {
		cout << "\n" << flush;
		cout << "Encountered fatal fcrypt error" << "\n";
		cout << "Error resetting current present working DIR" << "\n";
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
    cout << "\n" << flush;
    cout << "Encountered fatal fcrypt error" << "\n";
    cout << "No file name specified" << "\n";
    return 1;
  }
  
  if(futils_chdir(top_pwd) != 0) {
    cout << "\n" << flush;
    cout << "Encountered fatal fcrypt error" << "\n";
    cout << "Error resetting top present working DIR" << "\n";
    return 1;
  }

  DisplayVersion();
  cout << "\n" << flush;

  CryptSecretHdr cp;
  CryptSecretHdr tmp_cp;
  gxString password, password2;
  
  if(use_input_arg_key_file) {
    if(add_rsa_key) {
      cout << "Using symmetric key to add an RSA user key to an encrypted file" << "\n" << flush;
      cp.secret = CommandLinePassword.secret;
    }
    else {
      cout << "Using symmetric key for file encryption" << "\n" << flush;
    }
  }
  else {
    if(add_rsa_key) {
      cout << "Using password to add an RSA user key to an encrypted file" << "\n" << flush;
      if(CommandLinePassword.secret.is_null()) {
	cout << "Password: " << flush;
	if(!consoleGetString(password, 1)) {
	  password.Clear(1);
	  cout << "Invalid entry!" << "\n" << flush;
	  return 1;
	}
	cp.secret.Load(password.c_str(), password.length());
	password.Clear(1);
      }
    }
    else {
      cout << "Using password for symmetric file encryption" << "\n" << flush;
    }
  }

  gxListNode<gxString> *ptr = file_list.GetHead();
  tmp_cp = cp;
  rv = err = 0;
  unsigned offset = 0;

  if(add_rsa_key) {
    if(rsa_key_username.is_null()) {
      cout << "\n" << flush;
      cout << "ERROR: --add-rsa-key requires --rsa-key-username" << "\n" << flush;
      cout << "\n" << flush;
      return 1;
    }

    cout << "Adding RSA key for user " << rsa_key_username.c_str() << " to encrypted file " << ptr->data.c_str() << "\n" << flush;

    RSA_openssl_init();
    memset(rsa_ciphertext, 0, sizeof(rsa_ciphertext));
    rv = RSA_public_key_encrypt((const unsigned char *)public_key, public_key_len,
				cp.secret.m_buf(), cp.secret.length(),
				rsa_ciphertext, sizeof(rsa_ciphertext), &rsa_ciphertext_len);
    if(rv != RSA_NO_ERROR) {
      std::cout << "ERROR: " << RSA_err_string(rv) << "\n" << std::flush;
      return 1;
    }

    while(ptr) {
      FCryptCache fc(num_buckets);
      fc.key_iterations = key_iterations;
      if(!fc.AddRSAKeyToStaticArea(ptr->data.c_str(), cp.secret, public_key, public_key_len, rsa_key_username.c_str())) {
	cout << "ERROR: " << fc.err.c_str() << "\n" << flush;
      }
      cout << "Public RSA key " << rsa_key_username.c_str() << " added to " << ptr->data.c_str() << "\n" << flush;
      ptr = ptr->next;
    }
    return 0;
  }


  if(CommandLinePassword.secret.is_null()) {
    cout << "Password: " << flush;
    if(!consoleGetString(password, 1)) {
      password.Clear(1);
      cout << "Invalid entry!" << "\n" << flush;
      return 1;
    }
    cout << "\n" << flush;
    if((int)password.length() < AES_MIN_SECRET_LEN) {
      cout << "Password does not meet length requirement" 
	   << "\n" << flush;
      cout << "Password must be at least " << AES_MIN_SECRET_LEN 
	   << " characters long" << "\n" << flush;
      password.Clear(1);
      return 1;
    }
    cout << "Retype password: " << flush;
    if(!consoleGetString(password2, 1)) {
      password.Clear(1);
      password2.Clear(1);
      cout << "Invalid entry!" << "\n" << flush;
      return 1;
    }
    cout << "\n" << flush;
    if(password != password2) {
      password.Clear(1);
      password2.Clear(1);
      cout << "Passwords do not match" << "\n" << flush;
      return 1;
    }
    cp.secret.Load(password.c_str(), password.length());
    password.Clear(1);
    password2.Clear(1);
  }
  else {
    cp.secret = CommandLinePassword.secret;
    CommandLinePassword.Reset();
    if((int)cp.secret.length() < AES_MIN_SECRET_LEN) {
      cout << "Password does not meet length requirement" 
	   << "\n" << flush;
      cout << "Password must be at least " << AES_MIN_SECRET_LEN 
	   << " characters long" << "\n" << flush;
      return 1;
    }
  }
  
  while(ptr) {
    FCryptCache fc(num_buckets);
    fc.mode = mode;
    fc.key_iterations = key_iterations;
    fc.SetOverWrite(overwrite);
    fc.SetDotExt(en_dot_ext.c_str());
    if(!output_dir_name.is_null()) {
      fc.SetDir(output_dir_name.c_str());
    }
    if(!output_file_name.is_null()) {
      fc.SetOutputFileName(output_file_name.c_str());
    }
    if(gen_file_names) {
      fc.GenFileNames();
    }
    gxString sbuf;

    if(clientcfg->verbose_mode) {
      cout << "Encrypting:      " << ptr->data.c_str() << "\n" << flush;
      if(mode == -1 || mode == 3) {
	cout << "Encryption mode: " << "AES 256 CBC" << "\n" << flush;
      }
      else {
	cout << "Encryption mode: " << mode << "\n" << flush;
      }
      cout << "Key iterations:  " << key_iterations << "\n" << flush;
      cout << "Cache buckets:   " << num_buckets << "\n" << flush;
    }
    else {
      cout << "Encrypting: " << ptr->data.c_str() << "\n" << flush;
    }
    if(fc.mode == 0) cout << "\n" << "WARNING: Using mode 0 for test only - WARNING: Output file will not be encrypted" << "\n\n"<< flush;

    rv = fc.EncryptFile(ptr->data.c_str(), cp.secret);
    cp = tmp_cp;
    if(!rv) {
      cout << "File encryption failed" << "\n" << flush;
      cout << fc.err.c_str() << "\n" << flush;
      ptr = ptr->next;
      err = 1;
      ptr = ptr->next;
      continue;
    } 

    cout << "File encrypt successful" << "\n" << flush;
    sbuf << clear << wn << fc.BytesWrote();
    cout << "Wrote " << sbuf.c_str() << " bytes to "
	 << fc.OutFileName() << "\n" << flush;

    if(remove_src_file) {
      if(futils_remove(ptr->data.c_str()) != 0) {
	cout << "Error removing " << ptr->data.c_str() << " source file"
	     << "\n" << flush;
      }
    }

    ptr = ptr->next;
  }

  if(err == 0) {
    if(num_files > 1) {
      cout << "Encrypted " << num_files << " files" 
	   << "\n" << flush;
    }
    if(num_dirs > 0) {
      cout << "Traversed " << num_dirs << " directories"  
	   << "\n" << flush;
    }
  }

  return err;
}
// ----------------------------------------------------------- // 
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
