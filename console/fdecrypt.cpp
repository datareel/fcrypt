// ------------------------------- //
// -------- start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- // 
// C++ Source Code File
// Compiler Used: MSVC, BCC32, GCC, HPUX aCC, SOLARIS CC
// Produced By: DataReel Software Development Team
// File Creation Date: 07/21/2003
// Date Last Modified: 11/20/2023
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

#ifdef __MSVC_DEBUG__
#include "leaktest.h"
#endif

// Globals
gxString debug_message;
int debug_mode = 0;
int num_buckets = 255;
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
  cout << "Usage: " << clientcfg->executable_name.c_str() << " [switches] " 
       << "filename.enc" << "\n" << flush;
  cout << "Switches: -? = Display this help message and exit." << "\n" << flush;
  cout << "          -c[num] = Specify number of cache buckets" << "\n" << flush;
  cout << "          -d[name] = Specify output DIR for enc file(s)" << "\n" << flush;
  cout << "          -D[name] = Specify and make output DIR" << "\n" << flush;
  cout << "          -k = Specify a key to use for decryption" << "\n" << flush;
  cout << "          -l = List output file name(s) in enc file(s)" << "\n" << flush;
  cout << "          -p = Input a decrypt secret" << "\n" << flush;
  cout << "          -r = Remove encrypted source file" << "\n" << flush;
  cout << "          -R = Decrypt DIR including all files and subdirectories" << "\n" << flush;
  cout << "          -v = Enable verbose messages to the console" << "\n" << flush;
  cout << "\n"; // End of list
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
	cout << "\n" << flush;
	cout << "Bad number of cache buckets specified" << "\n" << flush;
	cout << "Valid range = 1 to 65535 bytes" << "\n" << flush;
	cout << "\n" << flush;
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

    case 'p':
      CommandLinePassword.secret.Load(arg+2, strlen(arg+2));
      use_input_arg_secret = 1;
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

int ExitMessage()
{
  if(debug_mode) {
    cout << debug_message << "\n" << flush; 
  }
  cout << "Error decrypting enc file" << "\n" << flush;
  return 1;
}

int ListFileNames(CryptSecretHdr &cp) 
{
  gxListNode<gxString> *ptr = file_list.GetHead();
  int err = 0;

  while(ptr) {
    FCryptCache fc(num_buckets);
    gxString sbuf;
    gxUINT32 version;
    cout << "Encrypted name: " << ptr->data.c_str() << "\n" << flush;
    if(!fc.DecryptOnlyTheFileName(ptr->data.c_str(), cp.secret, version, sbuf)) {
      cout << "File name decrypt failed" << "\n" << flush;
      debug_message << clear << "ERROR: " << fc.err;
      err = ExitMessage();
      ptr = ptr->next;
      continue;
    }
    if(fc.ERROR_LEVEL != 0) { // Check the ERROR level from the file caching ops
      cout << "File decrypt failed" << "\n" << flush;
      debug_message << clear << "ERROR: " << fc.err;
      err = ExitMessage();
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
  clientcfg->version_str = "2023.102";

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
	  fn = arg;
	  if(futils_isdirectory(fn.c_str())) {
	    if(recurse) {
	      if(use_abs_path) cryptdb_makeabspath(fn);
	      if(futils_getcwd(curr_pwd, futils_MAX_DIR_LENGTH) != 0) {
		cout << "\n" << flush;
		cout << "Encountered fatal decrypt error" << "\n";
		cout << "Error setting current present working DIR" << "\n";
		return 1;
	      }      

	      num_dirs++;
	      if(!cryptdb_getdircontents(fn, err_str, file_list, 
					 num_files, num_dirs)) {
		cout << "\n" << flush;
		cout << "Encountered fatal decrypt error" << "\n";
		cout << err_str.c_str() << "\n";
		return 1; 
	      }

	      if(futils_chdir(curr_pwd) != 0) {
		cout << "\n" << flush;
		cout << "Encountered fatal decrypt error" << "\n";
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
    cout << "Encountered fatal decrypt error" << "\n";
    cout << "No file name specified" << "\n";
    return 1;
  }
  
  DisplayVersion();
  cout << "\n" << flush;

  CryptSecretHdr cp;
  gxString password;
  
  if(use_input_arg_key_file) {
    cout << "Using key file for encryption" << "\n" << flush;
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
  rv = err = 0;

  while(ptr) {
    FCryptCache fc(num_buckets);
    if(!output_dir_name.is_null()) {
      fc.SetDir(output_dir_name.c_str());
    }
    gxString sbuf;
    gxUINT32 version;
    cout << "Decrypting: " << ptr->data.c_str() << "\n" << flush;

    if(!fc.DecryptFile(ptr->data.c_str(), cp.secret, version)) {
      cout << "File decrypt failed" << "\n" << flush;
      debug_message << clear << "ERROR: " << fc.err;
      err = ExitMessage();
      ptr = ptr->next;
      continue;
    }
    if(fc.ERROR_LEVEL != 0) { // Check the ERROR level from the file caching ops
      cout << "File decrypt failed" << "\n" << flush;
      debug_message << clear << "ERROR: " << fc.err;
      err = ExitMessage();
      ptr = ptr->next;
      continue;
    }
    cout << "File decrypt successful" << "\n" << flush;
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
      cout << "Decrypted " << num_files << " files" 
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
