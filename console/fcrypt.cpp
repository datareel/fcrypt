// ------------------------------- //
// -------- start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- // 
// C++ Source Code File
// Compiler Used: MSVC, BCC32, GCC, HPUX aCC, SOLARIS CC
// Produced By: DataReel Software Development Team
// File Creation Date: 07/21/2003
// Date Last Modified: 12/10/2023
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

#include <unistd.h>
#include <fcntl.h>

// Globals
gxString debug_message;
int debug_mode = 0;
int debug_level = 1;
int num_buckets = 1024;
int overwrite = 0;
int mode = -1;
unsigned key_iterations =  AES_DEF_ITERATIONS;
int remove_src_file = 0;
gxList<gxString> file_list;
gxString en_dot_ext(".enc");
gxString output_file_name;
gxString output_dir_name;
int recurse = 0;
int use_abs_path = 0;
int use_password = 0;
int use_key_file = 0;
gxString input_arg_key_file;
MemoryBuffer aes_file_encrypt_secret;
MemoryBuffer key;
gxString password;
gxString password2;
gxString public_rsa_key_file;
int add_rsa_key = 0;
unsigned char rsa_ciphertext[8192];
unsigned rsa_ciphertext_len;
gxString rsa_key_username;
char public_key[RSA_max_keybuf_len];
unsigned public_key_len = 0;
gxString rsa_key_passphrase;
int has_passphrase = 0;
unsigned static_data_size = DEFAULT_STATIC_DATA_AREA_SIZE;
gxString decrypted_output_filename;
#ifdef __ENABLE_SMART_CARD__
SmartCardOB sc;
gxString smartcard_cert_username;
int add_smart_card = 0;
int use_smartcard_cert = 0;
int use_smartcard_cert_file = 0;
gxString smartcard_cert_file;
#endif

// Functions
void DisplayVersion();
void HelpMessage();
int ProcessDashDashArg(gxString &arg);
int ProcessArgs(char *arg);
int DEBUG_m(char *message, int level = 1, int rv = 0);
int ExitProgram(int rv = 0, char *exit_message = 0);

void DisplayVersion()
{
  cout << "\n" << flush;
  cout << clientcfg->program_name.c_str() 
       << " version " << clientcfg->version_str.c_str();
  cout << "\n" << flush;
  cout << clientcfg->copyright.c_str() << " " 
       << clientcfg->copyright_dates.c_str() << "\n" << flush;
  cout << "Produced by: " << clientcfg->produced_by << "\n" << flush;
  cout << clientcfg->default_url.c_str() << "\n" << flush;
  cout << "\n" << flush;
  cout << "Encryption engine: Openssl" << "\n" << flush;
  cout << "Version string: " << OPENSSL_VERSION_TEXT << "\n" << flush;
  cout << "Version number: 0x" << hex << OPENSSL_VERSION_NUMBER << "\n" << flush;
#ifdef __ENABLE_SMART_CARD__
  cout << "\n" << flush;
  cout << "Smart card enabled for " << SC_get_default_engine_ID() << "\n" << flush;
#else
  cout << "\n" << flush;
  cout << "Smart card support is not enabled" << "\n" << flush;
#endif
}

void HelpMessage() 
{
  DisplayVersion();
  cout << "\n" << flush;
  cout << "Usage: " << clientcfg->executable_name.c_str() << " [switches] " << "filename" << "\n" << flush;
  cout << "Switches: -? = Display this help message and exit." << "\n" << flush;  
  if(debug_mode) {
    cout << "          -0 = No encryption for testing only." << "\n" << flush;
    cout << "          -3 = 256-bit encryption (default)." << "\n" << flush;
  }
  cout << "          -d  Enable debugging output" << "\n" << flush;  
  cout << "          -h  Display this help message and exit." << "\n" << flush;
  cout << "          -o  Overwrite existing enc file(s)" << "\n" << flush;
  cout << "          -r  Remove unencrypted source file(s)" << "\n" << flush;
  cout << "          -R  Encrypt DIR including all files and subdirectories" << "\n" << flush;
  cout << "          -v  Enable verbose messages to the console" << "\n" << flush;
  cout << "\n" << flush;
  cout << "          --add-rsa-key (Add access to an encrypted file for another users public RSA key)" << "\n" << flush;
  cout << "          --add-rsa-key input args can be a public key file name or a pipe" << "\n" << flush;
  cout << "          --cache=size (Set the cache size)" << "\n" << flush;
  cout << "          --debug (Turn on debugging and set optional level)" << "\n" << flush;
  cout << "          --decrypted-outfile=fname (Tell fdecrypt to write the decrypted output to specified file name)" << "\n" << flush;
  cout << "          --ext=.enc (Dot extension used for encrypted files)" << "\n" << flush;
  cout << "          --help (Display this help message and exit." << "\n" << flush;
  cout << "          --iter=num (Set the number of derived key iterations)" << "\n" << flush;
  cout << "          --key=aes_key (Use a key file for symmetric file encryption)" << "\n" << flush;
  cout << "          --outfile=fname (Write encrypted output to specified file name)" << "\n" << flush;
  cout << "          --outdir=dir (Write encrypted output to this directory)" << "\n" << flush;
  cout << "          --password (Use a password for symmetric file encryption)" << "\n" << flush;
  cout << "          --rsa-key-passphrase (Passphrase for public RSA key)" << "\n" << flush;
  cout << "          --rsa-key-username=name (Assign a name to the public RSA key)" << "\n" << flush;
  cout << "          --static-data-size=num (Set size of static data storage area)" << "\n" << flush;  
  cout << "          --verbose (Turn on verbose output)" << "\n" << flush;  
  cout << "          --version (Display program version number)" << "\n" << flush;
#ifdef __ENABLE_SMART_CARD__
  cout << "\n" << flush;
  cout << "          --add-smartcard-cert (Add access to encrypted file for a smart card)" << "\n" << flush;
  cout << "          --smartcard-username=name (Assign a name to smart card cert)" << "\n" << flush;
  cout << "          --smartcard-cert-id=" << SC_get_default_cert_id() << " (Set the ID number for the smart card cert)" << "\n" << flush;
  cout << "          --smartcard-engine=" << SC_get_default_enginePath() << " (Set the smart card engine path)" << "\n" << flush;
  cout << "          --smartcard-provider=" << SC_get_default_modulePath() << " (Set the smart card provider)" << "\n" << flush;
  cout << "\n" << flush;
  cout << "          --add-smartcard-cert-file (Add access to an encrypted file for another users exported smart card cert)" << "\n" << flush;
  cout << "          --add-smartcard-cert-file input arg must be a file name" << "\n" << flush;
#endif // __ENABLE_SMART_CARD__

  cout << "\n"; // End of list
}

int ProcessDashDashArg(gxString &arg)
{
  gxString sbuf, equal_arg, ebuf;
  int has_valid_args = 0;
  int rv = 0;
  char buf[1];
  unsigned bytes_read = 0;

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

  if(arg == "cache") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --cache requires an input argument" << "\n" << flush;
      return 0;
    }
    if(equal_arg.Atoi() <= 0) {
      cerr << "ERROR: Invalid value passed to --cache" << "\n" << flush;
      return 0;
    }
    num_buckets = equal_arg.Atoi();
    if((num_buckets < 1) || (num_buckets > 65535)) {
      cerr << "ERROR: Bad number of cache buckets specified" << "\n" << flush;
      cerr << "ERROR: Valid range = 1 to 65535 bytes" << "\n" << flush;
      return 0;
    }
    has_valid_args = 1;
  }

  if(arg == "static-data-size") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --static-data-size requires an input argument" << "\n" << flush;
      return 0;
    }
    if(equal_arg.Atoi() < 1) {
      cerr << "ERROR: Invalid value passed to --static-data-size" << "\n" << flush;
      return 0;
    }

    static_data_size = equal_arg.Atoi();
    if((static_data_size < MIN_STATIC_DATA_AREA_SIZE) || (static_data_size > MAX_STATIC_DATA_AREA_SIZE)) {
      cerr << "ERROR: Bad static data storage value specified" << "\n" << flush;
      cerr << "ERROR: Valid range = " << MIN_STATIC_DATA_AREA_SIZE << " to " << MAX_STATIC_DATA_AREA_SIZE << " bytes" << "\n" << flush;
      return 0;
    }
    has_valid_args = 1;
  }
  
  if(arg == "debug") {
    if(!equal_arg.is_null()) {
      if(equal_arg.Atoi() <= 0) {
	cerr << "ERROR: Invalid value passed to --debug" << "\n" << flush;
	return 0;
      }
      debug_level = equal_arg.Atoi();
      clientcfg->verbose_mode = 1;
      debug_mode = 1;
    }
    has_valid_args = 1;
  }

  if(arg == "verbose") {
    clientcfg->verbose_mode = 1;
    has_valid_args = 1;
  }

  if(arg == "password") {
    if(!equal_arg.is_null()) {
      password = equal_arg;
    }
    use_password  = 1;
    has_valid_args = 1;
  }

  if(arg == "decrypted-outfile") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --decrypted-outfile requires an input argument" << "\n" << flush;
      return 0;
    }
    decrypted_output_filename = equal_arg;
    has_valid_args = 1;
  }
  
  if(arg == "key") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --key requires an input argument" << "\n" << flush;
      return 0;
    }
    input_arg_key_file = equal_arg;
    if(!futils_exists(input_arg_key_file.c_str()) || !futils_isfile(input_arg_key_file.c_str())) {
      cerr << "ERROR: Key file " << input_arg_key_file.c_str() << " does not exist or cannot be read" <<  "\n" << flush;
      return 0;
    }
    else {
      DEBUG_m("Reading symmetric key file");
      if(read_key_file(input_arg_key_file.c_str(), key, ebuf) != 0) {
	cerr << "ERROR: " << ebuf.c_str() << "\n" << flush;
	return 0;
      }
    }
    use_key_file  = 1;
    has_valid_args = 1;
  }
  
  if(arg == "iter") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --iter requires an input argument: --iter=10000" << "\n" << flush;
      return 0;
    }
    if(equal_arg.Atoi() <= 0) {
      cerr << "ERROR: Invalid value passed to --iter" << "\n" << flush;
      return 0;
    }
    key_iterations = equal_arg.Atoi();
    has_valid_args = 1;
  }

  if(arg == "add-rsa-key") {
    if(public_rsa_key_file == "STDIN") {
      add_rsa_key = 1;
      has_valid_args = 1;
      
    }
    else {
      if(equal_arg.is_null()) {
	cerr << "ERROR: --add-rsa-key missing filename: --add-rsa-key=/$HOME/keys/rsa_pubkey.pem" << "\n" << flush;
	return 0;
      }
      public_rsa_key_file = equal_arg;
      
      DEBUG_m("Reading RSA key file");
      if(!futils_exists(public_rsa_key_file.c_str()) || !futils_isfile(public_rsa_key_file.c_str())) {
	cerr << "ERROR: Public RSA key file " << public_rsa_key_file.c_str() << " does not exist or cannot be read" <<  "\n" << flush;
	return 0;
      }
      rv = RSA_read_key_file(public_rsa_key_file.c_str(), public_key, sizeof(public_key), &public_key_len, &has_passphrase);
      if(rv != RSA_NO_ERROR) {
	std::cerr << "ERROR: " << RSA_err_string(rv) << "\n" << std::flush;
	return 0;
      }
      add_rsa_key = 1;
      has_valid_args = 1;
    }
  }
  
  if(arg == "rsa-key-username") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --rsa-key-username missing name: --rsa-key-username=$(whoami)" << "\n" << flush;
      return 0;
    }
    rsa_key_username = equal_arg;
    has_valid_args = 1;
  }

  if(arg == "rsa-key-passphrase") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --rsa-key-passphrase requires an input argument" << "\n" << flush;
      return 0;
    }
    rsa_key_passphrase = equal_arg;
    has_valid_args = 1;
  }

  if(arg == "ext") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --ext requires an input argument" << "\n" << flush;
      return 0;
    }
    en_dot_ext = equal_arg;
    if(en_dot_ext[0] != '.') {
      en_dot_ext.InsertAt(0, ".", 1);
    }
    has_valid_args = 1;
  }
  
  if(arg == "outdir") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --outdir requires an input argument" << "\n" << flush;
      return 0;
    }
    output_dir_name = equal_arg;
    if(!futils_exists(output_dir_name.c_str())) {
      if(futils_mkdir(output_dir_name.c_str()) != 0) {
	cerr << "Error making directory" << "\n" << flush;
	return 0;
      }
    }
    if(!futils_isdirectory(output_dir_name.c_str())) {
      cerr << "Bad output DIR specified" << "\n" << flush;
      cerr << output_dir_name.c_str() << " is a file name" << "\n" << flush;
      return 0;
    }
    has_valid_args = 1;
  }

  if(arg == "outfile") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --outfile requires an input argument" << "\n" << flush;
      return 0;
    }
    output_file_name = equal_arg;
    has_valid_args = 1;
  }

#ifdef __ENABLE_SMART_CARD__
  if(arg == "add-smartcard-cert") {
    add_smart_card = 1;
    use_smartcard_cert = 1;
    has_valid_args = 1;
  }

  if(arg == "smartcard-username") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --smartcard-username missing name: --smartcard-username=$(whoami)" << "\n" << flush;
      return 0;
    }
    smartcard_cert_username = equal_arg;
    has_valid_args = 1;
  }

  if(arg == "smartcard-cert-id") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --smartcard-cert-id missing ID: --smartcard-cert-id=01" << "\n" << flush;
      return 0;
    }
    sc.SetCertID(equal_arg.c_str());
    has_valid_args = 1;
  }

  if(arg == "smartcard-engine") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --smartcard-engine missing path: --smartcard-engine=" <<  SC_get_default_enginePath() << "\n" << flush;
      return 0;
    }
    sc.SetEnginePath(equal_arg.c_str());
    if(!futils_exists(sc.enginePath) || !futils_isfile(sc.enginePath)) {
      cerr << "ERROR: Smart card engine " << sc.enginePath << " does not exist or cannot be read" <<  "\n" << flush;
      return 0;
    }
    has_valid_args = 1;
  }

  if(arg == "smartcard-provider") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --smartcard-provider missing path: --smartcard-provider=" <<  SC_get_default_modulePath() << "\n" << flush;
      return 0;
    }
    sc.SetModulePath(equal_arg.c_str());
    if(!futils_exists(sc.modulePath) || !futils_isfile(sc.modulePath)) {
      cerr << "ERROR: Smart card provider " << sc.modulePath << " does not exist or cannot be read" <<  "\n" << flush;
      return 0;
    }
    has_valid_args = 1;
  }

  if(arg == "add-smartcard-cert-file") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --add-smartcard-cert-file missing filename: --add-smartcard-cert-file=${HOME}/certs/certfile.pem" << "\n" << flush;
      return 0;
    }
    add_smart_card = 1;
    use_smartcard_cert_file = 1;
    smartcard_cert_file = equal_arg;
    if(!futils_exists(smartcard_cert_file.c_str()) || !futils_isfile(smartcard_cert_file.c_str())) {
      cerr << "ERROR: Smart card cert file " << smartcard_cert_file.c_str() << " does not exist or cannot be read" <<  "\n" << flush;
      return 0;
    }
    if(SC_read_cert_file(&sc, smartcard_cert_file.c_str()) != 0) {
      cerr << "ERROR: " << sc.err_string << "\n" << flush;
      return 0;
    }
    has_valid_args = 1;
  }
#endif
  
  if(!has_valid_args) {
    cerr << "Unknown or invalid --" << arg.c_str() << "\n" << flush;
    cerr << "Exiting..." << "\n" << flush;
  }

  arg.Clear();
  return has_valid_args;
}

int ProcessArgs(char *arg)
{
  gxString sbuf;
  gxString ebuf;
  switch(arg[1]) {
    case 'd':
      clientcfg->verbose_mode = 1;
      debug_mode = 1;
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
      cerr << "Unknown switch " << arg << "\n" << flush;
      cerr << "Exiting..." << "\n" << flush;
      return 0;
  }
  arg[0] = '\0';

  return 1; // All command line arguments were valid
}

int DEBUG_m(char *message, int level, int rv)
{
  if(debug_mode && debug_level >= level) {
    if(message) cerr << "DEBUG" << debug_level << ": " << message << "\n" << flush; 
    if(!debug_message.is_null()) cerr << debug_message << "\n" << flush;
  }
  return rv; 
}

int ExitProgram(int rv, char *exit_message)
{
  // Clear and destory all global buffers
  aes_file_encrypt_secret.Clear(1);
  key.Clear(1);
  password.Clear(1);
  password2.Clear(1);
  rsa_key_username.Clear(1);
  memset(rsa_ciphertext, 0, sizeof(rsa_ciphertext));
  memset(public_key, 0, sizeof(public_key));
  rsa_key_passphrase.Clear(1);
  
  if(!debug_message.is_null()) DEBUG_m(debug_message.c_str(), debug_level);

  if(debug_mode) {
#ifdef __ENABLE_SMART_CARD__
    cerr << "Smart card: " << sc.err_string << "\n" << flush;
#endif
    char err[1024];
    memset(err, 0, sizeof(err));
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    cerr << "Openssl " << err << "\n" << flush;
  }
  
  if(!exit_message) {
    cerr << exit_message << "\n" << flush;
  }
  return rv;
}

int main(int argc, char **argv)
{
#ifdef __MSVC_DEBUG__
  InitLeakTest();
#endif

  fd_set readfds, writefds, exceptfds;
  struct timeval timeout;
  
  FD_ZERO(&readfds);
  FD_ZERO(&writefds);
  FD_ZERO(&exceptfds);
  FD_SET(fileno(stdin), &readfds);
  timeout.tv_sec  = 0;
  timeout.tv_usec = 5000;

  int selectRetVal = select(1, &readfds, &writefds, &exceptfds, &timeout);
  char buf[1];
  unsigned bytes_read = 0;
  
  if(selectRetVal > 0) {
    if(FD_ISSET(fileno(stdin), &readfds)) {
      while(read(0, buf, sizeof(buf)) > 0) {
	if(bytes_read > sizeof(public_key)) {
	  cerr << "ERROR: Public key size has exceeded " <<  sizeof(public_key) << " bytes" << "\n" << flush;
	  return 1;
	}
	public_key[bytes_read] = buf[0];
	bytes_read++;
      }
    }
  }

  if(bytes_read > 0) {
    public_rsa_key_file = "STDIN";
    public_key_len = bytes_read;
  }
   
  AES_openssl_init();
  
  // Set this programs information
  clientcfg->executable_name = "fcrypt";
  clientcfg->program_name = "File Encrypt";

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
    cerr << "Encountered fatal fcrypt error" << "\n";
    cerr << "Error setting top present working DIR" << "\n";
    return ExitProgram(1);
  }

  if(argc >= 2) {
    while (narg < argc) {
      if (arg[0] != '\0') {
	if (arg[0] == '-') { // Look for command line arguments
	  if(!ProcessArgs(arg)) return ExitProgram(1); // Exit if argument is not valid
	}
	else { 
	  // Process the command line string after last - argument
	  fn = arg;
	  if(futils_isdirectory(fn.c_str())) {
	    if(recurse) {
	      if(use_abs_path) cryptdb_makeabspath(fn);
	      if(futils_getcwd(curr_pwd, futils_MAX_DIR_LENGTH) != 0) {
		cerr << "Encountered fatal fcrypt error" << "\n";
		cerr << "Error setting current present working DIR" << "\n";
		return 1;
	      }      

	      num_dirs++;
	      if(!cryptdb_getdircontents(fn, err_str, file_list, 
					 num_files, num_dirs)) {
		cerr << "Encountered fatal fcrypt error" << "\n";
		cerr << err_str.c_str() << "\n";
		return ExitProgram(1); 
	      }

	      if(futils_chdir(curr_pwd) != 0) {
		cerr << "Encountered fatal fcrypt error" << "\n";
		cerr << "Error resetting current present working DIR" << "\n";
		return ExitProgram(1);
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
    cerr << "Encountered fatal fcrypt error" << "\n";
    cerr << "No file name specified" << "\n";
    return ExitProgram(1);
  }
  
  if(futils_chdir(top_pwd) != 0) {
    cerr << "Encountered fatal fcrypt error" << "\n";
    cerr << "Error resetting top present working DIR" << "\n";
    return ExitProgram(1);
  }

  gxListNode<gxString> *ptr = file_list.GetHead();
  rv = err = 0;

  if(use_key_file) {
    aes_file_encrypt_secret.Clear(1);
    aes_file_encrypt_secret.Cat(key.m_buf(), key.length());
    if(add_rsa_key) {
      cerr << "Using symmetric key to add an RSA user key to an encrypted file" << "\n" << flush;
    }
#ifdef __ENABLE_SMART_CARD__
    else if(add_smart_card) {
      cerr << "Using symmetric key to add a smartcard cert to an encrypted file" << "\n" << flush;
    }
#endif
    else {
      cerr << "Using symmetric key for file encryption" << "\n" << flush;
      if(aes_file_encrypt_secret.length() < AES_MIN_SECRET_LEN) {
	cerr << "Key does not meet length requirement" << "\n" << flush;
	cerr << "Password must be at least " << AES_MIN_SECRET_LEN << " bytes" << "\n" << flush;
	return ExitProgram(1);
      }
    }
  }
  else {
    if(add_rsa_key) {
      cerr << "Using password to add an RSA user key to an encrypted file" << "\n" << flush;
      if(password.is_null()) {
	cout << "Password: " << flush;
	if(!consoleGetString(password, 1)) {
	  password.Clear(1);
	  cerr << "Invalid entry!" << "\n" << flush;
	  return ExitProgram(1);
	}
	cout << "\n" << flush;
      }
      aes_file_encrypt_secret.Clear(1);
      aes_file_encrypt_secret.Cat(password.GetSPtr(), password.length());
    }
#ifdef __ENABLE_SMART_CARD__
    else if(add_smart_card) {
      cerr << "Using password to add a smartcard cert to an encrypted file" << "\n" << flush;
      if(password.is_null()) {
	cout << "Password: " << flush;
	if(!consoleGetString(password, 1)) {
	  password.Clear(1);
	  cerr << "Invalid entry!" << "\n" << flush;
	  return ExitProgram(1);
	}
	cout << "\n" << flush;
      }
      aes_file_encrypt_secret.Clear(1);
      aes_file_encrypt_secret.Cat(password.GetSPtr(), password.length());
    }
#endif
    else {
      cerr << "Using password for symmetric file encryption" << "\n" << flush;
      if(password.is_null()) {
	cout << "Password: " << flush;
	if(!consoleGetString(password, 1)) {
	  cerr << "Invalid entry!" << "\n" << flush;
	  return ExitProgram(1);
	}
	cout << "\n" << flush;
	cout << "Retype password: " << flush;
	if(!consoleGetString(password2, 1)) {
	  cerr << "Invalid entry!" << "\n" << flush;
	  return ExitProgram(1);
	}
	cout << "\n" << flush;
	if(password != password2) {
	  cerr << "Passwords do not match" << "\n" << flush;
	  return ExitProgram(1);
	}
      }
      // Our password is set now check the length
      if((int)password.length() < AES_MIN_SECRET_LEN) {
	cerr << "Password does not meet length requirement" << "\n" << flush;
	cerr << "Password must be at least " << AES_MIN_SECRET_LEN << " characters long" << "\n" << flush;
	return ExitProgram(1);
      }
      aes_file_encrypt_secret.Clear(1);
      aes_file_encrypt_secret.Cat(password.GetSPtr(), password.length());
    }
  }

  if(add_rsa_key) {
    if(has_passphrase && rsa_key_passphrase.is_null()) {
      cout << "RSA key passphrase: " << flush;
      if(!consoleGetString(rsa_key_passphrase, 1)) {
	rsa_key_passphrase.Clear(1);
	cout << "\n" << flush;
	cerr << "Invalid entry!" << "\n" << flush;
	return ExitProgram(1);
      }
      cout << "\n" << flush;
    }
  }

#ifdef __ENABLE_SMART_CARD__
  if(add_smart_card) {
    if(smartcard_cert_username.is_null()) {
      cerr << "ERROR: --add-smartcard-cert requires --smartcard-username" << "\n" << flush;
      return ExitProgram(1);
    }

    if(clientcfg->verbose_mode) {
      cerr << "Smart card engine ID = " << sc.engine_ID << "\n" << flush;
      cerr << "Smart card engine path = " << sc.enginePath << "\n" << flush;
      cerr << "Smart card module path = " << sc.modulePath << "\n" << flush;
      cerr << "Smart card cert ID = " << sc.cert_id << "\n"  << flush;
    }
    
    if(!use_smartcard_cert_file) {
      if(!futils_exists(sc.enginePath) || !futils_isfile(sc.enginePath)) {
	cerr << "ERROR: Smart card engine " << sc.enginePath << " does not exist or cannot be read" <<  "\n" << flush;
	return ExitProgram(1);
      }
      if(!futils_exists(sc.modulePath) || !futils_isfile(sc.modulePath)) {
	cerr << "ERROR: Smart card provider " << sc.modulePath << " does not exist or cannot be read" <<  "\n" << flush;
	return ExitProgram(1);
      }
    }
    
    cerr << "Adding smart card cert for user " << smartcard_cert_username.c_str() << " to encrypted file " << ptr->data.c_str() << "\n" << flush;

    if(debug_mode) sc.verbose_mode = 1;
    
    while(ptr) {
      FCryptCache fc(num_buckets);
      fc.key_iterations = key_iterations;
      if(!fc.AddSmartCardCertToStaticArea(&sc, use_smartcard_cert_file, ptr->data.c_str(), aes_file_encrypt_secret, smartcard_cert_username.c_str())) {
	cerr << "ERROR: " << fc.err.c_str() << "\n" << flush;
	return ExitProgram(1);
      }
      cerr << "Smart card cert for user " << smartcard_cert_username.c_str() << " added to " << ptr->data.c_str() << "\n" << flush;

      if(clientcfg->verbose_mode) {
	fc.LoadStaticDataBlocks();
	cerr << "Static data size  = " << fc.static_data_size << "\n" << flush;
	cerr << "Num static blocks = " << fc.num_static_data_blocks << "\n" << flush;
	cerr << "Static data bytes used = " << fc.static_data_bytes_used  << "\n" << flush;
	cerr << "Static data bytes left = " << (fc.static_data_size - fc.static_data_bytes_used) << "\n" << flush;
	cerr << "Authorized users list = ";
	gxListNode<StaticDataBlock> *list_ptr = fc.static_block_list.GetHead();
	while(list_ptr) {
	  cerr << list_ptr->data.username.c_str();
	  list_ptr = list_ptr->next;
	  if(list_ptr) cerr << ", ";
	}
	cerr << "\n" << flush;
      }
      ptr = ptr->next; // Go the next file
    }
    return ExitProgram(0); // Smart card cert was added, exit program here
  }
#endif
  
  if(add_rsa_key) {
    if(rsa_key_username.is_null()) {
      cerr << "ERROR: --add-rsa-key requires --rsa-key-username" << "\n" << flush;
      return ExitProgram(1);
    }

    cerr << "Adding RSA key for user " << rsa_key_username.c_str() << " to encrypted file " << ptr->data.c_str() << "\n" << flush;

    while(ptr) {
      FCryptCache fc(num_buckets);
      fc.key_iterations = key_iterations;
      if(!fc.AddRSAKeyToStaticArea(ptr->data.c_str(), aes_file_encrypt_secret, public_key, public_key_len, rsa_key_username.c_str())) {
	cerr << "ERROR: " << fc.err.c_str() << "\n" << flush;
	return ExitProgram(1);
      }
      cerr << "Public RSA key " << rsa_key_username.c_str() << " added to " << ptr->data.c_str() << "\n" << flush;

      if(clientcfg->verbose_mode) {
	fc.LoadStaticDataBlocks();
	cerr << "Static data size  = " << fc.static_data_size << "\n" << flush;
	cerr << "Num static blocks = " << fc.num_static_data_blocks << "\n" << flush;
	cerr << "Static data bytes used = " << fc.static_data_bytes_used  << "\n" << flush;
	cerr << "Static data bytes left = " << (fc.static_data_size - fc.static_data_bytes_used) << "\n" << flush;
	cerr << "Authorized users list = ";
	gxListNode<StaticDataBlock> *list_ptr = fc.static_block_list.GetHead();
	while(list_ptr) {
	  cerr << list_ptr->data.username.c_str();
	  list_ptr = list_ptr->next;
	  if(list_ptr) cerr << ", ";
	}
	cerr << "\n" << flush;
      }
      ptr = ptr->next; // Go the next file
    }
    return ExitProgram(0); // Key was added, exit program here
  }
  
  while(ptr) {
    FCryptCache fc(num_buckets, static_data_size);
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
    if(!decrypted_output_filename.is_null()) {
      fc.decrypted_output_filename = decrypted_output_filename;
    }
    
    gxString sbuf;

    if(clientcfg->verbose_mode) {
      cerr << "Encrypting:      " << ptr->data.c_str() << "\n" << flush;
      if(mode == -1 || mode == 3) {
	cerr << "Encryption mode: " << "AES 256 CBC" << "\n" << flush;
      }
      else {
	cerr << "Encryption mode: " << mode << "\n" << flush;
      }
      cerr << "Key iterations:  " << key_iterations << "\n" << flush;
      cerr << "Cache buckets:   " << num_buckets << "\n" << flush;
    }
    else {
      cerr << "Encrypting: " << ptr->data.c_str() << "\n" << flush;
    }
    if(fc.mode == 0) cerr << "\n" << "WARNING: Using mode 0 for test only - WARNING: Output file will not be encrypted" << "\n\n"<< flush;

    rv = fc.EncryptFile(ptr->data.c_str(), aes_file_encrypt_secret);
    if(!rv) {
      cerr << "File encryption failed" << "\n" << flush;
      cerr << fc.err.c_str() << "\n" << flush;
      ptr = ptr->next;
      err = 1;
      ptr = ptr->next;
      continue;
    } 

    cerr << "File encrypt successful" << "\n" << flush;
    sbuf << clear << wn << fc.BytesWrote();
    cerr << "Wrote " << sbuf.c_str() << " bytes to "
	 << fc.OutFileName() << "\n" << flush;

    if(remove_src_file) {
      if(futils_remove(ptr->data.c_str()) != 0) {
	cerr << "Error removing " << ptr->data.c_str() << " source file" << "\n" << flush;
      }
    }

    ptr = ptr->next;
  }

  if(err == 0) {
    if(num_files > 1) {
      cerr << "Encrypted " << num_files << " files" << "\n" << flush;
    }
    if(num_dirs > 0) {
      cerr << "Traversed " << num_dirs << " directories" << "\n" << flush;
    }
  }

  return ExitProgram(err);
}
// ----------------------------------------------------------- // 
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
