// ------------------------------- //
// -------- start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- // 
// C++ Source Code File
// Compiler Used: MSVC, BCC32, GCC, HPUX aCC, SOLARIS CC
// Produced By: DataReel Software Development Team
// File Creation Date: 07/21/2003
// Date Last Modified: 12/06/2023
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
int debug_level = 1;
int num_buckets = 1024;
gxList<gxString> file_list;
int remove_src_file = 0;
gxString output_dir_name;
int list_file_names = 0;
int recurse = 0;
int use_abs_path = 0;
int use_password = 0;
int use_key_file = 0;
gxString input_arg_key_file;
MemoryBuffer aes_file_decrypt_secret;
MemoryBuffer key;
gxString password;
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
gxString rsa_key_passphrase;
int has_passphrase = 0;
gxString rsa_key_username;
int list_rsa_key_users = 0;
#ifdef __ENABLE_SMART_CARD__
SmartCardOB sc;
gxString smartcard_cert_username;
int use_smartcard_cert = 0;
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
#endif
}

void HelpMessage() 
{
  DisplayVersion();
  cout << "\n" << flush;
  cout << "Usage: " << clientcfg->executable_name.c_str() << " [switches] " << "filename.enc" << "\n" << flush;
  cout << "Switches: -?  Display this help message and exit." << "\n" << flush;
  cout << "          -d  Enable debugging output" << "\n" << flush;
  cout << "          -h  Display this help message and exit." << "\n" << flush;
  cout << "          -l  List output file name(s) in enc file(s)" << "\n" << flush;
  cout << "          -r  Remove encrypted source file" << "\n" << flush;
  cout << "          -R  Decrypt DIR including all files and subdirectories" << "\n" << flush;
  cout << "          -v  Enable verbose messages to the console" << "\n" << flush;
  cout << "\n" << flush;
  cout << "          --cache=size (Set the cache size)" << "\n" << flush;
  cout << "          --debug (Turn on debugging and set optional level)" << "\n" << flush;
  cout << "          --help (Display this help message and exit." << "\n" << flush;
  cout << "          --iter=num (To set the number of derived key iterations)" << "\n" << flush;
  cout << "          --key=aes_key (Use a key file for symmetric file decryption)" << "\n" << flush;
  cout << "          --list-rsa-key-users (List the users that have RSA key access and exit)" << "\n" << flush;
  cout << "          --outfile=fname (Write decrypted output to specified file name)" << "\n" << flush;
  cout << "          --outdir=dir (Write decrypted output to this directory)" << "\n" << flush;
  cout << "          --password (Use a password for symmetric file decryption)" << "\n" << flush;
  cout << "          --rsa-key (Use a private RSA key for decryption)" << "\n" << flush;
  cout << "          --rsa-key input args can be a private key file name or a pipe" << "\n" << flush;
  cout << "          --rsa-key-passphrase (Passphrase for private RSA key)" << "\n" << flush;
  cout << "          --rsa-key-username=name (Username that owns the private RSA key)" << "\n" << flush;
  cout << "          --stdout (Write decrypted output to the console)" << "\n" << flush;
  cout << "          --verbose (Turn on verbose output)" << "\n" << flush;
  cout << "          --version (Display program version number)" << "\n" << flush;
#ifdef __ENABLE_SMART_CARD__
  cout << "\n" << flush;
  cout << "          --smartcard-cert (Use a smart card for decryption)" << "\n" << flush;
  cout << "          --smartcard-pin=pin (Supply smart card PIN on the command line for scripting, use with caution)" << "\n" << flush;
  cout << "          --smartcard-username=name (Username assigned to the smart card cert)" << "\n" << flush;
  cout << "          --smartcard-cert-id=" << SC_get_default_cert_id() << " (Set the ID number for the smartcard cert)" << "\n" << flush;
  cout << "          --smartcard-engine=" << SC_get_default_enginePath() << " (Set the smartcard engine path)" << "\n" << flush;
  cout << "          --smartcard-provider=" << SC_get_default_modulePath() << " (Set the smartcard provider)" << "\n" << flush;
#endif // __ENABLE_SMART_CARD__

  
  cout << "\n" << flush; // End of list
}

int ProcessDashDashArg(gxString &arg)
{
  gxString sbuf, equal_arg, ebuf;
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

  if(arg == "debug") {
    if(!equal_arg.is_null()) {
      if(equal_arg.Atoi() <= 0) {
	cerr << "ERROR: Invalid value passed to --debug" << "\n" << flush;
	return 0;
      }
      debug_level = equal_arg.Atoi();
      clientcfg->verbose_mode = 1;
      debug_mode= 1;
    }
    has_valid_args = 1;
  }

  if(arg == "verbose") {
    clientcfg->verbose_mode = 1;
    has_valid_args = 1;
  }

  if(arg == "cache") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --cache requires an input argument" << "\n" << flush;
      return 0;
    }
    if(equal_arg.Atoi() <= 0) {
      cerr << "ERROR: Invalid value passed to --iter" << "\n" << flush;
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

  if(arg == "outdir") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --outdir requires an input argument" << "\n" << flush;
      return 0;
    }
    output_dir_name = equal_arg;
    if(!futils_exists(output_dir_name.c_str())) {
      if(futils_mkdir(output_dir_name.c_str()) != 0) {
	cerr << "ERROR: Error making directory" << "\n" << flush;
	return 0;
      }
    }
    if(!futils_isdirectory(output_dir_name.c_str())) {
      cerr << "ERROR: Bad output DIR specified" << "\n" << flush;
      cerr << output_dir_name.c_str() << " is a file name" << "\n" << flush;
      return 0;
    }
    has_valid_args = 1;
  }
  
  if(arg == "iter") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --iter requires an input argument" << "\n" << flush;
      return 0;
    }
    if(equal_arg.Atoi() <= 0) {
      cerr << "ERROR: Invalid value passed to --iter" << "\n" << flush;
      return 0;
    }
    key_iterations = equal_arg.Atoi();
    has_valid_args = 1;
  }

  if(arg == "outfile") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --outfile requires an input argument" << "\n" << flush;
      return 0;
    }
    user_defined_output_file = equal_arg;
    use_ouput_file = 1;
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

  if(arg == "password") {
    if(!equal_arg.is_null()) {
      password = equal_arg;
    }
    use_password  = 1;
    has_valid_args = 1;
  }
  
  if(arg == "key") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --key requires an input argument" << "\n" << flush;
      return 0;
    }
    input_arg_key_file = equal_arg;
    if(!futils_exists(input_arg_key_file.c_str())|| !futils_isfile(input_arg_key_file.c_str())) {
      cerr << "ERROR: Key file " << input_arg_key_file.c_str() << " does not exist or cannot be read" <<  "\n" << flush;
      return 0;
    }
    DEBUG_m("Reading symmetric key file");
    if(read_key_file(input_arg_key_file.c_str(), key, ebuf) != 0) {
      cerr << "ERROR: " << ebuf.c_str() << "\n" << flush;
      return 0;
    }
    use_key_file  = 1;
    has_valid_args = 1;
  }
  
  if(arg == "rsa-key") {
    if(private_rsa_key_file == "STDIN") {
      use_private_rsa_key = 1;
      has_valid_args = 1;
      
    }
    else {
      if(equal_arg.is_null()) {
	cerr << "ERROR: --rsa-key missing filename: --rsa-key=/$HOME/keys/rsa_key.pem" << "\n" << flush;
	return 0;
      }
      private_rsa_key_file = equal_arg;
      if(!futils_exists(private_rsa_key_file.c_str()) || !futils_isfile(private_rsa_key_file.c_str())) {
	cerr << "ERROR: Private RSA key file " << private_rsa_key_file.c_str() << " does not exist or cannot be read" <<  "\n" << flush;
	return 0;
      }
      DEBUG_m("Reading RSA key file");
      rv = RSA_read_key_file(private_rsa_key_file.c_str(), private_key, sizeof(private_key), &private_key_len, &has_passphrase);
      if(rv != RSA_NO_ERROR) {
	cerr << "ERROR: " << RSA_err_string(rv) << "\n" << flush;
	return 0;
      }
      use_private_rsa_key = 1;
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

  if(arg == "list-rsa-key-users") {
    list_rsa_key_users = 1;
    has_valid_args = 1;
  }

  if(arg == "stdout") {
    write_to_stdout = 1;
    has_valid_args = 1;
  }


  #ifdef __ENABLE_SMART_CARD__
  if(arg == "smartcard-cert") {
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

  if(arg == "smartcard-pin") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --smartcard-pin missing pin number: --smartcard-pin=12345" << "\n" << flush;
      return 0;
    }
    sc.SetPin(equal_arg.c_str());
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
    case 'v':
      clientcfg->verbose_mode = 1;
      break;

    case 'd':
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

    case '-':
      sbuf = arg+2; 
      // Add all -- prepend filters here
      sbuf.TrimLeading('-');
      if(!ProcessDashDashArg(sbuf)) return 0;
      break;

    default:
      cerr << "ERROR: Unknown switch " << arg << "\n" << flush;
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
  aes_file_decrypt_secret.Clear(1);
  key.Clear(1);
  password.Clear(1);
  memset(rsa_ciphertext, 0, sizeof(rsa_ciphertext));
  memset(private_key, 0, sizeof(private_key));
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
	if(bytes_read > sizeof(private_key)) {
	  cerr << "ERROR: Private key size has exceeded " <<  sizeof(private_key) << " bytes" << "\n" << flush;
	  return 1;
	}
	private_key[bytes_read] = buf[0];
	bytes_read++;
      }
    }
  }

  if(bytes_read > 0) {
    private_rsa_key_file = "STDIN";
    private_key_len = bytes_read;
  }
  
  AES_openssl_init();
  
  // Set this programs information
  clientcfg->executable_name = "fdecrypt";
  clientcfg->program_name = "File Decrypt";

  if(argc < 2) {
    HelpMessage();
    return ExitProgram(1);
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
	  fn = arg;
	  if(futils_isdirectory(fn.c_str())) {
	    if(recurse) {
	      if(use_abs_path) cryptdb_makeabspath(fn);
	      if(futils_getcwd(curr_pwd, futils_MAX_DIR_LENGTH) != 0) {
		cerr << "Encountered fatal decrypt error" << "\n";
		cerr << "Error setting current present working DIR" << "\n";
		return ExitProgram(1);
	      }      

	      num_dirs++;
	      if(!cryptdb_getdircontents(fn, err_str, file_list, 
					 num_files, num_dirs)) {
		cerr << "Encountered fatal decrypt error" << "\n";
		cerr << err_str.c_str() << "\n";
		return ExitProgram(1);
	      }

	      if(futils_chdir(curr_pwd) != 0) {
		cerr << "Encountered fatal decrypt error" << "\n";
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
    cerr << "Encountered fatal decrypt error" << "\n";
    cerr << "No file name specified" << "\n";
    return ExitProgram(1);
  }
  
  if(use_key_file) {
    cerr << "Using key file for decryption" << "\n" << flush;
    aes_file_decrypt_secret.Clear(1);
    aes_file_decrypt_secret = key;
  }
  else if(use_private_rsa_key) {
    if(rsa_key_username.is_null()) {
      cerr << "ERROR: --rsa-key requires --rsa-key-username" << "\n" << flush;
      return ExitProgram(1);
    }
    cerr << "Using private RSA key file for decryption" << "\n" << flush;
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
  else if(use_smartcard_cert) {
    if(smartcard_cert_username.is_null()) {
      cerr << "ERROR: --smartcard-cert requires --smartcard-username" << "\n" << flush;
      return ExitProgram(1);
    }
    cerr << "Using private smart card cert for decryption" << "\n" << flush;
    if(debug_mode) sc.verbose_mode = 1;
    gxString pin_buf;
    if(sc.pin[0] == 0) {
      cout << "Smart card PIN: " << flush;
      if(!consoleGetString(pin_buf, 1)) {
	pin_buf.Clear(1);
	cout << "\n" << flush;
	cerr << "Invalid entry!" << "\n" << flush;
	return ExitProgram(1);
      }
      sc.SetPin(pin_buf.c_str());
      pin_buf.Clear(1);
      cout << "\n" << flush;
    }
  }
#endif
  else if(use_password) {
    if(password.is_null()) {
      cout << "Password: " << flush;
      if(!consoleGetString(password, 1)) {
	cout << "\n" << flush;
	password.Clear(1);
	cerr << "Invalid entry!" << "\n" << flush;
	return ExitProgram(1);
      }
      cout << "\n" << flush;
    }
    aes_file_decrypt_secret.Clear(1);
    aes_file_decrypt_secret.Cat(password.GetSPtr(), password.length());
  }
  else if(list_rsa_key_users) {
    DEBUG_m("No auth list RSA key users operation");
  }
  else {
    if(clientcfg->verbose_mode) cout << "No decryption method specifed, defaulting to password" << "\n" << flush;
    cout << "Password: " << flush;
    if(!consoleGetString(password, 1)) {
      cout << "\n" << flush;
      password.Clear(1);
      cerr << "Invalid entry!" << "\n" << flush;
      return ExitProgram(1);
    }
    cout << "\n" << flush;
    aes_file_decrypt_secret.Clear(1);
    aes_file_decrypt_secret.Cat(password.GetSPtr(), password.length());
  }
  
  gxListNode<gxString> *ptr = file_list.GetHead();
  err = 0;

  if(list_rsa_key_users) { // List user names found and exit program
    while(ptr) {
      cout << "Listing usernames with RSA key access to encrypted file " << ptr->data.c_str() << "\n" << flush;
      FCryptCache fc(num_buckets);
      if(!fc.LoadStaticDataBlocks(ptr->data.c_str())) {
	cerr << "ERROR: " << fc.err.c_str() << "\n" << flush; ;
	err = 1;
        ptr = ptr->next;
        continue;
      }

      gxListNode<StaticDataBlock> *list_ptr = fc.static_block_list.GetHead();
      if(!list_ptr) {
	cerr << "ERROR: No authorized RSA users found in encrypted file " << ptr->data.c_str() << "\n" << flush; ;
	ptr = ptr->next;
	continue;
      }
      cout << "Encrypted file has stored username for users: " << "\n" << flush;
      while(list_ptr) {
	cout << list_ptr->data.username.c_str() << "\n" << flush;
      	list_ptr = list_ptr->next;
      }
      ptr = ptr->next;
    }  
    return ExitProgram(err);
  }
  
  while(ptr) { // Decrypt file and exit program
    if(clientcfg->verbose_mode) cerr << "Decrypting: " << ptr->data.c_str() << "\n" << flush;
    
    FCryptCache fc(num_buckets);
    fc.key_iterations = key_iterations;
    if(!output_dir_name.is_null()) {
      fc.SetDir(output_dir_name.c_str());
    }
    gxString sbuf;
    gxUINT32 version;
    int rv = 0;
    unsigned decrypted_data_len = 0;
    unsigned char rsa_decrypted_message[2048];
    unsigned char hash[AES_MAX_HMAC_LEN];
    unsigned char SALT[AES_MAX_SALT_LEN];
    unsigned char IV[AES_MAX_IV_LEN];
    unsigned char KEY[AES_MAX_KEY_LEN];
    
    if(use_private_rsa_key) {
      if(!fc.LoadStaticDataBlocks(ptr->data.c_str())) {
	cerr << "ERROR: " << fc.err.c_str() << "\n" << flush; ;
	err = 1;
        ptr = ptr->next;
        continue;
      }

      gxListNode<StaticDataBlock> *list_ptr = fc.static_block_list.GetHead();
      if(!list_ptr) {
	cerr << "ERROR: No authorized RSA users found in encrypted file " << ptr->data.c_str() << "\n" << flush; ;
	ptr = ptr->next;
	err = 1;
	continue;
      }

      int found_key = 0;
      while(list_ptr) {
	memset(rsa_decrypted_message, 0, sizeof(rsa_decrypted_message));
	memset(hash, 0, sizeof(hash));
	decrypted_data_len = 0;

	if(debug_mode) {
	  cerr << "Encrypted file has stored username for user " << list_ptr->data.username.c_str() << "\n" << flush;
	}
	
	if(rsa_key_username == list_ptr->data.username.c_str()) {
	  if(clientcfg->verbose_mode) cerr << "Found stored RSA key for user " << list_ptr->data.username.c_str() << "\n" << flush;
	  char *passphrase = 0;
	  if(!rsa_key_passphrase.is_null()) passphrase = (char *)rsa_key_passphrase.GetSPtr();
	  rv = RSA_private_key_decrypt((const unsigned char *)private_key, private_key_len,
				       list_ptr->data.rsa_ciphertext.m_buf(), list_ptr->data.rsa_ciphertext.length(),
				       rsa_decrypted_message, sizeof(rsa_decrypted_message), &decrypted_data_len,
				       RSA_padding, passphrase);
	  if(rv != RSA_NO_ERROR) {
	    cerr << "RSA private key decrypt failed " << RSA_err_string(rv) << "\n" << flush;
	    found_key = 0;
	    err = 1;
	    break;
	  }
	  found_key = 1;
	  if(clientcfg->verbose_mode) cerr << "RSA key decryption authorized for user " << list_ptr->data.username.c_str() << "\n" << flush; 
	  memmove(SALT, rsa_decrypted_message, AES_MAX_SALT_LEN);
	  aes_file_decrypt_secret.Clear(1);
	  aes_file_decrypt_secret.Cat(rsa_decrypted_message+AES_MAX_SALT_LEN, (decrypted_data_len-AES_MAX_SALT_LEN));

	  rv = AES_derive_key((const unsigned char*)aes_file_decrypt_secret.m_buf(), aes_file_decrypt_secret.length(),
			      SALT, sizeof(SALT), KEY, sizeof(KEY), IV, sizeof(IV), 1000);
	  if(rv != AES_NO_ERROR) {
	    cerr << "Failed to generate derived key " << AES_err_string(rv) << "\n" << flush;
	    found_key = 0;
	    err = 1;
	    break;
	  }
	  
	  rv = AES_HMAC(KEY, sizeof(KEY), list_ptr->data.rsa_ciphertext.m_buf(), list_ptr->data.rsa_ciphertext.length(), hash, sizeof(hash));
	  
	  if(debug_mode && debug_level == 5) { // START debug code
	    unsigned i;
	    gxString HMAC1 = "RSA HMAC GEN: ";
	    gxString HMAC2 = "RSA HMAC PTR: ";
	    for(i = 0; i < sizeof(hash); ++i) { HMAC1 << hex << hash[i]; } DEBUG_m(HMAC1.c_str(), 5);
	    for(i = 0; i < sizeof(hash); ++i) { HMAC2 << hex << list_ptr->data.hmac.m_buf()[i]; } DEBUG_m(HMAC2.c_str(), 5);
	    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
	    SHA256(list_ptr->data.rsa_ciphertext.m_buf(), list_ptr->data.rsa_ciphertext.length(), sha256_hash);
	    gxString SHA256_str = "SHA256 RSA CT: ";
	    for(i = 0; i < sizeof(sha256_hash); ++i) { SHA256_str << hex << sha256_hash[i]; } DEBUG_m(SHA256_str.c_str(), 5);
#ifdef __DEBUG_ONLY__
	    SHA256(aes_file_decrypt_secret.m_buf(), aes_file_decrypt_secret.length(), sha256_hash);
	    SHA256_str << clear << "SHA256 PW: ";
	    for(i = 0; i < sizeof(sha256_hash); ++i) { SHA256_str << hex << sha256_hash[i]; } DEBUG_m(SHA256_str.c_str(), 5);
	    
	    gxString RSACIPHERTEXT = "RSACIPHERTEXT: ";
	    for(i = 0; i < list_ptr->data.rsa_ciphertext.length(); ++i) { RSACIPHERTEXT << hex << list_ptr->data.rsa_ciphertext.m_buf()[i]; }
	    DEBUG_m(RSACIPHERTEXT.c_str(), 5);
#endif
	  } // END debug code
	  
	  if(rv != AES_NO_ERROR) {
	    cerr << "ERROR: Failed to generate HMAC for RSA ciphertext " << AES_err_string(rv) << "\n" << flush;
	    found_key = 0;
	    err = 1;
	    break;
	  }
	  if(memcmp(hash, list_ptr->data.hmac.m_buf(), sizeof(hash)) != 0) {
	    cerr << "ERROR: Message authentication failed bad HMAC for RSA ciphertext" << "\n" << flush;
	    found_key = 0;
	    err = 1;
	    break;
	  }
	  break;
	}
	list_ptr = list_ptr->next;
      }
      if(!found_key) {
	cerr << "ERROR: The private RSA key provided for user " << rsa_key_username.c_str() << " does not have access to decrypt file " << ptr->data.c_str() << "\n" << flush;
	err = 1;
	ptr = ptr->next;
	continue;
      }
    }

#ifdef __ENABLE_SMART_CARD__
    if(use_smartcard_cert) {
      if(!fc.LoadStaticDataBlocks(ptr->data.c_str())) {
	cerr << "ERROR: " << fc.err.c_str() << "\n" << flush; ;
	err = 1;
        ptr = ptr->next;
        continue;
      }

      gxListNode<StaticDataBlock> *list_ptr = fc.static_block_list.GetHead();
      if(!list_ptr) {
	cerr << "ERROR: No authorized smart card users found in encrypted file " << ptr->data.c_str() << "\n" << flush; ;
	ptr = ptr->next;
	err = 1;
	continue;
      }

      int found_key = 0;
      while(list_ptr) {
	memset(rsa_decrypted_message, 0, sizeof(rsa_decrypted_message));
	memset(hash, 0, sizeof(hash));
	decrypted_data_len = 0;

	if(debug_mode) {
	  cerr << "Encrypted file has stored username for user " << list_ptr->data.username.c_str() << "\n" << flush;
	}
	
	if(smartcard_cert_username == list_ptr->data.username.c_str()) {
	  if(clientcfg->verbose_mode) cerr << "Found stored smart card cert for user " << list_ptr->data.username.c_str() << "\n" << flush;

	  rv = SC_private_key_decrypt(&sc, list_ptr->data.rsa_ciphertext.m_buf(), list_ptr->data.rsa_ciphertext.length(),
				      rsa_decrypted_message, sizeof(rsa_decrypted_message), &decrypted_data_len);
	  if(rv != 0) {
	    cerr << "ERROR: Smart card private key decrypt failed for cert ID " << sc.cert_id << "\n" << flush;
	    cerr << "ERROR: " << sc.err_string << "\n" << flush;
	    found_key = 0;
	    err = 1;
	    break;
	  }
	  found_key = 1;
	  if(clientcfg->verbose_mode) cerr << "Smart card prviate key decryption authorized for user " << list_ptr->data.username.c_str() << "\n" << flush; 
	  memmove(SALT, rsa_decrypted_message, AES_MAX_SALT_LEN);
	  aes_file_decrypt_secret.Clear(1);
	  aes_file_decrypt_secret.Cat(rsa_decrypted_message+AES_MAX_SALT_LEN, (decrypted_data_len-AES_MAX_SALT_LEN));

	  rv = AES_derive_key((const unsigned char*)aes_file_decrypt_secret.m_buf(), aes_file_decrypt_secret.length(),
			      SALT, sizeof(SALT), KEY, sizeof(KEY), IV, sizeof(IV), 1000);
	  if(rv != AES_NO_ERROR) {
	    cerr << "Failed to generate derived key " << AES_err_string(rv) << "\n" << flush;
	    found_key = 0;
	    err = 1;
	    break;
	  }
	  
	  rv = AES_HMAC(KEY, sizeof(KEY), list_ptr->data.rsa_ciphertext.m_buf(), list_ptr->data.rsa_ciphertext.length(), hash, sizeof(hash));
	  
	  if(debug_mode && debug_level == 5) { // START debug code
	    unsigned i;
	    gxString HMAC1 = "SC HMAC GEN: ";
	    gxString HMAC2 = "SC HMAC PTR: ";
	    for(i = 0; i < sizeof(hash); ++i) { HMAC1 << hex << hash[i]; } DEBUG_m(HMAC1.c_str(), 5);
	    for(i = 0; i < sizeof(hash); ++i) { HMAC2 << hex << list_ptr->data.hmac.m_buf()[i]; } DEBUG_m(HMAC2.c_str(), 5);
	    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
	    SHA256(list_ptr->data.rsa_ciphertext.m_buf(), list_ptr->data.rsa_ciphertext.length(), sha256_hash);
	    gxString SHA256_str = "SHA256 SC CT: ";
	    for(i = 0; i < sizeof(sha256_hash); ++i) { SHA256_str << hex << sha256_hash[i]; } DEBUG_m(SHA256_str.c_str(), 5);
#ifdef __DEBUG_ONLY__
	    SHA256(aes_file_decrypt_secret.m_buf(), aes_file_decrypt_secret.length(), sha256_hash);
	    SHA256_str << clear << "SHA256 PW: ";
	    for(i = 0; i < sizeof(sha256_hash); ++i) { SHA256_str << hex << sha256_hash[i]; } DEBUG_m(SHA256_str.c_str(), 5);
	    
	    gxString RSACIPHERTEXT = "RSACIPHERTEXT: ";
	    for(i = 0; i < list_ptr->data.rsa_ciphertext.length(); ++i) { RSACIPHERTEXT << hex << list_ptr->data.rsa_ciphertext.m_buf()[i]; }
	    DEBUG_m(RSACIPHERTEXT.c_str(), 5);
#endif
	  } // END debug code
	  
	  if(rv != AES_NO_ERROR) {
	    cerr << "ERROR: Failed to generate HMAC for smart card ciphertext " << AES_err_string(rv) << "\n" << flush;
	    found_key = 0;
	    err = 1;
	    break;
	  }
	  if(memcmp(hash, list_ptr->data.hmac.m_buf(), sizeof(hash)) != 0) {
	    cerr << "ERROR: Message authentication failed bad HMAC for smart card ciphertext" << "\n" << flush;
	    found_key = 0;
	    err = 1;
	    break;
	  }
	  break;
	}
	list_ptr = list_ptr->next;
      }
      if(!found_key) {
	cerr << "ERROR: Smart card for user " << rsa_key_username.c_str() << " does not have access to decrypt file " << ptr->data.c_str() << "\n" << flush;
	err = 1;
	ptr = ptr->next;
	continue;
      }
    }
#endif
    
    // List the file names and return
    if(list_file_names) {
      rv = fc.DecryptOnlyTheFileName(ptr->data.c_str(), aes_file_decrypt_secret, version, sbuf);
    }
    else  {
      if(write_to_stdout) {
	rv = fc.DecryptFile(ptr->data.c_str(), aes_file_decrypt_secret, version, "stdout");
      }
      else {
	if(use_ouput_file) {
	  rv = fc.DecryptFile(ptr->data.c_str(), aes_file_decrypt_secret, version, user_defined_output_file.c_str());
	}
	else {
	  rv = fc.DecryptFile(ptr->data.c_str(), aes_file_decrypt_secret, version);
	}
      }
    }
    
    if(!rv) {
      cerr << "ERROR: File decrypt failed" << "\n" << flush;
      DEBUG_m(fc.err.c_str());
      err = 1;
      ptr = ptr->next;
      continue;
    }
    if(fc.ERROR_LEVEL != 0) { // Check the ERROR level from the file caching ops
      cerr << "ERROR: File decrypt failed" << "\n" << flush;
      DEBUG_m(fc.err.c_str());
      err = 1;
      ptr = ptr->next;
      continue;
    }
    if(clientcfg->verbose_mode) cerr << "File decrypt successful" << "\n" << flush;

    if(list_file_names) {
      cout << "Decrypted name: " << sbuf.c_str() << "\n" << flush;
      ptr = ptr->next;
      continue;
    }
    
    sbuf << clear << wn << fc.BytesWrote();
    if(clientcfg->verbose_mode) cerr << "Wrote " << sbuf.c_str() << " bytes to " << fc.OutFileName() << "\n" << flush;

    if(remove_src_file) {
      if(futils_remove(ptr->data.c_str()) != 0) {
	cerr << "ERROR: Error removing " << ptr->data.c_str() << " source file" << "\n" << flush;
      }
    }
    ptr = ptr->next;
  }

  if(err == 0) {
    if(num_files > 1) {
      if(clientcfg->verbose_mode) cerr << "Decrypted " << num_files << " files" << "\n" << flush;
    }
    if(num_dirs > 0) {
      if(clientcfg->verbose_mode) cerr << "Traversed " << num_dirs << " directories"  << "\n" << flush;
    }
  }

  return ExitProgram(err);
}
// ----------------------------------------------------------- // 
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
