// ------------------------------- //
// -------- start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- // 
// C++ Source Code File
// Compiler Used: MSVC, BCC32, GCC, HPUX aCC, SOLARIS CC
// Produced By: DataReel Software Development Team
// File Creation Date: 07/21/2003
// Date Last Modified: 10/24/2026
// Copyright (c) 2003-2026 DataReel Software Development
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
#include "fckeymgmt.h"
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
int restore_path_mode = CRYPT_PATH_RELATIVE;
int overwrite = 0;
int allow_unencrypted = 0;
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
int list_users = 0;
int fips_request = FC_FIPS_AUTO;
int check_version = 0;   // 10/27/2026: --check-version
int access_log = 0;      // 10/27/2026: --access-log
gxString access_log_file;
int access_log_warned = 0;
int verify_access_log = 0;
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
int CheckFileFormat(const char *fname, int &fmt);
int ListNewFormatUsers(const char *fname);
int DecryptNewFormatFile(const char *fname);
int ReadSecretArg(const gxString &arg, const gxString &value, gxString &secret);
int CheckVersions();

void DisplayVersion()
{
  cout << "\n" << flush;
  cout << clientcfg->program_name.c_str() 
       << " version " << clientcfg->version_str.c_str();
  cout << "\n" << flush;
  cout << "Release Date: " << clientcfg->release_date.c_str() << "\n" << flush; 
  cout << clientcfg->copyright.c_str() << " " 
       << clientcfg->copyright_dates.c_str() << "\n" << flush;
  cout << "Produced by: " << clientcfg->produced_by << "\n" << flush;
  cout << clientcfg->default_url.c_str() << "\n" << flush;
  cout << "\n" << flush;
  cout << "Encryption engine: Openssl" << "\n" << flush;
  cout << "Version string: " << OPENSSL_VERSION_TEXT << "\n" << flush;
  cout << "Version number: 0x" << hex << OPENSSL_VERSION_NUMBER << dec << "\n" << flush;
  cout << "Encrypted file formats: " << FC_FILE_VERSION << ", and 2023103 and 2023102 outside FIPS mode" << "\n" << flush;
  gxString fips_err;
  if(FC_crypto_init(fips_request, fips_err)) {
    cout << FC_crypto_status().c_str() << "\n" << flush;
  }
  else {
    cout << fips_err.c_str() << "\n" << flush;
  }
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
  cout << "Usage: " << clientcfg->executable_name.c_str() << " [switches] " << "filename.enc" << "\n" << flush;
  cout << "Switches: -?  Display this help message and exit." << "\n" << flush;
  cout << "          -d  Enable debugging output" << "\n" << flush;
  cout << "          -h  Display this help message and exit." << "\n" << flush;
  cout << "          -l  List output file name(s) in enc file(s)" << "\n" << flush;
  cout << "          -o  Overwrite existing output files" << "\n" << flush;
  cout << "          -r  Remove encrypted source file" << "\n" << flush;
  cout << "          -R  Decrypt DIR including all files and subdirectories" << "\n" << flush;
  cout << "          -v  Enable verbose messages to the console" << "\n" << flush;
  cout << "\n" << flush;
  cout << "          --absolute-path (Restore to the exact path stored in the enc file)" << "\n" << flush;
  cout << "          --allow-unencrypted (Allow decrypting mode 0 test files that are not encrypted)" << "\n" << flush;
  cout << "          --access-log[=file] (Log each decrypt, default " << FC_default_log_file(".fcrypt").c_str() << ")" << "\n" << flush;
  cout << "          --no-access-log (Do not log, the default)" << "\n" << flush;
  cout << "          --verify-access-log (Check the access log entries of the files, needs the file credential)" << "\n" << flush;
  cout << "          --cache=size (Set the cache size)" << "\n" << flush;
  cout << "          --check-version (Report the file format of each file without decrypting, exit 1 if any is v1)" << "\n" << flush;
  cout << "          --debug (Turn on debugging and set optional level)" << "\n" << flush;
  cout << "          --fips (Use only the OpenSSL FIPS provider, see README.txt)" << "\n" << flush;
  cout << "          --help (Display this help message and exit." << "\n" << flush;
  cout << "          --iter=num (Key iterations for old format files, new files store their own)" << "\n" << flush;
  cout << "          --key=aes_key (Use a key file for symmetric file decryption)" << "\n" << flush;
#ifdef __ENABLE_SMART_CARD__
  cout << "          --list-users (List the users with RSA key of Smart Card cert access and exit)" << "\n" << flush;
#else
  cout << "          --list-users (List the users with RSA key access and exit)" << "\n" << flush;
#endif
  cout << "          --no-fips (Do not use FIPS mode, needed for old format files on a FIPS system)" << "\n" << flush;
  cout << "          --no-path (Restore only the file name, without the stored path)" << "\n" << flush;
  cout << "          --outfile=fname (Write decrypted output to specified file name)" << "\n" << flush;
  cout << "          --outdir=dir (Write decrypted output to this directory)" << "\n" << flush;
  cout << "          --password (Use a password for symmetric file decryption, prompts for the password)" << "\n" << flush;
  cout << "          --password-file=file (Read the password from the first line of a file only you can read)" << "\n" << flush;
  cout << "          --password-fd=n (Read the password from the first line of open file descriptor n)" << "\n" << flush;
  cout << "          --rsa-key (Use a private RSA key for decryption)" << "\n" << flush;
  cout << "          --rsa-key input args can be a private key file name or a pipe" << "\n" << flush;
  cout << "          --rsa-key-passphrase=pass (Passphrase for private RSA key, visible to other users, not recommended)" << "\n" << flush;
  cout << "          --rsa-key-passphrase-file=file (Read the private RSA key passphrase from a file only you can read)" << "\n" << flush;
  cout << "          --rsa-key-passphrase-fd=n (Read the private RSA key passphrase from open file descriptor n)" << "\n" << flush;
  cout << "          --rsa-key-username=name (Username that owns the private RSA key)" << "\n" << flush;
  cout << "          --stdout (Write decrypted output to the console)" << "\n" << flush;
  cout << "          --verbose (Turn on verbose output)" << "\n" << flush;
  cout << "          --version (Display program version number)" << "\n" << flush;
#ifdef __ENABLE_SMART_CARD__
  cout << "\n" << flush;
  cout << "          --smartcard-cert (Use a smart card for decryption)" << "\n" << flush;
  cout << "          --smartcard-pin=pin (Smart card PIN, visible to other users, not recommended)" << "\n" << flush;
  cout << "          --smartcard-pin-file=file (Read the smart card PIN from a file only you can read)" << "\n" << flush;
  cout << "          --smartcard-pin-fd=n (Read the smart card PIN from open file descriptor n)" << "\n" << flush;
  cout << "          --smartcard-slot=N (Use only the card in PKCS#11 slot N, decimal or 0x hex)" << "\n" << flush;
  cout << "          --smartcard-allow-pin-count-low (Send the PIN when the card reports low PIN tries)" << "\n" << flush;
  cout << "          --smartcard-allow-final-try (Send the PIN when the card reports one PIN try left, a wrong PIN locks the card)" << "\n" << flush;
  cout << "          --smartcard-username=name (Username assigned to the smart card cert)" << "\n" << flush;
  cout << "          --smartcard-cert-id=" << SC_get_default_cert_id() << " (Set the ID number for the smartcard cert)" << "\n" << flush;
  if(SC_uses_engine()) cout << "          --smartcard-engine=" << SC_get_default_enginePath() << " (Set the smartcard engine path)" << "\n" << flush;
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
    FC_warn_secret_on_command_line("--rsa-key-passphrase", "--rsa-key-passphrase-file or --rsa-key-passphrase-fd");
    rsa_key_passphrase = equal_arg;
    has_valid_args = 1;
  }

  // 10/27/2026: Secrets from a file or file descriptor, as in the
  // Encrypted Password Database. The buffers are wiped on exit.
  if((arg == "rsa-key-passphrase-file") || (arg == "rsa-key-passphrase-fd")) {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --" << arg.c_str() << " requires an input argument" << "\n" << flush;
      return 0;
    }
    if(ReadSecretArg(arg, equal_arg, rsa_key_passphrase) != 0) return 0;
    has_valid_args = 1;
  }
  if((arg == "password-file") || (arg == "password-fd")) {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --" << arg.c_str() << " requires an input argument" << "\n" << flush;
      return 0;
    }
    if(ReadSecretArg(arg, equal_arg, password) != 0) return 0;
    use_password = 1;
    has_valid_args = 1;
  }
  if(arg == "check-version") {
    check_version = 1;
    has_valid_args = 1;
  }
  if(arg == "access-log") {
    access_log = 1;
    if(!equal_arg.is_null()) access_log_file = equal_arg;
    has_valid_args = 1;
  }
  if(arg == "no-access-log") {
    access_log = 0;
    has_valid_args = 1;
  }
  if(arg == "verify-access-log") {
    verify_access_log = 1;
    has_valid_args = 1;
  }

  if(arg == "password") {
    if(!equal_arg.is_null()) {
      FC_warn_secret_on_command_line("--password", "--password-file or --password-fd");
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
    if(check_private_key_file(input_arg_key_file.c_str(), ebuf) != 0) { // 10/25/2026
      cerr << "ERROR: " << ebuf.c_str() << "\n" << flush;
      return 0;
    }
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
      if(check_private_key_file(private_rsa_key_file.c_str(), ebuf) != 0) { // 10/25/2026
        cerr << "ERROR: " << ebuf.c_str() << "\n" << flush;
        return 0;
      }
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

  if(arg == "list-rsa-key-users" || arg == "list-users" ) {
    list_users = 1;
    has_valid_args = 1;
  }

  if(arg == "absolute-path") {
    restore_path_mode = CRYPT_PATH_ABSOLUTE;
    has_valid_args = 1;
  }
  if(arg == "no-path") {
    restore_path_mode = CRYPT_PATH_NONE;
    has_valid_args = 1;
  }
  if(arg == "allow-unencrypted") {
    allow_unencrypted = 1;
    has_valid_args = 1;
  }
  if(arg == "stdout") {
    write_to_stdout = 1;
    has_valid_args = 1;
  }
  if(arg == "fips") {
    fips_request = FC_FIPS_ON;
    has_valid_args = 1;
  }
  if(arg == "no-fips") {
    fips_request = FC_FIPS_OFF;
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
    if(equal_arg.length() >= SC_max_cert_id_size) {
      cerr << "ERROR: --smartcard-cert-id is longer than " << (SC_max_cert_id_size-1) << " characters" << "\n" << flush;
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
    if(!SC_uses_engine()) {
      cerr << "NOTE: --smartcard-engine is ignored, this build loads the PKCS#11 provider module directly" << "\n" << flush;
    }
    if(SC_uses_engine() && (!futils_exists(sc.enginePath) || !futils_isfile(sc.enginePath))) {
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
    FC_warn_secret_on_command_line("--smartcard-pin", "--smartcard-pin-file or --smartcard-pin-fd");
    sc.SetPin(equal_arg.c_str());
    has_valid_args = 1;
  }
  if((arg == "smartcard-pin-file") || (arg == "smartcard-pin-fd")) {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --" << arg.c_str() << " requires an input argument" << "\n" << flush;
      return 0;
    }
    gxString pin_buf;
    if(ReadSecretArg(arg, equal_arg, pin_buf) != 0) return 0;
    sc.SetPin((char *)pin_buf.c_str());
    pin_buf.Clear(1);
    has_valid_args = 1;
  }

  // 10/26/2026: Log in when the card reports low PIN tries or one try left
  // 10/26/2026: Use only this PKCS#11 slot (reader), never another
  if(arg == "smartcard-slot") {
    unsigned long slot_id = 0;
    if(!SC_parse_slot(equal_arg.c_str(), &slot_id)) {
      cerr << "ERROR: --smartcard-slot needs a slot ID: --smartcard-slot=1 or --smartcard-slot=0x4" << "\n" << flush;
      return 0;
    }
    sc.SetSlot(slot_id);
    has_valid_args = 1;
  }
  if(arg == "smartcard-allow-pin-count-low") {
    sc.allow_pin_count_low = 1;
    has_valid_args = 1;
  }
  if(arg == "smartcard-allow-final-try") {
    sc.allow_pin_count_low = 1;
    sc.allow_pin_final_try = 1;
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

    case 'o': case 'O':
      overwrite = 1;
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

  if(exit_message) {
    cerr << exit_message << "\n" << flush;
  }
  FC_crypto_cleanup();
  return rv;
}

// 10/25/2026: Helpers for 2026102 format files
int CheckFileFormat(const char *fname, int &fmt)
// Returns false if the file cannot be decrypted in this mode
{
  fmt = FC_file_format(fname);
  if(fmt == FC_FORMAT_OPEN_ERROR) {
    cerr << "ERROR: Cannot open " << fname << "\n" << flush;
    return 0;
  }
  if(fmt == FC_FORMAT_LEGACY) {
    if(FC_fips_mode()) {
      cerr << "ERROR: " << fname << " uses the old file format, which FIPS mode does not allow" << "\n" << flush;
      cerr << "ERROR: Rerun with --no-fips, or convert the file with fmigrate --no-fips" << "\n" << flush;
      return 0;
    }
    if(fips_request == FC_FIPS_OFF && FC_system_fips_requested()) {
      cerr << "NOTICE: Decrypting old format file " << fname << " outside FIPS mode" << "\n" << flush;
    }
  }
  return 1;
}

int ListNewFormatUsers(const char *fname)
{
  FCryptFile fc;
  if(!fc.LoadHeader(fname)) {
    cerr << "ERROR: " << fc.err.c_str() << "\n" << flush;
    return 0;
  }
  // The key slots are not authenticated until the file is unlocked
  int n = 0;
  gxListNode<FCKeySlot> *list_ptr = fc.slots.GetHead();
  while(list_ptr) {
    if(list_ptr->data.type != FC_SLOT_SECRET) {
      if(n++ == 0) cout << "Encrypted file username inventory " << "\n" << flush;
      cout << "Username: " << list_ptr->data.username.c_str() << " Access: "
	   << FC_slot_type_name(list_ptr->data.type) << "\n" << flush;
    }
    list_ptr = list_ptr->next;
  }
  if(n == 0) {
    cerr << "ERROR: No authorized RSA users found in encrypted file " << fname << "\n" << flush;
  }
  return 1;
}

// 10/27/2026: Secrets from files and descriptors, version check and log
int ReadSecretArg(const gxString &arg, const gxString &value, gxString &secret)
// Returns 0 if successful or 1 after printing an error
{
  gxString err;
  int rv;
  if(arg.Find("-fd") != -1) rv = FC_read_secret_fd(value.c_str(), secret, err);
  else rv = FC_read_secret_file(value.c_str(), secret, err);
  if(rv != 0) cerr << "ERROR: " << err.c_str() << "\n" << flush;
  return rv;
}

int CheckVersions()
// Reports the format of each file without decrypting it and without a
// smart card. Returns 1 if any file is v1, 2 if a file cannot be read
// or is not an encrypted file, else 0.
{
  int any_v1 = 0, any_error = 0;
  gxListNode<gxString> *ptr = file_list.GetHead();
  while(ptr) {
    FCVersionInfo vi;
    gxString err;
    int rv = FC_check_version(ptr->data.c_str(), vi, err);
    if(rv != 0) {
      cout << ptr->data.c_str() << ": unknown: " << err.c_str() << "\n" << flush;
      any_error = 1;
    }
    else if(vi.is_v1) {
      cout << ptr->data.c_str() << ": v1: " << vi.version.c_str() << ", upgrade with: " << vi.upgrade.c_str() << "\n" << flush;
      any_v1 = 1;
    }
    else {
      cout << ptr->data.c_str() << ": v2: " << vi.version.c_str() << "\n" << flush;
    }
    ptr = ptr->next;
  }
  return any_v1 ? 1 : (any_error ? 2 : 0);
}

const char *AuthName()
{
  if(use_private_rsa_key) return "rsa-key";
#ifdef __ENABLE_SMART_CARD__
  if(use_smartcard_cert) return "smartcard";
#endif
  if(use_key_file) return "key-file";
  return "password";
}

gxString AuthSlotName()
{
  if(use_private_rsa_key) return rsa_key_username;
#ifdef __ENABLE_SMART_CARD__
  if(use_smartcard_cert) return smartcard_cert_username;
#endif
  return gxString();
}

void LogEvent(const char *fname, const gxString &id, const char *action, int ok,
	      const char *detail, const unsigned char *log_key)
// A log that cannot be written is reported once and never stops a decrypt
{
  if(!access_log) return;
  FCLogEntry e;
  e.tool = "fdecrypt";
  e.file = FC_abs_path(fname);
  e.id = id;
  e.auth = AuthName();
  e.slot = AuthSlotName();
  e.action = action;
  e.ok = ok;
  if(detail) e.detail = detail;
  gxString err;
  if(FC_log_append(access_log_file.c_str(), e, log_key, err) != 0 && !access_log_warned) {
    access_log_warned = 1;
    cerr << "WARNING: " << err.c_str() << ", continuing without the access log" << "\n" << flush;
  }
}

int VerifyAccessLog(const char *fname, FCryptFile &fc)
// Checks the log lines of an unlocked file. Returns 1 if they verify.
{
  unsigned char key[FC_LOG_KEY_LEN];
  FC_log_key(fc.FileKey(), FC_KEY_LEN, fc.FileID(), FC_FILE_ID_LEN, key);
  FCLogVerifyResult r;
  gxString err;
  int rv = FC_log_verify(access_log_file.c_str(), fc.FileIDHex().c_str(), key, r, err);
  OPENSSL_cleanse(key, sizeof(key));
  if(rv < 0) {
    cerr << "ERROR: " << err.c_str() << "\n" << flush;
    return 0;
  }
  cout << "Access log " << access_log_file.c_str() << " for " << fname << ": " << r.id_lines << " entries, "
       << r.tagged << " tags verified, " << r.untagged_covered << " untagged entries covered";
  if(r.trailing_untagged) cout << ", " << r.trailing_untagged << " untagged entries after the last tag (not checked)";
  cout << "\n" << flush;
  if(rv != 0) {
    cout << "TAMPERED: " << r.bad_lines << " problem(s), first at line " << r.first_bad_line << ": "
	 << r.first_bad_reason.c_str() << "\n" << flush;
    return 0;
  }
  cout << "OK: no changes found" << "\n" << flush;
  return 1;
}

int DecryptNewFormatFile(const char *fname)
{
  FCryptFile fc;
  fc.path_mode = restore_path_mode;
  fc.overwrite = overwrite;
  if(!output_dir_name.is_null()) fc.output_dir_name = output_dir_name;
  if(!fc.LoadHeader(fname)) {
    cerr << "ERROR: " << fc.err.c_str() << "\n" << flush;
    return 0;
  }

  int ok = 0;
  if(use_private_rsa_key) {
    char *passphrase = 0;
    if(!rsa_key_passphrase.is_null()) passphrase = (char *)rsa_key_passphrase.GetSPtr();
    ok = fc.UnlockWithRSAKey(rsa_key_username.c_str(), private_key, private_key_len, passphrase);
    if(!ok) {
      cerr << "ERROR: The private RSA key provided for user " << rsa_key_username.c_str() << " does not have access to decrypt file " << fname << "\n" << flush;
    }
  }
#ifdef __ENABLE_SMART_CARD__
  else if(use_smartcard_cert) {
    FCKeySlot *slot = fc.FindSlot(FC_SLOT_SMARTCARD, smartcard_cert_username.c_str());
    if(!slot) {
      fc.err << clear << "No smart card slot for user " << smartcard_cert_username;
    }
    else {
      unsigned char file_key[FC_MAX_WRAPPED_LEN];
      unsigned file_key_len = 0;
      int rv = SC_private_key_decrypt(&sc, slot->wrapped.m_buf(), slot->wrapped.length(),
				      file_key, sizeof(file_key), &file_key_len, RSA_PKCS1_OAEP_PADDING);
      if(rv != 0) {
	fc.err << clear << "Smart card private key decrypt failed for cert ID " << sc.cert_id << ": " << sc.err_string;
      }
      else if(file_key_len != FC_KEY_LEN) {
	fc.err << clear << "Bad length for decrypted key";
      }
      else {
	ok = fc.UnlockWithFileKey(file_key);
      }
      OPENSSL_cleanse(file_key, sizeof(file_key));
    }
    if(!ok) {
      cerr << "ERROR: Smart card for user " << smartcard_cert_username.c_str() << " does not have access to decrypt file " << fname << "\n" << flush;
    }
  }
#endif
  else {
    ok = fc.UnlockWithSecret(aes_file_decrypt_secret);
  }
  if(!ok) {
    LogEvent(fname, fc.FileIDHex(), "open", 0, "credential did not open the file", 0);
    cerr << "ERROR: File decrypt failed " << fname << "\n" << flush;
    cerr << "ERROR: " << fc.err.c_str() << "\n" << flush;
    return 0;
  }
  unsigned char log_key[FC_LOG_KEY_LEN];
  FC_log_key(fc.FileKey(), FC_KEY_LEN, fc.FileID(), FC_FILE_ID_LEN, log_key);
  if(verify_access_log) {
    OPENSSL_cleanse(log_key, sizeof(log_key));
    return VerifyAccessLog(fname, fc);
  }
  LogEvent(fname, fc.FileIDHex(), "open", 1, 0, log_key);
  OPENSSL_cleanse(log_key, sizeof(log_key));

  if(list_file_names) {
    gxString sbuf;
    if(!fc.DecryptStoredName(sbuf)) {
      cerr << "ERROR: File decrypt failed " << fname << "\n" << flush;
      cerr << "ERROR: " << fc.err.c_str() << "\n" << flush;
      return 0;
    }
    if(clientcfg->verbose_mode) cerr << "File decrypt successful" << "\n" << flush;
    cout << "Decrypted name: " << sbuf.c_str() << "\n" << flush;
    return 1;
  }

  if(write_to_stdout) ok = fc.DecryptFile("stdout");
  else if(use_ouput_file) ok = fc.DecryptFile(user_defined_output_file.c_str());
  else ok = fc.DecryptFile();
  if(!ok) {
    cerr << "ERROR: File decrypt failed " << fname << "\n" << flush;
    cerr << "ERROR: " << fc.err.c_str() << "\n" << flush;
    return 0;
  }
  if(clientcfg->verbose_mode) {
    gxString sbuf;
    sbuf << clear << wn << fc.bytes_wrote;
    cerr << "File decrypt successful" << "\n" << flush;
    cerr << "Wrote " << sbuf.c_str() << " bytes to " << fc.ofname.c_str() << "\n" << flush;
  }
  if(remove_src_file) {
    if(futils_remove(fname) != 0) {
      cerr << "ERROR: Error removing " << fname << " source file" << "\n" << flush;
    }
  }
  return 1;
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

  // 10/27/2026: Only --rsa-key with no file name reads the key from
  // stdin, so stdin stays free for --password-fd=0
  int stdin_key = 0;
  for(int i = 1; i < argc; i++) {
    if(strcmp(argv[i], "--rsa-key") == 0) stdin_key = 1;
  }
  int selectRetVal = stdin_key ? select(1, &readfds, &writefds, &exceptfds, &timeout) : 0;
  char buf[1];
  unsigned bytes_read = 0;
  
  if(selectRetVal > 0) {
    if(FD_ISSET(fileno(stdin), &readfds)) {
      while(read(0, buf, sizeof(buf)) > 0) {
	if(bytes_read >= sizeof(private_key)) {
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
	  int arg_ok = ProcessArgs(arg);
	  FC_wipe_secret_arg(argv[narg]); // 10/27/2026: Remove secrets from the process arguments
	  if(!arg_ok) return ExitProgram(1); // Exit if argument is not valid
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

  if(restore_path_mode == CRYPT_PATH_ABSOLUTE && !output_dir_name.is_null()) {
    cerr << "ERROR: --absolute-path cannot be used with --outdir" << "\n" << flush;
    return ExitProgram(1);
  }
  
  gxString fips_err;
  if(!FC_crypto_init(fips_request, fips_err)) {
    cerr << "ERROR: " << fips_err.c_str() << "\n" << flush;
    return ExitProgram(1);
  }
  if(clientcfg->verbose_mode) cerr << FC_crypto_status().c_str() << "\n" << flush;

  // 10/27/2026: Never asks for a credential or touches a smart card
  if(check_version) return ExitProgram(CheckVersions());
  if(verify_access_log && !access_log) access_log = 1;
  if(access_log && access_log_file.is_null()) access_log_file = FC_default_log_file(".fcrypt");

  if(use_key_file) {
    if(clientcfg->verbose_mode) cerr << "Using key file for decryption" << "\n" << flush;
    aes_file_decrypt_secret.Clear(1);
    aes_file_decrypt_secret = key;
  }
  else if(use_private_rsa_key) {
    if(rsa_key_username.is_null()) {
      cerr << "ERROR: --rsa-key requires --rsa-key-username" << "\n" << flush;
      return ExitProgram(1);
    }
    if(clientcfg->verbose_mode) cerr << "Using private RSA key file for decryption" << "\n" << flush;
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
    if(clientcfg->verbose_mode) cerr << "Using smart card cert for decryption" << "\n" << flush;

    if(clientcfg->verbose_mode) {
      if(SC_uses_engine()) {
        cerr << "Smart card engine ID = " << sc.engine_ID << "\n" << flush;
        cerr << "Smart card engine path = " << sc.enginePath << "\n" << flush;
      }
      cerr << "Smart card module path = " << sc.modulePath << "\n" << flush;
      cerr << "Smart card cert ID = " << sc.cert_id << "\n"  << flush;
    }

    if(SC_uses_engine() && (!futils_exists(sc.enginePath) || !futils_isfile(sc.enginePath))) {
      cerr << "ERROR: Smart card engine " << sc.enginePath << " does not exist or cannot be read" <<  "\n" << flush;
      return ExitProgram(1);
    }
    if(!futils_exists(sc.modulePath) || !futils_isfile(sc.modulePath)) {
      cerr << "ERROR: Smart card provider " << sc.modulePath << " does not exist or cannot be read" <<  "\n" << flush;
      return ExitProgram(1);
    }

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
  else if(list_users) {
    DEBUG_m("No auth list users operation");
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

  if(list_users) { // List user names found and exit program
    while(ptr) {
      cout << "Listing usernames with RSA key access to encrypted file " << ptr->data.c_str() << "\n" << flush;
      int fmt = FC_file_format(ptr->data.c_str());
      if(fmt == FC_FORMAT_2026102) {
	if(!ListNewFormatUsers(ptr->data.c_str())) err = 1;
	ptr = ptr->next;
	continue;
      }
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
      cout << "Encrypted file username inventory " << "\n" << flush;
      gxString access_type = "Unknown";
      while(list_ptr) {
	if(list_ptr->data.block_header.block_type == 1) access_type = "RSA key";
	if(list_ptr->data.block_header.block_type == 2) access_type = "Smart Card";
	cout << "Username: " << list_ptr->data.username.c_str() << " Access: " << access_type.c_str() << "\n" << flush;
      	list_ptr = list_ptr->next;
      }
      ptr = ptr->next;
    }  
    return ExitProgram(err);
  }
  
  while(ptr) { // Decrypt file and exit program
    if(clientcfg->verbose_mode) cerr << "Decrypting: " << ptr->data.c_str() << "\n" << flush;

    int fmt;
    if(!CheckFileFormat(ptr->data.c_str(), fmt)) {
      err = 1;
      ptr = ptr->next;
      continue;
    }
    if(fmt == FC_FORMAT_2026102) {
      if(!DecryptNewFormatFile(ptr->data.c_str())) err = 1;
      ptr = ptr->next;
      continue;
    }

    // Files from releases before 2026.102
    {
      FCVersionInfo vi; // 10/27/2026: Warn about v1 files still in use
      gxString verr;
      if(FC_check_version(ptr->data.c_str(), vi, verr) == 0 && vi.is_v1) {
	cerr << FC_v1_warning(ptr->data.c_str(), vi).c_str() << "\n" << flush;
      }
      if(verify_access_log) {
	cerr << "ERROR: " << ptr->data.c_str() << " is a v1 file, its access log entries have no tags to verify" << "\n" << flush;
	err = 1;
	ptr = ptr->next;
	continue;
      }
      LogEvent(ptr->data.c_str(), gxString(), "open", 1, "v1 file, decrypt result follows on stderr", 0);
    }
    
    FCryptCache fc(num_buckets);
    fc.key_iterations = key_iterations;
    fc.SetPathMode(restore_path_mode);
    fc.SetOverWrite(overwrite);
    fc.SetAllowUnencrypted(allow_unencrypted);
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
	
	if((rsa_key_username == list_ptr->data.username.c_str()) && (list_ptr->data.block_header.block_type == 1)) {
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
	  // 10/24/2026: Check the length before subtracting the salt length
	  if(decrypted_data_len < (AES_MAX_SALT_LEN + AES_MIN_SECRET_LEN) ||
	     decrypted_data_len > sizeof(rsa_decrypted_message)) {
	    cerr << "ERROR: Bad length for decrypted key" << "\n" << flush;
	    found_key = 0;
	    err = 1;
	    break;
	  }
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
	  if(list_ptr->data.hmac.length() != sizeof(hash) ||
	     CRYPTO_memcmp(hash, list_ptr->data.hmac.m_buf(), sizeof(hash)) != 0) {
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
	
	if((smartcard_cert_username == list_ptr->data.username.c_str()) && (list_ptr->data.block_header.block_type == 2)) {
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
	  // 10/24/2026: Check the length before subtracting the salt length
	  if(decrypted_data_len < (AES_MAX_SALT_LEN + AES_MIN_SECRET_LEN) ||
	     decrypted_data_len > sizeof(rsa_decrypted_message)) {
	    cerr << "ERROR: Bad length for decrypted key" << "\n" << flush;
	    found_key = 0;
	    err = 1;
	    break;
	  }
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
	  if(list_ptr->data.hmac.length() != sizeof(hash) ||
	     CRYPTO_memcmp(hash, list_ptr->data.hmac.m_buf(), sizeof(hash)) != 0) {
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
	cerr << "ERROR: Smart card for user " << smartcard_cert_username.c_str() << " does not have access to decrypt file " << ptr->data.c_str() << "\n" << flush;
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
      cerr << "ERROR: File decrypt failed " << ptr->data.c_str() << "\n" << flush;
      if(!fc.err.is_null()) cerr << "ERROR: " << fc.err.c_str() << "\n" << flush;
      err = 1;
      ptr = ptr->next;
      continue;
    }
    if(fc.ERROR_LEVEL != 0) { // Check the ERROR level from the file caching ops
      cerr << "ERROR: File decrypt failed " << ptr->data.c_str() << "\n" << flush;
      if(!fc.err.is_null()) cerr << "ERROR: " << fc.err.c_str() << "\n" << flush;
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
