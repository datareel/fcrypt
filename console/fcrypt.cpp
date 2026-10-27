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
#include "fckeymgmt.h"

#ifdef __MSVC_DEBUG__
#include "leaktest.h"
#endif

#include "devcache.h"
#include "memblock.h"
#include "gxlist.h"
#include "gxbstree.h"
#include "bstreei.h"
#include "gxs_b64.h"

#if defined (__UNIX__)
#include <unistd.h>
#endif

#include <fcntl.h>

// Globals
gxString debug_message;
int debug_mode = 0;
int debug_level = 1;
int num_buckets = 1024;
int overwrite = 0;
int mode = -1;
unsigned key_iterations = FC_DEF_ITERATIONS; // 10/25/2026: PBKDF2 iterations
unsigned legacy_key_iterations = AES_DEF_ITERATIONS; // Old format files, set with --iter
int fips_request = FC_FIPS_AUTO;
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
unsigned static_data_size = FC_DEF_SLOT_AREA_LEN;
gxString decrypted_output_filename;
// 10/27/2026: Key management
int remove_user = 0;
gxString remove_username;
unsigned remove_user_type = 0; // 0 = the only slot of the user
int rekey = 0;
gxString rekey_input_fd;
gxString rekey_input_file;
gxString rekey_new_password_fd;
gxString rekey_new_password_file;
int use_private_rsa_key = 0; // Authenticate key management with a private RSA key
gxString private_rsa_key_file;
char private_key[RSA_max_keybuf_len];
unsigned private_key_len = 0;
int private_key_has_passphrase = 0;
int access_log = 0;
gxString access_log_file;
int access_log_warned = 0;
int non_interactive = 0;  // 10/27/2026: Automation
int dry_run = 0;
int quiet_mode = 0;
unsigned lock_timeout = FC_DEF_LOCK_TIMEOUT;
int exit_code = 0;
void SetExit(int code) { if(!exit_code) exit_code = code; }
#define NOTE if(!quiet_mode) cerr
#ifdef __ENABLE_SMART_CARD__
SmartCardOB sc;
int use_smartcard_auth = 0;  // 10/27/2026: Authenticate key management with a smart card
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
int ReadSecretArg(const gxString &arg, const gxString &value, gxString &secret);
int KeyManagement();
int DEBUG_m(char *message, int level = 1, int rv = 0);
int ExitProgram(int rv = 0, char *exit_message = 0);

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
  cout << "Encrypted file format: " << FC_FILE_VERSION << "\n" << flush;
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
  cout << "          --fips (Use only the OpenSSL FIPS provider, see README.txt)" << "\n" << flush;
  cout << "          --iter=num (Set the number of PBKDF2 key iterations, default " << FC_DEF_ITERATIONS << ")" << "\n" << flush;
  cout << "          --key=aes_key (Use a key file for symmetric file encryption)" << "\n" << flush;
  cout << "          --no-fips (Do not use FIPS mode, even if the system is in FIPS mode)" << "\n" << flush;
  cout << "          --outfile=fname (Write encrypted output to specified file name)" << "\n" << flush;
  cout << "          --outdir=dir (Write encrypted output to this directory)" << "\n" << flush;
  cout << "          --password (Use a password for symmetric file encryption, prompts for the password)" << "\n" << flush;
  cout << "          --password-file=file (Read the password from the first line of a file only you can read)" << "\n" << flush;
  cout << "          --password-fd=n (Read the password from the first line of open file descriptor n)" << "\n" << flush;
  cout << "          --rsa-key-passphrase (Passphrase for public RSA key)" << "\n" << flush;
  cout << "          --rsa-key-passphrase-file=file (Read the RSA key passphrase from a file only you can read)" << "\n" << flush;
  cout << "          --rsa-key-passphrase-fd=n (Read the RSA key passphrase from open file descriptor n)" << "\n" << flush;
  cout << "          --rsa-key-username=name (Assign a name to the public RSA key)" << "\n" << flush;
  cout << "          --static-data-size=num (Set size of the key slot area, default " << FC_DEF_SLOT_AREA_LEN << ")" << "\n" << flush;  
  cout << "          --verbose (Turn on verbose output)" << "\n" << flush;  
  cout << "          --version (Display program version number)" << "\n" << flush;
#ifdef __ENABLE_SMART_CARD__
  cout << "\n" << flush;
  cout << "          --add-smartcard-cert (Add access to encrypted file for a smart card)" << "\n" << flush;
  cout << "          --smartcard-username=name (Assign a name to smart card cert)" << "\n" << flush;
  cout << "          --smartcard-cert-id=" << SC_get_default_cert_id() << " (Set the ID number for the smart card cert)" << "\n" << flush;
  if(SC_uses_engine()) cout << "          --smartcard-engine=" << SC_get_default_enginePath() << " (Set the smart card engine path)" << "\n" << flush;
  cout << "          --smartcard-provider=" << SC_get_default_modulePath() << " (Set the smart card provider)" << "\n" << flush;
  cout << "          --smartcard-slot=N (Use only the card in PKCS#11 slot N, decimal or 0x hex, see smartcard_list)" << "\n" << flush;
  cout << "\n" << flush;
  cout << "          --add-smartcard-cert-file (Add access to an encrypted file for another users exported smart card cert)" << "\n" << flush;
  cout << "          --add-smartcard-cert-file input arg must be a file name" << "\n" << flush;
#endif // __ENABLE_SMART_CARD__
  cout << "\n" << flush;
  cout << "Key management (2026102 format files):" << "\n" << flush;
  cout << "          --remove-user=name (Remove the RSA key or smart card access of a user)" << "\n" << flush;
  cout << "          --remove-user-type=rsa|smartcard (Which access to remove when the user has both)" << "\n" << flush;
  cout << "                 Removing a user does not revoke a file key the user already recovered, run --rekey after" << "\n" << flush;
  cout << "          --rekey (Give the file a new key and encrypt it again, every RSA and smart card user is rewrapped)" << "\n" << flush;
  cout << "          --rekey-file=file (Read the rekey input from a file only you can read, default stdin)" << "\n" << flush;
  cout << "          --rekey-fd=n (Read the rekey input from open file descriptor n)" << "\n" << flush;
  cout << "                 Rekey input lines: password=, new-password=, drop-password=yes," << "\n" << flush;
  cout << "                 rsa:user=public_key.pem, smartcard:user=cert.pem or smartcard:user=card (no PIN)," << "\n" << flush;
  cout << "                 drop-rsa:user=yes, drop-smartcard:user=yes. Values use \\n \\t \\\\ escapes, see README.txt" << "\n" << flush;
  cout << "          --rekey-new-password-file=file (Generate a new password for the password slot and write it to a new file)" << "\n" << flush;
  cout << "          --rekey-new-password-fd=n (Generate a new password and write it to open file descriptor n)" << "\n" << flush;
  cout << "          Authenticate key management with --password, --password-file, --password-fd or --key, or" << "\n" << flush;
  cout << "          --rsa-key=private_key.pem with --rsa-key-username" << "\n" << flush;
#ifdef __ENABLE_SMART_CARD__
  cout << "          --smartcard-cert (Authenticate key management with the smart card, logs in to the card once)" << "\n" << flush;
  cout << "          --smartcard-pin-file=file (Read the smart card PIN from a file only you can read)" << "\n" << flush;
  cout << "          --smartcard-pin-fd=n (Read the smart card PIN from open file descriptor n)" << "\n" << flush;
  cout << "          --smartcard-allow-pin-count-low (Send the PIN when the card reports low PIN tries)" << "\n" << flush;
  cout << "          --smartcard-allow-final-try (Send the PIN when the card reports one PIN try left, a wrong PIN locks the card)" << "\n" << flush;
#endif // __ENABLE_SMART_CARD__
  cout << "          --access-log[=file] (Log user changes and rekeys, default " << FC_default_log_file(".fcrypt").c_str() << ")" << "\n" << flush;
  cout << "          --no-access-log (Do not log, the default)" << "\n" << flush;
  cout << "          --dry-run (Write and check the changed file for --remove-user or --rekey, then remove it)" << "\n" << flush;
  cout << "          --non-interactive, --batch (Never prompt, a missing password, PIN or input is an error)" << "\n" << flush;
  cout << "          --quiet (Only errors)" << "\n" << flush;
  cout << "          --lock-timeout=seconds (Wait this long for another writer of the file, default " << FC_DEF_LOCK_TIMEOUT << ")" << "\n" << flush;
  cout << "          Exit codes for --remove-user and --rekey: 0 ok, 1 usage or other error, 2 the credential did not" << "\n" << flush;
  cout << "          open the file, 3 file or user not found, 4 locked by another writer, 7 read or write error" << "\n" << flush;

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
    if((static_data_size < FC_MIN_SLOT_AREA_LEN) || (static_data_size > FC_MAX_SLOT_AREA_LEN)) {
      cerr << "ERROR: Bad static data storage value specified" << "\n" << flush;
      cerr << "ERROR: Valid range = " << FC_MIN_SLOT_AREA_LEN << " to " << FC_MAX_SLOT_AREA_LEN << " bytes" << "\n" << flush;
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

  // 10/25/2026: FIPS mode
  if(arg == "fips") {
    fips_request = FC_FIPS_ON;
    has_valid_args = 1;
  }
  if(arg == "no-fips") {
    fips_request = FC_FIPS_OFF;
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
      if(check_private_key_file(input_arg_key_file.c_str(), ebuf) != 0) { // 10/25/2026
        cerr << "ERROR: " << ebuf.c_str() << "\n" << flush;
        return 0;
      }
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
    // 10/25/2026: PBKDF2 iterations for the 2026102 file format
    if(equal_arg.Atoi() < (int)FC_MIN_ITERATIONS || equal_arg.Atoi() > (int)FC_MAX_ITERATIONS) {
      cerr << "ERROR: --iter must be " << FC_MIN_ITERATIONS << " to " << FC_MAX_ITERATIONS << "\n" << flush;
      return 0;
    }
    key_iterations = legacy_key_iterations = equal_arg.Atoi();
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

  // 10/27/2026: Secrets from a file or file descriptor, never argv
  if((arg == "password-file") || (arg == "password-fd")) {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --" << arg.c_str() << " requires an input argument" << "\n" << flush;
      return 0;
    }
    if(ReadSecretArg(arg, equal_arg, password) != 0) return 0;
    use_password = 1;
    has_valid_args = 1;
  }
  if((arg == "rsa-key-passphrase-file") || (arg == "rsa-key-passphrase-fd")) {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --" << arg.c_str() << " requires an input argument" << "\n" << flush;
      return 0;
    }
    if(ReadSecretArg(arg, equal_arg, rsa_key_passphrase) != 0) return 0;
    has_valid_args = 1;
  }

  // 10/27/2026: Key management
  if(arg == "remove-user") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --remove-user missing name: --remove-user=name" << "\n" << flush;
      return 0;
    }
    remove_username = equal_arg;
    remove_user = 1;
    has_valid_args = 1;
  }
  if(arg == "remove-user-type") {
    gxString t = equal_arg;
    t.ToLower();
    if(t == "rsa") remove_user_type = FC_SLOT_RSA;
    else if(t == "smartcard") remove_user_type = FC_SLOT_SMARTCARD;
    else {
      cerr << "ERROR: --remove-user-type must be rsa or smartcard" << "\n" << flush;
      return 0;
    }
    has_valid_args = 1;
  }
  if(arg == "rekey") {
    rekey = 1;
    has_valid_args = 1;
  }
  if(arg == "rekey-fd" || arg == "rekey-file" || arg == "rekey-new-password-fd" || arg == "rekey-new-password-file") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --" << arg.c_str() << " requires an input argument" << "\n" << flush;
      return 0;
    }
    if(arg == "rekey-fd") rekey_input_fd = equal_arg;
    if(arg == "rekey-file") rekey_input_file = equal_arg;
    if(arg == "rekey-new-password-fd") rekey_new_password_fd = equal_arg;
    if(arg == "rekey-new-password-file") rekey_new_password_file = equal_arg;
    has_valid_args = 1;
  }
  if(arg == "rsa-key") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --rsa-key missing filename: --rsa-key=$HOME/keys/rsa_key.pem" << "\n" << flush;
      return 0;
    }
    private_rsa_key_file = equal_arg;
    if(!futils_exists(private_rsa_key_file.c_str()) || !futils_isfile(private_rsa_key_file.c_str())) {
      cerr << "ERROR: Private RSA key file " << private_rsa_key_file.c_str() << " does not exist or cannot be read" <<  "\n" << flush;
      return 0;
    }
    if(check_private_key_file(private_rsa_key_file.c_str(), ebuf) != 0) {
      cerr << "ERROR: " << ebuf.c_str() << "\n" << flush;
      return 0;
    }
    rv = RSA_read_key_file(private_rsa_key_file.c_str(), private_key, sizeof(private_key), &private_key_len, &private_key_has_passphrase);
    if(rv != RSA_NO_ERROR) {
      cerr << "ERROR: " << RSA_err_string(rv) << "\n" << flush;
      return 0;
    }
    use_private_rsa_key = 1;
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
  if(arg == "non-interactive" || arg == "batch") {
    non_interactive = 1;
    has_valid_args = 1;
  }
  if(arg == "dry-run") {
    dry_run = 1;
    has_valid_args = 1;
  }
  if(arg == "quiet") {
    quiet_mode = 1;
    has_valid_args = 1;
  }
  if(arg == "lock-timeout") {
    if(equal_arg.is_null() || equal_arg.Atoi() < 0 || equal_arg.Atoi() > 3600) {
      cerr << "ERROR: --lock-timeout must be 0 to 3600 seconds" << "\n" << flush;
      return 0;
    }
    lock_timeout = (unsigned)equal_arg.Atoi();
    has_valid_args = 1;
  }

#ifdef __ENABLE_SMART_CARD__
  if(arg == "smartcard-cert") {
    use_smartcard_auth = 1;
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

  // 10/26/2026: Use only the card in this PKCS#11 slot
  if(arg == "smartcard-slot") {
    unsigned long slot_id = 0;
    if(!SC_parse_slot(equal_arg.c_str(), &slot_id)) {
      cerr << "ERROR: --smartcard-slot needs a slot ID: --smartcard-slot=1 or --smartcard-slot=0x4" << "\n" << flush;
      return 0;
    }
    sc.SetSlot(slot_id);
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

int ReadSecretArg(const gxString &arg, const gxString &value, gxString &secret)
// 10/27/2026: Read a secret for a --xxx-file or --xxx-fd argument.
// Returns 0 if successful or 1 after printing an error.
{
  gxString err;
  int rv;
  if(arg.Find("-fd") != -1) rv = FC_read_secret_fd(value.c_str(), secret, err);
  else rv = FC_read_secret_file(value.c_str(), secret, err);
  if(rv != 0) cerr << "ERROR: " << err.c_str() << "\n" << flush;
  return rv;
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
      // 10/25/2026: The 2026102 file format always encrypts
      cerr << "ERROR: -0 (no encryption) is not supported by the " << FC_FILE_VERSION << " file format" << "\n" << flush;
      return 0;

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
int CheckLegacyFile(const char *fname, int &fmt)
// Returns false if the file cannot be used in this mode
{
  fmt = FC_file_format(fname);
  if(fmt == FC_FORMAT_OPEN_ERROR) {
    cerr << "ERROR: Cannot open " << fname << "\n" << flush;
    return 0;
  }
  if(fmt == FC_FORMAT_LEGACY && FC_fips_mode()) {
    cerr << "ERROR: " << fname << " uses the old file format, which FIPS mode does not allow" << "\n" << flush;
    cerr << "ERROR: Rerun with --no-fips, or convert the file with fmigrate --no-fips" << "\n" << flush;
    return 0;
  }
  return 1;
}

void ListNewFormatUsers(FCryptFile &fc)
{
  cerr << "Key slot area size = " << fc.slot_area_len << "\n" << flush;
  cerr << "Authorized users list = ";
  int n = 0;
  gxListNode<FCKeySlot> *list_ptr = fc.slots.GetHead();
  while(list_ptr) {
    if(list_ptr->data.type != FC_SLOT_SECRET) {
      if(n++) cerr << ", ";
      cerr << list_ptr->data.username.c_str();
    }
    list_ptr = list_ptr->next;
  }
  cerr << "\n" << flush;
}

int OpenNewFormatFile(FCryptFile &fc, const char *fname, const MemoryBuffer &secret)
{
  if(!fc.LoadHeader(fname) || !fc.UnlockWithSecret(secret)) {
    cerr << "ERROR: " << fc.err.c_str() << "\n" << flush;
    return 0;
  }
  return 1;
}

// ----------------------------------------------------------- //
// 10/27/2026: Key management: --remove-user and --rekey
// ----------------------------------------------------------- //
const char *AuthName()
{
  if(use_private_rsa_key) return "rsa-key";
#ifdef __ENABLE_SMART_CARD__
  if(use_smartcard_auth) return "smartcard";
#endif
  if(use_key_file) return "key-file";
  return "password";
}

gxString AuthSlotName()
{
  if(use_private_rsa_key) return rsa_key_username;
#ifdef __ENABLE_SMART_CARD__
  if(use_smartcard_auth) return smartcard_cert_username;
#endif
  return gxString();
}

void LogEvent(const char *fname, const gxString &id, const char *action, const gxString &slot, int ok,
	      const char *detail, const unsigned char *log_key)
// Writes an access log entry when --access-log is on. A log that cannot
// be written is reported once and never stops the operation.
{
  if(!access_log) return;
  FCLogEntry e;
  e.tool = "fcrypt";
  e.file = FC_abs_path(fname);
  e.id = id;
  e.auth = AuthName();
  e.slot = slot;
  e.action = action;
  e.ok = ok;
  if(detail) e.detail = detail;
  gxString err;
  if(FC_log_append(access_log_file.c_str(), e, log_key, err) != 0 && !access_log_warned) {
    access_log_warned = 1;
    cerr << "WARNING: " << err.c_str() << ", continuing without the access log" << "\n" << flush;
  }
}

int UnlockForKeyManagement(FCryptFile &nf, const char *fname, gxString &err)
// Opens the file with the credential given on the command line. A smart
// card is used through the one card login of SC_private_key_decrypt().
{
  if(!nf.LoadHeader(fname)) {
    err = nf.err;
    return 0;
  }
  if(use_private_rsa_key) {
    char *passphrase = 0;
    if(!rsa_key_passphrase.is_null()) passphrase = (char *)rsa_key_passphrase.GetSPtr();
    if(!nf.UnlockWithRSAKey(rsa_key_username.c_str(), private_key, private_key_len, passphrase)) {
      err = nf.err;
      return 0;
    }
    return 1;
  }
#ifdef __ENABLE_SMART_CARD__
  if(use_smartcard_auth) {
    FCKeySlot *slot = nf.FindSlot(FC_SLOT_SMARTCARD, smartcard_cert_username.c_str());
    if(!slot) {
      err << clear << "No smart card slot for user " << smartcard_cert_username;
      return 0;
    }
    unsigned char file_key[FC_MAX_WRAPPED_LEN];
    unsigned file_key_len = 0;
    int rv = SC_private_key_decrypt(&sc, slot->wrapped.m_buf(), slot->wrapped.length(),
				    file_key, sizeof(file_key), &file_key_len, RSA_PKCS1_OAEP_PADDING);
    int ok = 0;
    if(rv != 0) err << clear << "Smart card private key decrypt failed for cert ID " << sc.cert_id << ": " << sc.err_string;
    else if(file_key_len != FC_KEY_LEN) err << clear << "Bad length for decrypted key";
    else {
      ok = nf.UnlockWithFileKey(file_key);
      if(!ok) err = nf.err;
    }
    OPENSSL_cleanse(file_key, sizeof(file_key));
    return ok;
  }
#endif
  if(!nf.UnlockWithSecret(aes_file_encrypt_secret)) {
    err = nf.err;
    return 0;
  }
  return 1;
}

int WrapForRekey(const FCRekeySlot &slot, const unsigned char key[FC_KEY_LEN],
		 unsigned char *wrapped, unsigned *wrapped_len, gxString &err)
// Wraps the new file key with the public key of an RSA or smart card
// slot. Never logs in to a card.
{
  if(slot.type == FC_SLOT_RSA) {
    char pub[RSA_max_keybuf_len];
    unsigned pub_len = 0;
    int has_pass = 0;
    if(RSA_read_key_file(slot.source.c_str(), pub, sizeof(pub), &pub_len, &has_pass) != RSA_NO_ERROR) {
      err << clear << "Cannot read the public key file " << slot.source << " for user " << slot.username;
      return 0;
    }
    EVP_PKEY *pkey = RSA_load_public_key((const unsigned char *)pub, pub_len, 0);
    memset(pub, 0, sizeof(pub));
    if(!pkey) {
      err << clear << slot.source << " is not a public RSA key (user " << slot.username << ")";
      return 0;
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    int ok = EVP_PKEY_is_a(pkey, "RSA") && EVP_PKEY_get_bits(pkey) >= (int)FC_MIN_RSA_BITS;
#else
    int ok = (EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA) && EVP_PKEY_bits(pkey) >= (int)FC_MIN_RSA_BITS;
#endif
    if(ok) ok = (RSA_pkey_encrypt(pkey, key, FC_KEY_LEN, wrapped, FC_MAX_WRAPPED_LEN, wrapped_len,
				  RSA_PKCS1_OAEP_PADDING) == RSA_NO_ERROR);
    EVP_PKEY_free(pkey);
    if(!ok) err << clear << "Cannot wrap the new key with the RSA key of user " << slot.username
		<< " (it must be an RSA key of at least " << FC_MIN_RSA_BITS << " bits)";
    return ok;
  }
#ifdef __ENABLE_SMART_CARD__
  if(slot.type == FC_SLOT_SMARTCARD) {
    int rv;
    if(slot.source == "card") {
      // Reads the public key from the card, no PIN
      rv = SC_public_key_encrypt(&sc, key, FC_KEY_LEN, wrapped, FC_MAX_WRAPPED_LEN, wrapped_len, RSA_PKCS1_OAEP_PADDING);
      if(rv != 0) err << clear << "Cannot read the cert of user " << slot.username << " from the card: " << sc.err_string;
    }
    else {
      SmartCardOB cert;
      rv = SC_read_cert_file(&cert, slot.source.c_str());
      if(rv == 0) rv = SC_cert_file_public_key_encrypt(&cert, key, FC_KEY_LEN, wrapped, FC_MAX_WRAPPED_LEN,
						       wrapped_len, RSA_PKCS1_OAEP_PADDING);
      if(rv != 0) err << clear << "Cannot wrap the new key with the cert " << slot.source << " of user "
		      << slot.username << ": " << cert.err_string;
    }
    return rv == 0;
  }
#else
  if(slot.type == FC_SLOT_SMARTCARD) {
    err << clear << "Smart card support is not enabled, cannot rewrap the smart card slot of " << slot.username;
    return 0;
  }
#endif
  err << clear << "Unknown slot type";
  return 0;
}

int ReadRekeyInput(FCRekeyInput &in)
{
  MemoryBuffer data;
  gxString err;
  int rv;
  if(!rekey_input_file.is_null()) rv = FC_read_input_file(rekey_input_file.c_str(), data, err);
  else if(!rekey_input_fd.is_null()) rv = FC_read_input_fd(rekey_input_fd.c_str(), data, err);
  else if(FC_stdin_is_terminal()) rv = 0; // No input, the plan lists what is missing
  // (with --non-interactive too: nothing is read from a terminal)
  else rv = FC_read_input_fd("0", data, err);
  gxList<FCNameValue> list;
  if(rv == 0) rv = FC_parse_name_values(data, list, err);
  data.Clear(1);
  if(rv == 0) rv = FC_parse_rekey_input(list, in, err);
  FC_wipe_name_values(list);
  if(rv != 0) cerr << "ERROR: Rekey input: " << err.c_str() << "\n" << flush;
  return rv == 0;
}

int RekeyFile(FCryptFile &nf, const char *fname, FCRekeyInput &in, const unsigned char old_log_key[FC_LOG_KEY_LEN])
{
  gxList<FCRekeySlot> existing, keep;
  int has_password_slot = 0;
  for(gxListNode<FCKeySlot> *p = nf.slots.GetHead(); p; p = p->next) {
    if(p->data.type == FC_SLOT_SECRET) {
      has_password_slot = 1;
      continue;
    }
    FCRekeySlot r;
    r.type = p->data.type;
    r.username = p->data.username;
    existing.Add(r);
  }
  int password_supplied = !use_private_rsa_key;
#ifdef __ENABLE_SMART_CARD__
  if(use_smartcard_auth) password_supplied = 0;
#endif
  int generate = !rekey_new_password_file.is_null() || !rekey_new_password_fd.is_null();
  int pw_action = 0;
  gxString missing, err;
  int rv = FC_rekey_plan(existing, has_password_slot, password_supplied, generate, in, keep, pw_action, missing, err);
  if(rv == 1) {
    cerr << "ERROR: The rekey of " << fname << " needs a choice for every key slot, nothing was changed. Missing from the rekey input:" << "\n"
	 << missing.c_str() << flush;
    return 0;
  }
  if(rv != 0) {
    cerr << "ERROR: " << err.c_str() << "\n" << flush;
    return 0;
  }

  // The secret for the password slot
  MemoryBuffer new_secret;
  gxString generated;
  if(pw_action == FC_REKEY_PW_KEEP) {
    if(password_supplied) new_secret = aes_file_encrypt_secret;
    else {
      new_secret.Cat(in.password.GetSPtr(), in.password.length());
      FCryptFile chk; // The given password must open the password slot
      if(!chk.LoadHeader(fname) || !chk.UnlockWithSecret(new_secret)) {
	cerr << "ERROR: The password= in the rekey input does not open the password slot of " << fname << "\n" << flush;
	new_secret.Clear(1);
	return 0;
      }
    }
  }
  else if(pw_action == FC_REKEY_PW_NEW) {
    if((int)in.new_password.length() < AES_MIN_SECRET_LEN) {
      cerr << "ERROR: The new password must be at least " << AES_MIN_SECRET_LEN << " characters long" << "\n" << flush;
      return 0;
    }
    new_secret.Cat(in.new_password.GetSPtr(), in.new_password.length());
  }
  else if(pw_action == FC_REKEY_PW_GENERATE) {
    if(!FC_generate_secret(generated)) {
      cerr << "ERROR: Cannot generate a password" << "\n" << flush;
      return 0;
    }
    // Written before the file is changed, so it cannot be lost
    gxString werr;
    int wrv = !rekey_new_password_file.is_null() ?
      FC_write_secret_file(rekey_new_password_file.c_str(), generated, werr) :
      FC_write_secret_fd(rekey_new_password_fd.c_str(), generated, werr);
    if(wrv != 0) {
      cerr << "ERROR: " << werr.c_str() << ", the file was not changed" << "\n" << flush;
      generated.Clear(1);
      return 0;
    }
    new_secret.Cat(generated.GetSPtr(), generated.length());
  }

  if(!nf.BeginRekey()) {
    cerr << "ERROR: " << nf.err.c_str() << "\n" << flush;
    return 0;
  }
  unsigned char new_key[FC_KEY_LEN];
  memmove(new_key, nf.NewFileKey(), sizeof(new_key));
  int ok = 1;
  for(gxListNode<FCRekeySlot> *p = keep.GetHead(); ok && p; p = p->next) {
    unsigned char wrapped[FC_MAX_WRAPPED_LEN];
    unsigned wrapped_len = 0;
    ok = WrapForRekey(p->data, new_key, wrapped, &wrapped_len, err);
    if(ok) ok = nf.AddRekeySlot(p->data.type, p->data.username.c_str(), wrapped, wrapped_len);
    if(!ok && err.is_null()) err = nf.err;
  }
  gxString old_id = nf.FileIDHex();
  gxString backup;
  if(ok) {
    if(dry_run && pw_action == FC_REKEY_PW_GENERATE && !rekey_new_password_file.is_null()) {
      futils_remove(rekey_new_password_file.c_str());
    }
    ok = nf.FinishRekey(pw_action == FC_REKEY_PW_NONE ? 0 : &new_secret, 1, backup, dry_run);
    if(!ok) err = nf.err;
  }
  new_secret.Clear(1);
  if(!ok) {
    OPENSSL_cleanse(new_key, sizeof(new_key));
    LogEvent(fname, old_id, "rekey", AuthSlotName(), 0, "not changed", old_log_key);
    cerr << "ERROR: Rekey of " << fname << " failed: " << err.c_str() << "\n" << flush;
    if(pw_action == FC_REKEY_PW_GENERATE) {
      if(!rekey_new_password_file.is_null()) futils_remove(rekey_new_password_file.c_str());
      cerr << "The generated password was not used" << "\n" << flush;
    }
    generated.Clear(1);
    return 0;
  }
  generated.Clear(1);
  if(dry_run) {
    NOTE << "Dry run: the rekey of " << fname << " would work (the new file was written and checked, then removed), "
	 << "the file was not changed" << "\n" << flush;
    OPENSSL_cleanse(new_key, sizeof(new_key));
    return 1;
  }
  NOTE << "Rekeyed " << fname << ": new file key, every record encrypted again" << "\n" << flush;
  for(gxListNode<FCRekeySlot> *p = keep.GetHead(); p; p = p->next) {
    cerr << "  kept " << (p->data.type == FC_SLOT_RSA ? "RSA key" : "smart card") << " user " << p->data.username.c_str() << "\n" << flush;
  }
  if(pw_action == FC_REKEY_PW_KEEP) cerr << "  kept the password slot with the same password" << "\n" << flush;
  if(pw_action == FC_REKEY_PW_NEW) cerr << "  the password slot has the new password" << "\n" << flush;
  if(pw_action == FC_REKEY_PW_GENERATE) {
    cerr << "  the password slot has a generated password, written to "
	 << (rekey_new_password_file.is_null() ? "the file descriptor" : rekey_new_password_file.c_str()) << "\n" << flush;
  }
  if(pw_action == FC_REKEY_PW_NONE && has_password_slot) cerr << "  the password slot was removed" << "\n" << flush;
  cerr << "The original file was saved to " << backup.c_str() << ", delete it when you no longer need it, it opens with the old credentials" << "\n" << flush;

  // Access log: close the old chain and carry it to the new key
  if(access_log) {
    FCryptFile after;
    unsigned char new_log_key[FC_LOG_KEY_LEN];
    if(after.LoadHeader(fname) &&
       FC_log_key(new_key, FC_KEY_LEN, after.FileID(), FC_FILE_ID_LEN, new_log_key)) {
      gxString detail;
      detail << "new-id=" << after.FileIDHex();
      LogEvent(fname, old_id, "rekey", AuthSlotName(), 1, detail.c_str(), old_log_key);
      gxString lbackup, lerr;
      int lrv = FC_log_rekey(access_log_file.c_str(), old_id.c_str(), old_log_key,
			     after.FileIDHex().c_str(), new_log_key, lbackup, lerr);
      if(lrv == 1) cerr << "WARNING: " << lerr.c_str() << ". The log was kept as " << lbackup.c_str() << " and a new log started" << "\n" << flush;
      else if(lrv < 0 && !access_log_warned) {
	access_log_warned = 1;
	cerr << "WARNING: " << lerr.c_str() << "\n" << flush;
      }
      LogEvent(fname, after.FileIDHex(), "access-log-rekey", AuthSlotName(), 1, 0, new_log_key);
      OPENSSL_cleanse(new_log_key, sizeof(new_log_key));
    }
  }
  OPENSSL_cleanse(new_key, sizeof(new_key));
  return 1;
}

int KeyManagement()
// Returns the exit code
{
  if(remove_user && rekey) {
    cerr << "ERROR: Use --remove-user and --rekey in separate runs" << "\n" << flush;
    return 1;
  }
  // The credential
  if(use_private_rsa_key) {
    if(rsa_key_username.is_null()) {
      cerr << "ERROR: --rsa-key requires --rsa-key-username" << "\n" << flush;
      return 1;
    }
    if(private_key_has_passphrase && rsa_key_passphrase.is_null()) {
      if(non_interactive) {
	cerr << "ERROR: The RSA key has a passphrase, give it with --rsa-key-passphrase-fd or --rsa-key-passphrase-file" << "\n" << flush;
	return FC_EXIT_USAGE;
      }
      cerr << "RSA key passphrase: " << flush;
      if(!consoleGetString(rsa_key_passphrase, 1)) {
	rsa_key_passphrase.Clear(1);
	cerr << "\n" << "Invalid entry!" << "\n" << flush;
	return 1;
      }
      cerr << "\n" << flush;
    }
  }
#ifdef __ENABLE_SMART_CARD__
  else if(use_smartcard_auth) {
    if(smartcard_cert_username.is_null()) {
      cerr << "ERROR: --smartcard-cert requires --smartcard-username" << "\n" << flush;
      return 1;
    }
    if(!futils_exists(sc.modulePath) || !futils_isfile(sc.modulePath)) {
      cerr << "ERROR: Smart card provider " << sc.modulePath << " does not exist or cannot be read" <<  "\n" << flush;
      return 1;
    }
    if(sc.pin_too_long) {
      cerr << "ERROR: The smart card PIN is longer than " << (SC_max_pin_size-1) << " characters, the PIN was not sent" << "\n" << flush;
      return 1;
    }
    if(sc.pin[0] == 0) {
      gxString pin_buf;
      if(non_interactive) {
	cerr << "ERROR: Give the smart card PIN with --smartcard-pin-fd or --smartcard-pin-file, the PIN was not sent" << "\n" << flush;
	return FC_EXIT_USAGE;
      }
      cerr << "Smart card PIN: " << flush;
      if(!consoleGetString(pin_buf, 1) || pin_buf.is_null() || pin_buf.length() >= SC_max_pin_size) {
	pin_buf.Clear(1);
	cerr << "\n" << "ERROR: The smart card PIN is empty or too long, the PIN was not sent" << "\n" << flush;
	return 1;
      }
      cerr << "\n" << flush;
      sc.SetPin((char *)pin_buf.c_str());
      pin_buf.Clear(1);
    }
    if(debug_mode) sc.verbose_mode = 1;
  }
#endif
  else if(use_key_file) {
    aes_file_encrypt_secret.Clear(1);
    aes_file_encrypt_secret.Cat(key.m_buf(), key.length());
  }
  else {
    if(password.is_null()) {
      if(non_interactive) {
	cerr << "ERROR: Give the password with --password-fd or --password-file, or use --key" << "\n" << flush;
	return FC_EXIT_USAGE;
      }
      cerr << "Password: " << flush;
      if(!consoleGetString(password, 1)) {
	password.Clear(1);
	cerr << "\n" << "Invalid entry!" << "\n" << flush;
	return 1;
      }
      cerr << "\n" << flush;
    }
    aes_file_encrypt_secret.Clear(1);
    aes_file_encrypt_secret.Cat(password.GetSPtr(), password.length());
  }

  FCRekeyInput in;
  if(rekey && !ReadRekeyInput(in)) return 1;

  int errors = 0;
  gxListNode<gxString> *ptr = file_list.GetHead();
  while(ptr) {
    const char *fname = ptr->data.c_str();
    ptr = ptr->next;
    int fmt;
    if(!CheckLegacyFile(fname, fmt)) {
      SetExit(fmt == FC_FORMAT_OPEN_ERROR ? FC_EXIT_NOT_FOUND : FC_EXIT_USAGE);
      errors++;
      continue;
    }
    if(fmt != FC_FORMAT_2026102) {
      FCVersionInfo vi;
      gxString verr;
      if(FC_check_version(fname, vi, verr) == 0 && vi.is_v1) cerr << FC_v1_warning(fname, vi).c_str() << "\n" << flush;
      cerr << "ERROR: " << fname << " uses the old file format. --remove-user and --rekey need the "
	   << FC_FILE_VERSION << " format, convert it first with fmigrate" << "\n" << flush;
      errors++;
      continue;
    }
    FCLock lock; // Two writers of one file wait for each other
    {
      gxString lerr;
      int lrv = FC_lock_file(fname, lock_timeout, lock, lerr);
      if(lrv != 0) {
	cerr << "ERROR: " << lerr.c_str() << "\n" << flush;
	SetExit(lrv == 1 ? FC_EXIT_LOCKED : FC_EXIT_IO);
	errors++;
	continue;
      }
    }
    FCryptFile nf;
    gxString err;
    if(!UnlockForKeyManagement(nf, fname, err)) {
      SetExit(err.Find("Error opening") != -1 ? FC_EXIT_IO : FC_EXIT_AUTH);
      LogEvent(fname, nf.FileIDHex(), "open", AuthSlotName(), 0, "credential did not open the file", 0);
      cerr << "ERROR: " << fname << ": " << err.c_str() << "\n" << flush;
      errors++;
#ifdef __ENABLE_SMART_CARD__
      if(use_smartcard_auth) { // Never send the PIN again in this run
	OPENSSL_cleanse(sc.pin, sizeof(sc.pin));
	break;
      }
#endif
      continue;
    }
    unsigned char log_key[FC_LOG_KEY_LEN];
    FC_log_key(nf.FileKey(), FC_KEY_LEN, nf.FileID(), FC_FILE_ID_LEN, log_key);
    gxString id = nf.FileIDHex();
    LogEvent(fname, id, "open", AuthSlotName(), 1, 0, log_key);

    if(remove_user) {
      unsigned type = remove_user_type;
      if(!type) {
	FCKeySlot *r = nf.FindSlot(FC_SLOT_RSA, remove_username.c_str());
	FCKeySlot *c = nf.FindSlot(FC_SLOT_SMARTCARD, remove_username.c_str());
	if(r && c) {
	  cerr << "ERROR: User " << remove_username.c_str() << " has RSA key and smart card access to " << fname
	       << ", give --remove-user-type=rsa or --remove-user-type=smartcard" << "\n" << flush;
	  errors++;
	  OPENSSL_cleanse(log_key, sizeof(log_key));
	  continue;
	}
	type = c ? FC_SLOT_SMARTCARD : FC_SLOT_RSA;
      }
      gxString backup;
      if(!nf.RemoveSlot(type, remove_username.c_str(), 1, backup, dry_run)) {
	cerr << "ERROR: " << nf.err.c_str() << "\n" << flush;
	SetExit(nf.err.Find("has no") != -1 ? FC_EXIT_NOT_FOUND : FC_EXIT_USAGE);
	LogEvent(fname, id, "remove-user", remove_username, 0, "not changed", log_key);
	errors++;
      }
      else if(dry_run) {
	NOTE << "Dry run: removing " << FC_slot_type_name(type) << " access for user " << remove_username.c_str()
	     << " would work, " << fname << " was not changed" << "\n" << flush;
      }
      else {
	NOTE << "Removed " << FC_slot_type_name(type) << " access for user " << remove_username.c_str() << " from " << fname << "\n" << flush;
	cerr << "The original file was saved to " << backup.c_str() << ", delete it when you no longer need it" << "\n" << flush;
	cerr << "NOTE: Removing a user does not revoke a file key the user may already have recovered, "
	     << "or copies of the file made before. Run fcrypt --rekey on the file to give it a new key." << "\n" << flush;
	LogEvent(fname, id, "remove-user", remove_username, 1, 0, log_key);
	if(clientcfg->verbose_mode) ListNewFormatUsers(nf);
      }
    }
    if(rekey && !RekeyFile(nf, fname, in, log_key)) {
      SetExit(FC_EXIT_USAGE);
      errors++;
    }
    OPENSSL_cleanse(log_key, sizeof(log_key));
  }
  in.Wipe();
  return exit_code ? exit_code : (errors ? 1 : 0);
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

  // 10/27/2026: Only --add-rsa-key with no file name reads the key from
  // stdin, so stdin stays free for --password-fd=0 and --rekey input
  int stdin_key = 0;
  for(int i = 1; i < argc; i++) {
    if(strcmp(argv[i], "--add-rsa-key") == 0) stdin_key = 1;
  }
  int selectRetVal = stdin_key ? select(1, &readfds, &writefds, &exceptfds, &timeout) : 0;
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
	  int arg_ok = ProcessArgs(arg);
	  FC_wipe_secret_arg(argv[narg]); // 10/27/2026: Remove secrets from the process arguments
	  if(!arg_ok) return ExitProgram(1); // Exit if argument is not valid
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

  // 10/25/2026: Set up FIPS mode or the default provider
  gxString fips_err;
  if(!FC_crypto_init(fips_request, fips_err)) {
    cerr << "ERROR: " << fips_err.c_str() << "\n" << flush;
    return ExitProgram(1);
  }
  if(clientcfg->verbose_mode) cerr << FC_crypto_status().c_str() << "\n" << flush;
  
  if(futils_chdir(top_pwd) != 0) {
    cerr << "Encountered fatal fcrypt error" << "\n";
    cerr << "Error resetting top present working DIR" << "\n";
    return ExitProgram(1);
  }
  if(access_log && access_log_file.is_null()) access_log_file = FC_default_log_file(".fcrypt");
  if(remove_user || rekey) return ExitProgram(KeyManagement()); // 10/27/2026

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
      if(SC_uses_engine()) {
        cerr << "Smart card engine ID = " << sc.engine_ID << "\n" << flush;
        cerr << "Smart card engine path = " << sc.enginePath << "\n" << flush;
      }
      cerr << "Smart card module path = " << sc.modulePath << "\n" << flush;
      cerr << "Smart card cert ID = " << sc.cert_id << "\n"  << flush;
    }
    
    if(!use_smartcard_cert_file) {
      if(SC_uses_engine() && (!futils_exists(sc.enginePath) || !futils_isfile(sc.enginePath))) {
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
      int fmt;
      if(!CheckLegacyFile(ptr->data.c_str(), fmt)) return ExitProgram(1);
      if(fmt == FC_FORMAT_2026102) {
	FCryptFile nf;
	if(!OpenNewFormatFile(nf, ptr->data.c_str(), aes_file_encrypt_secret)) return ExitProgram(1);
	unsigned char wrapped[FC_MAX_WRAPPED_LEN];
	unsigned wrapped_len = 0;
	int sc_rv;
	if(use_smartcard_cert_file) {
	  sc_rv = SC_cert_file_public_key_encrypt(&sc, nf.FileKey(), FC_KEY_LEN, wrapped, sizeof(wrapped),
						  &wrapped_len, RSA_PKCS1_OAEP_PADDING);
	}
	else {
	  sc_rv = SC_public_key_encrypt(&sc, nf.FileKey(), FC_KEY_LEN, wrapped, sizeof(wrapped),
					&wrapped_len, RSA_PKCS1_OAEP_PADDING);
	}
	if(sc_rv != 0) {
	  cerr << "ERROR: " << sc.err_string << "\n" << flush;
	  return ExitProgram(1);
	}
	if(!nf.AddWrappedKey(FC_SLOT_SMARTCARD, smartcard_cert_username.c_str(), wrapped, wrapped_len)) {
	  cerr << "ERROR: " << nf.err.c_str() << "\n" << flush;
	  return ExitProgram(1);
	}
	cerr << "Smart card cert for user " << smartcard_cert_username.c_str() << " added to " << ptr->data.c_str() << "\n" << flush;
	if(clientcfg->verbose_mode) ListNewFormatUsers(nf);
	ptr = ptr->next;
	continue;
      }
      FCryptCache fc(num_buckets);
      fc.key_iterations = legacy_key_iterations;
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
      int fmt;
      if(!CheckLegacyFile(ptr->data.c_str(), fmt)) return ExitProgram(1);
      if(fmt == FC_FORMAT_2026102) {
	FCryptFile nf;
	if(!OpenNewFormatFile(nf, ptr->data.c_str(), aes_file_encrypt_secret)) return ExitProgram(1);
	char *passphrase = 0;
	if(!rsa_key_passphrase.is_null()) passphrase = (char *)rsa_key_passphrase.GetSPtr();
	if(!nf.AddRSAKey(rsa_key_username.c_str(), public_key, public_key_len, passphrase)) {
	  cerr << "ERROR: " << nf.err.c_str() << "\n" << flush;
	  return ExitProgram(1);
	}
	cerr << "Public RSA key " << rsa_key_username.c_str() << " added to " << ptr->data.c_str() << "\n" << flush;
	if(clientcfg->verbose_mode) ListNewFormatUsers(nf);
	ptr = ptr->next;
	continue;
      }
      FCryptCache fc(num_buckets);
      fc.key_iterations = legacy_key_iterations;
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
    // 10/25/2026: New files always use the 2026102 file format
    FCryptFile fc;
    fc.iterations = key_iterations;
    fc.slot_area_len = static_data_size;
    fc.overwrite = overwrite;
    fc.en_dot_ext = en_dot_ext;
    if(!output_dir_name.is_null()) fc.output_dir_name = output_dir_name;
    if(!output_file_name.is_null()) fc.output_file_name = output_file_name;
    if(!decrypted_output_filename.is_null()) fc.stored_name_override = decrypted_output_filename;
    
    gxString sbuf;

    if(clientcfg->verbose_mode) {
      cerr << "Encrypting:      " << ptr->data.c_str() << "\n" << flush;
      cerr << "File format:     " << FC_FILE_VERSION << "\n" << flush;
      cerr << "Encryption mode: " << "AES-256-CBC with HMAC-SHA256, PBKDF2-HMAC-SHA256" << "\n" << flush;
      cerr << "Key iterations:  " << key_iterations << "\n" << flush;
    }
    else {
      cerr << "Encrypting: " << ptr->data.c_str() << "\n" << flush;
    }

    rv = fc.EncryptFile(ptr->data.c_str(), aes_file_encrypt_secret);
    if(!rv) {
      cerr << "File encryption failed" << "\n" << flush;
      cerr << fc.err.c_str() << "\n" << flush;
      err = 1;
      ptr = ptr->next;
      continue;
    } 

    cerr << "File encrypt successful" << "\n" << flush;
    sbuf << clear << wn << fc.bytes_wrote;
    cerr << "Wrote " << sbuf.c_str() << " bytes to "
	 << fc.ofname.c_str() << "\n" << flush;

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
