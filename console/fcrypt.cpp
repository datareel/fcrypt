// ------------------------------- //
// -------- start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- // 
// C++ Source Code File
// Compiler Used: MSVC, BCC32, GCC, HPUX aCC, SOLARIS CC
// Produced By: DataReel Software Development Team
// File Creation Date: 07/21/2003
// Date Last Modified: 11/22/2023
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

// Constants

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
int use_public_rsa_key = 0;
unsigned char rsa_ciphertext[8192];
unsigned rsa_chipertext_len;

// ----------------------------------------------------------- // 
// Interactive user function prototypes
// ----------------------------------------------------------- // 
int CryptFile();
int ChangeDir(gxString &path, int prompt);
int LPWD();
int ListSystemDir(gxString &path, char sort_by = 'n');
int SetCacheBuckets(int intbuf = -1);
int SetDotExtension(gxString &ext);
int SetOutputDir(gxString &dir);
int SetEncLevel(int intbuf = -1);
void ShowOptions();
int SetKey();
int SetKeyIterations(int intbuf = 1000);
// ----------------------------------------------------------- // 

void PausePrg()
// Function used to pause the program.
{
  cout << "\n" << flush;
  cout << "Press any key to continue..." << "\n" << flush;
  int c;
  consoleGetChar(c);
}

void ClearInputStream(istream &s)
// Used to clear istream
{
  char c;
  s.clear();
  while(s.get(c) && c != '\n') { ; }
}

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
       << "filename" << "\n" << flush;
  cout << "Switches: -? = Display this help message and exit." << "\n" << flush;  
  cout << "          -0 = No encryption for testing only." << "\n" << flush;
  cout << "          -3 = 256-bit encryption (default)." << "\n" << flush;
  cout << "          -b[size] = Specify file buffer size in bytes" << "\n" << flush;
  cout << "          -c[num] = Specify number of cache buckets" << "\n" << flush;
  cout << "          -d[name] = Specify output DIR for enc file(s)" << "\n" << flush;
  cout << "          -D[name] = Specify and make output DIR" << "\n" << flush;
  cout << "          -f[name] = Specify output file and DIR name" << "\n" << flush;
  cout << "          -g = Generate hashed output file names" << "\n" << flush;
  cout << "          -k = Supply a key used to encrypt" << "\n" << flush;
  cout << "          -o = Overwrite existing enc file(s)" << "\n" << flush;
  cout << "          -p = Supply a password used to encrypt" << "\n" << flush;
  cout << "          -r = Remove unencrypted source file(s)" << "\n" << flush;
  cout << "          -R = Encrypt DIR including all files and subdirectories" << "\n" << flush;
  cout << "          -v = Enable verbose messages to the console" << "\n" << flush;
  cout << "          -x[ext] = Specify enc file(s) dot extension" << "\n" << flush;
  cout << "\n" << flush;
  cout << "          --iter=num (Set the number of derived key iterations)" << "\n" << flush;
  cout << "          --master-rsa-key=pubkey.pem (Use a single RSA key for encryption)" << "\n" << flush;
  cout << "\n"; // End of list
}

int ProcessDashDashArg(gxString &arg)
{
  gxString sbuf, equal_arg;
  int has_valid_args = 0;
  
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

  if(arg == "master-rsa-key") {
    if(equal_arg.is_null()) {
      cout << "ERROR: --master-rsa-key missing filename: --master-rsa-key=/$HOME/keys/rsa_pubkey.pem" << "\n" << flush;
      return 0;
    }
    public_rsa_key_file = equal_arg;
    if(!futils_exists(public_rsa_key_file.c_str())) {
	cout << "\n" << flush;
	cout << "ERROR: Public RSA key file " << public_rsa_key_file.c_str() << " does not exist" <<  "\n" << flush;
	cout << "\n" << flush;
	return 0;
    }
    use_public_rsa_key = 1;
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

void PrgMenu()
{
  const int num_menu = 24;
  const char *menu[num_menu] = {
    "cache    Set cache buckets",
    "cd       Change DIR",
    "clear    Clear screen",
    "crypt    Encrypt file",
    "date     Display date/time",
    "ext      Set dot extension",
    "hash     Hashed outfile names",
    "help     Print help menu",
    "iter     Set new key iterations",
    "key      Use key file to encrypt",
    "level    Set encryption level",
    "ls       list files by name",
    "ls -d    list files by date",
    "ls -s    list files by size",
    "over     Overwrite file(s)",
    "pwd      Present working DIR",
    "quit     Quit program",
    "remove   Remove source file(s)",
    "recurse  Follow DIRs",
    "setdir   Set output DIR",
    "shell    Shell to command prompt",
    "show     Show current settings",
    "ver      Program version info",
    "verb     Toggle verbose mode"
  };

  int i, j;
  const int slen = 32;

  cout << "\n" << flush;
  cout << "------------------ File Crypt User Commands ------------------" 
       << "\n" << flush;
  
  // Display split menu
  for(i = 0; i < num_menu; i++) {
    cout << menu[i];
    j = strlen(menu[i]);
    while(j++ < slen) cout << " ";
    if(i < (num_menu-1)) cout << " | ";
    i++;
    if(i == num_menu) break;
    cout << menu[i];
    cout << "\n" << flush;
  }
  cout << "\n" << flush;
}

int InteraciveMode()
{
  cout << "Entering Interactive Mode" << "\n" << flush;

  int rv = 1;
  int intbuf = -1;
  gxString cmd_prompt, input, command, fdnames;

  cmd_prompt << clear << "[fcrypt (? help)]> ";


  while(rv) {
    cout << "\n";
    cout << cmd_prompt.c_str() << flush;
    input.Clear();
    consoleGetString(input);
    input.TrimLeadingSpaces();
    input.TrimTrailingSpaces();
    input.ToLower();
    command = input;

    // Intercept dash commands
    if(command == "ls -d") {
      command = "ls-d";
      input.FilterString("ls -d");
    }
    if(command == "ls -s") {
      command = "ls-s";
      input.FilterString("ls -s");
    }
    if(command == "crypt -s") {
      command = "crypt-s";
      //input.FilterString("crypt -r");
      input.FilterString("crypt-s");
    }

    // Remove any command arguments
    command.DeleteAfterIncluding(" ");

    // Update the command history
    clientcfg->history[clientcfg->curr_command] = input;
    clientcfg->history[clientcfg->curr_command].FilterChar('\r');
    clientcfg->history[clientcfg->curr_command].FilterChar('\n');
    clientcfg->curr_command++;
    if(clientcfg->curr_command > (OP_HISTORY_LEN-1)) {
      clientcfg->curr_command = 0;
    }

    // Execute the user command
    if((command == "?") || (command == "help")) {
      PrgMenu();
      continue;
    }
    if((command == "quit") || (command == "exit") || (command == "bye")) {
      break; // Exit the program
    }
    if(command == "cache") {
      intbuf = -1;
      if(input.Find(" ") != -1) {
	input.TrimTrailingSpaces();
	input.DeleteBeforeIncluding(" ");
	intbuf = input.Atoi();
      }
      SetCacheBuckets(intbuf);
      continue;
    }
    if(command == "cd") {
      fdnames.Clear();
      if(input.Find(" ") != -1) {
	input.TrimTrailingSpaces();
	input.DeleteBeforeIncluding(" ");
	fdnames = input;
	ChangeDir(fdnames, 0);
      }
      else {
	ChangeDir(fdnames, 1);
      }
      continue;
    }
    if(command == "clear") {
      consoleClear(); 
      continue;
    }
    if(command == "crypt") {
      CryptFile();
      continue;
    }
    if(command == "date") {
      consoleDateTime();
      continue;
    }
    if(command == "ext") {
      fdnames.Clear();
      if(input.Find(" ") != -1) {
	input.TrimTrailingSpaces();
	input.DeleteBeforeIncluding(" ");
	fdnames = input;
      }
      SetDotExtension(fdnames);
      continue;
    }
    if(command == "hash") {
      if(gen_file_names == 1) {
	cout << "\n" << flush;
	cout << "Generate hashed output file names option off" 
	     << "\n" << flush;
	gen_file_names = 0;
      }
      else {
	cout << "\n" << flush;
	cout << "Generate hashed output file names option on" 
	     << "\n" << flush;
	gen_file_names = 1;
      }
      continue;
    }
    if(command == "key") {
      SetKey();
      continue;
    }
    if(command == "level") {
      intbuf = -1;
      if(input.Find(" ") != -1) {
	input.TrimTrailingSpaces();
	input.DeleteBeforeIncluding(" ");
	intbuf = input.Atoi();
      }
      SetEncLevel(intbuf);
      continue;
    }
    if(command == "iter") {
      intbuf = -1;
      if(input.Find(" ") != -1) {
	input.TrimTrailingSpaces();
	input.DeleteBeforeIncluding(" ");
	intbuf = input.Atoi();
      }
      SetKeyIterations(intbuf);
      continue;
    }

    if((command == "ls") || (command == "dir")) {
      fdnames.Clear();
      if(input.Find(" ") != -1) {
	input.TrimTrailingSpaces();
	input.DeleteBeforeIncluding(" ");
	fdnames = input;
      }
      ListSystemDir(fdnames, 'n');
      continue;
    }
    if(command == "ls-s") {
      fdnames.Clear();
      if(input.Find(" ") != -1) {
	input.TrimTrailingSpaces();
	input.DeleteBeforeIncluding(" ");
	fdnames = input;
      }
      ListSystemDir(fdnames, 's');
      continue;
    }
    if(command == "ls-d") {
      fdnames.Clear();
      if(input.Find(" ") != -1) {
	input.TrimTrailingSpaces();
	input.DeleteBeforeIncluding(" ");
	fdnames = input;
      }
      ListSystemDir(fdnames, 'd');
      continue;
    }
    if(command == "over") {
      if(overwrite == 1) {
	cout << "\n" << flush;
	cout << "Overwrite existing enc file(s) option off" << "\n" << flush;
	overwrite = 0;
      }
      else {
	cout << "\n" << flush;
	cout << "Overwrite existing enc file(s) option on" << "\n" << flush;
	overwrite = 1;
      }
      continue;
    }
    if(command == "pwd") {
      LPWD();
      continue;
    }
    if(command == "recurse") {
      if(recurse == 1) {
	cout << "\n" << flush;
	cout << "Recurse directory option off" << "\n" << flush;
	recurse = 0;
      }
      else {
	cout << "\n" << flush;
	cout << "Recurse directory option on" << "\n" << flush;
	recurse = 1;
      }
      continue;
    }
    if(command == "remove") {
      if(remove_src_file == 1) {
	cout << "\n" << flush;
	cout << "Remove source file option off" << "\n" << flush;
	remove_src_file = 0;
      }
      else {
	cout << "\n" << flush;
	cout << "Remove source file option on" << "\n" << flush;
	remove_src_file = 1;
      }
      continue;
    }
    if(command == "setdir") {
      fdnames.Clear();
      if(input.Find(" ") != -1) {
	input.TrimTrailingSpaces();
	input.DeleteBeforeIncluding(" ");
	fdnames = input;
      }
      SetOutputDir(fdnames);
      continue;
    }
    if((command == "shell") || (command == "!")) {
      consoleShell(); 
      continue;
    }
    if(command == "show") {
      ShowOptions();
      continue;
    }
    if(command == "ver") {
      DisplayVersion();
      continue;
    }
    if(command == "verb") {
      if(clientcfg->verbose_mode == 1) {
	cout << "\n" << flush;
	cout << "Verbose mode off" << "\n" << flush;
	clientcfg->verbose_mode = 0;
      }
      else {
	cout << "\n" << flush;
	cout << "Verbose mode on" << "\n" << flush;
	clientcfg->verbose_mode = 1;
      }
      continue;
    }

    // Default message if command unknown to interrupter or
    // no command is entered
    cout << "\n" << flush;
    if(!command.is_null()) {
      cout << "Unrecognized command: " << command.c_str() << "\n" << flush;
      cout << "\n" << flush;
      continue;
    }
    if(!input.is_null()) {
      cout << "Unrecognized input string: " << input.c_str() << "\n" << flush;
      cout << "\n" << flush;
      continue;
    }
  }

  cout << "\n" << flush;
  cout << "Exiting fcrypt program" << "\n" << flush;
  return 0;
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
  clientcfg->version_str = "2023.102";

  if(argc < 2) {
    HelpMessage();

    cout << "\n" << flush;
    cout << "Press i key for interactive mode or any other key to exit..." 
	 << "\n" << flush;
    int c;
    consoleGetChar(c);
    if(((char)c == 'i') || ((char)c == 'I')) {
      return InteraciveMode();
    } 
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
    cout << "Using key file for encryption" << "\n" << flush;
  }

  if(use_public_rsa_key) {
    cout << "Using master RSA key file for encryption" << "\n" << flush;
    RSA_openssl_init();
    char public_key[RSA_max_keybuf_len];
    unsigned public_key_len = 0;
    rv = RSA_read_key_file(public_rsa_key_file.c_str(), public_key, sizeof(public_key), &public_key_len);
    if(rv != RSA_NO_ERROR) {
      std::cerr << "ERROR: " << RSA_err_string(rv) << "\n" << std::flush;
      return 1;
    }
    if(CommandLinePassword.secret.is_null()) { // No AES file encryption key or password was provided by the caller 
      // Generate a file encryption key that will be used for the AES encryption
      unsigned char file_encryption_key[128];
      AES_fillrand(file_encryption_key, sizeof(file_encryption_key));
      key.Cat(file_encryption_key, sizeof(file_encryption_key));
      CommandLinePassword.secret = key;
    }
    
    memset(rsa_ciphertext, 0, sizeof(rsa_ciphertext));

    rv = RSA_public_key_encrypt((const unsigned char *)public_key, public_key_len,
				CommandLinePassword.secret.m_buf(), CommandLinePassword.secret.length(),
				rsa_ciphertext, sizeof(rsa_ciphertext), &rsa_chipertext_len);
    if(rv != RSA_NO_ERROR) {
      std::cerr << "ERROR: " << RSA_err_string(rv) << "\n" << std::flush;
      return 1;
    }
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
  
  gxListNode<gxString> *ptr = file_list.GetHead();
  tmp_cp = cp;
  rv = err = 0;
  unsigned offset = 0;
  
  while(ptr) {
    FCryptCache fc(num_buckets);
    if(use_public_rsa_key) {
      StaticDataBlockHdr static_data_block_header;
      static_data_block_header.block_len = rsa_chipertext_len;
      static_data_block_header.block_type = 1;
      offset = 0;
      memmove(fc.static_data, &static_data_block_header, sizeof(static_data_block_header));
      offset+=sizeof(static_data_block_header);
      memmove(fc.static_data+offset, rsa_ciphertext, rsa_chipertext_len);
    }
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
// Interactive user functions
// ----------------------------------------------------------- // 
int CryptFile()
{
  CryptSecretHdr cp;
  CryptSecretHdr tmp_cp;

  gxString fname;
  cout << "\n" << flush;
  cout << "File name: " << flush;
  if(!consoleGetString(fname)) {
    cout << "Invalid entry!" << "\n" << flush;
    return  0;
  }
  cout << "\n" << flush;
  if(fname.is_null()) {
    cout << "No file name was entered" << "\n" << flush;
    return  0;
  }

  gxString password, password2;
  
  if(CommandLinePassword.secret.is_null()) {
    cout << "Password: " << flush;
    if(!consoleGetString(password, 1)) {
      password.Clear(1);
      cout << "Invalid entry!" << "\n" << flush;
      return  0;
    }
    cout << "\n" << flush;

    cout << "Retype password: " << flush;
    if(!consoleGetString(password2, 1)) {
      password.Clear(1);
      password2.Clear(1);
      cout << "Invalid entry!" << "\n" << flush;
      return  0;
    }
    cout << "\n" << flush;
    if(password != password2) {
      password.Clear(1);
      password2.Clear(1);
      cout << "Passwords do not match" << "\n" << flush;
    return  0;
    }
    cp.secret.Load(password.c_str(), password.length());
    password.Clear(1);
    password2.Clear(1);
  }
  else {
    cp.secret = CommandLinePassword.secret;
    CommandLinePassword.Reset();
  }
  
  if((int)cp.secret.length() < AES_MIN_SECRET_LEN) {
    cout << "Password does not meet length requirement" 
	 << "\n" << flush;
    cout << "Password must be at least " << AES_MIN_SECRET_LEN 
	 << " characters long" << "\n" << flush;
      return  0;
  }
    
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
    cout << "Encrypting:      " << fname.c_str() << "\n" << flush;
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
    cout << "Encrypting: " << fname.c_str() << "\n" << flush;
  }
  if(mode == 0) cout << "\n" << "WARNING: Using mode 0 for test only - WARNING: Output file will not be encrypted" << "\n\n" << flush;

  int rv = fc.EncryptFile(fname.c_str(), cp.secret);
  if(!rv) {
    cout << "File encryption failed" << "\n" << flush;
    cout << fc.err.c_str() << "\n" << flush;
    return  0;
  } 

  cout << "File encrypt successful" << "\n" << flush;
  sbuf << clear << wn << fc.BytesWrote();
  cout << "Wrote " << sbuf.c_str() << " bytes to "
       << fc.OutFileName() << "\n" << flush;

  if(remove_src_file) {
    if(futils_remove(fname.c_str()) != 0) {
      cout << "Error removing " << fname.c_str() << " source file"
	   << "\n" << flush;
    }
  }
  
  return 1;
}

int ChangeDir(gxString &path, int prompt)
{
  if(prompt) {
   cout << "\n" << flush;
   cout << "Enter the name of the directory> " << flush;
   consoleGetString(path);
  }
  
  if(path.is_null()) {
    cout << "\n" << flush;
    cout << "No file name was entered" << "\n" << flush;
    return 0;
  }
  else {
    if(!cryptdb_makeabspath(path)) {
      cout << "\n" << flush;
      cout << "Error changing directory to: " << path << "\n" << flush;
      return 0;
    }
  }

  if(futils_chdir(path.c_str()) != 0) {
    cout << "\n" << flush;
    cout << "Error changing directory to: " << path << "\n" << flush;
    return 0;
  }

  cout << "\n" << flush;
  cout << "Changed directory to: " << path.c_str() << "\n" << flush;
  return 1;
}

int SetKey()
{
  gxString fname, ebuf;
  cout << "\n" << flush;
  cout << "Key file name: " << flush;
  if(!consoleGetString(fname)) {
    cout << "Invalid entry!" << "\n" << flush;
    return  0;
  }
  cout << "\n" << flush;
  if(fname.is_null()) {
    cout << "No file name was entered" << "\n" << flush;
    return  0;
  }
  if(!futils_exists(fname.c_str())) {
    cout << "\n" << flush;
    cout << "ERROR: Key file " << fname.c_str() << " does not exist" <<  "\n" << flush;
    cout << "\n" << flush;
    return 0;
  }
  if(read_key_file(fname.c_str(), key, ebuf) != 0) {
    cout << "\n" << flush;
    cout << "ERROR: " << ebuf.c_str() << "\n" << flush;
    cout << "\n" << flush;
    return 0;
  }
  CommandLinePassword.secret = key;
  use_input_arg_key_file  = 1;

  return 1;
}

int LPWD()
{
  char pwd[futils_MAX_DIR_LENGTH];
  if(futils_getcwd(pwd, futils_MAX_DIR_LENGTH) == 0) {
    cout << "\n" << flush;
    cout << pwd << "\n" << flush;
  }
  else {
    cout << "\n" << flush;
    cout << "Error reading local directory" << "\n" << flush;
    return 0;
  }
  return 1;
}

int ListSystemDir(gxString &path, char sort_by)
{
  if(path.is_null()) {
    char pwd[futils_MAX_DIR_LENGTH];
    if(futils_getcwd(pwd, futils_MAX_DIR_LENGTH) != 0) {
      path = ".";
    }
    path = pwd;
  }
  cryptdb_makeabspath(path);

  gxString cmd, tfname, sbuf;
  if((sort_by == 'n') || (sort_by == 'N')) {
    // Sort by name
#if defined (__WIN32__)
    cmd << clear << "dir /on " << path;
#else
    cmd << clear << "ls -Aal " << path;
#endif
  }
  else if((sort_by == 'd') || (sort_by == 'D')) {
    // Sort by date last modified
#if defined (__WIN32__)
    cmd << clear << "dir /od " << path;
#else
    cmd << clear << "ls -Aaltcr " << path;
#endif
  }
  else if((sort_by == 's') || (sort_by == 'S')) {
#if defined (__WIN32__)
    cmd << clear << "dir /os " << path;
#else
    cmd << clear << "ls -AalSr " << path;
#endif
  }
  else {
    // Default to sort by name
#if defined (__WIN32__)
    cmd << clear << "dir /on " << path;
#else
    cmd << clear << "ls -Aal " << path;
#endif
  }

#if defined (__WIN32__)
  if(futils_mkdir("\\tmp") != 0) {
    tfname = "list_dir_tmp_000";
  }
  else {
    tfname << clear << "\\tmp\\" << "list_dir_tmp_000";
  }
#else
  if(!futils_exists("/tmp")) {
    tfname = "list_dir_tmp_000";
  }
  else {
    tfname << clear << "/tmp/" << "list_dir_tmp_000";
  }
#endif
    
  int i = 1;
  tfname << i;
  while(futils_exists(tfname.c_str())) {
    tfname.DeleteAt((tfname.length()-1), 1);
    tfname << ++i;
  }

  cmd << " > " << tfname;
  system(cmd.c_str());

  DiskFileB infile;
  if(infile.df_Open(tfname.c_str(), DiskFileB::df_READONLY) != 
     DiskFileB::df_NO_ERROR) {
    cout << "\n" << flush;
    cout << "System list DIR request failed" << "\n" << flush;
    cout << "Cannot create tmp file" << "\n" << flush;
    return 0;
  }

  gxString dir_list(255); char lbuf[255];
  if(infile.df_GetError() == DiskFileB::df_NO_ERROR) {
    while(!infile.df_EOF()) {
      memset(lbuf, 0, sizeof(lbuf));
      infile.df_GetLine(lbuf, sizeof(lbuf));
      if(infile.df_GetError() != DiskFileB::df_NO_ERROR) {
	dir_list = "Error accessing DIR list information";
	break;
      }
#if defined (__WIN32__)
      if(lbuf[0] == ' ') { // Skip the volume label info
	if(lbuf[1] != ' ') continue;
      }

      // Remove the disk info from the DIR listing
      int offset = FindMatch((const char *)lbuf, 
			     (const char *)" Dir(s)", 0, 0, 0);
      if(offset != -1) {
	offset += strlen(" Dir(s)");
	lbuf[offset] = 0;
      }
      dir_list << lbuf << "\n";
#else
      sbuf << clear << lbuf;
      sbuf.DeleteBeforeLastIncluding("/");
      int offset = FindMatch((const char *)lbuf, 
			     (const char *)"/", 0, 0, 0);
      if(offset != -1) {
	lbuf[offset] = 0;
	strcat(lbuf, sbuf.c_str());
      }
      dir_list << lbuf << "\n";
#endif
    }
  }
  else {
    dir_list = "Error accessing DIR list information";
  }
  infile.df_Close();

  if(dir_list.is_null()) {
    cout << "\n" << flush;
    cout << "File system error listing DIR"
	 << "\n" << flush;
      return 0;
  }

  cout << "\n" << flush;
  cout << dir_list.c_str() << "\n" << flush;
  return 1;
}

int SetCacheBuckets(int intbuf)
{
  if(intbuf == -1) {
    gxString intstr;
    cout << "\n" << flush;
    cout << "Enter number of cache buckets (1-65535)> " << flush;
    if(!consoleGetString(intstr)) {
      cout << "\n" << flush;
      cout << "Invalid entry!" << "\n" << flush;
      return  0;
    }
    intbuf = intstr.Atoi();
  }
  if((intbuf < 1) || (intbuf > 65535)) {
    cout << "\n" << flush;
    cout << "Bad number of cache buckets specified" << "\n" << flush;
    cout << "Valid range = 1 to 65535 bytes" << "\n" << flush;
    return 0;
  }
  num_buckets = intbuf;
  return 1;
}

int SetDotExtension(gxString &ext)
{
  if(ext.is_null()) {
    cout << "\n" << flush;
    cout << "Enter new dot extension for enc file(s)> " << flush;
    if(!consoleGetString(ext)) {
      cout << "\n" << flush;
      cout << "Invalid entry!" << "\n" << flush;
      return  0;
    }
  }

  en_dot_ext = ext;
  if(en_dot_ext[0] != '.') {
    en_dot_ext.InsertAt(0, ".", 1);
  }

  return 1;
}

int SetOutputDir(gxString &dir)
{
  if(dir.is_null()) {
    cout << "\n" << flush;
    cout << "Enter new output DIR for enc file(s)> " << flush;
    if(!consoleGetString(dir)) {
      cout << "\n" << flush;
      cout << "Invalid entry!" << "\n" << flush;
      return  0;
    }
  }

  if(!futils_exists(dir.c_str())) {
    if(futils_mkdir(dir.c_str()) != 0) {
      cout << "\n" << flush;
      cout << "Error making output directory" << "\n" << flush;
      return 0;
    }
  }
  if(!futils_isdirectory(dir.c_str())) {
    cout << "\n" << flush;
    cout << "Bad output DIR specified" << "\n" << flush;
    cout << dir.c_str() << " is a file name" << "\n" << flush;
    return 0;
  }

  output_dir_name = dir;
  return 1;
}

int SetEncLevel(int intbuf)
{
  if(intbuf == -1) {
    gxString intstr;
    cout << "\n" << flush;
    cout << "Enter new encryption level (128, 192, or 256)> " << flush;
    if(!consoleGetString(intstr)) {
      cout << "\n" << flush;
      cout << "Invalid entry!" << "\n" << flush;
      return  0;
    }
    intbuf = intstr.Atoi();
  }
  if(intbuf == 256) {
    mode = 3;
  }
  else {
    cout << "\n" << flush;
    cout << "Bad encryption level specified" << "\n" << flush;
    cout << "Valid levels are 256" << "\n" << flush;
    return 0;
  }

  return 1;
}

int SetKeyIterations(int intbuf)
{
  if(intbuf == -1) {
    gxString intstr;
    cout << "\n" << flush;
    cout << "Enter new key iterations value> " << flush;
    if(!consoleGetString(intstr)) {
      cout << "\n" << flush;
      cout << "Invalid entry!" << "\n" << flush;
      return  0;
    }
    intbuf = intstr.Atoi();
  }
  if(intbuf <= 0) {
    cout << "\n" << flush;
    cout << "Bad key iterations value specified" << "\n" << flush;
    return 0;
  }

  key_iterations = intbuf;
  return 1;
}

void ShowOptions()
{
  cout << "\n" << flush;
  cout << "\n" << flush;
  cout << "Cache buckets: " << num_buckets << "\n" << flush;
  if(mode == 3) {
    cout << "Encryption mode: 256-bit" << "\n" << flush;
  }
  if(gen_file_names) {
    cout << "Generate hashed output file names option on" 
	 << "\n" << flush;
  }
  if(!output_dir_name.is_null()) {
    cout << "Output DIR for enc file(s): " << output_dir_name.c_str()
	 << "\n" << flush;
  }
  if(overwrite) {
    cout << "Overwrite existing enc file(s) option on" << "\n" << flush;
  }
  else {

  }
  if(recurse) {
    cout << "Recurse directory option on" << "\n" << flush;
  }
  else {

  }
  if(remove_src_file) {
    cout << "Remove source file option on" << "\n" << flush;
  }
  else {

  }
  cout << "\n" << flush;
}
// ----------------------------------------------------------- // 
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
