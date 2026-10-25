// ------------------------------- //
// -------- start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- //
// C++ Source Code File
// Compiler Used: MSVC, GCC
// Produced By: DataReel Software Development Team
// File Creation Date: 10/25/2026
// Date Last Modified: 10/25/2026
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

File migration program. Converts files encrypted by releases before
2026.102 to the 2026102 file format.

The old file is decrypted in memory and encrypted again as it is read,
so the plaintext is never written to disk. The new file is written to a
private temp file, decrypted again and checked against a SHA-256 hash
of the data, and only then renamed over the old file, or written to
--outdir.

The new file opens with the same password or key file as the old one.
When the old file is opened with an RSA key, that user's RSA key is
added to the new file. Other RSA and smart card users of the old file
are listed so they can be added again with fcrypt.

Reading the old format needs algorithms FIPS mode does not allow, so on
a system in FIPS mode fmigrate needs --no-fips.
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

#include <openssl/pem.h>

#ifdef __MSVC_DEBUG__
#include "leaktest.h"
#endif

// Globals
gxString debug_message;
int debug_mode = 0;
int debug_level = 1;
int num_buckets = 1024;
gxList<gxString> file_list;     // Files named on the command line
gxList<gxString> dir_file_list; // Files found with -R
gxString output_dir_name;
int recurse = 0;
int overwrite = 0;
int allow_unencrypted = 0;
int check_only = 0;
int use_password = 0;
int use_key_file = 0;
gxString input_arg_key_file;
MemoryBuffer key;
gxString password;
unsigned legacy_key_iterations = AES_DEF_ITERATIONS;
unsigned new_key_iterations = FC_DEF_ITERATIONS;
gxString private_rsa_key_file;
int use_private_rsa_key = 0;
char private_key[RSA_max_keybuf_len];
unsigned private_key_len = 0;
gxString rsa_key_passphrase;
int has_passphrase = 0;
gxString rsa_key_username;
int fips_request = FC_FIPS_AUTO;
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
int OldFormatVersion(const char *fname);
int CheckFile(const char *fname);
int MigrateFile(const char *fname, int from_dir);

// SHA-256 of the data passed through, to check the new file
class HashSink : public CryptDataSink
{
public:
  HashSink() {
    len = (FAU_t)0;
    ctx = EVP_MD_CTX_new();
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    md = EVP_MD_fetch(AES_get_libctx(), "SHA256", 0);
#else
    md = EVP_sha256();
#endif
    ok = (ctx && md && EVP_DigestInit_ex(ctx, md, 0) == 1);
  }
  ~HashSink() {
    if(ctx) EVP_MD_CTX_free(ctx);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if(md) EVP_MD_free(md);
#endif
  }
  int WriteData(const unsigned char *buf, unsigned n) {
    if(!ok) return 0;
    ok = EVP_DigestUpdate(ctx, buf, n) == 1;
    len += n;
    return ok;
  }
  int Final(unsigned char out[SHA256_DIGEST_LENGTH]) {
    unsigned n = 0;
    if(!ok) return 0;
    ok = EVP_DigestFinal_ex(ctx, out, &n) == 1 && n == SHA256_DIGEST_LENGTH;
    return ok;
  }
  FAU_t len;

private:
  EVP_MD_CTX *ctx;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  EVP_MD *md;
#else
  const EVP_MD *md;
#endif
  int ok;
};

// Encrypts what the old file decrypts to, and hashes it
class MigrateSink : public CryptDataSink
{
public:
  MigrateSink(FCryptCache *f, FCryptFile *n, const MemoryBuffer *s, const char *o) {
    fc = f; nf = n; secret = s; out_name = o; started = 0;
  }
  int Start() {
    if(started) return 1;
    gxString name = fc->StoredFileName();
    if(name.is_null()) {
      nf->err << clear << "The old file has no stored file name";
      return 0;
    }
    started = nf->BeginEncrypt(*secret, name.c_str(), out_name);
    return started;
  }
  int WriteData(const unsigned char *buf, unsigned n) {
    if(!Start()) return 0;
    return hash.WriteData(buf, n) && nf->WriteData(buf, n);
  }
  HashSink hash;
  int started;

private:
  FCryptCache *fc;
  FCryptFile *nf;
  const MemoryBuffer *secret;
  const char *out_name;
};

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
  cout << "Converts file formats 2023103 and 2023102 to " << FC_FILE_VERSION << "\n" << flush;
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
  cout << "Converts old encrypted files to the " << FC_FILE_VERSION << " format, in place unless --outdir is given" << "\n" << flush;
  cout << "Switches: -?  Display this help message and exit." << "\n" << flush;
  cout << "          -d  Enable debugging output" << "\n" << flush;
  cout << "          -h  Display this help message and exit." << "\n" << flush;
  cout << "          -o  Overwrite existing files in the output DIR" << "\n" << flush;
  cout << "          -R  Convert the encrypted files in a DIR and all its subdirectories" << "\n" << flush;
  cout << "          -v  Enable verbose messages to the console" << "\n" << flush;
  cout << "\n" << flush;
  cout << "          --allow-unencrypted (Convert mode 0 test files that are not encrypted)" << "\n" << flush;
  cout << "          --check (Show the format of each file and exit, no key needed)" << "\n" << flush;
  cout << "          --debug (Turn on debugging and set optional level)" << "\n" << flush;
  cout << "          --fips (Use only the OpenSSL FIPS provider, cannot read old files)" << "\n" << flush;
  cout << "          --help (Display this help message and exit." << "\n" << flush;
  cout << "          --iter=num (Key iterations used to encrypt the old files, default " << AES_DEF_ITERATIONS << ")" << "\n" << flush;
  cout << "          --key=aes_key (Key file the old files were encrypted with)" << "\n" << flush;
  cout << "          --new-iter=num (PBKDF2 iterations for the new files, default " << FC_DEF_ITERATIONS << ")" << "\n" << flush;
  cout << "          --no-fips (Do not use FIPS mode, needed on a system in FIPS mode)" << "\n" << flush;
  cout << "          --outdir=dir (Write the new files to this directory and keep the old files)" << "\n" << flush;
  cout << "          --password (Password the old files were encrypted with)" << "\n" << flush;
  cout << "          --rsa-key=file (Open the old files with a private RSA key)" << "\n" << flush;
  cout << "          --rsa-key-passphrase (Passphrase for private RSA key)" << "\n" << flush;
  cout << "          --rsa-key-username=name (Username that owns the private RSA key)" << "\n" << flush;
  cout << "          --verbose (Turn on verbose output)" << "\n" << flush;
  cout << "          --version (Display program version number)" << "\n" << flush;
#ifdef __ENABLE_SMART_CARD__
  cout << "\n" << flush;
  cout << "          --smartcard-cert (Open the old files with a smart card)" << "\n" << flush;
  cout << "          --smartcard-pin=pin (Supply smart card PIN on the command line for scripting, use with caution)" << "\n" << flush;
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
    equal_arg = arg;
    equal_arg.DeleteBeforeIncluding("=");
    arg.DeleteAfterIncluding("=");
    equal_arg.TrimLeading(' '); equal_arg.TrimTrailing(' ');
    equal_arg.TrimLeading('\"'); equal_arg.TrimTrailing('\"');
    equal_arg.TrimLeading('\''); equal_arg.TrimTrailing('\'');
  }

  arg.ToLower();

  if(arg == "help" || arg == "?") {
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
    }
    clientcfg->verbose_mode = 1;
    debug_mode = 1;
    has_valid_args = 1;
  }

  if(arg == "verbose") {
    clientcfg->verbose_mode = 1;
    has_valid_args = 1;
  }

  if(arg == "check") {
    check_only = 1;
    has_valid_args = 1;
  }

  if(arg == "outdir") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --outdir requires an input argument" << "\n" << flush;
      return 0;
    }
    output_dir_name = equal_arg;
    if(!futils_exists(output_dir_name.c_str())) {
      if(!cryptdb_makedirs(output_dir_name)) {
	cerr << "ERROR: Error making directory " << output_dir_name.c_str() << "\n" << flush;
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
    if(equal_arg.is_null() || equal_arg.Atoi() <= 0) {
      cerr << "ERROR: --iter requires a number: --iter=1000" << "\n" << flush;
      return 0;
    }
    legacy_key_iterations = equal_arg.Atoi();
    has_valid_args = 1;
  }

  if(arg == "new-iter") {
    if(equal_arg.Atoi() < (int)FC_MIN_ITERATIONS || equal_arg.Atoi() > (int)FC_MAX_ITERATIONS) {
      cerr << "ERROR: --new-iter must be " << FC_MIN_ITERATIONS << " to " << FC_MAX_ITERATIONS << "\n" << flush;
      return 0;
    }
    new_key_iterations = equal_arg.Atoi();
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

  if(arg == "allow-unencrypted") {
    allow_unencrypted = 1;
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
    if(equal_arg.is_null()) {
      cerr << "ERROR: --rsa-key missing filename: --rsa-key=/$HOME/keys/rsa_key.pem" << "\n" << flush;
      return 0;
    }
    private_rsa_key_file = equal_arg;
    if(!futils_exists(private_rsa_key_file.c_str()) || !futils_isfile(private_rsa_key_file.c_str())) {
      cerr << "ERROR: Private RSA key file " << private_rsa_key_file.c_str() << " does not exist or cannot be read" <<  "\n" << flush;
      return 0;
    }
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

  if(arg == "rsa-key-username") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --rsa-key-username missing name: --rsa-key-username=$(whoami)" << "\n" << flush;
      return 0;
    }
    rsa_key_username = equal_arg;
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
    has_valid_args = 1;
  }

  if(arg == "smartcard-provider") {
    if(equal_arg.is_null()) {
      cerr << "ERROR: --smartcard-provider missing path: --smartcard-provider=" <<  SC_get_default_modulePath() << "\n" << flush;
      return 0;
    }
    sc.SetModulePath(equal_arg.c_str());
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

    case 'o': case 'O':
      overwrite = 1;
      break;

    case 'R':
      recurse = 1;
      break;

    case '-':
      sbuf = arg+2;
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
  key.Clear(1);
  password.Clear(1);
  OPENSSL_cleanse(private_key, sizeof(private_key));
  rsa_key_passphrase.Clear(1);

  if(debug_mode) {
#ifdef __ENABLE_SMART_CARD__
    cerr << "Smart card: " << sc.err_string << "\n" << flush;
#endif
    char err[1024];
    memset(err, 0, sizeof(err));
    ERR_error_string(ERR_get_error(), err);
    cerr << "Openssl " << err << "\n" << flush;
  }

  if(exit_message) {
    cerr << exit_message << "\n" << flush;
  }
  FC_crypto_cleanup();
  return rv;
}

int OldFormatVersion(const char *fname)
// Returns the version at the start of an old format file, or 0
{
  FILE *fp = fopen(fname, "rb");
  if(!fp) return 0;
  unsigned char v[4];
  int n = (int)fread(v, 1, sizeof(v), fp);
  fclose(fp);
  if(n != (int)sizeof(v)) return 0;
  unsigned version = (unsigned)v[0] | ((unsigned)v[1] << 8) | ((unsigned)v[2] << 16) | ((unsigned)v[3] << 24);
  if(version == 2023103 || version == 2023102) return (int)version;
  return 0;
}

int CheckFile(const char *fname)
{
  int fmt = FC_file_format(fname);
  if(fmt == FC_FORMAT_OPEN_ERROR) {
    cerr << "ERROR: Cannot open " << fname << "\n" << flush;
    return 0;
  }
  if(fmt == FC_FORMAT_2026102) {
    cout << fname << ": " << FC_FILE_VERSION << " format" << "\n" << flush;
  }
  else if(OldFormatVersion(fname)) {
    cout << fname << ": old format, convert with fmigrate" << "\n" << flush;
  }
  else {
    cout << fname << ": not an fcrypt encrypted file" << "\n" << flush;
  }
  return 1;
}

int LegacyKeySecret(FCryptCache &fc, const char *fname, MemoryBuffer &secret)
// Recover the password or key of an old file from an RSA key or smart
// card user block, the same way as fdecrypt
{
  if(!fc.LoadStaticDataBlocks(fname)) {
    cerr << "ERROR: " << fc.err.c_str() << "\n" << flush;
    return 0;
  }
  gxString username = rsa_key_username;
  unsigned block_type = 1;
#ifdef __ENABLE_SMART_CARD__
  if(use_smartcard_cert) {
    username = smartcard_cert_username;
    block_type = 2;
  }
#endif

  unsigned char message[2048];
  unsigned char hash[AES_MAX_HMAC_LEN];
  unsigned char SALT[AES_MAX_SALT_LEN];
  unsigned char IV[AES_MAX_IV_LEN];
  unsigned char KEY[AES_MAX_KEY_LEN];
  unsigned message_len = 0;
  int ok = 0;
  gxListNode<StaticDataBlock> *list_ptr = fc.static_block_list.GetHead();
  while(list_ptr) {
    if(username == list_ptr->data.username.c_str() && list_ptr->data.block_header.block_type == block_type) break;
    list_ptr = list_ptr->next;
  }
  if(!list_ptr) {
    cerr << "ERROR: User " << username.c_str() << " does not have access to " << fname << "\n" << flush;
    return 0;
  }

  int rv;
#ifdef __ENABLE_SMART_CARD__
  if(use_smartcard_cert) {
    rv = SC_private_key_decrypt(&sc, list_ptr->data.rsa_ciphertext.m_buf(), list_ptr->data.rsa_ciphertext.length(),
				message, sizeof(message), &message_len);
    if(rv != 0) {
      cerr << "ERROR: Smart card private key decrypt failed for cert ID " << sc.cert_id << "\n" << flush;
      cerr << "ERROR: " << sc.err_string << "\n" << flush;
      return 0;
    }
  }
  else
#endif
  {
    char *passphrase = 0;
    if(!rsa_key_passphrase.is_null()) passphrase = (char *)rsa_key_passphrase.GetSPtr();
    rv = RSA_private_key_decrypt((const unsigned char *)private_key, private_key_len,
				 list_ptr->data.rsa_ciphertext.m_buf(), list_ptr->data.rsa_ciphertext.length(),
				 message, sizeof(message), &message_len, RSA_padding, passphrase);
    if(rv != RSA_NO_ERROR) {
      cerr << "ERROR: RSA private key decrypt failed " << RSA_err_string(rv) << "\n" << flush;
      return 0;
    }
  }

  if(message_len >= (AES_MAX_SALT_LEN + AES_MIN_SECRET_LEN) && message_len <= sizeof(message)) {
    memmove(SALT, message, AES_MAX_SALT_LEN);
    secret.Clear(1);
    secret.Cat(message+AES_MAX_SALT_LEN, (message_len-AES_MAX_SALT_LEN));
    rv = AES_derive_key((const unsigned char*)secret.m_buf(), secret.length(),
			SALT, sizeof(SALT), KEY, sizeof(KEY), IV, sizeof(IV), 1000);
    if(rv == AES_NO_ERROR) {
      rv = AES_HMAC(KEY, sizeof(KEY), list_ptr->data.rsa_ciphertext.m_buf(), list_ptr->data.rsa_ciphertext.length(), hash, sizeof(hash));
    }
    ok = (rv == AES_NO_ERROR && list_ptr->data.hmac.length() == sizeof(hash) &&
	  CRYPTO_memcmp(hash, list_ptr->data.hmac.m_buf(), sizeof(hash)) == 0);
    if(!ok) cerr << "ERROR: Message authentication failed for the user key block in " << fname << "\n" << flush;
  }
  else {
    cerr << "ERROR: Bad length for decrypted key" << "\n" << flush;
  }
  OPENSSL_cleanse(message, sizeof(message));
  OPENSSL_cleanse(KEY, sizeof(KEY));
  OPENSSL_cleanse(IV, sizeof(IV));
  if(!ok) secret.Clear(1);
  return ok;
}

int PublicKeyFromPrivate(MemoryBuffer &pub)
// PEM public key of the private RSA key given with --rsa-key
{
  char *passphrase = 0;
  if(!rsa_key_passphrase.is_null()) passphrase = (char *)rsa_key_passphrase.GetSPtr();
  EVP_PKEY *pkey = RSA_load_private_key((const unsigned char *)private_key, private_key_len, passphrase);
  if(!pkey) return 0;
  BIO *bio = BIO_new(BIO_s_mem());
  int ok = (bio && PEM_write_bio_PUBKEY(bio, pkey) == 1);
  if(ok) {
    char *data = 0;
    long len = BIO_get_mem_data(bio, &data);
    ok = (len > 0 && data);
    if(ok) pub.Load(data, (__ULWORD__)len);
  }
  if(bio) BIO_free(bio);
  EVP_PKEY_free(pkey);
  return ok;
}

gxString MakeTempName(const gxString &path)
{
  unsigned char rnd[8];
  memset(rnd, 0, sizeof(rnd));
  AES_fillrand(rnd, sizeof(rnd));
  const char *hex = "0123456789abcdef";
  gxString tmp = path;
  tmp << ".fmigrate_";
  for(unsigned i = 0; i < sizeof(rnd); i++) tmp << hex[(rnd[i] >> 4) & 0xF] << hex[rnd[i] & 0xF];
  tmp << ".tmp";
  return tmp;
}

int MigrateFile(const char *fname, int from_dir)
// Returns false on error
{
  int fmt = FC_file_format(fname);
  if(fmt == FC_FORMAT_OPEN_ERROR) {
    cerr << "ERROR: Cannot open " << fname << "\n" << flush;
    return 0;
  }
  if(fmt == FC_FORMAT_2026102) {
    cerr << "Skipping " << fname << ", already in the " << FC_FILE_VERSION << " format" << "\n" << flush;
    return 1;
  }
  int old_version = OldFormatVersion(fname);
  if(!old_version) {
    if(from_dir) {
      if(clientcfg->verbose_mode) cerr << "Skipping " << fname << ", not an fcrypt encrypted file" << "\n" << flush;
      return 1;
    }
    cerr << "ERROR: " << fname << " is not an fcrypt encrypted file" << "\n" << flush;
    return 0;
  }

  // Where the new file goes
  gxString final_name = fname;
  if(!output_dir_name.is_null()) {
    gxString base = fname;
    int sep = -1;
    for(int i = (int)base.length()-1; i >= 0; i--) {
      if(base[i] == '/' || base[i] == '\\') { sep = i; break; }
    }
    if(sep >= 0) base.DeleteAt(0, sep+1);
    gxString dir = output_dir_name;
#if defined (__WIN32__)
    futils_makeDOSpath(dir.c_str());
    if(dir[dir.length()-1] != '\\') dir << '\\';
#else
    if(dir[dir.length()-1] != '/') dir << '/';
#endif
    final_name = dir;
    final_name << base;
    if(futils_exists(final_name.c_str()) && !overwrite) {
      cerr << "ERROR: Output file " << final_name.c_str() << " exists, use -o to overwrite" << "\n" << flush;
      return 0;
    }
  }
  gxString tmp_name = MakeTempName(final_name);

  // The password or key that opens the old file, and the new one
  FCryptCache fc(num_buckets);
  fc.key_iterations = legacy_key_iterations;
  fc.SetAllowUnencrypted(allow_unencrypted);
  MemoryBuffer secret;
  int use_user_key = use_private_rsa_key;
#ifdef __ENABLE_SMART_CARD__
  if(use_smartcard_cert) use_user_key = 1;
#endif
  if(use_user_key) {
    if(!LegacyKeySecret(fc, fname, secret)) return 0;
  }
  else {
    if(use_key_file && !use_password) secret = key;
    else secret.Cat(password.GetSPtr(), password.length());
  }

  // The users of the old file, which are not carried over
  gxList<gxString> dropped;
  FCryptCache users(num_buckets);
  if(users.LoadStaticDataBlocks(fname)) {
    gxListNode<StaticDataBlock> *list_ptr = users.static_block_list.GetHead();
    while(list_ptr) {
      int same_user = (use_private_rsa_key && list_ptr->data.block_header.block_type == 1 &&
		       rsa_key_username == list_ptr->data.username.c_str());
      if(!same_user) {
	gxString s;
	s << (list_ptr->data.block_header.block_type == 2 ? "smart card user " : "RSA user ")
	  << list_ptr->data.username.c_str();
	dropped.Add(s);
      }
      list_ptr = list_ptr->next;
    }
  }

  if(clientcfg->verbose_mode) cerr << "Converting " << fname << " from " << old_version << " to " << FC_FILE_VERSION << "\n" << flush;

  // Decrypt the old file straight into the new one
  FCryptFile nf;
  nf.iterations = new_key_iterations;
  MigrateSink sink(&fc, &nf, &secret, tmp_name.c_str());
  gxUINT32 version;
  int ok = fc.DecryptToSink(fname, secret, version, &sink);
  if(!ok) {
    cerr << "ERROR: Cannot decrypt " << fname << "\n" << flush;
    if(!fc.err.is_null()) cerr << "ERROR: " << fc.err.c_str() << "\n" << flush;
    if(!nf.err.is_null()) cerr << "ERROR: " << nf.err.c_str() << "\n" << flush;
    nf.AbortEncrypt();
    secret.Clear(1);
    return 0;
  }
  ok = sink.Start(); // An empty file sends no data
  if(ok) ok = nf.FinishEncrypt();
  unsigned char hash1[SHA256_DIGEST_LENGTH];
  if(ok) ok = sink.hash.Final(hash1);
  if(!ok) {
    cerr << "ERROR: Cannot write the new file for " << fname << "\n" << flush;
    if(!nf.err.is_null()) cerr << "ERROR: " << nf.err.c_str() << "\n" << flush;
    nf.AbortEncrypt();
    futils_remove(tmp_name.c_str());
    secret.Clear(1);
    return 0;
  }

  // Check the new file before it replaces anything
  FCryptFile vf;
  HashSink check;
  unsigned char hash2[SHA256_DIGEST_LENGTH];
  vf.data_sink = &check;
  ok = vf.LoadHeader(tmp_name.c_str()) && vf.UnlockWithSecret(secret) && vf.DecryptFile() &&
    check.Final(hash2) && check.len == sink.hash.len && memcmp(hash1, hash2, sizeof(hash1)) == 0 &&
    vf.stored_name == fc.StoredFileName();
  if(!ok) {
    cerr << "ERROR: The new file for " << fname << " failed its check" << "\n" << flush;
    if(!vf.err.is_null()) cerr << "ERROR: " << vf.err.c_str() << "\n" << flush;
  }

  // Give the user who opened the old file with an RSA key the same access
  if(ok && use_private_rsa_key) {
    MemoryBuffer pub;
    ok = PublicKeyFromPrivate(pub) &&
      vf.AddRSAKey(rsa_key_username.c_str(), (const char *)pub.m_buf(), pub.length());
    if(!ok) {
      cerr << "ERROR: Cannot add the RSA key for user " << rsa_key_username.c_str() << " to the new file" << "\n" << flush;
      if(!vf.err.is_null()) cerr << "ERROR: " << vf.err.c_str() << "\n" << flush;
    }
    if(ok) {
      FCryptFile rf;
      char *passphrase = 0;
      if(!rsa_key_passphrase.is_null()) passphrase = (char *)rsa_key_passphrase.GetSPtr();
      ok = rf.LoadHeader(tmp_name.c_str()) &&
	rf.UnlockWithRSAKey(rsa_key_username.c_str(), private_key, private_key_len, passphrase);
      if(!ok) cerr << "ERROR: The RSA key for user " << rsa_key_username.c_str() << " cannot open the new file" << "\n" << flush;
    }
  }
  secret.Clear(1);

  if(ok) {
    ok = cryptdb_rename_file(tmp_name.c_str(), final_name.c_str(), 1);
    if(!ok) cerr << "ERROR: Error renaming " << tmp_name.c_str() << " to " << final_name.c_str() << "\n" << flush;
  }
  if(!ok) {
    futils_remove(tmp_name.c_str());
    return 0;
  }

  cerr << "Converted " << fname;
  if(final_name != fname) cerr << " to " << final_name.c_str();
  cerr << " (" << old_version << " to " << FC_FILE_VERSION << ")" << "\n" << flush;
  gxListNode<gxString> *dptr = dropped.GetHead();
  if(dptr) {
    cerr << "NOTE: These users of the old file must be added again with fcrypt:";
    while(dptr) {
      cerr << " " << dptr->data.c_str();
      dptr = dptr->next;
    }
    cerr << "\n" << flush;
  }
  return 1;
}

int main(int argc, char **argv)
{
#ifdef __MSVC_DEBUG__
  InitLeakTest();
#endif

  AES_openssl_init();

  // Set this programs information
  clientcfg->executable_name = "fmigrate";
  clientcfg->program_name = "File Migrate";

  if(argc < 2) {
    HelpMessage();
    return ExitProgram(1);
  }

  clientcfg->executable_name = argv[0]; // Set the name of this executable
  int narg;
  char *arg = argv[narg = 1];
  gxString fn;
  int num_files = 0;
  int num_dirs = 0;
  int err = 0;
  gxString err_str;

  char curr_pwd[futils_MAX_DIR_LENGTH];
  while(narg < argc) {
    if(arg[0] != '\0') {
      if(arg[0] == '-') { // Look for command line arguments
	if(!ProcessArgs(arg)) return ExitProgram(1); // Exit if argument is not valid
      }
      else {
	fn = arg;
	if(futils_isdirectory(fn.c_str())) {
	  if(!recurse) {
	    cerr << "ERROR: " << fn.c_str() << " is a directory, use -R to convert the files in it" << "\n" << flush;
	    return ExitProgram(1);
	  }
	  if(futils_getcwd(curr_pwd, futils_MAX_DIR_LENGTH) != 0) {
	    cerr << "ERROR: Error setting current present working DIR" << "\n" << flush;
	    return ExitProgram(1);
	  }
	  num_dirs++;
	  if(!cryptdb_getdircontents(fn, err_str, dir_file_list, num_files, num_dirs)) {
	    cerr << "ERROR: " << err_str.c_str() << "\n" << flush;
	    return ExitProgram(1);
	  }
	  if(futils_chdir(curr_pwd) != 0) {
	    cerr << "ERROR: Error resetting current present working DIR" << "\n" << flush;
	    return ExitProgram(1);
	  }
	}
	else {
	  num_files++;
	  file_list.Add(fn);
	}
      }
    }
    arg = argv[++narg];
  }

  if(file_list.IsEmpty() && dir_file_list.IsEmpty()) {
    cerr << "ERROR: No file name specified" << "\n" << flush;
    return ExitProgram(1);
  }

  gxListNode<gxString> *ptr;
  if(check_only) {
    for(ptr = file_list.GetHead(); ptr; ptr = ptr->next) if(!CheckFile(ptr->data.c_str())) err = 1;
    for(ptr = dir_file_list.GetHead(); ptr; ptr = ptr->next) if(!CheckFile(ptr->data.c_str())) err = 1;
    return ExitProgram(err);
  }

  gxString fips_err;
  if(!FC_crypto_init(fips_request, fips_err)) {
    cerr << "ERROR: " << fips_err.c_str() << "\n" << flush;
    return ExitProgram(1);
  }
  if(FC_fips_mode()) {
    cerr << "ERROR: Old format files cannot be read in FIPS mode, rerun fmigrate with --no-fips" << "\n" << flush;
    return ExitProgram(1);
  }
  if(clientcfg->verbose_mode) cerr << FC_crypto_status().c_str() << "\n" << flush;

  if(use_private_rsa_key) {
    if(rsa_key_username.is_null()) {
      cerr << "ERROR: --rsa-key requires --rsa-key-username" << "\n" << flush;
      return ExitProgram(1);
    }
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
    if(debug_mode) sc.verbose_mode = 1;
    if(sc.pin[0] == 0) {
      gxString pin_buf;
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
  else if(use_key_file && !use_password) {
    if(clientcfg->verbose_mode) cerr << "Using key file to open the old files" << "\n" << flush;
  }
  else if(password.is_null()) {
    cout << "Password: " << flush;
    if(!consoleGetString(password, 1)) {
      cout << "\n" << flush;
      password.Clear(1);
      cerr << "Invalid entry!" << "\n" << flush;
      return ExitProgram(1);
    }
    cout << "\n" << flush;
  }

  for(ptr = file_list.GetHead(); ptr; ptr = ptr->next) if(!MigrateFile(ptr->data.c_str(), 0)) err = 1;
  for(ptr = dir_file_list.GetHead(); ptr; ptr = ptr->next) if(!MigrateFile(ptr->data.c_str(), 1)) err = 1;

  return ExitProgram(err);
}
// ----------------------------------------------------------- //
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
