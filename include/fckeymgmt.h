// ------------------------------- //
// -------- Start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- //
// C++ Header File Name: fckeymgmt.h
// Compiler Used: MSVC, GCC
// Produced By: DataReel Software Development Team
// File Creation Date: 10/27/2026
// Date Last Modified: 10/27/2026
// Copyright (c) 2001-2026 DataReel Software Development
// ----------------------------------------------------------- //
// ---------- Include File Description and Details  ---------- //
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

Key management helpers shared by fcrypt, fdecrypt and the Encrypted
Password Database (EPDB): reading secrets from a file or file
descriptor, name=value input, safe file replacement, the access log
and the file version check. None of these change a file format.

ACCESS LOG FORMAT (FCLOG1)

One line per entry, UTF-8, fields separated by a tab. Every field is
name=value. In values a backslash, tab, carriage return and newline
are written as \\, \t, \r and \n. A field that does not apply is "-".

  FCLOG1 time= user= host= pid= tool= file= id= auth= slot= action=
  record= result= detail= mac=

  time    UTC, 2026-10-27T02:41:01Z
  user    OS user name, host = host name, pid = process ID
  tool    program name, such as epdb_auth_tool, fcrypt, fdecrypt or the GUI
  file    absolute path of the database or encrypted file
  id      database or file ID in hex, read from the file header
  auth    password, key-file, rsa-key, smartcard or none
  slot    user name of the RSA key or smart card slot used or changed
  action  open, add-record, update-record, delete-record, add-user,
          remove-user, rekey, upgrade or access-log-rekey
  record  record (key) name for record actions
  result  ok or fail
  detail  short reason, never a secret or a record value
  mac     tamper evidence tag in hex, or "-"

Tags form an HMAC-SHA256 chain per file ID. The key is
KBKDF-HMAC-SHA256(master key, "FCLOG1 access log", file ID): the EPDB
v2 master key or the fcrypt 2026102 file key. A line written with the
key (after the file was opened) gets

  mac = HMAC(key, previous tag || every "-" line of the same ID since
             the previous tag, each with its newline || this line up
             to the tab before mac=)

The previous tag is 32 zero bytes for the first tagged line of an ID.
Lines written without the key (a failed open, or a v1 database) get
mac=- and are covered by the next tagged line of the same ID. Changing,
removing, reordering or inserting lines before the last tagged line is
detected by --verify-access-log. Lines after the last tagged line, and
removal of whole lines from the end of the log, cannot be detected.

Logging is off unless asked for (--access-log or the GUI setting). The
log file is created with mode 0600. If it cannot be written the tools
warn once and go on: a log failure never stops an open or a change.
*/
// ----------------------------------------------------------- //
#ifndef __FC_KEYMGMT_HPP__
#define __FC_KEYMGMT_HPP__

#include "gxdlcode.h"
#include "gxstring.h"
#include "membuf.h"
#include "gxlist.h"
#include "gxheader.h"

#include <string.h>

const unsigned FC_MAX_SECRET_LINE = 4096;   // Longest secret read from a file or descriptor
const unsigned FC_MAX_INPUT_LEN = 1048576;  // Longest name=value input
const unsigned FC_LOG_KEY_LEN = 32;
const unsigned FC_LOG_TAG_LEN = 32;
const unsigned FC_GENERATED_SECRET_BYTES = 32; // Generated passwords are 64 hex digits

// ----------------------------------------------------------- //
// Secrets and input from a file, a file descriptor or stdin
// ----------------------------------------------------------- //
// The secret is the first line without its line ending. A file must
// be a regular file owned by the user with no group or other access.
// Return 0 if successful or 1 with err set.
int FC_read_secret_fd(const char *fd_str, gxString &secret, gxString &err);
int FC_read_secret_file(const char *fname, gxString &secret, gxString &err);
// Whole input (name=value lines). The file has the same checks as a
// secret file. fd_str "0" or "-" reads stdin.
int FC_read_input_fd(const char *fd_str, MemoryBuffer &data, gxString &err);
int FC_read_input_file(const char *fname, MemoryBuffer &data, gxString &err);
// Overwrites the value of --password=, --rsa-key-passphrase= and
// --smartcard-pin= in an argv string, so ps no longer shows it
void FC_wipe_secret_arg(char *arg);
// Warning for a secret given on the command line
void FC_warn_secret_on_command_line(const char *option, const char *alternatives);
// Returns 1 if fd_str is a valid file descriptor number
int FC_parse_fd(const char *fd_str, int *fd);
// Returns 1 if stdin is a terminal
int FC_stdin_is_terminal();
// Returns 1 if stdin and stderr are a terminal, so a person can answer
int FC_console_is_interactive();

struct GXDLCODE_API FCNameValue
{
  FCNameValue() { line = 0; }
  ~FCNameValue() { Wipe(); }
  FCNameValue(const FCNameValue &ob) { Copy(ob); }
  FCNameValue &operator=(const FCNameValue &ob) {
    if(&ob != this) Copy(ob);
    return *this;
  }
  void Copy(const FCNameValue &ob) { name = ob.name; value = ob.value; line = ob.line; }
  void Wipe();
  gxString name;   // Lower case up to the first colon, spaces trimmed
  gxString value;  // Unescaped: \n, \t, \r and \\ become the characters
  unsigned line;
};

// Parses name=value lines. Blank lines and lines starting with # are
// skipped. A line without = is an error. Returns 0 if successful.
int FC_parse_name_values(const MemoryBuffer &data, gxList<FCNameValue> &list, gxString &err);
void FC_wipe_name_values(gxList<FCNameValue> &list);

// ----------------------------------------------------------- //
// Rekey input and plan
// ----------------------------------------------------------- //
// Rekey input, name=value lines read from stdin, --rekey-fd=N or
// --rekey-file=path:
//   password=<current password>      Keep the password slot with this password
//   new-password=<password>          Give the password slot a new password
//   drop-password=yes                Remove the password slot
//   rsa:<user>=<public key file>     Rewrap the RSA slot of <user>
//   smartcard:<user>=<cert file>     Rewrap the smart card slot of <user>, PEM or DER
//   smartcard:<user>=card            Read the cert from the card in the reader, no PIN
//   drop-rsa:<user>=yes              Remove the RSA slot of <user>
//   drop-smartcard:<user>=yes        Remove the smart card slot of <user>
// A password given with --password-fd, --password-file, --password or
// --key to authenticate counts as password=. A new random password can
// be written to --rekey-new-password-file or --rekey-new-password-fd.
enum { // What happens to the password slot
  FC_REKEY_PW_NONE = 0,  // No password slot after the rekey
  FC_REKEY_PW_KEEP,      // The supplied current password
  FC_REKEY_PW_NEW,       // new-password=
  FC_REKEY_PW_GENERATE   // A generated password written to a file or descriptor
};

struct GXDLCODE_API FCRekeySlot
{
  FCRekeySlot() { type = 0; drop = 0; }
  unsigned type;      // FC_SLOT_RSA or FC_SLOT_SMARTCARD (fcfile.h)
  gxString username;
  gxString source;    // Public key or cert file, or "card"
  int drop;
};

struct GXDLCODE_API FCRekeyInput
{
  FCRekeyInput() { drop_password = 0; }
  ~FCRekeyInput() { Wipe(); }
  void Wipe();
  gxString password;
  gxString new_password;
  int drop_password;
  gxList<FCRekeySlot> slots;
};

// Parses rekey input. Returns 0 if successful.
int FC_parse_rekey_input(gxList<FCNameValue> &list, FCRekeyInput &in, gxString &err);

// Works out the rekey. existing lists the RSA and smart card slots of
// the file (type and username only). has_password_slot is 1 when the
// file has a password slot (an EPDB database always does: the password
// derives its master key). generate is 1 when a generated password was
// asked for. On success keep lists the slots to rewrap and pw_action is
// FC_REKEY_PW_*. Returns 0 if successful, 1 if credentials are missing
// (missing lists them, one per line) and -1 on other errors (err).
int FC_rekey_plan(gxList<FCRekeySlot> &existing, int has_password_slot, int password_supplied,
		  int generate, FCRekeyInput &in, gxList<FCRekeySlot> &keep, int &pw_action,
		  gxString &missing, gxString &err);

// ----------------------------------------------------------- //
// Files
// ----------------------------------------------------------- //
// Flushes a file to disk. Returns 0 if successful.
int FC_fsync_file(const char *fname);
// Copies a file to a new file only the user can read, then compares
// the copy with the original. Returns 0 if successful.
int FC_copy_private(const char *from, const char *to, gxString &err);
// Flushes from to disk and renames it over to. On Windows the rename
// replaces an existing file. Returns 0 if successful. For tests,
// FCRYPT_TEST_CRASH_BEFORE_RENAME=1 kills the program just before the
// rename, to show the original file survives.
int FC_replace_file(const char *from, const char *to, gxString &err);
// Name for a backup copy: fname with ".<tag>-YYYYMMDD-HHMMSS" inserted
// before ext (ext may be null for no extension change)
gxString FC_backup_name(const char *fname, const char *tag, const char *ext = 0);
// Makes a random password of FC_GENERATED_SECRET_BYTES bytes in hex
int FC_generate_secret(gxString &secret);
// Writes a new secret as one line to a new private file (it must not
// exist) or to an open file descriptor. Returns 0 if successful.
int FC_write_secret_file(const char *fname, const gxString &secret, gxString &err);
int FC_write_secret_fd(const char *fd_str, const gxString &secret, gxString &err);
// Offset of the last sub in s, or -1
int FC_find_last(const char *s, const char *sub);
// Absolute path of a file name, for the access log
gxString FC_abs_path(const char *fname);

// ----------------------------------------------------------- //
// Version check, without decrypting and without a smart card
// ----------------------------------------------------------- //
enum {
  FC_KIND_UNKNOWN = 0,
  FC_KIND_FCRYPT,      // fcrypt encrypted file
  FC_KIND_EPDB         // Encrypted Password Database data file (.ehd)
};

struct GXDLCODE_API FCVersionInfo
{
  FCVersionInfo() { kind = FC_KIND_UNKNOWN; format = 0; is_v1 = 0; }
  int kind;
  int format;          // 1 or 2
  int is_v1;           // 1 for formats that should be upgraded
  gxString version;    // Format name for messages
  gxString upgrade;    // Command that upgrades a v1 file
};

// Returns 0 if the file was identified, 1 if it is not an fcrypt or
// EPDB file and -1 if it cannot be read (err is set).
int FC_check_version(const char *fname, FCVersionInfo &info, gxString &err);
// Warning text for a v1 file, naming the upgrade command
gxString FC_v1_warning(const char *fname, const FCVersionInfo &info);

// ----------------------------------------------------------- //
// Access log, see the format above
// ----------------------------------------------------------- //
struct GXDLCODE_API FCLogEntry
{
  FCLogEntry() { }
  gxString tool;
  gxString file;
  gxString id;      // Hex file or database ID, or empty
  gxString auth;
  gxString slot;
  gxString action;
  gxString record;
  int ok;
  gxString detail;
};

struct GXDLCODE_API FCLogVerifyResult
{
  FCLogVerifyResult() { lines = id_lines = tagged = untagged_covered = trailing_untagged = bad_lines = 0; first_bad_line = 0; }
  unsigned lines;              // Lines in the log
  unsigned id_lines;           // Lines for this file ID
  unsigned tagged;             // Tagged lines that verified
  unsigned untagged_covered;   // mac=- lines covered by a later tag
  unsigned trailing_untagged;  // mac=- lines after the last tag
  unsigned bad_lines;          // Tags that did not verify or lines that do not parse
  unsigned first_bad_line;     // Line number of the first problem
  gxString first_bad_reason;
};

// Hex of a binary ID
gxString FC_hex(const unsigned char *buf, unsigned len);
// Derives the log key from a master key and ID. Returns 1 if successful.
int FC_log_key(const unsigned char *master, unsigned master_len,
	       const unsigned char *id, unsigned id_len, unsigned char key[FC_LOG_KEY_LEN]);
// Appends an entry. key is null for an untagged line. Returns 0 if
// successful.
int FC_log_append(const char *log_file, const FCLogEntry &entry,
		  const unsigned char *key, gxString &err);
// Checks the lines of one file ID. Returns 0 if every tag verified, 1
// if tampering was found and -1 if the log cannot be read.
int FC_log_verify(const char *log_file, const char *id, const unsigned char key[FC_LOG_KEY_LEN],
		  FCLogVerifyResult &result, gxString &err);
// After a rekey: checks the lines of old_id with old_key, then rewrites
// the log with those lines moved to new_id and tagged with new_key, so
// the chain continues with the new key. If the old lines do not verify
// the log is renamed to a backup and a new log is started. Returns 0 if
// the lines were moved, 1 if a new log was started (err holds the
// reason) and -1 on error.
int FC_log_rekey(const char *log_file, const char *old_id, const unsigned char old_key[FC_LOG_KEY_LEN],
		 const char *new_id, const unsigned char new_key[FC_LOG_KEY_LEN],
		 gxString &backup_file, gxString &err);
// Default log file: <home>/<app_dir>/logs/access.log, for example
// ~/.fcrypt/logs/access.log or %USERPROFILE%\.encrypted_password_database\logs\access.log.
// The logs directory is made with mode 0700. One log file is shared by
// every file and database: each line has the file path and ID, and the
// tag chain is per ID. Returns an empty string if there is no home DIR.
gxString FC_default_log_file(const char *app_dir);
// ----------------------------------------------------------- //
// In-file access log ring (EPDB static data area)
// ----------------------------------------------------------- //
// A fixed size ring of the most recent entries, kept in space that
// older readers never read. Layout, all integers little endian:
//
// Ring header, FC_RING_HDR_LEN (64) bytes:
//   0  magic "FCRING01"     8
//   8  entry length (96)    4
//   12 number of entries    4
//   16 next entry index     4
//   20 reserved (0)         4
//   24 entries written      8
//   32 HMAC-SHA256 over bytes 0-31 and the file ID   32
// Entries, FC_RING_ENTRY_LEN (96) bytes each:
//   0  IV                   16
//   16 AES-256-CBC of the 32 byte plain entry (PKCS#7 padded)  48
//   64 HMAC-SHA256 over the file ID, entry index, IV and ciphertext  32
// Plain entry, 32 bytes:
//   0  sequence number      8 (1 for the first entry ever written)
//   8  time, UTC seconds    8
//   16 action code          1 (FC_ACTION_*)
//   17 auth method          1 (FC_AUTH_*)
//   18 result               1 (1 = ok, 0 = fail)
//   19 flags                1 (0)
//   20 slot name hash       8 (HMAC of the user name, 0 if none)
//   28 reserved             4
// Keys: KBKDF(master key, "FCRING01 encryption" / "FCRING01 MAC",
// file ID). Nothing in the ring is readable without the master key:
// user names appear only as keyed hashes, and there is no host name.
const unsigned FC_RING_HDR_LEN = 64;
const unsigned FC_RING_ENTRY_LEN = 96;
const unsigned FC_RING_PLAIN_LEN = 32;

enum { // Action codes
  FC_ACTION_NONE = 0, FC_ACTION_OPEN, FC_ACTION_ADD_RECORD, FC_ACTION_UPDATE_RECORD,
  FC_ACTION_DELETE_RECORD, FC_ACTION_ADD_USER, FC_ACTION_REMOVE_USER, FC_ACTION_REKEY,
  FC_ACTION_UPGRADE, FC_ACTION_LOG_ON, FC_ACTION_LOG_OFF, FC_ACTION_LAST
};
enum { // Auth methods
  FC_AUTH_NONE = 0, FC_AUTH_PASSWORD, FC_AUTH_KEY_FILE, FC_AUTH_RSA_KEY, FC_AUTH_SMARTCARD, FC_AUTH_LAST
};
const char *FC_action_name(int code);
int FC_action_code(const char *name);
const char *FC_auth_name(int code);
int FC_auth_code(const char *name);

struct GXDLCODE_API FCRingEntry
{
  FCRingEntry() { seq = 0; when = 0; action = auth = result = flags = 0; memset(slot_hash, 0, sizeof(slot_hash)); index = 0; }
  unsigned long long seq;
  unsigned long long when;
  int action, auth, result, flags;
  unsigned char slot_hash[8];
  unsigned index;
};

// Bytes needed for a ring of n entries
unsigned FC_ring_size(unsigned n);
// Formats an empty ring. Returns 1 if successful.
int FC_ring_init(unsigned char *ring, unsigned ring_len, const unsigned char master[32],
		 const unsigned char *id, unsigned id_len);
// Adds an entry. Returns 1 if successful, 0 if the ring header does not
// verify (err is set).
int FC_ring_append(unsigned char *ring, unsigned ring_len, const unsigned char master[32],
		   const unsigned char *id, unsigned id_len, const FCRingEntry &entry,
		   const char *slot_username, gxString &err);
// Reads the entries, oldest first. Returns 0 if everything verified, 1
// if a tag failed or the sequence numbers show an entry was replaced or
// rolled back (err is set and the good entries are returned), -1 if the
// ring is not set up.
int FC_ring_read(const unsigned char *ring, unsigned ring_len, const unsigned char master[32],
		 const unsigned char *id, unsigned id_len, gxList<FCRingEntry> &entries,
		 unsigned long long &written, gxString &err);
// Re-encrypts every entry under a new master key and ID (after a
// rekey). Returns 1 if successful.
int FC_ring_rekey(unsigned char *ring, unsigned ring_len,
		  const unsigned char old_master[32], const unsigned char *old_id, unsigned old_id_len,
		  const unsigned char new_master[32], const unsigned char *new_id, unsigned new_id_len,
		  gxString &err);
// Keyed hash of a user name, as stored in an entry
void FC_ring_slot_hash(const unsigned char master[32], const unsigned char *id, unsigned id_len,
		       const char *username, unsigned char hash[8]);

// ----------------------------------------------------------- //
// Self-destruct control block (EPDB static data area)
// ----------------------------------------------------------- //
// 64 bytes in space older readers never read, not encrypted and not
// authenticated, so it can be updated after a failed open without the
// key. Anyone with a copy of the file can edit it: self-destruct only
// stops guessing through these programs.
//   0  magic "EPDBCTL1"        8
//   8  failed attempts         4
//   12 attempt limit           4 (1 to 99, default 5)
//   16 flags                   4 (FC_CTL_SELF_DESTRUCT)
//   20 destroyed               4 (1 after the database was destroyed)
//   24 destroyed time, UTC     8
//   32 reserved (0)            32
const unsigned FC_CTL_LEN = 64;
const unsigned FC_CTL_SELF_DESTRUCT = 0x01;
const unsigned FC_SD_DEFAULT_ATTEMPTS = 5;
const unsigned FC_SD_MAX_ATTEMPTS = 99;

struct GXDLCODE_API FCControlBlock
{
  FCControlBlock() { failed = 0; limit = FC_SD_DEFAULT_ATTEMPTS; flags = 0; destroyed = 0; destroyed_time = 0; }
  unsigned failed;
  unsigned limit;
  unsigned flags;
  unsigned destroyed;
  unsigned long long destroyed_time;
  int SelfDestruct() const { return (flags & FC_CTL_SELF_DESTRUCT) != 0; }
};

// Returns 1 if buf holds a control block
int FC_ctl_read(const unsigned char *buf, FCControlBlock &c);
void FC_ctl_write(unsigned char *buf, const FCControlBlock &c);
// "N of M attempts used, the records will be destroyed after M"
gxString FC_sd_message(unsigned used, unsigned limit);
// Overwrites a file with random data, flushes it and removes it.
// Returns 0 if successful.
int FC_secure_delete(const char *fname, gxString &err);
// Overwrites len bytes at offset with random data. Returns 0 if successful.
int FC_shred_range(FILE *fp, FAU_t offset, FAU_t len);
// Returns 1 if the file can be opened for writing (not read-only media
// or a read-only file)
int FC_file_writable(const char *fname);

// Current OS user and host name
gxString FC_os_user();
gxString FC_host_name();

#endif // __FC_KEYMGMT_HPP__
// ----------------------------------------------------------- //
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
