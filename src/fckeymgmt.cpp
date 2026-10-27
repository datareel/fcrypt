// ------------------------------- //
// -------- Start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- //
// C++ Source Code File Name: fckeymgmt.cpp
// Compiler Used: MSVC, GCC
// Produced By: DataReel Software Development Team
// File Creation Date: 10/27/2026
// Date Last Modified: 10/27/2026
// Copyright (c) 2001-2026 DataReel Software Development
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

Key management helpers, see fckeymgmt.h.
*/
// ----------------------------------------------------------- //
#include "fckeymgmt.h"
#include "fcfile.h"
#include "aesdb.h"
#include "futils.h"
#include "gxheader.h"
#include "gxdbase.h"

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

#if defined (__WIN32__)
#include <windows.h>
#include <io.h>
#include <process.h>
#else
#include <unistd.h>
#include <signal.h>
#include <sys/file.h>
#include <pwd.h>
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

// Vendored cJSON, compiled here so no build file needs it
#include "../3plibs/cjson/cJSON.c"

static const char *FC_LOG_MAGIC = "FCLOG1";

int FC_find_last(const char *s, const char *sub)
// Offset of the last sub in s, or -1
{
  if(!s || !sub || !*sub) return -1;
  int found = -1;
  for(const char *p = strstr(s, sub); p; p = strstr(p + 1, sub)) found = (int)(p - s);
  return found;
}
static const char *FC_LABEL_LOG = "FCLOG1 access log";

// ----------------------------------------------------------- //
// Low level I/O
// ----------------------------------------------------------- //
static int fc_read_fd(int fd, char *buf, unsigned len)
{
#if defined (__WIN32__)
  return _read(fd, buf, len);
#else
  return (int)read(fd, buf, len);
#endif
}

static int fc_write_fd(int fd, const char *buf, unsigned len)
// Returns 1 if every byte was written
{
  unsigned done = 0;
  while(done < len) {
#if defined (__WIN32__)
    int n = _write(fd, buf+done, len-done);
#else
    int n = (int)write(fd, buf+done, len-done);
    if(n < 0 && errno == EINTR) continue;
#endif
    if(n <= 0) return 0;
    done += (unsigned)n;
  }
  return 1;
}

static int fc_open_private_read(const char *fname, gxString &err, const char *what)
// Opens a file that must be a regular file owned by the user with no
// group or other access. Returns the descriptor or -1.
{
#if defined (__WIN32__)
  int fd = _open(fname, _O_RDONLY|_O_BINARY);
  if(fd < 0) err << clear << "Cannot open " << what << " " << fname;
  return fd;
#else
  int fd = open(fname, O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
  if(fd < 0) {
    err << clear << "Cannot open " << what << " " << fname << " (it must exist and not be a symbolic link)";
    return -1;
  }
  struct stat st;
  if(fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    err << clear << what << " " << fname << " is not a regular file";
    close(fd);
    return -1;
  }
  if(st.st_uid != geteuid()) {
    err << clear << what << " " << fname << " is not owned by the current user";
    close(fd);
    return -1;
  }
  if(st.st_mode & (S_IRWXG|S_IRWXO)) {
    err << clear << what << " " << fname << " can be read or written by other users, use chmod 600";
    close(fd);
    return -1;
  }
  return fd;
#endif
}

static void fc_close_fd(int fd)
{
#if defined (__WIN32__)
  _close(fd);
#else
  close(fd);
#endif
}

static int fc_read_secret_line(int fd, gxString &secret, gxString &err, const char *name)
// Reads one line, one byte at a time so nothing after the line is
// taken from a shared descriptor. Same rules as EPDB ReadSecretLine().
{
  char buf[FC_MAX_SECRET_LINE+1];
  unsigned len = 0;
  int rv = 0;
  while(len < FC_MAX_SECRET_LINE) {
    int n = fc_read_fd(fd, buf+len, 1);
#if !defined (__WIN32__)
    if(n < 0 && errno == EINTR) continue;
#endif
    if(n < 0) {
      err << clear << "Cannot read " << name;
      rv = 1;
      break;
    }
    if(n == 0) break;
    if(buf[len] == '\n') break;
    len++;
  }
  if(rv == 0 && len >= FC_MAX_SECRET_LINE) {
    err << clear << name << " is too long";
    rv = 1;
  }
  if(rv == 0 && len > 0 && buf[len-1] == '\r') len--;
  if(rv == 0 && len == 0) {
    err << clear << name << " is empty";
    rv = 1;
  }
  if(rv == 0) {
    secret.Clear(1);
    secret.SetString(buf, len);
  }
  OPENSSL_cleanse(buf, sizeof(buf));
  return rv;
}

static int fc_read_all(int fd, MemoryBuffer &data, gxString &err, const char *name)
{
  char buf[4096];
  data.Clear(1);
  for(;;) {
    int n = fc_read_fd(fd, buf, sizeof(buf));
#if !defined (__WIN32__)
    if(n < 0 && errno == EINTR) continue;
#endif
    if(n < 0) {
      err << clear << "Cannot read " << name;
      OPENSSL_cleanse(buf, sizeof(buf));
      data.Clear(1);
      return 1;
    }
    if(n == 0) break;
    if(data.length() + (unsigned)n > FC_MAX_INPUT_LEN) {
      err << clear << name << " is longer than " << FC_MAX_INPUT_LEN << " bytes";
      OPENSSL_cleanse(buf, sizeof(buf));
      data.Clear(1);
      return 1;
    }
    data.Cat(buf, (unsigned)n);
  }
  OPENSSL_cleanse(buf, sizeof(buf));
  return 0;
}

// ----------------------------------------------------------- //
// Secrets and input
// ----------------------------------------------------------- //
void FC_wipe_secret_arg(char *arg)
{
  if(!arg) return;
  const char *secret_args[] = { "password=", "rsa-key-passphrase=", "smartcard-pin=", 0 };
  char *p = arg;
  if(*p == 0) p++; // ProcessArgs() clears the first character
  while(*p == '-') p++;
  for(int i = 0; secret_args[i]; i++) {
    unsigned len = strlen(secret_args[i]);
    if(strncmp(p, secret_args[i], len) == 0) {
      char *v = p + len;
      memset(v, 'x', strlen(v));
      return;
    }
  }
}

void FC_warn_secret_on_command_line(const char *option, const char *alternatives)
{
  fprintf(stderr, "WARNING: %s=value puts the secret on the command line, where other users can read it. Use %s instead.\n",
	  option, alternatives);
}

int FC_parse_fd(const char *fd_str, int *fd)
{
  if(!fd_str || !*fd_str || strlen(fd_str) > 6) return 0;
  if(strcmp(fd_str, "-") == 0) {
    *fd = 0;
    return 1;
  }
  for(const char *p = fd_str; *p; p++) {
    if(*p < '0' || *p > '9') return 0;
  }
  *fd = atoi(fd_str);
  return 1;
}

int FC_read_secret_fd(const char *fd_str, gxString &secret, gxString &err)
{
  err.Clear();
  int fd = -1;
  if(!FC_parse_fd(fd_str, &fd)) {
    err << clear << "Invalid file descriptor " << (fd_str ? fd_str : "");
    return 1;
  }
  gxString name;
  name << clear << "file descriptor " << fd;
  return fc_read_secret_line(fd, secret, err, name.c_str());
}

int FC_read_secret_file(const char *fname, gxString &secret, gxString &err)
{
  err.Clear();
  int fd = fc_open_private_read(fname, err, "secret file");
  if(fd < 0) return 1;
  int rv = fc_read_secret_line(fd, secret, err, fname);
  fc_close_fd(fd);
  return rv;
}

int FC_read_input_fd(const char *fd_str, MemoryBuffer &data, gxString &err)
{
  err.Clear();
  int fd = -1;
  if(!FC_parse_fd(fd_str, &fd)) {
    err << clear << "Invalid file descriptor " << (fd_str ? fd_str : "");
    return 1;
  }
  gxString name;
  if(fd == 0) name = "stdin";
  else name << clear << "file descriptor " << fd;
  return fc_read_all(fd, data, err, name.c_str());
}

int FC_read_input_file(const char *fname, MemoryBuffer &data, gxString &err)
{
  err.Clear();
  int fd = fc_open_private_read(fname, err, "input file");
  if(fd < 0) return 1;
  int rv = fc_read_all(fd, data, err, fname);
  fc_close_fd(fd);
  return rv;
}

int FC_stdin_is_terminal()
{
#if defined (__WIN32__)
  return _isatty(_fileno(stdin));
#else
  return isatty(0);
#endif
}

int FC_console_is_interactive()
{
#if defined (__WIN32__)
  return _isatty(_fileno(stdin)) && _isatty(_fileno(stderr));
#else
  return isatty(0) && isatty(2);
#endif
}

void FCNameValue::Wipe()
{
  if(value.length()) OPENSSL_cleanse(value.GetSPtr(), value.length());
  value.Clear(1);
  name.Clear(1);
}

void FC_wipe_name_values(gxList<FCNameValue> &list)
{
  gxListNode<FCNameValue> *p = list.GetHead();
  while(p) {
    p->data.Wipe();
    p = p->next;
  }
  list.ClearList();
}

int FC_parse_name_values(const MemoryBuffer &data_in, gxList<FCNameValue> &list, gxString &err)
{
  err.Clear();
  MemoryBuffer &data = (MemoryBuffer &)data_in;
  const char *p = (const char *)data.m_buf();
  unsigned len = data.length();
  unsigned pos = 0, line = 0;
  while(pos < len) {
    line++;
    unsigned start = pos;
    while(pos < len && p[pos] != '\n') pos++;
    unsigned end = pos;
    if(pos < len) pos++; // Skip the newline
    if(end > start && p[end-1] == '\r') end--;
    if(line == 1 && end - start >= 3 && (unsigned char)p[start] == 0xEF &&
       (unsigned char)p[start+1] == 0xBB && (unsigned char)p[start+2] == 0xBF) start += 3; // UTF-8 BOM
    unsigned s = start;
    while(s < end && (p[s] == ' ' || p[s] == '\t')) s++;
    if(s == end || p[s] == '#') continue;
    unsigned eq = s;
    while(eq < end && p[eq] != '=') eq++;
    if(eq == end) {
      err << clear << "Line " << line << " is not name=value";
      FC_wipe_name_values(list);
      return 1;
    }
    FCNameValue nv;
    nv.line = line;
    nv.name.SetString(p+s, eq-s);
    nv.name.TrimTrailing(' ');
    nv.name.TrimTrailing('\t');
    // Names are not case sensitive, a user name after a colon is
    {
      int colon = nv.name.Find(":");
      char *np = (char *)nv.name.GetSPtr();
      for(int i = 0; np[i] && (colon < 0 || i < colon); i++) np[i] = (char)tolower((unsigned char)np[i]);
    }
    if(nv.name.is_null()) {
      err << clear << "Line " << line << " has no name before =";
      FC_wipe_name_values(list);
      return 1;
    }
    // Unescape the value
    unsigned vlen = end - (eq+1);
    char *v = new char[vlen+1];
    unsigned n = 0;
    for(unsigned i = eq+1; i < end; i++) {
      char c = p[i];
      if(c == '\\' && i+1 < end) {
	char e = p[i+1];
	if(e == 'n') { v[n++] = '\n'; i++; continue; }
	if(e == 't') { v[n++] = '\t'; i++; continue; }
	if(e == 'r') { v[n++] = '\r'; i++; continue; }
	if(e == '\\') { v[n++] = '\\'; i++; continue; }
      }
      v[n++] = c;
    }
    // SetString() takes a length of 0 as "up to the null", so an empty
    // value is set with Clear()
    if(n) nv.value.SetString(v, n);
    else nv.value.Clear();
    OPENSSL_cleanse(v, vlen+1);
    delete[] v;
    list.Add(nv);
  }
  return 0;
}

// ----------------------------------------------------------- //
// Advisory lock
// ----------------------------------------------------------- //
void FCLock::Release()
{
  if(fd < 0) return;
#if defined (__WIN32__)
  HANDLE h = (HANDLE)_get_osfhandle(fd);
  OVERLAPPED ov;
  memset(&ov, 0, sizeof(ov));
  UnlockFileEx(h, 0, 1, 0, &ov);
  _close(fd);
#else
  flock(fd, LOCK_UN);
  close(fd);
#endif
  fd = -1;
}

int FC_lock_file(const char *target, unsigned timeout, FCLock &lock, gxString &err)
{
  lock.Release();
  lock.name.Clear();
  lock.name << target << ".lock";
#if defined (__WIN32__)
  int fd = _open(lock.name.c_str(), _O_RDWR|_O_CREAT|_O_BINARY, _S_IREAD|_S_IWRITE);
#else
  int fd = open(lock.name.c_str(), O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC, 0600);
#endif
  if(fd < 0) {
    err << clear << "Cannot open the lock file " << lock.name;
    return -1;
  }
  unsigned waited = 0; // Tenths of a second
  for(;;) {
#if defined (__WIN32__)
    HANDLE h = (HANDLE)_get_osfhandle(fd);
    OVERLAPPED ov;
    memset(&ov, 0, sizeof(ov));
    int ok = LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK|LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ov) != 0;
#else
    int ok = flock(fd, LOCK_EX|LOCK_NB) == 0;
#endif
    if(ok) break;
    if(waited >= timeout * 10) {
      fc_close_fd(fd);
      err << clear << "Another program is changing " << target << " (" << lock.name
	  << " is locked), gave up after " << timeout << " seconds";
      return 1;
    }
#if defined (__WIN32__)
    Sleep(100);
#else
    usleep(100000);
#endif
    waited++;
  }
  lock.fd = fd;
  return 0;
}

// ----------------------------------------------------------- //
// JSON
// ----------------------------------------------------------- //
gxString FC_json_string(const char *s, unsigned len)
{
  gxString out;
  out << "\"";
  for(unsigned i = 0; i < len; i++) {
    unsigned char c = (unsigned char)s[i];
    switch(c) {
      case '"': out << "\\\""; break;
      case '\\': out << "\\\\"; break;
      case '\n': out << "\\n"; break;
      case '\r': out << "\\r"; break;
      case '\t': out << "\\t"; break;
      case '\b': out << "\\b"; break;
      case '\f': out << "\\f"; break;
      default:
	if(c < 0x20) {
	  char buf[8];
	  sprintf(buf, "\\u%04x", c);
	  out << buf;
	}
	else out << (char)c;
    }
  }
  out << "\"";
  return out;
}

gxString FC_json_string(const gxString &s)
{
  gxString &v = (gxString &)s;
  return FC_json_string(v.c_str(), v.length());
}

// Allocations of the parser keep their size in front, so free() can
// wipe them: parsed values are passwords and record fields.
static void *fc_json_malloc(size_t n)
{
  size_t *p = (size_t *)malloc(n + sizeof(size_t) * 2);
  if(!p) return 0;
  p[0] = n;
  return p + 2;
}

static void fc_json_free_mem(void *v)
{
  if(!v) return;
  size_t *p = ((size_t *)v) - 2;
  OPENSSL_cleanse(v, p[0]);
  free(p);
}

static int fc_json_has_duplicates(cJSON *item, gxString &err)
{
  for(cJSON *c = item ? item->child : 0; c; c = c->next) {
    if(cJSON_IsObject(item) && c->string) {
      for(cJSON *d = c->next; d; d = d->next) {
	if(d->string && strcmp(c->string, d->string) == 0) {
	  err << clear << "Duplicate key \"" << c->string << "\" in the JSON input";
	  return 1;
	}
      }
    }
    if(fc_json_has_duplicates(c, err)) return 1;
  }
  return 0;
}

cJSON *FC_json_parse(const MemoryBuffer &data_in, gxString &err)
{
  static int hooks_set = 0;
  if(!hooks_set) {
    cJSON_Hooks hooks;
    hooks.malloc_fn = fc_json_malloc;
    hooks.free_fn = fc_json_free_mem;
    cJSON_InitHooks(&hooks);
    hooks_set = 1;
  }
  MemoryBuffer &data = (MemoryBuffer &)data_in;
  if(data.length() > FC_MAX_INPUT_LEN) {
    err << clear << "The JSON input is longer than " << FC_MAX_INPUT_LEN << " bytes";
    return 0;
  }
  const char *end = 0;
  cJSON *root = cJSON_ParseWithLengthOpts((const char *)data.m_buf(), data.length(), &end, 0);
  if(!root) {
    unsigned pos = end ? (unsigned)(end - (const char *)data.m_buf()) : 0;
    unsigned line = 1, col = 1;
    const char *p = (const char *)data.m_buf();
    for(unsigned i = 0; i < pos && i < data.length(); i++) {
      if(p[i] == '\n') { line++; col = 1; }
      else col++;
    }
    err << clear << "The JSON input is not valid at line " << line << ", column " << col << " (byte " << pos << ")";
    return 0;
  }
  // Only spaces may follow the value
  if(end) {
    const char *p = (const char *)data.m_buf();
    for(unsigned i = (unsigned)(end - p); i < data.length(); i++) {
      if(p[i] != ' ' && p[i] != '\t' && p[i] != '\r' && p[i] != '\n') {
	err << clear << "Extra data after the JSON value at byte " << i;
	cJSON_Delete(root);
	return 0;
      }
    }
  }
  if(fc_json_has_duplicates(root, err)) {
    cJSON_Delete(root);
    return 0;
  }
  return root;
}

void FC_json_free(cJSON *root)
{
  if(root) cJSON_Delete(root);
}

int FC_input_is_json(const MemoryBuffer &data_in)
{
  MemoryBuffer &data = (MemoryBuffer &)data_in;
  const char *p = (const char *)data.m_buf();
  for(unsigned i = 0; i < data.length(); i++) {
    if(p[i] == ' ' || p[i] == '\t' || p[i] == '\r' || p[i] == '\n') continue;
    if(i == 0 && data.length() >= 3 && (unsigned char)p[0] == 0xEF) { i += 2; continue; } // BOM
    return p[i] == '{' || p[i] == '[';
  }
  return 0;
}

// ----------------------------------------------------------- //
// Rekey input and plan
// ----------------------------------------------------------- //
void FCRekeyInput::Wipe()
{
  if(password.length()) OPENSSL_cleanse(password.GetSPtr(), password.length());
  if(new_password.length()) OPENSSL_cleanse(new_password.GetSPtr(), new_password.length());
  password.Clear(1);
  new_password.Clear(1);
  drop_password = 0;
  slots.ClearList();
}

static int fc_yes(const gxString &v)
{
  gxString s = v;
  s.ToLower();
  return s == "yes" || s == "1" || s == "true";
}

int FC_parse_rekey_input(gxList<FCNameValue> &list, FCRekeyInput &in, gxString &err)
{
  gxListNode<FCNameValue> *p = list.GetHead();
  while(p) {
    gxString &n = p->data.name;
    if(n == "password") in.password = p->data.value;
    else if(n == "new-password") in.new_password = p->data.value;
    else if(n == "drop-password") in.drop_password = fc_yes(p->data.value);
    else {
      FCRekeySlot slot;
      gxString user;
      if(n.Find("rsa:") == 0) { slot.type = FC_SLOT_RSA; user = n.c_str() + 4; }
      else if(n.Find("smartcard:") == 0) { slot.type = FC_SLOT_SMARTCARD; user = n.c_str() + 10; }
      else if(n.Find("drop-rsa:") == 0) { slot.type = FC_SLOT_RSA; user = n.c_str() + 9; slot.drop = 1; }
      else if(n.Find("drop-smartcard:") == 0) { slot.type = FC_SLOT_SMARTCARD; user = n.c_str() + 15; slot.drop = 1; }
      else {
	err << clear << "Line " << p->data.line << ": unknown rekey input name " << n;
	return 1;
      }
      if(user.is_null()) {
	err << clear << "Line " << p->data.line << ": no user name after the colon";
	return 1;
      }
      if(slot.drop && !fc_yes(p->data.value)) {
	p = p->next;
	continue;
      }
      if(!slot.drop && p->data.value.is_null()) {
	err << clear << "Line " << p->data.line << ": no public key file for " << user;
	return 1;
      }
      slot.username = user;
      slot.source = p->data.value;
      in.slots.Add(slot);
    }
    p = p->next;
  }
  if(!in.new_password.is_null() && in.drop_password) {
    err << clear << "new-password and drop-password cannot both be given";
    return 1;
  }
  return 0;
}

static FCRekeySlot *fc_find_rekey_slot(gxList<FCRekeySlot> &l, unsigned type, const gxString &user)
{
  for(gxListNode<FCRekeySlot> *p = l.GetHead(); p; p = p->next) {
    if(p->data.type == type && p->data.username == user) return &p->data;
  }
  return 0;
}

int FC_rekey_plan(gxList<FCRekeySlot> &existing, int has_password_slot, int password_supplied,
		  int generate, FCRekeyInput &in, gxList<FCRekeySlot> &keep, int &pw_action,
		  gxString &missing, gxString &err)
{
  keep.ClearList();
  missing.Clear();
  pw_action = FC_REKEY_PW_NONE;
  // Every input line must name a slot of the file
  for(gxListNode<FCRekeySlot> *p = in.slots.GetHead(); p; p = p->next) {
    if(!fc_find_rekey_slot(existing, p->data.type, p->data.username)) {
      err << clear << "The file has no " << (p->data.type == FC_SLOT_RSA ? "RSA key" : "smart card")
	  << " slot for user " << p->data.username;
      return -1;
    }
  }
  for(gxListNode<FCRekeySlot> *p = existing.GetHead(); p; p = p->next) {
    FCRekeySlot *s = fc_find_rekey_slot(in.slots, p->data.type, p->data.username);
    const char *kind = (p->data.type == FC_SLOT_RSA) ? "rsa" : "smartcard";
    if(!s) {
      missing << "  " << kind << ":" << p->data.username << "="
	      << (p->data.type == FC_SLOT_RSA ? "<public key file>" : "<cert file or card>")
	      << "   (or drop-" << kind << ":" << p->data.username << "=yes)\n";
      continue;
    }
    if(s->drop) continue;
    FCRekeySlot k = p->data; // Keep the stored spelling of the name
    k.source = s->source;
    keep.Add(k);
  }
  int choices = (!in.new_password.is_null()) + (generate ? 1 : 0) + (in.drop_password ? 1 : 0);
  if(choices > 1) {
    err << clear << "Give only one of new-password, drop-password=yes and a generated password";
    return -1;
  }
  if(!has_password_slot) {
    if(choices) {
      err << clear << "The file has no password slot, new-password, drop-password and a generated password do not apply";
      return -1;
    }
  }
  else if(!in.new_password.is_null()) pw_action = FC_REKEY_PW_NEW;
  else if(generate) pw_action = FC_REKEY_PW_GENERATE;
  else if(in.drop_password) pw_action = FC_REKEY_PW_NONE;
  else if(password_supplied || !in.password.is_null()) pw_action = FC_REKEY_PW_KEEP;
  else {
    missing << "  password slot: password=<current password>, new-password=<new password>, "
	    << "drop-password=yes, or --rekey-new-password-file / --rekey-new-password-fd for a generated one\n";
  }
  if(!missing.is_null()) return 1;
  if(pw_action == FC_REKEY_PW_NONE && !keep.GetHead()) {
    err << clear << "The rekey would leave no password and no RSA or smart card slot, nothing could open the file";
    return -1;
  }
  return 0;
}

// ----------------------------------------------------------- //
// Files
// ----------------------------------------------------------- //
int FC_fsync_file(const char *fname)
{
#if defined (__WIN32__)
  HANDLE h = CreateFileA(fname, GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, 0, OPEN_EXISTING,
			 FILE_ATTRIBUTE_NORMAL, 0);
  if(h == INVALID_HANDLE_VALUE) return -1;
  int ok = FlushFileBuffers(h) != 0;
  CloseHandle(h);
  return ok ? 0 : -1;
#else
  int fd = open(fname, O_RDONLY|O_CLOEXEC);
  if(fd < 0) return -1;
  int rv = fsync(fd);
  close(fd);
  return rv == 0 ? 0 : -1;
#endif
}

static void fc_fsync_parent_dir(const char *fname)
// Makes a rename durable on Linux. Not needed on Windows.
{
#if !defined (__WIN32__)
  gxString dir(fname);
  int slash = FC_find_last(dir.c_str(), "/");
  if(slash < 0) dir = ".";
  else if(slash == 0) dir = "/";
  else dir.DeleteAt(slash, dir.length() - slash);
  int fd = open(dir.c_str(), O_RDONLY|O_CLOEXEC);
  if(fd >= 0) {
    fsync(fd);
    close(fd);
  }
#endif
}

int FC_copy_private(const char *from, const char *to, gxString &err)
{
  FILE *in = fopen(from, "rb");
  if(!in) {
    err << clear << "Cannot read " << from;
    return -1;
  }
#if defined (__WIN32__)
  int fd = _open(to, _O_WRONLY|_O_CREAT|_O_EXCL|_O_BINARY, _S_IREAD|_S_IWRITE);
#else
  int fd = open(to, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600);
#endif
  if(fd < 0) {
    fclose(in);
    err << clear << "Cannot create the backup " << to;
    return -1;
  }
  char buf[65536];
  size_t n;
  int ok = 1;
  while(ok && (n = fread(buf, 1, sizeof(buf), in)) > 0) ok = fc_write_fd(fd, buf, (unsigned)n);
  if(ferror(in)) ok = 0;
#if !defined (__WIN32__)
  if(ok && fsync(fd) != 0) ok = 0;
#endif
  fc_close_fd(fd);
  fclose(in);
  if(!ok) {
    futils_remove(to);
    err << clear << "Error writing the backup " << to;
    return -1;
  }
  // Compare the copy with the original
  FILE *a = fopen(from, "rb"), *b = fopen(to, "rb");
  int same = (a && b);
  char buf2[65536];
  while(same) {
    size_t na = fread(buf, 1, sizeof(buf), a);
    size_t nb = fread(buf2, 1, sizeof(buf2), b);
    if(na != nb || memcmp(buf, buf2, na) != 0) same = 0;
    if(na == 0) break;
  }
  if(a) fclose(a);
  if(b) fclose(b);
  OPENSSL_cleanse(buf, sizeof(buf));
  OPENSSL_cleanse(buf2, sizeof(buf2));
  if(!same) {
    futils_remove(to);
    err << clear << "The backup " << to << " does not match " << from;
    return -1;
  }
  return 0;
}

int FC_replace_file(const char *from, const char *to, gxString &err)
{
  if(FC_fsync_file(from) != 0) {
    err << clear << "Cannot flush " << from << " to disk";
    return -1;
  }
  const char *crash = getenv("FCRYPT_TEST_CRASH_BEFORE_RENAME");
  if(crash && strcmp(crash, "1") == 0) {
    // Test hook: stop the way a crash or kill -9 would, before the rename
#if defined (__WIN32__)
    TerminateProcess(GetCurrentProcess(), 137);
#else
    raise(SIGKILL);
#endif
  }
#if defined (__WIN32__)
  if(!MoveFileExA(from, to, MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)) {
#else
  if(rename(from, to) != 0) {
#endif
    err << clear << "Cannot rename " << from << " to " << to;
    return -1;
  }
  fc_fsync_parent_dir(to);
  return 0;
}

gxString FC_backup_name(const char *fname, const char *tag, const char *ext)
{
  char stamp[32];
  time_t now = time(0);
  struct tm *t = localtime(&now);
  strftime(stamp, sizeof(stamp), "%Y%m%d-%H%M%S", t);
  gxString name(fname);
  gxString suffix;
  suffix << "." << tag << "-" << stamp;
  if(ext && *ext) {
    // Replace the extension when the file has it
    unsigned el = strlen(ext);
    if(name.length() > el && CaseICmp(gxString(name.c_str() + name.length() - el), ext) == 0) {
      name.DeleteAt(name.length() - el, el);
    }
    name << suffix << ext;
  }
  else {
    name << suffix;
  }
  // Never reuse a name, two changes can come in the same second
  gxString unique = name;
  for(int i = 2; futils_exists(unique.c_str()) && i < 1000; i++) {
    unique = name;
    gxString n;
    n << "-" << i;
    if(ext && *ext) unique.InsertAt(unique.length() - strlen(ext), n.c_str(), n.length());
    else unique << n;
  }
  return unique;
}

int FC_generate_secret(gxString &secret)
{
  unsigned char rnd[FC_GENERATED_SECRET_BYTES];
  if(!FC_rand_bytes(rnd, sizeof(rnd), 1)) return 0;
  secret = FC_hex(rnd, sizeof(rnd));
  OPENSSL_cleanse(rnd, sizeof(rnd));
  return 1;
}

int FC_write_secret_file(const char *fname, const gxString &secret, gxString &err)
{
#if defined (__WIN32__)
  int fd = _open(fname, _O_WRONLY|_O_CREAT|_O_EXCL|_O_BINARY, _S_IREAD|_S_IWRITE);
#else
  int fd = open(fname, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600);
#endif
  if(fd < 0) {
    err << clear << "Cannot create " << fname << " (it must not exist yet)";
    return -1;
  }
  gxString &s = (gxString &)secret;
  int ok = fc_write_fd(fd, s.c_str(), s.length()) && fc_write_fd(fd, "\n", 1);
#if !defined (__WIN32__)
  if(ok && fsync(fd) != 0) ok = 0;
#endif
  fc_close_fd(fd);
  if(!ok) {
    futils_remove(fname);
    err << clear << "Error writing " << fname;
    return -1;
  }
  return 0;
}

int FC_write_secret_fd(const char *fd_str, const gxString &secret, gxString &err)
{
  int fd = -1;
  if(!FC_parse_fd(fd_str, &fd) || fd == 0) {
    err << clear << "Invalid file descriptor " << (fd_str ? fd_str : "");
    return -1;
  }
  gxString &s = (gxString &)secret;
  if(!fc_write_fd(fd, s.c_str(), s.length()) || !fc_write_fd(fd, "\n", 1)) {
    err << clear << "Cannot write to file descriptor " << fd;
    return -1;
  }
  return 0;
}

gxString FC_abs_path(const char *fname)
{
  gxString path(fname);
#if defined (__WIN32__)
  char buf[MAX_PATH*2];
  DWORD n = GetFullPathNameA(fname, sizeof(buf), buf, 0);
  if(n > 0 && n < sizeof(buf)) path = buf;
#else
  if(fname && fname[0] != '/') {
    char cwd[futils_MAX_DIR_LENGTH];
    if(futils_getcwd(cwd, sizeof(cwd)) == 0) {
      path.Clear();
      path << cwd << "/" << fname;
    }
  }
#endif
  return path;
}

// ----------------------------------------------------------- //
// Version check
// ----------------------------------------------------------- //
static unsigned fc_le32(const unsigned char *p)
{
  return (unsigned)p[0] | ((unsigned)p[1] << 8) | ((unsigned)p[2] << 16) | ((unsigned)p[3] << 24);
}

int FC_check_version(const char *fname, FCVersionInfo &info, gxString &err)
{
  info = FCVersionInfo();
  FILE *fp = fopen(fname, "rb");
  if(!fp) {
    err << clear << "Cannot open " << fname;
    return -1;
  }
  unsigned char hdr[256];
  memset(hdr, 0, sizeof(hdr));
  size_t n = fread(hdr, 1, sizeof(hdr), fp);
  // fcrypt 2026102: the magic of fcfile.cpp
  static const unsigned char fc_magic[8] = { 'F', 'C', 'R', 'Y', 'P', 'T', 0x1A, 0x04 };
  if(n >= 8 && memcmp(hdr, fc_magic, 8) == 0) {
    fclose(fp);
    info.kind = FC_KIND_FCRYPT;
    info.format = 2;
    info.version << clear << "fcrypt v2 (file format " << fc_le32(hdr+8) << ")";
    return 0;
  }
  // fcrypt 2023102 and 2023103: StaticDataHeader, version 2023103 and
  // the 0xABAB start checkword
  if(n >= 8 && fc_le32(hdr) == 2023103 && fc_le32(hdr+4) == 0xABAB) {
    fclose(fp);
    info.kind = FC_KIND_FCRYPT;
    info.format = 1;
    info.is_v1 = 1;
    info.version = "fcrypt v1 (file format 2023102 or 2023103)";
    info.upgrade << clear << "fmigrate " << fname;
    return 0;
  }
  // EPDB data file: a DataReel gxDatabase with the EPDB v2 header in the
  // config static area, see EPDB db_auth.h (EPDB_V2_HEADER_OFFSET 49152)
  const unsigned sig_off = (unsigned)((char *)&((gxFileHeader *)0)->gxd_sig - (char *)0);
  if(n >= sig_off + 7 && memcmp(hdr + sig_off, "GXDBASE", 7) == 0) {
    fclose(fp);
    // The DataReel file header size depends on the revision letter
    unsigned char v2[8];
    memset(v2, 0, sizeof(v2));
    int got = 0;
    gxDatabase db;
    if(db.Open(fname, gxDBASE_READONLY) == gxDBASE_NO_ERROR) {
      got = db.Read(v2, sizeof(v2), (FAU_t)db.FileHeaderSize() + 49152) == gxDBASE_NO_ERROR;
      db.Close();
    }
    static const unsigned char epdb_magic[8] = { 'E', 'P', 'D', 'B', 'V', '2', 0x1A, 0x01 };
    gxString name(fname);
    int is_ehd = name.length() > 4 && CaseICmp(gxString(name.c_str() + name.length() - 4), ".ehd") == 0;
    if(got && memcmp(v2, epdb_magic, 8) == 0) {
      info.kind = FC_KIND_EPDB;
      info.format = 2;
      info.version = "EPDB v2 (database format 2026103)";
      return 0;
    }
    if(!is_ehd) {
      err << clear << fname << " is a DataReel database file, not an encrypted password database (.ehd)";
      return 1;
    }
    info.kind = FC_KIND_EPDB;
    info.format = 1;
    info.is_v1 = 1;
    info.version = "EPDB v1 (database format before 2026.101)";
    info.upgrade << clear << "epdb_auth_tool --upgrade-db " << fname;
    return 0;
  }
  fclose(fp);
  err << clear << fname << " is not an fcrypt encrypted file or an encrypted password database";
  return 1;
}

gxString FC_v1_warning(const char *fname, const FCVersionInfo &info)
{
  gxString s;
  s << "WARNING: " << fname << " uses " << info.version
    << ", which has a weaker key derivation and no integrity check over the whole file. ";
  if(info.kind == FC_KIND_EPDB) {
    s << "Upgrade it with: " << info.upgrade << " (the v1 files are kept as a backup)";
  }
  else {
    s << "Convert it with: " << info.upgrade;
  }
  return s;
}

// ----------------------------------------------------------- //
// Access log
// ----------------------------------------------------------- //
gxString FC_hex(const unsigned char *buf, unsigned len)
{
  const char *hex = "0123456789abcdef";
  gxString s;
  for(unsigned i = 0; i < len; i++) s << hex[(buf[i] >> 4) & 0xF] << hex[buf[i] & 0xF];
  return s;
}

static int fc_unhex(const char *s, unsigned char *out, unsigned len)
{
  if(strlen(s) != len*2) return 0;
  for(unsigned i = 0; i < len; i++) {
    int v = 0;
    for(int j = 0; j < 2; j++) {
      char c = s[i*2+j];
      v <<= 4;
      if(c >= '0' && c <= '9') v |= c - '0';
      else if(c >= 'a' && c <= 'f') v |= c - 'a' + 10;
      else if(c >= 'A' && c <= 'F') v |= c - 'A' + 10;
      else return 0;
    }
    out[i] = (unsigned char)v;
  }
  return 1;
}

int FC_log_key(const unsigned char *master, unsigned master_len,
	       const unsigned char *id, unsigned id_len, unsigned char key[FC_LOG_KEY_LEN])
{
  if(!master || master_len != FC_KEY_LEN) return 0;
  return FC_kbkdf_sha256(master, FC_LABEL_LOG, id, id_len, key);
}

gxString FC_os_user()
{
  gxString s;
#if defined (__WIN32__)
  const char *u = getenv("USERNAME");
  if(u) s = u;
#else
  struct passwd *pw = getpwuid(geteuid());
  if(pw && pw->pw_name) s = pw->pw_name;
  else if(getenv("USER")) s = getenv("USER");
#endif
  if(s.is_null()) s = "unknown";
  return s;
}

gxString FC_host_name()
{
  gxString s;
#if defined (__WIN32__)
  char buf[MAX_COMPUTERNAME_LENGTH + 1];
  DWORD n = sizeof(buf);
  if(GetComputerNameA(buf, &n)) s.SetString(buf, n);
#else
  char buf[256];
  memset(buf, 0, sizeof(buf));
  if(gethostname(buf, sizeof(buf)-1) == 0) s = buf;
#endif
  if(s.is_null()) s = "unknown";
  return s;
}

gxString FC_default_log_file(const char *app_dir)
{
  gxString home;
#if defined (__WIN32__)
  if(getenv("USERPROFILE")) home = getenv("USERPROFILE");
  const char *sep = "\\";
#else
  if(getenv("HOME")) home = getenv("HOME");
  else {
    struct passwd *pw = getpwuid(geteuid());
    if(pw && pw->pw_dir) home = pw->pw_dir;
  }
  const char *sep = "/";
#endif
  if(home.is_null()) return home;
  gxString dir;
  dir << home << sep << app_dir;
  if(!futils_exists(dir.c_str())) {
#if defined (__WIN32__)
    futils_mkdir(dir.c_str());
#else
    mkdir(dir.c_str(), 0700);
#endif
  }
  dir << sep << "logs";
  if(!futils_exists(dir.c_str())) {
#if defined (__WIN32__)
    futils_mkdir(dir.c_str());
#else
    mkdir(dir.c_str(), 0700);
#endif
  }
  gxString f;
  f << dir << sep << "access.log";
  return f;
}

static void fc_log_escape(gxString &out, const gxString &in_value)
{
  gxString &v = (gxString &)in_value;
  if(v.is_null()) {
    out << "-";
    return;
  }
  const char *p = v.c_str();
  for(unsigned i = 0; i < v.length(); i++) {
    char c = p[i];
    if(c == '\\') out << "\\\\";
    else if(c == '\t') out << "\\t";
    else if(c == '\r') out << "\\r";
    else if(c == '\n') out << "\\n";
    else if((unsigned char)c < 32) out << "?";
    else out << c;
  }
}

static gxString fc_log_line_body(const FCLogEntry &e)
// The line up to, not including, the tab before mac=
{
  char stamp[32];
  time_t now = time(0);
  struct tm *t = gmtime(&now);
  strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%SZ", t);
  gxString s, pid;
#if defined (__WIN32__)
  pid << (unsigned long)_getpid();
#else
  pid << (unsigned long)getpid();
#endif
  s << FC_LOG_MAGIC;
  s << "\ttime=" << stamp;
  s << "\tuser="; fc_log_escape(s, FC_os_user());
  s << "\thost="; fc_log_escape(s, FC_host_name());
  s << "\tpid=" << pid;
  s << "\ttool="; fc_log_escape(s, e.tool);
  s << "\tfile="; fc_log_escape(s, e.file);
  s << "\tid="; fc_log_escape(s, e.id);
  s << "\tauth="; fc_log_escape(s, e.auth);
  s << "\tslot="; fc_log_escape(s, e.slot);
  s << "\taction="; fc_log_escape(s, e.action);
  s << "\trecord="; fc_log_escape(s, e.record);
  s << "\tresult=" << (e.ok ? "ok" : "fail");
  s << "\tdetail="; fc_log_escape(s, e.detail);
  return s;
}

struct FCLogLine {
  gxString body;  // Up to the tab before mac=
  gxString id;
  gxString mac;   // Hex or "-"
  int ok;         // 1 if the line parses
};

static void fc_log_parse_line(const gxString &line_in, FCLogLine &l)
{
  gxString &line = (gxString &)line_in;
  l.ok = 0;
  l.body.Clear(); l.id.Clear(); l.mac.Clear();
  int m = FC_find_last(line.c_str(), "\tmac=");
  if(m < 0 || line.Find(FC_LOG_MAGIC) != 0) return;
  l.body.SetString(line.c_str(), (unsigned)m);
  l.mac = line.c_str() + m + 5;
  int i = line.Find("\tid=");
  if(i < 0 || i > m) return;
  const char *p = line.c_str() + i + 4;
  const char *q = strchr(p, '\t');
  if(!q) return;
  l.id.SetString(p, (unsigned)(q - p));
  l.ok = 1;
}

static int fc_log_read_lines(int fd, gxList<gxString> &lines, gxString &err)
{
  MemoryBuffer data;
#if defined (__WIN32__)
  _lseek(fd, 0, SEEK_SET);
#else
  lseek(fd, 0, SEEK_SET);
#endif
  char buf[65536];
  for(;;) {
    int n = fc_read_fd(fd, buf, sizeof(buf));
    if(n < 0) {
      err << clear << "Cannot read the access log";
      return -1;
    }
    if(n == 0) break;
    data.Cat(buf, (unsigned)n);
  }
  const char *p = (const char *)data.m_buf();
  unsigned len = data.length(), pos = 0;
  while(pos < len) {
    unsigned start = pos;
    while(pos < len && p[pos] != '\n') pos++;
    gxString s;
    s.SetString(p+start, pos-start);
    lines.Add(s);
    if(pos < len) pos++;
  }
  return 0;
}

static int fc_log_tag(const unsigned char key[FC_LOG_KEY_LEN], const unsigned char prev[FC_LOG_TAG_LEN],
		      const MemoryBuffer &pending, const gxString &body, unsigned char tag[FC_LOG_TAG_LEN])
{
  MemoryBuffer &pend = (MemoryBuffer &)pending;
  gxString &b = (gxString &)body;
  AES_hmac_ctx *h = AES_hmac_new(key, FC_LOG_KEY_LEN);
  int ok = h && AES_hmac_update(h, prev, FC_LOG_TAG_LEN);
  if(ok && pend.length()) ok = AES_hmac_update(h, (const unsigned char *)pend.m_buf(), pend.length());
  if(ok) ok = AES_hmac_update(h, (const unsigned char *)b.c_str(), b.length());
  if(ok) ok = AES_hmac_final(h, tag, FC_LOG_TAG_LEN);
  if(h) AES_hmac_free(h);
  return ok;
}

static int fc_log_chain_state(gxList<gxString> &lines, const gxString &id,
			      unsigned char prev[FC_LOG_TAG_LEN], MemoryBuffer &pending)
// The last tag of an ID and the untagged lines after it
{
  memset(prev, 0, FC_LOG_TAG_LEN);
  pending.Clear();
  gxListNode<gxString> *p = lines.GetHead();
  while(p) {
    FCLogLine l;
    fc_log_parse_line(p->data, l);
    if(l.ok && l.id == id) {
      if(l.mac == "-") {
	pending.Cat(p->data.c_str(), p->data.length());
	pending.Cat("\n", 1);
      }
      else if(fc_unhex(l.mac.c_str(), prev, FC_LOG_TAG_LEN)) {
	pending.Clear();
      }
    }
    p = p->next;
  }
  return 1;
}

static int fc_lock_fd(int fd, int lock)
{
#if defined (__WIN32__)
  HANDLE h = (HANDLE)_get_osfhandle(fd);
  OVERLAPPED ov;
  memset(&ov, 0, sizeof(ov));
  if(lock) return LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK, 0, 0xFFFFFFFF, 0xFFFFFFFF, &ov) ? 0 : -1;
  return UnlockFileEx(h, 0, 0xFFFFFFFF, 0xFFFFFFFF, &ov) ? 0 : -1;
#else
  return flock(fd, lock ? LOCK_EX : LOCK_UN);
#endif
}

static int fc_log_open(const char *log_file, gxString &err)
{
#if defined (__WIN32__)
  int fd = _open(log_file, _O_RDWR|_O_CREAT|_O_APPEND|_O_BINARY, _S_IREAD|_S_IWRITE);
#else
  int fd = open(log_file, O_RDWR|O_CREAT|O_APPEND|O_NOFOLLOW|O_CLOEXEC, 0600);
#endif
  if(fd < 0) err << clear << "Cannot open the access log " << log_file;
  return fd;
}

int FC_log_append(const char *log_file, const FCLogEntry &entry,
		  const unsigned char *key, gxString &err)
{
  err.Clear();
  if(!log_file || !*log_file) {
    err << clear << "No access log file name";
    return -1;
  }
  int fd = fc_log_open(log_file, err);
  if(fd < 0) return -1;
  if(fc_lock_fd(fd, 1) != 0) {
    fc_close_fd(fd);
    err << clear << "Cannot lock the access log " << log_file;
    return -1;
  }
  gxString body = fc_log_line_body(entry);
  gxString line = body;
  int rv = 0;
  gxString id = entry.id.is_null() ? gxString("-") : entry.id;
  if(key && id != "-") {
    gxList<gxString> lines;
    unsigned char prev[FC_LOG_TAG_LEN], tag[FC_LOG_TAG_LEN];
    MemoryBuffer pending;
    if(fc_log_read_lines(fd, lines, err) != 0) rv = -1;
    if(rv == 0) {
      fc_log_chain_state(lines, id, prev, pending);
      if(!fc_log_tag(key, prev, pending, body, tag)) {
	err << clear << "Cannot compute the access log tag";
	rv = -1;
      }
    }
    if(rv == 0) line << "\tmac=" << FC_hex(tag, sizeof(tag));
  }
  else {
    line << "\tmac=-";
  }
  line << "\n";
  if(rv == 0 && !fc_write_fd(fd, line.c_str(), line.length())) {
    err << clear << "Cannot write to the access log " << log_file;
    rv = -1;
  }
#if !defined (__WIN32__)
  if(rv == 0) fsync(fd);
#endif
  fc_lock_fd(fd, 0);
  fc_close_fd(fd);
  return rv;
}

static int fc_log_verify_lines(gxList<gxString> &lines, const gxString &id,
			       const unsigned char key[FC_LOG_KEY_LEN], FCLogVerifyResult &r)
{
  unsigned char prev[FC_LOG_TAG_LEN], tag[FC_LOG_TAG_LEN], stored[FC_LOG_TAG_LEN];
  memset(prev, 0, sizeof(prev));
  MemoryBuffer pending;
  unsigned pending_lines = 0, n = 0;
  gxListNode<gxString> *p = lines.GetHead();
  while(p) {
    n++;
    r.lines++;
    if(p->data.is_null()) { p = p->next; continue; }
    FCLogLine l;
    fc_log_parse_line(p->data, l);
    if(!l.ok) {
      r.bad_lines++;
      if(!r.first_bad_line) {
	r.first_bad_line = n;
	r.first_bad_reason = "line is not an FCLOG1 entry";
      }
      p = p->next;
      continue;
    }
    if(l.id != id) { p = p->next; continue; }
    r.id_lines++;
    if(l.mac == "-") {
      pending.Cat(p->data.c_str(), p->data.length());
      pending.Cat("\n", 1);
      pending_lines++;
      p = p->next;
      continue;
    }
    int good = fc_unhex(l.mac.c_str(), stored, sizeof(stored)) &&
      fc_log_tag(key, prev, pending, l.body, tag) &&
      CRYPTO_memcmp(tag, stored, sizeof(tag)) == 0;
    if(good) {
      r.tagged++;
      r.untagged_covered += pending_lines;
    }
    else {
      r.bad_lines++;
      if(!r.first_bad_line) {
	r.first_bad_line = n;
	r.first_bad_reason = "tag does not match: this line or an earlier line of this file was changed, removed or inserted";
      }
    }
    // Continue from the stored tag, so later lines can still be checked
    if(fc_unhex(l.mac.c_str(), stored, sizeof(stored))) memmove(prev, stored, sizeof(prev));
    pending.Clear();
    pending_lines = 0;
    p = p->next;
  }
  r.trailing_untagged = pending_lines;
  return r.bad_lines ? 1 : 0;
}

int FC_log_verify(const char *log_file, const char *id, const unsigned char key[FC_LOG_KEY_LEN],
		  FCLogVerifyResult &result, gxString &err)
{
  result = FCLogVerifyResult();
#if defined (__WIN32__)
  int fd = _open(log_file, _O_RDONLY|_O_BINARY);
#else
  int fd = open(log_file, O_RDONLY|O_CLOEXEC);
#endif
  if(fd < 0) {
    err << clear << "Cannot open the access log " << log_file;
    return -1;
  }
  gxList<gxString> lines;
  int rv = fc_log_read_lines(fd, lines, err);
  fc_close_fd(fd);
  if(rv != 0) return -1;
  return fc_log_verify_lines(lines, gxString(id), key, result);
}

int FC_log_rekey(const char *log_file, const char *old_id, const unsigned char old_key[FC_LOG_KEY_LEN],
		 const char *new_id, const unsigned char new_key[FC_LOG_KEY_LEN],
		 gxString &backup_file, gxString &err)
{
  backup_file.Clear();
  err.Clear();
  if(!futils_exists(log_file)) return 0;
  int fd = fc_log_open(log_file, err);
  if(fd < 0) return -1;
  if(fc_lock_fd(fd, 1) != 0) {
    fc_close_fd(fd);
    err << clear << "Cannot lock the access log " << log_file;
    return -1;
  }
  gxList<gxString> lines;
  int rv = fc_log_read_lines(fd, lines, err);
  FCLogVerifyResult r;
  gxString oid(old_id), nid(new_id);
  if(rv == 0) rv = fc_log_verify_lines(lines, oid, old_key, r) == 0 ? 0 : 1;
  if(rv == 1) {
    // Keep the log that does not verify as evidence and start a new one
    err << clear << "The access log lines for this file did not verify (line " << r.first_bad_line
	<< ": " << r.first_bad_reason << ")";
    fc_lock_fd(fd, 0);
    fc_close_fd(fd);
    backup_file = FC_backup_name(log_file, "rekey", ".log");
    gxString e2;
    if(FC_replace_file(log_file, backup_file.c_str(), e2) != 0) {
      err << ". " << e2;
      return -1;
    }
    return 1;
  }
  if(rv < 0) {
    fc_lock_fd(fd, 0);
    fc_close_fd(fd);
    return -1;
  }
  // Rewrite: lines of the old ID move to the new ID and are tagged with
  // the new key, in the same order. Other lines are copied as they are.
  gxString tmp;
  tmp << log_file << ".rekey.tmp";
  futils_remove(tmp.c_str());
#if defined (__WIN32__)
  int out = _open(tmp.c_str(), _O_WRONLY|_O_CREAT|_O_EXCL|_O_BINARY, _S_IREAD|_S_IWRITE);
#else
  int out = open(tmp.c_str(), O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600);
#endif
  if(out < 0) {
    fc_lock_fd(fd, 0);
    fc_close_fd(fd);
    err << clear << "Cannot create " << tmp;
    return -1;
  }
  unsigned char prev[FC_LOG_TAG_LEN], tag[FC_LOG_TAG_LEN];
  memset(prev, 0, sizeof(prev));
  MemoryBuffer pending;
  int ok = 1;
  gxString idfield_old, idfield_new;
  idfield_old << "\tid=" << oid << "\t";
  idfield_new << "\tid=" << nid << "\t";
  gxListNode<gxString> *p = lines.GetHead();
  while(p && ok) {
    gxString line = p->data;
    FCLogLine l;
    fc_log_parse_line(line, l);
    if(l.ok && l.id == oid) {
      gxString body = l.body;
      body.ReplaceString(idfield_old.c_str(), idfield_new.c_str());
      if(l.mac == "-") {
	line = body;
	line << "\tmac=-";
	pending.Cat(line.c_str(), line.length());
	pending.Cat("\n", 1);
      }
      else {
	ok = fc_log_tag(new_key, prev, pending, body, tag);
	memmove(prev, tag, sizeof(prev));
	pending.Clear();
	line = body;
	line << "\tmac=" << FC_hex(tag, sizeof(tag));
      }
    }
    if(ok && !p->data.is_null()) {
      line << "\n";
      ok = fc_write_fd(out, line.c_str(), line.length());
    }
    p = p->next;
  }
  fc_close_fd(out);
  if(ok) ok = FC_replace_file(tmp.c_str(), log_file, err) == 0;
  else err << clear << "Error writing " << tmp;
  if(!ok) futils_remove(tmp.c_str());
  fc_lock_fd(fd, 0);
  fc_close_fd(fd);
  return ok ? 0 : -1;
}


// ----------------------------------------------------------- //
// In-file access log ring
// ----------------------------------------------------------- //
static const unsigned char FC_RING_MAGIC[8] = { 'F', 'C', 'R', 'I', 'N', 'G', '0', '1' };
static const char *FC_LABEL_RING_ENC = "FCRING01 encryption";
static const char *FC_LABEL_RING_MAC = "FCRING01 MAC";

static const char *fc_action_names[FC_ACTION_LAST] = {
  "-", "open", "add-record", "update-record", "delete-record", "add-user",
  "remove-user", "rekey", "upgrade", "access-log-on", "access-log-off"
};
static const char *fc_auth_names[FC_AUTH_LAST] = {
  "none", "password", "key-file", "rsa-key", "smartcard"
};

const char *FC_action_name(int code)
{
  return (code >= 0 && code < FC_ACTION_LAST) ? fc_action_names[code] : "unknown";
}

int FC_action_code(const char *name)
{
  for(int i = 0; name && i < FC_ACTION_LAST; i++) if(strcmp(name, fc_action_names[i]) == 0) return i;
  return FC_ACTION_NONE;
}

const char *FC_auth_name(int code)
{
  return (code >= 0 && code < FC_AUTH_LAST) ? fc_auth_names[code] : "unknown";
}

int FC_auth_code(const char *name)
{
  for(int i = 0; name && i < FC_AUTH_LAST; i++) if(strcmp(name, fc_auth_names[i]) == 0) return i;
  return FC_AUTH_NONE;
}

static void fc_put32le(unsigned char *p, unsigned v)
{
  for(int i = 0; i < 4; i++) p[i] = (unsigned char)((v >> (8*i)) & 0xFF);
}

static void fc_put64le(unsigned char *p, unsigned long long v)
{
  for(int i = 0; i < 8; i++) p[i] = (unsigned char)((v >> (8*i)) & 0xFF);
}

static unsigned long long fc_le64(const unsigned char *p)
{
  unsigned long long v = 0;
  for(int i = 7; i >= 0; i--) v = (v << 8) | p[i];
  return v;
}

struct FCRingKeys {
  FCRingKeys() { memset(enc, 0, sizeof(enc)); memset(mac, 0, sizeof(mac)); }
  ~FCRingKeys() { OPENSSL_cleanse(enc, sizeof(enc)); OPENSSL_cleanse(mac, sizeof(mac)); }
  unsigned char enc[32];
  unsigned char mac[32];
};

static int fc_ring_keys(const unsigned char master[32], const unsigned char *id, unsigned id_len, FCRingKeys &k)
{
  return FC_kbkdf_sha256(master, FC_LABEL_RING_ENC, id, id_len, k.enc) &&
    FC_kbkdf_sha256(master, FC_LABEL_RING_MAC, id, id_len, k.mac);
}

static int fc_ring_hmac(const unsigned char key[32], const char *label,
			const unsigned char *id, unsigned id_len,
			const unsigned char *a, unsigned a_len,
			const unsigned char *b, unsigned b_len, unsigned char out[32])
{
  AES_hmac_ctx *h = AES_hmac_new(key, 32);
  int ok = h && AES_hmac_update(h, (const unsigned char *)label, strlen(label) + 1) &&
    AES_hmac_update(h, id, id_len);
  if(ok && a_len) ok = AES_hmac_update(h, a, a_len);
  if(ok && b_len) ok = AES_hmac_update(h, b, b_len);
  if(ok) ok = AES_hmac_final(h, out, 32);
  if(h) AES_hmac_free(h);
  return ok;
}

unsigned FC_ring_size(unsigned n)
{
  return FC_RING_HDR_LEN + n * FC_RING_ENTRY_LEN;
}

static int fc_ring_seal_header(unsigned char *ring, const FCRingKeys &k, const unsigned char *id, unsigned id_len)
{
  return fc_ring_hmac(k.mac, "header", id, id_len, ring, 32, 0, 0, ring + 32);
}

static int fc_ring_check_header(const unsigned char *ring, unsigned ring_len, const FCRingKeys &k,
				const unsigned char *id, unsigned id_len, unsigned &n, gxString &err)
{
  if(ring_len < FC_RING_HDR_LEN || memcmp(ring, FC_RING_MAGIC, 8) != 0) {
    err << clear << "The in-file access log is not set up";
    return -1;
  }
  unsigned char tag[32];
  if(!fc_ring_hmac(k.mac, "header", id, id_len, ring, 32, 0, 0, tag) ||
     CRYPTO_memcmp(tag, ring + 32, 32) != 0) {
    err << clear << "The in-file access log header does not verify (changed outside this program or by another key)";
    return 0;
  }
  n = fc_le32(ring + 12);
  if(fc_le32(ring + 8) != FC_RING_ENTRY_LEN || n == 0 || FC_ring_size(n) > ring_len ||
     fc_le32(ring + 16) >= n) {
    err << clear << "The in-file access log header is damaged";
    return 0;
  }
  return 1;
}

int FC_ring_init(unsigned char *ring, unsigned ring_len, const unsigned char master[32],
		 const unsigned char *id, unsigned id_len)
{
  if(ring_len < FC_ring_size(1)) return 0;
  unsigned n = (ring_len - FC_RING_HDR_LEN) / FC_RING_ENTRY_LEN;
  FCRingKeys k;
  if(!fc_ring_keys(master, id, id_len, k)) return 0;
  memset(ring, 0, ring_len);
  memmove(ring, FC_RING_MAGIC, 8);
  fc_put32le(ring + 8, FC_RING_ENTRY_LEN);
  fc_put32le(ring + 12, n);
  fc_put32le(ring + 16, 0);
  fc_put64le(ring + 24, 0);
  return fc_ring_seal_header(ring, k, id, id_len);
}

void FC_ring_slot_hash(const unsigned char master[32], const unsigned char *id, unsigned id_len,
		       const char *username, unsigned char hash[8])
{
  memset(hash, 0, 8);
  if(!username || !*username) return;
  FCRingKeys k;
  unsigned char out[32];
  if(fc_ring_keys(master, id, id_len, k) &&
     fc_ring_hmac(k.mac, "slot", id, id_len, (const unsigned char *)username, strlen(username), 0, 0, out)) {
    memmove(hash, out, 8);
  }
  OPENSSL_cleanse(out, sizeof(out));
}

static int fc_ring_write_entry(unsigned char *ring, const FCRingKeys &k, const unsigned char *id, unsigned id_len,
			       unsigned index, const unsigned char plain[FC_RING_PLAIN_LEN])
{
  unsigned char *e = ring + FC_RING_HDR_LEN + index * FC_RING_ENTRY_LEN;
  unsigned char ix[4];
  unsigned ct_len = 0;
  fc_put32le(ix, index);
  if(!FC_rand_bytes(e, 16, 0)) return 0;
  if(!FC_aes256_cbc(1, k.enc, e, plain, FC_RING_PLAIN_LEN, e + 16, &ct_len) || ct_len != 48) return 0;
  return fc_ring_hmac(k.mac, "entry", id, id_len, ix, 4, e, 64, e + 64);
}

int FC_ring_append(unsigned char *ring, unsigned ring_len, const unsigned char master[32],
		   const unsigned char *id, unsigned id_len, const FCRingEntry &entry,
		   const char *slot_username, gxString &err)
{
  FCRingKeys k;
  unsigned n = 0;
  if(!fc_ring_keys(master, id, id_len, k)) {
    err << clear << "Cannot derive the access log keys";
    return 0;
  }
  if(fc_ring_check_header(ring, ring_len, k, id, id_len, n, err) != 1) return 0;
  unsigned next = fc_le32(ring + 16);
  unsigned long long written = fc_le64(ring + 24);
  unsigned char plain[FC_RING_PLAIN_LEN];
  memset(plain, 0, sizeof(plain));
  fc_put64le(plain, written + 1);
  fc_put64le(plain + 8, entry.when ? entry.when : (unsigned long long)time(0));
  plain[16] = (unsigned char)entry.action;
  plain[17] = (unsigned char)entry.auth;
  plain[18] = (unsigned char)(entry.result ? 1 : 0);
  plain[19] = (unsigned char)entry.flags;
  FC_ring_slot_hash(master, id, id_len, slot_username, plain + 20);
  int ok = fc_ring_write_entry(ring, k, id, id_len, next, plain);
  OPENSSL_cleanse(plain, sizeof(plain));
  if(!ok) {
    err << clear << "Cannot write the in-file access log entry";
    return 0;
  }
  fc_put32le(ring + 16, (next + 1) % n);
  fc_put64le(ring + 24, written + 1);
  return fc_ring_seal_header(ring, k, id, id_len);
}

int FC_ring_read(const unsigned char *ring, unsigned ring_len, const unsigned char master[32],
		 const unsigned char *id, unsigned id_len, gxList<FCRingEntry> &entries,
		 unsigned long long &written, gxString &err)
{
  entries.ClearList();
  written = 0;
  FCRingKeys k;
  unsigned n = 0;
  if(!fc_ring_keys(master, id, id_len, k)) {
    err << clear << "Cannot derive the access log keys";
    return -1;
  }
  int hrv = fc_ring_check_header(ring, ring_len, k, id, id_len, n, err);
  if(hrv < 0) return -1;
  if(hrv == 0) return 1;
  written = fc_le64(ring + 24);
  unsigned next = fc_le32(ring + 16);
  unsigned count = written < n ? (unsigned)written : n;
  unsigned start = (written < n) ? 0 : next;
  unsigned long long expect = written - count + 1;
  int bad = 0;
  for(unsigned j = 0; j < count; j++) {
    unsigned index = (start + j) % n;
    const unsigned char *e = ring + FC_RING_HDR_LEN + index * FC_RING_ENTRY_LEN;
    unsigned char ix[4], tag[32], plain[64];
    unsigned plain_len = 0;
    fc_put32le(ix, index);
    if(!fc_ring_hmac(k.mac, "entry", id, id_len, ix, 4, e, 64, tag) || CRYPTO_memcmp(tag, e + 64, 32) != 0 ||
       !FC_aes256_cbc(0, k.enc, e, e + 16, 48, plain, &plain_len) || plain_len != FC_RING_PLAIN_LEN) {
      if(!bad) err << clear << "In-file access log entry " << index << " does not verify";
      bad = 1;
      continue;
    }
    FCRingEntry r;
    r.seq = fc_le64(plain);
    r.when = fc_le64(plain + 8);
    r.action = plain[16];
    r.auth = plain[17];
    r.result = plain[18];
    r.flags = plain[19];
    memmove(r.slot_hash, plain + 20, 8);
    r.index = index;
    OPENSSL_cleanse(plain, sizeof(plain));
    if(r.seq != expect) {
      if(!bad) err << clear << "In-file access log entry " << index << " is out of sequence (an entry was replaced or rolled back)";
      bad = 1;
    }
    expect = r.seq + 1;
    entries.Add(r);
  }
  return bad ? 1 : 0;
}

int FC_ring_rekey(unsigned char *ring, unsigned ring_len,
		  const unsigned char old_master[32], const unsigned char *old_id, unsigned old_id_len,
		  const unsigned char new_master[32], const unsigned char *new_id, unsigned new_id_len,
		  gxString &err)
{
  FCRingKeys ok_keys, nk;
  unsigned n = 0;
  if(!fc_ring_keys(old_master, old_id, old_id_len, ok_keys) || !fc_ring_keys(new_master, new_id, new_id_len, nk)) {
    err << clear << "Cannot derive the access log keys";
    return 0;
  }
  if(fc_ring_check_header(ring, ring_len, ok_keys, old_id, old_id_len, n, err) != 1) return 0;
  unsigned long long written = fc_le64(ring + 24);
  unsigned count = written < n ? (unsigned)written : n;
  for(unsigned index = 0; index < n && index < count; index++) {
    unsigned char *e = ring + FC_RING_HDR_LEN + index * FC_RING_ENTRY_LEN;
    unsigned char ix[4], tag[32], plain[64];
    unsigned plain_len = 0;
    fc_put32le(ix, index);
    if(!fc_ring_hmac(ok_keys.mac, "entry", old_id, old_id_len, ix, 4, e, 64, tag) || CRYPTO_memcmp(tag, e + 64, 32) != 0 ||
       !FC_aes256_cbc(0, ok_keys.enc, e, e + 16, 48, plain, &plain_len) || plain_len != FC_RING_PLAIN_LEN) {
      err << clear << "In-file access log entry " << index << " does not verify, the log was not carried over";
      OPENSSL_cleanse(plain, sizeof(plain));
      return 0;
    }
    // Slot hashes are keyed, so carry them over under the new key is
    // not possible without the names: they keep the old key's hash and
    // the flags bit 0x80 marks them as from before the rekey.
    plain[19] |= 0x80;
    int wok = fc_ring_write_entry(ring, nk, new_id, new_id_len, index, plain);
    OPENSSL_cleanse(plain, sizeof(plain));
    if(!wok) {
      err << clear << "Cannot re-encrypt the in-file access log";
      return 0;
    }
  }
  return fc_ring_seal_header(ring, nk, new_id, new_id_len);
}

// ----------------------------------------------------------- //
// Self-destruct control block
// ----------------------------------------------------------- //
static const unsigned char FC_CTL_MAGIC[8] = { 'E', 'P', 'D', 'B', 'C', 'T', 'L', '1' };

int FC_ctl_read(const unsigned char *buf, FCControlBlock &c)
{
  c = FCControlBlock();
  if(memcmp(buf, FC_CTL_MAGIC, 8) != 0) return 0;
  c.failed = fc_le32(buf + 8);
  c.limit = fc_le32(buf + 12);
  c.flags = fc_le32(buf + 16);
  c.destroyed = fc_le32(buf + 20);
  c.destroyed_time = fc_le64(buf + 24);
  if(c.limit < 1 || c.limit > FC_SD_MAX_ATTEMPTS) c.limit = FC_SD_DEFAULT_ATTEMPTS;
  return 1;
}

void FC_ctl_write(unsigned char *buf, const FCControlBlock &c)
{
  memset(buf, 0, FC_CTL_LEN);
  memmove(buf, FC_CTL_MAGIC, 8);
  fc_put32le(buf + 8, c.failed);
  fc_put32le(buf + 12, c.limit);
  fc_put32le(buf + 16, c.flags);
  fc_put32le(buf + 20, c.destroyed);
  fc_put64le(buf + 24, c.destroyed_time);
}

gxString FC_sd_message(unsigned used, unsigned limit)
{
  gxString s;
  s << used << " of " << limit << " attempts used, the records will be destroyed after " << limit;
  return s;
}

int FC_shred_range(FILE *fp, FAU_t offset, FAU_t len)
{
  unsigned char buf[65536];
  if(fseek(fp, (long)offset, SEEK_SET) != 0) return -1;
  while(len > 0) {
    unsigned n = (len > (FAU_t)sizeof(buf)) ? (unsigned)sizeof(buf) : (unsigned)len;
    if(!FC_rand_bytes(buf, n, 0)) return -1;
    if(fwrite(buf, 1, n, fp) != n) return -1;
    len -= n;
  }
  return fflush(fp) == 0 ? 0 : -1;
}

int FC_secure_delete(const char *fname, gxString &err)
{
  FILE *fp = fopen(fname, "r+b");
  if(!fp) {
    err << clear << "Cannot open " << fname << " to delete it";
    return -1;
  }
  fseek(fp, 0, SEEK_END);
  long len = ftell(fp);
  int rv = (len < 0) ? -1 : FC_shred_range(fp, 0, (FAU_t)len);
  fclose(fp);
  if(rv == 0) FC_fsync_file(fname);
  if(futils_remove(fname) != 0) rv = -1;
  if(rv != 0) err << clear << "Cannot securely delete " << fname;
  return rv;
}

int FC_file_writable(const char *fname)
{
#if defined (__WIN32__)
  int fd = _open(fname, _O_RDWR|_O_BINARY);
#else
  int fd = open(fname, O_RDWR|O_CLOEXEC);
#endif
  if(fd < 0) return 0;
  fc_close_fd(fd);
  return 1;
}

// ----------------------------------------------------------- //
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
