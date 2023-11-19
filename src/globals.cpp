// ------------------------------- //
// -------- start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- // 
// C++ Source Code File
// Compiler Used: MSVC, BCC32, GCC, HPUX aCC, SOLARIS CC
// Produced By: DataReel Software Development Team
// File Creation Date: 09/15/2003
// Date Last Modified: 11/16/2023
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

This file contains global definitions for the given project. It                 
was created as an add-on to centralize all the global elements                  
used in throughout the source code.
*/
// ----------------------------------------------------------- // 
#include "gxdlcode.h"

#include "globals.h"
#include "cryptdb.h"

// --------------------------------------------------------------
// Internal variable initialzation
// --------------------------------------------------------------
// NOTE: If the any of the database table or key definitions are 
// changed the affected database will have to rebuild. The table
// definition should not be changed unless it is absolutely necessary 
// to add new field or remove existing fields.
//

// Message database table and key definitions
//
// F# Field Name               RDBMS Type     Field Description
//
// 0  Queue Number             VCHAR          Unique message identifier
// 1  Sender                   VCHAR          Sender's address
// 2  Recipient List           VCHAR          List of recipients
// 3  Subject                  VCHAR          Subject of the message
// 4  Date                     VCHAR          Date in message header  
// 5  Body                     BLOB           Body of the message 
// 6  Reserved1                VCHAR          Reserved for future use
// 7  Reserved2                VCHAR          Reserved for future use
// 8  Reserved3                VCHAR          Reserved for future use
// 9  Reserved4                INT32          Reserved for future use
// 10 Reserved5                INT32          Reserved for future use
//
const char *messages_table_def = "messages,Queue Number{25}VCHAR[15],\
Sender{25}VCHAR[15],Recipient List{25}VCHAR[15],\
Subject{25}VCHAR[15],Date{25}VCHAR[15],Body{0}BLOB[15],\
Reserved1{0}VCHAR[1],Reserved2{0}VCHAR[1],Reserved3{0}VCHAR[1],\
Reserved4{0}INT32,Reserved5{0}INT32";
//
const char *messages_key_def = "PRI: COL 1";

// Unsent messages database table and key definitions
//
// F# Field Name               RDBMS Type     Field Description
//
// 0  Queue Number             VCHAR          Unique message identifier
// 1  Reserved1                VCHAR          Reserved for future use
// 2  Reserved2                VCHAR          Reserved for future use
// 3  Reserved3                VCHAR          Reserved for future use
// 4  Reserved4                INT32          Reserved for future use
// 5  Reserved5                INT32          Reserved for future use
//
const char *unsent_table_def = "unsent,Queue Number{25}VCHAR[15],\
Reserved1{0}VCHAR[1],Reserved2{0}VCHAR[1],Reserved3{0}VCHAR[1],\
Reserved4{0}INT32,Reserved5{0}INT32";
//
const char *unsent_key_def = "PRI: COL 1";

// Password database table and key definitions
//
// F# Field Name               RDBMS Type     Field Description
//
// 0  Username                 VCHAR          Username for this account
// 1  Password                 BINARY         User password
// 2  Group Name               VCHAR          UNIX/WIN32 group name
// 3  Real Name                VCHAR          User?s real name
// 4  User ID                  INT32          UNIX UID
// 5  Group ID                 INT32          UNIX GID
// 6  Shell                    VCHAR          UNIX Shell
// 7  Home DIR                 VCHAR          Users home directory
// 8  Allowed                  VCHAR          Users allow rule
// 9  Denied                   VCHAR          Users deny rule
// 10 Read Only Account        BOOL           User cannot write to server
// 11 Enable Account           BOOL           Enable or disable account
// 12 User Can Change Password BOOL           Allow user to change passwd
// 13 Available hours          VCHAR          Hours account is available
// 14 Available days           VCHAR          Days account is available
// 15 Email Address            VCHAR          User email address
// 16 Contact Information      VCHAR          Snail mail, phone, fax, etc
// 17 Account Description      VCHAR          Brief account comments
// 18 Administrator Name       VCHAR          Admin who made/modified account
// 19 Date Created             INT32          Date account was created
// 20 Date Modified            INT32          Date account was last modified
// 21 Last Login               INT32          Date of last client logon
// 22 Reserved1                VCHAR          Reserved for future use
// 23 Reserved2                VCHAR          Reserved for future use
// 24 Reserved3                VCHAR          Reserved for future use
// 25 Reserved4                INT32          Reserved for future use
// 26 Reserved5                INT32          Reserved for future use
//
const char *passwd_table_def = "unpgdb,Username{25}VCHAR[15],\
Password{25}BINARY[15].P,Group Name{25}VCHAR[15],\
Real Name{25}VCHAR[15],User ID{25}INT32,\
Group ID{25}INT32,Shell{25}VCHAR[15],Home DIR{25}VCHAR[15],\
Allowed{25}VCHAR[15],Denied{25}VCHAR[15],Read Only Account{25}BOOL.Y,\
Enable Account{25}BOOL.Y,User Can Change Password{25}BOOL.Y,\
Available hours{25}VCHAR[15],Available days{25}VCHAR[15],\
Email Address{25}VCHAR[15],Contact Information{24}VCHAR[15],\
Account Description{25}VCHAR[15],Administrator Name{25}VCHAR[15],\
Date Created{25}INT32,Date Modified{25}INT32,Last Login{25}INT32,\
Reserved1{0}VCHAR[1],Reserved2{0}VCHAR[1],Reserved3{0}VCHAR[1],\
Reserved4{0}INT32,Reserved5{0}INT32";
//
const char *passwd_key_def = "PRI: COL 1";
// --------------------------------------------------------------

void gxClientStatsHeader::Reset()
{
  check_word = gxCheckWord;
  hdr_version = 1024;
  login_time = (gxUINT32)0;
  logout_time = (gxUINT32)0;
  current_op_time = (gxUINT32)0;
  last_good_op_time = (gxUINT32)0;
  last_bad_op_time = (gxUINT32)0;
  bytes_received = (FAU)0;
  bytes_transferred = (FAU)0;
  memset(current_op, 0, gxOP_STR_LEN);
  memset(last_good_op, 0, gxOP_STR_LEN);
  memset(last_bad_op, 0, gxOP_STR_LEN);
  memset(hostname, 0,  gxOP_STR_LEN);
  memset(username, 0,  gxOP_STR_LEN);
  memset(client_type, 0,  gxOP_STR_LEN);

  // Reset user profile
  memset(group_name, 0, gxOP_STR_LEN);
  uid = (gxINT32)-1;
  gid = (gxINT32)-1;
  memset(shell, 0, gxOP_NAME_LEN);
  memset(home_dir, 0, gxOP_NAME_LEN);
  memset(allowed, 0, gxOP_NAME_LEN);
  memset(denied, 0, gxOP_NAME_LEN);
  read_only = enabled = uc_passwd = (gxINT32)0;
  memset(a_hours, 0, gxOP_NAME_LEN);
  memset(a_days, 0, gxOP_NAME_LEN);
  created = modified = last = (gxUINT32)0;
}

int gxClientStatsHeader::TestHeader() 
{
  if(check_word != gxCheckWord) return 0;
  if(hdr_version != (gxUINT32)1024) return 0;
  return 1;
}

size_t gxClientStatsHeader::SizeOf()
{
  size_t size = (sizeof(gxUINT32) * 15);
  size += (sizeof(FAU) * 2);
  size += (gxOP_STR_LEN * 7);
  size += (gxOP_NAME_LEN * 6);
  return size;
}

gxSMTPDatabaseInfo::gxSMTPDatabaseInfo() 
{
  status = 0;
  auth_required = gxNoAuthRequired;
  database_read_locked = 0;
  database_write_locked = 0;
  database_read_lock_protect = 0;
  database_write_lock = new gxMutex;
  database_write_cond = new gxCondition;
  database_read_lock = new gxMutex;
  database_read_cond = new gxCondition;
}

gxSMTPDatabaseInfo::~gxSMTPDatabaseInfo() 
{ 
  if(database_write_lock) delete database_write_lock;
  if(database_write_cond) delete database_write_cond;
  if(database_read_lock) delete database_read_lock;
  if(database_read_cond) delete database_read_cond;
}

void gxSMTPDatabaseInfo::Copy(const gxSMTPDatabaseInfo &ob) 
{
  status = ob.status;
  auth_required = ob.auth_required;
  database_read_locked = ob.database_read_locked;
  database_write_locked = ob.database_write_locked;
  database_read_lock_protect = ob.database_read_lock_protect;
  table_def = ob.table_def;
  table_name = ob.table_name;
  def_file = ob.def_file;
  key_def = ob.key_def;
  form_def = ob.form_def;
  fkey_def = ob.fkey_def;
  group_def = ob.group_def;
  user_def = ob.user_def;
  
  // Each copy will have a unique mutex and condition variable
  if(database_write_lock) delete database_write_lock;
  if(database_write_cond) delete database_write_cond;
  if(database_read_lock) delete database_read_lock;
  if(database_read_cond) delete database_read_cond;
  database_write_lock = new gxMutex;
  database_write_cond = new gxCondition;
  database_read_lock = new gxMutex;
  database_read_cond = new gxCondition;
}

int GetHomeDir(gxString &home_dir)
{
  home_dir.Clear(); // Null the string

  // Check the environment for the users home directory
  if(getenv("HOME")) {
    home_dir = getenv("HOME");
    if(home_dir == "") return 0;
    if(home_dir[home_dir.length()-1] == '/') {
      home_dir.DeleteAt((home_dir.length()-1), 1);
    }
    return 1;
  }

  // Check for lower case HOME variables
  if(getenv("home")) {
    home_dir = getenv("home");
    if(home_dir == "") return 0;
    if(home_dir[home_dir.length()-1] == '/') {
      home_dir.DeleteAt((home_dir.length()-1), 1);
    }
    return 1;
  }

  return 0; // Could not find home directory
}

int CompressionRatio(FAU_t &bytes, FAU_t &compressed_bytes)
{
  if(compressed_bytes == (FAU_t)0) return 0;
  FAU_t comp = bytes/compressed_bytes;
  if(comp == 0) return 100;
  if(comp < 0) return 0;
  int result = 100/comp;
  if(result < 0) return 1;
  if(result == 100) return 1;
  return 100 - result;
}

const char *PasswdTableDef()
{
  return passwd_table_def;
}

const char *PasswdKeyDef()
{
  return passwd_key_def;
}

const char *MessagesTableDef()
{
  return messages_table_def;
}

const char *MessagesKeyDef()
{
  return messages_key_def;
}

const char *UnsentTableDef()
{
  return unsent_table_def;
}

const char *UnsentKeyDef()
{
  return unsent_key_def;
}

void SleepFor(int seconds)
{
#if defined (__WIN32__)
  int i = seconds * 1000; // Convert milliseconds to seconds
  Sleep((DWORD)i);
#elif defined (__UNIX__)
  sleep(seconds);
#else // No native sleep functions are defined
#error You must define a native API: __WIN32__ or __UNIX__
#endif
}

int touch(const char *file, time_t tm)
{
  struct utimbuf times;
  times.actime = times.modtime = tm;
  if(utime (file, &times) == -1) return 0;
  return 1;
}

void DumpThreadStatus(gxThread_t *thread, gxString &stats)
  // Thread debugging function
{
  if(!thread) return;
  stats.Clear();
  stats << "Thread OID: " << (int)thread->GetObjectID() << "\n";
  stats << "Thread CID: " << (int)thread->GetClassID() << "\n";
  stats << thread->ThreadExceptionMessage() << "\n";
  stats << thread->ThreadPriorityMessage() << "\n";
  stats << thread->ThreadStateMessage() << "\n";
  stats << thread->ThreadTypeMessage() << "\n";
  if(thread->GetStackSize() > (gxStackSizeType)0)
    stats << "Stack size: " << (int)thread->GetStackSize() << "\n";
}

int ValidateBoolValue(char &c, char default_value)
{
  // Check for acceptable bool types
  if((c == 'Y') || (c == 'y') || (c == 'T') || (c == 't') ||
     (c == 'F') || (c == 'f') || (c == '0') || (c == '1') ||
     (c == 0) || (c == 1) || (c == 'n') || (c == 'N')) {
    return 1;
  }
  c = default_value; // No valid so use the default setting
  return 0;
}
// ----------------------------------------------------------- // 
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //

