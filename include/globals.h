// ------------------------------- //
// -------- Start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- //
// C++ Header File
// Compiler Used: MSVC, BCC32, GCC, HPUX aCC, SOLARIS CC
// Produced By: DataReel Software Development Team
// File Creation Date: 09/15/2003
// Date Last Modified: 11/16/2023
// Copyright (c) 2001-2023 DataReel Software Development
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

This file contains global definitions for the given project. It                 
was created as an add-on to centralize all the global elements                  
used in throughout the source code.
*/
// ----------------------------------------------------------- //   
#ifndef __GLOBALS_HPP__
#define __GLOBALS_HPP__

// --------------------------------------------------------------
// Include Files
// --------------------------------------------------------------
// DataReel include files
#include "gxdlcode.h"
#include "gxmutex.h"
#include "gxcond.h"
#include "gxthread.h"
#include "systime.h"
#include "gxstream.h"
#include "gxconfig.h"
#include "gxshttp.h"
#include "devcache.h"
#include "dfileb.h"
#include "logfile.h"
#include "gxbstree.h"
#include "bstreei.h"
#include "gxrdbms.h"
#include "gxrdbdef.h"
#include "gxdstats.h"

// LIBC include files 
#if defined (__MSVC__)
#include <sys/utime.h>
#else
#include <utime.h>
#endif

#if defined (__LINUX__)
// Include file for TCP_NODELAY option
#include </usr/include/netinet/tcp.h>
#endif

// ZLIB include files
#ifndef __COMPRESSION_OFF__
#include "zlib.h"
#endif

// --------------------------------------------------------------

// --------------------------------------------------------------
// Constants
// --------------------------------------------------------------
// SMTP Database control commands
const __SBYTE__ gxSMTPDatabaseStats = 0;
const __SBYTE__ gxSMTPDeleteMessage = 1;
const __SBYTE__ gxSMTPDownloadMessage = 2;
const __SBYTE__ gxSMTPDumpMessageDB = 3;
const __SBYTE__ gxSMTPDumpUnsentMessageDB = 4;
const __SBYTE__ gxSMTPDeleteUnsentMessage = 5;

// SMTP stats control commands
const __SBYTE__ gxSMTPClientStats = 14;

// Default port values for this client/server application.
const int gxSMTPSERVER_PORT = 25; // Public port
const int gxSMTPSERVER_IPC_PORT = 59288; // Private port

// Fixed string lengths
const int gxOP_STR_LEN = 25;   // Fixed string length for SMTP operations 
const int gxOP_NAME_LEN = 255; // Fixed string length for SMTP file names
const int gxOP_ATTRIB_LEN = 5; // Fixed string length for DOS attributes

// Demoware constants
const int MAX_DEMOWARE_USERS = 2;

// Fixed buffer lengths
const int gxOP_HISTORY_LEN = 255; // Buffer size for command history 

// User constants
const int MAX_SMTP_USERS = 1500;
// --------------------------------------------------------------

// --------------------------------------------------------------
// Enumerations
// --------------------------------------------------------------
enum SMTPCommands {
  smtpEHLO = 0,
  smtpHELO,
  smtpMAIL,
  smtpRCPT,
  smtpDATA,
  smtpRSET,
  smtpNOOP,
  smtpQUIT
};
// --------------------------------------------------------------

// --------------------------------------------------------------
// Data Structures
// --------------------------------------------------------------
struct SMTPProxyData 
{
  SMTPProxyData() { resending = 0; }
  ~SMTPProxyData() { }

  gxString queue_number; // Unique message queue number
  gxString from;         // Message sender
  gxList<gxString> to;   // List of recipients 
  gxString data;         // Message header and body plus attachmnents
  int resending;         // Used to mark unsent records
 
private: // Disallow copying and assignment
  SMTPProxyData(const SMTPProxyData &ob) { }
  void operator=(const SMTPProxyData &ob) { }
};

struct gxClientStatsHeader
{
  gxClientStatsHeader() { Reset(); }
  ~gxClientStatsHeader() { }

  void Reset();
  int TestHeader();
  size_t SizeOf();

  gxUINT32 check_word;        // Checkword used to ID this header
  gxUINT32 hdr_version;       // Stat header version number
  gxUINT32 login_time;        // Time client has logged in 
  gxUINT32 logout_time;       // Time client has logged out
  gxUINT32 current_op_time;   // Time client started current op
  gxUINT32 last_good_op_time; // Time of last good client operation
  gxUINT32 last_bad_op_time;  // Time of last bad client operation

  FAU bytes_received;     // Total number of bytes received from client
  FAU bytes_transferred;  // Total number of bytes sent to client

  char current_op[gxOP_STR_LEN];   // Name of current client operation
  char last_good_op[gxOP_STR_LEN]; // Name of last good client operation
  char last_bad_op[gxOP_STR_LEN];  // Name of last bad client operation

  // Extended stats for IPC and remote admin clients
  char hostname[gxOP_STR_LEN]; // Client's hostname
  char username[gxOP_STR_LEN]; // Client's username
  char client_type[gxOP_STR_LEN]; // Client service type

  // User profile for IPC and remote admin clients
  char group_name[gxOP_STR_LEN];

  gxINT32 uid, gid;
  gxINT32 read_only, enabled, uc_passwd;
  gxUINT32 created, modified, last;
 
  char shell[gxOP_NAME_LEN];
  char home_dir[gxOP_NAME_LEN];
  char allowed[gxOP_NAME_LEN];
  char denied[gxOP_NAME_LEN];
  char a_hours[gxOP_NAME_LEN];
  char a_days[gxOP_NAME_LEN];

private: // Do not allow copying or assignment
  gxClientStatsHeader(const gxClientStatsHeader &ob) { }
  void operator=(const gxClientStatsHeader &ob) { }
};

// Structure used to store DB information 
struct gxSMTPDatabaseInfo
{
  gxSMTPDatabaseInfo();
  ~gxSMTPDatabaseInfo();
  gxSMTPDatabaseInfo(const gxSMTPDatabaseInfo &ob) {
    database_write_lock = database_read_lock = 0;
    database_read_cond = database_write_cond = 0;
    Copy(ob);
  }
  void operator=(const gxSMTPDatabaseInfo &ob) {
    Copy(ob);
  }

  void Copy(const gxSMTPDatabaseInfo &ob);

  char status;         // Current database status
  char auth_required;  // True if server auth is enabled
  gxString table_def;  // Parsed database table definition
  gxString table_name; // Table name retrieved from the parsed table def
  gxString key_def;    // Key definition
  gxString form_def;   // Form definition
  gxString fkey_def;   // Foreign key definition 
  gxString user_def;   // Users allowed access
  gxString group_def;  // Groups allowed access
  gxString def_file;   // File with absolute path

  // Database write lock synchronization code
  int database_write_locked;
  gxMutex *database_write_lock;
  gxCondition *database_write_cond;

  // Database read lock synchronization code
  int database_read_locked; 
  int database_read_lock_protect;
  gxMutex *database_read_lock;
  gxCondition *database_read_cond;
};
// --------------------------------------------------------------

// --------------------------------------------------------------
// Standalone client/server shared functions
// --------------------------------------------------------------
int CompressionRatio(FAU_t &bytes, FAU_t &compressed_bytes);
int GetHomeDir(gxString &home_dir);
void SleepFor(int seconds);
const char *PasswdTableDef();
const char *PasswdKeyDef();
const char *MessagesTableDef();
const char *MessagesKeyDef();
const char *UnsentTableDef();
const char *UnsentKeyDef();
int touch(const char *file, time_t tm);
int ValidateBoolValue(char &c, char default_value);
// --------------------------------------------------------------

// --------------------------------------------------------------
// Standalone debugging functions
// --------------------------------------------------------------
void DumpThreadStatus(gxThread_t *thread, gxString &stats);
// --------------------------------------------------------------

#endif  // __GLOBALS_HPP__
// ----------------------------------------------------------- // 
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
