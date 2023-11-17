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

Client configuration framework.
*/
// ----------------------------------------------------------- //   

#ifndef __GX_C_CONFIG_CLIENT_HPP__
#define __GX_C_CONFIG_CLIENT_HPP__

#include "gxdlcode.h"

#include "globals.h"

struct  ClientConfig {
  ClientConfig();
  ~ClientConfig();

  // Helper functions
  void set_dirs(const gxString &top_dir);
  void reset_all();

  gxString client_name; // Hostname assigned to this client
  gxString cfg_file;    // Name of client configuration file
  int verbose_mode;     // Enable console messages
  int confirm_prompt;   // Confirm delete and remove operations
  int more_prompt;      // Prompt user to continue for long lists

  // Client DIRs
  gxString home_dir;

  // Client auth variables
  gxString username; // User name client logged in with
  MemoryBuffer password; // Encrypted password
  gxClientStatsHeader user_profile; // User profile received from server

  int is_open; // True is client is connect

  // Client configuration variables
  gxsPort_t smtp_port;   // Client's file system access port number
  gxsPort_t ipc_port;  // Client's IPC port        

  // Message display synchronization interface
  gxMutex display_lock;     // Mutex object used to lock the display
  gxCondition display_cond; // Condition variable used with the display lock
  int display_is_locked;    // Display lock boolean predicate

  // Logfile synchronization interface
  gxMutex client_log_lock;
  gxCondition client_log_cond;
  int client_log_is_locked;

  // Retry variables
  int display_thread_retries;
  int client_log_thread_retries;

  // Client directories and files
  gxString work_dir; 
  gxString client_log_file;

  // Logging variables
  int log_client_messages;
  LogFile *client_log;

  // Control variables
  int up2date; // Enable/disable cached copies
  int stop_transfer; // Stop file uploads and downloads
 
  // Platform dependent variables
  gxString path_sep;
  char path_sepc;

  // Timeout varaibles
  int server_read_timeout; // Client side timeouts for server reads

  // Auth Variables
  gxWarningBanner banner;
  gxAuthHeader auth_header;
  int password_set;
  int login_retries;
  
  // Program inforamtion
  gxString executable_name;
  gxString version_str;
  double version;
  gxString compile_time;
  gxString program_name;
  gxString produced_by;
  gxString copyright;
  gxString copyright_dates;
  gxString release_date;
  gxString default_url;
  gxString fax_number;
  gxString snail_mail;
  gxString support_email;

  // Command history
  gxString history[gxOP_HISTORY_LEN];
  int curr_command;
  int next_command;
  int prev_command;
};

// --------------------------------------------------------------
// Globals configuration variables
// --------------------------------------------------------------
extern ClientConfig ClientConfigSruct;
extern ClientConfig *clientcfg;
// --------------------------------------------------------------

#endif // __GX_C_CONFIG_CLIENT_HPP__
// ----------------------------------------------------------- // 
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
