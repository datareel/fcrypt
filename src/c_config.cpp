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

Client configuration framework.
*/
// ----------------------------------------------------------- // 
#include "gxdlcode.h"

#include "c_config.h"

// --------------------------------------------------------------
// Globals variable initialzation
// --------------------------------------------------------------
ClientConfig ClientConfigSruct;
ClientConfig *clientcfg = &ClientConfigSruct;
// --------------------------------------------------------------

ClientConfig::ClientConfig()
{
  client_log = 0;
  reset_all();
}

ClientConfig::~ClientConfig()
{
  if(client_log) delete client_log;
  password.Clear(1);
}

void ClientConfig::reset_all()
{
  // Set the default client hostname
  client_name = "localhost";

  // Set the default port numbers
  smtp_port = gxSMTPSERVER_PORT;
  ipc_port = gxSMTPSERVER_IPC_PORT;

  verbose_mode = 0;   // Turn verbose mode off by default
  confirm_prompt = 1; // Turn on confirm prompt 
  more_prompt = 1;    // Turn on more prompt

  // Thread synchronization variables
  display_is_locked = 0;
  client_log_is_locked = 0;

  // Timeout values
  server_read_timeout = 300; // Allow 5 minutes per server read by default

  // Retry variables
  display_thread_retries = 255;
  client_log_thread_retries = 255;

  // Logging variables
  log_client_messages = 1;

  // Auth Variables
  password_set = 0;
  login_retries = 3;
  username = "anybody"; // Default user name
  password.Clear(1);

  // Control variables
  up2date = 1;
  stop_transfer = 0;
  is_open = 0;
  
  // Program information
  version = 1.1;
  version_str << clear << setp2 << version;

  program_name = "File crypt/decrypt utility";
  produced_by = "Datareel Open Source";
  copyright = "Copyright (c) Datareel Open Source"; 
  copyright_dates = "2003-2023";
  release_date = "11/16/2023";
  default_url = "https://datareel.com";
  support_email = "datareel@datareel.com";

  // Define operating system/hardware platform dependent variables here
  char pbuf[futils_MAX_PATH_LENGTH];
  int rv = futils_getcwd(pbuf, futils_MAX_PATH_LENGTH);

  // Platform dependent variables
#if defined (__WIN32__) || defined (__DOS__)
  path_sep = "\\";
  path_sepc = '\\';
  if(rv == 0) {
    work_dir = pbuf;
  }
  else {
    work_dir = ".\\";
  }  
  if(!GetHomeDir(home_dir)) {
    if(rv == 0) {
      home_dir = pbuf;
    }
    else {
      home_dir = ".\\";
    }  
  }
  set_dirs(work_dir.c_str());
#else // Default to UNIX
  path_sep = "/";
  path_sepc = '/';
  
  if(rv == 0) {
    work_dir = pbuf;
  }
  else {
    work_dir = "./";
  }
  if(!GetHomeDir(home_dir)) {
    if(rv == 0) {
      home_dir = pbuf;
    }
    else {
      home_dir = "./";
    }
  }
  set_dirs(work_dir.c_str());
#endif

  // Command history
  curr_command = 0;
  next_command = 0;
  prev_command = -1;
}

void ClientConfig::set_dirs(const gxString &top_dir)
{
  gxString sbuf;

  // Platform dependent variables
#if defined (__WIN32__) || defined (__DOS__)
  cfg_file = "smtp_cli.ini";
#else // Default to UNIX
  cfg_file = "smtp_cli.cfg";
#endif

  // Set the default file names
  sbuf << clear << "." << path_sep << cfg_file;
  cfg_file << clear << sbuf;
  client_log_file << clear << "." << path_sep << "smtp_cli.log";

  // Open client files after the file names have been set
  if(log_client_messages) {
    if(client_log) delete client_log; 
    client_log = new LogFile;
  }
}
// ----------------------------------------------------------- // 
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //


