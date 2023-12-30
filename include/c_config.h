// ------------------------------- //
// -------- Start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- //
// C++ Header File
// Compiler Used: MSVC, BCC32, GCC, HPUX aCC, SOLARIS CC
// Produced By: DataReel Software Development Team
// File Creation Date: 09/15/2003
// Date Last Modified: 12/06/2023
// Copyright (c) 2001-2024 DataReel Software Development
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
  void reset_all();

  int verbose_mode;     // Enable console messages
  
  // Program inforamtion
  gxString executable_name;
  gxString version_str;
  float version;
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
  gxString history[COMMAND_HISTORY_LEN];
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
