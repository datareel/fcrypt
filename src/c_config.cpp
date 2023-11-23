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
  reset_all();
}

ClientConfig::~ClientConfig()
{

}

void ClientConfig::reset_all()
{
  verbose_mode = 0;   // Turn verbose mode off by default
  
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

  // Command history
  curr_command = 0;
  next_command = 0;
  prev_command = -1;
}
// ----------------------------------------------------------- // 
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //


