// ------------------------------- //
// -------- Start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- //
// C++ Header File
// Compiler Used: MSVC, BCC32, GCC, HPUX aCC, SOLARIS CC
// Produced By: DataReel Software Development Team
// File Creation Date: 09/15/2003
// Date Last Modified: 07/17/2025
// Copyright (c) 2001-2025 DataReel Software Development
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

const float PROGRAM_VERSION_NUMBER = 2025.101; // Set the version number here
const int COMMAND_HISTORY_LEN = 255; // Buffer size for command history 

#endif  // __GLOBALS_HPP__
// ----------------------------------------------------------- // 
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
