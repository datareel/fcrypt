// ------------------------------- //
// -------- Start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- //
// C++ Header File
// Compiler Used: MSVC, BCC32, GCC, HPUX aCC, SOLARIS CC
// Produced By: DataReel Software Development Team
// Date Last Modified: 03/21/2004
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

Multithreaded file system client framework. 
*/
// ----------------------------------------------------------- //   
#ifndef __GX_C_MTHREAD_CLIENT_HPP__
#define __GX_C_MTHREAD_CLIENT_HPP__

#include "gxdlcode.h"

#include "globals.h"
#include "c_config.h"
#include "cryptdb.h"

int consoleGetChar(int &c);
void consolePutString(const char *s);
void consolePutChar(const char c);
int consoleGetString(gxString &s, int password = 0, int clear_input = 1);
int consoleGetString(gxString &s, char *defval, int password = 0,
		     int clear_input = 1);
int consoleGetString(char *s, int password = 0);
void consoleClear();
void consoleShell();
void consoleDateTime();

#endif // __GX_C_MTHREAD_CLIENT_HPP__
// ----------------------------------------------------------- // 
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
