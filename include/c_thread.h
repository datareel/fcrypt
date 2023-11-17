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

class c_WatchForConsoleKeyThread : public gxThread
{
public:
  c_WatchForConsoleKeyThread() { }
  ~c_WatchForConsoleKeyThread() { }

private:
  void *ThreadEntryRoutine(gxThread_t *thread);
  void ThreadExitRoutine(gxThread_t *thread);
  void ThreadCleanupHandler(gxThread_t *thread);

#if defined (__WIN32__)
private:
  HANDLE hconn;
#endif
};

class c_WatchForConsoleKey
{
public:
  c_WatchForConsoleKey() { key_watch_thread = 0; }
  ~c_WatchForConsoleKey() { Stop(); }

public:
  int Reset();
  int Start();
  int Stop();

public:
  c_WatchForConsoleKeyThread key_watch;
  gxThread_t *key_watch_thread;
};

// --------------------------------------------------------------
// Standalone client side messages database functions
// --------------------------------------------------------------
int c_DumpMessageDatabase(gxStream *client, gxString &err, 
			  gxString &queue_list);
int c_DumpUnsentDatabase(gxStream *client, gxString &err, 
			 gxString &queue_list);
int c_DumpDatabase(gxStream *client, gxString &err, 
		   gxString &queue_list, char req);
int c_DownloadMessage(gxStream *client, gxString &err, 
		      const gxString &queue_number,
		      gxrdDatabaseRecord &record);
int c_DeleteMessage(gxStream *client, gxString &err, 
		    gxString &queue_number);
int c_DeleteUnsent(gxStream *client, gxString &err, 
		   gxString &queue_number);
int c_DeleteRecord(gxStream *client, gxString &err, 
		   const gxString &queue_number, char req,
		   const char *def);
// --------------------------------------------------------------

// --------------------------------------------------------------
// Standalone client side console-based display and input functions
// --------------------------------------------------------------
void c_DisplayStatsHeader(gxClientStatsHeader &shdr, int display_all = 0);
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
// --------------------------------------------------------------

// --------------------------------------------------------------
// Standalone client side logging functions
// --------------------------------------------------------------
int c_CheckSocketError(gxSocket *s, gxString &err,
		       const char *mesg = 0, int report_error = 1);
int c_CheckThreadError(gxThread_t *thread, gxString &err,
		       const char *mesg = 0, int report_error = 1);
void c_FormatMessage(gxString &mesg, const gxString &hostname);
int c_LogMessage(gxString &mesg);
int c_LogMessage(const char *s1, const char *s2 = 0, const char *s3 = 0);
int c_LogLines(const char *L1, const char *L2 = 0, const char *L3 = 0);
int c_LogMessage(gxString &mesg, gxString &err);
int c_LogMessage(gxString &err, const char *s1, const char *s2 = 0, 
		 const char *s3 = 0);
int c_LogLines(gxString &err, const char *L1, const char *L2 = 0, 
	       const char *L3 = 0);
void c_WriteLogMessage(const char *s1, const char *s2 = 0, const char *s3 = 0);
void c_DisplayMessage(const char *s1, const char *s2 = 0, const char *s3 = 0);
void c_LogClientMessage(const char *s1, const char *s2 = 0, 
			const char *s3 = 0);
// --------------------------------------------------------------

#endif // __GX_C_MTHREAD_CLIENT_HPP__
// ----------------------------------------------------------- // 
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
