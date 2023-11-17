// ------------------------------- //
// -------- start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- // 
// C++ Source Code File
// Compiler Used: MSVC, BCC32, GCC, HPUX aCC, SOLARIS CC
// Produced By: DataReel Software Development Team
// Date Last Modified: 03/21/2004
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

Multithreaded file system client framework. 
*/
// ----------------------------------------------------------- // 
#include "gxdlcode.h"

#if defined (__CONSOLE__)
#if defined (__USE_ANSI_CPP__) // Use the ANSI Standard C++ library
#include <iostream>
#else // Use the old iostream library by default
#include <iostream.h>
#endif // __USE_ANSI_CPP__

#if defined (__WIN32__)
#include <conio.h> // Console I/O library
#endif

#if defined (__UNIX__)
#include <termios.h>
#endif

#include <stdio.h>
#endif // __CONSOLE__

#include "c_thread.h"

#ifdef __BCC32__
#pragma warn -8057
#pragma warn -8066
#pragma warn -8080
#endif

// Keyboard macro for console input functions
#define consoleCONTROL_KEY(c) ((c) & 037) 

int c_WatchForConsoleKey::Reset()
{
  // Reset all key events here
  clientcfg->stop_transfer = 0;
  return 1;
}

int c_WatchForConsoleKey::Start()
{
  Reset();
  key_watch_thread = key_watch.CreateThread();
  if(!key_watch_thread) {
    c_LogLines("Encountered fatal error starting key watch thread",
	       "Could not create key watch thread");
    return 0;
  }
  if(key_watch_thread->GetThreadError() != gxTHREAD_NO_ERROR) {
    c_LogLines("Encountered fatal error starting key watch thread",
	       key_watch_thread->ThreadExceptionMessage());
    delete key_watch_thread;
    key_watch_thread = 0;
    return 0;
  }

  return 1;
}

int c_WatchForConsoleKey::Stop()
{
  if(key_watch_thread) {
    if(key_watch.CancelThread(key_watch_thread) != 0) {
      c_LogMessage("Error canceling key watch thread");
    }
    if(key_watch.JoinThread(key_watch_thread) != 0) {
      c_LogMessage("Error joining key watch thread");
      return 0;
    }
    delete key_watch_thread;
    key_watch_thread = 0;
  }
  return 1;
}

void c_WatchForConsoleKeyThread::ThreadExitRoutine(gxThread_t *thread)
{
  c_LogMessage("Exiting key watch thread");
#if defined(__WIN32__)
  FlushConsoleInputBuffer(hconn);
  CloseHandle(hconn);
#endif
}

void c_WatchForConsoleKeyThread::ThreadCleanupHandler(gxThread_t *thread)
{
  c_LogMessage("Stopping key watch thread");
#if defined(__WIN32__)
  FlushConsoleInputBuffer(hconn);
  CloseHandle(hconn);
#endif
}

void *c_WatchForConsoleKeyThread::ThreadEntryRoutine(gxThread_t *thread)
{
#if defined (__WIN32__)
  fflush(stdin); fflush(stdout);
  GXSTD::cin.clear(); GXSTD::cout.clear();
  SleepFor(5); // Wait 5 seconds for all buffers to clear

  hconn = GetStdHandle(STD_INPUT_HANDLE);
  char sbuf[10];
  DWORD bytes_read = 0;
  DWORD write;
  if(!SetConsoleMode(hconn, 0)) {
    c_LogLines("Error setting console mode");
    return (void *)0;
  }

  while(1) {
    // Read the console buffer
    memset(sbuf, 0, sizeof(sbuf));
    if(!ReadConsole(hconn, sbuf, sizeof(sbuf), &bytes_read, NULL)) {
      c_LogLines("Error reading keyboard buffer");
      break;
    }

    // ---------------------------------------------------
    // Add all WIN32 key events here
    // ---------------------------------------------------
    // Check for Ctrl-b key
    for(write=0; write < bytes_read; write++) {
      if(sbuf[write] == consoleCONTROL_KEY('b')) {
	clientcfg->stop_transfer = 1;   
      }
    }
    // ---------------------------------------------------
  }
#elif defined (__UNIX__)
  int key = 0;
  while(1) {
    if(!consoleGetChar(key)) {
      c_LogLines("Error reading keyboard buffer");
      break;
    }
  

    // ---------------------------------------------------
    // Add all WIN32 key events here
    // ---------------------------------------------------
    // Check for Ctrl-b key
    if((char)key == consoleCONTROL_KEY('b')) {
      clientcfg->stop_transfer = 1;   
    }
    // ---------------------------------------------------
  }
#else
#error You must define a target platform: __WIN32__ or __UNIX__
#endif

  return (void *)0;
}

int c_DownloadMessage(gxStream *client, gxString &err, 
		      const gxString &queue_number,
		      gxrdDatabaseRecord &record)
{
  c_LogMessage("Sending download message request to the server");

  err.Clear();
  gxrdDatabaseTable table;
  gxDatabaseError dberr = table.CreateTable(MessagesTableDef());
  if(dberr != gxDBASE_NO_ERROR) {
    err = gxDatabaseExceptionMessage(dberr);
    c_LogLines("Error creating database table record", 
	       gxDatabaseExceptionMessage(dberr));
    return 0;
  }
  record.CreateRecord(table.record_def);
  record.SetField(queue_number.GetSPtr(), 
		  queue_number.length(), 0);
  
  MemoryBuffer block;
  dberr = record.CreateDiskRecord(block);
  if(dberr != gxDBASE_NO_ERROR) {
    err = gxDatabaseExceptionMessage(dberr);
    c_LogLines("Error creating database record", 
	       gxDatabaseExceptionMessage(dberr));
    return 0;
  }
  
  gxBlockHeader request_header;
  request_header.block_length = block.length();
  client->SetBlockStatus(request_header, gxSMTPDownloadMessage);

  gxBlockHeader requested_block_header;

  // Write the request header and the request itself
  if(client->WriteBlock(client->GetSocket(), block.m_buf(), request_header) 
     != gxSOCKET_NO_ERROR) {
    c_CheckSocketError((gxSocket *)client, err, 
		       "Error sending database record to server");
    return -1; // Signal to the caller to close this connection
  }

  int result_code;
  if(client->ReadResultBlock(result_code) != 0) {
    err = client->SocketExceptionMessage();
    c_LogLines("Error receiving download results", 
	       client->SocketExceptionMessage());
    return 0;
  }  
  if(result_code != gxDBASE_NO_ERROR) {
    err = gxDatabaseExceptionMessage((gxDatabaseError)result_code);
    c_LogLines("Record was not downloaded", 
	       gxDatabaseExceptionMessage((gxDatabaseError)result_code));
    return 0;
  }

  // Read the returned request header 
  if(client->ReadHeader(client->GetSocket(), requested_block_header, 
			clientcfg->server_read_timeout, 0) != 
     gxSOCKET_NO_ERROR) {
    c_CheckSocketError((gxSocket *)client, err, 
		       "Error receiving control HDR from server");
    return 0;
  }

  // Return null for all zero length blocks
  if(requested_block_header.block_length == (__ULWORD__)0) {
    c_LogMessage(err, "Error receiving database record zero block length");
    return 0;
  }

  MemoryBuffer buf;
  buf.resize((__ULWORD__)requested_block_header.block_length);

  if(client->Recv(client->GetSocket(), buf.m_buf(), 
		  requested_block_header.block_length, 
		  clientcfg->server_read_timeout, 0) < 0) {
    err = client->SocketExceptionMessage();
    c_LogLines("Error receiving database record", 
	       client->SocketExceptionMessage());
    return 0;
  }

  dberr = record.LoadDiskRecord(buf);
  if(dberr != gxDBASE_NO_ERROR) {
    err = gxDatabaseExceptionMessage(dberr);
    c_LogLines("Error loading record", 
	       gxDatabaseExceptionMessage(dberr));
    return 0;
  }    

  c_LogLines("Download message request successful");
  return 1;
}

int c_DumpMessageDatabase(gxStream *client, gxString &err, 
			  gxString &queue_list)
{
  return c_DumpDatabase(client, err, queue_list, 
			gxSMTPDumpMessageDB);
}

int c_DumpUnsentDatabase(gxStream *client, gxString &err, 
			 gxString &queue_list)
{
  return c_DumpDatabase(client, err, queue_list, 
			gxSMTPDumpUnsentMessageDB);
}

int c_DumpDatabase(gxStream *client, gxString &err, 
		   gxString &queue_list, char req)
{
  c_LogMessage("Sending database dump request to the server");
  err.Clear();
  queue_list.Clear();
  gxBlockHeader gx, null_hdr;
  client->SetBlockStatus(gx, req);

  if(client->WriteHeader(client->GetSocket(), gx) != 0) { 
    c_CheckSocketError((gxSocket *)client, err, 
		       "Error sending control HDR to server");
    return -1; // Signal to the caller to close this connection
  }

  gx = null_hdr;
  if(client->ReadHeader(client->GetSocket(), gx,
			clientcfg->server_read_timeout, 0) != 0) {
    c_CheckSocketError((gxSocket *)client, err, 
		       "Error receiving control HDR from server");
    return 0;
  }

  __ULWORD__ block_status = gx.block_status;
  __SBYTE__ status = (__SBYTE__)((block_status & 0xFF00)>>8);
  if(status == gxCloseConnection) {
    c_LogMessage(err, "Server closed connection do to a fatal error"); 
    return -1; // Signal to the caller to close this connection
  }

  if(gx.block_length == (gxUINT32)0) {
    c_LogMessage(err, "Error retrieving messages queue from server");
    return 0;
  }

  // Read the queue list from the server
  queue_list.resize((__ULWORD__)gx.block_length);
  if(client->ReadBlock(client->GetSocket(), queue_list.GetSPtr(), gx,
		       clientcfg->server_read_timeout, 0) != 0) {
    c_CheckSocketError((gxSocket *)client, err, 
		       "Error receiving data from server");
    return 0;
  }

  c_LogLines("Database dump successful");
  return 1;
}

int c_DeleteMessage(gxStream *client, gxString &err, 
		    gxString &queue_number)
{
  return c_DeleteRecord(client, err, queue_number, 
			gxSMTPDeleteMessage, MessagesTableDef());
}

int c_DeleteUnsent(gxStream *client, gxString &err, 
		   gxString &queue_number)
{
  return c_DeleteRecord(client, err, queue_number, 
			gxSMTPDeleteUnsentMessage, UnsentTableDef());
}

int c_DeleteRecord(gxStream *client, gxString &err, 
		   const gxString &queue_number, char req,
		   const char *def)
{
  c_LogMessage("Sending delete record request to the server");

  err.Clear();
  gxrdDatabaseTable table;
  gxrdDatabaseRecord record;
  gxDatabaseError dberr = table.CreateTable(def);
  if(dberr != gxDBASE_NO_ERROR) {
    err = gxDatabaseExceptionMessage(dberr);
    c_LogLines("Error creating database table record", 
	       gxDatabaseExceptionMessage(dberr));
    return 0;
  }
  record.CreateRecord(table.record_def);
  record.SetField(queue_number.GetSPtr(), 
		  queue_number.length(), 0);
  
  MemoryBuffer block;
  dberr = record.CreateDiskRecord(block);
  if(dberr != gxDBASE_NO_ERROR) {
    err = gxDatabaseExceptionMessage(dberr);
    c_LogLines("Error creating database record", 
	       gxDatabaseExceptionMessage(dberr));
    return 0;
  }
  
  gxBlockHeader request_header;
  request_header.block_length = block.length();
  client->SetBlockStatus(request_header, req);

  gxBlockHeader requested_block_header;

  // Write the request header and the request itself
  if(client->WriteBlock(client->GetSocket(), block.m_buf(), request_header) 
     != gxSOCKET_NO_ERROR) {
    c_CheckSocketError((gxSocket *)client, err, 
		       "Error sending database record to server");
    return -1; // Signal to the caller to close this connection
  }

  int result_code;
  if(client->ReadResultBlock(result_code) != 0) {
    err = client->SocketExceptionMessage();
    c_LogLines("Error receiving delete results", 
	       client->SocketExceptionMessage());
    return 0;
  }  
  if(result_code != gxDBASE_NO_ERROR) {
    err = gxDatabaseExceptionMessage((gxDatabaseError)result_code);
    c_LogLines("Record was not deleted", 
	       gxDatabaseExceptionMessage((gxDatabaseError)result_code));
    return 0;
  }
  
  c_LogLines("Download record request successful");
  return 1;
}

// --------------------------------------------------------------
// BEGIN: Server side logging and reporting functions
// --------------------------------------------------------------
int c_CheckSocketError(gxSocket *s, gxString &err, const char *mesg, 
		       int report_error)
// Test the socket for an error condition and report the message
// if the "report_error" variable is true. The "mesg" string is used
// display a message with the reported error. Returns true if an
// error was detected for false of no errors where detected. 
{
  if(s->GetSocketError() == gxSOCKET_NO_ERROR) {
    // No socket errors reported
    return 0;
  }
  err = s->SocketExceptionMessage();
  if(report_error) { // Reporting the error to an output device
    if(mesg) {
      c_LogLines(mesg, s->SocketExceptionMessage());
    }
    else {
      c_LogMessage(s->SocketExceptionMessage());
    }
  }
  return 1;
}

int c_CheckThreadError(gxThread_t *thread, gxString &err, const char *mesg, 
		       int report_error)
// Test the thread for an error condition and report the message
// if the "report_error" variable is true. The "mesg" string is used
// display a message with the reported error. Returns true if an
// error was detected for false of no errors where detected. 
{
  if(thread->GetThreadError() == gxTHREAD_NO_ERROR) {
    // No thread errors reported
    return 0;
  }
  err = thread->ThreadExceptionMessage();
  if(report_error) { // Reporting the error to an output device
    if(mesg) {
      c_LogLines(mesg, thread->ThreadExceptionMessage()); 
    }
    else {
      c_LogMessage(thread->ThreadExceptionMessage());
    }
  }
  return 1;
}

void c_FormatMessage(gxString &mesg, const gxString &hostname)
{
  SysTime systime;
  gxString sbuf(mesg);
  mesg << clear << systime.GetSyslogTime() << " " << hostname
       << ": " << sbuf;
}

int c_LogMessage(gxString &mesg)
{
  c_FormatMessage(mesg, clientcfg->client_name);
  c_WriteLogMessage(mesg.c_str());
  return 1;
}

int c_LogMessage(const char *s1, const char *s2, const char *s3)
{
  if(!s1) return 0;
  gxString sbuf(s1);
  if(s2) sbuf << " " << s2;
  if(s3) sbuf << " " << s3;
  return c_LogMessage(sbuf);
}

int c_LogLines(const char *L1, const char *L2, const char *L3)
{
  if(!L1) return 0;
  gxString mesg;
  gxString line1(L1);
  gxString line2, line3;
  c_FormatMessage(line1, clientcfg->client_name);
  mesg << line1;
  if(L2) {
    line2 = L2;
    c_FormatMessage(line2, clientcfg->client_name);
#if defined (__WIN32__)
    mesg << "\r\n" << line2;
#else
    mesg << "\n" << line2;
#endif
  }
  if(L3) {
    line3 = L3;
    c_FormatMessage(line3, clientcfg->client_name);
#if defined (__WIN32__)
    mesg << "\r\n" << line3;
#else
    mesg << "\n" << line3;
#endif
  }
  c_WriteLogMessage(mesg.c_str());
  return 1;
}

int c_LogMessage(gxString &mesg, gxString &err) 
{
  err = mesg;
  return c_LogMessage(mesg);
}

int c_LogMessage(gxString &err, const char *s1, const char *s2, 
		 const char *s3)
{
  err = s1;
  return c_LogMessage(s1, s2, s3);
}

int c_LogLines(gxString &err, const char *L1, const char *L2, 
	       const char *L3)
{
  err = L1;
  return c_LogLines(L1, L2, L3);
}

void c_WriteLogMessage(const char *s1, const char *s2, const char *s3)
// Thread safe write function that will not allow access to
// the critical section until the write operation is complete.
{
  c_DisplayMessage(s1, s2, s3);
  c_LogClientMessage(s1, s2, s3);
}

void c_DisplayMessage(const char *s1, const char *s2, const char *s3)
// Thread safe write function that will not allow access to
// the critical section until the write operation is complete.
{
  if(!clientcfg->verbose_mode) return;

  clientcfg->display_lock.MutexLock();

  // Ensure that all threads have finished writing to the device
  int num_try = 0;
  while(clientcfg->display_is_locked != 0) {
    // Block this thread from its own execution if a another thread
    // is writing to the device
    if(++num_try < clientcfg->display_thread_retries) {
      clientcfg->display_cond.ConditionWait(&clientcfg->display_lock);
    }
    else {
      return; // Could not write string to the device
    }
  }

  // Tell other threads to wait until write is complete
  clientcfg->display_is_locked = 1; 

  // ********** Enter Critical Section ******************* //
#if defined (__CONSOLE__)
#if defined (__WIN32__)
  GXSTD::cout << "\r\n";
#else
  GXSTD::cout << "\n";
#endif
  if(s1) GXSTD::cout << s1;
  if(s2) GXSTD::cout << s2;
  if(s3) GXSTD::cout << s3;
  GXSTD::cout.flush(); // Flush the ostream buffer to the stdio
#endif
  // ********** Leave Critical Section ******************* //

  // Tell other threads that this write is complete
  clientcfg->display_is_locked = 0; 
 
  // Wake up the next thread waiting on this condition
  clientcfg->display_cond.ConditionSignal();
  clientcfg->display_lock.MutexUnlock();
}

void c_LogClientMessage(const char *s1, const char *s2, const char *s3)
// Thread safe write function that will not allow access to
// the critical section until the write operation is complete.
{
  if(!clientcfg->log_client_messages) return;

  clientcfg->client_log_lock.MutexLock();

  // Ensure that all threads have finished writing to the device
  int num_try = 0;
  while(clientcfg->client_log_is_locked != 0) {
    // Block this thread from its own execution if a another thread
    // is writing to the device
    if(++num_try < clientcfg->client_log_thread_retries) {
      clientcfg->client_log_cond.ConditionWait(&clientcfg->client_log_lock);
    }
    else {
      return; // Could not write string to the device
    }
  }

  // Tell other threads to wait until write is complete
  clientcfg->client_log_is_locked = 1; 

  // ********** Enter Critical Section ******************* //
  // 07/10/2003: Exists varaible added so that the first line of
  // a new client log file will not be blank
  int exists = 1;
  if(!clientcfg->client_log->df_IsOpen()) {
    if(!futils_exists(clientcfg->client_log_file.c_str())) exists = 0;
    clientcfg->client_log->Open(clientcfg->client_log_file.c_str());
  }

  if(clientcfg->client_log->df_IsOpen()) {
    if(!exists) {
      SysTime systime;
      *(clientcfg->client_log) << clientcfg->program_name.c_str() <<
	" Log file created: " << systime.GetSystemDateTime();
    }

#if defined (__WIN32__)
    *(clientcfg->client_log) << "\r\n";
#else
    *(clientcfg->client_log) << "\n";
#endif
    if(s1) *(clientcfg->client_log) << s1;
    if(s2) *(clientcfg->client_log) << s2;
    if(s3) *(clientcfg->client_log) << s3;
    *(clientcfg->client_log) << flush;
  }

  // ********** Leave Critical Section ******************* //

  // Tell other threads that this write is complete
  clientcfg->client_log_is_locked = 0; 
 
  // Wake up the next thread waiting on this condition
  clientcfg->client_log_cond.ConditionSignal();
  clientcfg->client_log_lock.MutexUnlock();
}
// --------------------------------------------------------------
// END: Logging and reporting  functions
// --------------------------------------------------------------

// --------------------------------------------------------------
// BEGIN: Console-based display and input functions
// --------------------------------------------------------------
void c_DisplayStatsHeader(gxClientStatsHeader &shdr, int display_all)
{
#if defined (__CONSOLE__)
  gxString tx_str, rx_str;
  time_t tbuf;
  SysTime systime;
  
  // NOTE: Buffer and format the 64-bit integer values
  rx_str << clear << wn << shdr.bytes_received;
  tx_str << clear << wn << shdr.bytes_transferred;
  
  GXSTD::cout << "\n";
  GXSTD::cout << "----Client Statistics----" << "\n";

  if(display_all) {
    GXSTD::cout << "Client type: " << shdr.client_type << "\n";
    GXSTD::cout << "Hostname: " << shdr.hostname << "\n";
    GXSTD::cout << "Username: " << shdr.username << "\n";
    GXSTD::cout << "Group name: " << shdr.group_name << "\n";
#if defined (__UNIX__)
    GXSTD::cout << "UID: " << shdr.uid << " ";
    GXSTD::cout << "GID: " << shdr.gid << "\n";
    GXSTD::cout << "Shell: " << shdr.shell << "\n";
#endif
    GXSTD::cout << "Home DIR: " << shdr.home_dir << "\n"; 
    GXSTD::cout << "Allow: " << shdr.allowed << "\n";
    GXSTD::cout << "Deny: " << shdr.denied << "\n";
    GXSTD::cout << "Available hours: " << shdr.a_hours << "\n";
    GXSTD::cout << "Available days: " << shdr.a_days << "\n";
    GXSTD::cout << "Read only account: " << (char)shdr.read_only 
		<< "\n";
    GXSTD::cout << "Account enabled: " << (char)shdr.enabled
		<< "\n";
    GXSTD::cout << "User allowed to change password: " 
		<< (char)shdr.uc_passwd << "\n";
    tbuf = (time_t)shdr.created;
    if(tbuf > (time_t)0)
      GXSTD::cout << "Account created on: " << systime.MakeFileModTime(tbuf)
		  << "\n";
    tbuf = (time_t)shdr.modified;
    if(tbuf > (time_t)0)
      GXSTD::cout << "Account last modified on: " 
		  << systime.MakeFileModTime(tbuf) << "\n";
    tbuf = (time_t)shdr.login_time;
    if(tbuf > (time_t)0)
      GXSTD::cout << "Login time: " << systime.MakeFileModTime(tbuf) << "\n";
    tbuf = (time_t)shdr.logout_time;
    if(tbuf > (time_t)0)
      GXSTD::cout << "Logout time: " << systime.MakeFileModTime(tbuf) << "\n";
  }
  GXSTD::cout << "Total bytes received: " << rx_str.c_str() << "\n";
  GXSTD::cout << "Total bytes transferred: " << tx_str.c_str() << "\n";
  
  if(display_all) {
    GXSTD::cout << "Current op: " << shdr.current_op;
    tbuf = (time_t)shdr.current_op_time;
    if(tbuf > (time_t)0) {
      GXSTD::cout << " (" << systime.MakeFileModTime(tbuf) << ")";
    }
    GXSTD::cout << "\n";
  }
  GXSTD::cout << "Last good op: " << shdr.last_good_op;
  tbuf = (time_t)shdr.last_good_op_time;
  if(tbuf > (time_t)0) {
    GXSTD::cout << " (" << systime.MakeFileModTime(tbuf) << ")";
  }
  GXSTD::cout << "\n";
  GXSTD::cout << "Last bad op: " << shdr.last_bad_op;  
  tbuf = (time_t)shdr.last_bad_op_time;
  if(tbuf > (time_t)0) {
    GXSTD::cout << " (" << systime.MakeFileModTime(tbuf) << ")";
  }

  GXSTD::cout << GXSTD::flush;
#endif // __CONSOLE__
}

int consoleGetChar(int &c)
{
#if defined (__CONSOLE__)

#if defined (__WIN32__)
  c = getch();
#elif defined (__UNIX__)
  fd_set readfds, writefds, exceptfds;
  struct timeval timeout;
  static struct termios otty, ntty;

  // Create proper environment for select() 
  FD_ZERO(&readfds);
  FD_ZERO(&writefds);
  FD_ZERO(&exceptfds);
  FD_SET(fileno(stdin), &readfds);

  // Specify 0.5 sec as the waiting time 
  timeout.tv_sec  = 0;	 // 0 seconds 
  timeout.tv_usec = 500; // 500 microseconds 

  int fd = 0;
  
  // Put tty in raw mode 
  tcgetattr(fd, &otty); // Get the current options for the port
  tcgetattr(fd, &ntty);
  ntty.c_lflag &= ~(ECHO|ECHOE|ECHOK|ECHONL);
  ntty.c_lflag &= ~ICANON;
  ntty.c_lflag |= ISIG;
  ntty.c_cflag &= ~(CSIZE|PARENB);
  ntty.c_cflag |= CS8;
  ntty.c_iflag &= (ICRNL|ISTRIP);
  ntty.c_cc[VMIN] = 1;
  ntty.c_cc[VTIME] = 1;
  tcsetattr(fd, TCSANOW, &ntty);

  // Do a select 
  select(1, &readfds, &writefds, &exceptfds, &timeout);

  // Block until a key is pressed
  if(read(fileno(stdin), &c, 1) < 0) {
    tcsetattr(fd, TCSANOW, &otty);
    return 0;
  }

  // Reset the tty back to its original mode 
  tcsetattr(fd, TCSANOW, &otty);
#else
#error You must define a target platform: __WIN32__ or __UNIX__
#endif
  return 1;
#endif // __CONSOLE__
}

void consolePutString(const char *s)
{
#if defined (__CONSOLE__)
  printf("%s", s);
  fflush(stdout);
#endif // __CONSOLE__
}

void consolePutChar(const char c)
{
#if defined (__CONSOLE__)
  printf("%c", c);
  fflush(stdout);
#endif // __CONSOLE__
}

int consoleGetString(gxString &s, char *defval, int password,
		     int clear_input)
{
  const int max_len = 1024;
  char sbuf[max_len];
  memset(sbuf, 0, max_len);
  if(defval) { // Test the default value
    if(*(defval) != 0) {
      strncpy(sbuf, defval, max_len);
      sbuf[max_len-1] = 0;
    }
  }
  int rv = consoleGetString(sbuf, password);
  if(clear_input) {
    s << clear << sbuf;
  }
  else {
    s << sbuf;
  }
  return rv;
}

int consoleGetString(gxString &s, int password, int clear_input)
{
  const int max_len = 1024;
  char sbuf[max_len];
  memset(sbuf, 0, max_len);
  int rv = consoleGetString(sbuf, password);
  if(clear_input) {
    s << clear << sbuf;
  }
  else {
    s << sbuf;
  }
  return rv;
}

int consoleGetString(char *s, int password)
{
#if defined (__CONSOLE__)
  if(!s) return 0; // check to null pointers
  int key, i;
  char ch;
  int slen = strlen(s);
  int charcount = slen;
  char *pos = s+slen;
  char *p = s;

  while (1) {
    consoleGetChar(key);
    ch = (char)key;

    if((ch == '\n') || (ch == '\r') || (ch == consoleCONTROL_KEY('c'))) {
      *pos = 0;
      return 1;
    }

#if defined (__BCC32__) 
    if(key == 0) { // Look for extended keys
#else
    if(key == 0) { // Look for functions keys
      if(!consoleGetChar(key)) return -1;
      // No Function keys defined
      continue;
    }

    if(key == 224) { // Look for extended keyboard scan codes
#endif
      if(!consoleGetChar(key)) return -1;
      if(key == 72) { // Arrow up
	if(clientcfg->prev_command < 0) {
	  for(i = (gxOP_HISTORY_LEN-1); i > -1; i--) {
	    if(!clientcfg->history[i].is_null()) {
	      clientcfg->prev_command = i;
	      break;
	    }
	  }
	  if(clientcfg->history[i].is_null()) {
	    clientcfg->prev_command = 0;
	  }
	}
	slen = strlen(p);
	if(slen > 0) {
	  memset(p, 0, slen); // Clear the string
	  while(slen--) { // Clear the line
	    consolePutChar('\b');
	    consolePutChar(' ');
	    consolePutChar('\b');
	  }
	}
	if(clientcfg->prev_command < 0) clientcfg->prev_command = 0;   
	consolePutString(clientcfg->history[clientcfg->prev_command].c_str());
	strcpy(p, clientcfg->history[clientcfg->prev_command].c_str());
	charcount = strlen(p);
	pos = (p + charcount); // Reset the string pointer
	// if(clientcfg->prev_command > 0) 
	clientcfg->prev_command--;
      }
      if(key == 80) { // Arrow down
	if(clientcfg->next_command > (gxOP_HISTORY_LEN-1)) {
	  clientcfg->next_command = 0;
	}
	slen = strlen(p);
	if(slen > 0) {
	  memset(p, 0, slen); // Clear the string
	  while(slen--) { // Clear the line
	    consolePutChar('\b');
	    consolePutChar(' ');
	    consolePutChar('\b');
	  }
	}
	consolePutString(\
clientcfg->history[clientcfg->next_command].c_str());
	strcpy(p, clientcfg->history[clientcfg->next_command].c_str());
	charcount = strlen(p);
	pos = (p + charcount); // Reset the string pointer
	clientcfg->next_command++;
	if(clientcfg->next_command > (gxOP_HISTORY_LEN-1)) {
	  clientcfg->next_command = 0;
	}
	if(clientcfg->next_command > 0) {
	  if(clientcfg->history[clientcfg->next_command].is_null()) {
	    clientcfg->next_command = 0;
	  }
	}
      }
      if((key == 75) || (key == 83)) { // Left arrow or delete key
	if(charcount > 0) {
	  pos--;
	  charcount--;
	  consolePutChar('\b');
	  consolePutChar(' ');
	  consolePutChar('\b');
	}
      }
      if(key == 77) { // Right arrow
	consolePutChar(' ');
      }
      continue;
    }

    if((ch == '\b') || (ch == consoleCONTROL_KEY('d'))) { // Delete keys 
      if(charcount > 0) {
	pos--;
	charcount--;
	consolePutChar('\b');
	consolePutChar(' ');
	consolePutChar('\b');
      }
    }
    else {
      *pos++ = ch;
      charcount++;
      if(password) {
	consolePutChar('*');
      }
      else {
	consolePutChar(ch);
      }
    }
  }
#endif // __CONSOLE__
  return 1;
}

void consoleClear()
{
#if defined (__CONSOLE__)
#if defined (__WIN32__)
  system("cls");
#elif defined (__UNIX__)
  system("clear");
#else
#error You must define a target platform: __WIN32__ or __UNIX__
#endif
#endif // __CONSOLE__
}

void consoleShell()
{
#if defined (__CONSOLE__)
  GXSTD::cout << "\n" << GXSTD::flush;
  GXSTD::cout << "\n" << GXSTD::flush;
  GXSTD::cout << clientcfg->program_name << "\n" << GXSTD::flush;
  GXSTD::cout << "Shell to command line" << "\n" << GXSTD::flush;
  GXSTD::cout << "Enter exit to return" << "\n" << GXSTD::flush;
  GXSTD::cout << "\n" << GXSTD::flush;

#ifdef __LINUX__
  GXSTD::cout << "You may need to enter tset or reset if\n" << GXSTD::flush;
  GXSTD::cout << "your terminal type is not set correctly\n" << GXSTD::flush;
  GXSTD::cout << "\n" << GXSTD::flush;
#endif

  char pwd[futils_MAX_DIR_LENGTH];
  if(futils_getcwd(pwd, futils_MAX_DIR_LENGTH) != 0) {
    GXSTD::cout << "Error obtaining PWD cannot open shell" << GXSTD::flush;
    GXSTD::cout << "\n" << GXSTD::flush;
    return;
  }

#if defined (__WIN32__)
  system("cmd /k");
#elif defined (__UNIX__)
  system("/bin/sh");
#else
#error You must define a target platform: __WIN32__ or __UNIX__
#endif

  if(futils_chdir(pwd) != 0) {
    GXSTD::cout << "\n" << GXSTD::flush;
    GXSTD::cout << "Error restoring working DIR" << GXSTD::flush;
    GXSTD::cout << "\n" << GXSTD::flush;
    return;
  }

#endif // __CONSOLE__
}

void consoleDateTime()
{
#if defined (__CONSOLE__)
  SysTime systime;
  GXSTD::cout << "\n" << GXSTD::flush;
  GXSTD::cout << systime.GetSystemDateTime() << "\n" << GXSTD::flush;
#endif // __CONSOLE__
}
// --------------------------------------------------------------
// END: Console-based display and input functions
// --------------------------------------------------------------

#ifdef __BCC32__
#pragma warn .8057
#pragma warn .8066
#pragma warn .8080
#endif
// ----------------------------------------------------------- // 
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
