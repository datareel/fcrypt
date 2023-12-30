// ------------------------------- //
// -------- start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- // 
// C++ Source Code File
// Compiler Used: MSVC, BCC32, GCC, HPUX aCC, SOLARIS CC
// Produced By: DataReel Software Development Team
// Date Last Modified: 03/21/2004
// Date Last Modified: 12/06/2023
// Copyright (c) 2001-2024 DataReel Software Development
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

// Keyboard macro for console input functions
#define consoleCONTROL_KEY(c) ((c) & 037) 

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
	  for(i = (COMMAND_HISTORY_LEN-1); i > -1; i--) {
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
	if(clientcfg->next_command > (COMMAND_HISTORY_LEN-1)) {
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
	consolePutString(clientcfg->history[clientcfg->next_command].c_str());
	strcpy(p, clientcfg->history[clientcfg->next_command].c_str());
	charcount = strlen(p);
	pos = (p + charcount); // Reset the string pointer
	clientcfg->next_command++;
	if(clientcfg->next_command > (COMMAND_HISTORY_LEN-1)) {
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
#endif
  return 1;
}
// ----------------------------------------------------------- // 
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
