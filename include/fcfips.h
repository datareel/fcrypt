// ------------------------------- //
// -------- Start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- //
// C++ Header File Name: fcfips.h
// Compiler Used: MSVC, GCC
// Produced By: DataReel Software Development Team
// File Creation Date: 10/25/2026
// Date Last Modified: 10/25/2026
// Copyright (c) 2001-2026 DataReel Software Development
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

FIPS mode and OpenSSL library context setup.

In FIPS mode every crypto operation runs in a library context that has
only the OpenSSL "fips" and "base" providers loaded, with fips=yes as
the default property. If the FIPS provider cannot be loaded or fails
its self-test, FC_crypto_init() fails and nothing is encrypted or
decrypted.

Outside FIPS mode a library context with the "default" provider is
used, so --no-fips also works on a host whose OpenSSL configuration
turns on FIPS for every program.

FIPS mode is on when --fips is given, when FCRYPT_FIPS=1 is set, or
when the system is in FIPS mode (Linux /proc/sys/crypto/fips_enabled
is 1, the Windows FIPS algorithm policy is enabled, or the OpenSSL
configuration sets fips=yes). --no-fips turns it off for one run.

FIPS mode needs OpenSSL 3.0 or later. Builds with an older OpenSSL
refuse --fips, and run outside FIPS mode on a host in FIPS mode.
*/
// ----------------------------------------------------------- //
#ifndef __FC_FIPS_HPP__
#define __FC_FIPS_HPP__

#include "gxdlcode.h"
#include "gxstring.h"

enum {
  FC_FIPS_AUTO = 0, // FIPS mode if FCRYPT_FIPS=1 or the system is in FIPS mode
  FC_FIPS_ON,       // --fips
  FC_FIPS_OFF       // --no-fips
};

// Set up the library context. Returns 1 on success or 0 with err set.
int FC_crypto_init(int fips_request, gxString &err);

// Free the library context and providers
void FC_crypto_cleanup();

// True when FC_crypto_init() turned FIPS mode on
int FC_fips_mode();

// True if the system or the environment asks for FIPS mode
int FC_system_fips_requested();

// One line describing the providers in use, for --version and -v
gxString FC_crypto_status();

#endif // __FC_FIPS_HPP__
// ----------------------------------------------------------- //
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
