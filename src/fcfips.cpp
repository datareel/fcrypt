// ------------------------------- //
// -------- Start of File -------- //
// ------------------------------- //
// ----------------------------------------------------------- //
// C++ Source Code File Name: fcfips.cpp
// Compiler Used: MSVC, GCC
// Produced By: DataReel Software Development Team
// File Creation Date: 10/25/2026
// Date Last Modified: 10/25/2026
// Copyright (c) 2001-2026 DataReel Software Development
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

FIPS mode and OpenSSL library context setup.
*/
// ----------------------------------------------------------- //
#if defined (__WIN32__)
// Include windows.h first, without the wincrypt.h names that clash
// with OpenSSL
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#include "fcfips.h"
#include "aesdb.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#include <openssl/self_test.h>

static OSSL_LIB_CTX *fc_libctx = 0;
static OSSL_PROVIDER *fc_main_provider = 0;
static OSSL_PROVIDER *fc_base_provider = 0;
static OSSL_PROVIDER *fc_null_default_provider = 0;
static int fc_null_fips_was_on = 0;
static int fc_null_fips_was_off = 0;
#endif

static int fc_fips_mode = 0;
static int fc_system_fips = -1; // Set by FC_crypto_init()

int FC_system_fips_requested()
{
  // --no-fips turns off fips=yes in the default library context, so
  // answer with what the system asked for before that
  if(fc_system_fips != -1) return fc_system_fips;

  const char *env = getenv("FCRYPT_FIPS");
  if(env && strcmp(env, "1") == 0) return 1;

#if defined (__LINUX__)
  FILE *fp = fopen("/proc/sys/crypto/fips_enabled", "r");
  if(fp) {
    int c = fgetc(fp);
    fclose(fp);
    if(c == '1') return 1;
  }
#endif

#if defined (__WIN32__)
  // The "System cryptography: Use FIPS compliant algorithms" policy
  DWORD enabled = 0;
  DWORD size = sizeof(enabled);
  if(RegGetValueA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa\\FipsAlgorithmPolicy",
		  "Enabled", RRF_RT_REG_DWORD, 0, &enabled, &size) == ERROR_SUCCESS && enabled != 0) {
    return 1;
  }
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  // The OpenSSL configuration file sets fips=yes for every program
  if(EVP_default_properties_is_fips_enabled(0)) return 1;
#endif
  return 0;
}

int FC_crypto_init(int fips_request, gxString &err)
{
  FC_crypto_cleanup();
  fc_system_fips = FC_system_fips_requested();

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  int want_fips = 0;
  if(fips_request == FC_FIPS_ON) want_fips = 1;
  else if(fips_request == FC_FIPS_AUTO) want_fips = fc_system_fips;

  fc_libctx = OSSL_LIB_CTX_new();
  if(!fc_libctx) {
    err << clear << "Cannot create an OpenSSL library context";
    return 0;
  }

  if(want_fips) {
    // The fips provider reads its integrity data from fipsmodule.cnf, so
    // load the OpenSSL configuration file into this context first. The
    // configuration may activate other providers as well.
    OSSL_LIB_CTX_load_config(fc_libctx, 0);
    ERR_clear_error();
    fc_main_provider = OSSL_PROVIDER_load(fc_libctx, "fips");
    if(!fc_main_provider) {
      err << clear << "FIPS mode: the OpenSSL FIPS provider could not be loaded. "
	  << "Install the FIPS provider and run openssl fipsinstall, or use --no-fips";
      FC_crypto_cleanup();
      return 0;
    }
    if(!OSSL_PROVIDER_self_test(fc_main_provider)) {
      err << clear << "FIPS mode: the OpenSSL FIPS provider failed its self-test";
      FC_crypto_cleanup();
      return 0;
    }
    fc_base_provider = OSSL_PROVIDER_load(fc_libctx, "base");
    if(!fc_base_provider) {
      err << clear << "FIPS mode: the OpenSSL base provider could not be loaded";
      FC_crypto_cleanup();
      return 0;
    }
    if(!EVP_default_properties_enable_fips(fc_libctx, 1)) {
      err << clear << "FIPS mode: cannot set the fips=yes default property";
      FC_crypto_cleanup();
      return 0;
    }
    // A provider the configuration activated, such as default, stays
    // loaded but is never used: fips=yes only matches FIPS algorithms.

    // A few OpenSSL calls always use the default library context, such
    // as reading a traditional PEM key with a passphrase. Set fips=yes
    // there too, so they cannot use algorithms FIPS does not allow.
    if(!EVP_default_properties_is_fips_enabled(0)) {
      if(!EVP_default_properties_enable_fips(0, 1)) {
	err << clear << "FIPS mode: cannot set the fips=yes default property";
	FC_crypto_cleanup();
	return 0;
      }
      fc_null_fips_was_off = 1;
    }
    fc_fips_mode = 1;
  }
  else {
    // A new context ignores the system configuration, so a host that
    // turns on FIPS for every program can still run --no-fips.
    fc_main_provider = OSSL_PROVIDER_load(fc_libctx, "default");
    if(!fc_main_provider) {
      err << clear << "The OpenSSL default provider could not be loaded";
      FC_crypto_cleanup();
      return 0;
    }
    EVP_default_properties_enable_fips(fc_libctx, 0);

    // A few OpenSSL calls always use the default library context, such
    // as reading a traditional PEM key with a passphrase. Turn off
    // fips=yes there too, so --no-fips covers the whole program.
    if(EVP_default_properties_is_fips_enabled(0)) {
      fc_null_default_provider = OSSL_PROVIDER_load(0, "default");
      if(fc_null_default_provider && EVP_default_properties_enable_fips(0, 0)) {
	fc_null_fips_was_on = 1;
      }
    }
    fc_fips_mode = 0;
  }
  AES_set_libctx(fc_libctx);
  return 1;
#else
  // Builds for older systems, such as RHEL 7 and 8, keep working on a
  // host in FIPS mode. Only an explicit --fips is refused.
  if(fips_request == FC_FIPS_ON) {
    err << clear << "FIPS mode needs OpenSSL 3.0 or later, this build uses " << OPENSSL_VERSION_TEXT;
    return 0;
  }
  fc_fips_mode = 0;
  return 1;
#endif
}

void FC_crypto_cleanup()
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  AES_set_libctx(0);
  if(fc_null_fips_was_on) EVP_default_properties_enable_fips(0, 1);
  if(fc_null_fips_was_off) EVP_default_properties_enable_fips(0, 0);
  fc_null_fips_was_on = fc_null_fips_was_off = 0;
  if(fc_null_default_provider) OSSL_PROVIDER_unload(fc_null_default_provider);
  fc_null_default_provider = 0;
  if(fc_base_provider) OSSL_PROVIDER_unload(fc_base_provider);
  if(fc_main_provider) OSSL_PROVIDER_unload(fc_main_provider);
  fc_base_provider = fc_main_provider = 0;
  if(fc_libctx) OSSL_LIB_CTX_free(fc_libctx);
  fc_libctx = 0;
#endif
  fc_fips_mode = 0;
  fc_system_fips = -1;
}

int FC_fips_mode()
{
  return fc_fips_mode;
}

gxString FC_crypto_status()
{
  gxString s;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  if(fc_main_provider) {
    const char *name = 0, *version = 0;
    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_NAME, (char **)&name, 0);
    params[1] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_VERSION, (char **)&version, 0);
    params[2] = OSSL_PARAM_construct_end();
    OSSL_PROVIDER_get_params(fc_main_provider, params);
    s << (fc_fips_mode ? "FIPS mode on" : "FIPS mode off") << ", provider: "
      << (name ? name : OSSL_PROVIDER_get0_name(fc_main_provider));
    if(version) s << " " << version;
  }
  else {
    s << "FIPS mode off, crypto not initialized";
  }
#else
  s << "FIPS mode not available with " << OPENSSL_VERSION_TEXT;
#endif
  return s;
}
// ----------------------------------------------------------- //
// ------------------------------- //
// --------- End of File --------- //
// ------------------------------- //
