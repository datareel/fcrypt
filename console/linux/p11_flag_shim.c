/* Test only PKCS#11 shim for run_smartcard_list_tests.sh, never used with
 * a real card.
 *
 * Loads the module named by FC_SHIM_MODULE (a SoftHSM2 module) and
 * passes every call through, except that C_GetTokenInfo ORs the hex
 * token flags in FC_SHIM_FLAGS into the reply. This lets the tests set
 * CKF_USER_PIN_COUNT_LOW (0x10000), CKF_USER_PIN_FINAL_TRY (0x20000) and
 * CKF_USER_PIN_LOCKED (0x40000), which SoftHSM2 does not set itself, and
 * check that no PIN is sent to such a card. Count the C_Login calls by
 * loading this shim through the OpenSC pkcs11-spy module.
 *
 * Build: gcc -shared -fPIC -I../../include -o p11_flag_shim.so p11_flag_shim.c -ldl
 */
#define CRYPTOKI_COMPAT
#include <pkcs11.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

static CK_FUNCTION_LIST shim_list;
static CK_FUNCTION_LIST_PTR real_list = 0;

static CK_RV shim_GetTokenInfo(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info)
{
  CK_RV rv = real_list->C_GetTokenInfo(slot, info);
  const char *flags = getenv("FC_SHIM_FLAGS");
  if(rv == CKR_OK && info && flags && *flags) info->flags |= (CK_FLAGS)strtoul(flags, 0, 16);
  return rv;
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR list)
{
  if(!list) return CKR_ARGUMENTS_BAD;
  if(!real_list) {
    const char *module = getenv("FC_SHIM_MODULE");
    if(!module) return CKR_GENERAL_ERROR;
    void *lib = dlopen(module, RTLD_NOW | RTLD_LOCAL);
    if(!lib) return CKR_GENERAL_ERROR;
    CK_C_GetFunctionList get_list = (CK_C_GetFunctionList)dlsym(lib, "C_GetFunctionList");
    if(!get_list || get_list(&real_list) != CKR_OK || !real_list) return CKR_GENERAL_ERROR;
    memcpy(&shim_list, real_list, sizeof(shim_list));
    shim_list.C_GetTokenInfo = shim_GetTokenInfo;
  }
  *list = &shim_list;
  return CKR_OK;
}
