/* libp11, a simple layer on to of PKCS#11 API
 * Copyright (C) 2005 Olaf Kirch <okir@lst.de>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#include "libp11.h"
#include "libp11-int.h"

#define CKR_LIB_NAME "PKCS#11 module"

/* BEGIN ERROR CODES */
#ifndef NO_ERR

# define ERR_FUNC(func) ERR_PACK(0,func,0)
# define ERR_REASON(reason) ERR_PACK(0,0,reason)

static ERR_STRING_DATA CKR_str_functs[] = {
    {ERR_FUNC(CKR_F_PKCS11_CHANGE_PIN), "pkcs11_change_pin"},
    {ERR_FUNC(CKR_F_PKCS11_CHECK_TOKEN), "pkcs11_check_token"},
    {ERR_FUNC(CKR_F_PKCS11_CTX_LOAD), "pkcs11_CTX_load"},
    {ERR_FUNC(CKR_F_PKCS11_ECDH_DERIVE), "pkcs11_ecdh_derive"},
    {ERR_FUNC(CKR_F_PKCS11_ECDSA_SIGN), "pkcs11_ecdsa_sign"},
    {ERR_FUNC(CKR_F_PKCS11_ENUMERATE_SLOTS), "pkcs11_enumerate_slots"},
    {ERR_FUNC(CKR_F_PKCS11_FIND_CERTS), "pkcs11_find_certs"},
    {ERR_FUNC(CKR_F_PKCS11_FIND_KEYS), "pkcs11_find_keys"},
    {ERR_FUNC(CKR_F_PKCS11_GENERATE_RANDOM), "pkcs11_generate_random"},
    {ERR_FUNC(CKR_F_PKCS11_GETATTR_ALLOC), "pkcs11_getattr_alloc"},
    {ERR_FUNC(CKR_F_PKCS11_GETATTR_BN), "pkcs11_getattr_bn"},
    {ERR_FUNC(CKR_F_PKCS11_GETATTR_INT), "pkcs11_getattr_int"},
    {ERR_FUNC(CKR_F_PKCS11_INIT_PIN), "pkcs11_init_pin"},
    {ERR_FUNC(CKR_F_PKCS11_INIT_SLOT), "pkcs11_init_slot"},
    {ERR_FUNC(CKR_F_PKCS11_INIT_TOKEN), "pkcs11_init_token"},
    {ERR_FUNC(CKR_F_PKCS11_IS_LOGGED_IN), "pkcs11_is_logged_in"},
    {ERR_FUNC(CKR_F_PKCS11_LOGIN), "pkcs11_login"},
    {ERR_FUNC(CKR_F_PKCS11_LOGOUT), "pkcs11_logout"},
    {ERR_FUNC(CKR_F_PKCS11_NEXT_CERT), "pkcs11_next_cert"},
    {ERR_FUNC(CKR_F_PKCS11_NEXT_KEY), "pkcs11_next_key"},
    {ERR_FUNC(CKR_F_PKCS11_OPEN_SESSION), "pkcs11_open_session"},
    {ERR_FUNC(CKR_F_PKCS11_PRIVATE_DECRYPT), "pkcs11_private_decrypt"},
    {ERR_FUNC(CKR_F_PKCS11_PRIVATE_ENCRYPT), "pkcs11_private_encrypt"},
    {ERR_FUNC(CKR_F_PKCS11_RELOAD_KEY), "pkcs11_reload_key"},
    {ERR_FUNC(CKR_F_PKCS11_REOPEN_SESSION), "pkcs11_reopen_session"},
    {ERR_FUNC(CKR_F_PKCS11_SEED_RANDOM), "pkcs11_seed_random"},
    {ERR_FUNC(CKR_F_PKCS11_STORE_CERTIFICATE), "pkcs11_store_certificate"},
    {ERR_FUNC(CKR_F_PKCS11_STORE_KEY), "pkcs11_store_key"},
	{0, NULL}
};

static ERR_STRING_DATA CKR_str_reasons[] = {
	{CKR_CANCEL, "Cancel"},
	{CKR_HOST_MEMORY, "Host memory error"},
	{CKR_SLOT_ID_INVALID, "Invalid slot ID"},
	{CKR_GENERAL_ERROR, "General Error"},
	{CKR_FUNCTION_FAILED, "Function failed"},
	{CKR_ARGUMENTS_BAD, "Invalid arguments"},
	{CKR_NO_EVENT, "No event"},
	{CKR_NEED_TO_CREATE_THREADS, "Need to create threads"},
	{CKR_CANT_LOCK, "Cannott lock"},
	{CKR_ATTRIBUTE_READ_ONLY, "Attribute read only"},
	{CKR_ATTRIBUTE_SENSITIVE, "Attribute sensitive"},
	{CKR_ATTRIBUTE_TYPE_INVALID, "Attribute type invalid"},
	{CKR_ATTRIBUTE_VALUE_INVALID, "Attribute value invalid"},
	{CKR_DATA_INVALID, "Data invalid"},
	{CKR_DATA_LEN_RANGE, "Data len range"},
	{CKR_DEVICE_ERROR, "Device error"},
	{CKR_DEVICE_MEMORY, "Device memory"},
	{CKR_DEVICE_REMOVED, "Device removed"},
	{CKR_ENCRYPTED_DATA_INVALID, "Encrypted data invalid"},
	{CKR_ENCRYPTED_DATA_LEN_RANGE, "Encrypted data len range"},
	{CKR_FUNCTION_CANCELED, "Function canceled"},
	{CKR_FUNCTION_NOT_PARALLEL, "Function not parallel"},
	{CKR_FUNCTION_NOT_SUPPORTED, "Function not supported"},
	{CKR_KEY_HANDLE_INVALID, "Key handle invalid"},
	{CKR_KEY_SIZE_RANGE, "Key size range"},
	{CKR_KEY_TYPE_INCONSISTENT, "Key type inconsistent"},
	{CKR_KEY_NOT_NEEDED, "Key not needed"},
	{CKR_KEY_CHANGED, "Key changed"},
	{CKR_KEY_NEEDED, "Key needed"},
	{CKR_KEY_INDIGESTIBLE, "Key indigestible"},
	{CKR_KEY_FUNCTION_NOT_PERMITTED, "Key function not permitted"},
	{CKR_KEY_NOT_WRAPPABLE, "Key not wrappable"},
	{CKR_KEY_UNEXTRACTABLE, "Key unextractable"},
	{CKR_MECHANISM_INVALID, "Mechanism invalid"},
	{CKR_MECHANISM_PARAM_INVALID, "Mechanism param invalid"},
	{CKR_OBJECT_HANDLE_INVALID, "Object handle invalid"},
	{CKR_OPERATION_ACTIVE, "Operation active"},
	{CKR_OPERATION_NOT_INITIALIZED, "Operation not initialized"},
	{CKR_PIN_INCORRECT, "PIN incorrect"},
	{CKR_PIN_INVALID, "PIN invalid"},
	{CKR_PIN_LEN_RANGE, "Invalid PIN length"},
	{CKR_PIN_EXPIRED, "PIN expired"},
	{CKR_PIN_LOCKED, "PIN locked"},
	{CKR_SESSION_CLOSED, "Session closed"},
	{CKR_SESSION_COUNT, "Session count"},
	{CKR_SESSION_HANDLE_INVALID, "Session handle invalid"},
	{CKR_SESSION_PARALLEL_NOT_SUPPORTED, "Session parallel not supported"},
	{CKR_SESSION_READ_ONLY, "Session read only"},
	{CKR_SESSION_EXISTS, "Session exists"},
	{CKR_SESSION_READ_ONLY_EXISTS, "Read-only session exists"},
	{CKR_SESSION_READ_WRITE_SO_EXISTS, "Read/write SO session exists"},
	{CKR_SIGNATURE_INVALID, "Signature invalid"},
	{CKR_SIGNATURE_LEN_RANGE, "Signature len range"},
	{CKR_TEMPLATE_INCOMPLETE, "Incomplete template"},
	{CKR_TEMPLATE_INCONSISTENT, "Inconsistent template"},
	{CKR_TOKEN_NOT_PRESENT, "No PKCS#11 token present"},
	{CKR_TOKEN_NOT_RECOGNIZED, "PKCS#11 token not recognized"},
	{CKR_TOKEN_WRITE_PROTECTED, "Token write protected"},
	{CKR_UNWRAPPING_KEY_HANDLE_INVALID, "Unwrapping key handle invalid"},
	{CKR_UNWRAPPING_KEY_SIZE_RANGE, "Unwrapping key size range"},
	{CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT, "Unwrapping key type inconsistent"},
	{CKR_USER_ALREADY_LOGGED_IN, "User already logged in"},
	{CKR_USER_NOT_LOGGED_IN, "User not logged in"},
	{CKR_USER_PIN_NOT_INITIALIZED, "User pin not initialized"},
	{CKR_USER_TYPE_INVALID, "User type invalid"},
	{CKR_USER_ANOTHER_ALREADY_LOGGED_IN, "User another is already logged in"},
	{CKR_USER_TOO_MANY_TYPES, "User too many types"},
	{CKR_WRAPPED_KEY_INVALID, "Wrapped key invalid"},
	{CKR_WRAPPED_KEY_LEN_RANGE, "Wrapped key len range"},
	{CKR_WRAPPING_KEY_HANDLE_INVALID, "Wrapping key handle invalid"},
	{CKR_WRAPPING_KEY_SIZE_RANGE, "Wrapping key size range"},
	{CKR_WRAPPING_KEY_TYPE_INCONSISTENT, "Wrapping key type inconsistent"},
	{CKR_RANDOM_SEED_NOT_SUPPORTED, "Random seed not supported"},
	{CKR_RANDOM_NO_RNG, "Random no rng"},
	{CKR_DOMAIN_PARAMS_INVALID, "Domain params invalid"},
	{CKR_BUFFER_TOO_SMALL, "Buffer too small"},
	{CKR_SAVED_STATE_INVALID, "Saved state invalid"},
	{CKR_INFORMATION_SENSITIVE, "Information sensitive"},
	{CKR_STATE_UNSAVEABLE, "State unsaveable"},
	{CKR_CRYPTOKI_NOT_INITIALIZED, "Cryptoki not initialized"},
	{CKR_CRYPTOKI_ALREADY_INITIALIZED, "Cryptoki already initialized"},
	{CKR_MUTEX_BAD, "Mutex bad"},
	{CKR_MUTEX_NOT_LOCKED, "Mutex not locked"},
	{CKR_VENDOR_DEFINED, "Vendor defined"},
	{0, NULL}
};
#endif

#ifdef CKR_LIB_NAME
static ERR_STRING_DATA CKR_lib_name[] = {
	{0, CKR_LIB_NAME},
	{0, NULL}
};
#endif

static int CKR_lib_error_code = 0;
static int CKR_error_init = 1;

int ERR_load_CKR_strings(void)
{
	if (CKR_lib_error_code == 0)
		CKR_lib_error_code = ERR_get_next_error_library();

	if (CKR_error_init) {
		CKR_error_init = 0;
#ifndef OPENSSL_NO_ERR
		ERR_load_strings(CKR_lib_error_code, CKR_str_functs);
		ERR_load_strings(CKR_lib_error_code, CKR_str_reasons);
#endif

#ifdef CKR_LIB_NAME
		CKR_lib_name->error = ERR_PACK(CKR_lib_error_code, 0, 0);
		ERR_load_strings(0, CKR_lib_name);
#endif
	}
	return 1;
}

void ERR_unload_CKR_strings(void)
{
	if (CKR_error_init == 0) {
#ifndef OPENSSL_NO_ERR
		ERR_unload_strings(CKR_lib_error_code, CKR_str_functs);
		ERR_unload_strings(CKR_lib_error_code, CKR_str_reasons);
#endif

#ifdef CKR_LIB_NAME
		ERR_unload_strings(0, CKR_lib_name);
#endif
		CKR_error_init = 1;
	}
}

void ERR_CKR_error(int function, int reason, char *file, int line)
{
	if (CKR_lib_error_code == 0)
		CKR_lib_error_code = ERR_get_next_error_library();
	ERR_PUT_error(CKR_lib_error_code, function, reason, file, line);
}

int ERR_get_CKR_code(void)
{
	if (CKR_lib_error_code == 0)
		CKR_lib_error_code = ERR_get_next_error_library();
	return CKR_lib_error_code;
}

/* vim: set noexpandtab: */
