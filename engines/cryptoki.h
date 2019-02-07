/*
 * Copyright (c) 2017 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 cryptoki.h

 Set the PKCS#11 macros.
 *****************************************************************************/

#ifndef _CRYPTOKI_H
#define _CRYPTOKI_H

#ifdef _WIN32
#pragma pack(push, cryptoki, 1)
#endif

// 1. CK_PTR: The indirection string for making a pointer to an
// object.

#define CK_PTR *

// 2. CK_DECLARE_FUNCTION(returnType, name): A macro which makes
// an importable Cryptoki library function declaration out of a
// return type and a function name.

#ifdef _WIN32
#define CK_DECLARE_FUNCTION(returnType, name) \
   returnType __declspec(dllimport) name
#else
#define CK_DECLARE_FUNCTION(returnType, name) \
   returnType name
#endif

// 3. CK_DECLARE_FUNCTION_POINTER(returnType, name): A macro
// which makes a Cryptoki API function pointer declaration or
// function pointer type declaration out of a return type and a
// function name.

#ifdef _WIN32
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
   returnType __declspec(dllimport) (* name)
#else
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
   returnType (* name)
#endif

// 4. CK_CALLBACK_FUNCTION(returnType, name): A macro which makes
// a function pointer type for an application callback out of
// a return type for the callback and a name for the callback.

#define CK_CALLBACK_FUNCTION(returnType, name) \
   returnType (* name)

// 5. NULL_PTR: This macro is the value of a NULL pointer.

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11.h"

#ifdef _WIN32
#pragma pack(pop, cryptoki)
#endif

#endif // !_CRYPTOKI_H
