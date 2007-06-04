/* ====================================================================
 * Copyright (c) 1999-2006 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#ifndef HEADER_SAFESTACK_H
#define HEADER_SAFESTACK_H

#include <openssl/stack.h>

#ifndef OPENSSL_INLINE
#define OPENSSL_INLINE static inline
#endif

#define STACK_OF(type) struct stack_st_##type

#define IMPLEMENT_STACK_OF(type) /* nada (obsolete in new safestack approach)*/

#define DECLARE_STACK_OF(type) \
STACK_OF(type) \
    { \
    STACK stack; \
    }; \
OPENSSL_INLINE STACK_OF(type) *sk_##type##_new( \
	int (*cmp)(const type * const *, const type *const *)) \
    { return (STACK_OF(type) *)sk_new((int (*)())cmp); } \
OPENSSL_INLINE STACK_OF(type) *sk_##type##_new_null() \
    { return (STACK_OF(type) *)sk_new_null(); } \
OPENSSL_INLINE void sk_##type##_free(STACK_OF(type) *sk) \
    { sk_free((STACK *)sk); } \
OPENSSL_INLINE int sk_##type##_num(const STACK_OF(type) *sk) \
    { return M_sk_num((const STACK *)sk); } \
OPENSSL_INLINE type *sk_##type##_value(const STACK_OF(type) *sk,int n) \
    { return (type *)sk_value((STACK *)sk,n); } \
OPENSSL_INLINE type *sk_##type##_set(STACK_OF(type) *sk,int n,type *v) \
    { return (type *)(sk_set((STACK *)sk,n,(char *)v)); } \
OPENSSL_INLINE void sk_##type##_zero(STACK_OF(type) *sk) \
    { sk_zero((STACK *)sk); } \
OPENSSL_INLINE int sk_##type##_push(STACK_OF(type) *sk,type *v) \
    { return sk_push((STACK *)sk,(char *)v); } \
OPENSSL_INLINE int sk_##type##_unshift(STACK_OF(type) *sk,type *v) \
    { return sk_unshift((STACK *)sk,(char *)v); } \
OPENSSL_INLINE int sk_##type##_find(STACK_OF(type) *sk,type *v) \
    { return sk_find((STACK *)sk,(char *)v); } \
OPENSSL_INLINE type *sk_##type##_delete(STACK_OF(type) *sk,int n) \
    { return (type *)sk_delete((STACK *)sk,n); } \
OPENSSL_INLINE void sk_##type##_delete_ptr(STACK_OF(type) *sk,type *v) \
    { sk_delete_ptr((STACK *)sk,(char *)v); } \
OPENSSL_INLINE int sk_##type##_insert(STACK_OF(type) *sk,type *v,int n) \
    { return sk_insert((STACK *)sk,(char *)v,n); } \
OPENSSL_INLINE int (*sk_##type##_set_cmp_func(STACK_OF(type) *sk, \
    int (*cmp)(const type * const *,const type * const *))) \
	(const type *const *,const type *const *) \
    { return (int (*)(const type * const *,const type *const *)) \
	sk_set_cmp_func((STACK *)sk,(int(*)(const char * const *, const char * const *))cmp); } \
OPENSSL_INLINE STACK_OF(type) *sk_##type##_dup(STACK_OF(type) *sk) \
    { return (STACK_OF(type) *)sk_dup((STACK *)sk); } \
OPENSSL_INLINE void sk_##type##_pop_free(STACK_OF(type) *sk,void (*func)(type *)) \
    { sk_pop_free((STACK *)sk,(void (*)(void *))func); } \
OPENSSL_INLINE type *sk_##type##_shift(STACK_OF(type) *sk) \
    { return (type *)sk_shift((STACK *)sk); } \
OPENSSL_INLINE type *sk_##type##_pop(STACK_OF(type) *sk) \
    { return (type *)sk_pop((STACK *)sk); } \
OPENSSL_INLINE void sk_##type##_sort(STACK_OF(type) *sk) \
    { sk_sort((STACK *)sk); } \
OPENSSL_INLINE int sk_##type##_is_sorted(const STACK_OF(type) *sk) \
    { return sk_is_sorted((const STACK *)sk); }

#endif /* !defined HEADER_SAFESTACK_H */
