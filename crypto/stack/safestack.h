/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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

#define STACK_OF(type)	STACK_##type

#define DECLARE_STACK_OF(type) \
typedef struct stack_st_##type	\
    { \
    STACK stack; \
    } STACK_OF(type); \
STACK_OF(type) *sk_##type##_new(int (*cmp)(type **,type **)); \
STACK_OF(type) *sk_##type##_new_null(void); \
void sk_##type##_free(STACK_OF(type) *sk); \
int sk_##type##_num(const STACK_OF(type) *sk); \
type *sk_##type##_value(const STACK_OF(type) *sk,int n); \
type *sk_##type##_set(STACK_OF(type) *sk,int n,type *v); \
void sk_##type##_zero(STACK_OF(type) *sk); \
int sk_##type##_push(STACK_OF(type) *sk,type *v); \
int sk_##type##_unshift(STACK_OF(type) *sk,type *v); \
int sk_##type##_find(STACK_OF(type) *sk,type *v); \
type *sk_##type##_delete(STACK_OF(type) *sk,int n); \
void sk_##type##_delete_ptr(STACK_OF(type) *sk,type *v); \
int sk_##type##_insert(STACK_OF(type) *sk,type *v,int n); \
int (*sk_##type##_set_cmp_func(STACK_OF(type) *sk, \
			       int (*cmp)(type **,type **)))(type **,type **); \
STACK_OF(type) *sk_##type##_dup(STACK_OF(type) *sk); \
void sk_##type##_pop_free(STACK_OF(type) *sk,void (*func)(type *)); \
type *sk_##type##_shift(STACK_OF(type) *sk); \
type *sk_##type##_pop(STACK_OF(type) *sk); \
void sk_##type##_sort(STACK_OF(type) *sk);

#define IMPLEMENT_STACK_OF(type) \
STACK_OF(type) *sk_##type##_new(int (*cmp)(type **,type **)) \
    { return (STACK_OF(type) *)sk_new(cmp); } \
STACK_OF(type) *sk_##type##_new_null() \
    { return (STACK_OF(type) *)sk_new_null(); } \
void sk_##type##_free(STACK_OF(type) *sk) \
    { sk_free((STACK *)sk); } \
int sk_##type##_num(const STACK_OF(type) *sk) \
    { return M_sk_num((const STACK *)sk); } \
type *sk_##type##_value(const STACK_OF(type) *sk,int n) \
    { return (type *)sk_value((STACK *)sk,n); } \
type *sk_##type##_set(STACK_OF(type) *sk,int n,type *v) \
    { return (type *)(sk_set((STACK *)sk,n,(char *)v)); } \
void sk_##type##_zero(STACK_OF(type) *sk) \
    { sk_zero((STACK *)sk); } \
int sk_##type##_push(STACK_OF(type) *sk,type *v) \
    { return sk_push((STACK *)sk,(char *)v); } \
int sk_##type##_unshift(STACK_OF(type) *sk,type *v) \
    { return sk_unshift((STACK *)sk,(char *)v); } \
int sk_##type##_find(STACK_OF(type) *sk,type *v) \
    { return sk_find((STACK *)sk,(char *)v); } \
type *sk_##type##_delete(STACK_OF(type) *sk,int n) \
    { return (type *)sk_delete((STACK *)sk,n); } \
void sk_##type##_delete_ptr(STACK_OF(type) *sk,type *v) \
    { sk_delete_ptr((STACK *)sk,(char *)v); } \
int sk_##type##_insert(STACK_OF(type) *sk,type *v,int n) \
    { return sk_insert((STACK *)sk,(char *)v,n); } \
int (*sk_##type##_set_cmp_func(STACK_OF(type) *sk, \
			       int (*cmp)(type **,type **)))(type **,type **) \
    { return (int (*)(type **,type **))sk_set_cmp_func((STACK *)sk,cmp); } \
STACK_OF(type) *sk_##type##_dup(STACK_OF(type) *sk) \
    { return (STACK_OF(type) *)sk_dup((STACK *)sk); } \
void sk_##type##_pop_free(STACK_OF(type) *sk,void (*func)(type *)) \
    { sk_pop_free((STACK *)sk,func); } \
type *sk_##type##_shift(STACK_OF(type) *sk) \
    { return (type *)sk_shift((STACK *)sk); } \
type *sk_##type##_pop(STACK_OF(type) *sk) \
    { return (type *)sk_pop((STACK *)sk); } \
void sk_##type##_sort(STACK_OF(type) *sk) \
    { sk_sort((STACK *)sk); }

#endif /* ndef HEADER_SAFESTACK_H */
