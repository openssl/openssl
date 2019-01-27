/*
 * Copyright (c) 2001 Markus Friedl
 * Copyright (c) 2002 Juha Yrjölä
 * Copyright (c) 2003 Kevin Stefanik
 * Copyright (c) 2016 Michał Trojnara
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
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _ENGINE_PKCS11_H
#define _ENGINE_PKCS11_H

#include "libp11.h"
#include "e_pkcs11_err.h"
#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/engine.h>
#include <openssl/ui.h>

#define CMD_SO_PATH		ENGINE_CMD_BASE
#define CMD_MODULE_PATH 	(ENGINE_CMD_BASE+1)
#define CMD_PIN		(ENGINE_CMD_BASE+2)
#define CMD_VERBOSE		(ENGINE_CMD_BASE+3)
#define CMD_QUIET		(ENGINE_CMD_BASE+4)
#define CMD_LOAD_CERT_CTRL	(ENGINE_CMD_BASE+5)
#define CMD_INIT_ARGS	(ENGINE_CMD_BASE+6)
#define CMD_SET_USER_INTERFACE	(ENGINE_CMD_BASE + 7)
#define CMD_SET_CALLBACK_DATA	(ENGINE_CMD_BASE + 8)
#define CMD_FORCE_LOGIN	(ENGINE_CMD_BASE+9)

typedef struct st_engine_ctx ENGINE_CTX; /* opaque */

/* defined in eng_back.c */

ENGINE_CTX *ctx_new();

int ctx_destroy(ENGINE_CTX *ctx);

int ctx_init(ENGINE_CTX *ctx);

int ctx_finish(ENGINE_CTX *ctx);

int ctx_engine_ctrl(ENGINE_CTX *ctx, int cmd, long i, void *p, void (*f)());

EVP_PKEY *ctx_load_pubkey(ENGINE_CTX *ctx, const char *s_key_id,
	UI_METHOD * ui_method, void *callback_data);

EVP_PKEY *ctx_load_privkey(ENGINE_CTX *ctx, const char *s_key_id,
	UI_METHOD * ui_method, void *callback_data);

void ctx_log(ENGINE_CTX *ctx, int level, const char *format, ...)
#ifdef __GNUC__
	__attribute__((format(printf, 3, 4)))
#endif
	;

/* defined in eng_parse.c */

int parse_pkcs11_uri(ENGINE_CTX *ctx,
	const char *uri, PKCS11_TOKEN **p_tok,
	unsigned char *id, size_t *id_len, char *pin, size_t *pin_len,
	char **label);

int parse_slot_id_string(ENGINE_CTX *ctx,
	const char *slot_id, int *slot,
	unsigned char *id, size_t * id_len, char **label);

#endif

/* vim: set noexpandtab: */
