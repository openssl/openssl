/* tasn_prn.c */
/* Written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project 2000.
 */
/* ====================================================================
 * Copyright (c) 2000,2005 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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


#include <stddef.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include "asn1_locl.h"

#define ASN1_PCTX_FLAGS_SHOW_ABSENT	0x1
#define ASN1_PCTX_FLAGS_SHOW_SEQUENCE	0x2
#define ASN1_PCTX_FLAGS_SHOW_TYPE	0x4
#define ASN1_PCTX_FLAGS_NO_FIELD_NAME	0x8
#define ASN1_PCTX_FLAGS_NO_STRUCT_NAME	0x10

/* Print routines.
 */

/* ASN1_PCTX routines */

ASN1_PCTX default_pctx = 
	{
	ASN1_PCTX_FLAGS_SHOW_ABSENT,	/* flags */
	0,	/* nm_flags */
	0,	/* cert_flags */
	0,	/* oid_flags */
	0	/* str_flags */
	};
	

ASN1_PCTX *ASN1_PCTX_new(void)
	{
	ASN1_PCTX *ret;
	ret = OPENSSL_malloc(sizeof(ASN1_PCTX));
	if (ret == NULL)
		{
		ASN1err(ASN1_F_ASN1_PCTX_NEW, ERR_R_MALLOC_FAILURE);
		return NULL;
		}
	ret->flags = 0;
	ret->nm_flags = 0;
	ret->cert_flags = 0;
	ret->oid_flags = 0;
	ret->str_flags = 0;
	return ret;
	}

void ASN1_PCTX_free(ASN1_PCTX *p)
	{
	OPENSSL_free(p);
	}

unsigned long ASN1_PCTX_get_flags(ASN1_PCTX *p)
	{
	return p->flags;
	}

void ASN1_PCTX_set_flags(ASN1_PCTX *p, unsigned long flags)
	{
	p->flags = flags;
	}

unsigned long ASN1_PCTX_get_nm_flags(ASN1_PCTX *p)
	{
	return p->nm_flags;
	}

void ASN1_PCTX_set_nm_flags(ASN1_PCTX *p, unsigned long flags)
	{
	p->nm_flags = flags;
	}

unsigned long ASN1_PCTX_get_cert_flags(ASN1_PCTX *p)
	{
	return p->cert_flags;
	}

void ASN1_PCTX_set_cert_flags(ASN1_PCTX *p, unsigned long flags)
	{
	p->cert_flags = flags;
	}

unsigned long ASN1_PCTX_get_oid_flags(ASN1_PCTX *p)
	{
	return p->oid_flags;
	}

void ASN1_PCTX_set_oid_flags(ASN1_PCTX *p, unsigned long flags)
	{
	p->oid_flags = flags;
	}

unsigned long ASN1_PCTX_get_str_flags(ASN1_PCTX *p)
	{
	return p->str_flags;
	}

void ASN1_PCTX_set_str_flags(ASN1_PCTX *p, unsigned long flags)
	{
	p->str_flags = flags;
	}

/* Main print routines */

static int asn1_item_print_ctx(BIO *out, ASN1_VALUE **fld, int indent,
				const ASN1_ITEM *it, const ASN1_PCTX *pctx);
int asn1_template_print_ctx(BIO *out, ASN1_VALUE **fld, int indent,
				const ASN1_TEMPLATE *tt, const ASN1_PCTX *pctx);
static int asn1_primitive_print(BIO *out, ASN1_VALUE **fld,
				const ASN1_ITEM *it, int indent,
				const ASN1_PCTX *pctx);

int ASN1_item_print(BIO *out, ASN1_VALUE *ifld, int indent,
				const ASN1_ITEM *it, const ASN1_PCTX *pctx)
	{
	if (pctx == NULL)
		pctx = &default_pctx;
	return asn1_item_print_ctx(out, &ifld, indent, it, pctx);
	}

static int asn1_item_print_ctx(BIO *out, ASN1_VALUE **fld, int indent,
				const ASN1_ITEM *it, const ASN1_PCTX *pctx)
	{
	const ASN1_TEMPLATE *tt;
	const ASN1_EXTERN_FUNCS *ef;
	ASN1_VALUE **tmpfld;
	int i;
	if (BIO_printf(out, "%s:", it->sname) <= 0)
		return 0;
	if(*fld == NULL)
		{
		if (!(pctx->flags & ASN1_PCTX_FLAGS_SHOW_ABSENT))
			{
			if (BIO_puts(out, "\n") <= 0)
				return 0;
			}
		else
			{
			if (BIO_puts(out, "<ABSENT>\n") <= 0)
				return 0;
			}
		return 1;
		}

	switch(it->itype)
		{
		case ASN1_ITYPE_PRIMITIVE:
		if(it->templates)
			{
			if (!asn1_template_print_ctx(out, fld, indent,
							it->templates, pctx))
				return 0;
			}
		/* fall thru */
		case ASN1_ITYPE_MSTRING:
		if (!asn1_primitive_print(out, fld, it, indent, pctx))
			return 0;
		break;

		case ASN1_ITYPE_EXTERN:
		/* Use new style print routine if possible */
		ef = it->funcs;
		if (ef && ef->asn1_ex_print)
			{
			if (!ef->asn1_ex_print(out, fld, indent, "", pctx))
				return 0;
			}
		else if (BIO_printf(out, ":EXTERNAL TYPE %s\n", it->sname) <= 0)
			return 0;
		break;

		case ASN1_ITYPE_CHOICE:
		/* CHOICE type, get selector */
		i = asn1_get_choice_selector(fld, it);
		/* This should never happen... */
		if((i < 0) || (i >= it->tcount))
			{
			if (BIO_printf(out,
				"ERROR: selector [%d] invalid\n", i) <= 0)
				return 0;
			return 1;
			}
		tt = it->templates + i;
		tmpfld = asn1_get_field_ptr(fld, tt);
		if (!asn1_template_print_ctx(out, tmpfld, indent, tt, pctx))
			return 0;
		break;

		case ASN1_ITYPE_SEQUENCE:
		case ASN1_ITYPE_NDEF_SEQUENCE:
		if (pctx->flags & ASN1_PCTX_FLAGS_SHOW_SEQUENCE)
			{
			if (BIO_puts(out, " {\n") <= 0)
				return 0;
			}
		else
			{
			if (BIO_puts(out, "\n") <= 0)
				return 0;
			}

		/* Print each field entry */
		for(i = 0, tt = it->templates; i < it->tcount; i++, tt++)
			{
			const ASN1_TEMPLATE *seqtt;
			seqtt = asn1_do_adb(fld, tt, 1);
			tmpfld = asn1_get_field_ptr(fld, seqtt);
			if (!asn1_template_print_ctx(out, tmpfld,
						indent + 2, seqtt, pctx))
				return 0;
			}
		if (pctx->flags & ASN1_PCTX_FLAGS_SHOW_SEQUENCE)
			{
			if (BIO_printf(out, "%*s}\n", indent, "") < 0)
				return 0;
			}
		break;

		default:
		BIO_printf(out, "Unprocessed type %d\n", it->itype);
		return 0;
		}
	if (BIO_puts(out, "\n") <= 0)
		return 0;
	return 1;
	}

int asn1_template_print_ctx(BIO *out, ASN1_VALUE **fld, int indent,
				const ASN1_TEMPLATE *tt, const ASN1_PCTX *pctx)
	{
	int i, flags;
	flags = tt->flags;
	if(flags & ASN1_TFLG_SK_MASK)
		{
		char *tname;
		ASN1_VALUE *skitem;
		/* SET OF, SEQUENCE OF */
		if(pctx->flags & ASN1_PCTX_FLAGS_SHOW_SEQUENCE)
			{
			if(flags & ASN1_TFLG_SET_OF)
				tname = "SET";
			else
				tname = "SEQUENCE";
			if (BIO_printf(out, "%*s%s OF %s {\n",
				indent, "", tname, tt->field_name) <= 0)
				return 0;
			}
		else if (BIO_printf(out, "%*s%s:\n", indent, "",
					tt->field_name) <= 0)
				return 0;
		for(i = 0; i < sk_num((STACK *)*fld); i++)
			{
			if (BIO_printf(out, "%*s", indent + 2, "") <= 0)
				return 0;
			skitem = (ASN1_VALUE *)sk_value((STACK *)*fld, i);
			if (!asn1_item_print_ctx(out, &skitem, indent + 2,
					tt->item, pctx))
				return 0;
			}
		if(pctx->flags & ASN1_PCTX_FLAGS_SHOW_SEQUENCE)
			{
			if (BIO_printf(out, "%*s}\n", indent, "") <= 0)
				return 0;
			}
		return 1;
		}
	else if (BIO_printf(out, "%*s%s:", indent, "", tt->field_name) <= 0)
				return 0;
	return asn1_item_print_ctx(out, fld, indent, tt->item, pctx);
	}

int asn1_print_fsname(BIO *out, int indent,
			const char *fname, const char *sname,
			const ASN1_PCTX *pctx)
	{
	static char spaces[] = "                    ";
	const int nspaces = sizeof(spaces) - 1;
	while (indent > nspaces)
		{
		if (BIO_write(out, spaces, nspaces) != nspaces)
			return 0;
		indent -= nspaces;
		}
	if (BIO_write(out, spaces, indent) != indent)
		return 0;
	if (!(pctx->flags &
		(ASN1_PCTX_FLAGS_NO_FIELD_NAME|ASN1_PCTX_FLAGS_NO_STRUCT_NAME)))
		return 1;
	if (fname && !(pctx->flags & ASN1_PCTX_FLAGS_NO_FIELD_NAME))
		{
		if (BIO_puts(out, fname) <= 0)
			return 0;
		}
	if (sname && !(pctx->flags & ASN1_PCTX_FLAGS_NO_STRUCT_NAME))
		{
		if (pctx->flags & ASN1_PCTX_FLAGS_NO_FIELD_NAME)
			{
			if (BIO_puts(out, sname) <= 0)
				return 0;
			}
		else if (BIO_printf(out, " (%s)", sname) <= 0)
			return 0;
		}
	if (BIO_write(out, ":", 1) != 1)
		return 0;
	return 1;
	}

int asn1_print_boolean_ctx(BIO *out, const int bool, const ASN1_PCTX *pctx)
	{
	const char *str;
	switch (bool)
		{
		case -1:
		str = "BOOL ABSENT";
		break;

		case 0:
		str = "FALSE";
		break;

		default:
		str = "TRUE";
		break;

		}

	if (BIO_puts(out, str) <= 0)
		return 0;
	return 1;

	}

static int asn1_print_integer_ctx(BIO *out, ASN1_INTEGER *str,
						const ASN1_PCTX *pctx)
	{
	char *s;
	int ret = 1;
	s = i2s_ASN1_INTEGER(NULL, str);
	if (BIO_printf(out, "%s", s) <= 0)
		ret = 0;
	OPENSSL_free(s);
	return ret;
	}

static int asn1_print_oid_ctx(BIO *out, const ASN1_OBJECT *oid,
						const ASN1_PCTX *pctx)
	{
	char objbuf[80];
	const char *ln;
	ln = OBJ_nid2ln(OBJ_obj2nid(oid));
	if(!ln)
		ln = "";
	OBJ_obj2txt(objbuf, sizeof objbuf, oid, 1);
	if (BIO_printf(out, "%s (%s)", ln, objbuf) <= 0)
		return 0;
	return 1;
	}

static int asn1_print_obstring_ctx(BIO *out, ASN1_STRING *str, int indent,
						const ASN1_PCTX *pctx)
	{
	if (str->type == V_ASN1_BIT_STRING)
		{
		if (BIO_printf(out, " (%ld unused bits)\n",
					str->flags & 0x7) <= 0)
				return 0;
		}
	else if (BIO_puts(out, "\n") <= 0)
		return 0;
	if (BIO_dump_indent(out, (char *)str->data, str->length,
				indent + 2) <= 0)
		return 0;
	return 1;
	}

static int asn1_primitive_print(BIO *out, ASN1_VALUE **fld,
				const ASN1_ITEM *it, int indent,
				const ASN1_PCTX *pctx)
	{
	long utype;
	ASN1_STRING *str;
	int ret = 1;
	str = (ASN1_STRING *)*fld;
	if (it->itype == ASN1_ITYPE_MSTRING)
		utype = str->type & ~V_ASN1_NEG;
	else
		utype = it->utype;
	if (utype == V_ASN1_ANY)
		{
		ASN1_TYPE *atype = (ASN1_TYPE *)*fld;
		utype = atype->type;
		fld = (ASN1_VALUE **)&atype->value.ptr;
		str = (ASN1_STRING *)*fld;
		}
	if (BIO_puts(out, ASN1_tag2str(utype)) <= 0)
		return 0;
	if (utype != V_ASN1_NULL && BIO_puts(out, ":") <= 0)
		return 0;

	switch (utype)
		{
		case V_ASN1_BOOLEAN:
			{
			int bool = *(int *)fld;
			if (bool == -1)
				bool = it->size;
			ret = asn1_print_boolean_ctx(out, bool, pctx);
			}
		break;

		case V_ASN1_INTEGER:
		case V_ASN1_ENUMERATED:
		ret = asn1_print_integer_ctx(out, str, pctx);
		break;

		case V_ASN1_NULL:
		break;

		case V_ASN1_UTCTIME:
		ret = ASN1_UTCTIME_print(out, str);
		break;

		case V_ASN1_GENERALIZEDTIME:
		ret = ASN1_GENERALIZEDTIME_print(out, str);
		break;

		case V_ASN1_OBJECT:
		ret = asn1_print_oid_ctx(out, (const ASN1_OBJECT *)*fld, pctx);
		break;

		case V_ASN1_OCTET_STRING:
		case V_ASN1_BIT_STRING:
		ret = asn1_print_obstring_ctx(out, str, indent, pctx);
		break;

		case V_ASN1_SEQUENCE:
		case V_ASN1_SET:
		if (ASN1_parse_dump(out, str->data, str->length,
						indent, 0) <= 0)
			ret = 0;
		break;

		default:
		ret = ASN1_STRING_print_ex(out, str, pctx->str_flags);

		}
	if (!ret)
		return 0;
	return 1;
	}
