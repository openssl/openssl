#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/lhash.h>
#include <openssl/objects.h>

union cmp_fn_to_char_u
	{
	char *char_p;
	int (*fn_p)(const char *, const char *);
	};

union hash_fn_to_char_u
	{
	char *char_p;
	unsigned long (*fn_p)(const char *);
	};

union int_fn_to_char_u
	{
	char *char_p;
	int (*fn_p)();
	};

union ulong_fn_to_char_u
	{
	char *char_p;
	unsigned long (*fn_p)();
	};

union void_fn_to_char_u
	{
	char *char_p;
	void (*fn_p)();
	};

/* I use the ex_data stuff to manage the identifiers for the obj_name_types
 * that applications may define.  I only really use the free function field.
 */
static LHASH *names_lh=NULL;
static int names_type_num=OBJ_NAME_TYPE_NUM;
static STACK *names_cmp=NULL;
static STACK *names_hash=NULL;
static STACK *names_free=NULL;

static unsigned long obj_name_hash(OBJ_NAME *a);
static int obj_name_cmp(OBJ_NAME *a,OBJ_NAME *b);

int OBJ_NAME_init(void)
	{
	if (names_lh != NULL) return(1);
	MemCheck_off();
	names_lh=lh_new(obj_name_hash,obj_name_cmp);
	MemCheck_on();
	return(names_lh != NULL);
	}

int OBJ_NAME_new_index(unsigned long (*hash_func)(), int (*cmp_func)(),
	     void (*free_func)())
	{
	int ret;
	int i;
	union ulong_fn_to_char_u tmp_hash_func;
	union int_fn_to_char_u tmp_cmp_func;
	union void_fn_to_char_u tmp_free_func;
	union cmp_fn_to_char_u tmp_strcmp;
	union hash_fn_to_char_u tmp_lh_strhash;

	tmp_hash_func.fn_p = hash_func;
	tmp_cmp_func.fn_p = cmp_func;
	tmp_free_func.fn_p = free_func;
	tmp_strcmp.fn_p = (int (*)(const char *, const char *))strcmp;
	tmp_lh_strhash.fn_p = lh_strhash;

	if (names_free == NULL)
		{
		MemCheck_off();
		names_hash=sk_new_null();
		names_cmp=sk_new_null();
		names_free=sk_new_null();
		MemCheck_on();
		}
	if ((names_free == NULL) || (names_hash == NULL) || (names_cmp == NULL))
		{
		/* ERROR */
		return(0);
		}
	ret=names_type_num;
	names_type_num++;
	for (i=sk_num(names_free); i<names_type_num; i++)
		{
		MemCheck_off();
		sk_push(names_hash,tmp_strcmp.char_p);
		sk_push(names_cmp,tmp_lh_strhash.char_p);
		sk_push(names_free,NULL);
		MemCheck_on();
		}
	if (hash_func != NULL)
		sk_set(names_hash,ret,tmp_hash_func.char_p);
	if (cmp_func != NULL)
		sk_set(names_cmp,ret,tmp_cmp_func.char_p);
	if (free_func != NULL)
		sk_set(names_free,ret,tmp_free_func.char_p);
	return(ret);
	}

static int obj_name_cmp(OBJ_NAME *a, OBJ_NAME *b)
	{
	int ret;
	union int_fn_to_char_u cmp;

	ret=a->type-b->type;
	if (ret == 0)
		{
		if ((names_cmp != NULL) && (sk_num(names_cmp) > a->type))
			{
			cmp.char_p=sk_value(names_cmp,a->type);
			ret=cmp.fn_p(a->name,b->name);
			}
		else
			ret=strcmp(a->name,b->name);
		}
	return(ret);
	}

static unsigned long obj_name_hash(OBJ_NAME *a)
	{
	unsigned long ret;
	union ulong_fn_to_char_u hash;

	if ((names_hash != NULL) && (sk_num(names_hash) > a->type))
		{
		hash.char_p=sk_value(names_hash,a->type);
		ret=hash.fn_p(a->name);
		}
	else
		{
		ret=lh_strhash(a->name);
		}
	ret^=a->type;
	return(ret);
	}

const char *OBJ_NAME_get(const char *name, int type)
	{
	OBJ_NAME on,*ret;
	int num=0,alias;

	if (name == NULL) return(NULL);
	if ((names_lh == NULL) && !OBJ_NAME_init()) return(NULL);

	alias=type&OBJ_NAME_ALIAS;
	type&= ~OBJ_NAME_ALIAS;

	on.name=name;
	on.type=type;

	for (;;)
		{
		ret=(OBJ_NAME *)lh_retrieve(names_lh,(char *)&on);
		if (ret == NULL) return(NULL);
		if ((ret->alias) && !alias)
			{
			if (++num > 10) return(NULL);
			on.name=ret->data;
			}
		else
			{
			return(ret->data);
			}
		}
	}

int OBJ_NAME_add(const char *name, int type, const char *data)
	{
	union void_fn_to_char_u f;
	OBJ_NAME *onp,*ret;
	int alias;

	if ((names_lh == NULL) && !OBJ_NAME_init()) return(0);

	alias=type&OBJ_NAME_ALIAS;
	type&= ~OBJ_NAME_ALIAS;

	onp=(OBJ_NAME *)Malloc(sizeof(OBJ_NAME));
	if (onp == NULL)
		{
		/* ERROR */
		return(0);
		}

	onp->name=name;
	onp->alias=alias;
	onp->type=type;
	onp->data=data;

	ret=(OBJ_NAME *)lh_insert(names_lh,(char *)onp);
	if (ret != NULL)
		{
		/* free things */
		if ((names_free != NULL) && (sk_num(names_free) > ret->type))
			{
			f.char_p=sk_value(names_free,ret->type);
			f.fn_p(ret->name,ret->type,ret->data);
			}
		Free((char *)ret);
		}
	else
		{
		if (lh_error(names_lh))
			{
			/* ERROR */
			return(0);
			}
		}
	return(1);
	}

int OBJ_NAME_remove(const char *name, int type)
	{
	OBJ_NAME on,*ret;
	union void_fn_to_char_u f;

	if (names_lh == NULL) return(0);

	type&= ~OBJ_NAME_ALIAS;
	on.name=name;
	on.type=type;
	ret=(OBJ_NAME *)lh_delete(names_lh,(char *)&on);
	if (ret != NULL)
		{
		/* free things */
		if ((names_free != NULL) && (sk_num(names_free) > type))
			{
			f.char_p=sk_value(names_free,type);
			f.fn_p(ret->name,ret->type,ret->data);
			}
		Free((char *)ret);
		return(1);
		}
	else
		return(0);
	}

static int free_type;

static void names_lh_free(OBJ_NAME *onp, int type)
{
	if(onp == NULL)
	    return;

	if ((free_type < 0) || (free_type == onp->type))
		{
		OBJ_NAME_remove(onp->name,onp->type);
		}
	}

void OBJ_NAME_cleanup(int type)
	{
	unsigned long down_load;

	if (names_lh == NULL) return;

	free_type=type;
	down_load=names_lh->down_load;
	names_lh->down_load=0;

	lh_doall(names_lh,names_lh_free);
	if (type < 0)
		{
		lh_free(names_lh);
		sk_free(names_hash);
		sk_free(names_cmp);
		sk_free(names_free);
		names_lh=NULL;
		names_hash=NULL;
		names_cmp=NULL;
		names_free=NULL;
		}
	else
		names_lh->down_load=down_load;
	}

