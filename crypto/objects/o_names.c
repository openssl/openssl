#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/lhash.h>
#include <openssl/objects.h>

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
		sk_push(names_hash,(char *)strcmp);
		sk_push(names_cmp,(char *)lh_strhash);
		sk_push(names_free,NULL);
		MemCheck_on();
		}
	if (hash_func != NULL)
		sk_set(names_hash,ret,(char *)hash_func);
	if (cmp_func != NULL)
		sk_set(names_cmp,ret,(char *)cmp_func);
	if (free_func != NULL)
		sk_set(names_free,ret,(char *)free_func);
	return(ret);
	}

static int obj_name_cmp(OBJ_NAME *a, OBJ_NAME *b)
	{
	int ret;
	int (*cmp)();

	ret=a->type-b->type;
	if (ret == 0)
		{
		if ((names_cmp != NULL) && (sk_num(names_cmp) > a->type))
			{
			cmp=(int (*)())sk_value(names_cmp,a->type);
			ret=cmp(a->name,b->name);
			}
		else
			ret=strcmp(a->name,b->name);
		}
	return(ret);
	}

static unsigned long obj_name_hash(OBJ_NAME *a)
	{
	unsigned long ret;
	unsigned long (*hash)();

	if ((names_hash != NULL) && (sk_num(names_hash) > a->type))
		{
		hash=(unsigned long (*)())sk_value(names_hash,a->type);
		ret=hash(a->name);
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
	void (*f)();
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
			f=(void (*)())sk_value(names_free,ret->type);
			f(ret->name,ret->type,ret->data);
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
	void (*f)();

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
			f=(void (*)())sk_value(names_free,type);
			f(ret->name,ret->type,ret->data);
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

