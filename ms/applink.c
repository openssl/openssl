#define APPLINK_STDIN	1
#define APPLINK_STDOUT	2
#define APPLINK_STDERR	3
#define APPLINK_FPRINTF	4
#define APPLINK_FGETS	5
#define APPLINK_FREAD	6
#define APPLINK_FWRITE	7
#define APPLINK_FSETMOD	8
#define APPLINK_FEOF	9
#define APPLINK_FCLOSE 	10	/* should not be used */
#define APPLINK_MAX	10	/* always same as last macro */

#ifndef APPMACROS_ONLY
#include <stdio.h>
#include <io.h>
#include <fcntl.h>

static void *app_stdin()	{ return stdin;  }
static void *app_stdout()	{ return stdout; }
static void *app_stderr()	{ return stderr; }
static int   app_feof(FILE *fp)	{ return feof(fp); }
static int   app_fsetmod(FILE *fp,char mod)
{ return _setmode (_fileno(fp),mod=='b'?_O_BINARY:_O_TEXT); }

__declspec(dllexport) void **OPENSSL_Applink()
{ static int once=1;
  static void *OPENSSL_ApplinkTable[APPLINK_MAX+1]={(void *)APPLINK_MAX};

    if (once)
    {	OPENSSL_ApplinkTable[APPLINK_STDIN]	= app_stdin;
	OPENSSL_ApplinkTable[APPLINK_STDOUT]	= app_stdout;
	OPENSSL_ApplinkTable[APPLINK_STDERR]	= app_stderr;
	OPENSSL_ApplinkTable[APPLINK_FPRINTF]	= fprintf;
	OPENSSL_ApplinkTable[APPLINK_FGETS]	= fgets;
	OPENSSL_ApplinkTable[APPLINK_FREAD]	= fread;
	OPENSSL_ApplinkTable[APPLINK_FWRITE]	= fwrite;
	OPENSSL_ApplinkTable[APPLINK_FSETMOD]	= app_fsetmod;
	OPENSSL_ApplinkTable[APPLINK_FEOF]	= app_feof;
	OPENSSL_ApplinkTable[APPLINK_FCLOSE]	= fclose;
	once = 0;
    }

  return OPENSSL_ApplinkTable;
}
#endif
