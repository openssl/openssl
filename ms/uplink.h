#define APPMACROS_ONLY
#include "applink.c"

extern void *OPENSSL_UplinkTable[];
#define UP_stdin  (*(void *(*)())OPENSSL_UplinkTable[APPLINK_STDIN])()
#define UP_stdout (*(void *(*)())OPENSSL_UplinkTable[APPLINK_STDOUT])()
#define UP_stderr (*(void *(*)())OPENSSL_UplinkTable[APPLINK_STDERR])()
#define UP_fprintf (*(int (*)(void *,const char *,...))OPENSSL_UplinkTable[APPLINK_FPRINTF])
#define UP_fgets  (*(char *(*)(char *,int,void *))OPENSSL_UplinkTable[APPLINK_FGETS])
#define UP_fread  (*(size_t (*)(void *,size_t,size_t,void *))OPENSSL_UplinkTable[APPLINK_FREAD])
#define UP_fwrite (*(size_t (*)(void *,size_t,size_t,void *))OPENSSL_UplinkTable[APPLINK_FWRITE])
#define UP_fsetmod (*(int (*)(void *,char))OPENSSL_UplinkTable[APPLINK_FSETMOD])
#define UP_feof   (*(int (*)(void *))OPENSSL_UplinkTable[APPLINK_FEOF])
#define UP_fclose (*(int (*)(void *))OPENSSL_Uplink[APPLINK_FCLOSE])
