#include <stdio.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <Foundation/Foundation.h>
 
static FILE *(*libc_fopen)(const char *, const char *) = NULL;

__attribute__((constructor))
static void pre_main(void)
{
    /*
     * Pull reference to fopen(3) from libc.
     */
    void *handle = dlopen("libSystem.B.dylib",RTLD_LAZY);

    if (handle) {
        libc_fopen = dlsym(handle,"fopen");
        dlclose(handle);
    }

    /*
     * Change to Documents directory.
     */
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) lastObject];

    NSFileManager *filemgr = [NSFileManager defaultManager];
    [filemgr changeCurrentDirectoryPath: docs];
    [filemgr release];
}

char *mkdirhier(char *path)
{
    char *slash;
    struct stat buf;

    if (path[0]=='.' && path[1]=='/') path+=2;

    if ((slash = strrchr(path,'/'))) {
	*slash = '\0';
	if (stat(path,&buf)==0) {
	    *slash = '/';
	    return NULL;
	}
	(void)mkdirhier(path);
	mkdir (path,0777);
	*slash = '/';
    }

    return slash;
}
/*
 * Replacement fopen(3)
 */
FILE *fopen(const char *filename, const char *mode)
{
    FILE *ret;

    if ((ret = (*libc_fopen)(filename,mode)) == NULL) {
        /*
         * If file is not present in Documents directory, try from Bundle.
         */
        NSString *nsspath = [NSString stringWithFormat:@"%@/%s",
                                   [[NSBundle mainBundle] bundlePath],
                                   filename];

        if ((ret = (*libc_fopen)([nsspath cStringUsingEncoding:NSUTF8StringEncoding],mode)) == NULL &&
	    mode[0]=='w' &&
	    ((filename[0]!='.' && filename[0]!='/') ||
	     (filename[0]=='.' && filename[1]=='/')) ) {
	    /*
	     * If not present in Bundle, create directory in Documents
	     */
	    char *path = strdup(filename), *slash;
	    static int once = 1;

	    if ((slash = mkdirhier(path)) && once) {
		/*
		 * For some reason iOS truncates first created file
		 * upon program exit, so we create one preemptively...
		 */
		once = 0;
		strcpy(slash,"/.0");
		creat(path,0444);
	    }
	    free(path);
	    ret = (*libc_fopen)(filename,mode);
	}
    }

    return ret;
}
