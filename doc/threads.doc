How to compile SSLeay for multi-threading.

Well basically it is quite simple, set the compiler flags and build.
I have only really done much testing under Solaris and Windows NT.
If you library supports localtime_r() and gmtime_r() add,
-DTHREADS to the makefile parameters.  You can probably survive with out
this define unless you are going to have multiple threads generating
certificates at once.  It will not affect the SSL side of things.

The approach I have taken to doing locking is to make the application provide
callbacks to perform locking and so that the SSLeay library can distinguish
between threads (for the error state).

To have a look at an example program, 'cd mt; vi mttest.c'.
To build under solaris, sh solaris.sh, for Windows NT or Windows 95,
win32.bat

This will build mttest which will fire up 10 threads that talk SSL
to each other 10 times.
To enable everything to work, the application needs to call

CRYPTO_set_id_callback(id_function);
CRYPTO_set_locking_callback(locking_function);

before any multithreading is started.
id_function does not need to be defined under Windows NT or 95, the
correct function will be called if it is not.  Under unix, getpid()
is call if the id_callback is not defined, for solaris this is wrong
(since threads id's are not pid's) but under IRIX it is correct
(threads are just processes sharing the data segement).

The locking_callback is used to perform locking by the SSLeay library.
eg.

void solaris_locking_callback(mode,type,file,line)
int mode;
int type;
char *file;
int line;
	{
	if (mode & CRYPTO_LOCK)
		mutex_lock(&(lock_cs[type]));
	else
		mutex_unlock(&(lock_cs[type]));
	}

Now in this case I have used mutexes instead of read/write locks, since they
are faster and there are not many read locks in SSLeay, you may as well
always use write locks.  file and line are __FILE__ and __LINE__ from
the compile and can be usefull when debugging.

Now as you can see, 'type' can be one of a range of values, these values are
defined in crypto/crypto.h
CRYPTO_get_lock_name(type) will return a text version of what the lock is.
There are CRYPTO_NUM_LOCKS locks required, so under solaris, the setup
for multi-threading can be

static mutex_t lock_cs[CRYPTO_NUM_LOCKS];

void thread_setup()
	{
	int i;

	for (i=0; i<CRYPTO_NUM_LOCKS; i++)
		mutex_init(&(lock_cs[i]),USYNC_THREAD,NULL);
	CRYPTO_set_id_callback((unsigned long (*)())solaris_thread_id);
	CRYPTO_set_locking_callback((void (*)())solaris_locking_callback);
	}

As a final note, under Windows NT or Windows 95, you have to be careful
not to mix the various threaded, unthreaded and debug libraries.
Normally if they are mixed incorrectly, mttest will crash just after printing
out some usage statistics at the end.  This is because the
different system libraries use different malloc routines and if
data is malloc()ed inside crypt32.dll or ssl32.dll and then free()ed by a
different library malloc, things get very confused.

The default SSLeay DLL builds use /MD, so if you use this on your
application, things will work as expected.  If you use /MDd,
you will probably have to rebuild SSLeay using this flag.
I should modify util/mk1mf.pl so it does all this correctly, but 
this has not been done yet.

One last warning.  Because locking overheads are actually quite large, the
statistics collected against the SSL_CTX for successfull connections etc
are not locked when updated.  This does make it possible for these
values to be slightly lower than they should be, if you are
running multithreaded on a multi-processor box, but this does not really
matter much.

