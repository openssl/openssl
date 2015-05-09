#include <pthread.h>

static pthread_mutex_t arc4random_mtx = PTHREAD_MUTEX_INITIALIZER;

#define _ARC4_LOCK()   pthread_mutex_lock(&arc4random_mtx)
#define _ARC4_UNLOCK() pthread_mutex_unlock(&arc4random_mtx)
