#ifndef __OQS_COMMON_H
#define __OQS_COMMON_H

#include <stdlib.h>

#define OQS_SUCCESS 1
#define OQS_ERROR 0

void OQS_MEM_cleanse(void *ptr, size_t len);
void OQS_MEM_secure_free(void *ptr, size_t len);

#endif
