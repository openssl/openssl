#include <oqs/common.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#endif

void OQS_MEM_cleanse(void *ptr, size_t len) {
#if defined(_WIN32)
	SecureZeroMemory(ptr, len);
#elif defined(HAVE_MEMSET_S)
	if (0U < len && memset_s(ptr, (rsize_t) len, 0, (rsize_t) len) != 0) {
		abort();
	}
#else
	typedef void *(*memset_t)(void *, int, size_t);
	static volatile memset_t memset_func = memset;
	memset_func(ptr, 0, len);
#endif
}

void OQS_MEM_secure_free(void *ptr, size_t len) {
	if (ptr != NULL) {
		OQS_MEM_cleanse(ptr, len);
		free(ptr);
	}
}

/* Displays hexadecimal strings */
void OQS_print_hex_string(const char *label, const uint8_t *str, size_t len) {
	printf("%-20s (%4zu bytes):  ", label, len);
	for (size_t i = 0; i < (len); i++) {
		printf("%02X", ((unsigned char *) (str))[i]);
	}
	printf("\n");
}

/* Partially displays hexadecimal strings */
void OQS_print_part_hex_string(const char *label, const uint8_t *str, size_t len, size_t sub_len) {
	printf("%-20s (%4zu bytes):  ", label, len);
	for (size_t i = 0; i < (sub_len); i++) {
		printf("%02X", ((unsigned char *) (str))[i]);
	}
	printf("...");
	for (size_t i = 0; i < (sub_len); i++) {
		printf("%02X", ((unsigned char *) (str))[len - sub_len + i]);
	}
	printf("\n");
}
