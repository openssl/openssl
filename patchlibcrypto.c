#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

void* find_memory(void* haystack, size_t size_haystack, const void* needle, size_t size_needle)
{
	if (size_needle > size_haystack)
		return NULL;
	
	char* haystack_ptr = haystack;
	for (size_t i = 0; i < size_haystack - size_needle + 1; i++) {
		if (memcmp(haystack_ptr, needle, size_needle) == 0)
			return haystack_ptr;
		
		haystack_ptr++;
	}
	
	return NULL;
}

int main()
{
	FILE *f = fopen("libcrypto-3.dll", "rb");
	if (!f) {
		perror("could not open libcrypto-3.dll");
		return 1;
	}
	
	long size;
	fseek(f, 0, SEEK_END);
	size = ftell(f);
	fseek(f, 0, SEEK_SET);
	
	if (size < 0) {
		perror("libcrypto-3.dll is not a file or something");
		fclose(f);
		return 1;
	}
	
	char* fdata = malloc(size);
	if (fread(fdata, 1, size, f) != size) {
		perror("could not read entire file libcrypto-3.dll");
		fclose(f);
		return 1;
	}
	
	fclose(f);
	
	char* strtoi64_place = find_memory(fdata, size, "_strtoi64", 9);
	char* strtoui64_place = find_memory(fdata, size, "_strtoui64", 10);
	
	if (!strtoi64_place) {
		fprintf(stderr, "cannot find _strtoi64 in libcrypto-3");
		return 1;
	}
	if (!strtoui64_place) {
		fprintf(stderr, "cannot find _strtoui64 in libcrypto-3");
		return 1;
	}
	
	memcpy(strtoi64_place, "iswxdigit", 9);
	memcpy(strtoui64_place, "isleadbyte", 10);
	
	f = fopen("libcrypto-3-patched.dll", "wb");
	if (!f) {
		perror("cannot open libcrypto-3-patched.dll for writing");
		return 1;
	}
	
	if (fwrite(fdata, 1, size, f) != size) {
		perror("cannot write all bytes to libcrypto-3-patched.dll");
		fclose(f);
		return 1;
	}
	
	fclose(f);
	
	// perform the swap
	if (rename("libcrypto-3.dll", "libcrypto-3-original.dll") < 0) {
		if (errno == EEXIST) {
			// delete the file
			if (remove("libcrypto-3-original.dll") < 0) {
				perror("couldn't delete old libcrypto-3-original.dll to rename the actual original over");
				return 1;
			}
		}
		else {
			perror("cannot rename libcrypto-3.dll to libcrypto-3-original.dll");
			return 1;
		}
	}
	if (rename("libcrypto-3-patched.dll", "libcrypto-3.dll") < 0) {
		perror("cannot rename libcrypto-3-patched.dll to libcrypto-3.dll");
		return 1;
	}
	
	return 0;
}